"""
Log Parser — structures raw log lines into typed events and detects anomalies.

Supports the common SRE log format:
    YYYY-MM-DD HH:MM:SS LEVEL [service] message

Anomaly detection is keyword-driven and covers the three incident scenarios:
    • DB Connection Pool Exhaustion
    • CPU Spike — Thread Exhaustion
    • Memory Leak — JVM Heap OOM
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Log line pattern
# ---------------------------------------------------------------------------

_LOG_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(INFO|WARN|WARNING|ERROR|CRITICAL|DEBUG)\s+"
    r"\[([^\]]+)\]\s+"
    r"(.+)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Anomaly keyword → human-readable description
# Priority keywords first (more specific before broader).
# ---------------------------------------------------------------------------

_ANOMALY_KEYWORDS: list[tuple[str, str]] = [
    # DB Pool
    ("pool exhausted",              "Connection pool fully exhausted — new requests are failing"),
    ("cannot get jdbc",             "JDBC connection failure — database appears unreachable"),
    ("connection acquisition",      "DB connection acquisition timed out — pool under critical pressure"),
    ("hikaricp",                    "HikariCP pool event — monitor pool utilization closely"),
    # Memory
    ("outofmemoryerror",            "JVM OutOfMemoryError — heap limit reached, OOM imminent"),
    ("oomkilled",                   "Container killed by OOM — memory limit exceeded"),
    ("heap space",                  "JVM heap space error — GC cannot reclaim sufficient memory"),
    ("gc pause",                    "Excessive GC pause — memory pressure building"),
    # CPU / Threading
    ("thread pool",                 "Thread pool saturation — request throughput degraded"),
    ("cpu utilization",             "CPU utilization spike detected"),
    ("high cpu",                    "High CPU usage detected on host"),
    # Network / Availability
    ("circuit breaker",             "Circuit breaker opened — downstream service isolated"),
    ("502 bad gateway",             "Load balancer receiving 502s — upstream service unhealthy"),
    ("503 service unavailable",     "Service returning 503 — capacity limit exceeded"),
    ("readiness probe",             "Kubernetes readiness probe failed — pod may be cycling"),
    ("connection refused",          "Connection refused — target service may be down"),
    # General error patterns
    ("timeout exceeded",            "Timeout exceeded — operation did not complete in time"),
    ("retry attempt",               "Retry storm detected — upstream dependency is unstable"),
    ("failed to persist",           "Persistence failure — data write operations are failing"),
]


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------


@dataclass
class LogEvent:
    """A single parsed and structured log line."""

    line_number: int
    timestamp: str
    level: str
    service: str
    message: str
    raw: str

    @property
    def is_error(self) -> bool:
        return self.level in ("ERROR", "CRITICAL")

    @property
    def is_warning(self) -> bool:
        return self.level in ("WARN", "WARNING")


@dataclass
class ParseResult:
    """Aggregate output of parsing a log file."""

    events: list[LogEvent] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    error_count: int = 0
    warning_count: int = 0
    critical_count: int = 0
    services_affected: list[str] = field(default_factory=list)

    @property
    def total_events(self) -> int:
        return len(self.events)

    @property
    def has_critical_events(self) -> bool:
        return self.critical_count > 0 or self.error_count >= 3


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class LogParser:
    """
    Parses structured log files into typed events and detects anomalies.

    Thread-safe: all state lives in local variables, not instance state.
    """

    def parse(self, content: str) -> ParseResult:
        """
        Parse raw (already-redacted) log content into structured events.

        Rules are applied in declaration order. Lines that do not match the
        structured log format are treated as continuation lines (stack traces,
        multi-line messages) and are still scanned for anomaly keywords.

        Args:
            content: Raw redacted log text.

        Returns:
            ParseResult with typed events, anomaly descriptions, and counts.
        """
        result = ParseResult()
        services: set[str] = set()
        seen_anomalies: set[str] = set()

        for line_num, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue

            match = _LOG_PATTERN.match(line)
            if match:
                ts, level, service, message = match.groups()
                level_upper = level.upper()

                event = LogEvent(
                    line_number=line_num,
                    timestamp=ts,
                    level=level_upper,
                    service=service,
                    message=message,
                    raw=raw_line,
                )
                result.events.append(event)
                services.add(service)

                if level_upper == "CRITICAL":
                    result.critical_count += 1
                elif level_upper == "ERROR":
                    result.error_count += 1
                elif level_upper in ("WARN", "WARNING"):
                    result.warning_count += 1

                # Scan the parsed message for anomaly keywords
                self._detect_anomalies(message, line_num, result, seen_anomalies)
            else:
                # Continuation line — scan it too (stack traces contain keywords)
                self._detect_anomalies(line, line_num, result, seen_anomalies)

        result.services_affected = sorted(services)
        return result

    @staticmethod
    def _detect_anomalies(
        text: str,
        line_num: int,
        result: ParseResult,
        seen: set[str],
    ) -> None:
        """Scan a line for known anomaly keywords and append unique findings."""
        text_lower = text.lower()
        for keyword, description in _ANOMALY_KEYWORDS:
            if keyword in text_lower and description not in seen:
                seen.add(description)
                result.anomalies.append(description)
