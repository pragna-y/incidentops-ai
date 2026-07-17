"""
Metric Analysis Tools — ADK agent skill functions for the Triage Agent.

Provides access to correlated infrastructure metrics so the LLM can
quantify the severity of the incident beyond log pattern matching.
"""

from __future__ import annotations

import json

_state = None  # type: ignore[assignment]


def set_state(state) -> None:  # type: ignore[type-arg]
    """Called by the orchestrator to inject the shared IncidentState."""
    global _state
    _state = state


# ---------------------------------------------------------------------------
# Tool functions
# ---------------------------------------------------------------------------


def get_infrastructure_metrics() -> str:
    """
    Return current infrastructure metrics correlated with this incident.

    Metrics include CPU%, memory%, DB pool utilisation, error rate,
    active connections, and JVM heap usage where applicable.

    Use this tool to understand the quantitative state of the system
    and to inform severity classification and corrective action priority.

    Returns:
        JSON string with all available metric values (null = not applicable).
    """
    if _state is None:
        return json.dumps({"error": "No incident state loaded."})

    m = _state.metrics
    return json.dumps(
        {
            "cpu_percent": m.cpu_percent,
            "memory_percent": m.memory_percent,
            "db_pool_utilization_percent": m.db_pool_utilization_percent,
            "error_rate_per_minute": m.error_rate_per_minute,
            "active_connections": m.active_connections,
            "heap_used_gb": m.heap_used_gb,
            "additional_data": m.raw_data,
            "has_data": m.has_data,
        },
        indent=2,
    )


def get_metric_severity_assessment() -> str:
    """
    Return a plain-language severity assessment based on metric thresholds.

    Compares current metric values against known critical thresholds and
    produces a severity classification with supporting evidence.

    Returns:
        Text description of metric-based severity indicators.
    """
    if _state is None:
        return "No incident state loaded."

    m = _state.metrics
    findings: list[str] = []

    if m.cpu_percent is not None:
        if m.cpu_percent >= 90:
            findings.append(f"CRITICAL: CPU at {m.cpu_percent:.0f}% — system near saturation")
        elif m.cpu_percent >= 70:
            findings.append(f"HIGH: CPU at {m.cpu_percent:.0f}% — elevated, monitor closely")

    if m.memory_percent is not None:
        if m.memory_percent >= 90:
            findings.append(f"CRITICAL: Memory at {m.memory_percent:.0f}% — OOM risk is high")
        elif m.memory_percent >= 75:
            findings.append(f"HIGH: Memory at {m.memory_percent:.0f}% — approaching limit")

    if m.db_pool_utilization_percent is not None:
        if m.db_pool_utilization_percent >= 95:
            findings.append(
                f"CRITICAL: DB pool at {m.db_pool_utilization_percent:.0f}% — exhausted"
            )
        elif m.db_pool_utilization_percent >= 80:
            findings.append(
                f"HIGH: DB pool at {m.db_pool_utilization_percent:.0f}% — nearing limit"
            )

    if m.error_rate_per_minute is not None and m.error_rate_per_minute >= 10:
        findings.append(
            f"HIGH: Error rate {m.error_rate_per_minute:.0f}/min — user-facing impact"
        )

    if m.heap_used_gb is not None and m.heap_used_gb >= 3.5:
        findings.append(
            f"CRITICAL: JVM heap at {m.heap_used_gb:.1f}GB — OOM imminent"
        )

    if not findings:
        return "Metrics are within normal thresholds. No metric-based severity escalation needed."

    return "Metric-based severity indicators:\n" + "\n".join(f"  • {f}" for f in findings)
