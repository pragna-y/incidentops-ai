"""
Log Analysis Tools — ADK agent skill functions for the Triage Agent.

These are plain Python functions exposed as ADK tools. They read from the
shared IncidentState that is set by the orchestrator before agent execution.

Each function is designed to be called by the LLM during tool-use:
  - Clear docstring describes purpose and return format
  - Return type is always str so the LLM can reason about it naturally
  - Side effects: some tools also update the shared state
"""

from __future__ import annotations

import json

# Module-level state reference — set by orchestrator.set_state() before use.
# Using a module-level singleton is intentional: ADK tools must be plain
# functions (not methods), so we inject state at module level.
_state = None  # type: ignore[assignment]


def set_state(state) -> None:  # type: ignore[type-arg]
    """Called by the orchestrator to inject the shared IncidentState."""
    global _state
    _state = state


# ---------------------------------------------------------------------------
# Tool functions — called by the Triage Agent LLM
# ---------------------------------------------------------------------------


def get_incident_summary() -> str:
    """
    Return a structured summary of the current incident being triaged.

    Includes incident ID, scenario, status, severity, and the redacted log
    metadata. Use this tool first to understand the incident context.

    Returns:
        JSON string with incident summary fields.
    """
    if _state is None:
        return json.dumps({"error": "No incident state loaded."})

    inc = _state.incident
    raw = _state.raw_log
    return json.dumps(
        {
            "incident_id": inc.id,
            "scenario": inc.scenario,
            "severity": inc.severity.value,
            "status": inc.status.value,
            "log_lines": raw.line_count if raw else 0,
            "log_byte_size": raw.byte_size if raw else 0,
        },
        indent=2,
    )


def get_detected_anomalies() -> str:
    """
    Return all anomalies detected in the incident log by the parser.

    Each anomaly is a human-readable description of a suspicious pattern.
    Use this tool to understand what is wrong with the system.

    Returns:
        Numbered list of anomaly descriptions, or a message if none found.
    """
    if _state is None:
        return "No incident state loaded."

    anomalies = _state.anomalies
    if not anomalies:
        return "No anomalies detected in the log."

    lines = [f"{i + 1}. {a}" for i, a in enumerate(anomalies)]
    return "\n".join(lines)


def get_log_error_events() -> str:
    """
    Return ERROR and CRITICAL log events from the incident log.

    Use this tool to see the specific error messages that occurred,
    which services were involved, and when failures began.

    Returns:
        List of error/critical log events with timestamp and service.
    """
    if _state is None:
        return "No incident state loaded."

    structured = _state.structured_events
    if not structured:
        return "No structured events available. Run the parser first."

    errors = [e for e in structured if e.get("level") in ("ERROR", "CRITICAL")]
    if not errors:
        return "No ERROR or CRITICAL events found in the log."

    lines = []
    for e in errors[:20]:  # Cap at 20 to stay within context
        lines.append(
            f"[{e.get('timestamp', '?')}] {e.get('level')} "
            f"[{e.get('service', '?')}] {e.get('message', '')}"
        )
    return "\n".join(lines)


def get_affected_services() -> str:
    """
    Return the list of microservices mentioned in the incident log.

    Use this tool to understand the blast radius of the incident.

    Returns:
        Comma-separated list of service names seen in log entries.
    """
    if _state is None:
        return "No incident state loaded."

    structured = _state.structured_events
    if not structured:
        return "No structured events available."

    services = sorted({e.get("service", "") for e in structured if e.get("service")})
    if not services:
        return "No service names found in structured events."

    return ", ".join(services)


def get_redacted_log_sample() -> str:
    """
    Return the first 30 lines of the redacted incident log.

    Use this tool to get raw context from the log when anomaly summaries
    are insufficient to understand the incident pattern.

    Returns:
        First 30 lines of the redacted log content.
    """
    if _state is None or _state.redacted_log is None:
        return "No redacted log available."

    lines = _state.redacted_log.redacted_content.splitlines()[:30]
    return "\n".join(lines)


def record_triage_finding(severity: str, summary: str) -> str:
    """
    Record a triage finding into the incident state.

    Call this tool once you have analysed the anomalies and determined
    the incident severity and a brief root cause summary.

    Args:
        severity: One of 'low', 'medium', 'high', 'critical'.
        log_summary: One-sentence summary of the root cause.

    Returns:
        Confirmation message.
    """
    if _state is None:
        return "Error: no incident state loaded."

    from src.core.entities import Severity, IncidentStatus

    sev_map = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    sev = sev_map.get(severity.lower(), Severity.HIGH)
    _state.update_severity(sev)
    _state.update_status(IncidentStatus.TRIAGING)
    _state.log_action(
        agent="triage_agent",
        action="triage_finding_recorded",
        details={"severity": severity, "summary": summary},
    )
    return f"Triage finding recorded. Severity set to {sev.value}. Summary: {summary}"
