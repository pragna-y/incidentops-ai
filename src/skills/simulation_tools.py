"""
Simulation Tools — ADK agent skill functions for the Simulation Engine.

Provides the Planner Agent with tools to draft corrective action steps,
and the post-approval simulation engine with tools to execute a dry-run.

No real infrastructure changes are ever made. All actions produce a
structured SimulationReport showing what would have been executed.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

_state = None  # type: ignore[assignment]


def set_state(state) -> None:  # type: ignore[type-arg]
    """Called by the orchestrator to inject the shared IncidentState."""
    global _state
    _state = state


# ---------------------------------------------------------------------------
# Planning tools — used by the Planner Agent
# ---------------------------------------------------------------------------


def get_planning_context() -> str:
    """
    Return the full context needed to draft a corrective action plan.

    Combines anomalies, metrics, and retrieved runbook content into a
    single structured context string for the Planner Agent.

    Returns:
        JSON string with all planning inputs.
    """
    if _state is None:
        return json.dumps({"error": "No incident state loaded."})

    m = _state.metrics
    context = {
        "incident_id": _state.incident.id,
        "scenario": _state.incident.scenario,
        "severity": _state.incident.severity.value,
        "anomalies": _state.anomalies,
        "metrics": {
            "cpu_percent": m.cpu_percent,
            "memory_percent": m.memory_percent,
            "db_pool_utilization_percent": m.db_pool_utilization_percent,
            "error_rate_per_minute": m.error_rate_per_minute,
            "heap_used_gb": m.heap_used_gb,
        },
        "runbooks_available": len(_state.runbooks_retrieved),
        "runbook_titles": [b.get("title") for b in _state.runbooks_retrieved],
    }
    return json.dumps(context, indent=2)


def submit_action_plan(
    summary: str,
    action_steps_json: str,
    confidence_score: float,
) -> str:
    """
    Submit the finalised corrective action plan to the incident state.

    This is called by the Planner Agent after it has drafted the plan.
    The plan will be reviewed by the Reflector Agent before presentation
    to the human operator.

    Args:
        summary: One-paragraph description of the recommended approach.
        action_steps_json: JSON array of action step objects. Each must have:
            step_number (int), description (str), target_service (str),
            expected_impact (str), risk_level ('low'|'medium'|'high'),
            is_reversible (bool).
        confidence_score: Float from 0.0 to 1.0 representing plan confidence.

    Returns:
        Confirmation with the number of steps recorded.
    """
    if _state is None:
        return "Error: no incident state loaded."

    from src.core.entities import ActionStep, IncidentStatus

    try:
        raw_steps = json.loads(action_steps_json)
    except json.JSONDecodeError as exc:
        return f"Error: action_steps_json is not valid JSON — {exc}"

    steps = []
    for raw in raw_steps:
        steps.append(
            ActionStep(
                step_number=int(raw.get("step_number", 0)),
                description=str(raw.get("description", "")),
                target_service=str(raw.get("target_service", "unknown")),
                expected_impact=str(raw.get("expected_impact", "")),
                risk_level=str(raw.get("risk_level", "low")),
                is_reversible=bool(raw.get("is_reversible", True)),
            )
        )

    _state.recommendation.summary = summary
    _state.recommendation.action_steps = steps
    _state.recommendation.confidence_score = max(0.0, min(1.0, float(confidence_score)))
    _state.update_status(IncidentStatus.PLANNED)
    _state.log_action(
        agent="planner_agent",
        action="action_plan_submitted",
        details={"steps": len(steps), "confidence": confidence_score},
    )

    return (
        f"Action plan recorded: {len(steps)} steps, "
        f"confidence={confidence_score:.2f}. "
        "Ready for Reflector Agent review."
    )


# ---------------------------------------------------------------------------
# Reflection tools — used by the Reflector Agent
# ---------------------------------------------------------------------------


def get_plan_for_review() -> str:
    """
    Return the current action plan for reflection and critique.

    Use this tool to review the Planner Agent's proposed corrective
    actions before approving or requesting revision.

    Returns:
        JSON representation of the current recommendation.
    """
    if _state is None:
        return json.dumps({"error": "No incident state loaded."})

    rec = _state.recommendation
    steps = [
        {
            "step_number": s.step_number,
            "description": s.description,
            "target_service": s.target_service,
            "expected_impact": s.expected_impact,
            "risk_level": s.risk_level,
            "is_reversible": s.is_reversible,
        }
        for s in rec.action_steps
    ]
    return json.dumps(
        {
            "summary": rec.summary,
            "confidence_score": rec.confidence_score,
            "action_steps": steps,
            "step_count": len(steps),
        },
        indent=2,
    )


def submit_reflection(notes: list[str], confidence_adjustment: float = 0.0) -> str:
    """
    Submit the Reflector Agent's critique and optional confidence adjustment.

    The Reflector Agent calls this after reviewing the action plan.
    Notes should identify any risks, missing steps, or safety concerns.
    If the plan is sound, notes should confirm validation passed.

    Args:
        notes: List of reflection observations or validations.
        confidence_adjustment: Amount to add/subtract from confidence score
                               (e.g. -0.1 if a risk is found, +0.05 if
                               the plan aligns well with the runbook).

    Returns:
        Updated confidence score after adjustment.
    """
    if _state is None:
        return "Error: no incident state loaded."

    _state.recommendation.reflection_notes = notes
    old_score = _state.recommendation.confidence_score
    new_score = max(0.0, min(1.0, old_score + confidence_adjustment))
    _state.recommendation.confidence_score = new_score

    _state.log_action(
        agent="reflector_agent",
        action="reflection_submitted",
        details={
            "notes": notes,
            "confidence_before": old_score,
            "confidence_after": new_score,
        },
    )

    return (
        f"Reflection recorded. "
        f"Confidence adjusted: {old_score:.2f} -> {new_score:.2f}. "
        f"Notes: {len(notes)} observation(s)."
    )


def flag_for_escalation(reason: str) -> str:
    """
    Flag the incident for human escalation if the plan is unsafe or uncertain.

    Call this if confidence is too low, the plan contains high-risk steps
    with no safe mitigation, or the anomaly pattern is outside known runbooks.

    Args:
        reason: Plain English explanation of why escalation is required.

    Returns:
        Confirmation that escalation flag has been set.
    """
    if _state is None:
        return "Error: no incident state loaded."

    from src.core.entities import IncidentStatus

    _state.recommendation.requires_escalation = True
    _state.recommendation.escalation_reason = reason
    _state.update_status(IncidentStatus.ESCALATED)
    _state.log_action(
        agent="reflector_agent",
        action="escalation_flagged",
        details={"reason": reason},
    )
    return f"Escalation flag set. Reason: {reason}"


# ---------------------------------------------------------------------------
# Simulation engine — called after human approval
# ---------------------------------------------------------------------------


def run_simulation() -> str:
    """
    Execute a dry-run simulation of all approved corrective action steps.

    This function is called ONLY after the human operator has explicitly
    approved the recommendation. It produces a structured simulation report
    showing what would have been executed in a real environment.

    NO real infrastructure changes are made.

    Returns:
        JSON simulation report, or error if not yet approved.
    """
    if _state is None:
        return json.dumps({"error": "No incident state loaded."})

    from src.core.entities import (
        ApprovalStatus,
        IncidentStatus,
        SimulatedActionResult,
        SimulationReport,
    )

    rec = _state.recommendation
    if rec.approval_status != ApprovalStatus.APPROVED:
        return json.dumps({
            "error": "Simulation requires human approval. Status is currently: "
                     + rec.approval_status.value
        })

    results = []
    for step in rec.action_steps:
        results.append(
            SimulatedActionResult(
                step_number=step.step_number,
                action=step.description,
                target_service=step.target_service,
                status="Simulation Successful",
                expected_recovery=step.expected_impact,
                simulated_at=datetime.now(timezone.utc),
            )
        )

    report = SimulationReport(
        incident_id=_state.incident.id,
        scenario=_state.incident.scenario,
        results=results,
        overall_status="Simulation Complete",
    )

    _state.simulation_report = report
    _state.update_status(IncidentStatus.SIMULATED)
    _state.log_action(
        agent="simulation_engine",
        action="simulation_complete",
        details={"steps_simulated": len(results)},
    )

    # Serialise for return
    output = {
        "incident_id": report.incident_id,
        "scenario": report.scenario,
        "simulated_at": report.simulated_at.isoformat(),
        "overall_status": report.overall_status,
        "disclaimer": report.disclaimer,
        "results": [
            {
                "step": r.step_number,
                "action": r.action,
                "target": r.target_service,
                "status": r.status,
                "expected_recovery": r.expected_recovery,
            }
            for r in report.results
        ],
    }
    return json.dumps(output, indent=2)
