"""
Incident State Ledger — the single shared state object for IncidentOps AI.

All agents read from and write to this object. It acts as:
  - The working memory for the triage session
  - An append-only audit trail of every agent action
  - The handoff record between CLI, agents, and the simulation engine

Design principle: State flows forward only. Agents never delete history.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from src.core.entities import (
    ApprovalStatus,
    AuditEntry,
    Incident,
    IncidentStatus,
    Recommendation,
    RedactedLog,
    RawLog,
    Severity,
    SimulationReport,
)


class MetricsSnapshot(BaseModel):
    """
    Point-in-time infrastructure metrics correlated with the incident.

    Populated by the Metrics Correlator (Milestone 2) and read by the
    Planner agent to inform corrective action recommendations.
    """

    cpu_percent: float | None = None
    memory_percent: float | None = None
    db_pool_utilization_percent: float | None = None
    error_rate_per_minute: float | None = None
    active_connections: int | None = None
    heap_used_gb: float | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @property
    def has_data(self) -> bool:
        """Returns True if any metric value has been populated."""
        return any(
            v is not None
            for v in [
                self.cpu_percent,
                self.memory_percent,
                self.db_pool_utilization_percent,
                self.error_rate_per_minute,
                self.active_connections,
                self.heap_used_gb,
            ]
        )


class IncidentState(BaseModel):
    """
    The central state object passed between all agents and pipeline stages.

    This is intentionally a flat, serializable structure — easy to inspect,
    persist, or pass over a message bus if needed in future.

    Lifecycle:
        CLI reads log → Redactor → Parser → TriageAgent → ResearcherAgent
        → PlannerAgent → ReflectorAgent → Human approval → Simulation
    """

    # -----------------------------------------------------------------------
    # Core incident record
    # -----------------------------------------------------------------------
    incident: Incident = Field(default_factory=Incident)

    # -----------------------------------------------------------------------
    # Log pipeline
    # -----------------------------------------------------------------------
    raw_log: RawLog | None = None
    redacted_log: RedactedLog | None = None

    # -----------------------------------------------------------------------
    # Analysis outputs (populated by Milestone 2 agents)
    # -----------------------------------------------------------------------
    anomalies: list[str] = Field(default_factory=list)
    structured_events: list[dict[str, Any]] = Field(default_factory=list)
    metrics: MetricsSnapshot = Field(default_factory=MetricsSnapshot)

    # -----------------------------------------------------------------------
    # Runbook context (populated by Milestone 2 MCP server)
    # -----------------------------------------------------------------------
    runbooks_retrieved: list[dict[str, str]] = Field(default_factory=list)

    # -----------------------------------------------------------------------
    # Planning & reflection (populated by Milestone 3 agents)
    # -----------------------------------------------------------------------
    recommendation: Recommendation = Field(default_factory=Recommendation)

    # -----------------------------------------------------------------------
    # Simulation output (populated by Milestone 4)
    # -----------------------------------------------------------------------
    simulation_report: SimulationReport | None = None

    # -----------------------------------------------------------------------
    # Audit trail — append-only
    # -----------------------------------------------------------------------
    audit_trail: list[AuditEntry] = Field(default_factory=list)

    # -----------------------------------------------------------------------
    # Convenience mutators
    # -----------------------------------------------------------------------

    def log_action(
        self,
        agent: str,
        action: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Record an agent action in both the audit trail and the incident timeline.
        Call this after every significant agent operation.
        """
        entry = AuditEntry(
            agent=agent,
            action=action,
            details=details or {},
        )
        self.audit_trail.append(entry)
        self.incident.add_event(f"{agent} → {action}")

    def update_status(self, status: IncidentStatus) -> None:
        """Transition the incident to a new status and record it."""
        old = self.incident.status
        self.incident.status = status
        self.log_action(
            agent="system",
            action="status_transition",
            details={"from": old, "to": status},
        )

    def update_severity(self, severity: Severity) -> None:
        """Update incident severity and record it."""
        old = self.incident.severity
        self.incident.severity = severity
        self.log_action(
            agent="system",
            action="severity_update",
            details={"from": old, "to": severity},
        )

    def add_anomaly(self, anomaly: str) -> None:
        """Record a detected anomaly."""
        self.anomalies.append(anomaly)

    def add_runbook(self, title: str, content: str, source: str = "mcp") -> None:
        """Attach a retrieved runbook snippet to the state."""
        self.runbooks_retrieved.append(
            {"title": title, "content": content, "source": source}
        )

    @property
    def is_ready_for_planning(self) -> bool:
        """True when triage is complete and agents can begin planning."""
        return (
            self.redacted_log is not None
            and len(self.anomalies) > 0
        )

    @property
    def is_ready_for_simulation(self) -> bool:
        """True when a human-approved recommendation exists."""
        return (
            self.recommendation.approval_status == ApprovalStatus.APPROVED
            and len(self.recommendation.action_steps) > 0
        )
