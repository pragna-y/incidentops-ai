"""
Core domain entities for IncidentOps AI.

These are pure Pydantic models with no infrastructure dependencies.
All agents and services operate on these types.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    DETECTED = "detected"
    TRIAGING = "triaging"
    PLANNED = "planned"
    AWAITING_APPROVAL = "awaiting_approval"
    SIMULATED = "simulated"
    ESCALATED = "escalated"
    RESOLVED = "resolved"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


# ---------------------------------------------------------------------------
# Redaction models
# ---------------------------------------------------------------------------


class RedactionHit(BaseModel):
    """Records a single redaction event — used in the audit trail."""

    rule_name: str
    """Which rule triggered (e.g. 'JWT', 'IPV4_ADDRESS')."""

    original_preview: str
    """Truncated preview of the original value (max 50 chars)."""

    line_number: int | None = None
    """Approximate line number in the original file."""

    @property
    def replacement(self) -> str:
        """The placeholder that replaced the original. Derived from rule_name."""
        return f"[REDACTED:{self.rule_name}]"


class RawLog(BaseModel):
    """Represents an uploaded, unprocessed log file."""

    path: str
    content: str
    line_count: int
    byte_size: int
    scenario: str = "unknown"
    uploaded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RedactedLog(BaseModel):
    """
    A sanitized log file that is safe to pass to any LLM.

    Every sensitive value has been replaced with a labeled placeholder.
    The audit trail shows exactly what was found and replaced.
    """

    original_byte_size: int
    redacted_content: str
    redacted_byte_size: int
    hits: list[RedactionHit] = Field(default_factory=list)
    rules_triggered: list[str] = Field(default_factory=list)
    total_redactions: int = 0
    is_safe_for_llm: bool = True

    @property
    def bytes_scrubbed(self) -> int:
        """Difference in size caused by redaction."""
        return self.original_byte_size - self.redacted_byte_size

    @property
    def redaction_summary(self) -> dict[str, int]:
        """Returns count of redactions per rule name."""
        summary: dict[str, int] = {}
        for hit in self.hits:
            summary[hit.rule_name] = summary.get(hit.rule_name, 0) + 1
        return summary



# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class AuditEntry(BaseModel):
    """Append-only record of an agent action or system event."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent: str
    action: str
    details: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Planning & Recommendation
# ---------------------------------------------------------------------------


class ActionStep(BaseModel):
    """A single proposed corrective action step."""

    step_number: int
    description: str
    target_service: str
    expected_impact: str
    risk_level: str = "low"  # low | medium | high
    is_reversible: bool = True


class Recommendation(BaseModel):
    """The final proposed corrective action plan produced by the Planner agent."""

    summary: str = ""
    action_steps: list[ActionStep] = Field(default_factory=list)
    confidence_score: float = 0.0  # 0.0 – 1.0
    reflection_notes: list[str] = Field(default_factory=list)
    requires_escalation: bool = False
    escalation_reason: str = ""
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approved_at: datetime | None = None


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------


class SimulatedActionResult(BaseModel):
    """Result of simulating a single corrective action step."""

    step_number: int
    action: str
    target_service: str
    status: str = "Simulation Successful"
    expected_recovery: str = ""
    simulated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SimulationReport(BaseModel):
    """
    Full dry-run simulation report.

    Generated after human approval. No real infrastructure changes are made.
    """

    incident_id: str
    scenario: str
    simulated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    results: list[SimulatedActionResult] = Field(default_factory=list)
    overall_status: str = "Simulation Complete"
    disclaimer: str = (
        "⚠  SIMULATION ONLY — No real infrastructure changes were executed. "
        "This report demonstrates what would have been performed."
    )


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------


class Incident(BaseModel):
    """The central incident record. Updated as triage progresses."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8].upper())
    scenario: str = "unknown"
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.DETECTED
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    timeline: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    def add_event(self, event: str) -> None:
        """Append a timestamped event to the timeline."""
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        self.timeline.append(f"[{ts}] {event}")
