"""
Integration tests for the M1+M2 pipeline (no API key required).

Tests the full non-ADK pipeline end-to-end:
    Log file -> Redactor -> Parser -> Correlator -> MCP Client -> State

These tests verify that all three incident scenarios flow correctly
through the pipeline and produce valid IncidentState objects.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core.state import IncidentState
from src.services.correlator import MetricCorrelator
from src.services.parser import LogParser
from src.services.redactor import OfflineRedactor

SAMPLE_LOGS = Path(__file__).parent.parent.parent / "sample_logs"

SCENARIOS = [
    ("db_pool_exhaustion.log", "db_pool_exhaustion"),
    ("cpu_spike.log", "cpu_spike"),
    ("memory_leak.log", "memory_leak"),
]


@pytest.fixture(scope="module")
def redactor() -> OfflineRedactor:
    return OfflineRedactor()


@pytest.fixture(scope="module")
def parser() -> LogParser:
    return LogParser()


@pytest.fixture(scope="module")
def correlator() -> MetricCorrelator:
    return MetricCorrelator()


# ---------------------------------------------------------------------------
# Pipeline tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("filename,scenario_key", SCENARIOS)
def test_full_pipeline_produces_valid_state(
    filename: str,
    scenario_key: str,
    redactor: OfflineRedactor,
    parser: LogParser,
    correlator: MetricCorrelator,
) -> None:
    """
    End-to-end pipeline test: log file -> state with anomalies and metrics.
    No LLM or API key required.
    """
    log_path = SAMPLE_LOGS / filename
    if not log_path.exists():
        pytest.skip(f"{filename} not found")

    # Step 1: Redact
    content = log_path.read_text(encoding="utf-8")
    redacted = redactor.redact(content)
    assert redacted.is_safe_for_llm
    assert redacted.total_redactions > 0

    # Step 2: Parse
    parse_result = parser.parse(redacted.redacted_content)
    assert parse_result.total_events > 0, "Expected parsed events"
    assert len(parse_result.anomalies) > 0, "Expected anomalies detected"
    assert len(parse_result.services_affected) > 0, "Expected services identified"

    # Step 3: Correlate
    metrics = correlator.correlate(scenario_key, parse_result.anomalies)
    assert metrics.has_data, "Expected metrics snapshot to have data"

    # Step 4: Build IncidentState
    from src.core.entities import RawLog
    raw_log = RawLog(
        path=str(log_path),
        content=content,
        line_count=content.count("\n") + 1,
        byte_size=log_path.stat().st_size,
        scenario=scenario_key,
    )

    state = IncidentState()
    state.incident.scenario = scenario_key
    state.raw_log = raw_log
    state.redacted_log = redacted
    state.anomalies = parse_result.anomalies
    state.metrics = metrics
    state.log_action("test", "pipeline_complete", {"scenario": scenario_key})

    # Verify state
    assert state.incident.scenario == scenario_key
    assert state.raw_log is not None
    assert state.redacted_log is not None
    assert state.is_ready_for_planning  # has redacted log + anomalies
    assert len(state.audit_trail) == 1
    assert len(state.incident.timeline) == 1


@pytest.mark.parametrize("filename,scenario_key", SCENARIOS)
def test_parser_detects_errors(
    filename: str,
    scenario_key: str,
    redactor: OfflineRedactor,
    parser: LogParser,
) -> None:
    """Verify each sample log has detectable ERROR/CRITICAL events."""
    log_path = SAMPLE_LOGS / filename
    if not log_path.exists():
        pytest.skip(f"{filename} not found")

    content = log_path.read_text(encoding="utf-8")
    redacted = redactor.redact(content)
    result = parser.parse(redacted.redacted_content)

    assert result.error_count > 0 or result.critical_count > 0, (
        f"{filename}: Expected at least one ERROR or CRITICAL event"
    )


@pytest.mark.parametrize("filename,scenario_key", SCENARIOS)
def test_metric_correlator_returns_scenario_data(
    filename: str,
    scenario_key: str,
    correlator: MetricCorrelator,
) -> None:
    """Verify correlator returns populated metrics for all known scenarios."""
    metrics = correlator.correlate(scenario_key, [])
    assert metrics.has_data, f"No metrics for scenario: {scenario_key}"


def test_mcp_client_fallback_reads_local_files() -> None:
    """
    Verify the MCP client fallback reads local runbook files when
    the MCP server is not running.
    """
    from src.infra.mcp_client import RunbookClient
    client = RunbookClient()

    for scenario_key in ["db_pool_exhaustion", "cpu_spike", "memory_leak"]:
        # _read_local directly (bypasses MCP server)
        content = client._read_local(scenario_key)
        assert len(content) > 100, f"Runbook for {scenario_key} seems empty"
        assert "## " in content, f"Runbook for {scenario_key} lacks section headers"
        assert "Recovery" in content, f"Runbook for {scenario_key} lacks Recovery section"


def test_state_is_not_ready_for_simulation_without_approval() -> None:
    """Verify simulation gate requires explicit human approval."""
    state = IncidentState()
    state.anomalies = ["some anomaly"]
    state.redacted_log = object()  # type: ignore
    assert not state.is_ready_for_simulation


def test_state_is_ready_for_simulation_after_approval() -> None:
    """Verify simulation gate passes after approval and steps exist."""
    from src.core.entities import ActionStep, ApprovalStatus

    state = IncidentState()
    state.recommendation.action_steps = [
        ActionStep(
            step_number=1,
            description="Restart service",
            target_service="api",
            expected_impact="Service recovers",
        )
    ]
    state.recommendation.approval_status = ApprovalStatus.APPROVED
    assert state.is_ready_for_simulation


def test_simulation_tools_run_without_llm() -> None:
    """Verify simulation engine runs correctly without ADK/LLM."""
    import json
    import src.skills.simulation_tools as st
    from src.core.entities import ActionStep, ApprovalStatus

    state = IncidentState()
    state.incident.scenario = "db_pool_exhaustion"
    state.recommendation.action_steps = [
        ActionStep(
            step_number=1,
            description="Increase HikariCP pool max to 100",
            target_service="db-service",
            expected_impact="Pool no longer exhausted",
            risk_level="low",
            is_reversible=True,
        ),
        ActionStep(
            step_number=2,
            description="Restart order-service pods",
            target_service="order-service",
            expected_impact="Stale connections flushed",
            risk_level="low",
            is_reversible=True,
        ),
    ]
    state.recommendation.approval_status = ApprovalStatus.APPROVED

    st.set_state(state)
    result_json = st.run_simulation()
    result = json.loads(result_json)

    assert result["overall_status"] == "Simulation Complete"
    assert len(result["results"]) == 2
    assert all(r["status"] == "Simulation Successful" for r in result["results"])
    assert "SIMULATION ONLY" in result["disclaimer"]
    assert state.simulation_report is not None
