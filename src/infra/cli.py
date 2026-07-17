"""
IncidentOps AI — Command Line Interface

Entry point: `incidentops`

Commands:
    triage   Redact a log, parse anomalies, correlate metrics (Milestones 1-2)
    analyze  Full multi-agent triage with HITL approval + simulation (Milestones 3-4)

Usage:
    incidentops triage  --log sample_logs/db_pool_exhaustion.log
    incidentops analyze --log sample_logs/db_pool_exhaustion.log
    incidentops --help
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from src.config import settings
from src.core.entities import RawLog, RedactedLog
from src.core.state import IncidentState
from src.services.redactor import OfflineRedactor

# ---------------------------------------------------------------------------
# App & console setup
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="incidentops",
    help="IncidentOps AI -- Autonomous Incident Triage & Response Agent",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

# Force UTF-8 stdout to avoid Windows cp1252 legacy renderer issues.
_stdout_utf8 = io.TextIOWrapper(
    sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
)
console = Console(file=_stdout_utf8, highlight=False)
error_console = Console(stderr=True, style="bold red", highlight=False)

# Scenario name map derived from filenames
SCENARIO_MAP: dict[str, str] = {
    "db_pool_exhaustion": "DB Connection Pool Exhaustion",
    "cpu_spike": "CPU Spike — Thread Exhaustion",
    "memory_leak": "Memory Leak — JVM Heap OOM",
}


# ---------------------------------------------------------------------------
# Shared rendering helpers
# ---------------------------------------------------------------------------


def _render_header(subtitle: str = "Security Redaction Gate") -> None:
    """Render the IncidentOps AI banner."""
    banner = Text()
    banner.append("  IncidentOps AI", style="bold white")
    banner.append("  |  ", style="dim")
    banner.append(subtitle, style="bold cyan")

    console.print()
    console.print(
        Panel(banner, border_style="cyan", padding=(0, 4), expand=False)
    )
    console.print()


def _render_file_panel(raw_log: RawLog) -> None:
    """Render the file analysis info panel."""
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Key", style="dim", width=18)
    table.add_column("Value", style="bold white")
    table.add_row("Path", raw_log.path)
    table.add_row("Scenario", raw_log.scenario)
    table.add_row("Lines", f"{raw_log.line_count:,}")
    table.add_row("Original size", f"{raw_log.byte_size:,} bytes")

    console.print(
        Panel(table, title="[bold]>> Log File[/bold]", border_style="blue", padding=(0, 1))
    )
    console.print()


def _render_redaction_panel(result: RedactedLog) -> None:
    """Render the redaction summary panel."""
    if result.total_redactions == 0:
        console.print(
            Panel(
                "[green]OK  No sensitive data detected. Log is already safe.[/green]",
                title="[bold]>> Redaction[/bold]",
                border_style="green",
                padding=(0, 2),
            )
        )
        console.print()
        return

    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=box.ROUNDED,
        border_style="cyan",
        padding=(0, 1),
    )
    table.add_column("Rule", style="bold white", min_width=20)
    table.add_column("Count", justify="center", style="yellow", width=8)
    table.add_column("Sample", style="dim", min_width=30)

    summary = result.redaction_summary
    for rule_name, count in sorted(summary.items(), key=lambda x: -x[1]):
        sample = next(
            (h.original_preview for h in result.hits if h.rule_name == rule_name), "—"
        )
        table.add_row(_rule_badge(rule_name), str(count), f"[dim italic]{sample}[/dim italic]")

    console.print(
        Panel(
            table,
            title=f"[bold]>> Redaction[/bold] [dim]({result.total_redactions} total)[/dim]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    console.print()


def _render_anomaly_panel(anomalies: list[str], error_count: int, warn_count: int) -> None:
    """Render the anomaly detection panel."""
    if not anomalies:
        console.print(
            Panel(
                "[green]No anomalies detected. Log appears normal.[/green]",
                title="[bold]>> Anomalies[/bold]",
                border_style="green",
                padding=(0, 2),
            )
        )
        console.print()
        return

    body = Text()
    body.append(f"  Errors: ", style="dim")
    body.append(f"{error_count}", style="bold red")
    body.append("  |  Warnings: ", style="dim")
    body.append(f"{warn_count}\n\n", style="bold yellow")
    for i, a in enumerate(anomalies, 1):
        body.append(f"  {i}. ", style="bold yellow")
        body.append(f"{a}\n", style="white")

    console.print(
        Panel(
            body,
            title=f"[bold]>> Anomalies[/bold] [dim]({len(anomalies)} detected)[/dim]",
            border_style="yellow",
            padding=(0, 1),
        )
    )
    console.print()


def _render_metrics_panel(metrics) -> None:
    """Render the correlated infrastructure metrics panel."""
    if not metrics.has_data:
        return

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Metric", style="dim", width=28)
    table.add_column("Value", style="bold white")

    def _metric_row(label: str, value, unit: str = "", warn: float = 70, crit: float = 90) -> None:
        if value is None:
            return
        color = "green"
        if isinstance(value, (int, float)):
            if value >= crit:
                color = "red"
            elif value >= warn:
                color = "yellow"
        table.add_row(label, f"[{color}]{value}{unit}[/{color}]")

    _metric_row("CPU Utilisation", metrics.cpu_percent, "%")
    _metric_row("Memory Utilisation", metrics.memory_percent, "%")
    _metric_row("DB Pool Utilisation", metrics.db_pool_utilization_percent, "%")
    _metric_row("Error Rate", metrics.error_rate_per_minute, "/min", warn=10, crit=30)
    _metric_row("Active Connections", metrics.active_connections, "", warn=40, crit=48)
    _metric_row("JVM Heap Used", metrics.heap_used_gb, " GB", warn=3.0, crit=3.5)

    console.print(
        Panel(
            table,
            title="[bold]>> Infrastructure Metrics[/bold]",
            border_style="magenta",
            padding=(0, 1),
        )
    )
    console.print()


def _render_runbook_panel(content: str, source: str, scenario: str) -> None:
    """Render a brief runbook summary panel."""
    # Show first 6 lines (title + overview) only — full content is for agents
    preview_lines = [l for l in content.splitlines() if l.strip()][:6]
    preview = "\n".join(f"  {l}" for l in preview_lines)

    source_tag = "[green][MCP][/green]" if source == "mcp" else "[dim][local][/dim]"
    console.print(
        Panel(
            preview,
            title=f"[bold]>> Runbook Retrieved[/bold] {source_tag}",
            border_style="green",
            padding=(0, 1),
        )
    )
    console.print()


def _render_recommendation_panel(state: IncidentState) -> None:
    """Render the full agent recommendation panel."""
    rec = state.recommendation
    inc = state.incident

    # Incident header
    hdr = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    hdr.add_column("k", style="dim", width=20)
    hdr.add_column("v", style="bold white")
    sev_color = {"low": "green", "medium": "yellow", "high": "orange3", "critical": "red"}.get(
        inc.severity.value, "white"
    )
    hdr.add_row("Incident ID", inc.id)
    hdr.add_row("Scenario", inc.scenario)
    hdr.add_row("Severity", f"[{sev_color}]{inc.severity.value.upper()}[/{sev_color}]")
    conf = rec.confidence_score
    conf_color = "green" if conf >= 0.75 else "yellow" if conf >= 0.5 else "red"
    hdr.add_row("Confidence", f"[{conf_color}]{conf:.0%}[/{conf_color}]")

    console.print(
        Panel(hdr, title="[bold]>> Incident Summary[/bold]", border_style="white", padding=(0, 1))
    )
    console.print()

    # Action steps
    if rec.action_steps:
        step_body = Text()
        for step in rec.action_steps:
            risk_color = {"low": "green", "medium": "yellow", "high": "red"}.get(
                step.risk_level, "white"
            )
            rev_tag = "[dim]reversible[/dim]" if step.is_reversible else "[red]irreversible[/red]"
            step_body.append(f"\n  Step {step.step_number}: ", style="bold cyan")
            step_body.append(f"{step.description}\n", style="bold white")
            step_body.append(f"    Target: ", style="dim")
            step_body.append(f"{step.target_service}", style="white")
            step_body.append(f"  |  Risk: ", style="dim")
            step_body.append(f"{step.risk_level}", style=risk_color)
            step_body.append(f"  |  {rev_tag}\n", style="")
            step_body.append(f"    Impact: {step.expected_impact}\n", style="dim")

        console.print(
            Panel(
                step_body,
                title="[bold]>> Corrective Action Plan[/bold]",
                border_style="cyan",
                padding=(0, 1),
            )
        )
        console.print()

    # Reflection notes
    if rec.reflection_notes:
        notes_text = Text()
        for note in rec.reflection_notes:
            notes_text.append(f"  [*] {note}\n", style="dim green")
        console.print(
            Panel(
                notes_text,
                title="[bold]>> Reflector Agent Notes[/bold]",
                border_style="green",
                padding=(0, 1),
            )
        )
        console.print()


def _render_simulation_panel(state: IncidentState) -> None:
    """Render the simulation report."""
    report = state.simulation_report
    if report is None:
        return

    body = Text()
    body.append(f"\n  Incident:  {report.incident_id}\n", style="dim")
    body.append(f"  Scenario:  {report.scenario}\n", style="dim")
    body.append(f"  Simulated: {report.simulated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n", style="dim")

    for result in report.results:
        body.append(f"  Step {result.step_number}: ", style="bold white")
        body.append(f"{result.action}\n", style="white")
        body.append(f"    Target:   {result.target_service}\n", style="dim")
        body.append(f"    Status:   ", style="dim")
        body.append(f"{result.status}\n", style="bold green")
        body.append(f"    Expected: {result.expected_recovery}\n\n", style="dim")

    body.append(f"  {report.disclaimer}\n", style="bold yellow")

    console.print(
        Panel(
            body,
            title=f"[bold]>> Simulation Report[/bold] [dim]({report.overall_status})[/dim]",
            border_style="yellow",
            padding=(0, 1),
        )
    )
    console.print()


def _render_redacted_preview(result: RedactedLog, lines: int = 20) -> None:
    """Render a preview of the redacted log content."""
    preview = "\n".join(result.redacted_content.splitlines()[:lines])
    console.print(
        Panel(
            Text(preview),
            title=f"[bold]>> Redacted Preview[/bold] [dim](first {lines} lines)[/dim]",
            border_style="dim",
            padding=(0, 1),
        )
    )
    console.print()


def _rule_badge(rule_name: str) -> str:
    colors = {
        "BEARER_TOKEN": "red", "JWT": "red", "AWS_ACCESS_KEY": "red",
        "GCP_API_KEY": "red", "SECRET_VALUE": "orange3",
        "EMAIL": "yellow", "IPV4_ADDRESS": "blue",
    }
    color = colors.get(rule_name, "white")
    return f"[{color}][*][/{color}]  {rule_name}"


def _detect_scenario(path: Path) -> tuple[str, str]:
    """Return (scenario_key, display_name) from the log filename stem."""
    stem = path.stem.lower()
    display = SCENARIO_MAP.get(stem, stem.replace("_", " ").title())
    return stem, display


def _validate_log_file(log_path: Path) -> None:
    if not log_path.exists():
        error_console.print(f"\n  ERROR: File not found: {log_path}\n")
        raise typer.Exit(code=1)
    if not log_path.is_file():
        error_console.print(f"\n  ERROR: Path is not a file: {log_path}\n")
        raise typer.Exit(code=1)
    size_mb = log_path.stat().st_size / (1024 * 1024)
    if size_mb > settings.max_log_size_mb:
        error_console.print(
            f"\n  ERROR: File too large: {size_mb:.1f} MB "
            f"(limit: {settings.max_log_size_mb} MB)\n"
        )
        raise typer.Exit(code=1)


def _load_and_redact(log_path: Path, scenario: str) -> tuple[RawLog, RedactedLog]:
    """Read, build RawLog, and redact — shared by triage and analyze."""
    content = log_path.read_text(encoding="utf-8", errors="replace")
    line_count = content.count("\n") + 1
    byte_size = log_path.stat().st_size

    raw_log = RawLog(
        path=str(log_path),
        content=content,
        line_count=line_count,
        byte_size=byte_size,
        scenario=scenario,
    )
    _render_file_panel(raw_log)

    redactor = OfflineRedactor()
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Running security redaction engine...[/cyan]"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task("redacting", total=None)
        result = redactor.redact(content)

    return raw_log, result


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command(name="triage")
def triage(
    log: Path = typer.Option(..., "--log", "-l", help="Path to the incident log file."),
    save: bool = typer.Option(False, "--save", "-s", help="Save redacted log to output dir."),
    preview: bool = typer.Option(True, "--preview/--no-preview", help="Show redacted log preview."),
    preview_lines: int = typer.Option(20, "--preview-lines", min=5, max=100),
) -> None:
    """
    [bold cyan]Triage[/bold cyan] — Redact, parse, and correlate an incident log.

    Runs the M1+M2 pipeline: security redaction, log parsing,
    anomaly detection, metric correlation, and runbook retrieval.

    Examples:

        incidentops triage --log sample_logs/db_pool_exhaustion.log

        incidentops triage --log sample_logs/cpu_spike.log --save
    """
    _render_header("Security & Triage Pipeline")

    log_path = log.resolve()
    _validate_log_file(log_path)
    scenario_key, scenario = _detect_scenario(log_path)

    # Step 1: Redact
    raw_log, redacted = _load_and_redact(log_path, scenario)
    _render_redaction_panel(redacted)

    # Step 2: Parse anomalies
    from src.services.parser import LogParser

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Parsing log events and detecting anomalies...[/cyan]"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task("parsing", total=None)
        parse_result = LogParser().parse(redacted.redacted_content)

    _render_anomaly_panel(
        parse_result.anomalies, parse_result.error_count, parse_result.warning_count
    )

    # Step 3: Correlate metrics (use key for lookup)
    from src.services.correlator import MetricCorrelator
    metrics = MetricCorrelator().correlate(scenario_key, parse_result.anomalies)
    _render_metrics_panel(metrics)

    # Step 4: Fetch runbook via MCP (use key for lookup)
    from src.infra.mcp_client import RunbookClient
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Fetching runbook from MCP server...[/cyan]"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task("runbook", total=None)
        runbook_content, runbook_source = RunbookClient().get_runbook(scenario_key)

    _render_runbook_panel(runbook_content, runbook_source, scenario)

    # Step 5: Redacted log preview
    if preview:
        _render_redacted_preview(redacted, lines=preview_lines)

    # Step 6: Populate IncidentState
    state = IncidentState()
    state.incident.scenario = scenario
    state.raw_log = raw_log
    state.redacted_log = redacted
    state.anomalies = parse_result.anomalies
    state.structured_events = [
        {
            "line_number": e.line_number,
            "timestamp": e.timestamp,
            "level": e.level,
            "service": e.service,
            "message": e.message,
        }
        for e in parse_result.events
    ]
    state.metrics = metrics
    if runbook_content and not runbook_content.startswith("No runbook"):
        state.add_runbook(
            title=f"Runbook: {scenario}",
            content=runbook_content,
            source=runbook_source,
        )
    state.log_action(
        agent="cli",
        action="triage_complete",
        details={
            "redactions": redacted.total_redactions,
            "anomalies": len(parse_result.anomalies),
            "has_metrics": metrics.has_data,
        },
    )

    # Step 7: Save if requested
    if save:
        out_dir = Path(settings.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{log_path.stem}.redacted.log"
        out_path.write_text(redacted.redacted_content, encoding="utf-8")
        console.print(f"  [green]Saved[/green] redacted log -> [bold]{out_path}[/bold]\n")

    # Next step hint
    console.print(
        Panel(
            f"  Run [bold cyan]incidentops analyze --log {log}[/bold cyan] "
            "to launch the full Google ADK multi-agent pipeline.",
            border_style="dim",
            padding=(0, 2),
        )
    )
    console.print()


@app.command(name="analyze")
def analyze(
    log: Path = typer.Option(..., "--log", "-l", help="Path to the incident log file."),
    save_report: bool = typer.Option(
        False, "--save-report", help="Save the simulation report to output dir."
    ),
) -> None:
    """
    [bold cyan]Analyze[/bold cyan] — Full multi-agent incident triage with human approval.

    Runs the complete pipeline:
        Security Redaction -> Log Parser -> Metric Correlator ->
        MCP Runbook Server -> ADK Agents (Triage, Researcher, Planner, Reflector) ->
        Human Approval Gate -> Simulation Engine

    Requires: GOOGLE_API_KEY or GEMINI_API_KEY environment variable.

    Examples:

        incidentops analyze --log sample_logs/db_pool_exhaustion.log

        incidentops analyze --log sample_logs/memory_leak.log --save-report
    """
    _render_header("Full Multi-Agent Analysis")

    log_path = log.resolve()
    _validate_log_file(log_path)
    scenario_key, scenario = _detect_scenario(log_path)

    # ------------------------------------------------------------------
    # Phase 1: M1+M2 pipeline (redact, parse, correlate, fetch runbook)
    # ------------------------------------------------------------------
    raw_log, redacted = _load_and_redact(log_path, scenario)
    _render_redaction_panel(redacted)

    from src.services.parser import LogParser
    from src.services.correlator import MetricCorrelator
    from src.infra.mcp_client import RunbookClient

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Parsing + correlating...[/cyan]"),
        transient=True,
        console=console,
    ) as p:
        p.add_task("", total=None)
        parse_result = LogParser().parse(redacted.redacted_content)
        metrics = MetricCorrelator().correlate(scenario_key, parse_result.anomalies)

    _render_anomaly_panel(parse_result.anomalies, parse_result.error_count, parse_result.warning_count)
    _render_metrics_panel(metrics)

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Fetching runbook via MCP...[/cyan]"),
        transient=True,
        console=console,
    ) as p:
        p.add_task("", total=None)
        runbook_content, runbook_source = RunbookClient().get_runbook(scenario_key)

    _render_runbook_panel(runbook_content, runbook_source, scenario)

    # ------------------------------------------------------------------
    # Build initial IncidentState
    # ------------------------------------------------------------------
    state = IncidentState()
    state.incident.scenario = scenario
    state.raw_log = raw_log
    state.redacted_log = redacted
    state.anomalies = parse_result.anomalies
    state.structured_events = [
        {
            "line_number": e.line_number,
            "timestamp": e.timestamp,
            "level": e.level,
            "service": e.service,
            "message": e.message,
        }
        for e in parse_result.events
    ]
    state.metrics = metrics
    if runbook_content and not runbook_content.startswith("No runbook"):
        state.add_runbook(
            title=f"Runbook: {scenario}",
            content=runbook_content,
            source=runbook_source,
        )
    state.log_action("cli", "pre_agent_state_ready", {"anomalies": len(state.anomalies)})

    # ------------------------------------------------------------------
    # Phase 2: ADK Multi-Agent Pipeline
    # ------------------------------------------------------------------
    console.print(Rule("[bold cyan]Google ADK Multi-Agent Pipeline[/bold cyan]"))
    console.print()

    from src.agents.orchestrator import IncidentOrchestrator

    agent_display = {
        "triage_agent": "Triage Agent",
        "researcher_agent": "Researcher Agent (MCP)",
        "planner_agent": "Planner Agent",
        "reflector_agent": "Reflector Agent",
    }
    active_task_id = None

    def _on_progress(agent_name: str, status: str) -> None:
        nonlocal active_task_id
        display = agent_display.get(agent_name, agent_name)
        if status == "done":
            console.print(f"  [green][+][/green] {display} — done")
        else:
            console.print(f"  [cyan][-][/cyan] {display} — {status}")

    try:
        orchestrator = IncidentOrchestrator(state)
        state = orchestrator.run(progress_callback=_on_progress)
    except EnvironmentError as exc:
        error_console.print(f"\n{exc}\n")
        raise typer.Exit(code=1)
    except Exception as exc:
        error_console.print(f"\n  ERROR during agent pipeline: {exc}\n")
        raise typer.Exit(code=1)

    console.print()

    # ------------------------------------------------------------------
    # Phase 3: Show recommendation
    # ------------------------------------------------------------------
    _render_recommendation_panel(state)

    # Check for escalation
    if state.recommendation.requires_escalation:
        console.print(
            Panel(
                f"[red]Escalation Required[/red]\n\n"
                f"  Reason: {state.recommendation.escalation_reason}\n\n"
                f"  The Reflector Agent has determined this incident requires "
                f"manual SRE intervention.\n"
                f"  Please contact the on-call team immediately.",
                title="[bold red]>> ESCALATION[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )
        console.print()
        raise typer.Exit(code=0)

    # Check confidence threshold
    if state.recommendation.confidence_score < settings.confidence_threshold:
        console.print(
            Panel(
                f"[yellow]Confidence score {state.recommendation.confidence_score:.0%} is below "
                f"threshold {settings.confidence_threshold:.0%}.\n\n"
                f"Automatic escalation triggered. Contact the on-call SRE team.[/yellow]",
                title="[bold yellow]>> Low Confidence — Auto-Escalation[/bold yellow]",
                border_style="yellow",
                padding=(1, 2),
            )
        )
        console.print()
        raise typer.Exit(code=0)

    # ------------------------------------------------------------------
    # Phase 4: Human Approval Gate (HITL)
    # ------------------------------------------------------------------
    console.print(
        Panel(
            "[bold white]HUMAN APPROVAL REQUIRED[/bold white]\n\n"
            "  Review the corrective action plan above.\n\n"
            "  Type [bold green]yes[/bold green] to proceed with dry-run simulation.\n"
            "  Type [bold red]no[/bold red]  to escalate to the on-call SRE team.",
            title="[bold yellow]>> Approval Gate[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        )
    )
    console.print()

    approval = typer.prompt("  Decision (yes/no)").strip().lower()

    if approval not in ("yes", "y"):
        from src.core.entities import IncidentStatus
        state.update_status(IncidentStatus.ESCALATED)
        console.print(
            Panel(
                "[yellow]Plan rejected. Incident escalated to on-call SRE team.[/yellow]\n"
                "  Audit trail has been recorded.",
                border_style="yellow",
                padding=(0, 2),
            )
        )
        console.print()
        raise typer.Exit(code=0)

    # Record approval
    from src.core.entities import ApprovalStatus
    from datetime import datetime, timezone
    state.recommendation.approval_status = ApprovalStatus.APPROVED
    state.recommendation.approved_at = datetime.now(timezone.utc)
    state.log_action(
        "human_operator", "plan_approved",
        {"approved_at": state.recommendation.approved_at.isoformat()}
    )
    console.print(
        Panel(
            "[green]Plan approved. Running dry-run simulation...[/green]",
            border_style="green",
            padding=(0, 2),
        )
    )
    console.print()

    # ------------------------------------------------------------------
    # Phase 5: Simulation Engine
    # ------------------------------------------------------------------
    import src.skills.simulation_tools as st
    st.set_state(state)

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Running simulation engine...[/cyan]"),
        transient=True,
        console=console,
    ) as p:
        p.add_task("", total=None)
        st.run_simulation()

    _render_simulation_panel(state)

    # Optional: save report
    if save_report and state.simulation_report:
        out_dir = Path(settings.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        report_path = out_dir / f"{log_path.stem}.simulation_report.json"
        report_data = {
            "incident_id": state.simulation_report.incident_id,
            "scenario": state.simulation_report.scenario,
            "simulated_at": state.simulation_report.simulated_at.isoformat(),
            "overall_status": state.simulation_report.overall_status,
            "disclaimer": state.simulation_report.disclaimer,
            "results": [
                {
                    "step": r.step_number,
                    "action": r.action,
                    "target": r.target_service,
                    "status": r.status,
                    "expected_recovery": r.expected_recovery,
                }
                for r in state.simulation_report.results
            ],
            "audit_trail": [
                {"agent": a.agent, "action": a.action, "details": a.details}
                for a in state.audit_trail
            ],
        }
        report_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
        console.print(f"  [green]Report saved[/green] -> [bold]{report_path}[/bold]\n")

    console.print(
        Panel(
            "[green]Incident triage complete.[/green]\n\n"
            "  All agent actions are recorded in the audit trail.\n"
            "  No real infrastructure changes were made.",
            border_style="green",
            padding=(0, 2),
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
