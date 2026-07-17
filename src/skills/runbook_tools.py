"""
Runbook Tools — ADK agent skill functions for the Researcher Agent.

Wraps the RunbookClient so the LLM can retrieve SRE runbooks via
MCP during agent execution. The Researcher Agent uses these tools to
find relevant operational procedures and attach them to the state for
the Planner Agent to use.
"""

from __future__ import annotations

_state = None  # type: ignore[assignment]


def set_state(state) -> None:  # type: ignore[type-arg]
    """Called by the orchestrator to inject the shared IncidentState."""
    global _state
    _state = state


# ---------------------------------------------------------------------------
# Tool functions — called by the Researcher Agent LLM
# ---------------------------------------------------------------------------


def list_available_runbooks() -> str:
    """
    List all SRE runbooks available from the runbook server.

    Use this tool first to discover which runbooks exist before
    fetching a specific one.

    Returns:
        Comma-separated list of available runbook scenario names.
    """
    from src.infra.mcp_client import RunbookClient
    client = RunbookClient()
    books = client.list_runbooks()
    return ", ".join(books)


def fetch_runbook(scenario: str) -> str:
    """
    Retrieve the full SRE runbook for the given incident scenario.

    The runbook contains diagnosis steps, recovery actions, escalation
    criteria, and post-incident checklists for the scenario.

    Args:
        scenario: Scenario name, e.g. 'db_pool_exhaustion', 'cpu_spike',
                  or 'memory_leak'.

    Returns:
        Full runbook markdown content, or error message if not found.
    """
    from src.infra.mcp_client import RunbookClient
    client = RunbookClient()
    content, source = client.get_runbook(scenario)

    # Record in state so Planner Agent can reference it
    if _state is not None and not content.startswith("No runbook"):
        _state.add_runbook(
            title=f"Runbook: {scenario}",
            content=content,
            source=source,
        )
        _state.log_action(
            agent="researcher_agent",
            action="runbook_retrieved",
            details={"scenario": scenario, "source": source, "chars": len(content)},
        )

    return content


def fetch_runbook_section(scenario: str, section: str) -> str:
    """
    Retrieve a specific section from an SRE runbook.

    Useful for focusing on just the Recovery Steps or Diagnosis
    sections without the full runbook length.

    Args:
        scenario: Scenario name (same as fetch_runbook).
        section: Section heading to retrieve, e.g. 'Recovery Steps',
                 'Diagnosis', 'Escalation', 'Post-Incident Checklist'.

    Returns:
        Section content markdown, or full runbook if section not found.
    """
    from src.infra.mcp_client import RunbookClient
    from mcp import ClientSession, StdioServerParameters  # type: ignore
    import asyncio
    import sys
    from pathlib import Path

    # Try MCP search_runbook tool first, fall back to local parsing
    try:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

        server_script = (
            Path(__file__).parent.parent.parent
            / "mcp_servers" / "runbook_server" / "server.py"
        )

        async def _search():
            server_params = StdioServerParameters(
                command=sys.executable,
                args=[str(server_script)],
            )
            async with __import__("mcp.client.stdio", fromlist=["stdio_client"]).stdio_client(server_params) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    result = await session.call_tool(
                        "search_runbook", {"scenario": scenario, "query": section}
                    )
                    return result.content[0].text  # type: ignore

        return asyncio.run(_search())
    except Exception:
        # Fallback: parse local file
        client = RunbookClient()
        content, _ = client.get_runbook(scenario)
        lines = content.splitlines()
        in_section = False
        result_lines: list[str] = []
        for line in lines:
            if line.startswith("## ") and section.lower() in line.lower():
                in_section = True
            elif line.startswith("## ") and in_section:
                break
            if in_section:
                result_lines.append(line)
        return "\n".join(result_lines) if result_lines else content


def get_current_runbooks() -> str:
    """
    Return a summary of runbooks already retrieved for this incident.

    The Planner Agent uses this to check what operational context is
    available before drafting corrective action steps.

    Returns:
        Summary of retrieved runbooks or a message if none fetched yet.
    """
    if _state is None:
        return "No incident state loaded."

    books = _state.runbooks_retrieved
    if not books:
        return "No runbooks retrieved yet. Use fetch_runbook() to retrieve one."

    summaries = []
    for b in books:
        preview = b.get("content", "")[:200].replace("\n", " ")
        summaries.append(
            f"[{b.get('title', 'Untitled')}] (source: {b.get('source', '?')}) — {preview}..."
        )
    return "\n\n".join(summaries)
