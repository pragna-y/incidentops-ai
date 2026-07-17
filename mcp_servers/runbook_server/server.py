"""
IncidentOps AI — Runbook MCP Server

Exposes SRE operational runbooks as MCP tools so the Researcher Agent
can query them during incident triage.

Tools:
    list_runbooks()              → list of available scenario names
    get_runbook(scenario)        → full runbook markdown
    search_runbook(scenario, q)  → runbook section matching a query

Usage:
    # stdio transport (default — used by ADK MCPToolset)
    python mcp_servers/runbook_server/server.py

    # SSE transport (for Docker / standalone HTTP access)
    python mcp_servers/runbook_server/server.py --transport sse --port 8090
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

# Suppress fastmcp/uvicorn INFO logs — only show WARNING and above.
# This keeps the subprocess stderr clean when used from the MCP client.
logging.getLogger("mcp").setLevel(logging.WARNING)
logging.getLogger("fastmcp").setLevel(logging.WARNING)
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("anyio").setLevel(logging.WARNING)

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).parent / "data"

mcp = FastMCP(
    name="incidentops-runbook-server",
    instructions=(
        "You are a runbook retrieval service for SRE incident triage. "
        "Use list_runbooks to discover available scenarios, "
        "get_runbook to fetch full procedures, "
        "and search_runbook to extract specific sections."
    ),
)

_SCENARIO_FILES: dict[str, str] = {
    "db_pool_exhaustion": "db_pool_exhaustion.md",
    "cpu_spike": "cpu_spike.md",
    "memory_leak": "memory_leak.md",
}


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def list_runbooks() -> list[str]:
    """
    List all available SRE runbook scenario names.

    Returns:
        List of scenario identifiers that can be passed to get_runbook().
    """
    return list(_SCENARIO_FILES.keys())


@mcp.tool()
def get_runbook(scenario: str) -> str:
    """
    Retrieve the full SRE runbook for a specific incident scenario.

    Args:
        scenario: Scenario name, one of: db_pool_exhaustion, cpu_spike,
                  memory_leak. Case-insensitive.

    Returns:
        Markdown content of the runbook, or an error message if not found.
    """
    key = scenario.lower().strip().replace(" ", "_").replace("-", "_")
    filename = _SCENARIO_FILES.get(key)

    if not filename:
        available = ", ".join(_SCENARIO_FILES.keys())
        return (
            f"No runbook found for scenario '{scenario}'.\n"
            f"Available scenarios: {available}"
        )

    path = DATA_DIR / filename
    if not path.exists():
        return f"Runbook file missing from server data directory: {filename}"

    return path.read_text(encoding="utf-8")


@mcp.tool()
def search_runbook(scenario: str, query: str) -> str:
    """
    Search a runbook for content related to a specific query term.

    Finds the section whose heading contains the query and returns that
    section's content. Falls back to the full runbook if no section matches.

    Args:
        scenario: Scenario name (same as get_runbook).
        query: Section heading keyword to find (e.g. 'Recovery', 'Diagnosis').

    Returns:
        Matching section markdown, or full runbook if no match.
    """
    content = get_runbook(scenario)

    if content.startswith("No runbook") or content.startswith("Runbook file"):
        return content  # Propagate error

    lines = content.splitlines()
    in_section = False
    result_lines: list[str] = []
    query_lower = query.lower()

    for line in lines:
        if line.startswith("## "):
            if query_lower in line.lower():
                in_section = True
            elif in_section:
                break  # End of the matched section

        if in_section:
            result_lines.append(line)

    if result_lines:
        return "\n".join(result_lines)

    # No exact section match — return full runbook
    return content


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="IncidentOps AI Runbook MCP Server"
    )
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "sse"],
        help="MCP transport: stdio (default) or sse (HTTP)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host for SSE transport (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8090,
        help="Port for SSE transport (default: 8090)",
    )
    args = parser.parse_args()

    if args.transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        mcp.run(transport="stdio")
