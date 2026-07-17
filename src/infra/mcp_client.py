"""
MCP Client — connects to the Runbook MCP Server and fetches runbooks.

Transport strategy:
    1. Primary: MCP stdio transport — spawns the server as a subprocess and
       communicates via the MCP protocol. This is the standard production path
       used by the ADK Researcher Agent (Milestone 3).

    2. Fallback: Direct local file read — used when the server cannot be started
       (e.g. in CI, unit tests, or when the mcp package is unavailable). The
       fallback is transparent to callers and is logged as a warning.

Usage:
    client = RunbookClient()
    content, source = client.get_runbook("db_pool_exhaustion")
    # source is "mcp" or "local"
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

# Absolute path to the MCP server script — works regardless of cwd
_SERVER_SCRIPT = Path(__file__).parent.parent.parent / "mcp_servers" / "runbook_server" / "server.py"
_DATA_DIR = Path(__file__).parent.parent.parent / "mcp_servers" / "runbook_server" / "data"

_SCENARIO_FILES: dict[str, str] = {
    "db_pool_exhaustion": "db_pool_exhaustion.md",
    "cpu_spike": "cpu_spike.md",
    "memory_leak": "memory_leak.md",
}


class RunbookClient:
    """
    Retrieves SRE runbooks from the MCP server, with a local file fallback.

    The client is intentionally synchronous at the public API level so it can
    be called from Typer CLI commands and non-async agent tools without extra
    ceremony. Async MCP I/O is handled internally via asyncio.run().
    """

    def get_runbook(self, scenario: str) -> tuple[str, str]:
        """
        Fetch the runbook for a scenario.

        Args:
            scenario: Scenario key (e.g. 'db_pool_exhaustion').

        Returns:
            (content, source) where source is "mcp" or "local".
        """
        key = self._normalise(scenario)

        try:
            # asyncio.run() creates a new event loop — safe from sync context.
            # If there is already a running event loop (e.g. inside an async
            # framework), use asyncio.get_event_loop().run_until_complete()
            # or call _fetch_via_mcp directly from an async caller.
            if sys.platform == "win32":
                # Windows requires ProactorEventLoop for subprocess support.
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

            content = asyncio.run(self._fetch_via_mcp(key))
            return content, "mcp"
        except Exception as exc:
            logger.warning(
                "MCP server unavailable (%s) — falling back to local file.", exc
            )
            return self._read_local(key), "local"

    def list_runbooks(self) -> list[str]:
        """Return the list of available runbook scenario keys."""
        return list(_SCENARIO_FILES.keys())

    # ------------------------------------------------------------------
    # Async MCP path
    # ------------------------------------------------------------------

    @staticmethod
    async def _fetch_via_mcp(scenario: str) -> str:
        """
        Call the MCP server via stdio transport and invoke get_runbook tool.

        The server is spawned as a child process; communication uses the
        standard MCP JSON-RPC protocol over stdin/stdout.
        """
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        server_params = StdioServerParameters(
            command=sys.executable,  # Use the same Python interpreter
            args=[str(_SERVER_SCRIPT)],
            env=None,
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "get_runbook", {"scenario": scenario}
                )
                # MCP response content is a list of TextContent objects
                return result.content[0].text  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # Local fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _read_local(scenario: str) -> str:
        """Read the runbook markdown file directly from the data directory."""
        filename = _SCENARIO_FILES.get(scenario)
        if not filename:
            available = ", ".join(_SCENARIO_FILES.keys())
            return (
                f"No runbook found for scenario '{scenario}'.\n"
                f"Available: {available}"
            )

        path = _DATA_DIR / filename
        if path.exists():
            return path.read_text(encoding="utf-8")

        return f"Runbook file not found: {filename}"

    @staticmethod
    def _normalise(scenario: str) -> str:
        """Convert scenario to canonical snake_case key."""
        return (
            scenario.lower()
            .strip()
            .replace(" ", "_")
            .replace("-", "_")
            .replace("—", "_")
        )
