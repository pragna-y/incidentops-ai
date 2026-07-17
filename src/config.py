"""
IncidentOps AI — Global Configuration

Uses pydantic-settings so every value can be overridden via environment
variable without changing code. Useful for Docker deployments.

Usage:
    from src.config import settings
    print(settings.model_name)

Environment overrides (prefix: INCIDENTOPS_):
    INCIDENTOPS_MODEL_NAME=gemini-2.0-flash
    INCIDENTOPS_CONFIDENCE_THRESHOLD=0.7
    INCIDENTOPS_MAX_LOG_SIZE_MB=10
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INCIDENTOPS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # LLM Model (Milestone 3)
    # ------------------------------------------------------------------
    model_name: str = "gemini-2.0-flash"
    """The Google ADK model to use for all agents."""

    # ------------------------------------------------------------------
    # Redaction
    # ------------------------------------------------------------------
    redaction_enabled: bool = True
    """
    Master switch for the redactor. Should ALWAYS be True in production.
    Only disable in controlled test environments when needed.
    """

    redactor_backend: str = "offline"
    """
    Redaction backend to use.
    'offline' — local regex engine (default, no cloud required)
    'dlp'     — Google Cloud DLP (future, implement CloudDLPRedactor)
    """

    # ------------------------------------------------------------------
    # Agent Behaviour (Milestone 3)
    # ------------------------------------------------------------------
    confidence_threshold: float = 0.75
    """
    Minimum recommendation confidence score (0.0–1.0) before escalating
    to a human SRE instead of proceeding with the planned actions.
    """

    max_reflection_iterations: int = 2
    """
    Maximum number of plan → critique → revise cycles before the
    reflector gives up and triggers human escalation.
    """

    # ------------------------------------------------------------------
    # Log Processing
    # ------------------------------------------------------------------
    max_log_size_mb: float = 20.0
    """Maximum log file size accepted by the CLI."""

    max_log_lines_for_llm: int = 500
    """
    Maximum lines passed to agents after redaction.
    Logs exceeding this are truncated with a summary header to
    prevent context window exhaustion.
    """

    # ------------------------------------------------------------------
    # MCP Server (Milestone 2)
    # ------------------------------------------------------------------
    runbook_server_url: str = "http://localhost:8090"
    """URL of the Runbook MCP server."""

    runbook_server_timeout_seconds: int = 10
    """Timeout for MCP runbook fetch requests."""

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    output_dir: str = "output"
    """Directory where redacted logs and simulation reports are saved."""

    verbose: bool = False
    """Enable verbose debug output in the CLI."""


# Singleton — import this everywhere
settings = Settings()
