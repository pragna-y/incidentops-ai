"""
Interfaces (Protocols) for IncidentOps AI.

These define the contracts that service implementations must fulfill.
They are the extension points — to add a new backend (e.g. Google Cloud DLP),
simply implement the corresponding Protocol and swap it in via config.py.

No infrastructure code should ever import concrete implementations directly.
Always depend on the Protocol.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from src.core.entities import RedactedLog


@runtime_checkable
class RedactorProtocol(Protocol):
    """
    Contract for all log redaction implementations.

    Current implementation: OfflineRedactor (src/services/redactor.py)

    To add Google Cloud DLP support in a future milestone:
        1. Create src/services/dlp_redactor.py
        2. Implement CloudDLPRedactor(RedactorProtocol)
        3. Set REDACTOR_BACKEND=dlp in your environment
        4. The factory in config.py will resolve the correct implementation

    The caller (CLI, orchestrator) never changes — only the backend.
    """

    def redact(self, text: str) -> RedactedLog:
        """
        Redact all sensitive information from the given text.

        Args:
            text: Raw log content (may contain PII, secrets, tokens).

        Returns:
            RedactedLog with sanitized content and a full audit trail.
        """
        ...

    def is_safe(self, text: str) -> bool:
        """
        Quick boolean check — returns True if no sensitive data is detected.

        Useful for pre-flight checks before sending any content to an LLM.

        Args:
            text: Any string to inspect.

        Returns:
            True if no redaction rules would trigger, False otherwise.
        """
        ...
