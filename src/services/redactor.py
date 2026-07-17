"""
OfflineRedactor — Fully offline, regex-based PII and secrets redactor.

This is the security gate that every log must pass through before any
content is sent to an LLM. It operates with zero network calls.

Redaction rules (applied in order):
    1. BEARER_TOKEN   — Authorization: Bearer <token>
    2. JWT            — Standalone base64url three-part JWTs
    3. AWS_ACCESS_KEY — AKIA... keys
    4. GCP_API_KEY    — AIza... keys
    5. SECRET_VALUE   — password=, secret=, api_key=, token=, auth= patterns
    6. EMAIL          — user@domain.tld
    7. IPV4_ADDRESS   — 0.0.0.0 – 255.255.255.255

Each detected value is replaced with [REDACTED:<RULE_NAME>] so the log
remains human-readable while being fully safe for LLM processing.

Extension point:
    To add Google Cloud DLP, create CloudDLPRedactor in dlp_redactor.py
    and implement the same RedactorProtocol. No caller changes required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from src.core.entities import RedactedLog, RedactionHit


@dataclass(frozen=True)
class RedactionRule:
    """
    A single named redaction rule.

    Attributes:
        name: Human-readable rule identifier used in audit output.
        pattern: Compiled regex that matches sensitive content.
        label: The label used in the [REDACTED:<label>] placeholder.
    """

    name: str
    pattern: re.Pattern[str]
    label: str


class OfflineRedactor:
    """
    Production-grade offline redactor for SRE incident logs.

    Implements RedactorProtocol — can be used anywhere the protocol is expected.
    Thread-safe: all state is in local variables, not instance state.
    """

    # ------------------------------------------------------------------
    # Rule definitions
    # Rules are applied in declaration order. More specific rules come first
    # to prevent partial matches by broader rules.
    # ------------------------------------------------------------------
    RULES: ClassVar[list[RedactionRule]] = [
        # 1. Bearer tokens — catches "Bearer <anything>" including JWTs in headers.
        #    Must come before standalone JWT rule so full "Bearer eyJ..." is replaced.
        RedactionRule(
            name="BEARER_TOKEN",
            pattern=re.compile(
                r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
                re.IGNORECASE,
            ),
            label="BEARER_TOKEN",
        ),
        # 2. Standalone JWTs — three-part base64url tokens not in a Bearer header.
        #    Pattern: eyJ<header>.eyJ<payload>.<signature>
        RedactionRule(
            name="JWT",
            pattern=re.compile(
                r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+"
            ),
            label="JWT",
        ),
        # 3. AWS IAM Access Key IDs — always start with AKIA, 20 chars total.
        RedactionRule(
            name="AWS_ACCESS_KEY",
            pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            label="AWS_ACCESS_KEY",
        ),
        # 4. GCP API Keys — start with AIza, 39 chars total.
        RedactionRule(
            name="GCP_API_KEY",
            pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
            label="GCP_API_KEY",
        ),
        # 5. Generic secret key=value patterns.
        #    Matches: password=, passwd=, secret=, api_key=, apikey=, token=,
        #             auth=, auth_token=, credential=, credentials= followed
        #             by a non-whitespace value of at least 4 chars.
        #    Quotes around the value are optional.
        RedactionRule(
            name="SECRET_VALUE",
            pattern=re.compile(
                r"(?i)(?:password|passwd|secret|api[_\-]?key|apikey|"
                r"token|auth(?:_token)?|credential(?:s)?)\s*[=:]\s*"
                r"['\"]?(?!\[REDACTED)([^\s'\"&;,\]]{4,})['\"]?",
                re.IGNORECASE,
            ),
            label="SECRET_VALUE",
        ),
        # 6. Email addresses — RFC 5321 simplified.
        RedactionRule(
            name="EMAIL",
            pattern=re.compile(
                r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
            ),
            label="EMAIL",
        ),
        # 7. IPv4 addresses — strict octet validation (0–255 each).
        RedactionRule(
            name="IPV4_ADDRESS",
            pattern=re.compile(
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
            ),
            label="IPV4_ADDRESS",
        ),
    ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def redact(self, text: str) -> RedactedLog:
        """
        Scan and redact all sensitive content from the given text.

        Rules are applied sequentially. Each rule operates on the output
        of the previous, so a value matched by an earlier rule cannot
        accidentally be re-matched by a later, broader rule.

        Args:
            text: Raw log content.

        Returns:
            RedactedLog containing the sanitized content and full audit.
        """
        if not text:
            return RedactedLog(
                original_byte_size=0,
                redacted_content="",
                redacted_byte_size=0,
            )

        original_size = len(text.encode("utf-8"))
        working_text = text
        all_hits: list[RedactionHit] = []
        rules_triggered: set[str] = set()

        for rule in self.RULES:
            working_text, hits = self._apply_rule(working_text, rule)
            if hits:
                all_hits.extend(hits)
                rules_triggered.add(rule.name)

        # Sort hits by line number for a clean audit display
        all_hits.sort(key=lambda h: h.line_number or 0)

        return RedactedLog(
            original_byte_size=original_size,
            redacted_content=working_text,
            redacted_byte_size=len(working_text.encode("utf-8")),
            hits=all_hits,
            rules_triggered=sorted(rules_triggered),
            total_redactions=len(all_hits),
            is_safe_for_llm=True,
        )

    def is_safe(self, text: str) -> bool:
        """
        Quick check — returns True if no sensitive data is detected.

        Slightly more efficient than calling redact() and checking
        total_redactions because it short-circuits on first match.

        Args:
            text: Any string to inspect.

        Returns:
            True if the text is clean, False if redaction would trigger.
        """
        for rule in self.RULES:
            if rule.pattern.search(text):
                return False
        return True

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _apply_rule(
        text: str, rule: RedactionRule
    ) -> tuple[str, list[RedactionHit]]:
        """
        Apply a single redaction rule to the text using re.sub with a callback.

        The callback captures match metadata (original value, line number)
        before replacing each match with the labeled placeholder.

        Returns:
            (modified_text, list_of_hits)
        """
        hits: list[RedactionHit] = []

        def _replace(match: re.Match[str]) -> str:
            original = match.group(0)
            # Approximate line number based on newlines before this match
            line_num = text[: match.start()].count("\n") + 1

            # Truncate long values for the audit preview
            preview = original if len(original) <= 50 else original[:47] + "..."

            hits.append(
                RedactionHit(
                    rule_name=rule.name,
                    original_preview=preview,
                    line_number=line_num,
                )
            )
            return f"[REDACTED:{rule.label}]"

        modified = rule.pattern.sub(_replace, text)
        return modified, hits
