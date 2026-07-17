"""
Unit tests for OfflineRedactor.

Test strategy:
    1. Each rule is tested in complete isolation with targeted strings.
    2. Mixed content tests verify that multiple rules fire in one pass.
    3. All three sample log files are verified — zero PII should survive.
    4. Edge cases: empty strings, already-clean content, boundary values.
    5. The is_safe() helper is verified separately.

Guiding principle: If any test in this file fails, the system MUST NOT
be used in production. PII leakage to an LLM is a critical failure.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from src.core.entities import RedactedLog
from src.services.redactor import OfflineRedactor

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_LOGS_DIR = Path(__file__).parent.parent.parent / "sample_logs"


@pytest.fixture(scope="module")
def redactor() -> OfflineRedactor:
    """A single OfflineRedactor instance reused across all tests."""
    return OfflineRedactor()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

REDACTED_PATTERN = re.compile(r"\[REDACTED:[A-Z_]+\]")


def assert_no_pii(result: RedactedLog, originals: list[str]) -> None:
    """Assert that none of the original sensitive values survive in the output."""
    for original in originals:
        assert original not in result.redacted_content, (
            f"PII LEAKAGE DETECTED: '{original}' survived redaction.\n"
            f"Redacted content:\n{result.redacted_content}"
        )


def assert_redaction_count(result: RedactedLog, rule: str, expected: int) -> None:
    """Assert that a specific rule triggered exactly N times."""
    actual = result.redaction_summary.get(rule, 0)
    assert actual == expected, (
        f"Rule '{rule}': expected {expected} hits, got {actual}.\n"
        f"All hits: {result.redaction_summary}"
    )


# ---------------------------------------------------------------------------
# Rule 1: Bearer Tokens
# ---------------------------------------------------------------------------


class TestBearerTokenRedaction:
    def test_standard_bearer_header(self, redactor: OfflineRedactor) -> None:
        text = "Authorization: Bearer abc123xyz456def789ghi012jkl345"
        result = redactor.redact(text)
        assert "abc123xyz456def789ghi012jkl345" not in result.redacted_content
        assert "[REDACTED:BEARER_TOKEN]" in result.redacted_content

    def test_bearer_with_jwt(self, redactor: OfflineRedactor) -> None:
        """JWT inside a Bearer header should be caught by the Bearer rule."""
        text = (
            "Authorization: Bearer "
            "eyJhbGciOiJSUzI1NiJ9."
            "eyJzdWIiOiJ1c2VyXzEyMyJ9."
            "SflKxwRJSMeKKF2QT4fwpMeJf"
        )
        result = redactor.redact(text)
        assert "eyJhbGciOiJSUzI1NiJ9" not in result.redacted_content
        assert "[REDACTED:BEARER_TOKEN]" in result.redacted_content

    def test_bearer_case_insensitive(self, redactor: OfflineRedactor) -> None:
        text = "authorization: bearer mytoken12345678"
        result = redactor.redact(text)
        assert "mytoken12345678" not in result.redacted_content

    def test_bearer_rule_is_recorded(self, redactor: OfflineRedactor) -> None:
        text = "Auth: Bearer mysupersecrettoken123456"
        result = redactor.redact(text)
        assert "BEARER_TOKEN" in result.rules_triggered

    def test_bearer_hit_recorded_in_audit(self, redactor: OfflineRedactor) -> None:
        text = "Authorization: Bearer token-for-audit-test-abc123"
        result = redactor.redact(text)
        assert result.total_redactions >= 1
        hit_rules = [h.rule_name for h in result.hits]
        assert "BEARER_TOKEN" in hit_rules


# ---------------------------------------------------------------------------
# Rule 2: JWT Tokens (standalone)
# ---------------------------------------------------------------------------


class TestJWTRedaction:
    JWT = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiJ1c2VyXzEyMyIsImV4cCI6OTk5OX0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"
    )

    def test_standalone_jwt_in_log_line(self, redactor: OfflineRedactor) -> None:
        text = f"Session token stored: {self.JWT}"
        result = redactor.redact(text)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result.redacted_content

    def test_jwt_in_key_value(self, redactor: OfflineRedactor) -> None:
        """A token=<jwt> assignment is caught by SECRET_VALUE before JWT."""
        text = f"cache_token={self.JWT}"
        result = redactor.redact(text)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result.redacted_content

    def test_jwt_rule_recorded(self, redactor: OfflineRedactor) -> None:
        text = f"Decoded: {self.JWT}"
        result = redactor.redact(text)
        # Either JWT or SECRET_VALUE should fire
        triggered = set(result.rules_triggered)
        assert triggered & {"JWT", "SECRET_VALUE", "BEARER_TOKEN"}


# ---------------------------------------------------------------------------
# Rule 3: AWS Access Keys
# ---------------------------------------------------------------------------


class TestAWSAccessKeyRedaction:
    AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

    def test_aws_key_in_log(self, redactor: OfflineRedactor) -> None:
        text = f"Using credentials: {self.AWS_KEY}"
        result = redactor.redact(text)
        assert self.AWS_KEY not in result.redacted_content
        assert "[REDACTED:AWS_ACCESS_KEY]" in result.redacted_content

    def test_aws_key_rule_recorded(self, redactor: OfflineRedactor) -> None:
        text = f"api_key_id={self.AWS_KEY}"
        result = redactor.redact(text)
        # aws key pattern OR secret_value pattern should fire
        assert result.total_redactions >= 1

    def test_partial_aws_pattern_not_matched(self, redactor: OfflineRedactor) -> None:
        """Only full AKIA + 16 uppercase/digit chars should match."""
        text = "AKIA_SHORT"  # Too short — should NOT match
        result = redactor.redact(text)
        assert result.total_redactions == 0


# ---------------------------------------------------------------------------
# Rule 4: GCP API Keys
# ---------------------------------------------------------------------------


class TestGCPAPIKeyRedaction:
    GCP_KEY = "AIzaSyTEST-FAKE-KEY-NOT-REAL-xxxxxxxxxxx"

    def test_gcp_key_in_log(self, redactor: OfflineRedactor) -> None:
        text = f"GCP API Key: {self.GCP_KEY}"
        result = redactor.redact(text)
        assert self.GCP_KEY not in result.redacted_content
        assert "[REDACTED:GCP_API_KEY]" in result.redacted_content

    def test_gcp_key_rule_recorded(self, redactor: OfflineRedactor) -> None:
        text = f"Authenticating with key={self.GCP_KEY}"
        result = redactor.redact(text)
        assert result.total_redactions >= 1


# ---------------------------------------------------------------------------
# Rule 5: Generic Secret Values
# ---------------------------------------------------------------------------


class TestSecretValueRedaction:
    def test_password_equals(self, redactor: OfflineRedactor) -> None:
        text = "password=Sup3rS3cr3tPa$$w0rd!"
        result = redactor.redact(text)
        assert "Sup3rS3cr3tPa$$w0rd!" not in result.redacted_content

    def test_secret_equals(self, redactor: OfflineRedactor) -> None:
        text = "secret=my-webhook-secret-abc123"
        result = redactor.redact(text)
        assert "my-webhook-secret-abc123" not in result.redacted_content

    def test_api_key_equals(self, redactor: OfflineRedactor) -> None:
        text = "api_key=sk-prod-a1b2c3d4e5f6789abcdef012345"
        result = redactor.redact(text)
        assert "sk-prod-a1b2c3d4e5f6789abcdef012345" not in result.redacted_content

    def test_token_equals(self, redactor: OfflineRedactor) -> None:
        text = "token=svc-order-tkn-aBcDeFgH1234567890"
        result = redactor.redact(text)
        assert "svc-order-tkn-aBcDeFgH1234567890" not in result.redacted_content

    def test_auth_colon_syntax(self, redactor: OfflineRedactor) -> None:
        text = 'auth: "my-secret-auth-value-xyz"'
        result = redactor.redact(text)
        assert "my-secret-auth-value-xyz" not in result.redacted_content

    def test_short_values_not_redacted(self, redactor: OfflineRedactor) -> None:
        """Values shorter than 4 chars should NOT trigger the rule."""
        text = "token=abc"  # Only 3 chars after =
        result = redactor.redact(text)
        # Should not match (value too short per our rule's {4,} quantifier)
        # Note: this verifies we don't over-redact config-style short values
        assert result.total_redactions == 0


# ---------------------------------------------------------------------------
# Rule 6: Email Addresses
# ---------------------------------------------------------------------------


class TestEmailRedaction:
    def test_standard_email(self, redactor: OfflineRedactor) -> None:
        text = "Alert sent to john.doe@acme.com"
        result = redactor.redact(text)
        assert "john.doe@acme.com" not in result.redacted_content
        assert "[REDACTED:EMAIL]" in result.redacted_content

    def test_service_account_email(self, redactor: OfflineRedactor) -> None:
        text = "sa=cache-admin@project-prod.iam.gserviceaccount.com"
        result = redactor.redact(text)
        assert "cache-admin@project-prod.iam.gserviceaccount.com" not in result.redacted_content

    def test_multiple_emails(self, redactor: OfflineRedactor) -> None:
        text = "CC: sre-lead@company.com platform-lead@company.com"
        result = redactor.redact(text)
        assert "sre-lead@company.com" not in result.redacted_content
        assert "platform-lead@company.com" not in result.redacted_content
        assert_redaction_count(result, "EMAIL", 2)

    def test_email_rule_recorded(self, redactor: OfflineRedactor) -> None:
        text = "owner=admin@internal.io"
        result = redactor.redact(text)
        assert "EMAIL" in result.rules_triggered


# ---------------------------------------------------------------------------
# Rule 7: IPv4 Addresses
# ---------------------------------------------------------------------------


class TestIPv4Redaction:
    def test_private_ip(self, redactor: OfflineRedactor) -> None:
        text = "Host 192.168.1.45 initiated connection"
        result = redactor.redact(text)
        assert "192.168.1.45" not in result.redacted_content
        assert "[REDACTED:IPV4_ADDRESS]" in result.redacted_content

    def test_loopback_ip(self, redactor: OfflineRedactor) -> None:
        text = "Listening on 127.0.0.1:8080"
        result = redactor.redact(text)
        assert "127.0.0.1" not in result.redacted_content

    def test_public_ip(self, redactor: OfflineRedactor) -> None:
        text = "Request from 203.0.113.42"
        result = redactor.redact(text)
        assert "203.0.113.42" not in result.redacted_content

    def test_invalid_ip_not_matched(self, redactor: OfflineRedactor) -> None:
        """999.999.999.999 is not a valid IPv4 — should not match."""
        text = "Not a real IP: 999.999.999.999"
        result = redactor.redact(text)
        assert result.total_redactions == 0

    def test_multiple_ips_in_one_line(self, redactor: OfflineRedactor) -> None:
        text = "Routing from 10.0.2.15 to 10.0.2.16 via 10.0.0.1"
        result = redactor.redact(text)
        assert "10.0.2.15" not in result.redacted_content
        assert "10.0.2.16" not in result.redacted_content
        assert "10.0.0.1" not in result.redacted_content
        assert_redaction_count(result, "IPV4_ADDRESS", 3)


# ---------------------------------------------------------------------------
# Mixed content tests
# ---------------------------------------------------------------------------


class TestMixedContentRedaction:
    def test_multiple_rule_types_in_one_string(self, redactor: OfflineRedactor) -> None:
        text = (
            "Auth failed for admin@corp.com from 10.0.1.5 "
            "using token=secret-webhook-token-abc123xyz"
        )
        result = redactor.redact(text)
        assert_no_pii(result, ["admin@corp.com", "10.0.1.5", "secret-webhook-token-abc123xyz"])
        assert len(result.rules_triggered) >= 2

    def test_full_alert_line(self, redactor: OfflineRedactor) -> None:
        """Simulate a realistic alerting log line with multiple PII types."""
        text = (
            "CRITICAL: DB pool exhausted on 10.0.1.200:5432 — "
            "notify sre-lead@company.com — "
            "password=Sup3rS3cr3t! — "
            "api_key=AKIAIOSFODNN7EXAMPLE"
        )
        result = redactor.redact(text)
        assert_no_pii(
            result,
            ["10.0.1.200", "sre-lead@company.com", "Sup3rS3cr3t!", "AKIAIOSFODNN7EXAMPLE"],
        )

    def test_redacted_tokens_are_not_double_redacted(self, redactor: OfflineRedactor) -> None:
        """Running redact() on already-redacted content should be idempotent."""
        text = "Connect from 192.168.1.1 user=test@example.com"
        first_pass = redactor.redact(text)
        second_pass = redactor.redact(first_pass.redacted_content)
        # Second pass should make zero additional redactions
        assert second_pass.total_redactions == 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_string(self, redactor: OfflineRedactor) -> None:
        result = redactor.redact("")
        assert result.total_redactions == 0
        assert result.redacted_content == ""
        assert result.is_safe_for_llm is True

    def test_clean_log_line(self, redactor: OfflineRedactor) -> None:
        text = "2024-01-15 09:23:00 INFO [api] Request processed in 42ms — status=200"
        result = redactor.redact(text)
        assert result.total_redactions == 0
        assert result.redacted_content == text

    def test_is_safe_returns_false_for_pii(self, redactor: OfflineRedactor) -> None:
        assert redactor.is_safe("user=root@example.com") is False

    def test_is_safe_returns_true_for_clean_text(self, redactor: OfflineRedactor) -> None:
        assert redactor.is_safe("Service healthy — uptime=99.9%") is True

    def test_audit_trail_line_numbers_are_positive(self, redactor: OfflineRedactor) -> None:
        text = "Line1\nLine2 — ip=10.0.0.1\nLine3 — email=test@test.com"
        result = redactor.redact(text)
        for hit in result.hits:
            assert (hit.line_number or 0) >= 1

    def test_redaction_summary_matches_hits(self, redactor: OfflineRedactor) -> None:
        text = "From 10.0.0.1 to 10.0.0.2 — user=admin@co.com"
        result = redactor.redact(text)
        total_from_summary = sum(result.redaction_summary.values())
        assert total_from_summary == result.total_redactions


# ---------------------------------------------------------------------------
# Sample log file integration tests
# ---------------------------------------------------------------------------


class TestSampleLogFiles:
    """
    Critical integration tests: verify that all three sample log files
    are fully redacted with zero PII surviving to the output.
    """

    # Known PII embedded in each sample log
    DB_POOL_PII = [
        "192.168.1.45",
        "john.doe@acme.com",
        "10.0.1.200",
        "admin@acme-internal.com",
        "eyJhbGciOiJSUzI1NiJ9",  # JWT fragment
        "192.168.1.89",
        "sre-oncall@company.com",
        "AKIAIOSFODNN7EXAMPLE",
        "Sup3rS3cr3tPa$$w0rd!",
        "sre-lead@company.com",
        "10.0.0.10",
    ]

    CPU_SPIKE_PII = [
        "10.0.2.15",
        "203.0.113.42",
        "engineer@ops-team.internal",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",  # JWT fragment
        "jane.smith@company.com",
        "10.0.0.5",
        "sk-prod-a1b2c3d4e5f6789abcdef012345",
        "deploy-bot@ci-system.internal",
        "platform-team@company.com",
    ]

    MEMORY_LEAK_PII = [
        "10.0.3.22",
        "cache-admin@project-prod.iam.gserviceaccount.com",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",  # JWT fragment in token=
        "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPc3bL0z_A",
        "sre-lead@company.com",
        "platform-lead@company.com",
        "10.0.3.1",
    ]

    @pytest.fixture(autouse=True)
    def check_logs_exist(self) -> None:
        if not SAMPLE_LOGS_DIR.exists():
            pytest.skip("sample_logs directory not found")

    def _load_and_redact(
        self, filename: str, redactor: OfflineRedactor
    ) -> RedactedLog:
        path = SAMPLE_LOGS_DIR / filename
        if not path.exists():
            pytest.skip(f"{filename} not found in sample_logs/")
        content = path.read_text(encoding="utf-8")
        return redactor.redact(content)

    def test_db_pool_exhaustion_zero_pii(self, redactor: OfflineRedactor) -> None:
        result = self._load_and_redact("db_pool_exhaustion.log", redactor)
        assert_no_pii(result, self.DB_POOL_PII)
        assert result.total_redactions > 0, "Expected redactions in DB pool log"

    def test_cpu_spike_zero_pii(self, redactor: OfflineRedactor) -> None:
        result = self._load_and_redact("cpu_spike.log", redactor)
        assert_no_pii(result, self.CPU_SPIKE_PII)
        assert result.total_redactions > 0, "Expected redactions in CPU spike log"

    def test_memory_leak_zero_pii(self, redactor: OfflineRedactor) -> None:
        result = self._load_and_redact("memory_leak.log", redactor)
        assert_no_pii(result, self.MEMORY_LEAK_PII)
        assert result.total_redactions > 0, "Expected redactions in memory leak log"

    def test_all_logs_produce_valid_redacted_log_objects(
        self, redactor: OfflineRedactor
    ) -> None:
        for filename in [
            "db_pool_exhaustion.log",
            "cpu_spike.log",
            "memory_leak.log",
        ]:
            result = self._load_and_redact(filename, redactor)
            assert result.is_safe_for_llm is True
            assert result.redacted_byte_size > 0
            assert isinstance(result.rules_triggered, list)
            assert len(result.rules_triggered) > 0, (
                f"{filename}: Expected at least one rule to trigger"
            )

    def test_redaction_summary_keys_are_known_rules(
        self, redactor: OfflineRedactor
    ) -> None:
        known_rules = {r.name for r in OfflineRedactor.RULES}
        for filename in [
            "db_pool_exhaustion.log",
            "cpu_spike.log",
            "memory_leak.log",
        ]:
            result = self._load_and_redact(filename, redactor)
            for rule_name in result.redaction_summary:
                assert rule_name in known_rules, (
                    f"Unknown rule '{rule_name}' found in {filename} redaction summary"
                )
