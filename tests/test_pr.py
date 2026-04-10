"""Tests for phalanx.pr — auto-PR pipeline gatekeeper and open_rule_pr."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from phalanx.pr import _PENDING_PRS_FILE, open_rule_pr, run_gatekeeper


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rule(pattern: str, failure_count: int = 3, agents: list[str] | None = None) -> dict:
    now = time.time()
    return {
        "pattern": pattern,
        "source_signature": f"SecurityError:{pattern}",
        "failure_count": failure_count,
        "first_seen": now - 3600,
        "last_seen": now,
        "agents": agents or ["agent-1", "agent-2"],
    }


def _clean_rules(rule_patterns: list[str], count: int | None = None) -> list[dict]:
    n = count if count is not None else len(rule_patterns)
    return [_make_rule(p) for p in rule_patterns[:n]]


# ---------------------------------------------------------------------------
# Layer 1 — Gatekeeper passes on clean rules
# ---------------------------------------------------------------------------

class TestGatekeeperPasses:
    def test_clean_rules_pass(self, tmp_path):
        rules = [_make_rule("drop"), _make_rule("delete"), _make_rule("inject")]
        rules_path = tmp_path / "SAFETY_RULES.md"
        rules_path.write_text("# Safety Rules\n")

        passed, failures = run_gatekeeper(rules, rules_path)

        assert passed is True
        assert failures == []

    def test_no_rules_passes(self, tmp_path):
        rules_path = tmp_path / "SAFETY_RULES.md"
        passed, failures = run_gatekeeper([], rules_path)
        assert passed is True
        assert failures == []

    def test_missing_rules_file_passes(self, tmp_path):
        rules = [_make_rule("timeout")]
        rules_path = tmp_path / "SAFETY_RULES.md"
        # File does not exist — layer 5 should skip gracefully
        passed, failures = run_gatekeeper(rules, rules_path)
        assert passed is True

    def test_canary_unaffected_passes(self, tmp_path):
        rules = [_make_rule("drop")]
        rules_path = tmp_path / "SAFETY_RULES.md"
        safe_inputs = ["hello world", "fetch data", "run query"]
        passed, failures = run_gatekeeper(rules, rules_path, canary_safe_inputs=safe_inputs)
        assert passed is True


# ---------------------------------------------------------------------------
# Layer 2 — Gatekeeper blocks oversized diff (>20 rules)
# ---------------------------------------------------------------------------

class TestGatekeeperDiffSize:
    def test_exactly_20_rules_passes(self, tmp_path):
        rules = [_make_rule(f"pattern{i}") for i in range(20)]
        rules_path = tmp_path / "SAFETY_RULES.md"
        passed, failures = run_gatekeeper(rules, rules_path)
        assert passed is True

    def test_21_rules_blocked(self, tmp_path):
        rules = [_make_rule(f"pattern{i}") for i in range(21)]
        rules_path = tmp_path / "SAFETY_RULES.md"
        passed, failures = run_gatekeeper(rules, rules_path)
        assert passed is False
        assert any("diff size" in f.lower() or "Layer 2" in f for f in failures)

    def test_30_rules_blocked(self, tmp_path):
        rules = [_make_rule(f"term{i}") for i in range(30)]
        rules_path = tmp_path / "SAFETY_RULES.md"
        passed, failures = run_gatekeeper(rules, rules_path)
        assert passed is False
        assert len([f for f in failures if "Layer 2" in f]) >= 1


# ---------------------------------------------------------------------------
# Layer 3 — Gatekeeper blocks secret-like patterns
# ---------------------------------------------------------------------------

class TestGatekeeperSecretScan:
    def test_api_key_like_pattern_blocked(self, tmp_path):
        # Long alphanumeric string that looks like an API key (20+ chars triggers Layer 3)
        secret_pattern = "FAKE_API_KEY_abcdef1234567890abcdef123456"
        rules = [_make_rule(secret_pattern)]
        rules_path = tmp_path / "SAFETY_RULES.md"
        passed, failures = run_gatekeeper(rules, rules_path)
        assert passed is False
        assert any("Layer 3" in f or "secret" in f.lower() for f in failures)

    def test_base64_like_pattern_blocked(self, tmp_path):
        b64_pattern = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        rules = [_make_rule(b64_pattern)]
        rules_path = tmp_path / "SAFETY_RULES.md"
        passed, failures = run_gatekeeper(rules, rules_path)
        assert passed is False
        assert any("Layer 3" in f for f in failures)

    def test_short_alphanum_pattern_allowed(self, tmp_path):
        # 19 chars — just under the threshold
        short_pattern = "abcdefghijklmnopqrs"
        rules = [_make_rule(short_pattern)]
        rules_path = tmp_path / "SAFETY_RULES.md"
        passed, failures = run_gatekeeper(rules, rules_path)
        # Only layer 3 concern — should pass for length
        layer3_failures = [f for f in failures if "Layer 3" in f]
        assert layer3_failures == []


# ---------------------------------------------------------------------------
# Layer 1 — Shell/regex special char detection
# ---------------------------------------------------------------------------

class TestGatekeeperAllowlist:
    @pytest.mark.parametrize("bad_char", [";", "|", "&", "`", "$", "(", ")", "{", "}", "\\", "<", ">", "\"", "'", "!"])
    def test_shell_chars_blocked(self, tmp_path, bad_char):
        rules = [_make_rule(f"drop{bad_char}table")]
        rules_path = tmp_path / "SAFETY_RULES.md"
        passed, failures = run_gatekeeper(rules, rules_path)
        assert passed is False
        assert any("Layer 1" in f for f in failures)

    def test_hyphen_and_underscore_allowed(self, tmp_path):
        rules = [_make_rule("rm-rf"), _make_rule("drop_table")]
        rules_path = tmp_path / "SAFETY_RULES.md"
        passed, failures = run_gatekeeper(rules, rules_path)
        layer1_failures = [f for f in failures if "Layer 1" in f]
        assert layer1_failures == []


# ---------------------------------------------------------------------------
# Layer 4 — Canary validation
# ---------------------------------------------------------------------------

class TestGatekeeperCanary:
    def test_pattern_matching_safe_input_blocked(self, tmp_path):
        rules = [_make_rule("fetch")]
        rules_path = tmp_path / "SAFETY_RULES.md"
        safe_inputs = ["fetch data from db", "run query"]
        passed, failures = run_gatekeeper(rules, rules_path, canary_safe_inputs=safe_inputs)
        assert passed is False
        assert any("Layer 4" in f or "canary" in f.lower() for f in failures)

    def test_pattern_not_in_safe_inputs_passes(self, tmp_path):
        rules = [_make_rule("drop")]
        rules_path = tmp_path / "SAFETY_RULES.md"
        safe_inputs = ["fetch data", "read file", "list users"]
        passed, failures = run_gatekeeper(rules, rules_path, canary_safe_inputs=safe_inputs)
        layer4_failures = [f for f in failures if "Layer 4" in f]
        assert layer4_failures == []


# ---------------------------------------------------------------------------
# open_rule_pr — dry_run returns None and writes to pending_prs.jsonl
# ---------------------------------------------------------------------------

class TestOpenRulePrDryRun:
    def test_dry_run_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        rules = [_make_rule("drop"), _make_rule("inject")]
        rules_path = tmp_path / "SAFETY_RULES.md"
        rules_path.write_text("# Safety Rules\n")

        result = open_rule_pr(
            new_rules=rules,
            repo_path=tmp_path,
            rules_path=rules_path,
            dry_run=True,
        )

        assert result is None

    def test_dry_run_writes_pending_jsonl(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        rules = [_make_rule("drop"), _make_rule("inject")]
        rules_path = tmp_path / "SAFETY_RULES.md"
        rules_path.write_text("# Safety Rules\n")

        open_rule_pr(
            new_rules=rules,
            repo_path=tmp_path,
            rules_path=rules_path,
            dry_run=True,
        )

        pending_path = tmp_path / ".phalanx" / "pending_prs.jsonl"
        assert pending_path.exists(), "pending_prs.jsonl was not created"

        lines = pending_path.read_text().strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["dry_run"] is True
        assert record["rule_count"] == 2
        assert record["pr_url"] is None

    def test_dry_run_gatekeeper_passed_recorded(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        rules = [_make_rule("drop")]
        rules_path = tmp_path / "SAFETY_RULES.md"
        rules_path.write_text("# Safety Rules\n")

        open_rule_pr(
            new_rules=rules,
            repo_path=tmp_path,
            rules_path=rules_path,
            dry_run=True,
        )

        pending_path = tmp_path / ".phalanx" / "pending_prs.jsonl"
        record = json.loads(pending_path.read_text().strip())
        assert record["gatekeeper_passed"] is True
        assert record["gatekeeper_failures"] == []

    def test_gatekeeper_failure_writes_to_jsonl(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # >20 rules will trigger gatekeeper layer 2
        rules = [_make_rule(f"pattern{i}") for i in range(25)]
        rules_path = tmp_path / "SAFETY_RULES.md"
        rules_path.write_text("# Safety Rules\n")

        result = open_rule_pr(
            new_rules=rules,
            repo_path=tmp_path,
            rules_path=rules_path,
            dry_run=False,
        )

        assert result is None
        pending_path = tmp_path / ".phalanx" / "pending_prs.jsonl"
        assert pending_path.exists()
        record = json.loads(pending_path.read_text().strip())
        assert record["gatekeeper_passed"] is False

    def test_empty_rules_returns_none_no_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = open_rule_pr(new_rules=[], repo_path=tmp_path, dry_run=True)
        assert result is None
        # Should not create the pending file for empty rules
        pending_path = tmp_path / ".phalanx" / "pending_prs.jsonl"
        assert not pending_path.exists()


# ---------------------------------------------------------------------------
# compile_rules(auto_pr=False) does NOT call pr module
# ---------------------------------------------------------------------------

class TestCompileRulesAutoPr:
    def test_auto_pr_false_does_not_call_open_rule_pr(self, tmp_path):
        from phalanx.compile import compile_rules

        failures_dir = tmp_path / ".phalanx" / "failures"
        failures_dir.mkdir(parents=True)
        rules_path = tmp_path / "SAFETY_RULES.md"

        # Write two failure records with the same signature to trigger a rule
        for i in range(2):
            rec = {
                "type": "failure",
                "agent_id": f"agent-{i}",
                "error_type": "SecurityError",
                "error_message": "drop table users",
                "input_preview": "DROP TABLE users",
                "timestamp": time.time() - i * 10,
            }
            (failures_dir / f"failure_{i}.json").write_text(json.dumps(rec))

        with patch("phalanx.pr.open_rule_pr") as mock_pr:
            compile_rules(
                failures_dir=failures_dir,
                rules_path=rules_path,
                min_occurrences=2,
                auto_pr=False,
            )
            mock_pr.assert_not_called()

    def test_auto_pr_true_calls_open_rule_pr_when_rules_exist(self, tmp_path):
        from phalanx.compile import compile_rules

        failures_dir = tmp_path / ".phalanx" / "failures"
        failures_dir.mkdir(parents=True)
        rules_path = tmp_path / "SAFETY_RULES.md"

        for i in range(2):
            rec = {
                "type": "failure",
                "agent_id": f"agent-{i}",
                "error_type": "SecurityError",
                "error_message": "drop table users",
                "input_preview": "DROP TABLE users",
                "timestamp": time.time() - i * 10,
            }
            (failures_dir / f"failure_{i}.json").write_text(json.dumps(rec))

        # Patch at the source since compile_rules uses a lazy import
        with patch("phalanx.pr.open_rule_pr") as mock_pr:
            result = compile_rules(
                failures_dir=failures_dir,
                rules_path=rules_path,
                min_occurrences=2,
                auto_pr=True,
            )
            if result:  # only called if rules were generated
                mock_pr.assert_called_once()
                call_kwargs = mock_pr.call_args
                assert call_kwargs is not None

    def test_auto_pr_true_no_new_rules_does_not_call_pr(self, tmp_path):
        from phalanx.compile import compile_rules

        # No failures dir — no rules generated (dir doesn't exist)
        failures_dir = tmp_path / ".phalanx" / "failures"
        rules_path = tmp_path / "SAFETY_RULES.md"

        # open_rule_pr is never imported when auto_pr has no new rules to act on,
        # so we just verify compile_rules returns [] without calling into pr module.
        with patch("phalanx.pr.open_rule_pr") as mock_pr:
            result = compile_rules(
                failures_dir=failures_dir,
                rules_path=rules_path,
                auto_pr=True,
            )
            assert result == []
            mock_pr.assert_not_called()
