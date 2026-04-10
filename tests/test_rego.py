"""Tests for phalanx.rego — OPA/Rego policy generation."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from phalanx.rego import export_rego, rules_to_rego


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rule(pattern: str, failure_count: int = 3) -> dict:
    return {
        "pattern": pattern,
        "source_signature": f"SecurityError:{pattern}",
        "failure_count": failure_count,
        "agents": ["agent-1"],
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_empty_rules_returns_allow_all():
    rego = rules_to_rego([])
    assert "default allow := false" in rego
    assert "allow" in rego


def test_single_rule_in_deny_patterns():
    rules = [_make_rule("drop table")]
    rego = rules_to_rego(rules)
    assert '"drop table"' in rego


def test_multiple_rules():
    patterns = ["drop table", "rm -rf", "inject"]
    rules = [_make_rule(p) for p in patterns]
    rego = rules_to_rego(rules)
    for p in patterns:
        assert f'"{p}"' in rego


def test_rego_has_package_declaration():
    rego = rules_to_rego([_make_rule("exploit")])
    assert rego.startswith("package phalanx.safety")


def test_export_rego_writes_file(tmp_path):
    rules = [_make_rule("drop table"), _make_rule("rm -rf")]
    out = tmp_path / "policy.rego"
    result = export_rego(rules, out)
    assert result == out
    assert out.exists()
    content = out.read_text()
    assert "package phalanx.safety" in content
    assert '"drop table"' in content


def test_compile_rules_output_rego(tmp_path):
    """compile_rules(..., output='rego') should write a .rego file."""
    # Build a minimal failures directory with enough records to trigger rules.
    failures_dir = tmp_path / "failures"
    failures_dir.mkdir()
    for i in range(3):
        record = {
            "agent_id": "agent-1",
            "error_type": "SecurityError",
            "error_message": "drop table detected",
            "input_preview": "drop table users",
            "timestamp": time.time(),
        }
        (failures_dir / f"failure_{i}.json").write_text(json.dumps(record))

    rego_out = tmp_path / "p.rego"
    rules_path = tmp_path / "SAFETY_RULES.md"

    from phalanx.compile import compile_rules

    compile_rules(
        failures_dir=failures_dir,
        rules_path=rules_path,
        min_occurrences=2,
        use_darwin=False,
        output="rego",
        rego_path=rego_out,
    )

    assert rego_out.exists(), "Rego file was not created"
    content = rego_out.read_text()
    assert "package phalanx.safety" in content
