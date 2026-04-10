"""Tests for phalanx.compliance module."""
from __future__ import annotations
import json
import tempfile
from pathlib import Path

import pytest

from phalanx.compliance import (
    export_json,
    export_markdown,
    generate_compliance_report,
    _load_rules,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(**kwargs) -> dict:
    return generate_compliance_report(**kwargs)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_generate_report_empty():
    """generate_compliance_report with no data returns a valid structure."""
    report = _make_report()
    assert isinstance(report, dict)
    assert report["summary"]["total_events"] == 0
    assert report["summary"]["total_failures"] == 0
    assert report["summary"]["total_audit_entries"] == 0


def test_report_has_required_keys():
    """All top-level required keys are present."""
    report = _make_report()
    for key in ("report_metadata", "summary", "compliance", "chain_verified"):
        assert key in report, f"Missing key: {key}"


def test_owasp_section():
    """OWASP framework is included when requested."""
    report = _make_report(frameworks=["OWASP"])
    assert "OWASP_Agentic_Top10" in report["compliance"]
    section = report["compliance"]["OWASP_Agentic_Top10"]
    assert section["framework"] == "OWASP Agentic Top 10 (2025)"
    assert "controls" in section


def test_soc2_section():
    """SOC2 framework is included when requested."""
    report = _make_report(frameworks=["SOC2"])
    assert "SOC2" in report["compliance"]
    section = report["compliance"]["SOC2"]
    assert section["framework"] == "SOC 2 Type II"
    assert "criteria" in section


def test_eu_ai_act_section():
    """EU_AI_ACT framework is included when requested."""
    report = _make_report(frameworks=["EU_AI_ACT"])
    assert "EU_AI_Act" in report["compliance"]
    section = report["compliance"]["EU_AI_Act"]
    assert "EU AI Act" in section["framework"]
    assert "articles" in section


def test_framework_filtering():
    """Requesting only SOC2 excludes OWASP and EU_AI_ACT sections."""
    report = _make_report(frameworks=["SOC2"])
    compliance = report["compliance"]
    assert "SOC2" in compliance
    assert "OWASP_Agentic_Top10" not in compliance
    assert "EU_AI_Act" not in compliance


def test_export_json():
    """export_json returns a valid JSON string."""
    report = _make_report()
    json_str = export_json(report)
    assert isinstance(json_str, str)
    parsed = json.loads(json_str)
    assert parsed["summary"]["total_events"] == 0


def test_export_markdown():
    """export_markdown returns a string containing the expected header."""
    report = _make_report()
    md = export_markdown(report)
    assert isinstance(md, str)
    assert "# Phalanx Compliance Report" in md


def test_report_hash_present():
    """report_hash in metadata is a non-empty string."""
    report = _make_report()
    report_hash = report["report_metadata"]["report_hash"]
    assert isinstance(report_hash, str)
    assert len(report_hash) > 0


def test_load_rules_missing_file():
    """_load_rules returns [] when the rules file does not exist."""
    missing = Path("/tmp/nonexistent_safety_rules_xyzzy.md")
    assert not missing.exists()
    rules = _load_rules(missing)
    assert rules == []


# ---------------------------------------------------------------------------
# Additional edge-case tests
# ---------------------------------------------------------------------------

def test_failures_dir_with_data(tmp_path):
    """Failures from JSON files in failures_dir are counted correctly."""
    import time
    failures_dir = tmp_path / "failures"
    failures_dir.mkdir()
    failure = {
        "agent_id": "agent-1",
        "event_type": "injection_detected",
        "timestamp": time.time(),
    }
    (failures_dir / "fail1.json").write_text(json.dumps(failure))

    report = generate_compliance_report(failures_dir=failures_dir)
    assert report["summary"]["total_failures"] == 1
    assert report["summary"]["injections_blocked"] == 1
    assert report["summary"]["active_agents"] == 1


def test_rules_loaded_from_file(tmp_path):
    """Safety rules are loaded from a SAFETY_RULES.md file."""
    rules_file = tmp_path / "SAFETY_RULES.md"
    rules_file.write_text("# Rules\n- DENY: exec shell\n- ALLOW: read files\n- COMMENT: ignored\n")
    report = generate_compliance_report(rules_path=rules_file)
    assert report["summary"]["safety_rules_active"] == 2


def test_export_json_to_file(tmp_path):
    """export_json writes to output_path when provided."""
    report = _make_report()
    out = tmp_path / "report.json"
    export_json(report, output_path=out)
    assert out.exists()
    parsed = json.loads(out.read_text())
    assert "summary" in parsed


def test_export_markdown_to_file(tmp_path):
    """export_markdown writes to output_path when provided."""
    report = _make_report()
    out = tmp_path / "report.md"
    export_markdown(report, output_path=out)
    assert out.exists()
    assert "# Phalanx Compliance Report" in out.read_text()


def test_all_frameworks_default():
    """Default frameworks list includes all three frameworks."""
    report = _make_report()
    compliance = report["compliance"]
    assert "OWASP_Agentic_Top10" in compliance
    assert "SOC2" in compliance
    assert "EU_AI_Act" in compliance


def test_chain_verified_false_without_audit_log():
    """chain_verified is False when no audit_log is provided."""
    report = _make_report()
    assert report["chain_verified"] is False
    assert report["summary"]["chain_verified"] is False


def test_period_days_reflected_in_metadata():
    """period_days is stored correctly in report_metadata."""
    report = _make_report(period_days=7)
    assert report["report_metadata"]["period_days"] == 7


def test_old_failures_excluded(tmp_path):
    """Failures older than period_days are not included."""
    import time
    failures_dir = tmp_path / "failures"
    failures_dir.mkdir()
    old_failure = {
        "agent_id": "old-agent",
        "event_type": "error",
        "timestamp": time.time() - (40 * 86400),  # 40 days ago
    }
    (failures_dir / "old.json").write_text(json.dumps(old_failure))
    report = generate_compliance_report(failures_dir=failures_dir, period_days=30)
    assert report["summary"]["total_failures"] == 0
