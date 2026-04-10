"""Tests for phalanx.audit — hash-chained audit log."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from phalanx.audit import AuditLog


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_log(tmp_path: Path) -> AuditLog:
    return AuditLog(db_path=tmp_path / "audit.db")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_genesis_entry(tmp_path):
    log = make_log(tmp_path)
    entry = log.append("test", "agent-1", {"k": "v"})
    assert entry.prev_hash == "GENESIS"


def test_chain_links(tmp_path):
    log = make_log(tmp_path)
    e1 = log.append("event_a", "agent-1", {"x": 1})
    e2 = log.append("event_b", "agent-1", {"x": 2})
    assert e2.prev_hash == e1.entry_hash


def test_verify_intact(tmp_path):
    log = make_log(tmp_path)
    log.append("event", "agent-1", {"a": 1})
    log.append("event", "agent-2", {"b": 2})
    assert log.verify() is True


def test_verify_tampered(tmp_path):
    db_path = tmp_path / "audit.db"
    log = AuditLog(db_path=db_path)
    log.append("event", "agent-1", {"a": 1})
    log.append("event", "agent-2", {"b": 2})

    # Tamper directly via raw sqlite
    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE audit_log SET payload = ? WHERE agent_id = ?", ('{"tampered": true}', "agent-1"))
    conn.commit()
    conn.close()

    assert log.verify() is False


def test_get_entries_filter(tmp_path):
    log = make_log(tmp_path)
    log.append("event", "agent-A", {"i": 1})
    log.append("event", "agent-B", {"i": 2})
    log.append("event", "agent-A", {"i": 3})

    results = log.get_entries(agent_id="agent-A")
    assert len(results) == 2
    assert all(e.agent_id == "agent-A" for e in results)


def test_export_pdf_data(tmp_path):
    log = make_log(tmp_path)
    import time
    start = time.time()
    log.append("event", "agent-1", {"x": 1})
    end = time.time() + 1

    data = log.export_pdf_data(period_start=start, period_end=end)

    assert "period" in data
    assert "summary" in data
    assert "compliance" in data
    assert "chain_verified" in data
    assert "entries" in data
    # Default frameworks present
    assert "OWASP" in data["compliance"]
    assert "SOC2" in data["compliance"]
    assert "EU_AI_ACT" in data["compliance"]


def test_record_policy_result(tmp_path):
    log = make_log(tmp_path)
    result = SimpleNamespace(agent_id="a", verdict="DENY", action="x")
    entry = log.record_policy_result(result)

    assert entry.agent_id == "a"
    assert entry.event_type == "policy_result"
    assert entry.payload["verdict"] == "DENY"
    assert entry.payload["action"] == "x"


def test_thread_safe(tmp_path):
    log = make_log(tmp_path)
    errors = []

    def worker():
        try:
            for i in range(5):
                log.append("thread_event", "agent-t", {"i": i})
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread errors: {errors}"
    assert log.verify() is True
    entries = log.get_entries(limit=1000)
    assert len(entries) == 50
