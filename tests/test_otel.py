"""Tests for phalanx.otel — graceful degradation and basic smoke tests."""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from unittest.mock import patch


def test_otel_functions_exist():
    """All 5 public functions are importable from phalanx.otel."""
    from phalanx import otel

    assert callable(otel.get_tracer)
    assert callable(otel.record_watch_event)
    assert callable(otel.record_policy_decision)
    assert callable(otel.watch_otel_hook)
    assert callable(otel.meter_fleet_stats)


def test_graceful_degradation_without_otel():
    """All functions are no-ops when opentelemetry is not installed."""
    # Remove cached otel module so we can re-import with patched imports
    mods_to_remove = [k for k in sys.modules if k.startswith("phalanx.otel") or k.startswith("opentelemetry")]
    saved = {k: sys.modules.pop(k) for k in mods_to_remove}

    # Block opentelemetry imports
    import builtins
    real_import = builtins.__import__

    def _blocked_import(name: str, *args, **kwargs):
        if name.startswith("opentelemetry"):
            raise ImportError(f"Mocked: {name} not available")
        return real_import(name, *args, **kwargs)

    try:
        with patch("builtins.__import__", side_effect=_blocked_import):
            import phalanx.otel as otel_mod
            importlib.reload(otel_mod)

            assert otel_mod._OTEL_AVAILABLE is False

            # All functions should be callable without raising
            tracer = otel_mod.get_tracer()
            assert tracer is not None

            otel_mod.record_watch_event({"agent_id": "a1", "type": "failure"})
            otel_mod.record_policy_decision(types.SimpleNamespace(verdict="allow", agent_id="a1"))

            hook = otel_mod.watch_otel_hook(Path("/tmp/phalanx-test-failures"))
            hook()

            otel_mod.meter_fleet_stats({"active_agents": 3, "total_failures": 1})
    finally:
        # Restore original modules
        for k in list(sys.modules.keys()):
            if k.startswith("phalanx.otel") or k.startswith("opentelemetry"):
                sys.modules.pop(k, None)
        sys.modules.update(saved)
        # Reload the real module
        import phalanx.otel  # noqa: F401


def test_record_watch_event_no_error():
    """record_watch_event does not raise regardless of otel availability."""
    from phalanx.otel import record_watch_event

    # Minimal event
    record_watch_event({})

    # Failure event
    record_watch_event({
        "agent_id": "agent-001",
        "action": "tool:call:execute_sql",
        "error_type": "OperationalError",
        "type": "failure",
    })

    # Block event
    record_watch_event({
        "agent_id": "agent-002",
        "action": "tool:call:shell",
        "type": "block",
    })

    # Injection event
    record_watch_event({
        "agent_id": "agent-003",
        "action": "tool:call:search",
        "confidence": 0.95,
        "type": "injection",
    })


def test_meter_fleet_stats_no_error():
    """meter_fleet_stats does not raise regardless of otel availability."""
    from phalanx.otel import meter_fleet_stats

    # Empty dict — should silently skip all
    meter_fleet_stats({})

    # Full stats dict
    meter_fleet_stats({
        "active_agents": 5,
        "total_failures": 42,
        "rules_count": 10,
        "blocked_count": 3,
    })

    # Partial stats — missing keys skipped silently
    meter_fleet_stats({"active_agents": 2})
