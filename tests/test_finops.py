"""Tests for phalanx.finops — FinOps cost enforcement gateway."""
from __future__ import annotations
import time
import pytest
from pathlib import Path
from phalanx.finops import CostGate, BudgetPolicy, BudgetExceededError, CostEvent


@pytest.fixture
def gate(tmp_path):
    """CostGate backed by a temp DB."""
    return CostGate(db_path=tmp_path / "finops.db")


def test_no_policy_allows_all(gate):
    """No registered policy means no limit is enforced."""
    # Should not raise for any estimated cost
    gate.check("unknown-agent", estimated_cost=9999.0)


def test_daily_limit_enforced(gate):
    """Recording enough spend to exceed daily limit causes check() to raise."""
    gate.set_policy(BudgetPolicy(
        agent_id="agent-a",
        daily_limit_usd=1.0,
        per_task_limit_usd=10.0,
    ))
    # Record $0.90 of spend
    gate.record("agent-a", "t1", "gpt-4o-mini", cost_usd=0.90)
    # Another $0.20 would push total to $1.10 — over the $1.00 daily limit
    with pytest.raises(BudgetExceededError) as exc_info:
        gate.check("agent-a", estimated_cost=0.20)
    assert exc_info.value.agent_id == "agent-a"
    assert exc_info.value.limit_usd == 1.0


def test_per_task_limit_enforced(gate):
    """estimated_cost exceeding per_task_limit raises BudgetExceededError."""
    gate.set_policy(BudgetPolicy(
        agent_id="agent-b",
        daily_limit_usd=100.0,
        per_task_limit_usd=0.50,
    ))
    with pytest.raises(BudgetExceededError) as exc_info:
        gate.check("agent-b", estimated_cost=0.75)
    assert exc_info.value.limit_usd == 0.50


def test_soft_limit_no_raise(gate):
    """hard_stop=False does NOT raise even when limit is exceeded."""
    gate.set_policy(BudgetPolicy(
        agent_id="agent-soft",
        daily_limit_usd=0.10,
        per_task_limit_usd=0.05,
        hard_stop=False,
    ))
    # Record $0.09 — near daily limit
    gate.record("agent-soft", "t1", "gpt-4o-mini", cost_usd=0.09)
    # Should not raise even though estimated_cost pushes past daily limit
    gate.check("agent-soft", estimated_cost=0.50)  # no exception


def test_alert_callback_fires(gate):
    """Alert callback fires when daily spend reaches alert_threshold."""
    alerts = []

    def on_alert(agent_id, current_usd, limit_usd):
        alerts.append((agent_id, current_usd, limit_usd))

    gate.set_policy(BudgetPolicy(
        agent_id="agent-alert",
        daily_limit_usd=1.0,
        per_task_limit_usd=10.0,
        alert_threshold=0.8,
    ))
    gate.on_alert(on_alert)

    # Record $0.85 — past 80% threshold
    gate.record("agent-alert", "t1", "gpt-4o-mini", cost_usd=0.85)
    # check() triggers alert evaluation
    gate.check("agent-alert", estimated_cost=0.0)

    assert len(alerts) == 1
    assert alerts[0][0] == "agent-alert"
    assert alerts[0][2] == 1.0


def test_daily_spend_accumulates(gate):
    """Recording 3 events accumulates correctly in daily_spend()."""
    gate.record("agent-c", "t1", "gpt-4o-mini", cost_usd=0.10)
    gate.record("agent-c", "t2", "gpt-4o-mini", cost_usd=0.20)
    gate.record("agent-c", "t3", "gpt-4o-mini", cost_usd=0.15)
    total = gate.daily_spend("agent-c")
    assert abs(total - 0.45) < 1e-9


def test_fleet_summary(gate):
    """fleet_summary() returns correct structure for multiple agents."""
    gate.record("alpha", "t1", "gpt-4o-mini", cost_usd=0.10)
    gate.record("alpha", "t2", "gpt-4o-mini", cost_usd=0.05)
    gate.record("beta", "t1", "claude-haiku-4", cost_usd=0.20)

    summary = gate.fleet_summary()
    assert "date" in summary
    assert "agents" in summary
    assert "total_usd" in summary

    agent_ids = {a["agent_id"] for a in summary["agents"]}
    assert "alpha" in agent_ids
    assert "beta" in agent_ids

    alpha = next(a for a in summary["agents"] if a["agent_id"] == "alpha")
    assert alpha["task_count"] == 2
    assert abs(alpha["daily_spend_usd"] - 0.15) < 1e-9

    assert abs(summary["total_usd"] - 0.35) < 1e-9


def test_estimate_cost_known_model():
    """estimate_cost for a known model returns a reasonable positive value."""
    cost = CostGate.estimate_cost("claude-haiku-4", input_tokens=1000, output_tokens=500)
    # input: 1000/1000 * 0.00025 = 0.00025
    # output: 500/1000 * 0.00125 = 0.000625
    # total: 0.000875
    assert abs(cost - 0.000875) < 1e-9
    assert cost > 0


def test_estimate_cost_unknown_model():
    """estimate_cost for an unknown model falls back to gpt-4o-mini rates."""
    cost_unknown = CostGate.estimate_cost("totally-fake-model", input_tokens=1000, output_tokens=1000)
    cost_mini = CostGate.estimate_cost("gpt-4o-mini", input_tokens=1000, output_tokens=1000)
    assert abs(cost_unknown - cost_mini) < 1e-12


def test_cost_guard_decorator(gate):
    """cost_guard decorator records a cost event after the wrapped function runs."""
    gate.set_policy(BudgetPolicy(
        agent_id="decorated-agent",
        daily_limit_usd=10.0,
        per_task_limit_usd=5.0,
    ))

    call_count = {"n": 0}

    @gate.cost_guard("decorated-agent", model="gpt-4o-mini")
    def my_llm_call():
        call_count["n"] += 1
        return "result"

    result = my_llm_call()
    assert result == "result"
    assert call_count["n"] == 1

    # A cost event should have been recorded
    spend = gate.daily_spend("decorated-agent")
    assert spend > 0
