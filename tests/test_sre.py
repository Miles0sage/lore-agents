"""Tests for Agent SRE — error budgets, SLOs, fleet health."""

from phalanx.governance.sre import (
    AgentSRE,
    ErrorBudget,
    ErrorBudgetConfig,
    SafetySLI,
    SLOStatus,
)


class TestSafetySLI:
    def test_initial_compliance(self):
        sli = SafetySLI(agent_id="a1")
        assert sli.compliance_rate == 1.0
        assert sli.violation_rate == 0.0

    def test_record_compliant(self):
        sli = SafetySLI(agent_id="a1")
        sli.record_action(compliant=True)
        assert sli.total_actions == 1
        assert sli.compliant_actions == 1
        assert sli.compliance_rate == 1.0

    def test_record_violation(self):
        sli = SafetySLI(agent_id="a1")
        sli.record_action(compliant=False)
        assert sli.violations == 1
        assert sli.violation_rate == 1.0

    def test_mixed_compliance(self):
        sli = SafetySLI(agent_id="a1")
        for _ in range(9):
            sli.record_action(compliant=True)
        sli.record_action(compliant=False)
        assert sli.compliance_rate == 0.9
        assert sli.violation_rate == 0.1


class TestErrorBudget:
    def test_initial_healthy(self):
        budget = ErrorBudget(agent_id="a1")
        assert budget.status == SLOStatus.HEALTHY
        assert budget.remaining_budget == 1.0

    def test_compliant_stays_healthy(self):
        budget = ErrorBudget(agent_id="a1")
        for _ in range(50):
            status = budget.record(compliant=True)
        assert status == SLOStatus.HEALTHY

    def test_violations_exhaust_budget(self):
        config = ErrorBudgetConfig(slo_target=0.90)  # 90% SLO = 10% error budget
        budget = ErrorBudget(agent_id="a1", config=config)
        # With 90% target: 100 actions allows 10 violations
        for _ in range(95):
            budget.record(compliant=True)
        budget.record(compliant=False)  # 1st violation — within budget
        assert budget.status in (SLOStatus.HEALTHY, SLOStatus.WARNING)

        # Burn remaining budget
        for _ in range(14):
            budget.record(compliant=False)  # 15 total violations on 110 actions
        assert budget.remaining_budget <= 0.0

    def test_auto_restrict(self):
        config = ErrorBudgetConfig(slo_target=0.99, auto_restrict=True)
        budget = ErrorBudget(agent_id="a1", config=config)
        # Rapid violations
        for _ in range(5):
            budget.record(compliant=True)
        for _ in range(5):
            budget.record(compliant=False)
        assert budget.status == SLOStatus.RESTRICTED

    def test_recovery(self):
        config = ErrorBudgetConfig(slo_target=0.99, auto_restrict=True, recovery_actions=5)
        budget = ErrorBudget(agent_id="a1", config=config)
        # Get restricted
        for _ in range(5):
            budget.record(compliant=False)
        assert budget.status == SLOStatus.RESTRICTED

        # Recover with consecutive compliant actions
        for _ in range(5):
            budget.record(compliant=True)
        assert budget.status == SLOStatus.WARNING  # Recovered from restricted

    def test_burn_rate(self):
        config = ErrorBudgetConfig(slo_target=0.99)
        budget = ErrorBudget(agent_id="a1", config=config)
        # Not enough data
        assert budget.burn_rate == 0.0
        # Normal operation
        for _ in range(100):
            budget.record(compliant=True)
        assert budget.burn_rate == 0.0  # No errors = 0 burn rate


class TestAgentSRE:
    def test_register_and_record(self):
        sre = AgentSRE()
        sre.register("a1")
        status = sre.record("a1", compliant=True)
        assert status == SLOStatus.HEALTHY

    def test_auto_register(self):
        sre = AgentSRE()
        # Should auto-register on first record
        status = sre.record("a1", compliant=True)
        assert status == SLOStatus.HEALTHY

    def test_status(self):
        sre = AgentSRE()
        assert sre.status("unknown") == SLOStatus.HEALTHY  # Default for unknown
        sre.register("a1")
        assert sre.status("a1") == SLOStatus.HEALTHY

    def test_fleet_health(self):
        sre = AgentSRE()
        sre.register("a1")
        sre.register("a2")
        sre.register("a3")
        sre.record("a1", compliant=True)
        sre.record("a2", compliant=True)
        sre.record("a3", compliant=True)
        health = sre.fleet_health()
        assert health["agents"] == 3
        assert health["healthy"] == 3

    def test_fleet_health_empty(self):
        sre = AgentSRE()
        health = sre.fleet_health()
        assert health["agents"] == 0

    def test_restricted_agents(self):
        config = ErrorBudgetConfig(slo_target=0.99, auto_restrict=True)
        sre = AgentSRE(config=config)
        sre.register("a1")
        sre.register("a2")
        # Hammer a1 with violations
        for _ in range(10):
            sre.record("a1", compliant=False)
        sre.record("a2", compliant=True)

        restricted = sre.restricted_agents()
        assert "a1" in restricted
        assert "a2" not in restricted

    def test_budget_access(self):
        sre = AgentSRE()
        assert sre.budget("unknown") is None
        sre.register("a1")
        budget = sre.budget("a1")
        assert budget is not None
        assert budget.agent_id == "a1"
