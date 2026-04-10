"""Tests for canary propagation of learned policies."""

import time

from phalanx.governance.types import ExecutionRing, IntentCategory
from phalanx.evolution.darwin import LearnedRule
from phalanx.evolution.propagator import (
    CanaryPropagator,
    PropagationRecord,
    PropagationStatus,
)


def _make_rule(
    rule_id: str = "lr_test_0",
    action_pattern: str = "bad:*",
    confidence: float = 0.8,
) -> LearnedRule:
    return LearnedRule(
        rule_id=rule_id,
        source_cluster_id="cl_test",
        action_pattern=action_pattern,
        intent_category=IntentCategory.DESTRUCTIVE_DATA,
        confidence=confidence,
        description="Test learned rule",
    )


class TestCanaryDeploy:
    def test_deploy_starts_canary(self):
        prop = CanaryPropagator()
        record = prop.deploy(_make_rule())
        assert record.status == PropagationStatus.CANARY
        assert record.current_ring == ExecutionRing.UNTRUSTED

    def test_deploy_creates_policy(self):
        prop = CanaryPropagator()
        record = prop.deploy(_make_rule())
        assert record.policy is not None
        assert "darwin:" in record.policy.name

    def test_multiple_deployments(self):
        prop = CanaryPropagator()
        prop.deploy(_make_rule("r1"))
        prop.deploy(_make_rule("r2"))
        assert len(prop.records) == 2


class TestCanaryEvaluation:
    def test_rollback_on_false_positives(self):
        prop = CanaryPropagator()
        rule = _make_rule()
        prop.deploy(rule)
        # Record many false positives
        for _ in range(5):
            prop.record_outcome(rule.rule_id, is_true_positive=False)
        status = prop.evaluate(rule.rule_id)
        assert status == PropagationStatus.ROLLED_BACK

    def test_stays_canary_without_enough_time(self):
        prop = CanaryPropagator(observation_window=300.0)  # 5 min
        rule = _make_rule()
        prop.deploy(rule)
        prop.record_outcome(rule.rule_id, is_true_positive=True)
        status = prop.evaluate(rule.rule_id)
        assert status == PropagationStatus.CANARY  # Not enough time

    def test_promotes_after_window(self):
        prop = CanaryPropagator(observation_window=0.0)  # Instant window
        rule = _make_rule()
        record = prop.deploy(rule)
        record.deployed_at = time.time() - 1  # 1 second ago
        prop.record_outcome(rule.rule_id, is_true_positive=True)
        status = prop.evaluate(rule.rule_id)
        assert status == PropagationStatus.EXPANDING
        assert record.current_ring == ExecutionRing.USER

    def test_double_promote_to_supervisor(self):
        prop = CanaryPropagator(observation_window=0.0)
        rule = _make_rule()
        record = prop.deploy(rule)
        record.deployed_at = time.time() - 1
        prop.record_outcome(rule.rule_id, is_true_positive=True)

        # First promote: Ring 3 -> Ring 2
        prop.evaluate(rule.rule_id)
        assert record.current_ring == ExecutionRing.USER

        # Second promote: Ring 2 -> Ring 1
        record.deployed_at = time.time() - 1
        prop.evaluate(rule.rule_id)
        assert record.current_ring == ExecutionRing.SUPERVISOR
        assert record.status == PropagationStatus.PROMOTED

    def test_evaluate_all(self):
        prop = CanaryPropagator(observation_window=0.0)
        r1 = _make_rule("r1")
        r2 = _make_rule("r2")
        rec1 = prop.deploy(r1)
        rec2 = prop.deploy(r2)
        rec1.deployed_at = time.time() - 1
        rec2.deployed_at = time.time() - 1
        prop.record_outcome("r1", is_true_positive=True)
        prop.record_outcome("r2", is_true_positive=True)
        results = prop.evaluate_all()
        assert len(results) == 2

    def test_no_auto_promote(self):
        prop = CanaryPropagator(observation_window=0.0, auto_promote=False)
        rule = _make_rule()
        record = prop.deploy(rule)
        record.deployed_at = time.time() - 1
        prop.record_outcome(rule.rule_id, is_true_positive=True)
        status = prop.evaluate(rule.rule_id)
        assert status == PropagationStatus.CANARY  # No auto-promote


class TestActivePolicies:
    def test_get_active_policies(self):
        prop = CanaryPropagator()
        prop.deploy(_make_rule("r1"))
        prop.deploy(_make_rule("r2"))
        policies = prop.get_active_policies()
        assert len(policies) == 2

    def test_excludes_rolled_back(self):
        prop = CanaryPropagator()
        rule = _make_rule()
        prop.deploy(rule)
        for _ in range(5):
            prop.record_outcome(rule.rule_id, is_true_positive=False)
        prop.evaluate(rule.rule_id)
        policies = prop.get_active_policies()
        assert len(policies) == 0


class TestPropagatorStats:
    def test_stats(self):
        prop = CanaryPropagator()
        prop.deploy(_make_rule("r1"))
        prop.deploy(_make_rule("r2"))
        stats = prop.get_stats()
        assert stats["total_rules"] == 2
        assert stats["canary"] == 2
