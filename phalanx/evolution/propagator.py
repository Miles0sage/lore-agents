"""Canary Propagation — deploy learned policies across the fleet.

Learned rules from Darwin are NOT immediately applied fleet-wide.
They go through a canary rollout tied to the SRE error budget system:

1. Deploy to Ring 3 (untrusted) agents only
2. Monitor SafetySLI for false positives
3. If stable, promote to Ring 2 (user) agents
4. If stable, promote to Ring 1 (supervisor) agents
5. Ring 0 (kernel) policies require human approval

This ensures learned policies don't cause cascading failures.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from phalanx.governance.types import ActionVerdict, ExecutionContext, ExecutionRing, PolicyResult
from phalanx.governance.policy import BasePolicy, DenyListPolicy
from phalanx.governance.sre import AgentSRE, SLOStatus
from phalanx.evolution.darwin import LearnedRule


class PropagationStatus(str, Enum):
    """Status of a learned policy's rollout."""

    PENDING = "pending"         # Not yet deployed
    CANARY = "canary"           # Deployed to Ring 3 only
    EXPANDING = "expanding"     # Rolling out to Ring 2
    PROMOTED = "promoted"       # Active on Ring 2+
    ROLLED_BACK = "rolled_back" # False positive detected, reverted
    APPROVED = "approved"       # Human-approved for all rings


@dataclass
class PropagationRecord:
    """Tracks the rollout state of a learned policy."""

    rule: LearnedRule
    policy: BasePolicy
    status: PropagationStatus = PropagationStatus.PENDING
    deployed_at: float = 0.0
    current_ring: ExecutionRing = ExecutionRing.UNTRUSTED
    false_positives: int = 0
    true_positives: int = 0
    observation_window: float = 300.0  # 5 min per ring before promotion

    @property
    def accuracy(self) -> float:
        total = self.false_positives + self.true_positives
        if total == 0:
            return 1.0
        return self.true_positives / total

    @property
    def ready_to_promote(self) -> bool:
        """Check if enough time has passed and accuracy is acceptable."""
        if self.status == PropagationStatus.ROLLED_BACK:
            return False
        elapsed = time.time() - self.deployed_at
        return elapsed >= self.observation_window and self.accuracy >= 0.95


class CanaryPropagator:
    """Manages canary rollout of learned policies.

    Usage:
        propagator = CanaryPropagator(sre=agent_sre)

        # After Darwin generates rules:
        for rule in rules:
            propagator.deploy(rule)

        # Periodically check health and promote/rollback:
        propagator.evaluate_all()
    """

    def __init__(
        self,
        sre: AgentSRE | None = None,
        observation_window: float = 300.0,
        auto_promote: bool = True,
    ) -> None:
        self._sre = sre
        self._observation_window = observation_window
        self._auto_promote = auto_promote
        self._records: dict[str, PropagationRecord] = {}

    @property
    def records(self) -> dict[str, PropagationRecord]:
        return dict(self._records)

    def deploy(self, rule: LearnedRule) -> PropagationRecord:
        """Deploy a learned rule as a canary policy.

        Starts at Ring 3 (untrusted) only.
        """
        policy = DenyListPolicy(
            policy_name=f"darwin:{rule.rule_id}",
            blocked_patterns=[rule.action_pattern],
            reason=f"Learned policy: {rule.description}",
        )

        record = PropagationRecord(
            rule=rule,
            policy=policy,
            status=PropagationStatus.CANARY,
            deployed_at=time.time(),
            current_ring=ExecutionRing.UNTRUSTED,
            observation_window=self._observation_window,
        )

        self._records[rule.rule_id] = record
        return record

    def record_outcome(
        self,
        rule_id: str,
        is_true_positive: bool,
    ) -> None:
        """Record whether a policy hit was a true or false positive."""
        record = self._records.get(rule_id)
        if record is None:
            return
        if is_true_positive:
            record.true_positives += 1
        else:
            record.false_positives += 1

    def evaluate(self, rule_id: str) -> PropagationStatus:
        """Evaluate a single policy's canary health.

        Returns new status: PROMOTE, ROLLBACK, or current status.
        """
        record = self._records.get(rule_id)
        if record is None:
            return PropagationStatus.PENDING

        # Check for rollback condition
        if record.false_positives > 3 and record.accuracy < 0.90:
            record.status = PropagationStatus.ROLLED_BACK
            return record.status

        # Check for promotion
        if record.ready_to_promote and self._auto_promote:
            return self._promote(record)

        return record.status

    def evaluate_all(self) -> dict[str, PropagationStatus]:
        """Evaluate all active canary policies."""
        results: dict[str, PropagationStatus] = {}
        for rule_id in list(self._records.keys()):
            results[rule_id] = self.evaluate(rule_id)
        return results

    def get_active_policies(
        self,
        ring: ExecutionRing | None = None,
    ) -> list[BasePolicy]:
        """Get all active learned policies, optionally filtered by ring."""
        policies: list[BasePolicy] = []
        for record in self._records.values():
            if record.status in (
                PropagationStatus.ROLLED_BACK,
                PropagationStatus.PENDING,
            ):
                continue
            if ring is not None and record.current_ring < ring:
                # Policy's ring must be >= the requested ring
                # (lower ring number = higher privilege)
                continue
            policies.append(record.policy)
        return policies

    def get_stats(self) -> dict[str, Any]:
        """Get propagation statistics."""
        statuses = [r.status for r in self._records.values()]
        return {
            "total_rules": len(self._records),
            "canary": sum(1 for s in statuses if s == PropagationStatus.CANARY),
            "expanding": sum(1 for s in statuses if s == PropagationStatus.EXPANDING),
            "promoted": sum(1 for s in statuses if s == PropagationStatus.PROMOTED),
            "rolled_back": sum(1 for s in statuses if s == PropagationStatus.ROLLED_BACK),
            "approved": sum(1 for s in statuses if s == PropagationStatus.APPROVED),
        }

    def _promote(self, record: PropagationRecord) -> PropagationStatus:
        """Promote a policy to the next ring."""
        if record.current_ring == ExecutionRing.UNTRUSTED:
            record.current_ring = ExecutionRing.USER
            record.status = PropagationStatus.EXPANDING
            record.deployed_at = time.time()  # Reset observation window
        elif record.current_ring == ExecutionRing.USER:
            record.current_ring = ExecutionRing.SUPERVISOR
            record.status = PropagationStatus.PROMOTED
            record.deployed_at = time.time()
        # Ring 0 (KERNEL) requires human approval — never auto-promote
        return record.status
