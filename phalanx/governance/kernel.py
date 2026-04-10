"""Stateless policy evaluation kernel.

The heart of Phalanx's governance layer. Evaluates all policies
against an execution context and returns a final verdict.

Design principles:
- Stateless: each request carries its own context
- Fast: <0.1ms for static policy evaluation
- Deterministic: same input = same output
- Extensible: accepts any BasePolicy subclass (including learned policies)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Sequence

from phalanx.governance.types import (
    ActionVerdict,
    ExecutionContext,
    PolicyResult,
)
from phalanx.governance.policy import BasePolicy


# Verdict priority: higher index = higher priority (deny beats allow)
_VERDICT_PRIORITY: dict[ActionVerdict, int] = {
    ActionVerdict.ALLOW: 0,
    ActionVerdict.RATE_LIMITED: 1,
    ActionVerdict.DOWNGRADE_RING: 2,
    ActionVerdict.REQUIRE_APPROVAL: 3,
    ActionVerdict.DENY: 4,
}


@dataclass(frozen=True)
class KernelResult:
    """Aggregate result from evaluating all policies."""

    verdict: ActionVerdict
    results: tuple[PolicyResult, ...]
    elapsed_us: float  # Microseconds for evaluation

    @property
    def allowed(self) -> bool:
        return self.verdict == ActionVerdict.ALLOW

    @property
    def denied(self) -> bool:
        return self.verdict == ActionVerdict.DENY

    @property
    def blocking_results(self) -> tuple[PolicyResult, ...]:
        """Results that blocked the action."""
        return tuple(r for r in self.results if r.verdict != ActionVerdict.ALLOW)

    def __repr__(self) -> str:
        return (
            f"<KernelResult verdict={self.verdict.value} "
            f"policies={len(self.results)} elapsed={self.elapsed_us:.1f}us>"
        )


class StatelessKernel:
    """Stateless policy evaluation engine.

    Evaluates a sequence of policies against an execution context.
    No shared state — deployable as sidecar, serverless, or behind LB.

    Usage:
        kernel = StatelessKernel(policies=[
            StaticPolicy.read_only(),
            StaticPolicy.rate_limit(100, "1m"),
        ])
        result = kernel.evaluate(ctx)
        if result.allowed:
            execute_action(ctx)
    """

    def __init__(self, policies: Sequence[BasePolicy] | None = None) -> None:
        self._policies: list[BasePolicy] = list(policies or [])

    @property
    def policies(self) -> tuple[BasePolicy, ...]:
        return tuple(self._policies)

    def add_policy(self, policy: BasePolicy) -> None:
        """Register a policy for evaluation."""
        self._policies.append(policy)

    def remove_policy(self, name: str) -> bool:
        """Remove a policy by name. Returns True if found."""
        for i, p in enumerate(self._policies):
            if p.name == name:
                self._policies.pop(i)
                return True
        return False

    def evaluate(self, ctx: ExecutionContext) -> KernelResult:
        """Evaluate all policies against the context.

        Policies are evaluated in order. The highest-priority verdict wins.
        DENY > REQUIRE_APPROVAL > DOWNGRADE_RING > RATE_LIMITED > ALLOW.

        Short-circuits on DENY for performance.
        """
        start = time.perf_counter_ns()
        results: list[PolicyResult] = []
        highest_verdict = ActionVerdict.ALLOW

        for policy in self._policies:
            result = policy.evaluate(ctx)
            results.append(result)

            if _VERDICT_PRIORITY[result.verdict] > _VERDICT_PRIORITY[highest_verdict]:
                highest_verdict = result.verdict

            # Short-circuit on deny
            if highest_verdict == ActionVerdict.DENY:
                break

        elapsed_us = (time.perf_counter_ns() - start) / 1000.0

        return KernelResult(
            verdict=highest_verdict,
            results=tuple(results),
            elapsed_us=elapsed_us,
        )
