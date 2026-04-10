"""Agent Hypervisor — execution ring enforcement.

Combines the StatelessKernel (policy evaluation) with TrustBridge
(trust management) to enforce privilege rings at runtime.

Actions flow through:
1. Trust verification (is the agent who it claims to be?)
2. Ring check (does the agent's ring allow this action?)
3. Policy evaluation (do all policies permit this action?)
4. Execution (or rejection with full audit trail)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

from phalanx.governance.types import (
    ActionVerdict,
    AgentIdentity,
    ExecutionContext,
    ExecutionRing,
    PolicyResult,
)
from phalanx.governance.kernel import KernelResult, StatelessKernel
from phalanx.governance.policy import BasePolicy
from phalanx.governance.trust import TrustBridge, TrustDecayConfig


@dataclass(frozen=True)
class HypervisorResult:
    """Full result from hypervisor action processing."""

    allowed: bool
    verdict: ActionVerdict
    kernel_result: KernelResult | None
    agent: AgentIdentity
    ring: ExecutionRing
    reason: str = ""
    elapsed_us: float = 0.0

    def __repr__(self) -> str:
        return (
            f"<HypervisorResult allowed={self.allowed} "
            f"verdict={self.verdict.value} ring={self.ring.value} "
            f"elapsed={self.elapsed_us:.1f}us>"
        )


class AgentHypervisor:
    """Top-level governance orchestrator.

    Combines trust management, ring enforcement, and policy evaluation
    into a single entry point for agent action governance.

    Usage:
        hv = AgentHypervisor(policies=[
            StaticPolicy.deny(["delete:production:*"]),
            StaticPolicy.rate_limit(100, "1m"),
        ])

        agent = hv.register_agent("a1", "analyst", "alice@co.com",
                                   capabilities=frozenset({"read:data"}))

        result = hv.execute("a1", "read:data:users", {"limit": 10})
        if result.allowed:
            do_the_thing()
    """

    def __init__(
        self,
        policies: Sequence[BasePolicy] | None = None,
        trust_config: TrustDecayConfig | None = None,
        initial_trust: int = 0,
    ) -> None:
        self._kernel = StatelessKernel(policies)
        self._trust = TrustBridge(config=trust_config, initial_trust=initial_trust)

    @property
    def kernel(self) -> StatelessKernel:
        return self._kernel

    @property
    def trust_bridge(self) -> TrustBridge:
        return self._trust

    def register_agent(
        self,
        agent_id: str,
        name: str,
        sponsor: str,
        capabilities: frozenset[str] | None = None,
        initial_trust: int | None = None,
    ) -> AgentIdentity:
        """Register a new agent. Starts at Ring 3 (untrusted) by default."""
        return self._trust.register(
            agent_id=agent_id,
            name=name,
            sponsor=sponsor,
            capabilities=capabilities,
            initial_trust=initial_trust,
        )

    def get_agent(self, agent_id: str) -> AgentIdentity | None:
        """Get current agent identity with trust decay applied."""
        return self._trust.get(agent_id)

    def add_policy(self, policy: BasePolicy) -> None:
        """Add a policy to the kernel."""
        self._kernel.add_policy(policy)

    def execute(
        self,
        agent_id: str,
        action: str,
        params: dict[str, Any] | None = None,
        parent_agent_id: str | None = None,
    ) -> HypervisorResult:
        """Process an action through the full governance pipeline.

        Pipeline:
        1. Resolve agent identity (with trust decay)
        2. Build stateless execution context
        3. Evaluate all policies via kernel
        4. Return verdict with full audit trail
        """
        start = time.perf_counter_ns()

        # Step 1: Resolve agent
        agent = self._trust.get(agent_id)
        if agent is None:
            elapsed = (time.perf_counter_ns() - start) / 1000.0
            return HypervisorResult(
                allowed=False,
                verdict=ActionVerdict.DENY,
                kernel_result=None,
                agent=AgentIdentity(
                    agent_id=agent_id, name="unknown",
                    sponsor="unknown", trust_score=0,
                ),
                ring=ExecutionRing.UNTRUSTED,
                reason=f"Unknown agent: {agent_id}",
                elapsed_us=elapsed,
            )

        # Step 2: Build context
        ctx = ExecutionContext(
            agent=agent,
            action=action,
            params=params or {},
            parent_agent_id=parent_agent_id,
        )

        # Step 3: Evaluate policies
        kernel_result = self._kernel.evaluate(ctx)

        # Step 4: Update trust based on result
        if kernel_result.allowed:
            agent = self._trust.reward(agent)
        elif kernel_result.verdict == ActionVerdict.DENY:
            agent = self._trust.penalize(agent, reason=f"Denied action: {action}")

        elapsed = (time.perf_counter_ns() - start) / 1000.0

        return HypervisorResult(
            allowed=kernel_result.allowed,
            verdict=kernel_result.verdict,
            kernel_result=kernel_result,
            agent=agent,
            ring=agent.ring,
            elapsed_us=elapsed,
        )

    def delegate(
        self,
        parent_agent_id: str,
        child_agent_id: str,
        child_name: str,
        capabilities: frozenset[str] | None = None,
    ) -> AgentIdentity | None:
        """Create a delegated child agent with narrowed scope."""
        parent = self._trust.get(parent_agent_id)
        if parent is None:
            return None
        return self._trust.delegate(parent, child_agent_id, child_name, capabilities)
