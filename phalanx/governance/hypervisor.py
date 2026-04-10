"""Agent Hypervisor — the unified governance pipeline.

Combines ALL governance layers into a single execution point:
1. Trust verification (is the agent who it claims to be?)
2. Intent classification (is this action dangerous? OWASP Top 10)
3. Ring check (does the agent's ring allow this action?)
4. Policy evaluation (do all policies permit this action?)
5. SRE tracking (update error budgets, check SLO compliance)
6. Trust update (reward/penalize based on outcome)

This is what makes Phalanx a hypervisor, not just a policy engine.
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
    IntentCategory,
    PolicyResult,
)
from phalanx.governance.kernel import KernelResult, StatelessKernel
from phalanx.governance.policy import BasePolicy
from phalanx.governance.trust import TrustBridge, TrustDecayConfig
from phalanx.governance.intent import IntentClassifier, IntentResult
from phalanx.governance.sre import AgentSRE, ErrorBudgetConfig, SLOStatus


@dataclass(frozen=True)
class HypervisorResult:
    """Full result from hypervisor action processing."""

    allowed: bool
    verdict: ActionVerdict
    kernel_result: KernelResult | None
    agent: AgentIdentity
    ring: ExecutionRing
    intent: IntentResult | None = None
    slo_status: SLOStatus | None = None
    reason: str = ""
    elapsed_us: float = 0.0

    def __repr__(self) -> str:
        return (
            f"<HypervisorResult allowed={self.allowed} "
            f"verdict={self.verdict.value} ring={self.ring.value} "
            f"intent={self.intent.category.value if self.intent else 'none'} "
            f"slo={self.slo_status.value if self.slo_status else 'none'} "
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
        enable_intent: bool = True,
        enable_sre: bool = True,
        intent_classifier: IntentClassifier | None = None,
        sre_config: ErrorBudgetConfig | None = None,
    ) -> None:
        self._kernel = StatelessKernel(policies)
        self._trust = TrustBridge(config=trust_config, initial_trust=initial_trust)
        self._intent = intent_classifier or IntentClassifier() if enable_intent else None
        self._sre = AgentSRE(config=sre_config) if enable_sre else None

    @property
    def kernel(self) -> StatelessKernel:
        return self._kernel

    @property
    def trust_bridge(self) -> TrustBridge:
        return self._trust

    @property
    def intent_classifier(self) -> IntentClassifier | None:
        return self._intent

    @property
    def sre(self) -> AgentSRE | None:
        return self._sre

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
        2. Intent classification (OWASP Agentic Top 10 detection)
        3. SRE pre-check (is agent restricted by error budget?)
        4. Build stateless execution context
        5. Evaluate all policies via kernel
        6. SRE tracking (update error budgets)
        7. Trust update (reward/penalize based on outcome)
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

        # Step 2: Intent classification
        intent_result: IntentResult | None = None
        if self._intent is not None:
            intent_result = self._intent.classify_action(action, params)
            if intent_result.is_dangerous:
                # Dangerous intent detected — deny and penalize
                agent = self._trust.penalize(
                    agent, reason=f"Dangerous intent: {intent_result.category.value}",
                )
                if self._sre is not None:
                    self._sre.record(agent_id, compliant=False)
                elapsed = (time.perf_counter_ns() - start) / 1000.0
                return HypervisorResult(
                    allowed=False,
                    verdict=ActionVerdict.DENY,
                    kernel_result=None,
                    agent=agent,
                    ring=agent.ring,
                    intent=intent_result,
                    slo_status=self._sre.status(agent_id) if self._sre else None,
                    reason=f"Dangerous intent detected: {intent_result.category.value}",
                    elapsed_us=elapsed,
                )

        # Step 3: SRE pre-check — is agent restricted?
        slo_status: SLOStatus | None = None
        if self._sre is not None:
            slo_status = self._sre.status(agent_id)
            if slo_status == SLOStatus.RESTRICTED:
                elapsed = (time.perf_counter_ns() - start) / 1000.0
                return HypervisorResult(
                    allowed=False,
                    verdict=ActionVerdict.DENY,
                    kernel_result=None,
                    agent=agent,
                    ring=agent.ring,
                    intent=intent_result,
                    slo_status=slo_status,
                    reason="Agent restricted: error budget exhausted",
                    elapsed_us=elapsed,
                )

        # Step 4: Build context
        ctx = ExecutionContext(
            agent=agent,
            action=action,
            params=params or {},
            parent_agent_id=parent_agent_id,
        )

        # Step 5: Evaluate policies
        kernel_result = self._kernel.evaluate(ctx)

        # Step 6: SRE tracking
        if self._sre is not None:
            slo_status = self._sre.record(agent_id, compliant=kernel_result.allowed)

        # Step 7: Update trust based on result
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
            intent=intent_result,
            slo_status=slo_status,
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
