"""Trust scoring and verification.

Dynamic trust on a 0-1000 scale with configurable decay.
Agents earn trust through successful actions and lose it through
policy violations or inactivity.

Trust Bridge handles peer-to-peer verification using the
Inter-Agent Trust Protocol (IATP) pattern.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from phalanx.governance.types import AgentIdentity, TrustTier, trust_tier_for_score


@dataclass(frozen=True)
class TrustDecayConfig:
    """Configuration for trust score decay over time."""

    decay_rate: float = 1.0        # Points lost per decay_interval
    decay_interval: float = 3600.0  # Seconds between decay ticks (default: 1hr)
    min_score: int = 0              # Floor for decay
    reward_success: int = 5         # Points gained per successful action
    penalty_violation: int = 50     # Points lost per policy violation
    penalty_failure: int = 10       # Points lost per action failure


@dataclass(frozen=True)
class TrustEvent:
    """Record of a trust-modifying event."""

    agent_id: str
    event_type: str  # "success", "violation", "failure", "decay", "manual"
    score_delta: int
    new_score: int
    timestamp: float = field(default_factory=time.time)
    reason: str = ""


class TrustBridge:
    """Manages trust scores for agents and handles peer verification.

    Usage:
        bridge = TrustBridge()
        identity = bridge.register(name="analyst", sponsor="alice@co.com")
        identity = bridge.reward(identity)   # +5 trust
        identity = bridge.penalize(identity) # -50 trust

        # Peer verification
        ok = bridge.verify_peer(identity, required_score=700)
    """

    def __init__(
        self,
        config: TrustDecayConfig | None = None,
        initial_trust: int = 0,
    ) -> None:
        self._config = config or TrustDecayConfig()
        self._initial_trust = initial_trust
        self._agents: dict[str, AgentIdentity] = {}
        self._events: list[TrustEvent] = []
        self._last_decay: dict[str, float] = {}

    @property
    def agents(self) -> dict[str, AgentIdentity]:
        return dict(self._agents)

    @property
    def events(self) -> list[TrustEvent]:
        return list(self._events)

    def register(
        self,
        agent_id: str,
        name: str,
        sponsor: str,
        capabilities: frozenset[str] | None = None,
        initial_trust: int | None = None,
    ) -> AgentIdentity:
        """Register a new agent with initial trust score."""
        trust = initial_trust if initial_trust is not None else self._initial_trust
        identity = AgentIdentity(
            agent_id=agent_id,
            name=name,
            sponsor=sponsor,
            capabilities=capabilities or frozenset(),
            trust_score=trust,
        )
        self._agents[agent_id] = identity
        self._last_decay[agent_id] = time.time()
        self._record_event(agent_id, "register", 0, trust, "Agent registered")
        return identity

    def get(self, agent_id: str) -> AgentIdentity | None:
        """Get current identity for an agent, applying decay."""
        identity = self._agents.get(agent_id)
        if identity is None:
            return None
        return self._apply_decay(identity)

    def reward(
        self,
        identity: AgentIdentity,
        points: int | None = None,
        reason: str = "Successful action",
    ) -> AgentIdentity:
        """Increase trust after successful action."""
        delta = points if points is not None else self._config.reward_success
        new_score = min(1000, identity.trust_score + delta)
        updated = identity.with_trust(new_score)
        self._agents[identity.agent_id] = updated
        self._record_event(identity.agent_id, "success", delta, new_score, reason)
        return updated

    def penalize(
        self,
        identity: AgentIdentity,
        points: int | None = None,
        reason: str = "Policy violation",
    ) -> AgentIdentity:
        """Decrease trust after violation."""
        delta = points if points is not None else self._config.penalty_violation
        new_score = max(self._config.min_score, identity.trust_score - delta)
        updated = identity.with_trust(new_score)
        self._agents[identity.agent_id] = updated
        self._record_event(identity.agent_id, "violation", -delta, new_score, reason)
        return updated

    def set_trust(
        self,
        identity: AgentIdentity,
        score: int,
        reason: str = "Manual trust adjustment",
    ) -> AgentIdentity:
        """Manually set trust score."""
        delta = score - identity.trust_score
        updated = identity.with_trust(score)
        self._agents[identity.agent_id] = updated
        self._record_event(identity.agent_id, "manual", delta, updated.trust_score, reason)
        return updated

    def verify_peer(
        self,
        identity: AgentIdentity,
        required_score: int,
    ) -> bool:
        """Verify that an agent meets the minimum trust threshold."""
        current = self.get(identity.agent_id)
        if current is None:
            return False
        return current.trust_score >= required_score

    def delegate(
        self,
        parent: AgentIdentity,
        child_agent_id: str,
        child_name: str,
        capabilities: frozenset[str] | None = None,
    ) -> AgentIdentity | None:
        """Create a delegated child agent with narrowed scope.

        Child capabilities are intersection of parent's capabilities
        and requested capabilities. Trust is capped at parent's score.
        """
        if capabilities is not None:
            # Scope narrowing: child can only have subset of parent caps
            narrowed = parent.capabilities & capabilities
        else:
            narrowed = parent.capabilities

        # Child trust cannot exceed parent trust
        child_trust = min(parent.trust_score, self._initial_trust)

        return self.register(
            agent_id=child_agent_id,
            name=child_name,
            sponsor=parent.did,
            capabilities=narrowed,
            initial_trust=child_trust,
        )

    def _apply_decay(self, identity: AgentIdentity) -> AgentIdentity:
        """Apply time-based trust decay."""
        now = time.time()
        last = self._last_decay.get(identity.agent_id, now)
        elapsed = now - last

        if elapsed < self._config.decay_interval:
            return identity

        ticks = int(elapsed / self._config.decay_interval)
        if ticks <= 0:
            return identity

        decay_amount = int(ticks * self._config.decay_rate)
        if decay_amount <= 0:
            return identity

        new_score = max(self._config.min_score, identity.trust_score - decay_amount)
        updated = identity.with_trust(new_score)
        self._agents[identity.agent_id] = updated
        self._last_decay[identity.agent_id] = now
        self._record_event(
            identity.agent_id, "decay", -decay_amount, new_score,
            f"Decay: {ticks} intervals elapsed",
        )
        return updated

    def _record_event(
        self,
        agent_id: str,
        event_type: str,
        delta: int,
        new_score: int,
        reason: str,
    ) -> None:
        self._events.append(TrustEvent(
            agent_id=agent_id,
            event_type=event_type,
            score_delta=delta,
            new_score=new_score,
            reason=reason,
        ))
