"""Core types for Phalanx governance layer.

All governance decisions flow through these types. Designed to be:
- Immutable (frozen dataclasses)
- Stateless (each request carries its own context)
- Extensible (BasePolicy ABC accepts both static and learned policies)
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, FrozenSet, Optional


class ExecutionRing(IntEnum):
    """CPU-inspired privilege rings for agent execution.

    Ring 0 = most privileged (kernel), Ring 3 = least (sandboxed).
    Agents start at Ring 3 and earn promotions through trust.
    """

    KERNEL = 0       # Full system access, policy modification
    SUPERVISOR = 1   # Cross-agent coordination, elevated tools
    USER = 2         # Standard tool access within scope
    UNTRUSTED = 3    # Read-only, sandboxed execution


class TrustTier(str, Enum):
    """Behavioral trust tiers mapped to score ranges.

    Score boundaries (configurable):
      KERNEL:     >= 900
      SUPERVISOR: >= 700
      USER:       >= 400
      UNTRUSTED:  >= 100
      QUARANTINE: < 100
    """

    KERNEL = "kernel"
    SUPERVISOR = "supervisor"
    USER = "user"
    UNTRUSTED = "untrusted"
    QUARANTINE = "quarantine"


class ActionVerdict(str, Enum):
    """Result of policy evaluation on an agent action."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    DOWNGRADE_RING = "downgrade_ring"
    RATE_LIMITED = "rate_limited"


class IntentCategory(str, Enum):
    """Semantic intent classification for dangerous actions."""

    SAFE = "safe"
    DESTRUCTIVE_DATA = "destructive_data"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    PROMPT_INJECTION = "prompt_injection"


# Default trust boundaries
TRUST_BOUNDARIES: dict[TrustTier, int] = {
    TrustTier.KERNEL: 900,
    TrustTier.SUPERVISOR: 700,
    TrustTier.USER: 400,
    TrustTier.UNTRUSTED: 100,
    TrustTier.QUARANTINE: 0,
}

# Ring-to-tier mapping
RING_TRUST_MINIMUM: dict[ExecutionRing, int] = {
    ExecutionRing.KERNEL: 900,
    ExecutionRing.SUPERVISOR: 700,
    ExecutionRing.USER: 400,
    ExecutionRing.UNTRUSTED: 0,
}


def trust_tier_for_score(
    score: int,
    boundaries: dict[TrustTier, int] | None = None,
) -> TrustTier:
    """Map a trust score (0-1000) to its behavioral tier."""
    b = boundaries or TRUST_BOUNDARIES
    if score >= b[TrustTier.KERNEL]:
        return TrustTier.KERNEL
    if score >= b[TrustTier.SUPERVISOR]:
        return TrustTier.SUPERVISOR
    if score >= b[TrustTier.USER]:
        return TrustTier.USER
    if score >= b[TrustTier.UNTRUSTED]:
        return TrustTier.UNTRUSTED
    return TrustTier.QUARANTINE


def ring_for_score(
    score: int,
    minimums: dict[ExecutionRing, int] | None = None,
) -> ExecutionRing:
    """Map a trust score to the highest execution ring allowed."""
    m = minimums or RING_TRUST_MINIMUM
    if score >= m[ExecutionRing.KERNEL]:
        return ExecutionRing.KERNEL
    if score >= m[ExecutionRing.SUPERVISOR]:
        return ExecutionRing.SUPERVISOR
    if score >= m[ExecutionRing.USER]:
        return ExecutionRing.USER
    return ExecutionRing.UNTRUSTED


@dataclass(frozen=True)
class AgentIdentity:
    """Cryptographic agent identity with trust tracking.

    Uses DID-style identifiers. Trust score is dynamic (0-1000)
    and decays over time without positive signals.
    """

    agent_id: str
    name: str
    sponsor: str  # Human accountability — who created this agent
    capabilities: FrozenSet[str] = field(default_factory=frozenset)
    trust_score: int = 0  # New agents start untrusted
    created_at: float = field(default_factory=time.time)

    @property
    def did(self) -> str:
        """Decentralized identifier for this agent."""
        hash_input = f"{self.agent_id}:{self.name}:{self.sponsor}"
        short_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
        return f"did:phalanx:{self.name}:{short_hash}"

    @property
    def tier(self) -> TrustTier:
        return trust_tier_for_score(self.trust_score)

    @property
    def ring(self) -> ExecutionRing:
        return ring_for_score(self.trust_score)

    def with_trust(self, new_score: int) -> AgentIdentity:
        """Return a new identity with updated trust score (immutable)."""
        clamped = max(0, min(1000, new_score))
        return AgentIdentity(
            agent_id=self.agent_id,
            name=self.name,
            sponsor=self.sponsor,
            capabilities=self.capabilities,
            trust_score=clamped,
            created_at=self.created_at,
        )

    def can(self, capability: str) -> bool:
        """Check if agent has a specific capability."""
        # Wildcard support: "read:*" matches "read:data", "read:logs", etc.
        for cap in self.capabilities:
            if cap == capability:
                return True
            if cap.endswith(":*") and capability.startswith(cap[:-1]):
                return True
        return False


@dataclass(frozen=True)
class PolicyResult:
    """Outcome of evaluating a single policy against an action."""

    verdict: ActionVerdict
    policy_name: str
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionContext:
    """Stateless context carried with every action request.

    Each request is self-contained — no shared state required.
    Deployable behind load balancers, as K8s sidecars, or serverless.
    """

    agent: AgentIdentity
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    parent_agent_id: Optional[str] = None  # For delegation chains
    request_id: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def ring(self) -> ExecutionRing:
        return self.agent.ring

    @property
    def tier(self) -> TrustTier:
        return self.agent.tier
