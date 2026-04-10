"""Tests for core governance types."""

from phalanx.governance.types import (
    ActionVerdict,
    AgentIdentity,
    ExecutionContext,
    ExecutionRing,
    TrustTier,
    ring_for_score,
    trust_tier_for_score,
)


class TestExecutionRing:
    def test_ring_ordering(self):
        assert ExecutionRing.KERNEL < ExecutionRing.SUPERVISOR
        assert ExecutionRing.SUPERVISOR < ExecutionRing.USER
        assert ExecutionRing.USER < ExecutionRing.UNTRUSTED

    def test_ring_values(self):
        assert ExecutionRing.KERNEL == 0
        assert ExecutionRing.UNTRUSTED == 3


class TestTrustTierMapping:
    def test_kernel_tier(self):
        assert trust_tier_for_score(1000) == TrustTier.KERNEL
        assert trust_tier_for_score(900) == TrustTier.KERNEL

    def test_supervisor_tier(self):
        assert trust_tier_for_score(899) == TrustTier.SUPERVISOR
        assert trust_tier_for_score(700) == TrustTier.SUPERVISOR

    def test_user_tier(self):
        assert trust_tier_for_score(699) == TrustTier.USER
        assert trust_tier_for_score(400) == TrustTier.USER

    def test_untrusted_tier(self):
        assert trust_tier_for_score(399) == TrustTier.UNTRUSTED
        assert trust_tier_for_score(100) == TrustTier.UNTRUSTED

    def test_quarantine_tier(self):
        assert trust_tier_for_score(99) == TrustTier.QUARANTINE
        assert trust_tier_for_score(0) == TrustTier.QUARANTINE


class TestRingForScore:
    def test_kernel_ring(self):
        assert ring_for_score(900) == ExecutionRing.KERNEL

    def test_supervisor_ring(self):
        assert ring_for_score(700) == ExecutionRing.SUPERVISOR

    def test_user_ring(self):
        assert ring_for_score(400) == ExecutionRing.USER

    def test_untrusted_ring(self):
        assert ring_for_score(0) == ExecutionRing.UNTRUSTED


class TestAgentIdentity:
    def test_creation_defaults(self):
        agent = AgentIdentity(
            agent_id="a1", name="test", sponsor="alice@co.com",
        )
        assert agent.trust_score == 0
        assert agent.tier == TrustTier.QUARANTINE
        assert agent.ring == ExecutionRing.UNTRUSTED

    def test_did_generation(self):
        agent = AgentIdentity(agent_id="a1", name="test", sponsor="alice")
        assert agent.did.startswith("did:phalanx:test:")

    def test_immutable_trust_update(self):
        agent = AgentIdentity(agent_id="a1", name="test", sponsor="alice", trust_score=500)
        updated = agent.with_trust(900)
        assert agent.trust_score == 500  # Original unchanged
        assert updated.trust_score == 900

    def test_trust_clamping(self):
        agent = AgentIdentity(agent_id="a1", name="test", sponsor="alice")
        assert agent.with_trust(1500).trust_score == 1000
        assert agent.with_trust(-100).trust_score == 0

    def test_capability_check(self):
        agent = AgentIdentity(
            agent_id="a1", name="test", sponsor="alice",
            capabilities=frozenset({"read:data", "write:reports"}),
        )
        assert agent.can("read:data")
        assert agent.can("write:reports")
        assert not agent.can("delete:data")

    def test_wildcard_capability(self):
        agent = AgentIdentity(
            agent_id="a1", name="test", sponsor="alice",
            capabilities=frozenset({"read:*"}),
        )
        assert agent.can("read:data")
        assert agent.can("read:logs")
        assert not agent.can("write:data")

    def test_frozen(self):
        agent = AgentIdentity(agent_id="a1", name="test", sponsor="alice")
        try:
            agent.trust_score = 500  # type: ignore
            assert False, "Should raise"
        except AttributeError:
            pass


class TestExecutionContext:
    def test_context_carries_agent_ring(self):
        agent = AgentIdentity(
            agent_id="a1", name="test", sponsor="alice", trust_score=750,
        )
        ctx = ExecutionContext(agent=agent, action="read:data")
        assert ctx.ring == ExecutionRing.SUPERVISOR
        assert ctx.tier == TrustTier.SUPERVISOR
