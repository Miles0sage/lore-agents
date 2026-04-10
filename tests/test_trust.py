"""Tests for trust scoring and verification."""

from phalanx.governance.types import ExecutionRing, TrustTier
from phalanx.governance.trust import TrustBridge, TrustDecayConfig


class TestTrustBridge:
    def test_register_agent(self):
        bridge = TrustBridge()
        agent = bridge.register("a1", "test", "alice@co.com")
        assert agent.trust_score == 0
        assert agent.tier == TrustTier.QUARANTINE

    def test_register_with_initial_trust(self):
        bridge = TrustBridge(initial_trust=500)
        agent = bridge.register("a1", "test", "alice@co.com")
        assert agent.trust_score == 500
        assert agent.tier == TrustTier.USER

    def test_reward(self):
        bridge = TrustBridge()
        agent = bridge.register("a1", "test", "alice@co.com", initial_trust=100)
        updated = bridge.reward(agent)
        assert updated.trust_score == 105  # default +5

    def test_penalize(self):
        bridge = TrustBridge()
        agent = bridge.register("a1", "test", "alice@co.com", initial_trust=500)
        updated = bridge.penalize(agent)
        assert updated.trust_score == 450  # default -50

    def test_penalize_floor(self):
        bridge = TrustBridge()
        agent = bridge.register("a1", "test", "alice@co.com", initial_trust=10)
        updated = bridge.penalize(agent)
        assert updated.trust_score == 0

    def test_reward_ceiling(self):
        bridge = TrustBridge()
        agent = bridge.register("a1", "test", "alice@co.com", initial_trust=998)
        updated = bridge.reward(agent)
        assert updated.trust_score == 1000

    def test_verify_peer(self):
        bridge = TrustBridge()
        agent = bridge.register("a1", "test", "alice", initial_trust=750)
        assert bridge.verify_peer(agent, required_score=700)
        assert not bridge.verify_peer(agent, required_score=800)

    def test_set_trust(self):
        bridge = TrustBridge()
        agent = bridge.register("a1", "test", "alice", initial_trust=100)
        updated = bridge.set_trust(agent, 900, reason="Promoted to kernel")
        assert updated.trust_score == 900
        assert updated.ring == ExecutionRing.KERNEL

    def test_events_tracked(self):
        bridge = TrustBridge()
        agent = bridge.register("a1", "test", "alice")
        bridge.reward(agent)
        assert len(bridge.events) == 2  # register + reward

    def test_custom_config(self):
        config = TrustDecayConfig(reward_success=10, penalty_violation=100)
        bridge = TrustBridge(config=config)
        agent = bridge.register("a1", "test", "alice", initial_trust=500)
        rewarded = bridge.reward(agent)
        assert rewarded.trust_score == 510

    def test_delegation_scope_narrowing(self):
        bridge = TrustBridge(initial_trust=800)
        parent = bridge.register(
            "p1", "parent", "alice",
            capabilities=frozenset({"read:data", "write:data", "delete:data"}),
        )
        child = bridge.delegate(
            parent, "c1", "child",
            capabilities=frozenset({"read:data", "write:data"}),
        )
        assert child is not None
        assert child.can("read:data")
        assert child.can("write:data")
        assert not child.can("delete:data")  # Narrowed out

    def test_delegation_trust_capped(self):
        bridge = TrustBridge(initial_trust=0)
        parent = bridge.register("p1", "parent", "alice", initial_trust=800)
        child = bridge.delegate(parent, "c1", "child")
        assert child is not None
        assert child.trust_score <= parent.trust_score


class TestTrustDecay:
    def test_no_decay_within_interval(self):
        config = TrustDecayConfig(decay_rate=10, decay_interval=3600)
        bridge = TrustBridge(config=config)
        agent = bridge.register("a1", "test", "alice", initial_trust=500)
        # Get immediately — no decay should happen
        current = bridge.get("a1")
        assert current is not None
        assert current.trust_score == 500
