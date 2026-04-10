"""Tests for the AgentHypervisor — full governance pipeline."""

from phalanx.governance.types import ActionVerdict, ExecutionRing
from phalanx.governance.hypervisor import AgentHypervisor
from phalanx.governance.policy import StaticPolicy
from phalanx.governance.trust import TrustDecayConfig


class TestAgentHypervisor:
    def test_unknown_agent_denied(self):
        hv = AgentHypervisor()
        result = hv.execute("unknown", "read:data")
        assert not result.allowed
        assert result.verdict == ActionVerdict.DENY
        assert "Unknown agent" in result.reason

    def test_registered_agent_allowed(self):
        hv = AgentHypervisor(initial_trust=500)
        hv.register_agent("a1", "test", "alice")
        result = hv.execute("a1", "read:data")
        assert result.allowed

    def test_policy_blocks_action(self):
        hv = AgentHypervisor(
            policies=[StaticPolicy.deny(["delete:*"])],
            initial_trust=500,
        )
        hv.register_agent("a1", "test", "alice")
        result = hv.execute("a1", "delete:users")
        assert not result.allowed
        assert result.verdict == ActionVerdict.DENY

    def test_trust_increases_on_success(self):
        hv = AgentHypervisor(initial_trust=500)
        hv.register_agent("a1", "test", "alice")
        result = hv.execute("a1", "read:data")
        assert result.allowed
        assert result.agent.trust_score > 500

    def test_trust_decreases_on_deny(self):
        hv = AgentHypervisor(
            policies=[StaticPolicy.deny(["delete:*"])],
            initial_trust=500,
        )
        hv.register_agent("a1", "test", "alice")
        result = hv.execute("a1", "delete:everything")
        assert not result.allowed
        assert result.agent.trust_score < 500

    def test_ring_enforcement(self):
        hv = AgentHypervisor(
            policies=[StaticPolicy.ring_guard({"admin:*": ExecutionRing.KERNEL})],
            initial_trust=500,
        )
        hv.register_agent("a1", "test", "alice")
        result = hv.execute("a1", "admin:shutdown")
        assert not result.allowed  # trust=500 => Ring 2, need Ring 0

    def test_high_trust_passes_ring_guard(self):
        hv = AgentHypervisor(
            policies=[StaticPolicy.ring_guard({"admin:*": ExecutionRing.KERNEL})],
        )
        hv.register_agent("a1", "test", "alice", initial_trust=950)
        result = hv.execute("a1", "admin:shutdown")
        assert result.allowed  # trust=950 => Ring 0

    def test_delegation(self):
        hv = AgentHypervisor(initial_trust=800)
        parent = hv.register_agent(
            "p1", "parent", "alice",
            capabilities=frozenset({"read:*", "write:*"}),
        )
        child = hv.delegate("p1", "c1", "child", frozenset({"read:*"}))
        assert child is not None
        assert child.can("read:data")
        assert not child.can("write:data")

    def test_elapsed_time_tracked(self):
        hv = AgentHypervisor(initial_trust=500)
        hv.register_agent("a1", "test", "alice")
        result = hv.execute("a1", "read:data")
        assert result.elapsed_us >= 0

    def test_get_agent(self):
        hv = AgentHypervisor(initial_trust=500)
        hv.register_agent("a1", "test", "alice")
        agent = hv.get_agent("a1")
        assert agent is not None
        assert agent.name == "test"

    def test_get_unknown_agent(self):
        hv = AgentHypervisor()
        assert hv.get_agent("nope") is None

    def test_add_policy_after_init(self):
        hv = AgentHypervisor(initial_trust=500)
        hv.register_agent("a1", "test", "alice")

        # Initially allowed
        assert hv.execute("a1", "write:data").allowed

        # Add read-only policy
        hv.add_policy(StaticPolicy.read_only())
        assert not hv.execute("a1", "write:data").allowed

    def test_multiple_policies(self):
        hv = AgentHypervisor(
            policies=[
                StaticPolicy.deny(["drop:*"]),
                StaticPolicy.rate_limit(100, "1m"),
                StaticPolicy.require_approval(["deploy:*"]),
            ],
            initial_trust=500,
        )
        hv.register_agent("a1", "test", "alice")

        assert hv.execute("a1", "read:data").allowed
        assert hv.execute("a1", "drop:database").verdict == ActionVerdict.DENY
        assert hv.execute("a1", "deploy:prod").verdict == ActionVerdict.REQUIRE_APPROVAL


class TestHypervisorPerformance:
    def test_full_pipeline_under_200us(self):
        """Full hypervisor pipeline should complete in <200us."""
        hv = AgentHypervisor(
            policies=[
                StaticPolicy.deny(["drop:*"]),
                StaticPolicy.rate_limit(1000, "1m"),
                StaticPolicy.require_approval(["deploy:*"]),
            ],
            initial_trust=500,
        )
        hv.register_agent("a1", "test", "alice")

        # Warm up
        hv.execute("a1", "read:data")

        results = []
        for _ in range(100):
            r = hv.execute("a1", "read:data")
            results.append(r.elapsed_us)

        avg = sum(results) / len(results)
        assert avg < 200, f"Average pipeline time {avg:.1f}us exceeds 200us target"
