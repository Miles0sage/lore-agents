"""Tests for the AgentHypervisor — full governance pipeline."""

from phalanx.governance.types import ActionVerdict, ExecutionRing, IntentCategory
from phalanx.governance.hypervisor import AgentHypervisor
from phalanx.governance.policy import StaticPolicy
from phalanx.governance.trust import TrustDecayConfig
from phalanx.governance.sre import SLOStatus, ErrorBudgetConfig


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
            policies=[StaticPolicy.ring_guard({"config:*": ExecutionRing.KERNEL})],
            enable_intent=False,  # Test ring logic, not intent
        )
        hv.register_agent("a1", "test", "alice", initial_trust=950)
        result = hv.execute("a1", "config:update")
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
                StaticPolicy.require_approval(["release:*"]),
            ],
            initial_trust=500,
            enable_intent=False,  # Test policy logic, not intent
            enable_sre=False,     # Test policy logic, not SRE
        )
        hv.register_agent("a1", "test", "alice")

        assert hv.execute("a1", "read:data").allowed
        assert hv.execute("a1", "drop:table").verdict == ActionVerdict.DENY
        assert hv.execute("a1", "release:prod").verdict == ActionVerdict.REQUIRE_APPROVAL


class TestHypervisorIntentIntegration:
    def test_blocks_sql_injection(self):
        hv = AgentHypervisor(initial_trust=500, enable_intent=True)
        hv.register_agent("a1", "test", "alice")
        result = hv.execute("a1", "execute:sql", {"query": "DROP TABLE users;"})
        assert not result.allowed
        assert result.intent is not None
        assert result.intent.is_dangerous

    def test_safe_action_passes_intent(self):
        hv = AgentHypervisor(initial_trust=500, enable_intent=True)
        hv.register_agent("a1", "test", "alice")
        result = hv.execute("a1", "read:data", {"table": "users"})
        assert result.allowed
        assert result.intent is not None
        assert not result.intent.is_dangerous

    def test_intent_penalizes_trust(self):
        hv = AgentHypervisor(initial_trust=500, enable_intent=True)
        hv.register_agent("a1", "test", "alice")
        hv.execute("a1", "execute:sql", {"query": "DROP TABLE users;"})
        agent = hv.get_agent("a1")
        assert agent is not None
        assert agent.trust_score < 500

    def test_disable_intent(self):
        hv = AgentHypervisor(initial_trust=500, enable_intent=False)
        hv.register_agent("a1", "test", "alice")
        result = hv.execute("a1", "execute:sql", {"query": "DROP TABLE users;"})
        assert result.allowed  # No intent check — passes
        assert result.intent is None


class TestHypervisorSREIntegration:
    def test_sre_tracks_actions(self):
        hv = AgentHypervisor(initial_trust=500, enable_sre=True)
        hv.register_agent("a1", "test", "alice")
        result = hv.execute("a1", "read:data")
        assert result.slo_status is not None
        assert result.slo_status == SLOStatus.HEALTHY

    def test_sre_restricts_after_violations(self):
        config = ErrorBudgetConfig(slo_target=0.99, auto_restrict=True)
        hv = AgentHypervisor(
            policies=[StaticPolicy.deny(["bad:*"])],
            initial_trust=900,
            enable_sre=True,
            sre_config=config,
        )
        hv.register_agent("a1", "test", "alice")
        # Hammer with violations
        for _ in range(10):
            hv.execute("a1", "bad:action")
        # Next action should be blocked by SRE restriction
        result = hv.execute("a1", "read:data")
        assert not result.allowed
        assert "error budget exhausted" in result.reason

    def test_disable_sre(self):
        hv = AgentHypervisor(initial_trust=500, enable_sre=False)
        hv.register_agent("a1", "test", "alice")
        result = hv.execute("a1", "read:data")
        assert result.allowed
        assert result.slo_status is None

    def test_fleet_health_via_hypervisor(self):
        hv = AgentHypervisor(initial_trust=500, enable_sre=True)
        hv.register_agent("a1", "test1", "alice")
        hv.register_agent("a2", "test2", "bob")
        hv.execute("a1", "read:data")
        hv.execute("a2", "read:data")
        assert hv.sre is not None
        health = hv.sre.fleet_health()
        assert health["agents"] == 2
        assert health["healthy"] == 2


class TestHypervisorPerformance:
    def test_full_pipeline_under_500us(self):
        """Full hypervisor pipeline with intent + SRE should complete in <500us."""
        hv = AgentHypervisor(
            policies=[
                StaticPolicy.deny(["drop:*"]),
                StaticPolicy.rate_limit(1000, "1m"),
                StaticPolicy.require_approval(["deploy:*"]),
            ],
            initial_trust=500,
            enable_intent=True,
            enable_sre=True,
        )
        hv.register_agent("a1", "test", "alice")

        # Warm up
        hv.execute("a1", "read:data")

        results = []
        for _ in range(100):
            r = hv.execute("a1", "read:data")
            results.append(r.elapsed_us)

        avg = sum(results) / len(results)
        assert avg < 500, f"Average pipeline time {avg:.1f}us exceeds 500us target"
