"""Tests for Darwin Failure Capture — the moat."""

from phalanx.governance.types import (
    ActionVerdict,
    AgentIdentity,
    ExecutionContext,
    ExecutionRing,
    IntentCategory,
    PolicyResult,
)
from phalanx.evolution.darwin import (
    DarwinFailureCapture,
    FailureCluster,
    FailureRecord,
    LearnedRule,
)


def _make_ctx(
    agent_id: str = "a1",
    action: str = "write:data",
    trust: int = 500,
    params: dict | None = None,
) -> ExecutionContext:
    return ExecutionContext(
        agent=AgentIdentity(
            agent_id=agent_id, name="test", sponsor="alice",
            trust_score=trust,
        ),
        action=action,
        params=params or {},
    )


class TestRootCauseHash:
    def test_deterministic(self):
        darwin = DarwinFailureCapture()
        ctx = _make_ctx()
        h1 = darwin.generate_root_cause_hash(ctx)
        h2 = darwin.generate_root_cause_hash(ctx)
        assert h1 == h2

    def test_different_actions_different_hash(self):
        darwin = DarwinFailureCapture()
        h1 = darwin.generate_root_cause_hash(_make_ctx(action="write:data"))
        h2 = darwin.generate_root_cause_hash(_make_ctx(action="delete:data"))
        assert h1 != h2

    def test_different_rings_different_hash(self):
        darwin = DarwinFailureCapture()
        h1 = darwin.generate_root_cause_hash(_make_ctx(trust=500))  # Ring 2
        h2 = darwin.generate_root_cause_hash(_make_ctx(trust=100))  # Ring 3
        assert h1 != h2

    def test_different_intent_different_hash(self):
        darwin = DarwinFailureCapture()
        ctx = _make_ctx()
        h1 = darwin.generate_root_cause_hash(ctx, intent=IntentCategory.SAFE)
        h2 = darwin.generate_root_cause_hash(ctx, intent=IntentCategory.DESTRUCTIVE_DATA)
        assert h1 != h2

    def test_hash_length(self):
        darwin = DarwinFailureCapture()
        h = darwin.generate_root_cause_hash(_make_ctx())
        assert len(h) == 16


class TestCapture:
    def test_capture_adds_to_buffer(self):
        darwin = DarwinFailureCapture()
        ctx = _make_ctx()
        darwin.capture(ctx)
        assert darwin.buffer_size == 1

    def test_capture_returns_record(self):
        darwin = DarwinFailureCapture()
        record = darwin.capture(_make_ctx())
        assert isinstance(record, FailureRecord)
        assert record.agent_id == "a1"
        assert record.action == "write:data"

    def test_buffer_eviction(self):
        darwin = DarwinFailureCapture(max_buffer_size=5)
        for i in range(10):
            darwin.capture(_make_ctx(agent_id=f"a{i}"))
        assert darwin.buffer_size == 5

    def test_capture_with_policy_result(self):
        darwin = DarwinFailureCapture()
        result = PolicyResult(verdict=ActionVerdict.DENY, policy_name="test")
        record = darwin.capture(_make_ctx(), result=result)
        assert record.verdict == ActionVerdict.DENY

    def test_capture_with_intent(self):
        darwin = DarwinFailureCapture()
        record = darwin.capture(
            _make_ctx(), intent=IntentCategory.PROMPT_INJECTION,
        )
        assert record.intent_category == IntentCategory.PROMPT_INJECTION


class TestAnalyze:
    def test_no_clusters_below_threshold(self):
        darwin = DarwinFailureCapture(min_cluster_size=3)
        darwin.capture(_make_ctx())
        darwin.capture(_make_ctx())
        clusters = darwin.analyze()
        assert len(clusters) == 0

    def test_cluster_at_threshold(self):
        darwin = DarwinFailureCapture(min_cluster_size=3)
        for _ in range(3):
            darwin.capture(_make_ctx(action="bad:action"))
        clusters = darwin.analyze()
        assert len(clusters) == 1

    def test_cluster_tracks_agents(self):
        darwin = DarwinFailureCapture(min_cluster_size=3)
        for i in range(3):
            darwin.capture(_make_ctx(agent_id=f"a{i}", action="bad:action"))
        clusters = darwin.analyze()
        assert len(clusters[0].agent_ids) == 3

    def test_novel_cluster(self):
        darwin = DarwinFailureCapture(min_cluster_size=3)
        # Same action from 3 different agents = novel pattern
        for i in range(3):
            darwin.capture(_make_ctx(agent_id=f"a{i}", action="bad:action"))
        clusters = darwin.analyze()
        assert clusters[0].is_novel

    def test_not_novel_single_agent(self):
        darwin = DarwinFailureCapture(min_cluster_size=3)
        # Same agent, same action = not novel (just one agent misbehaving)
        for _ in range(3):
            darwin.capture(_make_ctx(agent_id="a1", action="bad:action"))
        clusters = darwin.analyze()
        assert not clusters[0].is_novel

    def test_multiple_clusters(self):
        darwin = DarwinFailureCapture(min_cluster_size=3)
        for _ in range(3):
            darwin.capture(_make_ctx(action="attack:sql"))
        for _ in range(3):
            darwin.capture(_make_ctx(action="exfil:data"))
        clusters = darwin.analyze()
        assert len(clusters) == 2

    def test_confidence_increases_with_spread(self):
        darwin = DarwinFailureCapture(min_cluster_size=3)
        # 3 failures from 1 agent
        for _ in range(3):
            darwin.capture(_make_ctx(agent_id="a1", action="bad:action"))
        clusters1 = darwin.analyze()

        darwin2 = DarwinFailureCapture(min_cluster_size=3)
        # 3 failures from 3 agents
        for i in range(3):
            darwin2.capture(_make_ctx(agent_id=f"a{i}", action="bad:action"))
        clusters2 = darwin2.analyze()

        assert clusters2[0].confidence > clusters1[0].confidence


class TestGenerateRules:
    def test_generates_rules_from_cluster(self):
        darwin = DarwinFailureCapture(min_cluster_size=3)
        for i in range(5):
            darwin.capture(_make_ctx(agent_id=f"a{i}", action="attack:sql:injection"))
        clusters = darwin.analyze()
        rules = darwin.generate_rules(clusters[0])
        assert len(rules) >= 1
        assert isinstance(rules[0], LearnedRule)

    def test_rule_has_action_pattern(self):
        darwin = DarwinFailureCapture(min_cluster_size=3)
        for i in range(3):
            darwin.capture(_make_ctx(agent_id=f"a{i}", action="attack:sql:injection"))
        clusters = darwin.analyze()
        rules = darwin.generate_rules(clusters[0])
        assert rules[0].action_pattern.endswith("*")

    def test_rules_tracked(self):
        darwin = DarwinFailureCapture(min_cluster_size=3)
        for i in range(3):
            darwin.capture(_make_ctx(agent_id=f"a{i}", action="bad:thing"))
        clusters = darwin.analyze()
        darwin.generate_rules(clusters[0])
        assert len(darwin.learned_rules) >= 1

    def test_rule_confidence_from_cluster(self):
        darwin = DarwinFailureCapture(min_cluster_size=3)
        for i in range(3):
            darwin.capture(_make_ctx(agent_id=f"a{i}", action="bad:thing"))
        clusters = darwin.analyze()
        rules = darwin.generate_rules(clusters[0])
        assert rules[0].confidence == clusters[0].confidence


class TestStats:
    def test_stats(self):
        darwin = DarwinFailureCapture(min_cluster_size=3)
        for i in range(5):
            darwin.capture(_make_ctx(agent_id=f"a{i}", action="bad:thing"))
        darwin.analyze()
        stats = darwin.get_stats()
        assert stats["buffer_size"] == 5
        assert stats["clusters"] == 1
        assert stats["novel_clusters"] == 1
