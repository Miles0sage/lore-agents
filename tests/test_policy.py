"""Tests for policy definitions."""

import time

from phalanx.governance.types import (
    ActionVerdict,
    AgentIdentity,
    ExecutionContext,
    ExecutionRing,
    PolicyResult,
)
from phalanx.governance.policy import (
    BasePolicy,
    CallablePolicy,
    CapabilityPolicy,
    DenyListPolicy,
    RateLimitPolicy,
    RequireApprovalPolicy,
    RingGuardPolicy,
    StaticPolicy,
    _parse_window,
)


def _make_ctx(
    action: str = "read:data",
    trust: int = 500,
    capabilities: frozenset[str] | None = None,
) -> ExecutionContext:
    return ExecutionContext(
        agent=AgentIdentity(
            agent_id="a1", name="test", sponsor="alice",
            trust_score=trust,
            capabilities=capabilities or frozenset(),
        ),
        action=action,
    )


class TestDenyListPolicy:
    def test_blocks_matching_action(self):
        p = DenyListPolicy("deny", ["delete:*"])
        result = p.evaluate(_make_ctx("delete:users"))
        assert result.verdict == ActionVerdict.DENY

    def test_allows_non_matching(self):
        p = DenyListPolicy("deny", ["delete:*"])
        result = p.evaluate(_make_ctx("read:users"))
        assert result.verdict == ActionVerdict.ALLOW

    def test_exact_match(self):
        p = DenyListPolicy("deny", ["drop_database"])
        assert p.evaluate(_make_ctx("drop_database")).verdict == ActionVerdict.DENY
        assert p.evaluate(_make_ctx("drop_table")).verdict == ActionVerdict.ALLOW


class TestRateLimitPolicy:
    def test_allows_under_limit(self):
        p = RateLimitPolicy("rl", max_calls=5, window_seconds=60)
        for _ in range(5):
            result = p.evaluate(_make_ctx())
            assert result.verdict == ActionVerdict.ALLOW

    def test_blocks_over_limit(self):
        p = RateLimitPolicy("rl", max_calls=2, window_seconds=60)
        p.evaluate(_make_ctx())
        p.evaluate(_make_ctx())
        result = p.evaluate(_make_ctx())
        assert result.verdict == ActionVerdict.RATE_LIMITED

    def test_retry_after_in_metadata(self):
        p = RateLimitPolicy("rl", max_calls=1, window_seconds=60)
        p.evaluate(_make_ctx())
        result = p.evaluate(_make_ctx())
        assert "retry_after" in result.metadata


class TestRequireApprovalPolicy:
    def test_requires_approval_for_matching(self):
        p = RequireApprovalPolicy("approve", ["delete:*"], min_approvals=2)
        result = p.evaluate(_make_ctx("delete:users"))
        assert result.verdict == ActionVerdict.REQUIRE_APPROVAL
        assert result.metadata["min_approvals"] == 2

    def test_allows_non_matching(self):
        p = RequireApprovalPolicy("approve", ["delete:*"])
        result = p.evaluate(_make_ctx("read:data"))
        assert result.verdict == ActionVerdict.ALLOW


class TestRingGuardPolicy:
    def test_denies_insufficient_ring(self):
        p = RingGuardPolicy("rg", {"write:*": ExecutionRing.SUPERVISOR})
        # trust=500 => Ring 2 (USER), but write needs Ring 1 (SUPERVISOR)
        result = p.evaluate(_make_ctx("write:data", trust=500))
        assert result.verdict == ActionVerdict.DENY

    def test_allows_sufficient_ring(self):
        p = RingGuardPolicy("rg", {"write:*": ExecutionRing.USER})
        result = p.evaluate(_make_ctx("write:data", trust=500))
        assert result.verdict == ActionVerdict.ALLOW

    def test_allows_higher_ring(self):
        p = RingGuardPolicy("rg", {"write:*": ExecutionRing.USER})
        result = p.evaluate(_make_ctx("write:data", trust=900))
        assert result.verdict == ActionVerdict.ALLOW


class TestCapabilityPolicy:
    def test_denies_missing_capability(self):
        p = CapabilityPolicy("cap", {"write:*": "write:data"})
        result = p.evaluate(_make_ctx("write:users", capabilities=frozenset({"read:data"})))
        assert result.verdict == ActionVerdict.DENY

    def test_allows_with_capability(self):
        p = CapabilityPolicy("cap", {"write:*": "write:data"})
        result = p.evaluate(_make_ctx("write:users", capabilities=frozenset({"write:data"})))
        assert result.verdict == ActionVerdict.ALLOW


class TestCallablePolicy:
    def test_wraps_function(self):
        def my_policy(ctx: ExecutionContext) -> PolicyResult:
            if "danger" in ctx.action:
                return PolicyResult(verdict=ActionVerdict.DENY, policy_name="custom")
            return PolicyResult(verdict=ActionVerdict.ALLOW, policy_name="custom")

        p = CallablePolicy("custom", my_policy)
        assert p.evaluate(_make_ctx("danger:zone")).verdict == ActionVerdict.DENY
        assert p.evaluate(_make_ctx("safe:action")).verdict == ActionVerdict.ALLOW


class TestStaticPolicyFactory:
    def test_read_only(self):
        p = StaticPolicy.read_only()
        assert p.evaluate(_make_ctx("write:data")).verdict == ActionVerdict.DENY
        assert p.evaluate(_make_ctx("read:data")).verdict == ActionVerdict.ALLOW

    def test_rate_limit(self):
        p = StaticPolicy.rate_limit(1, "1m")
        assert p.evaluate(_make_ctx()).verdict == ActionVerdict.ALLOW
        assert p.evaluate(_make_ctx()).verdict == ActionVerdict.RATE_LIMITED

    def test_deny(self):
        p = StaticPolicy.deny(["drop:*"])
        assert p.evaluate(_make_ctx("drop:database")).verdict == ActionVerdict.DENY


class TestParseWindow:
    def test_seconds(self):
        assert _parse_window("30s") == 30.0

    def test_minutes(self):
        assert _parse_window("5m") == 300.0

    def test_hours(self):
        assert _parse_window("1h") == 3600.0

    def test_days(self):
        assert _parse_window("1d") == 86400.0

    def test_invalid_unit(self):
        try:
            _parse_window("5x")
            assert False, "Should raise"
        except ValueError:
            pass
