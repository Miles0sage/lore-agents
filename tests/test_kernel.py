"""Tests for the stateless policy evaluation kernel."""

from phalanx.governance.types import (
    ActionVerdict,
    AgentIdentity,
    ExecutionContext,
)
from phalanx.governance.kernel import KernelResult, StatelessKernel
from phalanx.governance.policy import DenyListPolicy, RateLimitPolicy, StaticPolicy


def _make_ctx(action: str = "read:data", trust: int = 500) -> ExecutionContext:
    return ExecutionContext(
        agent=AgentIdentity(agent_id="a1", name="test", sponsor="alice", trust_score=trust),
        action=action,
    )


class TestStatelessKernel:
    def test_no_policies_allows_all(self):
        kernel = StatelessKernel()
        result = kernel.evaluate(_make_ctx())
        assert result.allowed
        assert result.verdict == ActionVerdict.ALLOW

    def test_single_deny(self):
        kernel = StatelessKernel([StaticPolicy.deny(["delete:*"])])
        result = kernel.evaluate(_make_ctx("delete:users"))
        assert result.denied
        assert not result.allowed

    def test_deny_beats_allow(self):
        kernel = StatelessKernel([
            StaticPolicy.read_only(),       # denies write
            StaticPolicy.rate_limit(100, "1m"),  # allows (under limit)
        ])
        result = kernel.evaluate(_make_ctx("write:data"))
        assert result.denied

    def test_multiple_allows(self):
        kernel = StatelessKernel([
            StaticPolicy.rate_limit(100, "1m"),
            StaticPolicy.deny(["drop:*"]),
        ])
        result = kernel.evaluate(_make_ctx("read:data"))
        assert result.allowed

    def test_short_circuit_on_deny(self):
        kernel = StatelessKernel([
            StaticPolicy.deny(["*"]),  # Deny everything
            StaticPolicy.rate_limit(1, "1s"),  # Should not be reached
        ])
        result = kernel.evaluate(_make_ctx("anything"))
        assert result.denied
        assert len(result.results) == 1  # Short-circuited

    def test_elapsed_time_tracked(self):
        kernel = StatelessKernel([StaticPolicy.rate_limit(100, "1m")])
        result = kernel.evaluate(_make_ctx())
        assert result.elapsed_us >= 0

    def test_blocking_results(self):
        kernel = StatelessKernel([
            StaticPolicy.deny(["write:*"]),
            StaticPolicy.rate_limit(100, "1m"),
        ])
        result = kernel.evaluate(_make_ctx("write:data"))
        assert len(result.blocking_results) == 1

    def test_add_remove_policy(self):
        kernel = StatelessKernel()
        kernel.add_policy(StaticPolicy.deny(["drop:*"], name="no_drop"))
        assert len(kernel.policies) == 1

        removed = kernel.remove_policy("no_drop")
        assert removed
        assert len(kernel.policies) == 0

    def test_remove_nonexistent(self):
        kernel = StatelessKernel()
        assert not kernel.remove_policy("nope")

    def test_require_approval_verdict(self):
        kernel = StatelessKernel([
            StaticPolicy.require_approval(["deploy:*"], min_approvals=2),
        ])
        result = kernel.evaluate(_make_ctx("deploy:production"))
        assert result.verdict == ActionVerdict.REQUIRE_APPROVAL
        assert not result.allowed


class TestKernelPerformance:
    def test_sub_100us_for_static_policies(self):
        """Policy evaluation must complete in <100us (0.1ms)."""
        kernel = StatelessKernel([
            StaticPolicy.deny(["drop:*"]),
            StaticPolicy.rate_limit(1000, "1m"),
            StaticPolicy.require_approval(["deploy:*"]),
            StaticPolicy.read_only(name="ro2"),
        ])
        # Warm up
        kernel.evaluate(_make_ctx())

        # Measure
        results = []
        for _ in range(100):
            r = kernel.evaluate(_make_ctx("read:data"))
            results.append(r.elapsed_us)

        avg = sum(results) / len(results)
        # Should be well under 100us for 4 static policies
        assert avg < 100, f"Average evaluation time {avg:.1f}us exceeds 100us target"
