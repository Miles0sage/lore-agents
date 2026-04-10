"""Policy definitions — static and dynamic.

KEY DESIGN DECISION: Policies are CALLABLE, not just YAML.
Microsoft AGT uses static YAML/OPA/Cedar files.
Phalanx policies are Python callables — this enables DynamicPolicy
(Week 5-6) to inject learned neural network weights.

BasePolicy is the ABC. StaticPolicy covers YAML-style rules.
DynamicPolicy (evolution layer) will extend BasePolicy with learned weights.
"""

from __future__ import annotations

import fnmatch
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

from phalanx.governance.types import (
    ActionVerdict,
    ExecutionContext,
    ExecutionRing,
    IntentCategory,
    PolicyResult,
)


class BasePolicy(ABC):
    """Abstract base for all Phalanx policies.

    Subclass this for static rules, rate limits, approval gates,
    or (Week 5-6) learned DynamicPolicy from Darwin engine.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique policy identifier."""

    @abstractmethod
    def evaluate(self, ctx: ExecutionContext) -> PolicyResult:
        """Evaluate this policy against an execution context.

        Must complete in <0.1ms for static policies.
        """

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"


class DenyListPolicy(BasePolicy):
    """Block actions matching glob patterns."""

    def __init__(
        self,
        policy_name: str,
        blocked_patterns: Sequence[str],
        reason: str = "Action blocked by deny list",
    ) -> None:
        self._name = policy_name
        self._blocked = list(blocked_patterns)
        self._reason = reason

    @property
    def name(self) -> str:
        return self._name

    def evaluate(self, ctx: ExecutionContext) -> PolicyResult:
        for pattern in self._blocked:
            if fnmatch.fnmatch(ctx.action, pattern):
                return PolicyResult(
                    verdict=ActionVerdict.DENY,
                    policy_name=self.name,
                    reason=f"{self._reason}: {ctx.action} matches {pattern}",
                )
        return PolicyResult(
            verdict=ActionVerdict.ALLOW,
            policy_name=self.name,
        )


class RateLimitPolicy(BasePolicy):
    """Enforce rate limits per agent."""

    def __init__(
        self,
        policy_name: str,
        max_calls: int,
        window_seconds: float,
    ) -> None:
        self._name = policy_name
        self._max_calls = max_calls
        self._window = window_seconds
        self._calls: dict[str, list[float]] = {}

    @property
    def name(self) -> str:
        return self._name

    def evaluate(self, ctx: ExecutionContext) -> PolicyResult:
        now = time.monotonic()
        agent_id = ctx.agent.agent_id
        timestamps = self._calls.setdefault(agent_id, [])

        # Prune expired entries
        cutoff = now - self._window
        timestamps[:] = [t for t in timestamps if t > cutoff]

        if len(timestamps) >= self._max_calls:
            return PolicyResult(
                verdict=ActionVerdict.RATE_LIMITED,
                policy_name=self.name,
                reason=f"Rate limit exceeded: {self._max_calls} calls per {self._window}s",
                metadata={"retry_after": timestamps[0] + self._window - now},
            )

        timestamps.append(now)
        return PolicyResult(
            verdict=ActionVerdict.ALLOW,
            policy_name=self.name,
        )


class RequireApprovalPolicy(BasePolicy):
    """Require human approval for dangerous actions."""

    def __init__(
        self,
        policy_name: str,
        action_patterns: Sequence[str],
        min_approvals: int = 1,
        timeout_minutes: float = 30.0,
    ) -> None:
        self._name = policy_name
        self._patterns = list(action_patterns)
        self._min_approvals = min_approvals
        self._timeout = timeout_minutes

    @property
    def name(self) -> str:
        return self._name

    def evaluate(self, ctx: ExecutionContext) -> PolicyResult:
        for pattern in self._patterns:
            if fnmatch.fnmatch(ctx.action, pattern):
                return PolicyResult(
                    verdict=ActionVerdict.REQUIRE_APPROVAL,
                    policy_name=self.name,
                    reason=f"Action {ctx.action} requires {self._min_approvals} approval(s)",
                    metadata={
                        "min_approvals": self._min_approvals,
                        "timeout_minutes": self._timeout,
                    },
                )
        return PolicyResult(
            verdict=ActionVerdict.ALLOW,
            policy_name=self.name,
        )


class RingGuardPolicy(BasePolicy):
    """Enforce minimum execution ring for actions."""

    def __init__(
        self,
        policy_name: str,
        action_ring_requirements: dict[str, ExecutionRing],
    ) -> None:
        self._name = policy_name
        self._requirements = action_ring_requirements

    @property
    def name(self) -> str:
        return self._name

    def evaluate(self, ctx: ExecutionContext) -> PolicyResult:
        for pattern, required_ring in self._requirements.items():
            if fnmatch.fnmatch(ctx.action, pattern):
                if ctx.ring > required_ring:  # Higher ring number = less privilege
                    return PolicyResult(
                        verdict=ActionVerdict.DENY,
                        policy_name=self.name,
                        reason=(
                            f"Action {ctx.action} requires Ring {required_ring.value} "
                            f"but agent is Ring {ctx.ring.value}"
                        ),
                        metadata={
                            "required_ring": required_ring.value,
                            "agent_ring": ctx.ring.value,
                        },
                    )
        return PolicyResult(
            verdict=ActionVerdict.ALLOW,
            policy_name=self.name,
        )


class CapabilityPolicy(BasePolicy):
    """Enforce capability-based access control."""

    def __init__(
        self,
        policy_name: str,
        action_capabilities: dict[str, str],
    ) -> None:
        """Map action patterns to required capabilities.

        Example: {"write:*": "write:data", "delete:*": "delete:data"}
        """
        self._name = policy_name
        self._caps = action_capabilities

    @property
    def name(self) -> str:
        return self._name

    def evaluate(self, ctx: ExecutionContext) -> PolicyResult:
        for action_pattern, required_cap in self._caps.items():
            if fnmatch.fnmatch(ctx.action, action_pattern):
                if not ctx.agent.can(required_cap):
                    return PolicyResult(
                        verdict=ActionVerdict.DENY,
                        policy_name=self.name,
                        reason=f"Agent lacks capability {required_cap!r} for {ctx.action}",
                    )
        return PolicyResult(
            verdict=ActionVerdict.ALLOW,
            policy_name=self.name,
        )


class CallablePolicy(BasePolicy):
    """Wrap any Python callable as a policy.

    This is the bridge to DynamicPolicy — any function that takes
    an ExecutionContext and returns a PolicyResult is a valid policy.
    """

    def __init__(
        self,
        policy_name: str,
        fn: Callable[[ExecutionContext], PolicyResult],
    ) -> None:
        self._name = policy_name
        self._fn = fn

    @property
    def name(self) -> str:
        return self._name

    def evaluate(self, ctx: ExecutionContext) -> PolicyResult:
        return self._fn(ctx)


# Convenience constructors matching Microsoft's API
class StaticPolicy:
    """Factory for common static policies (Microsoft AGT compatible)."""

    @staticmethod
    def read_only(name: str = "read_only") -> DenyListPolicy:
        return DenyListPolicy(
            policy_name=name,
            blocked_patterns=["write:*", "delete:*", "update:*", "create:*"],
            reason="Read-only policy blocks mutations",
        )

    @staticmethod
    def rate_limit(
        max_calls: int,
        window: str,
        name: str = "rate_limit",
    ) -> RateLimitPolicy:
        seconds = _parse_window(window)
        return RateLimitPolicy(
            policy_name=name,
            max_calls=max_calls,
            window_seconds=seconds,
        )

    @staticmethod
    def require_approval(
        actions: Sequence[str],
        min_approvals: int = 1,
        timeout_minutes: float = 30.0,
        name: str = "require_approval",
    ) -> RequireApprovalPolicy:
        return RequireApprovalPolicy(
            policy_name=name,
            action_patterns=actions,
            min_approvals=min_approvals,
            timeout_minutes=timeout_minutes,
        )

    @staticmethod
    def deny(
        patterns: Sequence[str],
        reason: str = "Denied by policy",
        name: str = "deny_list",
    ) -> DenyListPolicy:
        return DenyListPolicy(
            policy_name=name,
            blocked_patterns=patterns,
            reason=reason,
        )

    @staticmethod
    def ring_guard(
        requirements: dict[str, ExecutionRing],
        name: str = "ring_guard",
    ) -> RingGuardPolicy:
        return RingGuardPolicy(
            policy_name=name,
            action_ring_requirements=requirements,
        )

    @staticmethod
    def capability_guard(
        caps: dict[str, str],
        name: str = "capability_guard",
    ) -> CapabilityPolicy:
        return CapabilityPolicy(
            policy_name=name,
            action_capabilities=caps,
        )


def _parse_window(window: str) -> float:
    """Parse time window strings like '1m', '30s', '1h'."""
    unit = window[-1].lower()
    value = float(window[:-1])
    multipliers = {"s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}
    if unit not in multipliers:
        raise ValueError(f"Unknown time unit: {unit!r}. Use s/m/h/d.")
    return value * multipliers[unit]
