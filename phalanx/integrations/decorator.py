"""Universal decorator for any agent framework.

Usage:
    from phalanx import AgentHypervisor
    from phalanx.integrations.decorator import phalanx_guard

    hv = AgentHypervisor(policies=[...], initial_trust=500)
    hv.register_agent("my-agent", "worker", "alice@co.com")

    @phalanx_guard(hv, "my-agent")
    def my_tool_function(query: str) -> str:
        return db.execute(query)

    # Every call to my_tool_function goes through the 7-step pipeline
    result = my_tool_function("SELECT * FROM users")
"""

from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

from phalanx.governance.hypervisor import AgentHypervisor, HypervisorResult
from phalanx.governance.types import ActionVerdict

F = TypeVar("F", bound=Callable[..., Any])


class PhalanxDenyError(Exception):
    """Raised when Phalanx denies a decorated function call."""

    def __init__(self, result: HypervisorResult) -> None:
        self.result = result
        super().__init__(f"Phalanx denied: {result.reason}")


def phalanx_guard(
    hypervisor: AgentHypervisor,
    agent_id: str,
    action_prefix: str = "tool:call",
    block_on_deny: bool = True,
) -> Callable[[F], F]:
    """Decorator that wraps any function with Phalanx governance.

    Args:
        hypervisor: The AgentHypervisor instance
        agent_id: The agent executing this function
        action_prefix: Prefix for the action name (default: "tool:call")
        block_on_deny: If True, raises PhalanxDenyError on deny
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Build action name from function name
            action = f"{action_prefix}:{fn.__name__}"

            # Build params from first string arg (for intent analysis)
            params: dict[str, Any] = {}
            if args and isinstance(args[0], str):
                params["input"] = args[0][:500]

            # Run through hypervisor
            result = hypervisor.execute(agent_id, action, params)

            if not result.allowed and block_on_deny:
                raise PhalanxDenyError(result)

            if not result.allowed:
                return None

            return fn(*args, **kwargs)

        # Attach the hypervisor result for inspection
        wrapper._phalanx_hypervisor = hypervisor  # type: ignore
        wrapper._phalanx_agent_id = agent_id  # type: ignore
        return wrapper  # type: ignore

    return decorator
