"""LangChain integration — governance as a callback handler.

Usage:
    from phalanx.integrations.langchain import PhalanxCallbackHandler

    handler = PhalanxCallbackHandler(hypervisor=hv, agent_id="my-agent")
    llm = ChatOpenAI(callbacks=[handler])

Intercepts every LLM call and tool use through Phalanx's 7-step pipeline.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from phalanx.governance.hypervisor import AgentHypervisor, HypervisorResult
from phalanx.governance.types import ActionVerdict


class PhalanxGovernanceError(Exception):
    """Raised when Phalanx blocks an action."""

    def __init__(self, result: HypervisorResult) -> None:
        self.result = result
        super().__init__(f"Phalanx blocked action: {result.reason}")


class PhalanxCallbackHandler:
    """LangChain callback handler that enforces Phalanx governance.

    Intercepts on_llm_start, on_tool_start, and on_chain_start
    to run each action through the full hypervisor pipeline.

    Compatible with LangChain's BaseCallbackHandler interface.
    Import LangChain only if this module is used.
    """

    def __init__(
        self,
        hypervisor: AgentHypervisor,
        agent_id: str,
        block_on_deny: bool = True,
    ) -> None:
        self._hv = hypervisor
        self._agent_id = agent_id
        self._block = block_on_deny
        self._results: list[HypervisorResult] = []

    @property
    def results(self) -> list[HypervisorResult]:
        return list(self._results)

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """Intercept LLM calls."""
        model_name = serialized.get("name", serialized.get("id", ["unknown"])[-1])
        result = self._hv.execute(
            self._agent_id,
            f"llm:call:{model_name}",
            {"prompts_count": len(prompts)},
        )
        self._results.append(result)
        if self._block and not result.allowed:
            raise PhalanxGovernanceError(result)

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Intercept tool calls — the critical governance point."""
        tool_name = serialized.get("name", "unknown_tool")
        result = self._hv.execute(
            self._agent_id,
            f"tool:call:{tool_name}",
            {"input": input_str[:500]},  # Truncate for intent analysis
        )
        self._results.append(result)
        if self._block and not result.allowed:
            raise PhalanxGovernanceError(result)

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Intercept chain starts."""
        chain_name = serialized.get("name", serialized.get("id", ["unknown"])[-1])
        result = self._hv.execute(
            self._agent_id,
            f"chain:start:{chain_name}",
        )
        self._results.append(result)
        if self._block and not result.allowed:
            raise PhalanxGovernanceError(result)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Track successful LLM completions for trust rewards."""
        pass

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Track successful tool completions."""
        pass

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        """Track LLM errors for Darwin failure capture."""
        pass

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        """Track tool errors for Darwin failure capture."""
        pass
