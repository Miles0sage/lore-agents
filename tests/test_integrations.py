"""Tests for framework integrations — decorator and LangChain handler."""

import pytest

from phalanx.governance.hypervisor import AgentHypervisor
from phalanx.governance.policy import StaticPolicy
from phalanx.governance.types import ActionVerdict
from phalanx.integrations.decorator import phalanx_guard, PhalanxDenyError
from phalanx.integrations.langchain import PhalanxCallbackHandler, PhalanxGovernanceError


class TestPhalanxGuardDecorator:
    def test_allows_safe_function(self):
        hv = AgentHypervisor(initial_trust=500, enable_intent=False)
        hv.register_agent("a1", "test", "alice")

        @phalanx_guard(hv, "a1")
        def safe_func(x: int) -> int:
            return x * 2

        assert safe_func(5) == 10

    def test_blocks_denied_function(self):
        hv = AgentHypervisor(
            policies=[StaticPolicy.deny(["tool:call:danger*"])],
            initial_trust=500,
            enable_intent=False,
        )
        hv.register_agent("a1", "test", "alice")

        @phalanx_guard(hv, "a1")
        def dangerous_func() -> str:
            return "should not reach here"

        with pytest.raises(PhalanxDenyError):
            dangerous_func()

    def test_non_blocking_mode(self):
        hv = AgentHypervisor(
            policies=[StaticPolicy.deny(["tool:call:blocked*"])],
            initial_trust=500,
            enable_intent=False,
        )
        hv.register_agent("a1", "test", "alice")

        @phalanx_guard(hv, "a1", block_on_deny=False)
        def blocked_func() -> str:
            return "reached"

        result = blocked_func()
        assert result is None  # Denied but not raised

    def test_preserves_function_name(self):
        hv = AgentHypervisor(initial_trust=500, enable_intent=False)
        hv.register_agent("a1", "test", "alice")

        @phalanx_guard(hv, "a1")
        def my_tool() -> str:
            """My docstring."""
            return "ok"

        assert my_tool.__name__ == "my_tool"
        assert my_tool.__doc__ == "My docstring."

    def test_custom_action_prefix(self):
        hv = AgentHypervisor(
            policies=[StaticPolicy.deny(["api:call:danger*"])],
            initial_trust=500,
            enable_intent=False,
        )
        hv.register_agent("a1", "test", "alice")

        @phalanx_guard(hv, "a1", action_prefix="api:call")
        def dangerous_api() -> str:
            return "nope"

        with pytest.raises(PhalanxDenyError):
            dangerous_api()

    def test_string_arg_passed_for_intent(self):
        hv = AgentHypervisor(initial_trust=500, enable_intent=True)
        hv.register_agent("a1", "test", "alice")

        @phalanx_guard(hv, "a1")
        def query_db(sql: str) -> str:
            return f"executed: {sql}"

        # Safe query passes
        result = query_db("SELECT * FROM users")
        assert "executed" in result

    def test_intent_blocks_dangerous_input(self):
        hv = AgentHypervisor(initial_trust=500, enable_intent=True)
        hv.register_agent("a1", "test", "alice")

        @phalanx_guard(hv, "a1")
        def query_db(sql: str) -> str:
            return f"executed: {sql}"

        with pytest.raises(PhalanxDenyError):
            query_db("DROP TABLE users;")


class TestLangChainHandler:
    def test_allows_safe_llm_call(self):
        hv = AgentHypervisor(initial_trust=500, enable_intent=False)
        hv.register_agent("a1", "test", "alice")
        handler = PhalanxCallbackHandler(hv, "a1")

        # Should not raise
        handler.on_llm_start(
            {"name": "gpt-4"},
            ["What is 2+2?"],
        )
        assert len(handler.results) == 1
        assert handler.results[0].allowed

    def test_allows_safe_tool_call(self):
        hv = AgentHypervisor(initial_trust=500, enable_intent=False)
        hv.register_agent("a1", "test", "alice")
        handler = PhalanxCallbackHandler(hv, "a1")

        handler.on_tool_start(
            {"name": "calculator"},
            "2 + 2",
        )
        assert handler.results[0].allowed

    def test_blocks_denied_tool(self):
        hv = AgentHypervisor(
            policies=[StaticPolicy.deny(["tool:call:danger*"])],
            initial_trust=500,
            enable_intent=False,
        )
        hv.register_agent("a1", "test", "alice")
        handler = PhalanxCallbackHandler(hv, "a1")

        with pytest.raises(PhalanxGovernanceError):
            handler.on_tool_start(
                {"name": "dangerous_tool"},
                "some input",
            )

    def test_non_blocking_mode(self):
        hv = AgentHypervisor(
            policies=[StaticPolicy.deny(["tool:call:blocked*"])],
            initial_trust=500,
            enable_intent=False,
        )
        hv.register_agent("a1", "test", "alice")
        handler = PhalanxCallbackHandler(hv, "a1", block_on_deny=False)

        # Should not raise even though denied
        handler.on_tool_start(
            {"name": "blocked_tool"},
            "some input",
        )
        assert not handler.results[0].allowed

    def test_intent_blocks_sql_injection(self):
        hv = AgentHypervisor(initial_trust=500, enable_intent=True)
        hv.register_agent("a1", "test", "alice")
        handler = PhalanxCallbackHandler(hv, "a1")

        with pytest.raises(PhalanxGovernanceError):
            handler.on_tool_start(
                {"name": "database"},
                "DROP TABLE users; --",
            )

    def test_chain_start(self):
        hv = AgentHypervisor(initial_trust=500, enable_intent=False)
        hv.register_agent("a1", "test", "alice")
        handler = PhalanxCallbackHandler(hv, "a1")

        handler.on_chain_start(
            {"name": "my_chain"},
            {"input": "test"},
        )
        assert handler.results[0].allowed
