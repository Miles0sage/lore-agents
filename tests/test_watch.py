"""Tests for @watch decorator + compile pipeline — the MVP."""

import json
import shutil
import time
from pathlib import Path

import pytest

from phalanx.watch import watch, call, WatchError
from phalanx.compile import compile_rules


@pytest.fixture
def tmp_phalanx(tmp_path):
    """Create temp directories for failures and rules."""
    failures_dir = tmp_path / ".phalanx" / "failures"
    failures_dir.mkdir(parents=True)
    rules_path = tmp_path / "SAFETY_RULES.md"
    return {"failures_dir": failures_dir, "rules_path": rules_path, "root": tmp_path}


class TestWatch:
    def test_passes_through_on_success(self, tmp_phalanx):
        @watch("a1", failures_dir=tmp_phalanx["failures_dir"])
        def good_func(x: int) -> int:
            return x * 2

        assert good_func(5) == 10

    def test_captures_failure(self, tmp_phalanx):
        @watch("a1", failures_dir=tmp_phalanx["failures_dir"])
        def bad_func():
            raise ValueError("something broke")

        with pytest.raises(ValueError, match="something broke"):
            bad_func()

        # Check failure was recorded
        files = list(tmp_phalanx["failures_dir"].glob("*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text())
        assert data["agent_id"] == "a1"
        assert data["error_type"] == "ValueError"
        assert "something broke" in data["error_message"]

    def test_captures_input(self, tmp_phalanx):
        @watch("a1", failures_dir=tmp_phalanx["failures_dir"])
        def query_db(sql: str) -> str:
            raise RuntimeError(f"SQL error: {sql}")

        with pytest.raises(RuntimeError):
            query_db("DROP TABLE users")

        files = list(tmp_phalanx["failures_dir"].glob("*.json"))
        data = json.loads(files[0].read_text())
        assert "DROP TABLE" in data["input_preview"]

    def test_preserves_function_metadata(self, tmp_phalanx):
        @watch("a1", failures_dir=tmp_phalanx["failures_dir"])
        def my_func():
            """My docstring."""
            return 42

        assert my_func.__name__ == "my_func"
        assert my_func.__doc__ == "My docstring."

    def test_enforces_learned_rules(self, tmp_phalanx):
        # Write a rule
        tmp_phalanx["rules_path"].write_text("- DENY: drop table\n")

        @watch("a1", rules_path=tmp_phalanx["rules_path"],
               failures_dir=tmp_phalanx["failures_dir"])
        def query_db(sql: str) -> str:
            return f"executed: {sql}"

        with pytest.raises(WatchError, match="drop table"):
            query_db("DROP TABLE users")

    def test_allows_safe_calls_with_rules(self, tmp_phalanx):
        tmp_phalanx["rules_path"].write_text("- DENY: drop table\n")

        @watch("a1", rules_path=tmp_phalanx["rules_path"],
               failures_dir=tmp_phalanx["failures_dir"])
        def query_db(sql: str) -> str:
            return f"executed: {sql}"

        result = query_db("SELECT * FROM users")
        assert "executed" in result

    def test_records_blocks(self, tmp_phalanx):
        tmp_phalanx["rules_path"].write_text("- DENY: danger\n")

        @watch("a1", rules_path=tmp_phalanx["rules_path"],
               failures_dir=tmp_phalanx["failures_dir"])
        def dangerous(x: str) -> str:
            return x

        with pytest.raises(WatchError):
            dangerous("this is danger zone")

        block_files = list(tmp_phalanx["failures_dir"].glob("*_block.json"))
        assert len(block_files) == 1

    def test_non_blocking_mode(self, tmp_phalanx):
        tmp_phalanx["rules_path"].write_text("- DENY: danger\n")

        @watch("a1", rules_path=tmp_phalanx["rules_path"],
               failures_dir=tmp_phalanx["failures_dir"],
               block_on_match=False)
        def safe_anyway(x: str) -> str:
            return x

        # Should not raise even with matching rule
        result = safe_anyway("danger zone")
        assert result == "danger zone"

    def test_call_function(self, tmp_phalanx):
        def add(a: int, b: int) -> int:
            return a + b

        result = call("a1", add, 2, 3)
        assert result == 5


class TestCompile:
    def test_no_failures_no_rules(self, tmp_phalanx):
        rules = compile_rules(
            failures_dir=tmp_phalanx["failures_dir"],
            rules_path=tmp_phalanx["rules_path"],
        )
        assert rules == []

    def test_single_failure_below_threshold(self, tmp_phalanx):
        # Write one failure
        record = {
            "timestamp": time.time(),
            "agent_id": "a1",
            "action": "tool:call:query",
            "input_preview": "DROP TABLE users",
            "error_type": "RuntimeError",
            "error_message": "SQL error: drop table attempt blocked",
            "traceback": "",
        }
        (tmp_phalanx["failures_dir"] / "001_a1.json").write_text(
            json.dumps(record)
        )
        rules = compile_rules(
            failures_dir=tmp_phalanx["failures_dir"],
            rules_path=tmp_phalanx["rules_path"],
            min_occurrences=2,
        )
        assert rules == []  # Need 2+ occurrences

    def test_generates_rule_at_threshold(self, tmp_phalanx):
        for i in range(3):
            record = {
                "timestamp": time.time() + i,
                "agent_id": f"a{i}",
                "action": "tool:call:query",
                "input_preview": "DROP TABLE users",
                "error_type": "RuntimeError",
                "error_message": "SQL error: drop table not allowed",
                "traceback": "",
            }
            (tmp_phalanx["failures_dir"] / f"00{i}_a{i}.json").write_text(
                json.dumps(record)
            )
        rules = compile_rules(
            failures_dir=tmp_phalanx["failures_dir"],
            rules_path=tmp_phalanx["rules_path"],
            min_occurrences=2,
        )
        assert len(rules) >= 1
        assert tmp_phalanx["rules_path"].exists()
        content = tmp_phalanx["rules_path"].read_text()
        assert "DENY:" in content

    def test_doesnt_duplicate_rules(self, tmp_phalanx):
        # Write existing rule
        tmp_phalanx["rules_path"].write_text("- DENY: drop\n")

        for i in range(3):
            record = {
                "timestamp": time.time() + i,
                "agent_id": f"a{i}",
                "action": "tool:call:query",
                "input_preview": "DROP TABLE",
                "error_type": "RuntimeError",
                "error_message": "drop table error",
                "traceback": "",
            }
            (tmp_phalanx["failures_dir"] / f"00{i}_a{i}.json").write_text(
                json.dumps(record)
            )
        rules = compile_rules(
            failures_dir=tmp_phalanx["failures_dir"],
            rules_path=tmp_phalanx["rules_path"],
        )
        assert len(rules) == 0  # Already exists

    def test_multiple_error_types(self, tmp_phalanx):
        # SQL errors
        for i in range(3):
            record = {
                "timestamp": time.time() + i,
                "agent_id": f"a{i}",
                "action": "tool:call:query",
                "input_preview": f"DELETE FROM users WHERE id={i}",
                "error_type": "PermissionError",
                "error_message": "delete operation denied by policy",
                "traceback": "",
            }
            (tmp_phalanx["failures_dir"] / f"sql_{i}.json").write_text(
                json.dumps(record)
            )
        # Auth errors
        for i in range(3):
            record = {
                "timestamp": time.time() + i + 10,
                "agent_id": f"b{i}",
                "action": "tool:call:admin",
                "input_preview": f"sudo command {i}",
                "error_type": "AuthError",
                "error_message": "unauthorized sudo escalation attempt",
                "traceback": "",
            }
            (tmp_phalanx["failures_dir"] / f"auth_{i}.json").write_text(
                json.dumps(record)
            )
        rules = compile_rules(
            failures_dir=tmp_phalanx["failures_dir"],
            rules_path=tmp_phalanx["rules_path"],
            min_occurrences=2,
        )
        assert len(rules) >= 2  # Should find both patterns


class TestFullLoop:
    """The complete loop: fail → compile → block."""

    def test_failure_to_immunity(self, tmp_phalanx):
        """The 60-second demo in test form."""

        # Step 1: Agent fails multiple times
        @watch("agent-1", failures_dir=tmp_phalanx["failures_dir"],
               rules_path=tmp_phalanx["rules_path"])
        def risky_query(sql: str) -> str:
            if "drop" in sql.lower():
                raise RuntimeError("SQL error: drop table not allowed")
            return f"ok: {sql}"

        # Multiple agents hit the same failure (fleet-wide pattern)
        for i in range(3):
            @watch(f"agent-{i}", failures_dir=tmp_phalanx["failures_dir"],
                   rules_path=tmp_phalanx["rules_path"])
            def fleet_query(sql: str) -> str:
                if "drop" in sql.lower():
                    raise RuntimeError("SQL error: drop table not allowed")
                return f"ok: {sql}"

            with pytest.raises(RuntimeError):
                fleet_query("DROP TABLE users")

        # Step 2: Compile failures into rules
        rules = compile_rules(
            failures_dir=tmp_phalanx["failures_dir"],
            rules_path=tmp_phalanx["rules_path"],
            min_occurrences=2,
        )
        assert len(rules) >= 1
        assert tmp_phalanx["rules_path"].exists()

        # Step 3: New agent is now IMMUNE — blocked before execution
        @watch("agent-2", failures_dir=tmp_phalanx["failures_dir"],
               rules_path=tmp_phalanx["rules_path"])
        def another_query(sql: str) -> str:
            return f"executed: {sql}"  # Should never reach here

        with pytest.raises(WatchError):
            another_query("DROP TABLE users")

        # Step 4: Safe queries still work
        result = another_query("SELECT * FROM users")
        assert "executed" in result
