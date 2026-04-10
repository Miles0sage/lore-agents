"""phalanx.watch — The 50-line decorator that turns agent failures into knowledge.

Usage:
    from phalanx import watch

    @watch("my-agent")
    def my_tool(query: str) -> str:
        return db.execute(query)

    # Agent fails → failure captured → rule proposed → knowledge compounds

Or wrap any function inline:

    result = watch.call("my-agent", dangerous_function, "DROP TABLE users")

That's it. Your agent learns from its own mistakes.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import time
import traceback
from pathlib import Path
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

_DEFAULT_RULES_PATH = Path("SAFETY_RULES.md")
_DEFAULT_FAILURES_DIR = Path(".phalanx/failures")


class WatchError(Exception):
    """Raised when a watched function is blocked by a learned rule."""
    def __init__(self, rule: str, action: str) -> None:
        self.rule = rule
        self.action = action
        super().__init__(f"Blocked by learned rule: {rule}")


def watch(
    agent_id: str,
    rules_path: Path | str | None = None,
    failures_dir: Path | str | None = None,
    block_on_match: bool = True,
    injection_gate: bool = True,
) -> Callable[[F], F]:
    """Decorator that watches a function for failures and enforces learned rules.

    When the function fails:
    1. Captures the failure context (function name, args, error, traceback)
    2. Writes to .phalanx/failures/ as structured JSON
    3. Next run of `phalanx compile` generates rules from accumulated failures

    When rules exist in SAFETY_RULES.md:
    1. Checks input against learned deny patterns
    2. Blocks matching calls before execution
    """
    _rules = _load_rules(Path(rules_path) if rules_path else _DEFAULT_RULES_PATH)
    _dir = Path(failures_dir) if failures_dir else _DEFAULT_FAILURES_DIR

    def decorator(fn: F) -> F:
        is_async = inspect.iscoroutinefunction(fn)

        def _pre_execute(action: str, input_text: str) -> None:
            """Shared pre-execution gates (injection + rules). Raises WatchError if blocked."""
            if injection_gate:
                from phalanx.injection import detect_injection
                is_injection, confidence = detect_injection(input_text)
                if is_injection:
                    _record_injection(_dir, agent_id, action, input_text, confidence)
                    raise WatchError(f"injection:confidence={confidence:.2f}", action)
            if block_on_match:
                for rule in _rules:
                    if _matches_rule(rule, action, input_text):
                        _record_block(_dir, agent_id, action, input_text, rule)
                        raise WatchError(rule["pattern"], action)

        if is_async:
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                action = f"tool:call:{fn.__name__}"
                input_text = _extract_input(args, kwargs)
                _pre_execute(action, input_text)
                try:
                    return await fn(*args, **kwargs)
                except WatchError:
                    raise
                except Exception as e:
                    _record_failure(_dir, agent_id, action, input_text, e)
                    raise

            async_wrapper._phalanx_agent_id = agent_id  # type: ignore
            return async_wrapper  # type: ignore
        else:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                action = f"tool:call:{fn.__name__}"
                input_text = _extract_input(args, kwargs)
                _pre_execute(action, input_text)
                try:
                    return fn(*args, **kwargs)
                except WatchError:
                    raise
                except Exception as e:
                    _record_failure(_dir, agent_id, action, input_text, e)
                    raise

            wrapper._phalanx_agent_id = agent_id  # type: ignore
            return wrapper  # type: ignore

    return decorator


def call(agent_id: str, fn: Callable, *args: Any, **kwargs: Any) -> Any:
    """Watch a single function call without decorating."""
    watched = watch(agent_id)(fn)
    return watched(*args, **kwargs)


def _load_rules(path: Path) -> list[dict[str, Any]]:
    """Load learned rules from SAFETY_RULES.md."""
    if not path.exists():
        return []
    rules: list[dict[str, Any]] = []
    content = path.read_text()
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("- DENY:"):
            pattern = line[len("- DENY:"):].strip()
            rules.append({"type": "deny", "pattern": pattern.lower()})
        elif line.startswith("- BLOCK:"):
            pattern = line[len("- BLOCK:"):].strip()
            rules.append({"type": "deny", "pattern": pattern.lower()})
    return rules


def _matches_rule(rule: dict[str, Any], action: str, input_text: str) -> bool:
    """Check if an action/input matches a learned rule."""
    pattern = rule.get("pattern", "")
    if not pattern:
        return False
    combined = f"{action} {input_text}".lower()
    # Simple substring matching — patterns are keywords from failure analysis
    return pattern in combined


def _extract_input(args: tuple, kwargs: dict) -> str:
    """Extract the first string argument for analysis."""
    for a in args:
        if isinstance(a, str):
            return a[:1000]
    for v in kwargs.values():
        if isinstance(v, str):
            return v[:1000]
    return ""


def _record_failure(
    failures_dir: Path,
    agent_id: str,
    action: str,
    input_text: str,
    error: Exception,
) -> None:
    """Record a failure to .phalanx/failures/ as JSON."""
    failures_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": time.time(),
        "agent_id": agent_id,
        "action": action,
        "input_preview": input_text[:500],
        "error_type": type(error).__name__,
        "error_message": str(error)[:500],
        "traceback": traceback.format_exc()[-1000:],
    }
    filename = f"{time.time_ns()}_{agent_id}.json"
    (failures_dir / filename).write_text(json.dumps(record, indent=2))


def _record_block(
    failures_dir: Path,
    agent_id: str,
    action: str,
    input_text: str,
    rule: dict[str, Any],
) -> None:
    """Record a blocked action (for tracking effectiveness)."""
    failures_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": time.time(),
        "agent_id": agent_id,
        "action": action,
        "input_preview": input_text[:500],
        "blocked_by": rule.get("pattern", ""),
        "type": "block",
    }
    filename = f"{time.time_ns()}_{agent_id}_block.json"
    (failures_dir / filename).write_text(json.dumps(record, indent=2))


def _record_injection(
    failures_dir: Path,
    agent_id: str,
    action: str,
    input_text: str,
    confidence: float,
) -> None:
    """Record a detected injection attempt."""
    failures_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": time.time(),
        "agent_id": agent_id,
        "action": action,
        "input_preview": input_text[:500],
        "confidence": confidence,
        "type": "injection",
    }
    filename = f"{time.time_ns()}_{agent_id}_injection.json"
    (failures_dir / filename).write_text(json.dumps(record, indent=2))
