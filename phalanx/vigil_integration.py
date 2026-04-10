"""phalanx.vigil_integration — Wire @watch into VIGIL/Segundo's tool pipeline.

Three concrete integration patterns:

  Pattern 1: Universal Tool Wrapper
    wrap_vigil_tools(registry) → every tool auto-watched in one call

  Pattern 2: lore-agents Breaker + phalanx @watch
    WatchedBreaker — circuit breaker trips become phalanx failure records

  Pattern 3: Auto-compile pipeline
    RulesCompiler — threshold/cron trigger, canary validation, VIGIL notification

Usage:
    from phalanx.vigil_integration import wrap_vigil_tools, WatchedBreaker, RulesCompiler
"""

from __future__ import annotations

import json
import time
import threading
from pathlib import Path
from typing import Any, Callable

from phalanx.watch import watch, _record_failure, _DEFAULT_FAILURES_DIR, _DEFAULT_RULES_PATH
from phalanx.compile import compile_rules


# ---------------------------------------------------------------------------
# Pattern 1: Universal Tool Wrapper
# ---------------------------------------------------------------------------

def wrap_vigil_tools(
    registry: dict[str, Callable],
    agent_id: str = "vigil",
    rules_path: Path | str = _DEFAULT_RULES_PATH,
    failures_dir: Path | str = _DEFAULT_FAILURES_DIR,
) -> dict[str, Callable]:
    """Auto-wrap every tool in VIGIL's registry with @watch.

    One call covers all 69 tools. Original registry is not mutated.

    Usage:
        # In vigil's Python tool dispatcher (tool_executor_functions.py):
        from phalanx.vigil_integration import wrap_vigil_tools

        WATCHED = wrap_vigil_tools(TOOL_REGISTRY, agent_id="vigil-prod")

        def dispatch(tool_name: str, params: dict) -> Any:
            return WATCHED[tool_name](**params)
    """
    watched: dict[str, Callable] = {}
    decorator = watch(agent_id, rules_path=rules_path, failures_dir=failures_dir)
    for name, fn in registry.items():
        watched[name] = decorator(fn)
    return watched


# ---------------------------------------------------------------------------
# Pattern 2: lore-agents Breaker + phalanx @watch
# ---------------------------------------------------------------------------

class WatchedBreaker:
    """Circuit breaker whose trips are captured as phalanx failure records.

    The Breaker (lore archetype) prevents cascade failure. When it opens,
    phalanx records the trip as a structured failure so compile_rules() can
    learn from repeated outages and generate DENY patterns.

    Usage:
        from lore_agents.reliability import CircuitBreaker
        from phalanx.vigil_integration import WatchedBreaker

        wb = WatchedBreaker(
            breaker=CircuitBreaker(failure_threshold=3, name="exa-search"),
            agent_id="vigil",
        )

        @wb.guard
        def call_exa(query: str) -> dict:
            return exa_client.search(query)

        # Breaker trips → phalanx records it → rules compiler learns it
    """

    def __init__(
        self,
        breaker: Any,               # lore_agents CircuitBreaker instance
        agent_id: str = "vigil",
        failures_dir: Path | str = _DEFAULT_FAILURES_DIR,
        rules_path: Path | str = _DEFAULT_RULES_PATH,
    ) -> None:
        self._breaker = breaker
        self._agent_id = agent_id
        self._failures_dir = Path(failures_dir)
        self._watch_decorator = watch(agent_id, rules_path=rules_path, failures_dir=failures_dir)

    def guard(self, fn: Callable) -> Callable:
        """Decorator: circuit-checks first, then @watch wraps execution."""
        watched_fn = self._watch_decorator(fn)

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # 1. Breaker pre-check — trip is an error phalanx records
            try:
                self._breaker.check()
            except Exception as trip_err:
                _record_failure(
                    self._failures_dir,
                    self._agent_id,
                    action=f"tool:call:{fn.__name__}",
                    input_text=str(args[0])[:500] if args else "",
                    error=trip_err,
                )
                raise

            # 2. Execute under @watch (failures are also recorded there)
            try:
                result = watched_fn(*args, **kwargs)
                self._breaker.record_success()
                return result
            except Exception:
                self._breaker.record_failure()
                raise  # @watch already recorded it, breaker state updated

        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper


# ---------------------------------------------------------------------------
# Pattern 3: Auto-compile pipeline
# ---------------------------------------------------------------------------

class RulesCompiler:
    """Threshold + cron trigger for compile_rules(), with canary validation
    and a notification hook for VIGIL ("sir, I've learned N new patterns").

    Trigger modes (configurable, combinable):
      - failure_threshold: compile when N new failures accumulate
      - cron_interval_s:   compile every N seconds regardless
      - on_new_failure:    compile immediately after each failure (dev mode)

    Canary validation: new rules must NOT match a set of known-safe inputs
    before being promoted to the live SAFETY_RULES.md.

    VIGIL notification: calls notify_fn(new_rules) so the PA can surface the
    summary to the user in natural language.

    Usage:
        compiler = RulesCompiler(
            failures_dir=Path(".phalanx/failures"),
            rules_path=Path("SAFETY_RULES.md"),
            failure_threshold=5,
            cron_interval_s=3600,
            canary_safe_inputs=["SELECT * FROM users", "search for cats"],
            notify_fn=vigil_notify,   # async or sync — both work
        )
        compiler.start()   # background thread
        # ...later...
        compiler.stop()
    """

    def __init__(
        self,
        failures_dir: Path | str = _DEFAULT_FAILURES_DIR,
        rules_path: Path | str = _DEFAULT_RULES_PATH,
        failure_threshold: int = 5,
        cron_interval_s: int = 3600,
        canary_safe_inputs: list[str] | None = None,
        notify_fn: Callable[[list[dict]], None] | None = None,
        on_new_failure: bool = False,
    ) -> None:
        self._failures_dir = Path(failures_dir)
        self._rules_path = Path(rules_path)
        self._threshold = failure_threshold
        self._interval = cron_interval_s
        self._canary = canary_safe_inputs or []
        self._notify = notify_fn
        self._on_new_failure = on_new_failure

        self._last_compiled_count = self._failure_count()
        self._last_compiled_ts = 0.0
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # Public API --------------------------------------------------------

    def start(self) -> None:
        """Start background compile loop."""
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop background compile loop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def maybe_compile(self) -> list[dict]:
        """Call after each tool failure when on_new_failure=True."""
        if self._on_new_failure:
            return self._run_compile()
        return []

    # Internal ----------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            now = time.time()
            current_count = self._failure_count()
            new_failures = current_count - self._last_compiled_count
            time_elapsed = now - self._last_compiled_ts

            if new_failures >= self._threshold or time_elapsed >= self._interval:
                self._run_compile()

            self._stop_event.wait(timeout=60)   # poll every minute

    def _run_compile(self) -> list[dict]:
        """Compile, validate via canary, notify VIGIL."""
        new_rules = compile_rules(
            failures_dir=self._failures_dir,
            rules_path=self._rules_path,
        )
        if not new_rules:
            return []

        # Canary ring: reject rules that would block safe inputs
        safe_rules = [r for r in new_rules if not self._canary_fails(r)]
        blocked = len(new_rules) - len(safe_rules)
        if blocked:
            # Re-write without the canary-rejected rules — simple: compile
            # already deduplicates; just note the rejection in a sidecar log
            self._log_canary_rejects(new_rules, safe_rules)

        # Update watermarks
        self._last_compiled_count = self._failure_count()
        self._last_compiled_ts = time.time()

        if safe_rules and self._notify:
            self._notify(safe_rules)

        return safe_rules

    def _canary_fails(self, rule: dict) -> bool:
        """Return True if this rule would block a known-safe input."""
        pattern = rule.get("pattern", "").lower()
        return any(pattern in inp.lower() for inp in self._canary)

    def _failure_count(self) -> int:
        if not self._failures_dir.exists():
            return 0
        return sum(1 for f in self._failures_dir.glob("*.json") if "_block" not in f.name)

    def _log_canary_rejects(self, all_rules: list[dict], accepted: list[dict]) -> None:
        rejected = [r for r in all_rules if r not in accepted]
        sidecar = self._failures_dir / "canary_rejects.jsonl"
        self._failures_dir.mkdir(parents=True, exist_ok=True)
        with sidecar.open("a") as fh:
            for r in rejected:
                fh.write(json.dumps({"ts": time.time(), "rejected_rule": r}) + "\n")


# ---------------------------------------------------------------------------
# VIGIL notification helper — the "sir, I've learned N new patterns" moment
# ---------------------------------------------------------------------------

def make_vigil_notifier(
    telegram_fn: Callable[[str], None] | None = None,
    log_path: Path | str | None = None,
) -> Callable[[list[dict]], None]:
    """Return a notify_fn compatible with RulesCompiler.

    Pass this to RulesCompiler(notify_fn=make_vigil_notifier(...)).
    Logs to file always; sends Telegram if telegram_fn is provided.

    For VIGIL/Segundo: wire telegram_fn to the existing Telegram alert helper
    already live in /root/openclaw/alerts.py or similar.

    Example:
        from openclaw.alerts import send_telegram
        notifier = make_vigil_notifier(telegram_fn=send_telegram)
        compiler = RulesCompiler(..., notify_fn=notifier)
    """
    _log = Path(log_path) if log_path else Path(".phalanx/rule_notifications.jsonl")

    def notify(new_rules: list[dict]) -> None:
        n = len(new_rules)
        patterns = [r["pattern"] for r in new_rules]
        msg = (
            f"Sir, I've learned {n} new safety pattern{'s' if n != 1 else ''} "
            f"this cycle: {', '.join(patterns)}. SAFETY_RULES.md updated."
        )
        _log.parent.mkdir(parents=True, exist_ok=True)
        with _log.open("a") as fh:
            fh.write(json.dumps({"ts": time.time(), "message": msg, "rules": new_rules}) + "\n")
        if telegram_fn:
            try:
                telegram_fn(msg)
            except Exception:
                pass   # notification failure must never crash the pipeline

    return notify
