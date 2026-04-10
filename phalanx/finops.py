"""phalanx.finops — Pre-dispatch cost budget enforcement for AI agents.

Stops runaway token costs BEFORE they happen, not after.
Works standalone or as a @watch companion.
"""
from __future__ import annotations
import sqlite3, threading, time, json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

@dataclass
class BudgetPolicy:
    """Cost budget for an agent or fleet."""
    agent_id: str
    daily_limit_usd: float        # Hard limit per day
    per_task_limit_usd: float     # Max cost per single task
    alert_threshold: float = 0.8  # Alert at 80% of daily limit
    hard_stop: bool = True        # If True, raise on limit exceeded

@dataclass
class CostEvent:
    """A recorded cost event."""
    event_id: str
    agent_id: str
    task_id: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    timestamp: float

class BudgetExceededError(Exception):
    """Raised when an agent exceeds its budget."""
    def __init__(self, agent_id: str, current_usd: float, limit_usd: float):
        self.agent_id = agent_id
        self.current_usd = current_usd
        self.limit_usd = limit_usd
        super().__init__(f"Agent {agent_id} exceeded budget: ${current_usd:.4f} / ${limit_usd:.4f}")

# Token cost estimates per model (USD per 1K tokens)
MODEL_COSTS = {
    "gpt-4o": {"input": 0.0025, "output": 0.010},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "claude-opus-4": {"input": 0.015, "output": 0.075},
    "claude-sonnet-4": {"input": 0.003, "output": 0.015},
    "claude-haiku-4": {"input": 0.00025, "output": 0.00125},
    "qwen": {"input": 0.0001, "output": 0.0002},      # Alibaba ~$0.001/task
    "glm": {"input": 0.0001, "output": 0.0002},
    "gemini-flash": {"input": 0.000075, "output": 0.0003},
    "gemini-pro": {"input": 0.00125, "output": 0.005},
}

class CostGate:
    """Pre-dispatch cost enforcement gateway.

    Usage:
        gate = CostGate()
        gate.set_policy(BudgetPolicy("my-agent", daily_limit_usd=5.0, per_task_limit_usd=0.50))

        # Before dispatching a model call:
        gate.check("my-agent", estimated_cost=0.10)  # raises BudgetExceededError if over limit

        # After call completes:
        gate.record("my-agent", "task-123", "gpt-4o-mini", input_tokens=500, output_tokens=200)
    """

    def __init__(self, db_path: Path = Path(".phalanx/finops.db")):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = str(db_path)
        self._lock = threading.Lock()
        self._policies: dict[str, BudgetPolicy] = {}
        self._alert_callbacks: list[Callable] = []
        self._init_schema()

    def _init_schema(self):
        with sqlite3.connect(self._db) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS cost_events (
                event_id TEXT PRIMARY KEY,
                agent_id TEXT,
                task_id TEXT,
                model TEXT,
                input_tokens INTEGER,
                output_tokens INTEGER,
                cost_usd REAL,
                timestamp REAL
            )""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_ts ON cost_events(agent_id, timestamp)")

    def set_policy(self, policy: BudgetPolicy):
        """Register a budget policy for an agent."""
        with self._lock:
            self._policies[policy.agent_id] = policy

    def on_alert(self, callback: Callable[[str, float, float], None]):
        """Register callback for budget alerts: callback(agent_id, current_usd, limit_usd)."""
        self._alert_callbacks.append(callback)

    def check(self, agent_id: str, estimated_cost: float = 0.0):
        """Check if agent can proceed. Raises BudgetExceededError if over limit."""
        policy = self._policies.get(agent_id)
        if not policy:
            return  # No policy = no limit

        if estimated_cost > policy.per_task_limit_usd:
            if policy.hard_stop:
                raise BudgetExceededError(agent_id, estimated_cost, policy.per_task_limit_usd)

        daily_spend = self.daily_spend(agent_id)
        if daily_spend + estimated_cost > policy.daily_limit_usd:
            if policy.hard_stop:
                raise BudgetExceededError(agent_id, daily_spend + estimated_cost, policy.daily_limit_usd)

        # Alert threshold
        if daily_spend >= policy.daily_limit_usd * policy.alert_threshold:
            for cb in self._alert_callbacks:
                try:
                    cb(agent_id, daily_spend, policy.daily_limit_usd)
                except Exception:
                    pass

    def record(self, agent_id: str, task_id: str, model: str,
               input_tokens: int = 0, output_tokens: int = 0,
               cost_usd: Optional[float] = None) -> CostEvent:
        """Record a completed model call."""
        import uuid
        if cost_usd is None:
            cost_usd = self.estimate_cost(model, input_tokens, output_tokens)
        event = CostEvent(
            event_id=str(uuid.uuid4()),
            agent_id=agent_id,
            task_id=task_id,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
            timestamp=time.time(),
        )
        with self._lock:
            with sqlite3.connect(self._db) as conn:
                conn.execute(
                    "INSERT INTO cost_events VALUES (?,?,?,?,?,?,?,?)",
                    (event.event_id, event.agent_id, event.task_id, event.model,
                     event.input_tokens, event.output_tokens, event.cost_usd, event.timestamp)
                )
        return event

    def daily_spend(self, agent_id: str, day_start: Optional[float] = None) -> float:
        """Get total spend for agent today."""
        if day_start is None:
            import datetime
            today = datetime.date.today()
            day_start = time.mktime(today.timetuple())
        with sqlite3.connect(self._db) as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(cost_usd), 0) FROM cost_events WHERE agent_id=? AND timestamp>=?",
                (agent_id, day_start)
            ).fetchone()
        return row[0] if row else 0.0

    def fleet_summary(self) -> dict:
        """Summary of all agent costs today."""
        import datetime
        today = datetime.date.today()
        day_start = time.mktime(today.timetuple())
        with sqlite3.connect(self._db) as conn:
            rows = conn.execute(
                "SELECT agent_id, SUM(cost_usd), COUNT(*) FROM cost_events WHERE timestamp>=? GROUP BY agent_id",
                (day_start,)
            ).fetchall()
        return {
            "date": str(today),
            "agents": [{"agent_id": r[0], "daily_spend_usd": r[1], "task_count": r[2]} for r in rows],
            "total_usd": sum(r[1] for r in rows),
        }

    @staticmethod
    def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost for a model call."""
        costs = MODEL_COSTS.get(model, MODEL_COSTS["gpt-4o-mini"])
        return (input_tokens / 1000 * costs["input"]) + (output_tokens / 1000 * costs["output"])

    def cost_guard(self, agent_id: str, model: str = "gpt-4o-mini"):
        """Decorator: checks budget before function runs, records cost after.

        Usage:
            gate = CostGate()

            @gate.cost_guard("my-agent", model="claude-haiku-4")
            def call_llm(prompt: str) -> str:
                return llm.complete(prompt)
        """
        def decorator(fn):
            import functools
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                self.check(agent_id, estimated_cost=0.05)  # pre-check with conservative estimate
                result = fn(*args, **kwargs)
                self.record(agent_id, fn.__name__, model, cost_usd=0.05)
                return result
            return wrapper
        return decorator
