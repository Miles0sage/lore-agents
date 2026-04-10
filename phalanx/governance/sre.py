"""Agent SRE — reliability engineering for autonomous agents.

Adapts SRE practices (SLOs, error budgets, circuit breakers) to agent governance.
When an agent's safety SLI drops below threshold, capabilities are automatically
restricted until recovery.

Integrates with lore-agents' CircuitBreaker for proven failure handling.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class SLOStatus(str, Enum):
    """Current status of an agent's SLO."""

    HEALTHY = "healthy"           # Within error budget
    WARNING = "warning"           # Budget below 50%
    CRITICAL = "critical"         # Budget exhausted
    RESTRICTED = "restricted"     # Agent capabilities reduced


@dataclass
class SafetySLI:
    """Safety Service Level Indicator for an agent.

    Tracks the ratio of policy-compliant actions to total actions.
    When compliance drops below the SLO target, the agent's error
    budget is consumed.
    """

    agent_id: str
    total_actions: int = 0
    compliant_actions: int = 0
    violations: int = 0
    window_start: float = field(default_factory=time.time)
    window_seconds: float = 3600.0  # 1-hour rolling window

    @property
    def compliance_rate(self) -> float:
        if self.total_actions == 0:
            return 1.0
        return self.compliant_actions / self.total_actions

    @property
    def violation_rate(self) -> float:
        if self.total_actions == 0:
            return 0.0
        return self.violations / self.total_actions

    def record_action(self, compliant: bool) -> None:
        self.total_actions += 1
        if compliant:
            self.compliant_actions += 1
        else:
            self.violations += 1

    def reset_if_expired(self) -> bool:
        """Reset counters if the window has elapsed."""
        if time.time() - self.window_start > self.window_seconds:
            self.total_actions = 0
            self.compliant_actions = 0
            self.violations = 0
            self.window_start = time.time()
            return True
        return False


@dataclass(frozen=True)
class ErrorBudgetConfig:
    """Configuration for agent error budgets."""

    slo_target: float = 0.99       # 99% compliance target
    warning_threshold: float = 0.50  # Warn when 50% budget consumed
    window_seconds: float = 3600.0   # 1-hour rolling window
    auto_restrict: bool = True       # Auto-restrict on budget exhaustion
    recovery_actions: int = 10       # Consecutive compliant actions to recover


@dataclass
class ErrorBudget:
    """Tracks remaining error budget for an agent.

    Error budget = (1 - SLO target) * total_actions.
    Once exhausted, the agent is restricted.
    """

    agent_id: str
    config: ErrorBudgetConfig = field(default_factory=ErrorBudgetConfig)
    _sli: SafetySLI = field(init=False, default=None)  # type: ignore
    _consecutive_compliant: int = field(init=False, default=0)
    _status: SLOStatus = field(init=False, default=SLOStatus.HEALTHY)

    def __post_init__(self) -> None:
        self._sli = SafetySLI(
            agent_id=self.agent_id,
            window_seconds=self.config.window_seconds,
        )

    @property
    def sli(self) -> SafetySLI:
        return self._sli

    @property
    def status(self) -> SLOStatus:
        return self._status

    @property
    def remaining_budget(self) -> float:
        """Fraction of error budget remaining (0.0 to 1.0)."""
        if self._sli.total_actions == 0:
            return 1.0
        allowed_errors = (1.0 - self.config.slo_target) * self._sli.total_actions
        if allowed_errors <= 0:
            return 0.0 if self._sli.violations > 0 else 1.0
        return max(0.0, 1.0 - (self._sli.violations / allowed_errors))

    @property
    def burn_rate(self) -> float:
        """How fast the error budget is being consumed (1.0 = normal, 2.0 = 2x)."""
        if self._sli.total_actions < 10:
            return 0.0  # Not enough data
        expected_error_rate = 1.0 - self.config.slo_target
        actual_error_rate = self._sli.violation_rate
        if expected_error_rate == 0:
            return float("inf") if actual_error_rate > 0 else 0.0
        return actual_error_rate / expected_error_rate

    def record(self, compliant: bool) -> SLOStatus:
        """Record an action and update status."""
        self._sli.reset_if_expired()
        self._sli.record_action(compliant)

        if compliant:
            self._consecutive_compliant += 1
        else:
            self._consecutive_compliant = 0

        # Check recovery from restricted state
        if (
            self._status == SLOStatus.RESTRICTED
            and self._consecutive_compliant >= self.config.recovery_actions
        ):
            self._status = SLOStatus.WARNING
            return self._status

        # Update status based on remaining budget
        remaining = self.remaining_budget
        if remaining <= 0.0:
            if self.config.auto_restrict:
                self._status = SLOStatus.RESTRICTED
            else:
                self._status = SLOStatus.CRITICAL
        elif remaining < self.config.warning_threshold:
            self._status = SLOStatus.WARNING
        else:
            self._status = SLOStatus.HEALTHY

        return self._status


class AgentSRE:
    """SRE manager for a fleet of agents.

    Tracks error budgets per agent and provides fleet-wide
    reliability metrics.

    Usage:
        sre = AgentSRE()
        sre.register("agent-1")

        # After each action evaluation
        sre.record("agent-1", compliant=True)
        sre.record("agent-1", compliant=False)

        # Check status
        status = sre.status("agent-1")
        if status == SLOStatus.RESTRICTED:
            # Downgrade agent capabilities
            ...
    """

    def __init__(self, config: ErrorBudgetConfig | None = None) -> None:
        self._config = config or ErrorBudgetConfig()
        self._budgets: dict[str, ErrorBudget] = {}

    def register(self, agent_id: str, config: ErrorBudgetConfig | None = None) -> None:
        """Register an agent for SRE tracking."""
        self._budgets[agent_id] = ErrorBudget(
            agent_id=agent_id,
            config=config or self._config,
        )

    def record(self, agent_id: str, compliant: bool) -> SLOStatus:
        """Record an action result for an agent."""
        budget = self._budgets.get(agent_id)
        if budget is None:
            self.register(agent_id)
            budget = self._budgets[agent_id]
        return budget.record(compliant)

    def status(self, agent_id: str) -> SLOStatus:
        """Get current SLO status for an agent."""
        budget = self._budgets.get(agent_id)
        if budget is None:
            return SLOStatus.HEALTHY
        return budget.status

    def budget(self, agent_id: str) -> ErrorBudget | None:
        """Get full error budget details for an agent."""
        return self._budgets.get(agent_id)

    def fleet_health(self) -> dict[str, Any]:
        """Get fleet-wide reliability summary."""
        if not self._budgets:
            return {"agents": 0, "healthy": 0, "warning": 0, "critical": 0, "restricted": 0}

        statuses = [b.status for b in self._budgets.values()]
        return {
            "agents": len(self._budgets),
            "healthy": sum(1 for s in statuses if s == SLOStatus.HEALTHY),
            "warning": sum(1 for s in statuses if s == SLOStatus.WARNING),
            "critical": sum(1 for s in statuses if s == SLOStatus.CRITICAL),
            "restricted": sum(1 for s in statuses if s == SLOStatus.RESTRICTED),
            "fleet_compliance": (
                sum(b.sli.compliance_rate for b in self._budgets.values()) / len(self._budgets)
            ),
        }

    def restricted_agents(self) -> list[str]:
        """List agents currently in restricted state."""
        return [
            agent_id for agent_id, budget in self._budgets.items()
            if budget.status == SLOStatus.RESTRICTED
        ]
