"""Phalanx — The Agent Hypervisor.

The interlocking shield wall for autonomous AI.
Learned policy enforcement, zero-trust identity, execution sandboxing,
and fleet intelligence.
"""

__version__ = "0.1.0"

from phalanx.governance.types import (
    ActionVerdict,
    AgentIdentity,
    ExecutionContext,
    ExecutionRing,
    PolicyResult,
    TrustTier,
)
from phalanx.governance.policy import BasePolicy, StaticPolicy
from phalanx.governance.kernel import StatelessKernel
from phalanx.governance.trust import TrustBridge, TrustDecayConfig
from phalanx.governance.hypervisor import AgentHypervisor
from phalanx.governance.sre import AgentSRE, ErrorBudgetConfig, SLOStatus
from phalanx.governance.intent import IntentClassifier, IntentCategory
from phalanx.evolution.darwin import DarwinFailureCapture, FailureCluster, LearnedRule
from phalanx.evolution.propagator import CanaryPropagator, PropagationStatus
from phalanx.watch import watch, call as watch_call, WatchError
from phalanx.compile import compile_rules

__all__ = [
    "ActionVerdict",
    "AgentIdentity",
    "AgentHypervisor",
    "AgentSRE",
    "BasePolicy",
    "ErrorBudgetConfig",
    "ExecutionContext",
    "ExecutionRing",
    "IntentCategory",
    "IntentClassifier",
    "PolicyResult",
    "SLOStatus",
    "StatelessKernel",
    "StaticPolicy",
    "TrustBridge",
    "TrustDecayConfig",
    "TrustTier",
    "DarwinFailureCapture",
    "FailureCluster",
    "LearnedRule",
    "CanaryPropagator",
    "PropagationStatus",
]
