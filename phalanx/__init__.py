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

__all__ = [
    "ActionVerdict",
    "AgentIdentity",
    "AgentHypervisor",
    "BasePolicy",
    "ExecutionContext",
    "ExecutionRing",
    "PolicyResult",
    "StatelessKernel",
    "StaticPolicy",
    "TrustBridge",
    "TrustDecayConfig",
    "TrustTier",
]
