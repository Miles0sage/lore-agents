# Phalanx

**The immune system for autonomous AI agents.**

Microsoft tells agents what they can't do. Phalanx watches what they actually do, learns from failures, and evolves its policies automatically.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-163%20passing-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/coverage-94%25-brightgreen.svg)]()

---

## Why Phalanx?

Every AI governance framework today is a **seatbelt** — static rules written by humans, enforced at runtime. When Agent A discovers a novel failure mode, Agent B has no idea.

Phalanx is an **immune system**. When one agent in your fleet fails, Phalanx:
1. Captures the failure and hashes the root cause
2. Clusters similar failures to detect patterns
3. Generates a learned policy (no YAML, no human rules)
4. Validates through a 5-layer gatekeeper
5. Canary-deploys the policy across your entire fleet

**Agent B is now immune. Automatically.**

## Quick Start

```python
from phalanx import AgentHypervisor, StaticPolicy

# Create a hypervisor with policies
hv = AgentHypervisor(
    policies=[
        StaticPolicy.deny(["delete:production:*"]),
        StaticPolicy.rate_limit(100, "1m"),
        StaticPolicy.require_approval(["deploy:*"]),
    ],
    initial_trust=500,  # 0-1000 scale
)

# Register an agent
hv.register_agent("analyst-1", "data-analyst", "alice@company.com",
                   capabilities=frozenset({"read:data", "write:reports"}))

# Every action goes through the 7-step governance pipeline
result = hv.execute("analyst-1", "read:data:users", {"limit": 100})

if result.allowed:
    print(f"Allowed (Ring {result.ring.value}, Trust {result.agent.trust_score})")
else:
    print(f"Denied: {result.reason}")
    # Intent: {result.intent.category.value}
    # SLO: {result.slo_status.value}
```

## The 7-Step Pipeline

Every action passes through the full governance pipeline in **<500 microseconds**:

```
1. Agent Resolution    → Verify identity, apply trust decay
2. Intent Classification → OWASP Agentic Top 10 detection
3. SRE Pre-check       → Error budget exhausted? Auto-restrict.
4. Context Building     → Stateless execution context
5. Policy Evaluation    → <0.1ms, short-circuit on deny
6. SRE Tracking        → Update compliance metrics
7. Trust Update        → Reward success, penalize violations
```

## What Makes Phalanx Different

| Feature | Microsoft AGT | Asqav | Phalanx |
|---------|:---:|:---:|:---:|
| Trust scoring (0-1000) | Yes | No | **Yes** |
| Execution rings | Yes | No | **Yes** |
| OWASP Top 10 | Yes | Yes | **Yes** |
| Sub-ms policy eval | Yes | No | **Yes** |
| Quantum-safe audit | No | Yes | Planned |
| **Callable policies** | No | No | **Yes** |
| **Failure learning (Darwin)** | No | No | **Yes** |
| **Fleet propagation** | No | No | **Yes** |
| **Auto-generated rules** | No | No | **Yes** |

**Microsoft AGT** enforces rules humans write in YAML.
**Phalanx** learns rules from failures and deploys them automatically.

## Darwin Engine — The Moat

```python
from phalanx import DarwinFailureCapture, CanaryPropagator

darwin = DarwinFailureCapture(min_cluster_size=3)

# Failures are captured automatically by the hypervisor
# After enough data, analyze for patterns:
clusters = darwin.analyze()

for cluster in clusters:
    if cluster.is_novel:  # Seen across multiple agents
        rules = darwin.generate_rules(cluster)
        # Rules are auto-deployed via canary propagation
```

Darwin captures failures, clusters root causes using density-based analysis, and generates learned policies. The CanaryPropagator rolls them out gradually through execution rings (Ring 3 → 2 → 1), monitoring SRE error budgets at each stage. Ring 0 (kernel) always requires human approval.

## Architecture

```
phalanx/
├── governance/           # Runtime governance layer
│   ├── types.py          # ExecutionRing, TrustTier, AgentIdentity, PolicyResult
│   ├── policy.py         # BasePolicy (callable!), StaticPolicy factory
│   ├── kernel.py         # StatelessKernel — <0.1ms evaluation
│   ├── trust.py          # TrustBridge — 0-1000 scoring with decay
│   ├── hypervisor.py     # AgentHypervisor — unified 7-step pipeline
│   ├── sre.py            # AgentSRE — error budgets, fleet health
│   └── intent.py         # IntentClassifier — OWASP Top 10 detection
└── evolution/            # The moat — failure learning
    ├── darwin.py          # DarwinFailureCapture — clustering + rule generation
    └── propagator.py      # CanaryPropagator — graduated fleet rollout
```

## Key Concepts

### Trust Scoring (0-1000)
Agents start untrusted and earn trust through successful actions. Trust decays over time without positive signals.

| Score | Tier | Ring | Access |
|-------|------|------|--------|
| 900+ | Kernel | Ring 0 | Full system access |
| 700-899 | Supervisor | Ring 1 | Cross-agent coordination |
| 400-699 | User | Ring 2 | Standard tool access |
| 100-399 | Untrusted | Ring 3 | Read-only, sandboxed |
| 0-99 | Quarantine | Ring 3 | Fully isolated |

### Callable Policies
Unlike YAML-based systems, Phalanx policies are Python callables:

```python
from phalanx import CallablePolicy, PolicyResult, ActionVerdict

def my_custom_policy(ctx):
    if ctx.agent.trust_score < 300 and "write" in ctx.action:
        return PolicyResult(verdict=ActionVerdict.DENY,
                          policy_name="low_trust_write_guard",
                          reason="Low-trust agents cannot write")
    return PolicyResult(verdict=ActionVerdict.ALLOW,
                       policy_name="low_trust_write_guard")

policy = CallablePolicy("custom_guard", my_custom_policy)
```

This is the bridge to Darwin — learned policies are just callables injected at runtime.

### SRE Error Budgets
When an agent's policy violation rate exceeds the SLO target, its capabilities are automatically restricted:

```python
from phalanx import AgentSRE, ErrorBudgetConfig

sre = AgentSRE(config=ErrorBudgetConfig(
    slo_target=0.99,        # 99% compliance required
    auto_restrict=True,      # Auto-restrict on budget exhaustion
    recovery_actions=10,     # 10 consecutive good actions to recover
))
```

## Performance

- **Policy evaluation**: <100 microseconds (4 static policies)
- **Full pipeline**: <500 microseconds (intent + SRE + policies + trust)
- **Zero dependencies**: Pure Python, no ML libraries required
- **163 tests**, 94% coverage

## Complementary to Microsoft AGT

Phalanx is designed to work alongside Microsoft's Agent Governance Toolkit, not replace it. Use AGT for static compliance (YAML/OPA/Cedar policies, EU AI Act mapping). Use Phalanx for adaptive governance (failure learning, fleet intelligence, dynamic trust).

## License

MIT

## Contributing

Contributions welcome. The Darwin engine is where the real innovation happens — if you're interested in failure analysis, clustering algorithms, or fleet intelligence, that's where to focus.
