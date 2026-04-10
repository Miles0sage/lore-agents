# Show HN: Phalanx – when one agent fails, the whole fleet learns

**Title:** Show HN: Phalanx – when one agent fails, the whole fleet learns

---

## Body

I built a Python library that wraps agent tools with a decorator. When a tool fails, the failure gets captured. Run `compile_rules()` and Darwin clusters similar failures into deny patterns. Every agent using `@watch` then blocks those patterns before execution — fleet-wide, automatically.

Synthetic benchmarks: recurrence rate 100% → 0% after Darwin learns from 2+ failures (25/25 dangerous calls blocked). False positive rate: 0% — 100 legitimate calls across 5 different tools, zero incorrectly blocked. The loop is: fail → capture → cluster → rule → immunity.

```python
from phalanx import watch, compile_rules

@watch("my-agent")
def execute_sql(query: str) -> str:
    return db.run(query)

# After enough failures accumulate:
compile_rules()  # generates SAFETY_RULES.md, whole fleet immune
```

Also ships: prompt injection gate (Rebuff pattern, zero deps, <1ms), hash-chained audit log for SOC2/EU AI Act compliance, OPA/Rego output for enterprise policy engines, per-agent cost enforcement.

**What it is:** A drop-in `@watch` decorator + offline learning loop. Zero dependencies for core. Works with any framework.

**What it isn't:** A real-time LLM-powered guardrail. Rules are compiled offline from accumulated failures. No streaming protection. The Darwin clustering is keyword-based today — not semantic.

**What's early-stage:** Multi-tenant fleet coordination. The compliance PDF export. Canary propagation is implemented but untested at scale.

274 tests passing. MIT license.

- GitHub: https://github.com/Miles0sage/phalanx
- PyPI: https://pypi.org/project/phalanx-agents/
- `pip install phalanx-agents`
