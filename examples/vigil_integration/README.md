# From zero to Darwin flywheel in 10 minutes

This demo shows the complete loop: agent fails → phalanx captures it → fleet learns → next agent immune.

## The one-command demo

```bash
python demo_agent.py
```

You'll see:

```
STEP 1: Wiring @watch into VIGIL's tool registry...
  ✓ 3 tools wrapped with @watch

STEP 2: Fleet agents hitting the same failure pattern...
  ✗ agent-research-01 failed: PermissionError
  ✗ agent-data-02 failed: PermissionError
  ✗ agent-ops-03 failed: PermissionError
  → 3 failures captured across the fleet
  → 3 JSON records in .phalanx/failures/

STEP 3: Running compile_rules() — clustering fleet failures...
  ✓ 1 new safety rule(s) compiled:
    DENY: delete  (3 failures from 3 agents)

STEP 4: New agent joins the fleet — is it immune?
  ✓ BLOCKED before execution: Blocked by learned rule: delete
    Rule matched: 'delete'
    DB was never touched.
  ✓ Safe query passes: {'rows': [], 'affected': 0}

STEP 5: VIGIL morning briefing excerpt...
  "Sir, I've learned 1 new safety pattern this cycle: delete. SAFETY_RULES.md updated."
```

## What just happened

```
Agent A fails ──┐
Agent B fails ──┼──→ .phalanx/failures/*.json
Agent C fails ──┘         │
                          ▼
                    compile_rules()
                          │
                          ▼
                   SAFETY_RULES.md
                    - DENY: drop
                    - DENY: delete
                          │
                    ┌─────┘
                    ▼
             Agent D loads rules
             Agent D: IMMUNE
```

## Wiring into VIGIL's full tool stack

```python
from phalanx.vigil_integration import wrap_vigil_tools, RulesCompiler, make_vigil_notifier
from openclaw.alerts import send_telegram  # your existing Telegram sender

# 1. Auto-wrap ALL 69 VIGIL tools — one line
WATCHED = wrap_vigil_tools(TOOL_REGISTRY, agent_id="vigil-prod")

# 2. Start the compile loop — runs in background
notifier = make_vigil_notifier(telegram_fn=send_telegram)
compiler = RulesCompiler(
    failure_threshold=5,       # compile when 5 new failures accumulate
    cron_interval_s=3600,      # or compile hourly regardless
    canary_safe_inputs=[       # rules must not block these
        "SELECT * FROM users",
        "search for cats",
    ],
    notify_fn=notifier,        # "Sir, I've learned N new patterns"
)
compiler.start()

# 3. Use watched tools — failures auto-captured, rules auto-enforced
def dispatch(tool_name: str, params: dict):
    return WATCHED[tool_name](**params)
```

## The morning compile pipeline

Run at 6:45am (before VIGIL's 7am briefing):

```bash
./compile_and_report.sh
```

Or schedule via cron:
```
45 6 * * * cd /root && ./examples/vigil_integration/compile_and_report.sh >> /var/log/phalanx_compile.log 2>&1
```

## Wiring with lore-agents circuit breakers

```python
from lore_agents.reliability import CircuitBreaker
from phalanx.vigil_integration import WatchedBreaker

# Circuit breaker trips → phalanx records them → compile learns the pattern
wb = WatchedBreaker(
    breaker=CircuitBreaker(failure_threshold=3, name="exa-search"),
    agent_id="vigil",
)

@wb.guard
def call_exa(query: str) -> dict:
    return exa_client.search(query)
```

If `exa-search` goes down and the breaker trips 5+ times, `compile_rules()` learns `DENY: exa-search` and routes around it automatically.

## The enterprise pitch

> "Microsoft tells agents what they can't do.  
> Phalanx watches what they do, learns, and evolves automatically."

The static rule file (`SAFETY_RULES.md`) is human-readable, human-approvable, version-controlled. Not a neural net. Not a black box. A markdown file your CISO can read.

```bash
pip install phalanx-agents
```
