# VIGIL ↔ Phalanx Integration — Parked for Later

**Status:** Architecture designed, code ready. Not yet wired into VIGIL production.
**Pick up here** when phalanx has a stable HTTP API and VIGIL needs fleet intelligence.

---

## What's built and ready

All integration code lives in `phalanx/vigil_integration.py` (305 lines, zero new deps):

| Component | What it does | Status |
|---|---|---|
| `wrap_vigil_tools(TOOL_REGISTRY)` | Auto-wraps all 69 VIGIL tools with @watch in one call | ✅ Built, tested |
| `WatchedBreaker` | lore CircuitBreaker trips → phalanx failure records | ✅ Built |
| `RulesCompiler` | Background thread: threshold/cron compile, canary ring | ✅ Built |
| `make_vigil_notifier(telegram_fn)` | "Sir, I've learned N new patterns this cycle" | ✅ Built |

---

## The integration picture

```
User intent
    │
    ▼
VIGIL/Segundo (pa.overseerclaw.uk)
    │  GPT-5.4, 69 tools, Jarvis personality
    │  SOUL hot-reload (personality + SAFETY_RULES.md)
    │
    ▼  routes intent to archetypes
LORE-AGENTS runtime
    │  Commander → Router → Scout/Archivist/Council/Breaker
    │  circuit breakers, memory stacks, reviewer loops
    │
    ▼  wraps every call
PHALANX @watch
    │  captures failures → .phalanx/failures/*.json
    │  enforces SAFETY_RULES.md before execution
    │
    ▼  background thread
RulesCompiler
    │  threshold: 5 failures → compile
    │  cron: every hour + 6:45am before morning briefing
    │  canary: validates rules don't block safe inputs
    │
    ▼  on new rules
VIGIL Telegram alert
    "Sir, I've learned 3 new safety patterns: drop, truncate, sudo"
```

---

## How to wire it (when ready)

### Step 1 — Auto-wrap VIGIL's Python tool dispatcher

In `/root/openclaw/vigil/tools/dispatcher.py` (or wherever TOOL_REGISTRY lives):

```python
from phalanx.vigil_integration import wrap_vigil_tools, RulesCompiler, make_vigil_notifier
from openclaw.alerts import send_telegram  # existing Telegram sender

# At module load time — one line covers all 69 tools
WATCHED_TOOLS = wrap_vigil_tools(
    TOOL_REGISTRY,
    agent_id="vigil-prod",
    failures_dir=Path("/root/.phalanx/failures"),
    rules_path=Path("/root/SAFETY_RULES.md"),
)

# Background compile loop
notifier = make_vigil_notifier(telegram_fn=send_telegram)
compiler = RulesCompiler(
    failures_dir=Path("/root/.phalanx/failures"),
    rules_path=Path("/root/SAFETY_RULES.md"),
    failure_threshold=5,
    cron_interval_s=3600,
    canary_safe_inputs=["SELECT * FROM users", "search for"],
    notify_fn=notifier,
)
compiler.start()

# Replace all tool dispatch calls with:
def dispatch(tool_name: str, params: dict):
    return WATCHED_TOOLS[tool_name](**params)
```

### Step 2 — Intent → lore archetype routing

In VIGIL's intent classifier (currently classifies to tool calls):

```python
INTENT_TO_ARCHETYPE = {
    "research":      "scout",      # parallel web search
    "decision":      "council",    # multi-agent consensus
    "memory_recall": "archivist",  # RAG + recall
    "risky_action":  "breaker",    # circuit breaker guard
    "review":        "sentinel",   # output validation
    "orchestrate":   "commander",  # top-level task routing
}
```

### Step 3 — SOUL hot-reload extends to SAFETY_RULES.md

VIGIL already hot-reloads `SOUL.md` without restart. Same mechanism:

```python
# In the SOUL watcher (wherever file watch is implemented)
WATCHED_FILES = [
    Path("/root/SOUL.md"),
    Path("/root/SAFETY_RULES.md"),  # ADD THIS
]
```

When `SAFETY_RULES.md` changes (after compile), VIGIL reloads rules without restart.
All subsequent tool calls enforce the new rules immediately.

### Step 4 — Morning briefing enhancement

Add to VIGIL's 7am briefing skill:

```python
# Before generating morning text, pull fleet stats
from phalanx.vigil_integration import generate_briefing_data
from pathlib import Path

fleet_data = generate_briefing_data(
    failures_dir=Path("/root/.phalanx/failures"),
    rules_path=Path("/root/SAFETY_RULES.md"),
)
# Inject into briefing prompt:
# "Fleet trust scores: {fleet_data['scores']}. New rules: {fleet_data['new_rules']}."
```

---

## Why NOT to wire this now (devil's advocate was right)

1. **VIGIL is production** — breaking it proves an architectural point but has zero upside
2. **Phalanx needs HTTP API first** — right now it's a Python library, not a service. VIGIL (Cloudflare Workers JS) needs a REST endpoint to call, not Python imports
3. **No real failure data yet** — the clustering is keyword matching until there's a real corpus
4. **The demo first** — prove the Darwin flywheel works with synthetic data, get the Show HN post, THEN wire into production

## What unblocks this

- [ ] `phalanx serve` — FastAPI wrapper around the governance kernel (1 day)
- [ ] VIGIL calls `POST /phalanx/check` before each tool execution (1 day)
- [ ] Real failure corpus from VIGIL production use (2-4 weeks of data)
- [ ] Gemma 4 LoRA on failure corpus replaces keyword matching (when corpus exists)

---

## The Jarvis moment (the demo to record)

When this is live, the 60-second demo is:

1. VIGIL executes a research task → agent hallucinates a URL 3 times
2. Phalanx captures all 3 failures silently
3. `compile_rules()` runs at 6:45am → generates `DENY: hallucinated-url-pattern`
4. VIGIL gets Telegram: *"Sir, I've learned 1 new safety pattern: hallucinated-url. SAFETY_RULES.md updated."*
5. New research agent tries same hallucination → `WatchError` before execution
6. VIGIL morning briefing shows: Fleet trust 87.2 → 94.1, 1 new rule, 0 recurrence

That's the enterprise pitch made visceral.
