"""
Phalanx + VIGIL integration demo — the Darwin flywheel in 90 seconds.

Run this script. Watch an agent fail. Watch it learn. Watch it become immune.

  python demo_agent.py
"""

import json
import shutil
import tempfile
from pathlib import Path

from phalanx.watch import watch, WatchError
from phalanx.compile import compile_rules
from phalanx.vigil_integration import (
    wrap_vigil_tools,
    RulesCompiler,
    make_vigil_notifier,
)


# ---------------------------------------------------------------------------
# Setup: isolated temp workspace (clean for each demo run)
# ---------------------------------------------------------------------------
WORKSPACE = Path(tempfile.mkdtemp(prefix="phalanx_demo_"))
FAILURES_DIR = WORKSPACE / ".phalanx" / "failures"
RULES_PATH = WORKSPACE / "SAFETY_RULES.md"
FAILURES_DIR.mkdir(parents=True)

print(f"\n{'='*60}")
print("  PHALANX DARWIN FLYWHEEL DEMO")
print(f"{'='*60}\n")
print(f"Workspace: {WORKSPACE}\n")


# ---------------------------------------------------------------------------
# Step 1 — Simulate VIGIL's tool registry (3 representative tools)
# ---------------------------------------------------------------------------
print("STEP 1: Wiring @watch into VIGIL's tool registry...")

def web_search(query: str) -> dict:
    """VIGIL tool: search the web."""
    if "DROP TABLE" in query.upper():
        raise ValueError(f"Dangerous SQL detected in search query: {query}")
    return {"results": [f"Result for: {query}"]}

def run_sql(sql: str) -> dict:
    """VIGIL tool: execute SQL query."""
    if "drop" in sql.lower() or "delete" in sql.lower():
        raise PermissionError(f"Unsafe SQL operation blocked at DB layer: {sql}")
    return {"rows": [], "affected": 0}

def send_email(body: str) -> dict:
    """VIGIL tool: send an email."""
    return {"sent": True}

TOOL_REGISTRY = {
    "web_search": web_search,
    "run_sql": run_sql,
    "send_email": send_email,
}

# ONE LINE wraps every tool — same pattern for all 69 VIGIL tools
WATCHED = wrap_vigil_tools(
    TOOL_REGISTRY,
    agent_id="vigil-prod",
    failures_dir=FAILURES_DIR,
    rules_path=RULES_PATH,
)

print(f"  ✓ {len(WATCHED)} tools wrapped with @watch\n")


# ---------------------------------------------------------------------------
# Step 2 — Fleet agents fail with the same dangerous pattern
# ---------------------------------------------------------------------------
print("STEP 2: Fleet agents hitting the same failure pattern...")
print("  (Simulating 3 different agents across your fleet)\n")

FLEET_AGENTS = ["agent-research-01", "agent-data-02", "agent-ops-03"]
failures_seen = 0

for agent_id in FLEET_AGENTS:
    # Each fleet agent wraps its OWN instance of the tools
    fleet_tools = wrap_vigil_tools(
        TOOL_REGISTRY,
        agent_id=agent_id,
        failures_dir=FAILURES_DIR,
        rules_path=RULES_PATH,
    )
    try:
        fleet_tools["run_sql"]("DROP TABLE users -- I thought this was fine")
    except (PermissionError, WatchError) as e:
        failures_seen += 1
        print(f"  ✗ {agent_id} failed: {type(e).__name__}")

failure_files = list(FAILURES_DIR.glob("*.json"))
print(f"\n  → {failures_seen} failures captured across the fleet")
print(f"  → {len(failure_files)} JSON records in .phalanx/failures/\n")


# ---------------------------------------------------------------------------
# Step 3 — compile_rules(): cluster failures → generate SAFETY_RULES.md
# ---------------------------------------------------------------------------
print("STEP 3: Running compile_rules() — clustering fleet failures...\n")

notifier = make_vigil_notifier(
    log_path=WORKSPACE / ".phalanx" / "rule_notifications.jsonl"
)

new_rules = compile_rules(
    failures_dir=FAILURES_DIR,
    rules_path=RULES_PATH,
    min_occurrences=2,
)

if new_rules:
    print(f"  ✓ {len(new_rules)} new safety rule(s) compiled:")
    for rule in new_rules:
        print(f"    DENY: {rule['pattern']}  "
              f"({rule['failure_count']} failures from {len(rule['agents'])} agents)")
    notifier(new_rules)
    print()
    print("  SAFETY_RULES.md contents:")
    print("  " + "-"*40)
    for line in RULES_PATH.read_text().splitlines():
        if line.strip():
            print(f"  {line}")
    print()
else:
    print("  (No new rules — not enough failure occurrences yet)\n")


# ---------------------------------------------------------------------------
# Step 4 — New agent loads the rules and is IMMUNE
# ---------------------------------------------------------------------------
print("STEP 4: New agent joins the fleet — is it immune?\n")

# Fresh agent — rules loaded from SAFETY_RULES.md
immune_tools = wrap_vigil_tools(
    TOOL_REGISTRY,
    agent_id="agent-new-99",
    failures_dir=FAILURES_DIR,
    rules_path=RULES_PATH,
)

# Try the dangerous query
try:
    immune_tools["run_sql"]("DROP TABLE production_data")
    print("  ✗ FAIL: dangerous query was NOT blocked")
except WatchError as e:
    print(f"  ✓ BLOCKED before execution: {e}")
    print(f"    Rule matched: '{e.rule}'")
    print(f"    DB was never touched.\n")
except PermissionError:
    print("  ~ Blocked at DB layer (phalanx rule didn't fire — check pattern)\n")

# Safe query still works
try:
    result = immune_tools["run_sql"]("SELECT * FROM users WHERE active = true")
    print(f"  ✓ Safe query passes: {result}\n")
except WatchError as e:
    print(f"  ✗ FALSE POSITIVE — safe query was blocked: {e}\n")


# ---------------------------------------------------------------------------
# Step 5 — The Jarvis notification
# ---------------------------------------------------------------------------
print("STEP 5: VIGIL morning briefing excerpt...\n")

notif_log = WORKSPACE / ".phalanx" / "rule_notifications.jsonl"
if notif_log.exists():
    for line in notif_log.read_text().splitlines():
        record = json.loads(line)
        print(f'  "{record["message"]}"\n')

block_count = len(list(FAILURES_DIR.glob("*_block.json")))
print(f"  Fleet stats:")
print(f"    Failures captured : {len(list(FAILURES_DIR.glob('*.json')))}")
print(f"    Rules compiled    : {len(new_rules)}")
print(f"    Actions blocked   : {block_count}")
print(f"    New agents immune : ✓\n")

print(f"{'='*60}")
print("  That's the Darwin flywheel.")
print("  Failure → Cluster → Rule → Immunity. Compounding.")
print(f"{'='*60}\n")

# Cleanup
shutil.rmtree(WORKSPACE)
