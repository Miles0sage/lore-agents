#!/usr/bin/env bash
# compile_and_report.sh — One command: fail → compile → show diff → briefing
#
# Usage:
#   ./compile_and_report.sh                          # use defaults
#   ./compile_and_report.sh .phalanx/failures SAFETY_RULES.md
#
# This is the script to run at 6:45am before VIGIL's morning briefing.
# Wire it as a cron or RulesCompiler(cron_interval_s=3600) in Python.

set -euo pipefail

FAILURES_DIR="${1:-.phalanx/failures}"
RULES_PATH="${2:-SAFETY_RULES.md}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHALANX_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PHALANX COMPILE PIPELINE"
echo "  $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Count failures
FAILURE_COUNT=0
if [ -d "$FAILURES_DIR" ]; then
    FAILURE_COUNT=$(find "$FAILURES_DIR" -name "*.json" ! -name "*_block*" | wc -l | tr -d ' ')
fi
BLOCK_COUNT=0
if [ -d "$FAILURES_DIR" ]; then
    BLOCK_COUNT=$(find "$FAILURES_DIR" -name "*_block.json" | wc -l | tr -d ' ')
fi

echo "  Failures on disk : $FAILURE_COUNT"
echo "  Blocks recorded  : $BLOCK_COUNT"
echo ""

# Snapshot existing rules before compile
RULES_BEFORE=""
if [ -f "$RULES_PATH" ]; then
    RULES_BEFORE=$(grep -E "^- (DENY|BLOCK):" "$RULES_PATH" 2>/dev/null || true)
    RULES_BEFORE_COUNT=$(echo "$RULES_BEFORE" | grep -c "DENY\|BLOCK" 2>/dev/null || echo 0)
    echo "  Rules before     : $RULES_BEFORE_COUNT"
else
    RULES_BEFORE_COUNT=0
    echo "  Rules before     : 0 (no SAFETY_RULES.md yet)"
fi

echo ""
echo "  Running compile_rules()..."
echo ""

# Run the compiler
cd "$PHALANX_ROOT"
python3 -m phalanx.compile 2>&1 | sed 's/^/  /'

# Snapshot rules after
RULES_AFTER=""
RULES_AFTER_COUNT=0
if [ -f "$RULES_PATH" ]; then
    RULES_AFTER=$(grep -E "^- (DENY|BLOCK):" "$RULES_PATH" 2>/dev/null || true)
    RULES_AFTER_COUNT=$(echo "$RULES_AFTER" | grep -c "DENY\|BLOCK" 2>/dev/null || echo 0)
fi

NEW_COUNT=$((RULES_AFTER_COUNT - RULES_BEFORE_COUNT))

echo ""
echo "  Rules after      : $RULES_AFTER_COUNT"
echo "  New rules added  : $NEW_COUNT"
echo ""

if [ "$NEW_COUNT" -gt 0 ]; then
    echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  NEW RULES (diff):"
    echo ""
    # Show only new lines (not in before, in after)
    comm -13 \
        <(echo "$RULES_BEFORE" | sort) \
        <(echo "$RULES_AFTER" | sort) \
    | sed 's/^/  + /'
    echo ""
    echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  Sir, I've learned $NEW_COUNT new safety pattern(s) this cycle."
    echo "  SAFETY_RULES.md updated. Fleet will be immune on next load."
    echo ""
else
    echo "  No new patterns found. Fleet knowledge is current."
    echo ""
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  FLEET INTELLIGENCE BRIEFING"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Morning briefing
python3 "$SCRIPT_DIR/morning_briefing.py" \
    --failures-dir "$FAILURES_DIR" \
    --rules-path "$RULES_PATH" \
    2>&1 | sed 's/^/  /'

echo ""
