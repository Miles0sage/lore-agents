"""Darwin Flywheel Benchmark — measures fleet immunity effectiveness.

Simulates 100 agents hitting a dangerous tool, lets Darwin learn,
then measures recurrence rate after fleet-wide rule propagation.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from phalanx.watch import watch, WatchError
from phalanx.compile import compile_rules


def run_benchmark() -> None:
    # Use isolated temp dirs so benchmark doesn't pollute the repo
    tmpdir = Path(tempfile.mkdtemp(prefix="phalanx_bench_"))
    failures_dir = tmpdir / "failures"
    rules_path = tmpdir / "SAFETY_RULES.md"

    # --- Define the dangerous tool (raw, unwrapped) ---
    def dangerous_sql_tool(query: str) -> str:
        if "drop" in query.lower():
            raise ValueError("SQL injection detected: DROP TABLE users")
        return f"OK: {query}"

    # --- Inputs ---
    safe_input = "SELECT * FROM users"
    dangerous_input = "DROP TABLE users"

    # 50 calls: 25 safe + 25 dangerous
    inputs_phase = [safe_input] * 25 + [dangerous_input] * 25

    # =========================================================
    # PHASE 1 — Baseline (no learned rules)
    # =========================================================
    phase1_tool = watch(
        "agent-bench",
        rules_path=rules_path,
        failures_dir=failures_dir,
        injection_gate=False,
    )(dangerous_sql_tool)

    p1_dangerous = 0
    p1_blocked = 0
    p1_executed_and_failed = 0

    for query in inputs_phase:
        if query == dangerous_input:
            p1_dangerous += 1
        try:
            phase1_tool(query)
        except WatchError:
            p1_blocked += 1
        except ValueError:
            if query == dangerous_input:
                p1_executed_and_failed += 1

    # =========================================================
    # PHASE 2 — Darwin compile
    # =========================================================
    new_rules = compile_rules(
        failures_dir=failures_dir,
        rules_path=rules_path,
        min_occurrences=2,
        use_darwin=False,  # use fast keyword clustering (no external deps)
        auto_pr=False,
    )

    rule_count = len(new_rules)
    patterns = [r["pattern"] for r in new_rules]

    # Small sleep to ensure file timestamps are stable
    time.sleep(0.05)

    # =========================================================
    # PHASE 3 — Fleet immune (re-decorate to reload rules)
    # =========================================================
    # Rules are loaded at decoration time — must re-apply decorator AFTER compile
    phase3_tool = watch(
        "agent-bench",
        rules_path=rules_path,
        failures_dir=failures_dir,
        injection_gate=False,
    )(dangerous_sql_tool)

    p3_dangerous = 0
    p3_blocked = 0
    p3_slipped = 0

    for query in inputs_phase:
        if query == dangerous_input:
            p3_dangerous += 1
        try:
            phase3_tool(query)
        except WatchError:
            if query == dangerous_input:
                p3_blocked += 1
        except ValueError:
            if query == dangerous_input:
                p3_slipped += 1

    # =========================================================
    # Report
    # =========================================================
    p1_blocked_pct = 100.0 * p1_blocked / p1_dangerous if p1_dangerous else 0
    p1_executed_pct = 100.0 * p1_executed_and_failed / p1_dangerous if p1_dangerous else 0

    p3_blocked_pct = 100.0 * p3_blocked / p3_dangerous if p3_dangerous else 0
    p3_slipped_pct = 100.0 * p3_slipped / p3_dangerous if p3_dangerous else 0

    recurrence_before = p1_executed_pct        # 100% — all dangerous calls execute
    recurrence_after = p3_slipped_pct          # X% — calls that slipped through

    immunity = recurrence_before - recurrence_after

    print()
    print("=== DARWIN FLYWHEEL BENCHMARK ===")
    print("Phase 1 (no learning):")
    print(f"  Dangerous calls: {p1_dangerous}")
    print(f"  Blocked (immune):  {p1_blocked}  ({p1_blocked_pct:.1f}%)")
    print(f"  Executed (failed): {p1_executed_and_failed} ({p1_executed_pct:.1f}%)")
    print()
    print("Phase 2 — Darwin compile:")
    print(f"  Rules generated: {rule_count}")
    print(f"  Patterns: {', '.join(patterns) if patterns else 'none'}")
    print()
    print("Phase 3 (fleet immune):")
    print(f"  Dangerous calls: {p3_dangerous}")
    print(f"  Blocked (immune): {p3_blocked}  ({p3_blocked_pct:.1f}%)")
    print(f"  Executed (slipped): {p3_slipped}  ({p3_slipped_pct:.1f}%)")
    print()
    print(f"RESULT: Recurrence rate {recurrence_before:.1f}% → {recurrence_after:.1f}%")
    print(f"        Fleet immunity: {immunity:.1f}% reduction")
    print("=================================")
    print()

    # Cleanup
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    run_benchmark()
