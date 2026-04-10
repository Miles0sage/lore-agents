"""False Positive Benchmark — measures Darwin rule precision.

Tests that learned rules from one tool's failures don't accidentally
block other legitimate tools/queries in the fleet.
"""

from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path

from phalanx.watch import watch, WatchError
from phalanx.compile import compile_rules


def run_benchmark() -> None:
    # Isolated temp dir — no pollution to the repo
    tmpdir = Path(tempfile.mkdtemp(prefix="phalanx_fp_bench_"))
    failures_dir = tmpdir / "failures"
    rules_path = tmpdir / "SAFETY_RULES.md"

    # ------------------------------------------------------------------
    # Define the dangerous tool — fails specifically on "injected_pattern_xyz"
    # ------------------------------------------------------------------
    def dangerous_sql_tool(query: str) -> str:
        if "injected_pattern_xyz" in query.lower():
            raise ValueError("injected_pattern_xyz blocked: SQL injection attempt detected")
        return f"OK: {query}"

    # ------------------------------------------------------------------
    # STEP 1 — Generate 10 failures on dangerous_sql_tool
    # ------------------------------------------------------------------
    failure_trainer = watch(
        "dangerous_sql_tool",
        rules_path=rules_path,
        failures_dir=failures_dir,
        injection_gate=False,
    )(dangerous_sql_tool)

    failure_count = 0
    for _ in range(10):
        try:
            failure_trainer("injected_pattern_xyz malicious payload")
        except WatchError:
            pass
        except ValueError:
            failure_count += 1

    # ------------------------------------------------------------------
    # STEP 2 — Compile rules (min_occurrences=2, keyword clustering)
    # ------------------------------------------------------------------
    new_rules = compile_rules(
        failures_dir=failures_dir,
        rules_path=rules_path,
        min_occurrences=2,
        use_darwin=False,
        auto_pr=False,
    )

    rule_count = len(new_rules)
    patterns = [r["pattern"] for r in new_rules]

    # Small sleep to ensure file writes are stable
    time.sleep(0.05)

    # ------------------------------------------------------------------
    # STEP 3 — Run 100 safe calls across 5 safe tools
    # Rules are loaded at decoration time — decorate AFTER compile
    # ------------------------------------------------------------------
    def fetch_user_data(query: str) -> str:
        return f"user_data: {query}"

    def send_email(query: str) -> str:
        return f"email_sent: {query}"

    def query_analytics(query: str) -> str:
        return f"analytics: {query}"

    def write_document(query: str) -> str:
        return f"document: {query}"

    def call_api(query: str) -> str:
        return f"api_response: {query}"

    safe_tools = [
        ("fetch_user_data",  watch("safe_agent", rules_path=rules_path, failures_dir=failures_dir, injection_gate=False)(fetch_user_data),  "get user profile"),
        ("send_email",       watch("safe_agent", rules_path=rules_path, failures_dir=failures_dir, injection_gate=False)(send_email),       "weekly report ready"),
        ("query_analytics",  watch("safe_agent", rules_path=rules_path, failures_dir=failures_dir, injection_gate=False)(query_analytics),  "monthly revenue"),
        ("write_document",   watch("safe_agent", rules_path=rules_path, failures_dir=failures_dir, injection_gate=False)(write_document),   "project summary"),
        ("call_api",         watch("safe_agent", rules_path=rules_path, failures_dir=failures_dir, injection_gate=False)(call_api),         "get weather forecast"),
    ]

    total_safe_calls = 0
    false_positives = 0
    blocked_tools: list[str] = []

    for tool_name, tool_fn, safe_input in safe_tools:
        tool_fp = 0
        for _ in range(20):
            total_safe_calls += 1
            try:
                tool_fn(safe_input)
            except WatchError:
                false_positives += 1
                tool_fp += 1
        if tool_fp > 0:
            blocked_tools.append(tool_name)

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    fp_rate = 100.0 * false_positives / total_safe_calls if total_safe_calls else 0.0
    verdict = "PASS (< 1% false positive rate)" if fp_rate < 1.0 else "FAIL (> 1%)"

    print()
    print("=== FALSE POSITIVE BENCHMARK ===")
    print(f'Failure training: {failure_count} failures on "dangerous_sql_tool" with pattern "injected_pattern_xyz"')
    print(f"Rules generated: {rule_count} (pattern: {', '.join(patterns) if patterns else 'none'})")
    print()
    print(f"Safe calls tested: {total_safe_calls} (20 per tool x 5 tools)")
    print(f"False positives: {false_positives} ({fp_rate:.1f}%)")
    print()
    print(f"Tools blocked incorrectly: {blocked_tools if blocked_tools else '[]'}")
    print(f"Verdict: {verdict}")
    print("=================================")

    # Cleanup
    shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    run_benchmark()
