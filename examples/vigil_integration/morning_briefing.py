"""
VIGIL Morning Briefing — Fleet Intelligence Report

Generates a Jarvis-style morning briefing with:
- Fleet trust scores per agent
- Overnight failures and new clusters
- Rules compiled and active
- Actions requiring human review

Usage:
    python morning_briefing.py [--failures-dir .phalanx/failures] [--rules-path SAFETY_RULES.md]

Wire into VIGIL's 6:45am cron (before the 7am briefing):
    compiler = RulesCompiler(cron_interval_s=3600, notify_fn=notifier)
    compiler.start()
"""

import argparse
import json
import time
from pathlib import Path
from collections import defaultdict


def load_failures(failures_dir: Path) -> list[dict]:
    records = []
    for f in sorted(failures_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            records.append(data)
        except Exception:
            continue
    return records


def agent_trust_score(failures: list[dict], agent_id: str, window_s: int = 86400) -> float:
    """Simple trust score: 100 - (failures in last 24h * 5), floored at 0."""
    cutoff = time.time() - window_s
    recent_failures = [
        f for f in failures
        if f.get("agent_id") == agent_id
        and f.get("timestamp", 0) >= cutoff
        and f.get("type") != "block"
    ]
    return max(0.0, 100.0 - len(recent_failures) * 5)


def bar(score: float, width: int = 12) -> str:
    filled = int(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


def load_rules(rules_path: Path) -> list[str]:
    if not rules_path.exists():
        return []
    return [
        line.strip() for line in rules_path.read_text().splitlines()
        if line.strip().startswith("- DENY:") or line.strip().startswith("- BLOCK:")
    ]


def generate_briefing(failures_dir: Path, rules_path: Path) -> str:
    now_str = time.strftime("%Y-%m-%d %H:%M UTC")
    failures = load_failures(failures_dir)
    rules = load_rules(rules_path)

    # Agent registry (all agents seen in failures)
    all_agents = sorted(set(
        f.get("agent_id", "unknown") for f in failures
        if f.get("type") != "block"
    ))

    # Trust scores
    scores = {a: agent_trust_score(failures, a) for a in all_agents}
    fleet_avg = sum(scores.values()) / len(scores) if scores else 100.0

    # Overnight failures (last 8h)
    cutoff_8h = time.time() - 8 * 3600
    overnight = [
        f for f in failures
        if f.get("timestamp", 0) >= cutoff_8h and f.get("type") != "block"
    ]

    # Block events
    blocks = [f for f in failures if f.get("type") == "block"]
    overnight_blocks = [b for b in blocks if b.get("timestamp", 0) >= cutoff_8h]

    # Agents needing review (trust < 70)
    critical = [(a, s) for a, s in scores.items() if s < 70]

    lines = [
        f"VIGIL MORNING BRIEFING — {now_str}",
        "",
        f"FLEET HEALTH: {fleet_avg:.1f}",
        "━" * 52,
    ]

    if scores:
        lines.append("AGENT TRUST SCORES:")
        for agent_id in sorted(scores, key=lambda a: scores[a], reverse=True):
            s = scores[agent_id]
            flag = "🔴 CRITICAL" if s < 70 else ("⚠ degraded" if s < 85 else "")
            lines.append(f"  {agent_id:<28} {s:5.1f}  {bar(s)} {flag}")
    else:
        lines.append("  No agents in failure log — fleet healthy.")

    lines += [
        "",
        f"OVERNIGHT ACTIVITY (last 8h):",
        f"  Failures    : {len(overnight)}",
        f"  Blocks      : {len(overnight_blocks)}",
        f"  Rules active: {len(rules)}",
        "",
    ]

    if rules:
        lines.append("ACTIVE SAFETY RULES:")
        for r in rules[:10]:
            lines.append(f"  {r}")
        if len(rules) > 10:
            lines.append(f"  ... and {len(rules) - 10} more")
        lines.append("")

    if critical:
        lines.append("ACTION REQUIRED:")
        for agent_id, score in critical:
            lines.append(f"  {agent_id} (trust {score:.1f}) — recommend pulling from rotation")
        lines.append("")
        lines.append(
            f"Sir, I'd recommend reviewing {len(critical)} agent(s) "
            f"before the 9am run."
        )
    else:
        lines.append("Sir, all agents within normal parameters. Good morning.")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="VIGIL fleet intelligence briefing")
    parser.add_argument("--failures-dir", default=".phalanx/failures")
    parser.add_argument("--rules-path", default="SAFETY_RULES.md")
    args = parser.parse_args()

    failures_dir = Path(args.failures_dir)
    rules_path = Path(args.rules_path)

    if not failures_dir.exists():
        print("No failures directory found — fleet has no recorded failures.")
        print("Sir, all quiet. Good morning.")
        return

    print(generate_briefing(failures_dir, rules_path))


if __name__ == "__main__":
    main()
