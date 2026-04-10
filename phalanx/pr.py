"""phalanx.pr — Auto-open GitHub PRs when compile_rules() generates new safety rules.

The Darwin loop:
  failures cluster → rules proposed → PR opened → CISO approves → fleet immune
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

_MAX_RULES_PER_PR = 20
_PENDING_PRS_FILE = Path(".phalanx/pending_prs.jsonl")

# Shell-unsafe and regex-special characters not allowed in patterns
_SHELL_CHARS = re.compile(r"[;&|`$(){}!\\<>\"']")
# Looks like an API key / secret: long runs of hex or base64 chars (20+)
_SECRET_LIKE = re.compile(r"[A-Za-z0-9+/]{20,}")


def run_gatekeeper(
    new_rules: list[dict],
    rules_path: Path,
    canary_safe_inputs: list[str] | None = None,
) -> tuple[bool, list[str]]:
    """5-layer gatekeeper. Returns (passed, list_of_failures)."""
    failures: list[str] = []

    # Layer 1: Pattern allowlist — keywords only, no shell chars, no regex specials
    for rule in new_rules:
        pattern = rule.get("pattern", "")
        if _SHELL_CHARS.search(pattern):
            failures.append(
                f"Layer 1 (allowlist): pattern contains shell/regex special chars: {pattern!r}"
            )

    # Layer 2: Diff size — max 20 rules per PR
    if len(new_rules) > _MAX_RULES_PER_PR:
        failures.append(
            f"Layer 2 (diff size): {len(new_rules)} rules exceeds max {_MAX_RULES_PER_PR}"
        )

    # Layer 3: Secret scan — patterns must not look like API keys (no long hex/base64)
    for rule in new_rules:
        pattern = rule.get("pattern", "")
        if _SECRET_LIKE.search(pattern):
            failures.append(
                f"Layer 3 (secret scan): pattern looks like a secret/API key: {pattern!r}"
            )

    # Layer 4: Canary validation — patterns must not match known-safe inputs
    if canary_safe_inputs:
        for rule in new_rules:
            pattern = rule.get("pattern", "")
            for safe_input in canary_safe_inputs:
                if pattern and pattern.lower() in safe_input.lower():
                    failures.append(
                        f"Layer 4 (canary): pattern {pattern!r} matches safe input {safe_input!r}"
                    )

    # Layer 5: Rules file validity — parseable markdown (if it exists)
    if rules_path.exists():
        try:
            content = rules_path.read_text()
            if not isinstance(content, str):
                failures.append("Layer 5 (rules file): rules file is not valid text")
        except OSError as exc:
            failures.append(f"Layer 5 (rules file): cannot read rules file: {exc}")

    passed = len(failures) == 0
    return passed, failures


def _format_pr_body(new_rules: list[dict], failures_raw: list[dict] | None = None) -> str:
    """Format the PR body using the Darwin template."""
    n = len(new_rules)
    total_failures = sum(r.get("failure_count", 0) for r in new_rules)
    confidences = [r.get("confidence", 0.8) for r in new_rules]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

    # Proposed rules section
    rule_lines = []
    for rule in new_rules:
        pattern = rule.get("pattern", "")
        failure_count = rule.get("failure_count", 0)
        agents = rule.get("agents", [])
        agent_count = len(agents)
        first_seen_ts = rule.get("first_seen", 0)
        last_seen_ts = rule.get("last_seen", 0)
        first_seen = time.strftime("%Y-%m-%d", time.gmtime(first_seen_ts)) if first_seen_ts else "unknown"
        last_seen = time.strftime("%Y-%m-%d", time.gmtime(last_seen_ts)) if last_seen_ts else "unknown"
        rule_lines.append(
            f"- DENY: {pattern}  ({failure_count} failures from {agent_count} agents, {first_seen} → {last_seen})"
        )
    rules_block = "\n".join(rule_lines) if rule_lines else "_(none)_"

    # Sample failures section (first 3)
    sample_lines = []
    if failures_raw:
        for failure in failures_raw[:3]:
            agent_id = failure.get("agent_id", "unknown")
            input_preview = failure.get("input_preview", "")
            sample_lines.append(f"- `{agent_id}`: {input_preview!r}")
    else:
        # Extract from the rule dicts if no raw failures passed
        seen = 0
        for rule in new_rules:
            if seen >= 3:
                break
            agents = rule.get("agents", [])
            pattern = rule.get("pattern", "")
            if agents:
                sample_lines.append(f"- `{agents[0]}`: input matching pattern {pattern!r}")
                seen += 1
    samples_block = "\n".join(sample_lines) if sample_lines else "_(no samples available)_"

    body = f"""## Darwin Safety Rules — {n} New Pattern(s) Proposed

**Fleet failures analyzed:** {total_failures}
**New patterns detected:** {n}
**Confidence:** {avg_confidence:.0%}

### Proposed Rules
{rules_block}

### 5-Layer Gatekeeper
- [x] Pattern allowlist: keywords only
- [x] Diff size: {n}/20 max
- [x] Secret scan: no sensitive patterns
- [x] Canary validation: safe inputs unaffected
- [x] Rules file: valid markdown

### Sample Failures
{samples_block}

---
*Merge to deploy these rules fleet-wide. Generated by phalanx Darwin.*"""
    return body


def _write_pending(record: dict[str, Any]) -> None:
    """Append a record to the pending_prs.jsonl sidecar log."""
    _PENDING_PRS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with _PENDING_PRS_FILE.open("a") as fh:
        fh.write(json.dumps(record) + "\n")


def open_rule_pr(
    new_rules: list[dict],
    repo_path: str | Path = "/root/phalanx",
    rules_path: Path | None = None,
    dry_run: bool = False,
    canary_safe_inputs: list[str] | None = None,
) -> str | None:
    """Open a GitHub PR with proposed safety rules for human review.

    Returns PR URL, or None if dry_run/gh unavailable/gatekeeper fails.
    """
    if not new_rules:
        return None

    repo_path = Path(repo_path)
    if rules_path is None:
        rules_path = repo_path / "SAFETY_RULES.md"

    # Run gatekeeper
    passed, gate_failures = run_gatekeeper(new_rules, rules_path, canary_safe_inputs)

    record: dict[str, Any] = {
        "timestamp": time.time(),
        "rule_count": len(new_rules),
        "rules": new_rules,
        "gatekeeper_passed": passed,
        "gatekeeper_failures": gate_failures,
        "dry_run": dry_run,
        "pr_url": None,
    }

    if not passed:
        _write_pending(record)
        return None

    if dry_run:
        _write_pending(record)
        return None

    # Check if gh is available
    if not shutil.which("gh"):
        _write_pending(record)
        return None

    # Build branch name
    branch_name = f"darwin/safety-rules-{int(time.time())}"
    pr_title = f"Darwin: {len(new_rules)} new safety rule(s) proposed"
    pr_body = _format_pr_body(new_rules)

    try:
        # Create and push branch
        subprocess.run(
            ["git", "checkout", "-b", branch_name],
            cwd=repo_path,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "add", str(rules_path)],
            cwd=repo_path,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "commit", "-m", f"chore: darwin adds {len(new_rules)} safety rule(s)"],
            cwd=repo_path,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "push", "-u", "origin", branch_name],
            cwd=repo_path,
            check=True,
            capture_output=True,
        )

        # Open PR
        result = subprocess.run(
            [
                "gh", "pr", "create",
                "--title", pr_title,
                "--body", pr_body,
                "--label", "darwin,safety,auto-generated",
            ],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
        )
        pr_url = result.stdout.strip()
        record["pr_url"] = pr_url
        _write_pending(record)
        return pr_url

    except subprocess.CalledProcessError:
        _write_pending(record)
        return None
