"""phalanx compile — Turn accumulated failures into learned safety rules.

Reads .phalanx/failures/*.json, clusters by error pattern,
generates SAFETY_RULES.md that the @watch decorator enforces.

Usage:
    from phalanx.compile import compile_rules
    compile_rules()  # Reads failures, writes SAFETY_RULES.md

Or from CLI:
    python -m phalanx.compile

Knowledge compounds. Every failure makes your agents smarter.
"""

from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    from phalanx.evolution.darwin import DarwinFailureCapture
    from phalanx.governance.types import (
        AgentIdentity,
        ExecutionContext,
        IntentCategory,
    )
    _DARWIN_AVAILABLE = True
except Exception:  # pragma: no cover
    _DARWIN_AVAILABLE = False


_DEFAULT_FAILURES_DIR = Path(".phalanx/failures")
_DEFAULT_RULES_PATH = Path("SAFETY_RULES.md")
_MIN_OCCURRENCES = 2  # Minimum failures before generating a rule


def compile_rules(
    failures_dir: Path | str | None = None,
    rules_path: Path | str | None = None,
    min_occurrences: int = _MIN_OCCURRENCES,
    use_darwin: bool = True,
    auto_pr: bool = False,
    output: str = "markdown",
    rego_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Compile failure logs into learned safety rules.

    Reads all failure JSON files, clusters by error pattern,
    and generates SAFETY_RULES.md with deny rules.

    Args:
        failures_dir: Directory containing failure JSON files.
        rules_path: Path to write SAFETY_RULES.md.
        min_occurrences: Minimum failures before generating a rule.
        use_darwin: When True (default), use DarwinFailureCapture for
            root-cause-hash clustering instead of keyword matching.
            Falls back to keyword clustering if darwin import failed.
        auto_pr: When True and new rules exist, open a GitHub PR via phalanx.pr.
        output: Output format — "markdown" (default) writes SAFETY_RULES.md;
            "rego" additionally writes an OPA/Rego policy file.
        rego_path: Destination for the Rego file when output="rego".
            Defaults to rules_path with a .rego extension.

    Returns the list of generated rules.
    """
    fdir = Path(failures_dir) if failures_dir else _DEFAULT_FAILURES_DIR
    rpath = Path(rules_path) if rules_path else _DEFAULT_RULES_PATH

    if not fdir.exists():
        return []

    # Load all failure records
    failures = _load_failures(fdir)
    if not failures:
        return []

    # Cluster by error signature
    if use_darwin and _DARWIN_AVAILABLE:
        clusters = _cluster_failures_darwin(failures)
    else:
        clusters = _cluster_failures(failures)

    # Generate rules from clusters meeting threshold
    rules = _generate_rules(clusters, min_occurrences)

    # Load existing rules to avoid duplicates
    existing = set()
    if rpath.exists():
        for line in rpath.read_text().splitlines():
            line = line.strip()
            if line.startswith("- DENY:") or line.startswith("- BLOCK:"):
                existing.add(line)

    # Write rules
    new_rules = []
    for rule in rules:
        rule_line = f"- DENY: {rule['pattern']}"
        if rule_line not in existing:
            new_rules.append(rule)

    if new_rules:
        _write_rules(rpath, new_rules, existing)

    if output == "rego":
        from phalanx.rego import export_rego  # lazy import
        _rego_path = Path(rego_path) if rego_path else rpath.with_suffix(".rego")
        export_rego(rules, _rego_path)

    if auto_pr and new_rules:
        from phalanx.pr import open_rule_pr  # lazy import to avoid circular deps
        open_rule_pr(new_rules, rules_path=rpath)

    return new_rules


def _load_failures(failures_dir: Path) -> list[dict[str, Any]]:
    """Load all failure JSON files."""
    failures = []
    for f in sorted(failures_dir.glob("*.json")):
        if "_block" in f.name:
            continue  # Skip block records
        try:
            data = json.loads(f.read_text())
            if data.get("type") != "block":
                failures.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return failures


def _cluster_failures_darwin(
    failures: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Cluster failures using DarwinFailureCapture (root cause hashing).

    Creates an ExecutionContext from each failure JSON record, feeds them
    into DarwinFailureCapture.capture(), then calls analyze() to get
    FailureCluster objects grouped by root_cause_hash.

    Returns the same ``{sig: [failure_records]}`` dict that
    _generate_rules() expects, where sig = cluster.root_cause_hash.
    """
    darwin = DarwinFailureCapture(
        min_cluster_size=2,          # Match _MIN_OCCURRENCES default
        cluster_window_seconds=86400.0,  # 24 h — cover offline batch runs
    )

    # Build a map from root_cause_hash → original JSON records so we can
    # return the raw dicts (not FailureRecord objects) to _generate_rules().
    hash_to_failures: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for failure in failures:
        agent_id = failure.get("agent_id", "unknown")
        action = failure.get("action", failure.get("error_type", "unknown"))
        error_type = failure.get("error_type", "policy_deny")

        identity = AgentIdentity(
            agent_id=agent_id,
            name=agent_id,
            sponsor="compile",
            trust_score=0,
        )
        ctx = ExecutionContext(
            agent=identity,
            action=action,
            params={},
        )

        record = darwin.capture(
            ctx,
            result=None,
            error_type=error_type,
            intent=IntentCategory.SAFE,
        )
        hash_to_failures[record.root_cause_hash].append(failure)

    clusters = darwin.analyze()

    # Build result keyed by an _error_signature-compatible string so that
    # _extract_pattern() (called by _generate_rules) can derive the same
    # keyword-based DENY pattern it would produce from keyword clustering.
    # Using "{error_type}:{keyword}" keeps full compatibility with dedup logic.
    result: dict[str, list[dict[str, Any]]] = {}
    for cluster in clusters:
        rch = cluster.root_cause_hash
        if rch not in hash_to_failures:
            continue
        cluster_failures = hash_to_failures[rch]
        # Derive a stable sig from the representative (first) failure record
        rep = cluster_failures[0]
        sig = _error_signature(
            rep.get("error_type", "Unknown"),
            rep.get("error_message", ""),
        )
        result[sig] = cluster_failures

    return result


def _cluster_failures(
    failures: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Cluster failures by error signature.

    Signature = error_type + first meaningful word from error message.
    Simple but effective for v1 — upgrade to DBSCAN/Gemma 4 later.
    """
    clusters: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in failures:
        error_type = f.get("error_type", "Unknown")
        error_msg = f.get("error_message", "")
        # Extract key terms from error
        sig = _error_signature(error_type, error_msg)
        clusters[sig].append(f)
    return dict(clusters)


def _error_signature(error_type: str, error_message: str) -> str:
    """Generate a simple error signature for clustering."""
    # Normalize
    msg = error_message.lower().strip()
    # Extract meaningful terms
    dangerous_terms = [
        "drop", "delete", "truncate", "inject", "unauthorized",
        "permission", "denied", "forbidden", "timeout", "overflow",
        "exploit", "bypass", "escalat", "exfiltrat", "sudo",
        "rm -rf", "format", "shutdown", "kill", "admin",
    ]
    matched = [t for t in dangerous_terms if t in msg]
    if matched:
        return f"{error_type}:{matched[0]}"
    # Fallback to error type + first 3 words
    words = msg.split()[:3]
    return f"{error_type}:{'-'.join(words)}" if words else error_type


def _generate_rules(
    clusters: dict[str, list[dict[str, Any]]],
    min_occurrences: int,
) -> list[dict[str, Any]]:
    """Generate deny rules from failure clusters."""
    rules = []
    for sig, failures in clusters.items():
        if len(failures) < min_occurrences:
            continue

        # Extract common patterns from inputs
        inputs = [f.get("input_preview", "") for f in failures]
        pattern = _extract_pattern(sig, inputs)

        if pattern:
            rules.append({
                "pattern": pattern,
                "source_signature": sig,
                "failure_count": len(failures),
                "first_seen": min(f.get("timestamp", 0) for f in failures),
                "last_seen": max(f.get("timestamp", 0) for f in failures),
                "agents": list(set(f.get("agent_id", "") for f in failures)),
            })
    return rules


def _extract_pattern(sig: str, inputs: list[str]) -> str:
    """Extract a deny pattern from failure signature and inputs."""
    # Use the dangerous term from the signature
    parts = sig.split(":")
    if len(parts) >= 2:
        return parts[1].strip()
    return parts[0].strip().lower()


def _write_rules(
    rules_path: Path,
    new_rules: list[dict[str, Any]],
    existing_lines: set[str],
) -> None:
    """Write or append rules to SAFETY_RULES.md."""
    lines: list[str] = []

    if rules_path.exists():
        lines = rules_path.read_text().splitlines()
    else:
        lines = [
            "# Safety Rules",
            "",
            "Auto-generated by Phalanx Darwin from agent failure analysis.",
            "These rules are enforced by the @watch decorator.",
            "Edit or remove rules as needed — you own this file.",
            "",
            "## Learned Rules",
            "",
        ]

    # Append new rules
    lines.append("")
    lines.append(f"## Compiled {time.strftime('%Y-%m-%d %H:%M')}")
    lines.append("")
    for rule in new_rules:
        lines.append(f"- DENY: {rule['pattern']}")
        lines.append(
            f"  <!-- {rule['failure_count']} failures from "
            f"{', '.join(rule['agents'])} -->"
        )

    rules_path.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    rules = compile_rules()
    if rules:
        print(f"Generated {len(rules)} new safety rules → SAFETY_RULES.md")
        for r in rules:
            print(f"  DENY: {r['pattern']} ({r['failure_count']} failures)")
    else:
        print("No new patterns found. Keep running your agents.")
