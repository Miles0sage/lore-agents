"""phalanx.rego — Export learned safety rules as OPA/Rego policy files."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def rules_to_rego(
    rules: list[dict[str, Any]],
    package_name: str = "phalanx.safety",
) -> str:
    """Convert a list of deny-rule dicts into a Rego policy string."""
    lines = [f"package {package_name}", "", "default allow := false", ""]
    if rules:
        lines.append("allow {")
        for i, rule in enumerate(rules):
            pattern = rule.get("pattern", "").strip()
            if not pattern:
                continue
            safe_pattern = pattern.replace('"', '\\"')
            lines.append(f'    not contains(lower(input.action), "{safe_pattern}")')
        lines.append("}")
    else:
        lines.append("allow {")
        lines.append("    true")
        lines.append("}")
    lines.append("")
    return "\n".join(lines)


def export_rego(
    rules: list[dict[str, Any]],
    output_path: Path | str | None = None,
) -> Path:
    """Write rules as a Rego policy file. Returns the path written."""
    path = Path(output_path) if output_path else Path("SAFETY_POLICY.rego")
    path.write_text(rules_to_rego(rules))
    return path


def rules_from_md(rules_path: Path | str) -> list[dict[str, Any]]:
    """Parse SAFETY_RULES.md lines into rule dicts."""
    path = Path(rules_path)
    if not path.exists():
        return []
    rules: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("- DENY:"):
            pattern = line[len("- DENY:"):].strip()
            rules.append({"type": "deny", "pattern": pattern.lower()})
        elif line.startswith("- BLOCK:"):
            pattern = line[len("- BLOCK:"):].strip()
            rules.append({"type": "deny", "pattern": pattern.lower()})
    return rules
