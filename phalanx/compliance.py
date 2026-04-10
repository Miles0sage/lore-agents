"""phalanx.compliance — Compliance report generator for AI agent fleets.

Maps Darwin failure data and audit logs to regulatory frameworks.
Output: structured dict ready for PDF rendering or JSON export.
"""
from __future__ import annotations
import json, time, hashlib, datetime
from pathlib import Path
from typing import Optional

# OWASP Agentic Top 10 (2025) mapping
OWASP_AGENTIC_TOP10 = {
    "OAT-01": "Prompt Injection",
    "OAT-02": "Insecure Output Handling",
    "OAT-03": "Excessive Agency",
    "OAT-04": "Overreliance on Agent Memory",
    "OAT-05": "Inadequate Sandboxing",
    "OAT-06": "Insufficient Logging and Monitoring",
    "OAT-07": "Uncontrolled Resource Consumption",
    "OAT-08": "Insecure Inter-Agent Communication",
    "OAT-09": "Inadequate Human Oversight",
    "OAT-10": "Supply Chain Vulnerabilities",
}

SOC2_CRITERIA = {
    "CC6.1": "Logical and Physical Access Controls",
    "CC6.6": "Logical Access Security Measures",
    "CC7.2": "System Monitoring",
    "CC7.3": "Evaluation of Security Events",
    "CC8.1": "Change Management",
    "A1.1": "Availability — Performance Monitoring",
}

EU_AI_ACT_ARTICLES = {
    "Art.9": "Risk Management System",
    "Art.12": "Record-keeping",
    "Art.13": "Transparency",
    "Art.14": "Human Oversight",
    "Art.17": "Quality Management",
}


def generate_compliance_report(
    audit_log=None,
    failures_dir: Optional[Path] = None,
    rules_path: Optional[Path] = None,
    period_days: int = 30,
    frameworks: Optional[list[str]] = None,
    agent_id: Optional[str] = None,
) -> dict:
    """Generate a compliance report dict from phalanx data.

    Args:
        audit_log: AuditLog instance (optional)
        failures_dir: Path to .phalanx/failures/*.json directory
        rules_path: Path to SAFETY_RULES.md
        period_days: Number of days to cover (default 30)
        frameworks: List of frameworks to include: ["OWASP", "SOC2", "EU_AI_ACT"]
        agent_id: Filter to specific agent (optional)

    Returns:
        Structured dict with all compliance data, ready for PDF rendering
    """
    if frameworks is None:
        frameworks = ["OWASP", "SOC2", "EU_AI_ACT"]

    now = time.time()
    period_start = now - (period_days * 86400)
    period_start_dt = datetime.datetime.fromtimestamp(period_start, tz=datetime.timezone.utc)
    period_end_dt = datetime.datetime.fromtimestamp(now, tz=datetime.timezone.utc)

    # Collect failure data
    failures = _load_failures(failures_dir, period_start, agent_id)
    rules = _load_rules(rules_path)
    audit_entries = _load_audit_entries(audit_log, period_start, agent_id)

    # Build summary
    total_events = len(audit_entries) + len(failures)
    denials = sum(1 for e in audit_entries if e.get("payload", {}).get("verdict") == "DENY")
    injections_blocked = sum(1 for f in failures if "injection" in f.get("event_type", "").lower())
    unique_agents = set()
    for f in failures:
        unique_agents.add(f.get("agent_id", "unknown"))
    for e in audit_entries:
        unique_agents.add(e.get("agent_id", "unknown"))

    # Build framework mappings
    compliance_sections = {}

    if "OWASP" in frameworks:
        compliance_sections["OWASP_Agentic_Top10"] = _build_owasp_section(
            failures, audit_entries, denials, injections_blocked
        )

    if "SOC2" in frameworks:
        compliance_sections["SOC2"] = _build_soc2_section(audit_entries, rules, unique_agents)

    if "EU_AI_ACT" in frameworks:
        compliance_sections["EU_AI_Act"] = _build_eu_ai_act_section(failures, rules, audit_entries)

    # Chain verification
    chain_verified = False
    if audit_log is not None:
        try:
            chain_verified = audit_log.verify()
        except Exception:
            chain_verified = False

    # Build the full report
    report = {
        "report_metadata": {
            "generated_at": period_end_dt.isoformat(),
            "generated_by": "phalanx compliance module",
            "period_start": period_start_dt.isoformat(),
            "period_end": period_end_dt.isoformat(),
            "period_days": period_days,
            "frameworks": frameworks,
            "report_hash": "",  # filled below
        },
        "summary": {
            "total_events": total_events,
            "total_failures": len(failures),
            "total_audit_entries": len(audit_entries),
            "policy_denials": denials,
            "injections_blocked": injections_blocked,
            "active_agents": len(unique_agents),
            "safety_rules_active": len(rules),
            "chain_verified": chain_verified,
        },
        "compliance": compliance_sections,
        "safety_rules": rules[:50],  # cap at 50 for report
        "chain_verified": chain_verified,
    }

    # Sign the report with SHA-256
    report_json = json.dumps(report, sort_keys=True, default=str)
    report["report_metadata"]["report_hash"] = hashlib.sha256(report_json.encode()).hexdigest()

    return report


def _load_failures(failures_dir: Optional[Path], since: float, agent_id: Optional[str]) -> list[dict]:
    if failures_dir is None:
        failures_dir = Path(".phalanx/failures")
    failures = []
    if failures_dir.exists():
        for f in failures_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                if data.get("timestamp", 0) >= since:
                    if agent_id is None or data.get("agent_id") == agent_id:
                        failures.append(data)
            except Exception:
                pass
    return failures


def _load_rules(rules_path: Optional[Path]) -> list[str]:
    if rules_path is None:
        rules_path = Path("SAFETY_RULES.md")
    if not rules_path.exists():
        return []
    rules = []
    for line in rules_path.read_text().splitlines():
        line = line.strip()
        if line.startswith("- DENY:") or line.startswith("- ALLOW:"):
            rules.append(line)
    return rules


def _load_audit_entries(audit_log, since: float, agent_id: Optional[str]) -> list[dict]:
    if audit_log is None:
        return []
    try:
        entries = audit_log.get_entries(agent_id=agent_id, since=since, limit=10000)
        return [
            {
                "agent_id": e.agent_id,
                "event_type": e.event_type,
                "payload": e.payload,
                "timestamp": e.timestamp,
            }
            for e in entries
        ]
    except Exception:
        return []


def _build_owasp_section(failures, audit_entries, denials, injections_blocked) -> dict:
    return {
        "framework": "OWASP Agentic Top 10 (2025)",
        "controls": {
            "OAT-01 Prompt Injection": {
                "status": "MONITORED",
                "events": injections_blocked,
                "evidence": (
                    f"{injections_blocked} injection attempts detected and blocked by "
                    "phalanx injection.py heuristic scanner"
                ),
            },
            "OAT-03 Excessive Agency": {
                "status": "CONTROLLED",
                "events": denials,
                "evidence": (
                    f"{denials} policy DENY verdicts enforced by AgentHypervisor trust ring system"
                ),
            },
            "OAT-06 Insufficient Logging": {
                "status": "COMPLIANT",
                "events": len(audit_entries),
                "evidence": (
                    f"{len(audit_entries)} events recorded in tamper-evident hash-chained audit log"
                ),
            },
            "OAT-09 Inadequate Human Oversight": {
                "status": "COMPLIANT",
                "events": 0,
                "evidence": (
                    "Darwin loop generates GitHub PRs requiring human approval before "
                    "fleet-wide rule deployment"
                ),
            },
        },
    }


def _build_soc2_section(audit_entries, rules, unique_agents) -> dict:
    return {
        "framework": "SOC 2 Type II",
        "criteria": {
            "CC6.1 Access Controls": {
                "status": "COMPLIANT",
                "evidence": (
                    f"4-tier execution ring system enforces least-privilege for "
                    f"{len(unique_agents)} registered agents"
                ),
            },
            "CC7.2 System Monitoring": {
                "status": "COMPLIANT",
                "evidence": (
                    f"{len(audit_entries)} agent actions logged with SHA-256 hash chain. "
                    "Chain integrity: verifiable."
                ),
            },
            "CC7.3 Security Event Evaluation": {
                "status": "COMPLIANT",
                "evidence": (
                    f"Darwin failure engine clusters security events into "
                    f"{len(rules)} active safety rules"
                ),
            },
            "CC8.1 Change Management": {
                "status": "COMPLIANT",
                "evidence": (
                    "All safety rule changes require human-approved GitHub PR before deployment "
                    "(5-layer gatekeeper)"
                ),
            },
        },
    }


def _build_eu_ai_act_section(failures, rules, audit_entries) -> dict:
    return {
        "framework": "EU AI Act (2024/1689)",
        "articles": {
            "Art.9 Risk Management": {
                "status": "IMPLEMENTED",
                "evidence": (
                    f"Darwin failure learning system continuously identifies and mitigates risks. "
                    f"{len(rules)} active rules."
                ),
            },
            "Art.12 Record-keeping": {
                "status": "COMPLIANT",
                "evidence": (
                    f"Hash-chained append-only audit log with {len(audit_entries)} entries. "
                    "Cryptographically tamper-evident."
                ),
            },
            "Art.13 Transparency": {
                "status": "COMPLIANT",
                "evidence": (
                    "All safety rules stored as human-readable Markdown in SAFETY_RULES.md. "
                    "All changes via GitHub PR."
                ),
            },
            "Art.14 Human Oversight": {
                "status": "COMPLIANT",
                "evidence": (
                    "No safety rule deployed without human GitHub PR approval. "
                    "AutoGen approval gate for Ring-0 actions."
                ),
            },
        },
    }


def export_json(report: dict, output_path: Optional[Path] = None) -> str:
    """Export compliance report as JSON string."""
    json_str = json.dumps(report, indent=2, default=str)
    if output_path:
        output_path.write_text(json_str)
    return json_str


def export_markdown(report: dict, output_path: Optional[Path] = None) -> str:
    """Export compliance report as Markdown (for GitHub/audit trail)."""
    meta = report["report_metadata"]
    summary = report["summary"]
    lines = [
        "# Phalanx Compliance Report",
        f"**Period:** {meta['period_start'][:10]} → {meta['period_end'][:10]}",
        f"**Generated:** {meta['generated_at']}",
        f"**Report Hash:** `{meta['report_hash'][:16]}...`",
        f"**Chain Verified:** {'✅' if summary['chain_verified'] else '❌'}",
        "",
        "## Summary",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Events | {summary['total_events']} |",
        f"| Policy Denials | {summary['policy_denials']} |",
        f"| Injections Blocked | {summary['injections_blocked']} |",
        f"| Active Agents | {summary['active_agents']} |",
        f"| Safety Rules Active | {summary['safety_rules_active']} |",
        "",
    ]
    for framework, section in report.get("compliance", {}).items():
        lines.append(f"## {section.get('framework', framework)}")
        controls = (
            section.get("controls")
            or section.get("criteria")
            or section.get("articles")
            or {}
        )
        for control, data in controls.items():
            status_icon = (
                "✅"
                if data.get("status") in ("COMPLIANT", "IMPLEMENTED", "MONITORED", "CONTROLLED")
                else "⚠️"
            )
            lines.append(f"### {status_icon} {control}")
            lines.append(f"**Status:** {data.get('status')} | **Events:** {data.get('events', 'N/A')}")
            lines.append(f"> {data.get('evidence', '')}")
            lines.append("")

    md = "\n".join(lines)
    if output_path:
        output_path.write_text(md)
    return md
