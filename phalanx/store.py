"""phalanx.store — SQLite-backed failure store for fleet-wide learning.

Replaces or complements the JSON file store. Enables:
- Cross-agent failure queries
- Fleet trust scores
- Failure timeline
- generate_briefing_data() for VIGIL morning briefings

Usage:
    from phalanx.store import FailureStore
    store = FailureStore("/root/ai-factory/data/phalanx_fleet.db")
    store.record(failure_dict)
    clusters = store.get_clusters(min_occurrences=2, hours=168)
    summary = store.fleet_summary()
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections import defaultdict
from pathlib import Path
from typing import Any


_SCHEMA = """
CREATE TABLE IF NOT EXISTS failures (
    id INTEGER PRIMARY KEY,
    timestamp REAL,
    agent_id TEXT,
    action TEXT,
    input_preview TEXT,
    error_type TEXT,
    error_message TEXT,
    traceback TEXT,
    type TEXT DEFAULT 'failure'
);
CREATE INDEX IF NOT EXISTS idx_ts ON failures(timestamp);
CREATE INDEX IF NOT EXISTS idx_agent ON failures(agent_id);
"""

# Table for tracking generated rules count (lightweight counter)
_RULES_SCHEMA = """
CREATE TABLE IF NOT EXISTS learned_rules (
    id INTEGER PRIMARY KEY,
    created_at REAL,
    rule_text TEXT,
    source TEXT
);
"""


class FailureStore:
    """SQLite-backed store for phalanx fleet failure data."""

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    # ------------------------------------------------------------------
    # Schema / lifecycle
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(_SCHEMA)
            self._conn.executescript(_RULES_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "FailureStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record(self, failure: dict) -> None:
        """Insert a failure (or block) record into the store.

        Accepts the same dict format that watch.py writes to JSON files:
            {timestamp, agent_id, action, input_preview, error_type,
             error_message, traceback, type}
        Missing keys default to empty string / current time.
        """
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO failures
                    (timestamp, agent_id, action, input_preview,
                     error_type, error_message, traceback, type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    failure.get("timestamp", time.time()),
                    failure.get("agent_id", ""),
                    failure.get("action", ""),
                    failure.get("input_preview", ""),
                    failure.get("error_type", ""),
                    failure.get("error_message", ""),
                    failure.get("traceback", ""),
                    failure.get("type", "failure"),
                ),
            )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_failures(
        self,
        hours: int = 168,
        agent_id: str | None = None,
    ) -> list[dict]:
        """Return recent failures within the given window.

        Args:
            hours: Look-back window in hours (default 168 = 7 days).
            agent_id: Optional filter to a specific agent.

        Returns:
            List of failure dicts ordered newest-first.
        """
        cutoff = time.time() - hours * 3600
        if agent_id is not None:
            rows = self._conn.execute(
                """
                SELECT * FROM failures
                WHERE timestamp >= ? AND agent_id = ?
                ORDER BY timestamp DESC
                """,
                (cutoff, agent_id),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT * FROM failures
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
                """,
                (cutoff,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_clusters(
        self,
        min_occurrences: int = 2,
        hours: int = 168,
    ) -> dict[str, list[dict]]:
        """Group failures by error signature (error_type + action prefix).

        Returns a dict mapping signature -> list of matching failure dicts.
        Only includes signatures that appear >= min_occurrences times.
        """
        failures = self.get_failures(hours=hours)
        groups: dict[str, list[dict]] = defaultdict(list)
        for f in failures:
            # Signature = error_type + first segment of action
            action_prefix = (f.get("action") or "").split(":")[0]
            error_type = f.get("error_type") or "unknown"
            sig = f"{error_type}:{action_prefix}"
            groups[sig].append(f)

        return {sig: records for sig, records in groups.items() if len(records) >= min_occurrences}

    # ------------------------------------------------------------------
    # Trust / scoring
    # ------------------------------------------------------------------

    def agent_trust_score(self, agent_id: str, hours: int = 24) -> float:
        """Compute a simple trust score for an agent.

        Score = 100 - (failure_count * 5), floored at 0.
        Only counts records with type='failure' (not 'block').
        """
        cutoff = time.time() - hours * 3600
        row = self._conn.execute(
            """
            SELECT COUNT(*) as cnt FROM failures
            WHERE agent_id = ? AND timestamp >= ? AND type = 'failure'
            """,
            (agent_id, cutoff),
        ).fetchone()
        failures = row["cnt"] if row else 0
        return max(0.0, 100.0 - failures * 5.0)

    # ------------------------------------------------------------------
    # Summary / reporting
    # ------------------------------------------------------------------

    def fleet_summary(self) -> dict:
        """Return a fleet-wide summary dict.

        Returns:
            {
                fleet_avg_trust: float,
                total_agents: int,
                total_failures: int,
                top_patterns: list[str],   # top 5 error signatures
                new_rules_count: int,
            }
        """
        # All-time totals (last 168h for trust calc)
        all_time = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM failures WHERE type = 'failure'"
        ).fetchone()
        total_failures = all_time["cnt"] if all_time else 0

        agent_rows = self._conn.execute(
            "SELECT DISTINCT agent_id FROM failures"
        ).fetchall()
        agent_ids = [r["agent_id"] for r in agent_rows if r["agent_id"]]
        total_agents = len(agent_ids)

        # Average trust across known agents (24h window)
        if agent_ids:
            trust_scores = [self.agent_trust_score(a, hours=24) for a in agent_ids]
            fleet_avg_trust = sum(trust_scores) / len(trust_scores)
        else:
            fleet_avg_trust = 100.0

        # Top patterns from last 168h clusters
        clusters = self.get_clusters(min_occurrences=2, hours=168)
        sorted_patterns = sorted(clusters.items(), key=lambda kv: len(kv[1]), reverse=True)
        top_patterns = [sig for sig, _ in sorted_patterns[:5]]

        # Rules count
        rules_row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM learned_rules"
        ).fetchone()
        new_rules_count = rules_row["cnt"] if rules_row else 0

        return {
            "fleet_avg_trust": round(fleet_avg_trust, 2),
            "total_agents": total_agents,
            "total_failures": total_failures,
            "top_patterns": top_patterns,
            "new_rules_count": new_rules_count,
        }

    def generate_briefing_data(self) -> dict:
        """Generate full data payload for VIGIL morning briefings.

        Returns a rich dict with fleet health, per-agent breakdown,
        top failure clusters, and actionable highlights.
        """
        now = time.time()
        summary = self.fleet_summary()

        # Per-agent breakdown (24h)
        agent_rows = self._conn.execute(
            "SELECT DISTINCT agent_id FROM failures"
        ).fetchall()
        agent_ids = [r["agent_id"] for r in agent_rows if r["agent_id"]]

        agents = []
        for agent_id in agent_ids:
            cutoff_24h = now - 24 * 3600
            row = self._conn.execute(
                """
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN type='failure' THEN 1 ELSE 0 END) as failures,
                    SUM(CASE WHEN type='block' THEN 1 ELSE 0 END) as blocks,
                    MAX(timestamp) as last_seen
                FROM failures
                WHERE agent_id = ? AND timestamp >= ?
                """,
                (agent_id, cutoff_24h),
            ).fetchone()
            agents.append(
                {
                    "agent_id": agent_id,
                    "trust_score": self.agent_trust_score(agent_id, hours=24),
                    "failures_24h": row["failures"] or 0,
                    "blocks_24h": row["blocks"] or 0,
                    "last_seen": row["last_seen"],
                }
            )

        # Sort agents by trust score ascending (worst first)
        agents.sort(key=lambda a: a["trust_score"])

        # Cluster analysis (7 days)
        clusters = self.get_clusters(min_occurrences=2, hours=168)
        cluster_summary = []
        for sig, records in sorted(clusters.items(), key=lambda kv: len(kv[1]), reverse=True)[:10]:
            unique_agents = len({r.get("agent_id") for r in records})
            cluster_summary.append(
                {
                    "signature": sig,
                    "occurrences": len(records),
                    "unique_agents": unique_agents,
                    "is_novel": unique_agents >= 2,
                    "first_seen": min(r["timestamp"] for r in records),
                    "last_seen": max(r["timestamp"] for r in records),
                }
            )

        # Highlight agents below trust threshold
        at_risk_agents = [a for a in agents if a["trust_score"] < 60]

        return {
            "generated_at": now,
            "summary": summary,
            "agents": agents,
            "clusters": cluster_summary,
            "at_risk_agents": at_risk_agents,
            "highlights": {
                "total_agents": summary["total_agents"],
                "fleet_avg_trust": summary["fleet_avg_trust"],
                "at_risk_count": len(at_risk_agents),
                "novel_patterns": sum(1 for c in cluster_summary if c["is_novel"]),
                "top_failure_pattern": cluster_summary[0]["signature"] if cluster_summary else None,
            },
        }

    # ------------------------------------------------------------------
    # Import from JSON dir
    # ------------------------------------------------------------------

    def import_from_json_dir(self, json_dir: Path) -> int:
        """Import all .json failure files from a .phalanx/failures/ directory.

        Reads each JSON file, maps its fields to the DB schema, and inserts.
        Skips files that cannot be parsed.

        Args:
            json_dir: Path to the directory containing JSON failure files.

        Returns:
            Number of records successfully imported.
        """
        json_dir = Path(json_dir)
        if not json_dir.exists():
            return 0

        imported = 0
        for json_file in sorted(json_dir.glob("*.json")):
            try:
                data = json.loads(json_file.read_text())
                # Normalise 'blocked_by' block records — they lack error fields
                if data.get("type") == "block":
                    data.setdefault("error_type", "block")
                    data.setdefault("error_message", data.get("blocked_by", ""))
                    data.setdefault("traceback", "")
                self.record(data)
                imported += 1
            except Exception:
                # Silently skip unparseable files
                continue

        return imported
