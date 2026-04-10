"""Hash-chained audit log — stdlib only, no external deps."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AuditEntry:
    entry_id: str
    timestamp: float
    event_type: str
    agent_id: str
    payload: dict
    prev_hash: str
    entry_hash: str


def _compute_entry_hash(
    entry_id: str,
    timestamp: float,
    event_type: str,
    agent_id: str,
    payload: dict,
    prev_hash: str,
) -> str:
    data = {
        "entry_id": entry_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "agent_id": agent_id,
        "payload": payload,
        "prev_hash": prev_hash,
    }
    serialized = json.dumps(data, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()


class AuditLog:
    def __init__(self, db_path: Path = Path(".phalanx/audit.db")) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._create_table()

    def _create_table(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                entry_id  TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                event_type TEXT NOT NULL,
                agent_id  TEXT NOT NULL,
                payload   TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def _last_entry_hash(self) -> str:
        cur = self._conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY timestamp DESC, entry_id DESC LIMIT 1"
        )
        row = cur.fetchone()
        return row[0] if row else "GENESIS"

    def append(self, event_type: str, agent_id: str, payload: dict) -> AuditEntry:
        with self._lock:
            entry_id = str(uuid.uuid4())
            timestamp = time.time()
            prev_hash = self._last_entry_hash()
            entry_hash = _compute_entry_hash(
                entry_id, timestamp, event_type, agent_id, payload, prev_hash
            )
            self._conn.execute(
                """
                INSERT INTO audit_log
                    (entry_id, timestamp, event_type, agent_id, payload, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry_id,
                    timestamp,
                    event_type,
                    agent_id,
                    json.dumps(payload),
                    prev_hash,
                    entry_hash,
                ),
            )
            self._conn.commit()
            return AuditEntry(
                entry_id=entry_id,
                timestamp=timestamp,
                event_type=event_type,
                agent_id=agent_id,
                payload=payload,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )

    def verify(self) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "SELECT entry_id, timestamp, event_type, agent_id, payload, prev_hash, entry_hash "
                "FROM audit_log ORDER BY timestamp ASC, entry_id ASC"
            )
            rows = cur.fetchall()

        expected_prev = "GENESIS"
        for row in rows:
            entry_id, timestamp, event_type, agent_id, payload_json, prev_hash, stored_hash = row
            payload = json.loads(payload_json)

            if prev_hash != expected_prev:
                return False

            computed = _compute_entry_hash(
                entry_id, timestamp, event_type, agent_id, payload, prev_hash
            )
            if computed != stored_hash:
                return False

            expected_prev = stored_hash

        return True

    def get_entries(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 100,
    ) -> List[AuditEntry]:
        conditions: List[str] = []
        params: List[Any] = []

        if agent_id is not None:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if event_type is not None:
            conditions.append("event_type = ?")
            params.append(event_type)
        if since is not None:
            conditions.append("timestamp >= ?")
            params.append(since)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)

        cur = self._conn.execute(
            f"SELECT entry_id, timestamp, event_type, agent_id, payload, prev_hash, entry_hash "
            f"FROM audit_log {where} ORDER BY timestamp ASC, entry_id ASC LIMIT ?",
            params,
        )
        rows = cur.fetchall()
        return [
            AuditEntry(
                entry_id=r[0],
                timestamp=r[1],
                event_type=r[2],
                agent_id=r[3],
                payload=json.loads(r[4]),
                prev_hash=r[5],
                entry_hash=r[6],
            )
            for r in rows
        ]

    def export_pdf_data(
        self,
        period_start: float,
        period_end: float,
        frameworks: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if frameworks is None:
            frameworks = ["OWASP", "SOC2", "EU_AI_ACT"]

        entries = self.get_entries(since=period_start, limit=10000)
        entries = [e for e in entries if e.timestamp <= period_end]

        compliance: Dict[str, Any] = {}
        for fw in frameworks:
            compliance[fw] = {
                "framework": fw,
                "entries_checked": len(entries),
                "status": "compliant" if self.verify() else "non_compliant",
            }

        return {
            "period": {"start": period_start, "end": period_end},
            "summary": {
                "total_entries": len(entries),
                "agents": list({e.agent_id for e in entries}),
                "event_types": list({e.event_type for e in entries}),
            },
            "compliance": compliance,
            "chain_verified": self.verify(),
            "entries": [asdict(e) for e in entries],
        }

    def record_policy_result(self, result: Any) -> AuditEntry:
        payload: Dict[str, Any] = {"verdict": result.verdict}
        # Capture any extra attributes gracefully
        for attr in ("action", "reason", "rule"):
            val = getattr(result, attr, None)
            if val is not None:
                payload[attr] = val
        return self.append(
            event_type="policy_result",
            agent_id=result.agent_id,
            payload=payload,
        )

    def close(self) -> None:
        self._conn.close()
