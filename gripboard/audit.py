"""SQLite-backed audit logging for clipboard scan events."""

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from gripboard.scanner import ScanResult, Severity
from gripboard.scoring import ScoreBreakdown

DEFAULT_DB_DIR = Path(os.environ.get(
    "XDG_DATA_HOME", os.path.expanduser("~/.local/share")
)) / "gripboard"

DEFAULT_DB_PATH = DEFAULT_DB_DIR / "audit.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    content_preview TEXT NOT NULL,
    content_length INTEGER NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    findings_count INTEGER NOT NULL,
    findings_json TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'none',
    app_class TEXT,
    profile_name TEXT,
    score_details TEXT
);

CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_severity ON scan_events(severity);
CREATE INDEX IF NOT EXISTS idx_content_hash ON scan_events(content_hash);
"""


@dataclass
class AuditEntry:
    id: int
    timestamp: str
    content_hash: str
    content_preview: str
    content_length: int
    severity: str
    score: int
    findings_count: int
    findings_json: str
    action: str
    app_class: str | None
    profile_name: str | None
    score_details: str | None


class AuditLog:
    """Audit logger backed by SQLite."""

    def __init__(self, db_path: Path | None = None):
        self._db_path = db_path or DEFAULT_DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def log_scan(
        self,
        result: ScanResult,
        score: ScoreBreakdown | None = None,
        action: str = "none",
        app_class: str | None = None,
        profile_name: str | None = None,
    ) -> int:
        """Record a scan event. Returns the row ID."""
        content_hash = hashlib.sha256(result.content.encode()).hexdigest()[:16]
        preview = result.content[:200]

        findings_data = [
            {
                "rule": f.rule,
                "description": f.description,
                "severity": f.severity.value,
                "position": f.position,
                "codepoint": f.codepoint,
            }
            for f in result.findings
        ]

        severity = result.severity.value if result.findings else "safe"
        score_val = score.total_score if score else 0
        score_details = json.dumps(score.details) if score else "[]"

        cursor = self._conn.execute(
            """INSERT INTO scan_events
            (timestamp, content_hash, content_preview, content_length,
             severity, score, findings_count, findings_json,
             action, app_class, profile_name, score_details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                content_hash,
                preview,
                len(result.content),
                severity,
                score_val,
                len(result.findings),
                json.dumps(findings_data),
                action,
                app_class,
                profile_name,
                score_details,
            ),
        )
        self._conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def query(
        self,
        limit: int = 50,
        severity: str | None = None,
        since: str | None = None,
    ) -> list[AuditEntry]:
        """Query audit log entries."""
        query = "SELECT * FROM scan_events WHERE 1=1"
        params: list = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if since:
            query += " AND timestamp >= ?"
            params.append(since)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [AuditEntry(*row) for row in rows]

    def stats(self) -> dict:
        """Get summary statistics from the audit log."""
        total = self._conn.execute("SELECT COUNT(*) FROM scan_events").fetchone()[0]
        by_severity = dict(
            self._conn.execute(
                "SELECT severity, COUNT(*) FROM scan_events GROUP BY severity"
            ).fetchall()
        )
        by_action = dict(
            self._conn.execute(
                "SELECT action, COUNT(*) FROM scan_events GROUP BY action"
            ).fetchall()
        )
        avg_score = self._conn.execute(
            "SELECT AVG(score) FROM scan_events WHERE findings_count > 0"
        ).fetchone()[0]

        return {
            "total_scans": total,
            "by_severity": by_severity,
            "by_action": by_action,
            "avg_threat_score": round(avg_score, 1) if avg_score else 0,
        }

    def export_json(self, limit: int = 1000) -> str:
        """Export audit log as JSON."""
        entries = self.query(limit=limit)
        data = []
        for e in entries:
            data.append({
                "id": e.id,
                "timestamp": e.timestamp,
                "content_hash": e.content_hash,
                "content_preview": e.content_preview,
                "severity": e.severity,
                "score": e.score,
                "findings_count": e.findings_count,
                "action": e.action,
                "app_class": e.app_class,
                "profile_name": e.profile_name,
            })
        return json.dumps(data, indent=2)

    def close(self) -> None:
        self._conn.close()
