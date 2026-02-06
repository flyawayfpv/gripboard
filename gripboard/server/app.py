"""FastAPI application for Gripboard community rule distribution and telemetry."""

import hashlib
import hmac
import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Gripboard API",
    description="Community rule distribution and anonymized telemetry for Gripboard",
    version="0.1.0-alpha",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

DB_PATH = Path(os.environ.get("GRIPBOARD_DB", "gripboard_server.db"))

_SERVER_SCHEMA = """
CREATE TABLE IF NOT EXISTS community_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    pattern TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'full',
    tags TEXT NOT NULL DEFAULT '[]',
    submitted_by TEXT,
    submitted_at TEXT NOT NULL,
    approved INTEGER NOT NULL DEFAULT 0,
    downloads INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL,
    client_hash TEXT NOT NULL,
    total_scans INTEGER NOT NULL DEFAULT 0,
    findings_by_severity TEXT NOT NULL DEFAULT '{}',
    top_rules TEXT NOT NULL DEFAULT '[]',
    version TEXT
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    rate_limit INTEGER NOT NULL DEFAULT 100,
    is_admin INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_rules_approved ON community_rules(approved);
CREATE INDEX IF NOT EXISTS idx_telemetry_received ON telemetry(received_at);
"""


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SERVER_SCHEMA)
    return conn


# ---------------------------------------------------------------------------
# Rate limiting (in-memory, per-IP)
# ---------------------------------------------------------------------------

_rate_store: dict[str, list[float]] = {}
RATE_WINDOW = 60  # seconds
RATE_LIMIT = 60  # requests per window


def _check_rate_limit(client_ip: str) -> None:
    now = time.time()
    hits = _rate_store.get(client_ip, [])
    hits = [t for t in hits if now - t < RATE_WINDOW]
    if len(hits) >= RATE_LIMIT:
        raise HTTPException(429, "Rate limit exceeded. Try again later.")
    hits.append(now)
    _rate_store[client_ip] = hits


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    response = await call_next(request)
    return response


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class RuleOut(BaseModel):
    rule_id: str
    description: str
    severity: str
    pattern: str
    scope: str = "full"
    tags: list[str] = []


class RuleSubmission(BaseModel):
    rule_id: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-z0-9\-]+$")
    description: str = Field(..., min_length=5, max_length=256)
    severity: str = Field(..., pattern=r"^(low|medium|high|critical)$")
    pattern: str = Field(..., min_length=3, max_length=1024)
    scope: str = Field(default="full", pattern=r"^(full|line|word)$")
    tags: list[str] = Field(default_factory=list, max_length=10)
    submitted_by: str | None = None


class TelemetryPayload(BaseModel):
    client_hash: str = Field(..., min_length=8, max_length=64)
    total_scans: int = Field(default=0, ge=0)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    top_rules: list[str] = Field(default_factory=list, max_length=20)
    version: str | None = None


class StatsOut(BaseModel):
    total_rules: int
    approved_rules: int
    total_telemetry_reports: int
    unique_clients: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0-alpha"}


@app.get("/rules", response_model=list[RuleOut])
async def get_rules(
    tag: str | None = None,
    severity: str | None = None,
):
    """Fetch approved community rules. Optionally filter by tag or severity."""
    db = get_db()
    query = "SELECT * FROM community_rules WHERE approved = 1"
    params: list = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    query += " ORDER BY downloads DESC"
    rows = db.execute(query, params).fetchall()
    db.close()

    results = []
    for row in rows:
        tags = json.loads(row["tags"])
        if tag and tag not in tags:
            continue
        results.append(RuleOut(
            rule_id=row["rule_id"],
            description=row["description"],
            severity=row["severity"],
            pattern=row["pattern"],
            scope=row["scope"],
            tags=tags,
        ))

    return results


@app.get("/rules/toml")
async def get_rules_toml(
    tag: str | None = None,
    severity: str | None = None,
):
    """Fetch approved rules as a TOML-formatted file for direct use."""
    rules = await get_rules(tag=tag, severity=severity)
    lines = ["# Gripboard community rules", f"# Fetched: {datetime.now(timezone.utc).isoformat()}", ""]
    for r in rules:
        lines.append("[[rules]]")
        lines.append(f'id = "{r.rule_id}"')
        lines.append(f'description = "{r.description}"')
        lines.append(f'severity = "{r.severity}"')
        lines.append(f"pattern = '''{r.pattern}'''")
        lines.append(f'scope = "{r.scope}"')
        lines.append(f'tags = {json.dumps(r.tags)}')
        lines.append("")

    return JSONResponse(
        content="\n".join(lines),
        media_type="application/toml",
    )


@app.post("/rules/submit", status_code=201)
async def submit_rule(submission: RuleSubmission):
    """Submit a new community rule for review."""
    import re
    # Validate the regex pattern
    try:
        re.compile(submission.pattern)
    except re.error as e:
        raise HTTPException(400, f"Invalid regex pattern: {e}")

    db = get_db()

    # Check for duplicate rule_id
    existing = db.execute(
        "SELECT 1 FROM community_rules WHERE rule_id = ?",
        (submission.rule_id,),
    ).fetchone()
    if existing:
        db.close()
        raise HTTPException(409, f"Rule ID '{submission.rule_id}' already exists.")

    db.execute(
        """INSERT INTO community_rules
        (rule_id, description, severity, pattern, scope, tags, submitted_by, submitted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            submission.rule_id,
            submission.description,
            submission.severity,
            submission.pattern,
            submission.scope,
            json.dumps(submission.tags),
            submission.submitted_by,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    db.commit()
    db.close()

    return {"status": "submitted", "rule_id": submission.rule_id, "approved": False}


@app.post("/telemetry", status_code=201)
async def submit_telemetry(payload: TelemetryPayload):
    """Accept anonymized telemetry from clients (opt-in only)."""
    db = get_db()
    db.execute(
        """INSERT INTO telemetry
        (received_at, client_hash, total_scans, findings_by_severity, top_rules, version)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (
            datetime.now(timezone.utc).isoformat(),
            payload.client_hash,
            payload.total_scans,
            json.dumps(payload.findings_by_severity),
            json.dumps(payload.top_rules),
            payload.version,
        ),
    )
    db.commit()
    db.close()

    return {"status": "received"}


@app.get("/stats", response_model=StatsOut)
async def get_stats():
    """Public stats about the Gripboard community."""
    db = get_db()
    total_rules = db.execute("SELECT COUNT(*) FROM community_rules").fetchone()[0]
    approved_rules = db.execute(
        "SELECT COUNT(*) FROM community_rules WHERE approved = 1"
    ).fetchone()[0]
    total_telemetry = db.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0]
    unique_clients = db.execute(
        "SELECT COUNT(DISTINCT client_hash) FROM telemetry"
    ).fetchone()[0]
    db.close()

    return StatsOut(
        total_rules=total_rules,
        approved_rules=approved_rules,
        total_telemetry_reports=total_telemetry,
        unique_clients=unique_clients,
    )
