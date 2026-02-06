"""Client-side rule sync and opt-in telemetry submission."""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from gripboard import __version__
from gripboard.audit import AuditLog

DEFAULT_API_URL = "https://api.gripboard.dev"

SYNC_DIR = Path(os.environ.get(
    "XDG_DATA_HOME", os.path.expanduser("~/.local/share")
)) / "gripboard"

COMMUNITY_RULES_PATH = SYNC_DIR / "community_rules.toml"
CLIENT_ID_PATH = SYNC_DIR / ".client_id"
LAST_SYNC_PATH = SYNC_DIR / ".last_sync"


def _get_client_hash() -> str:
    """Get or create a stable anonymized client identifier."""
    CLIENT_ID_PATH.parent.mkdir(parents=True, exist_ok=True)
    if CLIENT_ID_PATH.exists():
        raw = CLIENT_ID_PATH.read_text().strip()
    else:
        raw = str(uuid.uuid4())
        CLIENT_ID_PATH.write_text(raw)

    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def sync_rules(api_url: str | None = None, timeout: int = 10) -> dict:
    """Pull latest community rules from the API and save locally.

    Returns a summary dict with status and rule count.
    """
    url = (api_url or DEFAULT_API_URL).rstrip("/") + "/rules/toml"

    try:
        req = Request(url, headers={"User-Agent": f"Gripboard/{__version__}"})
        with urlopen(req, timeout=timeout) as resp:
            content = resp.read().decode()
    except (URLError, OSError) as e:
        return {"status": "error", "message": str(e)}

    # Save to disk
    COMMUNITY_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    COMMUNITY_RULES_PATH.write_text(content)

    # Record sync timestamp
    LAST_SYNC_PATH.write_text(datetime.now(timezone.utc).isoformat())

    # Count rules
    rule_count = content.count("[[rules]]")

    return {
        "status": "ok",
        "rules_synced": rule_count,
        "saved_to": str(COMMUNITY_RULES_PATH),
    }


def submit_telemetry(api_url: str | None = None, timeout: int = 10) -> dict:
    """Submit anonymized telemetry from the local audit log.

    Only sends aggregate counts — never clipboard content.
    """
    url = (api_url or DEFAULT_API_URL).rstrip("/") + "/telemetry"

    audit = AuditLog()
    stats = audit.stats()
    audit.close()

    payload = {
        "client_hash": _get_client_hash(),
        "total_scans": stats.get("total_scans", 0),
        "findings_by_severity": stats.get("by_severity", {}),
        "top_rules": [],  # Could be expanded to track most-triggered rules
        "version": __version__,
    }

    try:
        data = json.dumps(payload).encode()
        req = Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"Gripboard/{__version__}",
            },
            method="POST",
        )
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (URLError, OSError) as e:
        return {"status": "error", "message": str(e)}


def submit_rule(
    rule_id: str,
    description: str,
    severity: str,
    pattern: str,
    scope: str = "full",
    tags: list[str] | None = None,
    api_url: str | None = None,
    timeout: int = 10,
) -> dict:
    """Submit a new rule to the community for review."""
    url = (api_url or DEFAULT_API_URL).rstrip("/") + "/rules/submit"

    payload = {
        "rule_id": rule_id,
        "description": description,
        "severity": severity,
        "pattern": pattern,
        "scope": scope,
        "tags": tags or [],
    }

    try:
        data = json.dumps(payload).encode()
        req = Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"Gripboard/{__version__}",
            },
            method="POST",
        )
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (URLError, OSError) as e:
        return {"status": "error", "message": str(e)}


def get_last_sync() -> str | None:
    """Return the ISO timestamp of the last successful rule sync, or None."""
    if LAST_SYNC_PATH.exists():
        return LAST_SYNC_PATH.read_text().strip()
    return None
