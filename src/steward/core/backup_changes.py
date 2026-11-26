"""Transactional, bounded change feed for worker-owned backup evidence."""

from __future__ import annotations

import json
import re
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .config import Slug
from .inventory import Digest

MAX_CHANGES = 10000


class Changes(BaseModel):
    model_config = ConfigDict(extra="forbid")
    after_id: int = Field(0, ge=0)
    limit: int = Field(200, ge=1, le=200)


class Change(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    id: int = Field(gt=0)
    ts: float = Field(ge=0)
    job_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    project: Slug
    capture_id: Digest
    repository_id: Digest
    state: Literal["queued", "running", "succeeded", "failed"]
    error: str | None = Field(max_length=64)
    previous_error: str | None = Field(max_length=64)
    uploaded_at: float | None = Field(None, ge=0)
    integrity_checked_at: float | None = Field(None, ge=0)
    restored_bytes_at: float | None = Field(None, ge=0)


def _clean_error(value):
    if value is None:
        return None
    if isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value):
        return value
    if isinstance(value, str) and value.startswith("interrupted: lease expired"):
        return "interrupted"
    return "unknown_error"


def initialize(db):
    """Install feed triggers atomically; legacy jobs get an explicit baseline."""
    db.execute(
        "CREATE TABLE IF NOT EXISTS backup_feed_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS backup_changes (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "ts REAL NOT NULL, job_id TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL, "
        "error TEXT, previous_error TEXT, receipt TEXT)"
    )
    exists = db.execute("SELECT 1 FROM backup_feed_meta WHERE key='stream'").fetchone()
    if not exists:
        legacy = db.execute("SELECT COUNT(*) FROM jobs WHERE kind='backup_upload'").fetchone()[0]
        db.execute("INSERT INTO backup_feed_meta VALUES ('stream', ?)", (uuid.uuid4().hex,))
        db.execute("INSERT INTO backup_feed_meta VALUES ('baseline', ?)", ("1" if legacy else "0",))
        # Existing jobs are a snapshot, not a reconstruction of prior transitions.
        db.execute(
            "INSERT INTO backup_changes(ts,job_id,payload,state,error,previous_error,receipt) "
            "SELECT j.updated_at,j.id,j.payload,j.state,j.error,NULL,r.body FROM jobs j "
            "LEFT JOIN backup_receipts r ON r.repository=json_extract(j.payload,'$.repository_id') "
            "AND r.capture=json_extract(j.payload,'$.capture_id') WHERE j.kind='backup_upload' "
            "ORDER BY j.rowid DESC LIMIT ?",
            (MAX_CHANGES,),
        )
    receipt = (
        "(SELECT body FROM backup_receipts WHERE "
        "repository=json_extract(NEW.payload,'$.repository_id') "
        "AND capture=json_extract(NEW.payload,'$.capture_id'))"
    )
    insert = (  # noqa: S608 - all fragments are fixed SQL and a fixed integer
        "INSERT INTO backup_changes(ts,job_id,payload,state,error,previous_error,receipt) "  # noqa: S608
        "VALUES (NEW.updated_at,NEW.id,NEW.payload,NEW.state,NEW.error,{previous},"
        + receipt
        + "); DELETE FROM backup_changes WHERE id <= "
        + f"(SELECT MAX(id)-{MAX_CHANGES} FROM backup_changes);"  # noqa: S608
    )
    db.execute(
        "CREATE TRIGGER IF NOT EXISTS backup_change_insert AFTER INSERT ON jobs "
        "WHEN NEW.kind='backup_upload' BEGIN " + insert.format(previous="NULL") + " END"
    )
    db.execute(
        "CREATE TRIGGER IF NOT EXISTS backup_change_update AFTER UPDATE OF "
        "state,error,result ON jobs WHEN NEW.kind='backup_upload' AND "
        "(NEW.state IS NOT OLD.state OR NEW.error IS NOT OLD.error "
        "OR NEW.result IS NOT OLD.result) BEGIN " + insert.format(previous="OLD.error") + " END"
    )


def changes(ledger, page: Changes) -> dict:
    """Read one coherent page; this feed cannot grant deletion authority."""
    db = ledger._conn()
    db.execute("BEGIN")
    try:
        meta = dict(db.execute("SELECT key,value FROM backup_feed_meta").fetchall())
        oldest, _newest = db.execute("SELECT MIN(id), MAX(id) FROM backup_changes").fetchone()
        seq = db.execute("SELECT seq FROM sqlite_sequence WHERE name='backup_changes'").fetchone()
        newest_id = seq[0] if seq else 0
        rows = db.execute(
            "SELECT * FROM backup_changes WHERE id>? ORDER BY id LIMIT ?",
            (page.after_id, page.limit),
        ).fetchall()
        result = []
        for row in rows:
            payload = json.loads(row["payload"])
            receipt = json.loads(row["receipt"]) if row["receipt"] else {}
            item = Change.model_validate(
                {
                    "id": row["id"],
                    "ts": row["ts"],
                    "job_id": row["job_id"],
                    "project": payload["project"],
                    "capture_id": payload["capture_id"],
                    "repository_id": payload["repository_id"],
                    "state": row["state"],
                    "error": _clean_error(row["error"]),
                    "previous_error": _clean_error(row["previous_error"]),
                    "uploaded_at": receipt.get("recorded_at"),
                    "integrity_checked_at": receipt.get("integrity_checked_at"),
                    "restored_bytes_at": receipt.get("restore_verified_at"),
                }
            )
            result.append(item.model_dump(mode="json"))
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise
    return {
        "changes": result,
        "next_id": result[-1]["id"]
        if result
        else newest_id
        if page.after_id < newest_id
        else page.after_id,
        "coverage": {
            "stream_id": meta["stream"],
            "oldest_id": oldest,
            "newest_id": newest_id,
            "baseline": meta["baseline"] == "1",
        },
    }
