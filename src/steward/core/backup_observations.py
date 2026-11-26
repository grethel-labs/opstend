"""Bounded, worker-owned projection of backup jobs and phase evidence.

These records are claims by the unprivileged upload worker, not root capture
provenance or permission to restore or delete anything.
"""

from __future__ import annotations

import json
import math
import re

from pydantic import BaseModel, ConfigDict, Field

from .backups import Receipt
from .canonical import revision_id
from .config import Slug
from .inventory import Digest

MAX_RECORDS = 1280


class Page(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project: Slug | None = None
    offset: int = Field(0, ge=0, le=MAX_RECORDS)
    limit: int = Field(50, ge=1, le=200)
    snapshot_id: Digest | None = None


class SnapshotChanged(Exception):
    """The evidence changed between pages."""


def query(ledger, page: Page, *, now: float, max_age_s: int) -> dict:
    """Read jobs and receipts from one SQLite snapshot without exposing paths.

    The digest fences pagination. Freshness uses the original capture time and
    is evaluated at each request; the digest describes evidence, not the clock.
    """
    if max_age_s <= 0:
        raise ValueError("invalid freshness window")
    db = ledger._conn()
    db.execute("BEGIN")
    try:
        rows = db.execute(
            "SELECT * FROM jobs WHERE kind='backup_upload' ORDER BY rowid DESC LIMIT ?",
            (MAX_RECORDS + 1,),
        ).fetchall()
        truncated = len(rows) > MAX_RECORDS
        records = []
        for row in rows[:MAX_RECORDS]:
            if (
                not re.fullmatch(r"[a-f0-9]{32}", row["id"])
                or row["state"] not in ("queued", "running", "succeeded", "failed")
                or not isinstance(row["updated_at"], (int, float))
                or not math.isfinite(row["updated_at"])
            ):
                raise ValueError("invalid job evidence")
            payload = json.loads(row["payload"])
            # A corrupted ledger must not produce reassuring partial evidence.
            from ..backupworker import Upload

            payload = Upload.model_validate(payload)
            if row["target"] != payload.project:
                raise ValueError("job target mismatch")
            receipt_row = db.execute(
                "SELECT body FROM backup_receipts WHERE repository=? AND capture=?",
                (payload.repository_id, payload.capture_id),
            ).fetchone()
            receipt = Receipt.model_validate_json(receipt_row[0]) if receipt_row else None
            if receipt and (
                receipt.repository_id != payload.repository_id
                or receipt.capture.id != payload.capture_id
                or receipt.capture.binding.project != payload.project
            ):
                raise ValueError("receipt binding mismatch")
            error = row["error"]
            if error is not None and not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error):
                error = "invalid_error"
            records.append(
                {
                    "job_id": row["id"],
                    "project": payload.project,
                    "capture_id": payload.capture_id,
                    "repository_id": payload.repository_id,
                    "config_revision": receipt.capture.binding.config_revision if receipt else None,
                    "capture_created_at": receipt.capture.created_at if receipt else None,
                    "snapshot_id": receipt.snapshot_id if receipt else None,
                    "snapshot_created_at": receipt.snapshot_created_at if receipt else None,
                    "uploaded_at": receipt.recorded_at if receipt else None,
                    "integrity_checked_at": receipt.integrity_checked_at if receipt else None,
                    "restored_bytes_at": receipt.restore_verified_at if receipt else None,
                    "application_drill_at": None,
                    "job_state": row["state"],
                    "job_error": error,
                    "updated_at": row["updated_at"],
                    "provenance": "worker_reported",
                }
            )
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise
    if page.project is not None:
        records = [record for record in records if record["project"] == page.project]
    snapshot_id = revision_id({"records": records, "truncated": truncated})
    if page.snapshot_id is not None and snapshot_id != page.snapshot_id:
        raise SnapshotChanged()
    selected = records[page.offset : page.offset + page.limit]
    for record in selected:
        capture_time = record["capture_created_at"]
        record["capture_freshness"] = (
            "unknown"
            if capture_time is None or capture_time > now
            else "stale"
            if now - capture_time > max_age_s
            else "fresh"
        )
    return {
        "snapshot_id": snapshot_id,
        "observed_at": now,
        "ledger_coverage": "truncated" if truncated else "complete",
        "total": len(records),
        "next_offset": page.offset + len(selected)
        if page.offset + len(selected) < len(records)
        else None,
        "records": selected,
    }
