"""Read and correlate unprivileged worker claims with root schedule records."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .config import Slug
from .inventory import Digest


class WorkerRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    job_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    project: Slug
    capture_id: Digest
    repository_id: Digest
    config_revision: Digest | None
    capture_created_at: float | None = Field(ge=0)
    snapshot_id: Digest | None
    snapshot_created_at: float | None = Field(ge=0)
    uploaded_at: float | None = Field(ge=0)
    integrity_checked_at: float | None = Field(ge=0)
    restored_bytes_at: float | None = Field(ge=0)
    application_drill_at: None
    job_state: Literal["queued", "running", "succeeded", "failed"]
    job_error: str | None = Field(max_length=64)
    updated_at: float = Field(ge=0)
    provenance: Literal["worker_reported"]
    capture_freshness: Literal["fresh", "stale", "unknown"]


class Page(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    snapshot_id: Digest
    observed_at: float = Field(ge=0)
    ledger_coverage: Literal["complete", "truncated"]
    total: int = Field(ge=0, le=1280)
    next_offset: int | None = Field(ge=1, le=1280)
    records: list[WorkerRecord] = Field(max_length=200)


def read_snapshot(request, socket_path):
    """Read all bounded pages, failing closed on change, truncation or malformed pages."""
    records, offset, expected, total = [], 0, None, None
    while True:
        params = {"offset": offset, "limit": 200}
        if expected is not None:
            params["snapshot_id"] = expected
        page = Page.model_validate(
            request("backups_query", params, socket_path=socket_path, timeout=5)
        )
        if page.ledger_coverage != "complete":
            raise ValueError("worker ledger is truncated")
        if expected is None:
            expected, total = page.snapshot_id, page.total
        if page.snapshot_id != expected or page.total != total:
            raise ValueError("worker snapshot changed")
        records.extend(page.records)
        if len(records) > total:
            raise ValueError("invalid worker page length")
        if page.next_offset is None:
            if len(records) != total:
                raise ValueError("incomplete worker snapshot")
            break
        if not page.records or page.next_offset != len(records) or page.next_offset >= total:
            raise ValueError("invalid worker pagination")
        offset = page.next_offset
    if len({item.job_id for item in records}) != len(records):
        raise ValueError("duplicate worker job")
    return records


def correlate(schedule: dict, records: list[WorkerRecord], *, revision: str, now: float) -> dict:
    """Correlate IDs; root and worker provenance stay distinct in the result."""
    result = {}
    by_capture = {}
    for record in records:
        by_capture.setdefault((record.project, record.capture_id), []).append(record)
    for project, root in schedule.items():
        if (
            root.get("state") != "exported"
            or root.get("config_revision") != revision
            or root.get("capture_id") is None
            or root.get("capture_created_at") is None
        ):
            result[project] = {"state": "unknown", "reason": "root_capture_unavailable"}
            continue
        if root["capture_created_at"] > now:
            result[project] = {"state": "unknown", "reason": "capture_time_in_future"}
            continue
        matches = by_capture.get((project, root["capture_id"]), [])
        if not matches:
            result[project] = {"state": "missing", "capture_id": root["capture_id"]}
            continue
        if len(matches) != 1:
            result[project] = {"state": "unknown", "reason": "ambiguous_worker_records"}
            continue
        record = matches[0]
        times = (
            record.snapshot_created_at,
            record.uploaded_at,
            record.integrity_checked_at,
            record.restored_bytes_at,
        )
        bad_error = record.job_error is not None and not re.fullmatch(
            r"[a-z][a-z0-9_]{0,63}", record.job_error
        )
        if (
            bad_error
            or any(value is not None and value > now for value in times)
            or (
                record.uploaded_at is not None
                and (
                    record.config_revision != revision
                    or record.capture_created_at != root["capture_created_at"]
                    or record.snapshot_id is None
                    or record.snapshot_created_at is None
                )
            )
            or (
                record.uploaded_at is None
                and (record.snapshot_id is not None or any(value is not None for value in times))
            )
            or (
                record.integrity_checked_at is not None
                and record.uploaded_at is not None
                and record.integrity_checked_at < record.uploaded_at
            )
            or (
                record.restored_bytes_at is not None
                and record.integrity_checked_at is not None
                and record.restored_bytes_at < record.integrity_checked_at
            )
            or (record.restored_bytes_at is not None and record.integrity_checked_at is None)
        ):
            result[project] = {"state": "unknown", "reason": "worker_evidence_mismatch"}
            continue
        result[project] = {
            "state": "failed" if record.job_error or record.job_state == "failed" else "reported",
            "capture_id": root["capture_id"],
            "capture_created_at": root["capture_created_at"],
            "root_provenance": "executor_schedule",
            "worker_provenance": "worker_reported",
            "repository_id": record.repository_id,
            "snapshot_id": record.snapshot_id,
            "job_state": record.job_state,
            "job_error": record.job_error,
            "uploaded_at": record.uploaded_at,
            "integrity_checked_at": record.integrity_checked_at,
            "restored_bytes_at": record.restored_bytes_at,
            "application_drill_at": None,
        }
    return result
