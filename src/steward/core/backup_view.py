"""Bounded presentation of controller backup observations, without authority."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path

MAX_SNAPSHOT_BYTES = 1024 * 1024
_PROJECT = re.compile(r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_ERROR = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _time(value):
    try:
        return (
            value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None
        )
    except OverflowError:
        return None


def _digest(value):
    return value if isinstance(value, str) and _DIGEST.fullmatch(value) else None


def read(path: Path, *, now: float, projects: list[str] | None = None) -> dict:
    """Read a bounded snapshot and filter by authorized project IDs before projection."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_SNAPSHOT_BYTES + 1)
        if len(raw) > MAX_SNAPSHOT_BYTES:
            raise ValueError("snapshot too large")
        snapshot = json.loads(raw)
        if not isinstance(snapshot, dict):
            raise ValueError("invalid snapshot")
        status = snapshot.get("status")
        if not isinstance(status, dict) or snapshot.get("status_ok") is not True:
            raise ValueError("controller status unavailable")
        stamp = _time(snapshot.get("generated_at"))
        project_map = status.get("projects")
        if stamp is None or not isinstance(project_map, dict) or len(project_map) > 128:
            raise ValueError("invalid snapshot metadata")
        if projects is None:
            selected = sorted(
                p for p in project_map if isinstance(p, str) and _PROJECT.fullmatch(p)
            )
        else:
            selected = sorted(
                set(p for p in projects if isinstance(p, str) and _PROJECT.fullmatch(p))
            )
            if len(selected) > 128:
                raise ValueError("too many projects")
        enabled = status.get("backup_enabled")
        if type(enabled) is not bool:
            enabled = None
        roots = status.get("backup_schedule_observations")
        workers = snapshot.get("backup_observations")
        roots = roots if isinstance(roots, dict) else {}
        workers = workers if isinstance(workers, dict) else {}
        records = []
        for project in selected:
            root = roots.get(project)
            worker = workers.get(project)
            root = root if isinstance(root, dict) else {}
            worker = worker if isinstance(worker, dict) else {}
            root_state = root.get("state")
            if root_state not in (
                "missing",
                "invalid",
                "unavailable",
                "admitted",
                "capturing",
                "captured",
                "exported",
                "failed",
            ):
                root_state = "unknown"
            worker_state = worker.get("state")
            if worker_state not in ("unknown", "missing", "failed", "reported"):
                worker_state = "unknown"
            error = worker.get("job_error")
            if not isinstance(error, str) or not _ERROR.fullmatch(error):
                error = None
            job_state = worker.get("job_state")
            if job_state not in ("queued", "running", "succeeded", "failed"):
                job_state = None
            capture_at = _time(root.get("capture_created_at"))
            interval = _time(root.get("interval_s"))
            capture_freshness = "unknown"
            if (
                capture_at is not None
                and interval is not None
                and interval > 0
                and root_state in ("captured", "exported")
                and root.get("provenance") == "executor_schedule"
                and _digest(root.get("capture_id")) is not None
                and _digest(root.get("config_revision")) is not None
                and root.get("config_revision") == status.get("config_revision")
                and now - capture_at >= 0
            ):
                capture_freshness = "stale" if now - capture_at > 2 * interval else "fresh"
            records.append(
                {
                    "project": project,
                    "registered": project in project_map,
                    "capture_state": root_state,
                    "capture_id": _digest(root.get("capture_id")),
                    "capture_created_at": capture_at,
                    "capture_freshness": capture_freshness,
                    "config_revision": _digest(root.get("config_revision")),
                    "worker_state": worker_state,
                    "job_state": job_state,
                    "job_error": error,
                    "repository_id": _digest(worker.get("repository_id")),
                    "snapshot_id": _digest(worker.get("snapshot_id")),
                    "uploaded_at": _time(worker.get("uploaded_at")),
                    "integrity_checked_at": _time(worker.get("integrity_checked_at")),
                    "restored_bytes_at": _time(worker.get("restored_bytes_at")),
                    "application_drill_at": None,
                    "root_provenance": "executor_schedule"
                    if root.get("provenance") == "executor_schedule"
                    else None,
                    "worker_provenance": "worker_reported"
                    if worker.get("worker_provenance") == "worker_reported"
                    else None,
                }
            )
        return {
            "enabled": enabled,
            "freshness": "fresh" if 0 <= now - stamp <= 120 else "stale",
            "generated_at": stamp,
            "projects": records,
        }
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return {"enabled": None, "freshness": "unknown", "generated_at": None, "projects": []}
