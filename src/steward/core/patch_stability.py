"""Stability gate and automatic-rollback selection for the `patch` profile (decisions 15, 17).

Two deterministic, model-free rules for the patch controller path:

* **Stability (decision 17).** A service is offered an update only after it has been
  continuously healthy for the contract's `min_healthy_s` (default 30 minutes). The
  controller derives that from its own health observations with a small durable tracker:
  any unhealthy, unknown or missing observation, or a gap in observation longer than
  `GAP_S` (controller down), restarts the clock. The tracker only ever delays an update;
  a lost or damaged file means "not yet stable".
* **Automatic rollback candidate (decision 15).** An update with migration `none` that was
  verified healthy and then fails its health checks durably within `rollback_window_s`
  after apply is offered to the executor's `rollback` action once. The executor re-derives
  every condition (see `executor/update_auto_rollback.py`); this module only selects.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .config import DEFAULT_MIN_HEALTHY_S, DEFAULT_ROLLBACK_WINDOW_S

PLANNED_S = 180  # a restart by an audited backup pause/capture stays neutral this long
PAUSE_MAX_S = 300  # an unresolved pause older than this (or with an error) is not planned
GAP_S = 300  # observations further apart than this are not "continuous"
SAVE_EVERY_S = 60
DURABLE_FACTOR = 2  # failed checks in a row, as a multiple of the project's retries


def observed_healthy(entry: Any) -> bool:
    """A complete positive observation: deployed, active, healthy and isolated."""
    if not isinstance(entry, dict) or entry.get("deploy") is not True:
        return False
    if (entry.get("unit") or {}).get("active") != "active":
        return False
    if (entry.get("health") or {}).get("ok") is not True:
        return False
    return (entry.get("hardening") or {}).get("violations") == []


def planned_projects(status: dict[str, Any]) -> set[str]:
    """Projects currently in, or just out of, an audited executor backup pause/capture.

    Signals come only from the executor status: the durable pause intent (without a
    recorded recovery error and not older than `PAUSE_MAX_S`) and the audited
    `backup_resume` record (`backup_planned_restarts`) no older than `PLANNED_S`."""
    now = status.get("checked_at")
    if type(now) not in (int, float):
        return set()
    out: set[str] = set()
    for pause in status.get("backup_recovery") or []:
        prepared = pause.get("prepared_at") if isinstance(pause, dict) else None
        if (
            isinstance(pause, dict)
            and isinstance(pause.get("project_id"), str)
            and not pause.get("error_class")
            and type(prepared) in (int, float)
            and 0 <= now - prepared <= PAUSE_MAX_S
        ):
            out.add(pause["project_id"])
    resumed = status.get("backup_planned_restarts")
    for project, ts in (resumed if isinstance(resumed, dict) else {}).items():
        if isinstance(project, str) and type(ts) in (int, float) and 0 <= now - ts <= PLANNED_S:
            out.add(project)
    return out


class StabilityTracker:
    """`{project: {since, last}}` persisted atomically; unreadable state starts empty."""

    def __init__(self, path: Path):
        self.path = path
        self._saved_at = 0.0
        self._state: dict[str, dict[str, float]] = self._load()

    def _load(self) -> dict[str, dict[str, float]]:
        try:
            raw = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}
        out: dict[str, dict[str, float]] = {}
        if isinstance(raw, dict):
            for project, entry in raw.items():
                if (
                    isinstance(project, str)
                    and isinstance(entry, dict)
                    and type(entry.get("since")) in (int, float)
                    and type(entry.get("last")) in (int, float)
                ):
                    out[project] = {"since": float(entry["since"]), "last": float(entry["last"])}
        return out

    def observe(self, status: dict[str, Any], now: float) -> None:
        changed = False
        projects = status.get("projects")
        seen = projects if isinstance(projects, dict) else {}
        planned = planned_projects(status)
        for project in list(self._state):
            if project in seen and project in planned and not observed_healthy(seen[project]):
                # A planned, audited backup pause/capture restart: neutral. The clock
                # neither resets nor counts the window as an outage.
                known = self._state[project]
                if 0 <= now - known["last"] <= GAP_S:
                    known["last"] = now
                    continue
            if project not in seen or not observed_healthy(seen[project]):
                del self._state[project]
                changed = True
        for project, entry in seen.items():
            if not observed_healthy(entry):
                continue
            known = self._state.get(project)
            if known is None or not 0 <= now - known["last"] <= GAP_S:
                self._state[project] = {"since": now, "last": now}
                changed = True
            else:
                known["last"] = now
        if changed or now - self._saved_at >= SAVE_EVERY_S:
            self._save(now)

    def healthy_for(self, project: str, now: float) -> float:
        known = self._state.get(project)
        if known is None or not 0 <= now - known["last"] <= GAP_S:
            return 0.0
        return max(0.0, now - known["since"])

    def reset(self, project: str, now: float) -> None:
        if self._state.pop(project, None) is not None:
            self._save(now)

    def _save(self, now: float) -> None:
        self._saved_at = now
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self._state, handle)
            os.replace(tmp, self.path)
        except OSError:
            pass  # in-memory state still gates; a lost file only delays updates


def min_healthy_s(update_status: dict[str, Any]) -> int:
    value = update_status.get("min_healthy_s")
    return value if type(value) is int and value >= 0 else DEFAULT_MIN_HEALTHY_S


def rollback_block(status: dict[str, Any]) -> str | None:
    """Why no automatic rollback may be requested right now (None: it may)."""
    if status.get("automation_profile") != "patch":
        return "automation profile is not patch"
    if status.get("kill_switch") is not False:
        return "kill switch is active or unknown"
    if status.get("deployment_recovery") != "clear":
        return "deployment state must be resolved first"
    return None


def durable_suspects(status: dict[str, Any], failures: dict[str, int]) -> list[str]:
    """Projects whose health checks failed long enough to call the failure durable."""
    out = []
    for project, entry in sorted((status.get("projects") or {}).items()):
        if not isinstance(entry, dict) or entry.get("deploy") is not True:
            continue
        if (entry.get("unit") or {}).get("active") != "active":
            continue
        needed = DURABLE_FACTOR * int(entry.get("health_retries", 3))
        if failures.get(project, 0) >= needed:
            out.append(project)
    return out


def _applied_stamp(row: dict[str, Any]) -> float | None:
    """When this update was applied: the journal's `applied_at`, else `updated_at` for the
    states that only exist after an apply attempt reached the workload."""
    applied_at = row.get("applied_at")
    if type(applied_at) in (int, float):
        return float(applied_at)
    updated = row.get("updated_at")
    if row.get("state") in ("restore_required", "rollback_failed") and type(updated) in (
        int,
        float,
    ):
        return float(updated)
    return None


def rollback_selection(
    result: dict[str, Any], project: str, now: float
) -> tuple[dict[str, Any] | None, str | None]:
    """`(candidate, None)` or `(None, reason)`.

    Only the newest applied update of the project may be rolled back automatically, and
    only when that very update is eligible (state applied, migration `none`, inside its
    window, never auto-rolled-back). An older eligible row never stands in for a newer one
    that is not (for example a newer `restore_required` update)."""
    window = result.get("rollback_window_s")
    if type(window) is not int or window <= 0:
        window = DEFAULT_ROLLBACK_WINDOW_S if window is None else 0
    if window <= 0:
        return None, "automatic rollback is disabled for this project"
    newest: dict[str, Any] | None = None
    newest_at = -1.0
    for row in result.get("approvals", []):
        stamp = _applied_stamp(row) if isinstance(row, dict) else None
        if stamp is not None and stamp > newest_at:
            newest, newest_at = row, stamp
    if newest is None:
        return None, "no applied update"
    applied_at, image = newest.get("applied_at"), newest.get("new_image")
    if newest.get("state") != "applied":
        return None, f"newest update is {newest.get('state')}, not applied"
    if newest.get("migration") != "none":
        return None, "newest update has a data migration"
    if "auto_rollback" in newest:
        return None, "newest update was already rolled back automatically"
    if type(applied_at) not in (int, float) or not 0 <= now - applied_at <= window:
        return None, "newest update is outside the rollback window"
    if (
        not isinstance(newest.get("approval_id"), str)
        or not isinstance(image, str)
        or "@sha256:" not in image
    ):
        return None, "newest update has no verifiable image digest"
    candidate = {
        "project_id": project,
        "approval_id": newest["approval_id"],
        "digest": image.rsplit("@", 1)[1],
        "applied_at": applied_at,
    }
    return candidate, None


def rollback_candidate(result: dict[str, Any], project: str, now: float) -> dict[str, Any] | None:
    """The newest applied update of the project when it is eligible for rollback, else None."""
    return rollback_selection(result, project, now)[0]
