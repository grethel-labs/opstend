"""Announced maintenance drills (L11): registered actions `drill_announce`, `drill_run`,
`drill_release` and `drill_status`.

A drill runs only when ALL hold, each checked by the executor at execution time:
the kill switch is off; the drill is configured in the root registry
(`maintenance.drills`, which this release never renders: the config feature
`maintenance.drills` is unavailable); the clock is inside the regular window and the
drill's budget fits before it ends; that window was announced early enough; the
service is not suspended; resources are healthy; for restore a verified capture
exists. A drill is recorded once per (drill, service, window).

- `resources`: the registered resource check, recorded.
- `restart`: restart one managed project (same locks and contract as a health
  restart), measure the time until its registered probe reports healthy. A service
  that is not healthy by the deadline (budget or window end) fails the drill and is
  suspended; the controller's normal repair chain still applies to it.
- `restore`: materialize the newest verified capture in a private workspace and
  verify it; production data is never read for writing or replaced.

No drill reboots the host: there is no reboot code path here at all. Application
groups are not drilled yet (they go through the L02 group actions, still unwired).
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..core.backups import BackupError, FilesystemCapture, load_capture
from ..core.drills import (
    BUDGET_S,
    DRILLS,
    HOST,
    MAX_ANNOUNCE_LEAD_S,
    MIN_ANNOUNCE_LEAD_S,
    DrillLedger,
)
from ..core.filebackups import materialize_tree
from ..core.maintenance import admit, regular_window
from ..core.maintenance_work import resource_check, window_dict
from .protocol import ExecutorError

if TYPE_CHECKING:
    from .server import Executor

PROJECT_ID = r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$"
POLL_S = 2.0
FREE_MARGIN = 256 * 1024 * 1024


def _now() -> float:  # replaced by tests
    return time.time()


def _monotonic() -> float:  # replaced by tests
    return time.monotonic()


def _sleep(seconds: float) -> None:  # replaced by tests
    time.sleep(seconds)


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NoParams(_Params):
    pass


class DrillRunParams(_Params):
    drill: Literal["resources", "restart", "restore"]
    project_id: str | None = Field(None, pattern=PROJECT_ID)

    @model_validator(mode="after")
    def _scope(self) -> DrillRunParams:
        if (self.drill == "resources") != (self.project_id is None):
            raise ValueError("restart and restore drills name a project; resources none")
        return self


class DrillReleaseParams(_Params):
    project_id: str = Field(pattern=PROJECT_ID)


def _ledger(ex: Executor) -> DrillLedger:
    return DrillLedger(os.path.join(os.path.dirname(ex._db_path), "drills.db"))


def _policy(registry: dict[str, Any]) -> dict[str, Any]:
    policy = registry.get("maintenance")
    if not isinstance(policy, dict) or not policy.get("drills"):
        raise ExecutorError("policy_denied", "no maintenance drills are configured")
    return policy


def _audit(ex: Executor, outcome: str, **fields: Any) -> None:
    ex.audit.append("maintenance_drill", outcome=outcome, **fields)


# ---- announcement ---------------------------------------------------------------------


def drill_announce(ex: Executor, _params: NoParams, role: str, registry: dict[str, Any]):
    """Record the announcement of the next regular window's drills (idempotent)."""
    policy = _policy(registry)
    now = _now()
    moment = datetime.fromtimestamp(now, UTC)
    try:
        window = regular_window(policy["weekly_window"], moment)
    except (KeyError, TypeError, ValueError):
        raise ExecutorError("policy_denied", "maintenance policy is not valid") from None
    if window.contains(moment):
        return {"announced": False, "reason": "window_already_open", "window": window_dict(window)}
    lead = window.start.timestamp() - now
    if lead > MAX_ANNOUNCE_LEAD_S:
        return {"announced": False, "reason": "too_early", "window": window_dict(window)}
    if lead < MIN_ANNOUNCE_LEAD_S:
        return {"announced": False, "reason": "too_late", "window": window_dict(window)}
    drills = [d for d in DRILLS if d in policy["drills"]]
    created = _ledger(ex).announce(window.start.isoformat(), drills, now)
    if created:
        _audit(
            ex,
            "announced",
            drills=drills,
            window_start=window.start.isoformat(),
            window_end=window.end.isoformat(),
            allow_reboot=False,
        )
    return {
        "announced": True,
        "created": created,
        "drills": drills,
        "window": window_dict(window),
    }


# ---- running ----------------------------------------------------------------------------


def _deferred(reason: str, **extra: Any) -> dict[str, Any]:
    return {"state": "deferred", "reason": reason, **extra}


def _newest_capture(ex: Executor, project: str, server: str):
    spool = Path(ex._db_path).parent / "captures" / project
    try:
        entries = sorted(spool.iterdir())[:16]
    except OSError:
        return None
    best = None
    for entry in entries:
        try:
            manifest = load_capture(entry)
        except (BackupError, OSError, ValueError):
            continue
        if (
            isinstance(manifest, FilesystemCapture)
            and manifest.binding.project == project
            and manifest.binding.server == server
            and (best is None or manifest.completed_at > best[1].completed_at)
        ):
            best = (entry, manifest)
    return best


def _fix_applied_since(ex: Executor, project: str, since: float) -> bool:
    """A verified update applied after the failure counts as a fix."""
    ledger = getattr(ex, "update_ledger", None)
    if ledger is None:
        return False
    try:
        return any(
            row["state"] == "applied" and row["updated_at"] > since
            for row in ledger.summaries(project, 20)
        )
    except Exception:  # noqa: BLE001 - an unreadable ledger never releases a suspension
        return False


def drill_run(ex: Executor, params: DrillRunParams, role: str, registry: dict[str, Any]):
    from .server import load_registry

    if ex.host.kill_switch():
        raise ExecutorError("kill_switch", "maintenance drills are stopped")
    drill, project = params.drill, params.project_id
    with ex.target_lock("maintenance-drills"):
        registry = load_registry(ex.registry_path)
        policy = _policy(registry)
        if drill not in policy["drills"]:
            raise ExecutorError("policy_denied", "this drill is not configured")
        now = _now()
        try:
            admission = admit(
                policy["weekly_window"],
                datetime.fromtimestamp(now, UTC),
                work_seconds=BUDGET_S[drill],
                kind="routine",
                allow_reboot=False,
            )
        except (KeyError, TypeError, ValueError):
            raise ExecutorError("policy_denied", "maintenance policy is not valid") from None
        if not admission.allowed or admission.window is None:
            return _deferred(
                admission.reason,
                retry_at=admission.retry_at.isoformat() if admission.retry_at else None,
            )
        window = admission.window
        start_key = window.start.isoformat()
        ledger = _ledger(ex)
        for stale in ledger.recover(now):
            _audit(ex, "failed", cause="interrupted", **stale)
        announced = ledger.announcement(start_key)
        if (
            announced is None
            or drill not in announced["drills"]
            or announced["announced_at"] > window.start.timestamp() - MIN_ANNOUNCE_LEAD_S
        ):
            return _deferred("not_announced", window=window_dict(window))
        spec: dict[str, Any] = {}
        if project is not None:
            if project in registry.get("applications", {}):
                raise ExecutorError("policy_denied", "application drills are not available")
            spec = registry["projects"].get(project)
            if spec is None:
                raise ExecutorError("policy_denied", "project is not registered")
            if not spec["deploy"]:
                raise ExecutorError("policy_denied", "project is configured as stopped")
            if drill == "restart" and not spec["allow_restart"]:
                raise ExecutorError("policy_denied", "no maintenance contract permits restarts")
            held = ledger.suspension(project)
            if held is not None and _fix_applied_since(ex, project, held["since"]):
                ledger.release(project)
                _audit(ex, "released", service=project, cause="verified_fix")
                held = None
            if held is not None:
                return _deferred("suspended", since=held["since"], cause=held["cause"])
        # Resource and backup state first: an unhealthy host defers, it does not drill.
        try:
            check = resource_check(
                ex.host.resources(), ex.host.load_average(), registry["reserved_memory_mb"]
            )
        except Exception:  # noqa: BLE001 - unknown is never success
            check = None
        if drill != "resources" and (check is None or not check["healthy"]):
            return _deferred("resources_unhealthy")
        capture = None
        if drill == "restore":
            capture = _newest_capture(ex, project, registry["server_name"])
            if capture is None:
                return _deferred("no_verified_capture")
        elif drill == "restart" and spec.get("has_data") and registry["backup"].get("enabled"):
            newest = _newest_capture(ex, project, registry["server_name"])
            interval = registry["backup"].get("interval_s", 86400)
            if newest is None or now - newest[1].completed_at > 2 * interval:
                return _deferred("backup_not_fresh")
        service = project or HOST
        run_id = ledger.begin(drill, service, start_key, now)
        if run_id is None:
            return _deferred("already_ran_in_window", window=window_dict(window))
        common = {
            "drill": drill,
            "service": service,
            "run_id": run_id,
            "window_start": start_key,
            "window_end": window.end.isoformat(),
        }
        _audit(ex, "started", **common)
        began = _monotonic()
        deadline = began + min(BUDGET_S[drill], window.end.timestamp() - now)
        ok, cause, result = False, None, None
        try:
            if drill == "resources":
                ok, cause, result = (
                    (True, None, check)
                    if check is not None and check["healthy"]
                    else (
                        False,
                        "resources_unhealthy" if check else "measurement_unavailable",
                        check,
                    )
                )
            elif drill == "restart":
                ok, cause, result = _restart(ex, registry, project, spec, deadline, began)
            else:
                ok, cause, result = _restore(ex, capture, deadline, began)
        except ExecutorError as exc:
            cause = f"{exc.error_class}"
        except Exception as exc:  # noqa: BLE001 - a failed drill is recorded, not raised
            cause = f"drill failed: {type(exc).__name__}"
        elapsed = round(_monotonic() - began, 3)
        ledger.finish(run_id, ok=ok, now=_now(), elapsed_s=elapsed, cause=cause, result=result)
        if not ok and drill == "restart" and cause != "target_busy":
            ledger.suspend(project, run_id, cause or "failed", _now())
        _audit(
            ex,
            "completed" if ok else "failed",
            elapsed_s=elapsed,
            **common,
            **({"cause": cause} if cause else {}),
            **({"suspended": True} if not ok and drill == "restart" else {}),
        )
        return {
            "state": "completed" if ok else "failed",
            "run_id": run_id,
            "drill": drill,
            "service": service,
            "elapsed_s": elapsed,
            "cause": cause,
            "result": result,
            "window": window_dict(window),
        }


def _restart(ex, registry, project, spec, deadline, began):
    from .server import probe_health

    with ex.target_lock("deployment-execution"):
        if ex.deployment_fence() is not None:
            raise ExecutorError("target_busy", "deployment recovery is pending")
        with ex.target_lock(f"project-{project}"):
            if ex.backup_pause(project) is not None:
                raise ExecutorError("unavailable", "backup pause recovery is pending")
            ex.ensure_group_restart_allowed(registry, spec)
            restarted, detail = ex.host.restart_user_unit(spec["user"], spec["unit"])
            if not restarted:
                return False, "restart_failed", {"detail": (detail or "")[:200]}
            # The restart is complete; now only observe, bounded by budget and window.
            while True:
                health = probe_health(ex.host, spec)
                if health.get("state") == "healthy":
                    return (
                        True,
                        None,
                        {"health": "healthy", "recovery_s": round(_monotonic() - began, 3)},
                    )
                if _monotonic() + POLL_S > deadline:
                    window_over = _monotonic() >= deadline
                    return (
                        False,
                        "overrun" if window_over else "not_healthy_in_time",
                        {"health": health.get("state", "unknown")},
                    )
                _sleep(POLL_S)


def _restore(ex, capture, deadline, began):
    directory, manifest = capture
    work_root = Path(ex._db_path).parent / "drill-work"
    work_root.mkdir(mode=0o700, exist_ok=True)
    if shutil.disk_usage(work_root).free < manifest.data_bytes + FREE_MARGIN:
        return False, "insufficient_space", None
    work = Path(tempfile.mkdtemp(prefix=".drill-", dir=work_root))
    try:
        materialize_tree(directory / manifest.filename, manifest, work)
    except BackupError as exc:
        return False, f"restore_failed:{exc.error_class}", None
    finally:
        shutil.rmtree(work, ignore_errors=True)
    result = {"capture": directory.name, "data_bytes": manifest.data_bytes, "isolated": True}
    if _monotonic() > deadline:
        return False, "overrun", result
    return True, None, result


# ---- release and status ------------------------------------------------------------------


def drill_release(ex: Executor, params: DrillReleaseParams, role: str, registry: dict[str, Any]):
    """Explicit reconciliation: an operator resumes drills for one service."""
    released = _ledger(ex).release(params.project_id)
    if released:
        _audit(ex, "released", service=params.project_id, cause="operator")
    return {"project_id": params.project_id, "released": released}


def drill_status(ex: Executor, _params: NoParams, _role: str, registry: dict[str, Any]):
    path = os.path.join(os.path.dirname(ex._db_path), "drills.db")
    if not os.path.exists(path):
        return {"runs": [], "suspensions": []}
    ledger = DrillLedger(path)
    return {"runs": ledger.runs(10), "suspensions": ledger.suspensions()}


def register(actions: dict, action_cls) -> None:
    both = frozenset({"operator", "controller"})
    actions["drill_announce"] = action_cls(NoParams, both, True, drill_announce)
    actions["drill_run"] = action_cls(DrillRunParams, both, True, drill_run)
    actions["drill_release"] = action_cls(
        DrillReleaseParams, frozenset({"operator"}), True, drill_release
    )
    actions["drill_status"] = action_cls(
        NoParams, frozenset({"operator", "controller", "api"}), False, drill_status
    )
