"""Registered maintenance work and read-only maintenance reporting (L03).

Maintenance work is addressed by a fixed ID from `WORK`; no caller supplies a
command, path or duration. The only work today is the read-only resource check.
Pure functions: the executor passes the clock, the host measurements and the
stored runs, so every rule is testable without a host.

Used by the executor only. The controller never imports this module: it reads
the summary the executor puts into `platform_status`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .maintenance import WorkKind, regular_window

WORK_IDS = ("resource_check",)
DISK_FREE_MIN_FRACTION = 0.10  # same limit the controller applies to disk
LOAD_PER_CPU_MAX = 2.0
RECENT_RUNS = 10


@dataclass(frozen=True)
class WorkSpec:
    kind: WorkKind
    work_seconds: int


WORK: dict[str, WorkSpec] = {"resource_check": WorkSpec("routine", 60)}


def resource_check(
    resources: dict[str, Any], load: dict[str, Any], reserved_memory_mb: int
) -> dict[str, Any]:
    """Compare measurements against totals. Missing values raise: unknown is not success."""
    memory_total = _positive(resources.get("memory_total_mb"))
    memory_free = _non_negative(resources.get("memory_available_mb"))
    disk_total = _positive(resources.get("disk_total_mb"))
    disk_free = _non_negative(resources.get("disk_free_mb"))
    cpus = _positive(load.get("cpus"))
    load5 = _non_negative(load.get("load5"))
    memory_min = max(reserved_memory_mb // 4, 1)
    checks = {
        "memory": memory_free >= memory_min,
        "disk": disk_free / disk_total >= DISK_FREE_MIN_FRACTION,
        "load": load5 <= cpus * LOAD_PER_CPU_MAX,
    }
    return {
        "healthy": all(checks.values()),
        "checks": checks,
        "memory_available_mb": memory_free,
        "memory_total_mb": memory_total,
        "disk_free_mb": disk_free,
        "disk_total_mb": disk_total,
        "load5": round(load5, 2),
        "cpus": int(cpus),
    }


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError("measurement is not available")
    return float(value)


def _positive(value: Any) -> float:
    number = _number(value)
    if number <= 0:
        raise ValueError("measurement is not available")
    return number


def _non_negative(value: Any) -> float:
    number = _number(value)
    if number < 0:
        raise ValueError("measurement is not available")
    return number


def policy_summary(
    policy: dict[str, Any], now: float, runs: list[dict[str, Any]] | None
) -> dict[str, Any]:
    """Read-only view of the rendered policy: current and next regular window, recent runs."""
    out: dict[str, Any] = {
        "configured": True,
        "weekly_window": policy.get("weekly_window"),
        "allow_reboot": policy.get("allow_reboot") is True,
        "emergency": policy.get("emergency", {}),
        "drills": policy.get("drills", []),
        "recent_runs": runs_summary(runs or []),
    }
    try:
        moment = datetime.fromtimestamp(now, UTC)
        window = regular_window(policy["weekly_window"], moment)
        current = window if window.contains(moment) else None
        upcoming = regular_window(policy["weekly_window"], window.end) if current else window
    except (KeyError, TypeError, ValueError):
        # A damaged policy is reported, never treated as an open window.
        return {**out, "state": "unknown", "error": "maintenance policy is not valid"}
    return {
        **out,
        "state": "in_window" if current else "outside_window",
        "current_window": window_dict(current),
        "next_window": window_dict(upcoming),
    }


def window_dict(window) -> dict[str, str] | None:
    if window is None:
        return None
    return {"start": window.start.isoformat(), "end": window.end.isoformat()}


def runs_summary(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for job in jobs[:RECENT_RUNS]:
        payload = job.get("payload") or {}
        out.append(
            {
                "id": job.get("id"),
                "work": payload.get("work"),
                "state": job.get("state"),
                "window_start": payload.get("window_start"),
                "window_end": payload.get("window_end"),
                "updated_at": job.get("updated_at"),
                "error": job.get("error"),
            }
        )
    return out
