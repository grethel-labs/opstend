"""Deterministic selection for the `patch` automation profile (L06).

The controller may apply an already validated, independently approved image update and
nothing else: it cannot validate evidence, choose a version, change a window, roll back
or restore data. This module only decides *whether to ask* the executor to apply one
approval now; the executor rechecks evidence, window, backup age, revision, kill switch,
lock and budget itself and stays the authority. No model output is read here.

Inputs are the verified `platform_status` snapshot and the executor's `update_status`
summaries. Missing or unrecognised data never selects an update.
"""

from __future__ import annotations

from typing import Any

from .config import DEFAULT_MIN_HEALTHY_S

APPLY_ACTION = "apply_verified_image"


def global_block(status: dict[str, Any]) -> str | None:
    """Why no automatic update may be requested at all right now (None: it may)."""
    if status.get("automation_profile") != "patch":
        return "automation profile is not patch"
    if status.get("kill_switch") is not False:
        return "kill switch is active or unknown"
    if status.get("deployment_recovery") != "clear":
        return "deployment state must be resolved first"
    window = status.get("maintenance")
    if not isinstance(window, dict) or window.get("configured") is not True:
        return "no maintenance window is configured"
    if window.get("state") != "in_window":
        return "outside the maintenance window"
    return None


def project_block(status: dict[str, Any], project: str) -> str | None:
    entry = status.get("projects", {}).get(project)
    if not isinstance(entry, dict) or entry.get("deploy") is not True:
        return "project is not deployed"
    if entry.get("unit", {}).get("active") != "active":
        return "workload is not active"
    health = entry.get("health") or {}
    if health.get("ok") is not True:
        return "workload health is not verified"
    if (entry.get("hardening") or {}).get("violations") != []:
        return "isolation is not verified"
    if any(p.get("project_id") == project for p in status.get("backup_recovery", [])):
        return "backup pause recovery is pending"
    return None


def candidates(approvals: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
    """Validated, unexpired approvals with a complete candidate, soonest expiry first."""
    out = []
    for row in approvals:
        candidate = row.get("candidate")
        if row.get("state") != "validated" or not isinstance(candidate, dict):
            continue
        digest, expires = candidate.get("digest"), candidate.get("expires_at")
        if (
            not isinstance(row.get("approval_id"), str)
            or not isinstance(digest, str)
            or type(expires) not in (int, float)
            or expires <= now
        ):
            continue
        out.append({"approval_id": row["approval_id"], "digest": digest, "expires_at": expires})
    return sorted(out, key=lambda c: (c["expires_at"], c["approval_id"]))


def select_update(
    status: dict[str, Any],
    approvals: dict[str, list[dict[str, Any]]],
    now: float,
    healthy_for: dict[str, float] | None = None,
    min_healthy_s: dict[str, int] | None = None,
) -> tuple[dict[str, str] | None, dict[str, str]]:
    """At most one `{project_id, approval_id, digest}` per cycle, plus skip reasons.

    `healthy_for` (seconds of continuous observed health per project) and `min_healthy_s`
    (the contract's minimum, default 30 minutes) gate each project when given (decision 17);
    the controller always passes them."""
    skipped: dict[str, str] = {}
    blocked = global_block(status)
    if blocked:
        return None, {"*": blocked}
    for project in sorted(approvals):
        reason = project_block(status, project)
        if reason:
            skipped[project] = reason
            continue
        if healthy_for is not None:
            needed = (min_healthy_s or {}).get(project, DEFAULT_MIN_HEALTHY_S)
            have = healthy_for.get(project, 0.0)
            if have < needed:
                skipped[project] = (
                    f"healthy for {int(have)} s of the {needed} s required before an update"
                )
                continue
        found = candidates(approvals[project], now)
        if not found:
            skipped[project] = "no validated approval"
            continue
        chosen = found[0]
        return (
            {
                "project_id": project,
                "approval_id": chosen["approval_id"],
                "digest": chosen["digest"],
            },
            skipped,
        )
    return None, skipped
