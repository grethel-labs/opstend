"""Automatic rollback of a verified-healthy update that became durably unhealthy (decision 15).

The patch controller may ask the executor's existing `rollback` action to return an applied
update to its previous image, and only under these conditions, all re-derived here from the
root-owned registry and the durable journal (the controller's claim is never trusted):

* the `patch` profile is on and the kill switch is off (the latter is enforced by the
  dispatcher for every non-operator caller);
* the update declared migration `none` and recovered image-only: a migrating update keeps
  escalating to the operator, and the controller can never acknowledge a data restore;
* it is `applied` and was verified healthy, and `now - applied_at` is within the contract's
  `rollback_window_s` (default 30 minutes; 0 disables);
* the executor itself observes a definite unhealthy answer right now (an unknown probe never
  triggers a rollback);
* it was not attempted before: the journal marker `auto_rollback` is written when the
  rollback starts and is never cleared, so one attempt happens per update, success or not;
* the per-project budget has room.

The rollback itself is the unchanged operator machinery. Refusals leave the update applied.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..core.config import UpdatePolicy
from .protocol import ExecutorError

if TYPE_CHECKING:
    from .server import Executor

BUDGET_PER_HOUR = 1


def require(
    ex: Executor,
    registry: dict[str, Any],
    spec: dict[str, Any],
    contract: UpdatePolicy,
    row: dict[str, Any],
    project: str,
    now: float,
    *,
    acknowledge_data_restore: bool,
) -> dict[str, Any]:
    """Refuse unless an automatic rollback is justified; returns the journal marker."""
    from .server import probe_health

    journal = row["journal"]
    if registry.get("automation_profile") != "patch":
        raise ExecutorError("policy_denied", "automatic rollback needs the patch profile")
    if acknowledge_data_restore or journal.get("migration") != "none":
        raise ExecutorError(
            "policy_denied", "an update with a data migration is rolled back by an operator only"
        )
    if journal.get("recovery_mode") != "image_only" or row["state"] != "applied":
        raise ExecutorError("policy_denied", "only an applied image-only update qualifies")
    if "auto_rollback" in journal:
        raise ExecutorError("replay", "an automatic rollback was already attempted")
    window = contract.effective_rollback_window_s
    applied_at = journal.get("applied_at")
    if window <= 0 or type(applied_at) not in (int, float):
        raise ExecutorError("policy_denied", "automatic rollback is not enabled for this update")
    if not 0 <= now - applied_at <= window:
        raise ExecutorError("policy_denied", "the automatic rollback window has passed")
    health = probe_health(ex.host, spec)
    if health.get("ok") is not False or health.get("state") == "unknown":
        raise ExecutorError("policy_denied", "the workload is not observed as unhealthy")
    ex.spend_budget(project, "auto_rollback", BUDGET_PER_HOUR)
    return {"at": now, "reason": "durably_unhealthy", "health": str(health.get("state"))[:40]}
