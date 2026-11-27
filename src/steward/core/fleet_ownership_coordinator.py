"""Coordinate a paused, locally confirmed handoff of one adopted native schedule."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pydantic import TypeAdapter

from .fleet_adoption import adoption_for_instance, view_adoption
from .fleet_adoption_models import Calendar
from .fleet_enrollment import power_target_grant
from .fleet_identity import FleetIdentityConflict, FleetIdentityRegistry, _timestamp
from .fleet_ownership import (
    Owner,
    OwnershipClaim,
    OwnershipEpoch,
    OwnershipExchange,
    OwnershipPlan,
    OwnershipReceipt,
    OwnershipReply,
    OwnershipStatus,
)
from .fleet_policy import FleetTarget, PolicyName, RevisionId, _target_record
from .fleet_policy_apply import FleetPolicyActor, FleetPolicyDenied, FleetPolicyNotFound, _Access
from .fleet_power import CLAIM_MS, CommandKey
from .fleet_power_commands import _power_context, _scope
from .pve_power import JobId

_ID = TypeAdapter(JobId)
_DIGEST = TypeAdapter(RevisionId)
_KEY = TypeAdapter(CommandKey)
_PROFILE = TypeAdapter(PolicyName)
_OWNER = TypeAdapter(Owner)
_EPOCH = TypeAdapter(OwnershipEpoch)
_CALENDAR = TypeAdapter(Calendar)
_CLAIM = timedelta(milliseconds=CLAIM_MS)


class FleetOwnershipConflict(ValueError):
    """The selected ownership transition cannot advance."""


def _slot(db: sqlite3.Connection, instance_id: str, vmid: int) -> sqlite3.Row | None:
    return db.execute(
        "SELECT * FROM fleet_guest_ownership WHERE instance_id = ? AND vmid = ?",
        (instance_id, vmid),
    ).fetchone()


def _plan(row: sqlite3.Row) -> OwnershipPlan:
    plan = OwnershipPlan.model_validate_json(row["plan"])
    if (plan.transition_id, plan.digest) != (row["id"], row["digest"]):
        raise FleetOwnershipConflict("stored ownership plan has changed")
    return plan


def _event(
    db: sqlite3.Connection,
    plan: OwnershipPlan,
    state: str,
    now: datetime,
    evidence: str | None = None,
) -> None:
    status = OwnershipStatus.from_plan(plan, "pausing" if state == "claim" else state)
    db.execute(
        """INSERT INTO fleet_ownership_history
           (handoff_id, state, owner, epoch, occurred_at, evidence) VALUES (?, ?, ?, ?, ?, ?)""",
        (plan.transition_id, state, status.owner, status.epoch, _timestamp(now), evidence),
    )


def _status(db: sqlite3.Connection, plan: OwnershipPlan) -> OwnershipStatus:
    row = db.execute(
        """SELECT state FROM fleet_ownership_history
           WHERE handoff_id = ? AND state != 'claim' ORDER BY id DESC LIMIT 1""",
        (plan.transition_id,),
    ).fetchone()
    return OwnershipStatus.from_plan(plan, row["state"])


def _adopted_schedule(
    db: sqlite3.Connection,
    guest: sqlite3.Row,
    target: FleetTarget,
    schedule_ref: str,
    now: datetime,
) -> str:
    try:
        row = adoption_for_instance(db, guest["instance_id"])
    except FleetIdentityConflict:
        raise FleetOwnershipConflict("ownership requires a fresh standalone adoption") from None
    adopted = view_adoption(db, row, history=False, now=now)
    current = adopted.current
    if (
        current is None
        or row["route_id"] != guest["route_id"]
        or current.observation_id != guest["observation_id"]
        or current.node != guest["node"]
        or (adopted.local_profile is not None and adopted.local_profile.node != guest["node"])
    ):
        raise FleetOwnershipConflict("ownership requires a fresh standalone adoption")
    schedule = next((item for item in current.schedules if item.job_ref == schedule_ref), None)
    if (
        schedule is None
        or schedule.guest_ids != (target.id,)
        or schedule.schedule is None
        or not schedule.enabled
    ):
        raise FleetOwnershipConflict("ownership requires an enabled single-guest native schedule")
    return _CALENDAR.validate_python(schedule.schedule)


def _drained(db: sqlite3.Connection, plan: OwnershipPlan) -> bool:
    return (
        db.execute(
            """SELECT 1 FROM fleet_power_commands WHERE instance_id = ? AND vmid = ?
           AND state IN ('preparing', 'review', 'queued', 'released', 'accepted', 'uncertain')""",
            (plan.instance_id, plan.scope.vmid),
        ).fetchone()
        is None
    )


def _live_plan(
    db: sqlite3.Connection, row: sqlite3.Row, plan: OwnershipPlan, now: datetime
) -> bool:
    actor = FleetPolicyActor(
        plan.subject, coordinator=bool(row["coordinator"]), source=row["source"]
    )
    context = _power_context(
        db, _Access(db, actor), actor, plan.target, now, backup_profile=plan.profile
    )
    if context is None:
        return False
    guest, applied, approval, local = context
    return (
        (applied, approval, local)
        == (plan.policy_revision, plan.policy_approval, plan.local_revision)
        and _scope(guest) == plan.scope
        and guest["instance_id"] == plan.instance_id
        and (guest["agent_id"], guest["grant_generation"])
        == (plan.agent_id, plan.enrollment_generation)
    )


def _last_event(db: sqlite3.Connection, plan: OwnershipPlan, state: str) -> sqlite3.Row | None:
    return db.execute(
        """SELECT occurred_at, evidence FROM fleet_ownership_history
           WHERE handoff_id = ? AND state = ? ORDER BY id DESC LIMIT 1""",
        (plan.transition_id, state),
    ).fetchone()


def _release(
    db: sqlite3.Connection, row: sqlite3.Row, plan: OwnershipPlan, now: datetime
) -> OwnershipClaim | None:
    if not _drained(db, plan) or not _live_plan(db, row, plan, now):
        return None
    prior = _last_event(db, plan, "claim")
    if prior is not None and now < datetime.fromisoformat(prior["occurred_at"]):
        return None
    until = datetime.fromisoformat(prior["evidence"]) if prior is not None else now
    if now >= until:
        until = now + _CLAIM
        _event(db, plan, "claim", now, _timestamp(until))
    remaining_ms = (until - now) // timedelta(milliseconds=1)
    if remaining_ms < 1:
        return None
    return OwnershipClaim(claim_until=until, valid_for_ms=remaining_ms)


def _record(
    db: sqlite3.Connection, plan: OwnershipPlan, receipt: OwnershipReceipt, now: datetime
) -> None:
    previous = _last_event(db, plan, receipt.state)
    if previous is not None:
        if OwnershipReceipt.model_validate_json(previous["evidence"]) != receipt:
            raise FleetOwnershipConflict("ownership receipt conflicts with recorded evidence")
        return

    slot = _slot(db, plan.instance_id, plan.scope.vmid)
    status = OwnershipStatus.from_plan(plan, receipt.state)
    expected_state = "committed" if receipt.state == "active" else "pausing"
    if (
        slot is None
        or (slot["handoff_id"], slot["state"]) != (plan.transition_id, expected_state)
        or receipt.epoch != status.epoch
    ):
        raise FleetOwnershipConflict("ownership receipt does not match the pending transition")
    if receipt.state == "committed":
        if _last_event(db, plan, "claim") is None:
            raise FleetOwnershipConflict("ownership receipt requires a released transition")
    elif receipt.state == "active":
        committed = _last_event(db, plan, "committed")
        if (
            committed is None
            or OwnershipReceipt.model_validate_json(committed["evidence"]).schedule_fingerprint
            != receipt.schedule_fingerprint
        ):
            raise FleetOwnershipConflict("activation requires matching committed schedule evidence")
    _event(db, plan, receipt.state, now, receipt.model_dump_json())
    db.execute(
        """UPDATE fleet_guest_ownership SET owner = ?, epoch = ?, state = ?
           WHERE instance_id = ? AND vmid = ?""",
        (status.owner, status.epoch, status.state, plan.instance_id, plan.scope.vmid),
    )


def _require_visible(db: sqlite3.Connection, access: _Access, plan: OwnershipPlan) -> None:
    if not access.allows(plan.target, _target_record(db, plan.target)):
        raise FleetPolicyNotFound("ownership transition is unavailable")


class FleetOwnershipCoordinator:
    def __init__(
        self, registry: FleetIdentityRegistry, *, now: Callable[[], datetime] | None = None
    ):
        self._registry = registry
        self._clock = now

    def _now(self) -> datetime:
        now = self._clock() if self._clock is not None else datetime.now(UTC)
        if now.utcoffset() is None:
            raise ValueError("fleet ownership clock must be timezone-aware")
        return now.astimezone(UTC)

    def request(
        self,
        actor: FleetPolicyActor,
        target: FleetTarget,
        schedule_ref: str,
        profile: str,
        next_owner: Owner,
        key: str,
        epoch: int,
    ) -> OwnershipStatus:
        schedule_ref = _DIGEST.validate_python(schedule_ref)
        profile = _PROFILE.validate_python(profile)
        next_owner = _OWNER.validate_python(next_owner)
        epoch = _EPOCH.validate_python(epoch, strict=True)
        key = _KEY.validate_python(key)
        with self._registry._write() as db:
            now = self._now()
            access = _Access(db, actor)
            existing = db.execute(
                """SELECT * FROM fleet_ownership_plans
                   WHERE subject = ? AND source = ? AND request_key = ?""",
                (actor.subject, actor.source, key),
            ).fetchone()
            if existing is not None:
                plan = _plan(existing)
                _require_visible(db, access, plan)
                if (plan.target, plan.schedule_ref, plan.profile, plan.next_owner, plan.epoch) != (
                    target,
                    schedule_ref,
                    profile,
                    next_owner,
                    epoch,
                ):
                    raise FleetOwnershipConflict("request key is bound to a different transition")
                return _status(db, plan)

            context = _power_context(db, access, actor, target, now, backup_profile=profile)
            if context is None:
                raise FleetPolicyDenied(
                    "ownership requires current scoped operator and backup policy"
                )
            guest, applied, approval, local = context
            instance_id, vmid = guest["instance_id"], guest["vmid"]
            old = _slot(db, instance_id, vmid)
            if old is None:
                previous_owner, confirmed_epoch = "standalone", 0
            else:
                if (old["target_id"], old["generation"], old["job_ref"]) != (
                    target.id,
                    target.generation,
                    schedule_ref,
                ) or old["state"] not in ("active", "canceled"):
                    raise FleetOwnershipConflict("scope has an existing ownership fence")
                previous_owner, confirmed_epoch = old["owner"], old["epoch"]
            if epoch != confirmed_epoch:
                raise FleetOwnershipConflict("confirmed ownership epoch changed")
            if next_owner == previous_owner:
                raise FleetOwnershipConflict("requested owner is already confirmed")
            calendar = _adopted_schedule(db, guest, target, schedule_ref, now)
            plan = OwnershipPlan(
                transition_id=uuid4().hex,
                target=target,
                scope=_scope(guest),
                instance_id=instance_id,
                schedule_ref=schedule_ref,
                calendar=calendar,
                profile=profile,
                previous_owner=previous_owner,
                next_owner=next_owner,
                epoch=epoch,
                policy_revision=applied,
                policy_approval=approval,
                local_revision=local,
                subject=actor.subject,
                agent_id=guest["agent_id"],
                enrollment_generation=guest["grant_generation"],
            )
            db.execute(
                """INSERT INTO fleet_ownership_plans
                   (id, digest, plan, subject, source, coordinator, request_key)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    plan.transition_id,
                    plan.digest,
                    plan.model_dump_json(),
                    actor.subject,
                    actor.source,
                    actor.coordinator,
                    key,
                ),
            )
            db.execute(
                """INSERT INTO fleet_guest_ownership
                   (instance_id, vmid, target_id, generation, job_ref, owner, epoch,
                    state, handoff_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'pausing', ?)
                   ON CONFLICT(instance_id, vmid) DO UPDATE SET state = 'pausing',
                     handoff_id = excluded.handoff_id""",
                (
                    instance_id,
                    vmid,
                    target.id,
                    target.generation,
                    schedule_ref,
                    previous_owner,
                    epoch,
                    plan.transition_id,
                ),
            )
            db.execute(
                """UPDATE fleet_power_commands
                   SET state = 'refused', reason = 'preconditions_changed'
                   WHERE instance_id = ? AND vmid = ?
                     AND state IN ('preparing', 'review', 'queued')""",
                (instance_id, vmid),
            )
            _event(db, plan, "pausing", now)
            return _status(db, plan)

    def status(self, actor: FleetPolicyActor, transition_id: str) -> OwnershipStatus:
        with self._registry._write() as db:
            row = db.execute(
                "SELECT * FROM fleet_ownership_plans WHERE id = ?",
                (_ID.validate_python(transition_id),),
            ).fetchone()
            if row is None:
                raise FleetPolicyNotFound("ownership transition is unavailable")
            plan = _plan(row)
            _require_visible(db, _Access(db, actor), plan)
            return _status(db, plan)

    def exchange(self, fingerprint: str, request: OwnershipExchange) -> OwnershipReply:
        with self._registry._write() as db:
            now = self._now()
            grant = power_target_grant(db, fingerprint, request.target)
            row = db.execute(
                "SELECT * FROM fleet_ownership_plans WHERE id = ?", (request.transition_id,)
            ).fetchone()
            if row is None:
                raise FleetPolicyDenied("ownership transition does not match the enrolled target")
            plan = _plan(row)
            if (plan.target, plan.agent_id, plan.digest) != (
                request.target,
                grant.agent_id,
                request.digest,
            ) or grant.generation < plan.enrollment_generation:
                raise FleetPolicyDenied("ownership transition does not match the enrolled target")
            claim = None
            if request.receipt is not None:
                _record(db, plan, request.receipt, now)
            elif grant.generation == plan.enrollment_generation:
                slot = _slot(db, plan.instance_id, plan.scope.vmid)
                if slot is not None and (slot["handoff_id"], slot["state"]) == (
                    plan.transition_id,
                    "pausing",
                ):
                    claim = _release(db, row, plan, now)
            return OwnershipReply(status=_status(db, plan), plan=plan, claim=claim)
