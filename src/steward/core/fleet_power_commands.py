"""Persist and schedule exact reviewed fleet commands in the coordinator registry."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pydantic import TypeAdapter

from .canonical import revision_id
from .fleet_enrollment import power_target_grant, power_target_route
from .fleet_identity import FleetIdentityRegistry, _timestamp
from .fleet_policy import FleetTarget, RevisionId, _resolve, _target_record
from .fleet_policy_apply import (
    FleetPolicyActor,
    FleetPolicyDenied,
    FleetPolicyNotFound,
    _Access,
    _coordinates,
    _load_plan,
    _report,
    _reported_approval,
)
from .fleet_power import (
    CLAIM_MS,
    CommandCatalog,
    CommandKey,
    CommandPhase,
    CommandPoll,
    CommandReply,
    CommandReport,
    CommandSpec,
    CommandStatus,
    CommandTarget,
    CommandWork,
    PowerAction,
    PowerScope,
)
from .pve_power import JobId

_LIFETIME = timedelta(minutes=5)
_CLAIM = timedelta(milliseconds=CLAIM_MS)
_MAX_INVENTORY_AGE = timedelta(minutes=5)
_RECONCILE = ("released", "accepted", "uncertain")
_KEY = TypeAdapter(CommandKey)
_ACTION = TypeAdapter(PowerAction)
_ID = TypeAdapter(JobId)
_DIGEST = TypeAdapter(RevisionId)


class FleetCommandConflict(ValueError):
    """The command cannot advance under its current preconditions."""


def _command(db: sqlite3.Connection, command_id: str) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM fleet_power_commands WHERE id = ?", (command_id,)).fetchone()


def _public_target(spec: CommandSpec, instance_id: str, name: str | None) -> dict:
    return {
        "target": spec.target,
        "name": name,
        "instance_id": instance_id,
        "node": spec.scope.node,
        "kind": spec.scope.kind,
        "vmid": spec.scope.vmid,
        "policy_revision": spec.policy_revision,
    }


def _status(row: sqlite3.Row) -> CommandStatus:
    spec = CommandSpec.model_validate_json(row["spec"])
    return CommandStatus(
        **_public_target(spec, row["instance_id"], row["name"]),
        command_id=spec.command_id,
        action=spec.action,
        subject=spec.subject,
        role=spec.role,
        expires_at=spec.expires_at,
        state=row["state"],
        digest=row["digest"],
        reason=row["reason"],
        observed_state=row["observed_state"],
        task_ref=row["task_ref"],
    )


def _visible(db: sqlite3.Connection, access: _Access, row: sqlite3.Row) -> bool:
    target = FleetTarget(kind="pve_guest", id=row["target_id"], generation=row["generation"])
    return access.allows(target, _target_record(db, target))


def _expire(db: sqlite3.Connection, now: datetime, target: FleetTarget | None = None) -> None:
    """A released claim stays fenced after its release window or command expiry."""
    coordinates = (
        (None, None, None) if target is None else (target.id, target.id, target.generation)
    )
    db.execute(
        """UPDATE fleet_power_commands SET state = 'expired', reason = 'confirmation_expired'
           WHERE state IN ('preparing', 'review', 'queued')
             AND expires_at <= ? AND (? IS NULL OR (target_id = ? AND generation = ?))""",
        (_timestamp(now), *coordinates),
    )
    db.execute(
        """UPDATE fleet_power_commands SET state = 'uncertain', reason = 'release_unconfirmed'
           WHERE state = 'released' AND claim_until <= ?
             AND (? IS NULL OR (target_id = ? AND generation = ?))""",
        (_timestamp(now), *coordinates),
    )


def _power_context(
    db: sqlite3.Connection,
    access: _Access,
    actor: FleetPolicyActor,
    target: FleetTarget,
    now: datetime,
    *,
    backup_profile: str | None = None,
) -> tuple[sqlite3.Row, str, str, str] | None:
    if target.kind != "pve_guest" or access.record is None:
        return None
    record = _target_record(db, target)
    desired = access.targets.get(target)
    if desired is None or record is None or not record["available"]:
        return None
    if not access.allows(target, record, write=True):
        return None
    local, applied = _report(db, target)
    approval = _reported_approval(db, target)
    if local is None or applied != access.record.id or approval is None:
        return None
    outcome = db.execute(
        """SELECT a.digest FROM fleet_policy_approvals AS a
           JOIN fleet_policy_outcomes AS o ON o.approval_id = a.id
           WHERE a.id = ? AND o.kind = ? AND o.target_id = ? AND o.generation = ?
             AND o.status = 'applied'""",
        (approval, *_coordinates(target)),
    ).fetchone()
    if outcome is None:
        return None
    plan = _load_plan(db, outcome["digest"])
    reviewed = next((item for item in plan.targets if item.target == target), None)
    effective = _resolve(access.record, desired, record, local, local.revision, now)
    if (
        plan.revision != applied
        or reviewed is None
        or reviewed.local_revision != local.revision
        or effective != reviewed.effective
        or effective.status != "ready"
        or (
            backup_profile is not None
            and backup_profile not in effective.values.backup_profile_refs
        )
        or not any(
            item.subject == actor.subject and item.role == "operator"
            for item in effective.values.role_assignments
        )
    ):
        return None
    guest = db.execute(
        """SELECT g.kind, g.node, g.vmid, g.name, g.pve_uid, g.registered_at_ms, g.observation_id,
                  i.id AS instance_id, i.binding AS instance_binding,
                  b.agent_id, b.grant_generation, a.host_id, p.route_id, o.observed_at
           FROM fleet_guests AS g JOIN fleet_instances AS i ON i.id = g.instance_id
           JOIN fleet_observations AS o ON o.id = g.observation_id
           JOIN fleet_power_target_bindings AS b
             ON b.kind = 'pve_guest' AND b.target_id = g.id AND b.generation = g.generation
           JOIN fleet_agent_grants AS p
             ON p.agent_id = b.agent_id AND p.generation = b.grant_generation
           JOIN fleet_agents AS a ON a.id = b.agent_id
           WHERE g.id = ? AND g.generation = ? AND p.capability = 'pve_power_target'
             AND p.fingerprint IS NOT NULL AND g.pve_uid IS NOT NULL
             AND g.registered_at_ms IS NOT NULL AND o.route_id = p.route_id""",
        (target.id, target.generation),
    ).fetchone()
    if (
        guest is None
        or guest["route_id"] != power_target_route(db, target, guest["host_id"])
        or not timedelta()
        <= now - datetime.fromisoformat(guest["observed_at"])
        <= _MAX_INVENTORY_AGE
    ):
        return None
    if backup_profile is None and not _power_owned(db, guest, target):
        return None
    return guest, applied, approval, local.revision


def _power_owned(db: sqlite3.Connection, guest: sqlite3.Row, target: FleetTarget) -> bool:
    row = db.execute(
        """SELECT owner, state, target_id, generation FROM fleet_guest_ownership
           WHERE instance_id = ? AND vmid = ?""",
        (guest["instance_id"], guest["vmid"]),
    ).fetchone()
    return row is None or (
        (row["owner"], row["target_id"], row["generation"])
        == ("fleet", target.id, target.generation)
        and row["state"] in ("active", "canceled")
    )


def _scope(guest: sqlite3.Row) -> PowerScope:
    return PowerScope(**{field: guest[field] for field in PowerScope.model_fields})


def _valid(db: sqlite3.Connection, row: sqlite3.Row, spec: CommandSpec, now: datetime) -> bool:
    actor = FleetPolicyActor(
        spec.subject, coordinator=bool(row["coordinator"]), source=row["source"]
    )
    context = _power_context(db, _Access(db, actor), actor, spec.target, now)
    if context is None or now >= spec.expires_at:
        return False
    guest, policy, approval, local = context
    return (
        (policy, approval, local)
        == (spec.policy_revision, spec.policy_approval, spec.local_revision)
        and _scope(guest) == spec.scope
        and guest["instance_id"] == row["instance_id"]
        and (guest["agent_id"], guest["grant_generation"])
        == (spec.agent_id, spec.enrollment_generation)
    )


def _owned(db: sqlite3.Connection, actor: FleetPolicyActor, command_id: str) -> sqlite3.Row:
    row = _command(db, _ID.validate_python(command_id))
    if (
        row is None
        or (row["subject"], row["source"]) != (actor.subject, actor.source)
        or not _visible(db, _Access(db, actor), row)
    ):
        raise FleetPolicyNotFound("fleet command record is unavailable")
    return row


class FleetPowerCommands:
    def __init__(
        self,
        registry: FleetIdentityRegistry,
        *,
        now: Callable[[], datetime] | None = None,
    ):
        self._registry = registry
        self._clock = now

    def _now(self) -> datetime:
        now = self._clock() if self._clock is not None else datetime.now(UTC)
        if now.utcoffset() is None:
            raise ValueError("fleet command clock must be timezone-aware")
        return now.astimezone(UTC)

    def catalog(self, actor: FleetPolicyActor) -> CommandCatalog:
        with self._registry._write() as db:
            now = self._now()
            _expire(db, now)
            access = _Access(db, actor)
            targets = []
            for target in access.targets:
                context = _power_context(db, access, actor, target, now)
                if context is not None:
                    guest, policy, _, _ = context
                    targets.append(
                        CommandTarget(
                            target=target,
                            policy_revision=policy,
                            **{
                                key: guest[key]
                                for key in ("name", "instance_id", "node", "kind", "vmid")
                            },
                        )
                    )
            commands = []
            for row in db.execute(
                """SELECT * FROM fleet_power_commands WHERE subject = ? AND source = ?
                   ORDER BY rowid DESC""",
                (actor.subject, actor.source),
            ):
                if _visible(db, access, row):
                    commands.append(_status(row))
                    if len(commands) == 20:
                        break
            return CommandCatalog(targets=tuple(targets), commands=tuple(commands))

    def request(
        self,
        actor: FleetPolicyActor,
        target: FleetTarget,
        policy_revision: str,
        action: PowerAction,
        key: str,
    ) -> CommandStatus:
        key = _KEY.validate_python(key)
        action = _ACTION.validate_python(action)
        policy_revision = _DIGEST.validate_python(policy_revision)
        with self._registry._write() as db:
            now = self._now()
            _expire(db, now)
            access = _Access(db, actor)
            existing = db.execute(
                """SELECT * FROM fleet_power_commands
                   WHERE subject = ? AND source = ? AND request_key = ?""",
                (actor.subject, actor.source, key),
            ).fetchone()
            if existing is not None:
                if not _visible(db, access, existing):
                    raise FleetPolicyNotFound("fleet command record is unavailable")
                spec = CommandSpec.model_validate_json(existing["spec"])
                if (spec.target, spec.policy_revision, spec.action) != (
                    target,
                    policy_revision,
                    action,
                ):
                    raise FleetCommandConflict("request key is bound to a different command")
                return _status(existing)

            context = _power_context(db, access, actor, target, now)
            if context is None:
                raise FleetPolicyDenied("fleet command requires current scoped operator authority")
            guest, policy, approval, local = context
            if policy != policy_revision:
                raise FleetCommandConflict("fleet command policy revision changed")
            if (
                db.execute(
                    """SELECT 1 FROM fleet_power_commands WHERE instance_id = ? AND vmid = ?
                   AND state IN (
                       'preparing', 'review', 'queued', 'released', 'accepted', 'uncertain'
                   )""",
                    (guest["instance_id"], guest["vmid"]),
                ).fetchone()
                is not None
            ):
                raise FleetCommandConflict("guest already has unfinished fleet work")
            spec = CommandSpec(
                command_id=uuid4().hex,
                target=target,
                scope=_scope(guest),
                policy_revision=policy,
                policy_approval=approval,
                local_revision=local,
                subject=actor.subject,
                agent_id=guest["agent_id"],
                enrollment_generation=guest["grant_generation"],
                expires_at=now + _LIFETIME,
                action=action,
            )
            db.execute(
                """INSERT INTO fleet_power_commands
                   (id, target_id, generation, instance_id, vmid, subject, source, coordinator,
                    request_key, spec, expires_at, name, state)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'preparing')""",
                (
                    spec.command_id,
                    target.id,
                    target.generation,
                    guest["instance_id"],
                    guest["vmid"],
                    actor.subject,
                    actor.source,
                    actor.coordinator,
                    key,
                    spec.model_dump_json(),
                    _timestamp(spec.expires_at),
                    guest["name"],
                ),
            )
            return _status(_command(db, spec.command_id))

    def approve(
        self, actor: FleetPolicyActor, command_id: str, digest: str, key: str
    ) -> CommandStatus:
        digest = _DIGEST.validate_python(digest)
        key = _KEY.validate_python(key)
        with self._registry._write() as db:
            now = self._now()
            _expire(db, now)
            row = _owned(db, actor, command_id)
            if row["digest"] != digest:
                raise FleetCommandConflict("command approval does not match the reviewed plan")
            if row["approval_key"] is not None:
                if row["approval_key"] != key:
                    raise FleetCommandConflict("command already has an approval")
                return _status(row)
            spec = CommandSpec.model_validate_json(row["spec"])
            if row["state"] != "review":
                raise FleetCommandConflict("command is unavailable for approval")
            access = _Access(db, actor)
            if not access.allows(spec.target, _target_record(db, spec.target), write=True):
                raise FleetPolicyDenied("fleet command requires current scoped operator authority")
            if not _valid(db, row, spec, now):
                raise FleetCommandConflict("reviewed command preconditions changed")
            if (
                db.execute(
                    """SELECT 1 FROM fleet_power_commands
                   WHERE subject = ? AND source = ? AND approval_key = ?""",
                    (actor.subject, actor.source, key),
                ).fetchone()
                is not None
            ):
                raise FleetCommandConflict("approval key is bound to a different command")
            db.execute(
                """UPDATE fleet_power_commands SET state = 'queued', approval_key = ?
                   WHERE id = ?""",
                (key, command_id),
            )
            return _status(_command(db, command_id))

    def status(self, actor: FleetPolicyActor, command_id: str) -> CommandStatus:
        with self._registry._write() as db:
            _expire(db, self._now())
            return _status(_owned(db, actor, command_id))

    def poll(self, fingerprint: str, request: CommandPoll) -> CommandReply:
        with self._registry._write() as db:
            now = self._now()
            target = request.target
            grant = power_target_grant(db, fingerprint, target)
            _expire(db, now, target)
            if request.report is not None:
                row = _command(db, request.report.command_id)
            else:
                row = db.execute(
                    """SELECT * FROM fleet_power_commands WHERE target_id = ? AND generation = ?
                       AND state IN ('preparing', 'queued', 'released', 'accepted', 'uncertain')""",
                    (target.id, target.generation),
                ).fetchone()
            if row is None:
                if request.report is not None:
                    raise FleetPolicyDenied("command report does not match outstanding work")
                return CommandReply()
            spec = CommandSpec.model_validate_json(row["spec"])
            state = row["state"]
            generation_matches = grant.generation == spec.enrollment_generation
            rotated_receipt = (
                request.report is not None and row["claim_generation"] == grant.generation
            )
            can_reconcile = grant.generation > spec.enrollment_generation and (
                state in _RECONCILE or rotated_receipt
            )
            if (
                spec.target != target
                or spec.agent_id != grant.agent_id
                or not (generation_matches or can_reconcile)
            ):
                if request.report is not None:
                    raise FleetPolicyDenied("command report does not match the enrolled target")
                if spec.target == target and state in ("preparing", "queued"):
                    _refuse(db, spec.command_id)
                return CommandReply()

            if request.report is not None:
                if row["claim_generation"] != grant.generation:
                    raise FleetPolicyDenied("command report does not match the claim generation")
                _settle(db, row, spec, request, now)
                return CommandReply()
            until = row["claim_until"]
            if until is not None and until > _timestamp(now):
                return CommandReply()
            if state in _RECONCILE:
                phase = "reconcile"
            else:
                if not _valid(db, row, spec, now) or not _matches(spec, request):
                    _refuse(db, spec.command_id)
                    return CommandReply()
                phase = "prepare" if state == "preparing" else "execute"
            return _claim(db, row, spec, phase, grant.generation, now)


def _matches(spec: CommandSpec, request: CommandPoll) -> bool:
    return (spec.policy_revision, spec.policy_approval, spec.local_revision) == (
        request.policy_revision,
        request.policy_approval,
        request.local_revision,
    )


def _refuse(db: sqlite3.Connection, command_id: str) -> None:
    db.execute(
        """UPDATE fleet_power_commands SET state = 'refused', reason = 'preconditions_changed'
           WHERE id = ?""",
        (command_id,),
    )


def _claim(
    db: sqlite3.Connection,
    row: sqlite3.Row,
    spec: CommandSpec,
    phase: CommandPhase,
    generation: int,
    now: datetime,
) -> CommandReply:
    until = now + _CLAIM
    if phase != "reconcile":
        until = min(until, spec.expires_at)
    valid_for_ms = (until - now) // timedelta(milliseconds=1)
    if valid_for_ms < 1:
        return CommandReply()
    work = CommandWork(
        spec=spec,
        phase=phase,
        native_digest=row["native_digest"],
        claim_id=uuid4().hex,
        recipient_generation=generation,
        claim_until=until,
        valid_for_ms=valid_for_ms,
    )
    db.execute(
        """UPDATE fleet_power_commands SET state = ?, claim_id = ?, claim_generation = ?,
               claim_until = ? WHERE id = ?""",
        (
            "released" if phase == "execute" else row["state"],
            work.claim_id,
            generation,
            _timestamp(until),
            spec.command_id,
        ),
    )
    return CommandReply(work=work)


def _settle(
    db: sqlite3.Connection,
    row: sqlite3.Row,
    spec: CommandSpec,
    request: CommandPoll,
    now: datetime,
) -> None:
    report = request.report
    assert report is not None
    if row["report"] is not None:
        previous = CommandReport.model_validate_json(row["report"])
        if previous.claim_id == report.claim_id:
            if previous == report:
                return
            raise FleetPolicyDenied("conflicting command report for the same claim")
    if row["claim_id"] != report.claim_id:
        raise FleetPolicyDenied("command report claim does not match outstanding work")
    state = row["state"]
    reason = None
    native_digest = row["native_digest"]
    digest = row["digest"]
    if state == "preparing" and report.state in ("prepared", "refused"):
        if row["claim_until"] <= _timestamp(now) or not (
            _matches(spec, request) and _valid(db, row, spec, now)
        ):
            _refuse(db, spec.command_id)
            return
        if report.state == "prepared":
            native_digest = report.native_digest
            digest = revision_id({"command": spec.model_dump(mode="json"), "native": native_digest})
        state = "review" if report.state == "prepared" else "refused"
        reason = (report.reason or "native_preview_refused") if state == "refused" else None
    elif state in _RECONCILE and report.state != "prepared":
        if report.native_digest != native_digest:
            raise FleetPolicyDenied("command report native plan does not match approval")
        previous_task = row["task_ref"]
        if previous_task is not None and (
            report.state == "refused"
            or (
                report.task_ref != previous_task
                and not (report.state == "uncertain" and report.task_ref is None)
            )
        ):
            raise FleetPolicyDenied("command report task disagrees with recorded task")
        state = report.state
        reason = report.reason or {
            "failed": "native_failed",
            "refused": "native_not_dispatched",
            "uncertain": "native_unconfirmed",
        }.get(state)
    else:
        raise FleetPolicyDenied("command report does not match the outstanding phase")

    db.execute(
        """UPDATE fleet_power_commands SET state = ?, digest = ?, native_digest = ?, report = ?,
               task_ref = COALESCE(?, task_ref), observed_state = ?, reason = ?, claim_until = NULL
           WHERE id = ?""",
        (
            state,
            digest,
            native_digest,
            report.model_dump_json(),
            report.task_ref,
            "stopped" if report.state == "prepared" else report.observed_state,
            reason,
            spec.command_id,
        ),
    )
