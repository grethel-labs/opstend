"""Coordinate explicit fleet policy review and target-owned admission."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal
from uuid import uuid4

from pydantic import TypeAdapter

from .canonical import canonical_json, revision_id
from .fleet_enrollment import (
    FleetEnrollmentConflict,
    FleetGrant,
    policy_target_active,
    policy_target_bound,
    policy_target_grant,
)
from .fleet_identity import FleetIdentityRegistry
from .fleet_policy import (
    EffectiveFleetPolicy,
    FleetLocalPolicy,
    FleetPolicy,
    FleetPolicyConflict,
    FleetPolicyRevision,
    FleetTarget,
    PolicyName,
    RegistryId,
    RevisionId,
    _commit,
    _get_revision,
    _head,
    _resolve,
    _target_record,
)
from .fleet_policy_reconcile import (
    CLAIM_SECONDS,
    MAX_POLICY_SYNC_BYTES,
    FleetPolicyClaim,
    FleetPolicyOutcome,
    FleetPolicyReceipt,
    FleetPolicySyncReply,
    FleetPolicySyncRequest,
)
from .fleet_policy_target import FleetPolicyTargetState
from .pve_inventory_models import Projection

if TYPE_CHECKING:
    from .fleet_policy_target import FleetPolicyTargetStore

_PLAN_LIFETIME = timedelta(minutes=5)
_NAME = TypeAdapter(PolicyName)
_SITE_ID = TypeAdapter(RegistryId)


class FleetPolicyDenied(PermissionError):
    """This action requires coordinator authority."""


class FleetPolicyNotFound(LookupError):
    """There is no policy record visible for this operation."""


@dataclass(frozen=True)
class FleetPolicyActor:
    subject: str
    coordinator: bool = False
    source: Literal["local", "browser"] = "local"

    def __post_init__(self) -> None:
        _NAME.validate_python(self.subject, strict=True)


@dataclass(frozen=True)
class FleetPolicyGrant:
    subject: str
    permission: Literal["read", "write"]
    site_id: str | None = None
    group_id: str | None = None
    target: FleetTarget | None = None

    def __post_init__(self) -> None:
        _NAME.validate_python(self.subject, strict=True)
        if self.permission not in ("read", "write"):
            raise ValueError("invalid fleet policy grant permission")
        if sum(scope is not None for scope in (self.site_id, self.group_id, self.target)) != 1:
            raise ValueError("a fleet policy grant requires exactly one scope")
        if self.site_id is not None:
            _SITE_ID.validate_python(self.site_id, strict=True)
        if self.group_id is not None:
            _NAME.validate_python(self.group_id, strict=True)


class FleetPolicyTargetView(Projection):
    target: FleetTarget
    site_id: RegistryId
    group_ids: tuple[PolicyName, ...]
    applied_revision: RevisionId | None
    can_write: bool
    local_revision: RevisionId | None = None
    observed_at: datetime | None = None
    conflict_owner: Literal["local_operator"] | None = None


class FleetPolicyHead(Projection):
    head: RevisionId | None
    can_manage: bool
    targets: tuple[FleetPolicyTargetView, ...]
    approval_ids: tuple[RegistryId, ...]


class FleetPolicyPlanTarget(Projection):
    target: FleetTarget
    applied_revision: RevisionId | None
    applied_approval_id: RegistryId | None = None
    local_revision: RevisionId | None
    observed_at: datetime | None
    effective: EffectiveFleetPolicy


class _PlanBody(Projection):
    revision: RevisionId
    expires_at: datetime
    targets: tuple[FleetPolicyPlanTarget, ...]


class FleetPolicyPlan(_PlanBody):
    digest: RevisionId


class FleetPolicyApproval(Projection):
    id: RegistryId
    digest: RevisionId
    revision: RevisionId
    expires_at: datetime
    outcomes: tuple[FleetPolicyOutcome, ...]


def _coordinates(target: FleetTarget) -> tuple[str, str, int]:
    return target.kind, target.id, target.generation


def _may_coordinate(db: sqlite3.Connection, actor: FleetPolicyActor) -> bool:
    return actor.coordinator and (
        actor.source == "local"
        or db.execute(
            "SELECT 1 FROM fleet_policy_coordinators WHERE subject = ?", (actor.subject,)
        ).fetchone()
        is not None
    )


def _require_coordinator(db: sqlite3.Connection, actor: FleetPolicyActor) -> None:
    if not _may_coordinate(db, actor):
        raise FleetPolicyDenied("fleet policy coordinator authority is required")


def _missing() -> FleetPolicyNotFound:
    return FleetPolicyNotFound("fleet policy record is unavailable")


def _report(
    db: sqlite3.Connection, target: FleetTarget
) -> tuple[FleetLocalPolicy | None, str | None]:
    row = db.execute(
        """SELECT local, applied_revision FROM fleet_policy_reports
           WHERE kind = ? AND target_id = ? AND generation = ?""",
        _coordinates(target),
    ).fetchone()
    if row is None:
        return None, None
    return FleetLocalPolicy.model_validate_json(row["local"]), row["applied_revision"]


def _save_report(
    db: sqlite3.Connection,
    local: FleetLocalPolicy,
    applied_revision: str | None,
    approval_id: str | None,
) -> None:
    db.execute(
        """INSERT INTO fleet_policy_reports (kind, target_id, generation, local, applied_revision)
           VALUES (?, ?, ?, ?, ?) ON CONFLICT (kind, target_id, generation)
           DO UPDATE SET local = excluded.local, applied_revision = excluded.applied_revision""",
        (*_coordinates(local.target), local.model_dump_json(), applied_revision),
    )

    db.execute(
        """INSERT INTO fleet_policy_report_state (kind, target_id, generation, approval_id)
           VALUES (?, ?, ?, ?) ON CONFLICT (kind, target_id, generation)
           DO UPDATE SET approval_id = excluded.approval_id""",
        (*_coordinates(local.target), approval_id),
    )


def _reported_approval(db: sqlite3.Connection, target: FleetTarget) -> str | None:
    row = db.execute(
        """SELECT approval_id FROM fleet_policy_report_state
           WHERE kind = ? AND target_id = ? AND generation = ?""",
        _coordinates(target),
    ).fetchone()
    return row["approval_id"] if row is not None else None


def _local_conflict(
    db: sqlite3.Connection, local: FleetLocalPolicy, applied: str | None, head: str
) -> Literal["local_operator"] | None:
    approval_id = _reported_approval(db, local.target)
    reviews = db.execute(
        """WITH reviews AS (
               SELECT p.digest, p.revision, a.id, o.status, a.rowid AS sequence
               FROM fleet_policy_outcomes AS o
               JOIN fleet_policy_approvals AS a ON a.id = o.approval_id
               JOIN fleet_policy_plans AS p ON p.digest = a.digest
               WHERE o.kind = ? AND o.target_id = ? AND o.generation = ?
           )
           SELECT digest FROM (
               SELECT digest FROM reviews
               WHERE id = ? OR (? IS NULL AND revision = ? AND status = 'applied')
               ORDER BY sequence DESC LIMIT 1
           )
           UNION
           SELECT digest FROM (
               SELECT digest FROM reviews WHERE revision = ? ORDER BY sequence DESC LIMIT 1
           )""",
        (*_coordinates(local.target), approval_id, approval_id, applied, head),
    )
    for row in reviews:
        reviewed = next(
            item for item in _load_plan(db, row["digest"]).targets if item.target == local.target
        )
        if reviewed.local_revision is not None and reviewed.local_revision != local.revision:
            return "local_operator"
    return None


class _Access:
    """Authorize against current membership, independent of desired role assignments."""

    def __init__(self, db: sqlite3.Connection, actor: FleetPolicyActor):
        head = _head(db)
        self.record = _get_revision(db, head) if head is not None else None
        self.targets = (
            {item.target: item for item in self.record.policy.targets}
            if self.record is not None
            else {}
        )
        self.coordinator = _may_coordinate(db, actor)
        self.grants = {
            (row["scope"], row["scope_id"], row["generation"]): row["permission"]
            for row in db.execute(
                """SELECT scope, scope_id, generation, permission FROM fleet_policy_grants
                   WHERE subject = ? ORDER BY permission""",
                (actor.subject,),
            )
        }

    def allows(
        self, target: FleetTarget, record: sqlite3.Row | None, *, write: bool = False
    ) -> bool:
        if self.coordinator:
            return True
        item = self.targets.get(target)
        if item is None or record is None or not record["available"]:
            return False
        scopes = (
            _coordinates(target),
            ("site", record["site_id"], 0),
            *(("group", group, 0) for group in item.group_ids),
        )
        return any(
            permission == "write" or (permission == "read" and not write)
            for permission in (self.grants.get(scope) for scope in scopes)
        )


def _load_plan(db: sqlite3.Connection, digest: str) -> FleetPolicyPlan:
    row = db.execute("SELECT body FROM fleet_policy_plans WHERE digest = ?", (digest,)).fetchone()
    if row is None:
        raise _missing()
    body = _PlanBody.model_validate_json(row["body"])
    if revision_id(body.model_dump(mode="json", exclude_unset=True)) != digest:
        raise _missing()
    return FleetPolicyPlan(
        digest=digest, revision=body.revision, expires_at=body.expires_at, targets=body.targets
    )


def _outcome(row: sqlite3.Row) -> FleetPolicyOutcome:
    return FleetPolicyOutcome(
        target=FleetTarget(kind=row["kind"], id=row["target_id"], generation=row["generation"]),
        status=row["status"],
        reason=row["reason"],
        conflict_owner="local_operator" if row["reason"] == "local_revision_changed" else None,
    )


def _approval(db: sqlite3.Connection, access: _Access, approval_id: str) -> FleetPolicyApproval:
    row = db.execute(
        """SELECT a.digest, p.revision, json_extract(p.body, '$.expires_at') AS expires_at
           FROM fleet_policy_approvals AS a JOIN fleet_policy_plans AS p ON a.digest = p.digest
           WHERE a.id = ?""",
        (approval_id,),
    ).fetchone()
    if row is None:
        raise _missing()
    outcomes = []
    for result in db.execute(
        """SELECT kind, target_id, generation, status, reason FROM fleet_policy_outcomes
           WHERE approval_id = ? ORDER BY kind, target_id, generation""",
        (approval_id,),
    ):
        target = FleetTarget(
            kind=result["kind"], id=result["target_id"], generation=result["generation"]
        )
        if access.allows(target, _target_record(db, target)):
            outcomes.append(_outcome(result))
    if not outcomes:
        raise _missing()
    return FleetPolicyApproval(
        id=approval_id,
        digest=row["digest"],
        revision=row["revision"],
        expires_at=datetime.fromisoformat(row["expires_at"]),
        outcomes=tuple(outcomes),
    )


class FleetPolicyApply:
    def __init__(
        self, registry: FleetIdentityRegistry, *, clock: Callable[[], datetime] | None = None
    ):
        self._registry = registry
        self._clock = clock

    def _now(self) -> datetime:
        now = self._clock() if self._clock is not None else datetime.now(UTC)
        if now.utcoffset() is None:
            raise ValueError("fleet policy clock must be timezone-aware")
        return now.astimezone(UTC)

    def set_grant(
        self, actor: FleetPolicyActor, grant: FleetPolicyGrant, *, enabled: bool = True
    ) -> None:
        with self._registry._write() as db:
            _require_coordinator(db, actor)
            if grant.site_id is not None:
                scope = ("site", grant.site_id, 0)
                if (
                    enabled
                    and db.execute(
                        "SELECT 1 FROM fleet_sites WHERE id = ?", (grant.site_id,)
                    ).fetchone()
                    is None
                ):
                    raise _missing()
            elif grant.group_id is not None:
                scope = ("group", grant.group_id, 0)
            else:
                assert grant.target is not None
                scope = _coordinates(grant.target)
                if enabled and _target_record(db, grant.target) is None:
                    raise _missing()

            coordinates = (grant.subject, grant.permission, *scope)
            if enabled:
                db.execute(
                    """INSERT INTO fleet_policy_grants
                       (subject, permission, scope, scope_id, generation)
                       VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING""",
                    coordinates,
                )
            else:
                db.execute(
                    """DELETE FROM fleet_policy_grants WHERE subject = ? AND permission = ?
                       AND scope = ? AND scope_id = ? AND generation = ?""",
                    coordinates,
                )

    def set_coordinator(
        self, actor: FleetPolicyActor, subject: str, *, enabled: bool = True
    ) -> None:
        if actor.source != "local" or not actor.coordinator:
            raise FleetPolicyDenied("the local coordinator owner is required")
        _NAME.validate_python(subject, strict=True)
        with self._registry._write() as db:
            if enabled:
                db.execute(
                    "INSERT INTO fleet_policy_coordinators VALUES (?) ON CONFLICT DO NOTHING",
                    (subject,),
                )
            else:
                db.execute("DELETE FROM fleet_policy_coordinators WHERE subject = ?", (subject,))

    def head(self, actor: FleetPolicyActor) -> FleetPolicyHead:
        with self._registry._connection() as db:
            db.execute("BEGIN")
            access = _Access(db, actor)
            targets = []
            for target, item in access.targets.items():
                record = _target_record(db, target)
                if record is not None and access.allows(target, record):
                    local, applied = _report(db, target)
                    targets.append(
                        FleetPolicyTargetView(
                            target=target,
                            site_id=record["site_id"],
                            group_ids=item.group_ids,
                            applied_revision=applied,
                            can_write=access.allows(target, record, write=True),
                            local_revision=local.revision if local is not None else None,
                            observed_at=local.observed_at if local is not None else None,
                            conflict_owner=_local_conflict(db, local, applied, access.record.id)
                            if local is not None and access.record is not None
                            else None,
                        )
                    )
            if access.coordinator:
                approval_ids = tuple(
                    row["id"]
                    for row in db.execute(
                        "SELECT id FROM fleet_policy_approvals ORDER BY rowid DESC LIMIT 20"
                    )
                )
            else:
                visible = {}
                for item in targets:
                    visible.update(
                        (row["id"], row["sequence"])
                        for row in db.execute(
                            """SELECT a.id, a.rowid AS sequence FROM fleet_policy_outcomes AS o
                               JOIN fleet_policy_approvals AS a ON o.approval_id = a.id
                               WHERE o.kind = ? AND o.target_id = ? AND o.generation = ?
                               ORDER BY sequence DESC LIMIT 20""",
                            _coordinates(item.target),
                        )
                    )
                approval_ids = tuple(sorted(visible, key=visible.__getitem__, reverse=True)[:20])
            return FleetPolicyHead(
                head=access.record.id
                if access.record and (access.coordinator or targets)
                else None,
                can_manage=access.coordinator,
                targets=tuple(targets),
                approval_ids=approval_ids,
            )

    def revision(self, actor: FleetPolicyActor, revision: str) -> FleetPolicyRevision:
        with self._registry._connection() as db:
            db.execute("BEGIN")
            _require_coordinator(db, actor)
            record = _get_revision(db, revision)
            if record is None:
                raise _missing()
            return record

    def commit(
        self, actor: FleetPolicyActor, policy: FleetPolicy, *, parent: str | None
    ) -> FleetPolicyRevision:
        with self._registry._write() as db:
            _require_coordinator(db, actor)
            return _commit(db, policy, parent)

    def rollback(
        self, actor: FleetPolicyActor, earlier: str, *, parent: str | None
    ) -> FleetPolicyRevision:
        with self._registry._write() as db:
            _require_coordinator(db, actor)
            head = _head(db)
            if parent != head:
                raise FleetPolicyConflict(head)
            record = _get_revision(db, earlier)
            if record is None:
                raise _missing()
            if earlier == head:
                raise ValueError("rollback requires an earlier fleet policy revision")
            return _commit(db, record.policy, parent)

    def preview(
        self, actor: FleetPolicyActor, revision: str, targets: Iterable[FleetTarget]
    ) -> FleetPolicyPlan:
        requested = tuple(targets)
        if not requested or len(set(requested)) != len(requested):
            raise ValueError("review requires a nonempty set of distinct targets")
        with self._registry._write() as db:
            access = _Access(db, actor)
            items = []
            now = self._now()
            for target in sorted(requested, key=_coordinates):
                record = _target_record(db, target)
                desired = access.targets.get(target)
                if desired is None or not access.allows(target, record):
                    raise _missing()
                items.append((target, desired, record))
            assert access.record is not None
            if access.record.id != revision:
                raise FleetPolicyConflict(access.record.id)

            reviewed = []
            for target, desired, record in items:
                local, applied = _report(db, target)
                local_revision = local.revision if local is not None else None
                reviewed.append(
                    FleetPolicyPlanTarget(
                        target=target,
                        applied_revision=applied,
                        applied_approval_id=_reported_approval(db, target),
                        local_revision=local_revision,
                        observed_at=local.observed_at if local is not None else None,
                        effective=_resolve(
                            access.record, desired, record, local, local_revision, now
                        ),
                    )
                )

            body = _PlanBody(
                revision=revision, expires_at=now + _PLAN_LIFETIME, targets=tuple(reviewed)
            )
            payload = body.model_dump(mode="json")
            digest = revision_id(payload)
            db.execute(
                """INSERT INTO fleet_policy_plans (digest, revision, body) VALUES (?, ?, ?)
                   ON CONFLICT DO NOTHING""",
                (digest, revision, canonical_json(payload)),
            )
            return FleetPolicyPlan(
                digest=digest,
                revision=body.revision,
                expires_at=body.expires_at,
                targets=body.targets,
            )

    def approve(self, actor: FleetPolicyActor, digest: str, key: str) -> FleetPolicyApproval:
        _NAME.validate_python(key, strict=True)
        with self._registry._write() as db:
            access = _Access(db, actor)
            for row in db.execute(
                """SELECT json_extract(item.value, '$.target') AS target
                   FROM fleet_policy_plans AS p, json_each(p.body, '$.targets') AS item
                   WHERE p.digest = ?""",
                (digest,),
            ):
                target = FleetTarget.model_validate_json(row["target"])
                if not access.allows(target, _target_record(db, target), write=True):
                    raise _missing()
            plan = _load_plan(db, digest)
            existing = db.execute(
                """SELECT id, digest FROM fleet_policy_approvals
                   WHERE actor_source = ? AND subject = ? AND request_key = ?""",
                (actor.source, actor.subject, key),
            ).fetchone()
            if existing is not None:
                if existing["digest"] != digest:
                    raise ValueError("fleet policy approval key is already in use")
                return _approval(db, access, existing["id"])

            head = access.record.id if access.record else None
            if head != plan.revision:
                raise FleetPolicyConflict(head)
            if self._now() >= plan.expires_at:
                raise ValueError("fleet policy preview has expired")

            approval_id = uuid4().hex
            db.execute(
                """INSERT INTO fleet_policy_approvals
                   (id, digest, subject, coordinator, actor_source, request_key)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (approval_id, digest, actor.subject, access.coordinator, actor.source, key),
            )
            db.executemany(
                """INSERT INTO fleet_policy_outcomes
                   (approval_id, kind, target_id, generation, status, reason)
                   VALUES (?, ?, ?, ?, 'pending', ?)""",
                (
                    (
                        approval_id,
                        *_coordinates(item.target),
                        "awaiting_target"
                        if item.effective.status == "ready"
                        else "review_required",
                    )
                    for item in plan.targets
                ),
            )
            return _approval(db, access, approval_id)

    def approval(self, actor: FleetPolicyActor, approval_id: str) -> FleetPolicyApproval:
        with self._registry._connection() as db:
            db.execute("BEGIN")
            return _approval(db, _Access(db, actor), approval_id)

    def report_local(self, target_store: FleetPolicyTargetStore) -> FleetPolicyTargetState:
        with target_store.transaction(self._registry) as db:
            state = target_store.read(db, self._now())
            if _target_record(db, state.local.target) is None:
                raise _missing()
            if policy_target_bound(db, state.local.target):
                raise FleetPolicyDenied("the target uses remote policy reconciliation")
            _save_report(db, state.local, state.applied_revision, state.approval_id)
            return state

    def adopt_local(
        self, target_store: FleetPolicyTargetStore, approval_id: str, digest: str
    ) -> FleetPolicyOutcome:
        with target_store.transaction(self._registry) as db:
            now = self._now()
            state = target_store.read(db, now)
            target = state.local.target
            if policy_target_bound(db, target):
                raise FleetPolicyDenied("the target uses remote policy reconciliation")
            approved = db.execute(
                """SELECT subject, coordinator, actor_source FROM fleet_policy_approvals
                   WHERE id = ? AND digest = ?""",
                (approval_id, digest),
            ).fetchone()
            if approved is None:
                raise _missing()
            selected = db.execute(
                """SELECT kind, target_id, generation, status, reason FROM fleet_policy_outcomes
                   WHERE approval_id = ? AND kind = ? AND target_id = ? AND generation = ?""",
                (approval_id, *_coordinates(target)),
            ).fetchone()
            if selected is None:
                raise _missing()
            if selected["status"] != "pending":
                return _outcome(selected)
            plan = _load_plan(db, digest)
            reviewed = next(item for item in plan.targets if item.target == target)
            record = _target_record(db, target)
            actor = FleetPolicyActor(
                approved["subject"], bool(approved["coordinator"]), approved["actor_source"]
            )
            access = _Access(db, actor)
            reason = (
                "approval_scope_revoked"
                if actor.coordinator and not access.coordinator
                else _admission_issue(db, access, reviewed, plan, state, record, now)
            )
            if reason is None:
                target_store.apply(db, reviewed.effective, approval_id)
                _save_report(db, state.local, plan.revision, approval_id)
            elif record is not None:
                _save_report(db, state.local, state.applied_revision, state.approval_id)

            status = "applied" if reason is None else "rejected"
            db.execute(
                """UPDATE fleet_policy_outcomes SET status = ?, reason = ?
                   WHERE approval_id = ? AND kind = ? AND target_id = ? AND generation = ?""",
                (status, reason, approval_id, *_coordinates(target)),
            )
            return FleetPolicyOutcome(
                target=target,
                status=status,
                reason=reason,
                conflict_owner="local_operator" if reason == "local_revision_changed" else None,
            )

    def reconcile_target(
        self, fingerprint: str, request: FleetPolicySyncRequest
    ) -> FleetPolicySyncReply:
        target = request.local.target
        with self._registry._write() as db:
            try:
                grant = policy_target_grant(db, fingerprint, target)
            except FleetEnrollmentConflict:
                raise FleetPolicyDenied(
                    "client has no current grant for this policy target"
                ) from None

            previous = _remote_report(db, grant.agent_id, request)
            settled = _settle_receipt(db, grant.agent_id, target, request.receipt)
            response = {
                "sequence": request.sequence,
                "target": target,
                "acknowledged_receipt": request.receipt.claim_id if settled else None,
            }
            now = self._now()
            observed = request.local.model_copy(update={"observed_at": now})
            report_ready = _record_remote_report(db, grant.agent_id, request, previous, observed)
            if request.approval_id is None:
                return FleetPolicySyncReply(outcome=settled, **response)
            if not report_ready:
                return FleetPolicySyncReply(
                    outcome=FleetPolicyOutcome(
                        target=target, status="pending", reason="stale_report"
                    ),
                    **response,
                )
            outcome, claim = self._claim_remote(db, grant, request, observed, now)
            return FleetPolicySyncReply(outcome=outcome, claim=claim, **response)

    def _claim_remote(
        self,
        db: sqlite3.Connection,
        grant: FleetGrant,
        request: FleetPolicySyncRequest,
        observed: FleetLocalPolicy,
        now: datetime,
    ) -> tuple[FleetPolicyOutcome, FleetPolicyClaim | None]:
        approval_id, digest = request.approval_id, request.digest
        assert approval_id is not None and digest is not None
        target = request.local.target
        approved = db.execute(
            """SELECT subject, coordinator, actor_source FROM fleet_policy_approvals
               WHERE id = ? AND digest = ?""",
            (approval_id, digest),
        ).fetchone()
        result = _selected_outcome(db, approval_id, target)
        if approved is None or result is None:
            return FleetPolicyOutcome(
                target=target, status="rejected", reason="approval_unavailable"
            ), None
        if result["status"] != "pending":
            return _outcome(result), None

        plan = _load_plan(db, digest)
        reviewed = next(item for item in plan.targets if item.target == target)
        record = _target_record(db, target)
        actor = FleetPolicyActor(
            approved["subject"], bool(approved["coordinator"]), approved["actor_source"]
        )
        access = _Access(db, actor)
        state = FleetPolicyTargetState(
            local=observed,
            applied_revision=request.applied_revision,
            approval_id=request.applied_approval_id,
            effective=None,
        )
        if not policy_target_active(db, target, grant.host_id):
            reason = "target_unavailable"
        elif actor.coordinator and not access.coordinator:
            reason = "approval_scope_revoked"
        else:
            reason = _admission_issue(db, access, reviewed, plan, state, record, now)

        remaining_ms = min(
            CLAIM_SECONDS * 1000, (plan.expires_at - self._now()) // timedelta(milliseconds=1)
        )
        if reason is None and remaining_ms < 1:
            reason = "approval_expired"
        if reason is not None:
            # An ordered report from the same serialized target proves earlier
            # claims have either been reported or never applied. A claim owned by
            # another agent may still have a result this agent cannot report.
            has_claim = db.execute(
                """SELECT 1 FROM fleet_policy_remote_claims
                   WHERE approval_id = ? AND kind = ? AND target_id = ? AND generation = ?
                     AND agent_id != ? LIMIT 1""",
                (approval_id, *_coordinates(target), grant.agent_id),
            ).fetchone()
            if has_claim is None:
                _set_outcome(db, approval_id, target, "rejected", reason)
            return FleetPolicyOutcome(
                target=target,
                status="pending" if has_claim else "rejected",
                reason=reason,
                conflict_owner="local_operator" if reason == "local_revision_changed" else None,
            ), None

        receipt = FleetPolicyReceipt(
            claim_id=uuid4().hex,
            sequence=request.sequence,
            approval_id=approval_id,
            digest=digest,
            local_revision=request.local.revision,
            effective_digest=revision_id(reviewed.effective.model_dump(mode="json")),
        )
        claim = FleetPolicyClaim(
            **dict(receipt),
            effective=reviewed.effective,
            prior_applied_revision=request.applied_revision,
            prior_applied_approval_id=request.applied_approval_id,
            prior_effective_digest=request.effective_digest,
            expires_at=plan.expires_at,
            valid_for_ms=remaining_ms,
        )
        outcome = FleetPolicyOutcome(target=target, status="pending", reason="awaiting_receipt")
        candidate_reply = FleetPolicySyncReply(
            sequence=request.sequence,
            target=target,
            claim=claim,
            outcome=outcome,
            acknowledged_receipt=request.receipt.claim_id if request.receipt is not None else None,
        )
        if len(candidate_reply.model_dump_json().encode()) > MAX_POLICY_SYNC_BYTES:
            return FleetPolicyOutcome(
                target=target, status="pending", reason="claim_too_large"
            ), None

        db.execute(
            """INSERT INTO fleet_policy_remote_claims
               (id, agent_id, grant_generation, approval_id, kind, target_id, generation,
                sequence, receipt)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                receipt.claim_id,
                grant.agent_id,
                grant.generation,
                approval_id,
                *_coordinates(target),
                request.sequence,
                receipt.model_dump_json(),
            ),
        )
        _set_outcome(db, approval_id, target, "pending", outcome.reason)
        return outcome, claim


def _selected_outcome(
    db: sqlite3.Connection, approval_id: str, target: FleetTarget
) -> sqlite3.Row | None:
    return db.execute(
        """SELECT kind, target_id, generation, status, reason FROM fleet_policy_outcomes
           WHERE approval_id = ? AND kind = ? AND target_id = ? AND generation = ?""",
        (approval_id, *_coordinates(target)),
    ).fetchone()


def _set_outcome(
    db: sqlite3.Connection,
    approval_id: str,
    target: FleetTarget,
    status: str,
    reason: str | None,
) -> None:
    db.execute(
        """UPDATE fleet_policy_outcomes SET status = ?, reason = ?
           WHERE approval_id = ? AND kind = ? AND target_id = ? AND generation = ?
             AND status = 'pending'""",
        (status, reason, approval_id, *_coordinates(target)),
    )


def _settle_receipt(
    db: sqlite3.Connection, agent_id: str, target: FleetTarget, receipt: FleetPolicyReceipt | None
) -> FleetPolicyOutcome | None:
    if receipt is None:
        return None
    row = db.execute(
        """SELECT receipt FROM fleet_policy_remote_claims
           WHERE id = ? AND agent_id = ? AND kind = ? AND target_id = ? AND generation = ?""",
        (receipt.claim_id, agent_id, *_coordinates(target)),
    ).fetchone()
    if row is None or FleetPolicyReceipt.model_validate_json(row["receipt"]) != receipt:
        raise FleetPolicyDenied("receipt does not match a durable policy claim")
    result = _selected_outcome(db, receipt.approval_id, target)
    if result is None or result["status"] == "rejected":
        raise FleetPolicyDenied("receipt does not match an admitted policy outcome")
    _set_outcome(db, receipt.approval_id, target, "applied", None)
    return FleetPolicyOutcome(target=target, status="applied", reason=None)


def _remote_report(
    db: sqlite3.Connection, agent_id: str, request: FleetPolicySyncRequest
) -> sqlite3.Row | None:
    row = db.execute(
        """SELECT sequence, request FROM fleet_policy_remote_reports
           WHERE kind = ? AND target_id = ? AND generation = ? AND agent_id = ?""",
        (*_coordinates(request.local.target), agent_id),
    ).fetchone()
    if (
        row is not None
        and row["sequence"] == request.sequence
        and FleetPolicySyncRequest.model_validate_json(row["request"]) != request
    ):
        raise FleetPolicyDenied("conflicting target policy report for the same sequence")
    return row


def _record_remote_report(
    db: sqlite3.Connection,
    agent_id: str,
    request: FleetPolicySyncRequest,
    previous: sqlite3.Row | None,
    observed: FleetLocalPolicy,
) -> bool:
    if previous is not None and request.sequence <= previous["sequence"]:
        return False

    target = request.local.target
    reported, applied = _report(db, target)
    approval_id = _reported_approval(db, target)
    applied_changed = applied != request.applied_revision or (
        approval_id is not None and approval_id != request.applied_approval_id
    )
    if (
        reported is not None
        and applied_changed
        and (
            request.receipt is None
            or (previous is not None and request.receipt.sequence < previous["sequence"])
        )
    ):
        # A delayed receipt can settle its own outcome without replacing newer
        # current-state reports with the earlier claim's state.
        return False

    if request.applied_approval_id is not None:
        _verify_reported_adoption(db, request)

    db.execute(
        """INSERT INTO fleet_policy_remote_reports
               (kind, target_id, generation, agent_id, sequence, request)
           VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (kind, target_id, generation, agent_id)
           DO UPDATE SET sequence = excluded.sequence, request = excluded.request""",
        (*_coordinates(target), agent_id, request.sequence, request.model_dump_json()),
    )
    _save_report(db, observed, request.applied_revision, request.applied_approval_id)
    return True


def _verify_reported_adoption(db: sqlite3.Connection, request: FleetPolicySyncRequest) -> None:
    row = db.execute(
        """SELECT a.digest FROM fleet_policy_approvals AS a
           JOIN fleet_policy_outcomes AS o ON a.id = o.approval_id
           WHERE a.id = ? AND o.kind = ? AND o.target_id = ? AND o.generation = ?
             AND o.status = 'applied'""",
        (request.applied_approval_id, *_coordinates(request.local.target)),
    ).fetchone()
    if row is not None:
        plan = _load_plan(db, row["digest"])
        reviewed = next(item for item in plan.targets if item.target == request.local.target)
        if (
            reviewed.effective.revision == request.applied_revision
            and revision_id(reviewed.effective.model_dump(mode="json")) == request.effective_digest
        ):
            return
    raise FleetPolicyDenied("target report does not match an applied policy outcome")


def _admission_issue(
    db: sqlite3.Connection,
    access: _Access,
    reviewed: FleetPolicyPlanTarget,
    plan: FleetPolicyPlan,
    state: FleetPolicyTargetState,
    record: sqlite3.Row | None,
    now: datetime,
) -> str | None:
    if access.record is None or access.record.id != plan.revision:
        return "revision_superseded"
    if now >= plan.expires_at:
        return "approval_expired"
    if record is None or not record["available"]:
        return "target_unavailable"
    if not access.allows(reviewed.target, record, write=True):
        return "approval_scope_revoked"
    if reviewed.effective.status != "ready":
        return "review_required"
    local = state.local
    reported, applied = _report(db, local.target)
    if (
        state.applied_revision != reviewed.applied_revision
        or applied != reviewed.applied_revision
        or (
            "applied_approval_id" in reviewed.model_fields_set
            and state.approval_id != reviewed.applied_approval_id
            and (reviewed.applied_approval_id is not None or reviewed.applied_revision is None)
        )
    ):
        return "applied_revision_changed"
    if (
        local.revision != reviewed.local_revision
        or reported is None
        or reported.revision != local.revision
    ):
        return "local_revision_changed"
    desired = access.targets[local.target]
    effective = _resolve(access.record, desired, record, local, reviewed.local_revision, now)
    if effective != reviewed.effective:
        return "effective_policy_changed"
    return None
