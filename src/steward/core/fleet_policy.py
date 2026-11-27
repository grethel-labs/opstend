"""Revisioned fleet policy and read-only resolution against local safety limits."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Annotated, Literal, get_args

from pydantic import (
    AfterValidator,
    Field,
    PlainSerializer,
    StringConstraints,
    field_validator,
    model_validator,
)

from .canonical import canonical_json, revision_id
from .config import SecretRef
from .fleet_identity import FleetIdentityRegistry
from .maintenance import parse_window_spec
from .pve_inventory_models import Projection, TimedProjection
from .store import ConflictError

RegistryId = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]
_REVISION_PATTERN = r"^[a-f0-9]{64}$"
RevisionId = Annotated[str, StringConstraints(pattern=_REVISION_PATTERN)]
PolicyName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")]
TargetKind = Literal["host", "pve_instance", "pve_guest"]
PolicyProperty = Literal[
    "maintenance_windows", "role_assignments", "credential_refs", "backup_profile_refs"
]
Scope = Literal["fleet", "site", "group", "target"]
IssueCode = Literal[
    "group_conflict",
    "fleet_limit",
    "local_limit",
    "local_unknown",
    "local_stale",
    "target_unavailable",
]
_LOCAL_MAX_AGE = timedelta(seconds=300)


class FleetTarget(Projection):
    kind: TargetKind
    id: RegistryId
    generation: Annotated[int, Field(ge=1, le=2**63 - 1)] = 1

    @model_validator(mode="after")
    def _validate_generation(self) -> FleetTarget:
        if self.kind != "pve_guest" and self.generation != 1:
            raise ValueError("only guest targets can have a generation other than one")
        if self.kind == "pve_guest" and "generation" not in self.model_fields_set:
            raise ValueError("guest targets require an explicit generation")
        return self


class RoleAssignment(Projection):
    subject: PolicyName
    role: Literal["observer", "operator", "backup_verifier", "planner", "executor"]


class FleetPolicyValues(Projection):
    maintenance_windows: tuple[Annotated[str, StringConstraints(max_length=128)], ...] = ()
    role_assignments: tuple[RoleAssignment, ...] = ()
    credential_refs: tuple[SecretRef, ...] = ()
    backup_profile_refs: tuple[PolicyName, ...] = ()

    @field_validator("maintenance_windows")
    @classmethod
    def _normalize_windows(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            parse_window_spec(value)
        return tuple(sorted(set(values)))

    @field_validator("credential_refs", "backup_profile_refs")
    @classmethod
    def _normalize_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(values)))

    @field_validator("role_assignments")
    @classmethod
    def _normalize_roles(cls, values: tuple[RoleAssignment, ...]) -> tuple[RoleAssignment, ...]:
        return tuple(sorted(set(values), key=lambda value: (value.subject, value.role)))


class FleetTargetPolicy(Projection):
    target: FleetTarget
    group_ids: tuple[PolicyName, ...] = ()
    exception: FleetPolicyValues = FleetPolicyValues()

    @field_validator("group_ids")
    @classmethod
    def _normalize_groups(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(values)))


class FleetPolicy(Projection):
    """Desired scopes and ceilings.

    Serialize with exclude_unset=True to preserve sparse overrides on reimport.
    """

    defaults: FleetPolicyValues = FleetPolicyValues()
    limits: FleetPolicyValues = FleetPolicyValues()
    sites: Annotated[
        Mapping[RegistryId, FleetPolicyValues],
        AfterValidator(MappingProxyType),
        PlainSerializer(dict, return_type=dict[str, FleetPolicyValues]),
    ] = Field(default_factory=lambda: MappingProxyType({}))
    groups: Annotated[
        Mapping[PolicyName, FleetPolicyValues],
        AfterValidator(MappingProxyType),
        PlainSerializer(dict, return_type=dict[str, FleetPolicyValues]),
    ] = Field(default_factory=lambda: MappingProxyType({}))
    targets: tuple[FleetTargetPolicy, ...] = ()

    @field_validator("targets")
    @classmethod
    def _normalize_targets(
        cls, values: tuple[FleetTargetPolicy, ...]
    ) -> tuple[FleetTargetPolicy, ...]:
        if len({value.target for value in values}) != len(values):
            raise ValueError("target policy is configured more than once")
        return tuple(
            sorted(
                values, key=lambda item: (item.target.kind, item.target.id, item.target.generation)
            )
        )

    @model_validator(mode="after")
    def _validate_groups(self) -> FleetPolicy:
        if any(group not in self.groups for item in self.targets for group in item.group_ids):
            raise ValueError("target policy references an unknown group")
        return self


class FleetLocalPolicy(TimedProjection):
    target: FleetTarget
    revision: RevisionId
    limits: FleetPolicyValues = FleetPolicyValues()


class FleetPolicyRevision(Projection):
    id: RevisionId
    parent: RevisionId | None
    policy: FleetPolicy

    def export(self) -> str:
        """Serialize the revision while preserving sparse policy overrides."""
        return canonical_json(self.model_dump(mode="json", exclude_unset=True))


class FleetPolicySource(Projection):
    scope: Scope
    id: str | None = None


class FleetPolicyIssue(Projection):
    code: IssueCode
    property: PolicyProperty | None = None
    scope_ids: tuple[str, ...] = ()


class EffectiveFleetPolicy(Projection):
    revision: RevisionId
    target: FleetTarget
    values: FleetPolicyValues
    provenance: Annotated[
        Mapping[PolicyProperty, tuple[FleetPolicySource, ...]],
        AfterValidator(MappingProxyType),
        PlainSerializer(dict, return_type=dict[PolicyProperty, tuple[FleetPolicySource, ...]]),
    ]
    status: Literal["ready", "pending"]
    issues: tuple[FleetPolicyIssue, ...]


class FleetPolicyConflict(ConflictError):
    """The supplied parent is no longer the fleet policy head."""


def _target_record(db: sqlite3.Connection, target: FleetTarget) -> sqlite3.Row | None:
    match target.kind:
        case "host":
            query = "SELECT site_id, 1 AS available FROM fleet_hosts WHERE id = ?"
            params = (target.id,)
        case "pve_instance":
            query = "SELECT site_id, 1 AS available FROM fleet_instances WHERE id = ?"
            params = (target.id,)
        case "pve_guest":
            query = """
                SELECT i.site_id, g.state = 'present' AND NOT o.disputed AS available
                FROM fleet_guests AS g JOIN fleet_instances AS i ON i.id = g.instance_id
                JOIN fleet_observations AS o ON o.id = g.observation_id
                WHERE g.id = ? AND g.generation = ?
            """
            params = (target.id, target.generation)
    return db.execute(query, params).fetchone()


def _head(db: sqlite3.Connection) -> str | None:
    row = db.execute("SELECT revision FROM fleet_policy_head WHERE singleton = 1").fetchone()
    return None if row is None else row["revision"]


def _get_revision(db: sqlite3.Connection, revision: str) -> FleetPolicyRevision | None:
    row = db.execute(
        "SELECT parent, body FROM fleet_policy_revisions WHERE id = ?", (revision,)
    ).fetchone()
    if row is None:
        return None
    return FleetPolicyRevision(
        id=revision, parent=row["parent"], policy=FleetPolicy.model_validate_json(row["body"])
    )


def _local_issue(
    local: FleetLocalPolicy | None, target: FleetTarget, expected: str | None, now: datetime
) -> IssueCode | None:
    if (
        local is None
        or local.target != target
        or expected is None
        or not re.fullmatch(_REVISION_PATTERN, expected)
        or local.revision != expected
    ):
        return "local_unknown"
    if not timedelta() <= now - local.observed_at <= _LOCAL_MAX_AGE:
        return "local_stale"
    return None


def _resolve(
    record: FleetPolicyRevision,
    desired: FleetTargetPolicy,
    target_record: sqlite3.Row | None,
    local: FleetLocalPolicy | None,
    expected_local_revision: str | None,
    now: datetime,
) -> EffectiveFleetPolicy:
    policy = record.policy
    target = desired.target
    site_id = None if target_record is None else target_record["site_id"]
    site = policy.sites.get(site_id)
    values = {}
    provenance = {}
    issues = []
    if target_record is None or not target_record["available"]:
        issues.append(FleetPolicyIssue(code="target_unavailable", scope_ids=(target.id,)))
    local_issue = _local_issue(local, target, expected_local_revision, now)
    if local_issue:
        issues.append(FleetPolicyIssue(code=local_issue, scope_ids=(target.id,)))

    for field in get_args(PolicyProperty):
        value = getattr(policy.defaults, field)
        sources = (FleetPolicySource(scope="fleet"),)
        if site is not None and field in site.model_fields_set:
            value = getattr(site, field)
            sources = (FleetPolicySource(scope="site", id=site_id),)

        proposals = {
            group: getattr(policy.groups[group], field)
            for group in desired.group_ids
            if field in policy.groups[group].model_fields_set
        }
        if len(set(proposals.values())) > 1:
            issues.append(
                FleetPolicyIssue(code="group_conflict", property=field, scope_ids=tuple(proposals))
            )
            continue
        if proposals:
            value = next(iter(proposals.values()))
            sources = tuple(FleetPolicySource(scope="group", id=group) for group in proposals)
        if field in desired.exception.model_fields_set:
            value = getattr(desired.exception, field)
            sources = (FleetPolicySource(scope="target", id=target.id),)

        values[field] = value
        provenance[field] = sources
        source_ids = tuple(source.id for source in sources if source.id is not None)
        if not set(value).issubset(getattr(policy.limits, field)):
            issues.append(
                FleetPolicyIssue(code="fleet_limit", property=field, scope_ids=source_ids)
            )
        if (
            local_issue is None
            and local is not None
            and not set(value).issubset(getattr(local.limits, field))
        ):
            issues.append(
                FleetPolicyIssue(code="local_limit", property=field, scope_ids=(target.id,))
            )

    return EffectiveFleetPolicy(
        revision=record.id,
        target=target,
        values=FleetPolicyValues(**values),
        provenance=provenance,
        status="pending" if issues else "ready",
        issues=tuple(issues),
    )


class FleetPolicyStore:
    """Store immutable fleet policy revisions in the coordinator's registry."""

    def __init__(self, registry: FleetIdentityRegistry):
        self._registry = registry

    def head(self) -> str | None:
        with self._registry._connection() as db:
            return _head(db)

    def get_revision(self, revision: str) -> FleetPolicyRevision | None:
        with self._registry._connection() as db:
            return _get_revision(db, revision)

    def commit(self, policy: FleetPolicy, *, parent: str | None) -> FleetPolicyRevision:
        with self._registry._write() as db:
            head = _head(db)
            if parent != head:
                raise FleetPolicyConflict(head)

            # Revalidate caller-supplied models and hash exactly the normalized stored body.
            policy = FleetPolicy.model_validate_json(policy.model_dump_json(exclude_unset=True))
            body = policy.model_dump(mode="json", exclude_unset=True)
            for site in policy.sites:
                if db.execute("SELECT 1 FROM fleet_sites WHERE id = ?", (site,)).fetchone() is None:
                    raise ValueError("policy references an unknown site")
            for item in policy.targets:
                if _target_record(db, item.target) is None:
                    raise ValueError("policy references an unknown target generation")

            revision = revision_id({"parent": parent, "policy": body})
            db.execute(
                "INSERT INTO fleet_policy_revisions (id, parent, body) VALUES (?, ?, ?)",
                (revision, parent, canonical_json(body)),
            )
            db.execute(
                """INSERT INTO fleet_policy_head (singleton, revision) VALUES (1, ?)
                   ON CONFLICT(singleton) DO UPDATE SET revision = excluded.revision""",
                (revision,),
            )
            return FleetPolicyRevision(id=revision, parent=parent, policy=policy)

    def effective(
        self,
        revision: str,
        target: FleetTarget,
        *,
        local: FleetLocalPolicy | None = None,
        expected_local_revision: str | None = None,
        now: datetime | None = None,
    ) -> EffectiveFleetPolicy | None:
        """Preview desired values and issues for a later admission decision.

        expected_local_revision must come from independently trusted local applied state.
        Return None for an unknown revision or a target outside that revision.
        """
        if now is None:
            now = datetime.now(UTC)
        elif now.utcoffset() is None:
            raise ValueError("fleet policy clock must be timezone-aware")
        now = now.astimezone(UTC)
        with self._registry._connection() as db:
            db.execute("BEGIN")
            record = _get_revision(db, revision)
            if record is None:
                return None
            desired = next((item for item in record.policy.targets if item.target == target), None)
            if desired is None:
                return None
            return _resolve(
                record, desired, _target_record(db, target), local, expected_local_revision, now
            )
