"""Coordinator-owned enrollment against verified TLS client key fingerprints."""

from __future__ import annotations

import re
import sqlite3
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from typing import Literal

from pydantic import AwareDatetime, SecretStr, SerializerFunctionWrapHandler, model_serializer

from .fleet_adoption import (
    MAX_ADOPTION_AGE_SECONDS,
    AdoptedLocalProfile,
    PveAdoptionAttachment,
    PveAdoptionView,
    adoption_for_instance,
    adoption_for_route,
    attachment,
    clear_attempt_for_agent,
    invalidate_inventory_head,
    record_projection,
    view_adoption,
)
from .fleet_adoption_models import LocalPveProfile, PveAdoptionEvidence
from .fleet_identity import (
    FleetIdentityConflict,
    FleetIdentityRegistry,
    InventoryObservation,
    PveConnectorRoute,
    _committed_observation,
    _digest,
    _timestamp,
)
from .fleet_policy import FleetTarget, _target_record
from .pve_inventory_models import InventorySnapshot, Projection

FleetCapability = Literal["heartbeat", "pve_inventory", "policy_target", "pve_power_target"]
# SQL identifiers come exclusively from this fixed mapping.
_TARGET_TABLES = {
    "policy_target": ("fleet_policy_target_invitations", "fleet_policy_target_bindings"),
    "pve_power_target": ("fleet_power_target_invitations", "fleet_power_target_bindings"),
}


class FleetEnrollmentConflict(FleetIdentityConflict):
    """Enrollment or authorization failed without exposing credentials."""


class IssuedInvitation(Projection):
    token: SecretStr
    expires_at: AwareDatetime


class FleetGrant(Projection):
    agent_id: str
    host_id: str
    generation: int
    capability: FleetCapability
    route_id: str | None
    target: FleetTarget | None = None

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict:
        values = handler(self)
        if self.target is None:
            values.pop("target", None)
        return values


def _fingerprint(value: str) -> str:
    try:
        return _digest(value)
    except ValueError:
        raise FleetEnrollmentConflict("invalid client key fingerprint") from None


def _generation(value: int) -> None:
    if type(value) is not int or not 0 <= value < 2**63 - 1:
        raise FleetEnrollmentConflict("invalid grant generation")


def _current_agent(db: sqlite3.Connection, agent_id: str, expected_generation: int) -> sqlite3.Row:
    row = db.execute(
        """SELECT a.host_id, h.site_id, COALESCE(g.generation, 0) AS generation
           FROM fleet_agents AS a JOIN fleet_hosts AS h ON h.id = a.host_id
           LEFT JOIN fleet_agent_grants AS g ON g.agent_id = a.id WHERE a.id = ?""",
        (agent_id,),
    ).fetchone()
    if row is None or row["generation"] != expected_generation:
        raise FleetEnrollmentConflict("agent identity or grant generation mismatch")
    return row


def _unused_key(db: sqlite3.Connection, fingerprint: str) -> None:
    if db.execute(
        "SELECT 1 FROM fleet_enrolled_keys WHERE fingerprint = ?", (fingerprint,)
    ).fetchone():
        raise FleetEnrollmentConflict("client key has already been enrolled")


def _advance(
    db: sqlite3.Connection,
    agent_id: str,
    generation: int,
    fingerprint: str | None = None,
    capability: FleetCapability | None = None,
    route_id: str | None = None,
) -> None:
    db.execute(
        """INSERT INTO fleet_agent_grants (agent_id, generation, fingerprint, capability, route_id)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(agent_id) DO UPDATE SET generation = excluded.generation,
               fingerprint = excluded.fingerprint, capability = excluded.capability,
               route_id = excluded.route_id""",
        (agent_id, generation, fingerprint, capability, route_id),
    )
    db.execute("DELETE FROM fleet_invitations WHERE agent_id = ?", (agent_id,))
    clear_attempt_for_agent(db, agent_id)
    db.execute(
        """UPDATE fleet_pve_adoptions SET grant_generation = ?
           WHERE agent_id = ? AND status = 'attached'""",
        (generation, agent_id),
    )


def _authorize(db: sqlite3.Connection, fingerprint: str, capability: FleetCapability) -> FleetGrant:
    row = db.execute(
        """SELECT g.agent_id, a.host_id, g.generation, g.capability, g.route_id
           FROM fleet_agent_grants AS g JOIN fleet_agents AS a ON a.id = g.agent_id
           WHERE g.fingerprint = ? AND g.capability = ?""",
        (fingerprint, capability),
    ).fetchone()
    if row is None:
        raise FleetEnrollmentConflict("client key has no current grant for this capability")
    target = None
    if capability in _TARGET_TABLES:
        _, bindings = _TARGET_TABLES[capability]
        binding = db.execute(
            f"""SELECT kind, target_id AS id, generation FROM {bindings}
               WHERE agent_id = ? AND grant_generation = ?""",  # noqa: S608
            (row["agent_id"], row["generation"]),
        ).fetchone()
        if binding is None:
            raise FleetEnrollmentConflict("client key has no current target binding")
        target = FleetTarget(**dict(binding))
    grant = FleetGrant(**dict(row), target=target)
    if capability == "pve_power_target":
        assert target is not None
        if grant.route_id is None or grant.route_id != power_target_route(
            db, target, grant.host_id
        ):
            raise FleetEnrollmentConflict("power target has no current confirmed route")
    return grant


def policy_target_grant(
    db: sqlite3.Connection, fingerprint: str, target: FleetTarget
) -> FleetGrant:
    """Check the current TLS key and its exact scope in the caller's transaction."""
    grant = _authorize(db, _fingerprint(fingerprint), "policy_target")
    if grant.target != target:
        raise FleetEnrollmentConflict("client key has no current grant for this target")
    return grant


def power_target_grant(db: sqlite3.Connection, fingerprint: str, target: FleetTarget) -> FleetGrant:
    grant = _authorize(db, _fingerprint(fingerprint), "pve_power_target")
    if grant.target != target:
        raise FleetEnrollmentConflict("client key has no current grant for this target")
    return grant


def power_target_route(db: sqlite3.Connection, target: FleetTarget, host_id: str) -> str | None:
    if target.kind != "pve_guest":
        return None
    route = db.execute(
        """SELECT r.id FROM fleet_guests AS g
           JOIN fleet_instances AS i ON i.id = g.instance_id AND i.kind = 'standalone'
           JOIN fleet_routes AS r ON r.instance_id = i.id AND r.node = g.node
           JOIN fleet_route_addresses AS a ON a.route_id = r.id
           LEFT JOIN fleet_pve_adoptions AS d ON d.route_id = r.id
           WHERE g.id = ? AND g.generation = ? AND r.host_id = ?
             AND (d.status IS NULL OR d.status != 'detached')""",
        (target.id, target.generation, host_id),
    ).fetchone()
    return route["id"] if route is not None else None


def policy_target_bound(db: sqlite3.Connection, target: FleetTarget) -> bool:
    row = db.execute(
        """SELECT 1 FROM fleet_policy_target_bindings
           WHERE kind = ? AND target_id = ? AND generation = ?""",
        (target.kind, target.id, target.generation),
    ).fetchone()
    return row is not None


def _policy_target_route(db: sqlite3.Connection, target: FleetTarget, host_id: str) -> str | None:
    instance_id = target.id
    if target.kind == "pve_guest":
        guest = db.execute(
            "SELECT instance_id FROM fleet_guests WHERE id = ? AND generation = ?",
            (target.id, target.generation),
        ).fetchone()
        if guest is None:
            return None
        instance_id = guest["instance_id"]
    route = db.execute(
        """SELECT r.id FROM fleet_routes AS r
           JOIN fleet_route_addresses AS a ON a.route_id = r.id
           WHERE r.instance_id = ? AND r.host_id = ?""",
        (instance_id, host_id),
    ).fetchone()
    return route["id"] if route is not None else None


def _require_target_binding(
    db: sqlite3.Connection,
    target: FleetTarget,
    agent_id: str,
    host_id: str,
    capability: FleetCapability,
) -> str | None:
    route = None
    if capability == "pve_power_target":
        route = power_target_route(db, target, host_id)
        record = _target_record(db, target)
        matches = route is not None and record is not None and record["available"]
    elif target.kind == "host":
        matches = target.id == host_id
    else:
        matches = _policy_target_route(db, target, host_id) is not None
    if not matches:
        raise FleetEnrollmentConflict("target does not belong to the agent's registered host")
    _, bindings = _TARGET_TABLES[capability]
    other = db.execute(
        f"""SELECT 1 FROM {bindings} AS b
           WHERE (b.agent_id = ? AND (b.kind, b.target_id, b.generation) != (?, ?, ?))
              OR ((b.kind, b.target_id, b.generation) = (?, ?, ?) AND b.agent_id != ?)""",  # noqa: S608
        (
            agent_id,
            target.kind,
            target.id,
            target.generation,
            target.kind,
            target.id,
            target.generation,
            agent_id,
        ),
    ).fetchone()
    if other is not None:
        raise FleetEnrollmentConflict("target and agent already have an authoritative binding")
    return route


def _require_separate_power_agent(
    db: sqlite3.Connection, agent_id: str, capability: FleetCapability
) -> None:
    previous = db.execute(
        "SELECT 1 FROM fleet_agent_grants WHERE agent_id = ?", (agent_id,)
    ).fetchone()
    power_agent = db.execute(
        "SELECT 1 FROM fleet_power_target_bindings WHERE agent_id = ?", (agent_id,)
    ).fetchone()
    if (power_agent and capability != "pve_power_target") or (
        capability == "pve_power_target" and previous is not None and not power_agent
    ):
        raise FleetEnrollmentConflict("power targets require a separate agent")


def policy_target_active(db: sqlite3.Connection, target: FleetTarget, host_id: str) -> bool:
    record = _target_record(db, target)
    if record is None or not record["available"]:
        return False
    if target.kind == "host":
        return target.id == host_id
    route_id = _policy_target_route(db, target, host_id)
    if route_id is None:
        return False
    adoption = adoption_for_route(db, route_id)
    return adoption is None or adoption["status"] != "detached"


def _require_live_route(db: sqlite3.Connection, route_id: str) -> None:
    row = adoption_for_route(db, route_id)
    if row is not None and row["status"] == "detached":
        raise FleetEnrollmentConflict("standalone route is detached")


def _require_rejoin_agent(db: sqlite3.Connection, route_id: str | None, agent_id: str) -> None:
    if route_id is not None:
        row = adoption_for_route(db, route_id)
        if row is not None and row["status"] == "detached" and row["agent_id"] != agent_id:
            raise FleetEnrollmentConflict("detached route requires the original connector")


class FleetEnrollment:
    """Issue grants locally and redeem them using the key authenticated by TLS."""

    def __init__(self, registry: FleetIdentityRegistry):
        self._registry = registry

    def issue(
        self,
        agent_id: str,
        *,
        key_fingerprint: str,
        capability: FleetCapability,
        route_id: str | None = None,
        target: FleetTarget | None = None,
        expected_generation: int = 0,
        ttl_seconds: int = 600,
        now: datetime | None = None,
    ) -> IssuedInvitation:
        fingerprint = _fingerprint(key_fingerprint)
        _generation(expected_generation)
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 900:
            raise FleetEnrollmentConflict("invitation lifetime must be between 1 and 900 seconds")
        if (
            capability not in ("heartbeat", "pve_inventory", *_TARGET_TABLES)
            or (route_id is not None) != (capability == "pve_inventory")
            or (target is not None) != (capability in _TARGET_TABLES)
            or (target is not None and not isinstance(target, FleetTarget))
        ):
            raise FleetEnrollmentConflict("invitation requires one capability with its exact scope")
        token = token_urlsafe(32)
        token_hash = sha256(token.encode("ascii")).hexdigest()
        with self._registry._write() as db:
            issued = now if now is not None else datetime.now(UTC)
            timestamp = _timestamp(issued)
            expires_at = issued.astimezone(UTC) + timedelta(seconds=ttl_seconds)
            agent = _current_agent(db, agent_id, expected_generation)
            _unused_key(db, fingerprint)
            _require_separate_power_agent(db, agent_id, capability)
            if (
                route_id is not None
                and db.execute(
                    """SELECT 1 FROM fleet_routes AS r
                   JOIN fleet_route_addresses AS a ON a.route_id = r.id
                   JOIN fleet_hosts AS h ON h.id = r.host_id
                   WHERE r.id = ? AND h.site_id = ?""",
                    (route_id, agent["site_id"]),
                ).fetchone()
                is None
            ):
                raise FleetEnrollmentConflict("connector requires a confirmed route in its site")
            _require_rejoin_agent(db, route_id, agent_id)
            db.execute("DELETE FROM fleet_invitations WHERE expires_at <= ?", (timestamp,))
            if target is not None:
                route_id = _require_target_binding(
                    db, target, agent_id, agent["host_id"], capability
                )
                invitations, _ = _TARGET_TABLES[capability]
                waiting = db.execute(
                    f"""SELECT 1 FROM {invitations} AS b
                       JOIN fleet_invitations AS i ON i.token_hash = b.token_hash
                       WHERE b.kind = ? AND b.target_id = ? AND b.generation = ?
                         AND i.agent_id != ?""",  # noqa: S608
                    (target.kind, target.id, target.generation, agent_id),
                ).fetchone()
                if waiting is not None:
                    raise FleetEnrollmentConflict("target already has an outstanding invitation")
            db.execute(
                """INSERT INTO fleet_invitations
                   (token_hash, agent_id, expected_generation, fingerprint, capability,
                    route_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    token_hash,
                    agent_id,
                    expected_generation,
                    fingerprint,
                    capability,
                    route_id,
                    _timestamp(expires_at),
                ),
            )
            if target is not None:
                db.execute(
                    f"INSERT INTO {invitations} VALUES (?, ?, ?, ?)",  # noqa: S608
                    (token_hash, target.kind, target.id, target.generation),
                )
        return IssuedInvitation(token=SecretStr(token), expires_at=expires_at)

    def redeem(
        self, token: str, *, key_fingerprint: str, now: datetime | None = None
    ) -> FleetGrant:
        fingerprint = _fingerprint(key_fingerprint)
        if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
            raise FleetEnrollmentConflict(
                "invitation invalid, expired, or unavailable for this key"
            )
        token_hash = sha256(token.encode("ascii")).hexdigest()
        with self._registry._write() as db:
            timestamp = _timestamp(now if now is not None else datetime.now(UTC))
            invite = db.execute(
                """SELECT agent_id, expected_generation, capability, route_id
                   FROM fleet_invitations
                   WHERE token_hash = ? AND fingerprint = ? AND expires_at > ?""",
                (token_hash, fingerprint, timestamp),
            ).fetchone()
            if invite is None:
                raise FleetEnrollmentConflict(
                    "invitation invalid, expired, or unavailable for this key"
                )
            agent_id = invite["agent_id"]
            agent = _current_agent(db, agent_id, invite["expected_generation"])
            _unused_key(db, fingerprint)
            _require_rejoin_agent(db, invite["route_id"], agent_id)
            target = None
            capability = invite["capability"]
            _require_separate_power_agent(db, agent_id, capability)
            if capability in _TARGET_TABLES:
                invitations, bindings = _TARGET_TABLES[capability]
                binding = db.execute(
                    f"""SELECT kind, target_id AS id, generation FROM {invitations}
                       WHERE token_hash = ?""",  # noqa: S608
                    (token_hash,),
                ).fetchone()
                if binding is None:
                    raise FleetEnrollmentConflict("invitation has no target binding")
                target = FleetTarget(**dict(binding))
                route_id = _require_target_binding(
                    db, target, agent_id, agent["host_id"], capability
                )
                if route_id != invite["route_id"]:
                    raise FleetEnrollmentConflict("target binding route changed")
            generation = agent["generation"] + 1
            db.execute("INSERT INTO fleet_enrolled_keys VALUES (?)", (fingerprint,))
            _advance(
                db, agent_id, generation, fingerprint, invite["capability"], invite["route_id"]
            )
            if target is not None:
                db.execute(
                    f"""INSERT INTO {bindings} VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(agent_id) DO UPDATE
                       SET grant_generation = excluded.grant_generation""",  # noqa: S608
                    (agent_id, generation, target.kind, target.id, target.generation),
                )
            grant = _authorize(db, fingerprint, invite["capability"])
        return grant

    def revoke(self, agent_id: str, *, expected_generation: int) -> int:
        _generation(expected_generation)
        with self._registry._write() as db:
            agent = _current_agent(db, agent_id, expected_generation)
            generation = agent["generation"] + 1
            _advance(db, agent_id, generation)
        return generation

    def authorize(self, key_fingerprint: str, *, capability: FleetCapability) -> FleetGrant:
        fingerprint = _fingerprint(key_fingerprint)
        with self._registry._connection() as db:
            db.execute("BEGIN")
            grant = _authorize(db, fingerprint, capability)
            if grant.route_id is not None:
                _require_live_route(db, grant.route_id)
            return grant

    def _connector_scope(
        self, db: sqlite3.Connection, fingerprint: str
    ) -> tuple[FleetGrant, PveConnectorRoute]:
        grant = _authorize(db, fingerprint, "pve_inventory")
        route = self._registry._connector_route(db, grant.route_id) if grant.route_id else None
        if route is None:
            raise FleetEnrollmentConflict("connector grant has no confirmed route")
        _require_live_route(db, route.route_id)
        return grant, route

    def connector_route(self, key_fingerprint: str) -> tuple[FleetGrant, PveConnectorRoute]:
        fingerprint = _fingerprint(key_fingerprint)
        with self._registry._connection() as db:
            db.execute("BEGIN")
            return self._connector_scope(db, fingerprint)

    def publish_inventory(
        self, key_fingerprint: str, *, generation: int, snapshot: InventorySnapshot
    ) -> InventoryObservation:
        fingerprint = _fingerprint(key_fingerprint)
        _generation(generation)
        with self._registry._write() as db:
            grant, route = self._connector_scope(db, fingerprint)
            if grant.generation != generation:
                raise FleetEnrollmentConflict("connector grant generation mismatch")
            observation = self._registry._ingest_snapshot(
                db,
                snapshot,
                route_id=route.route_id,
                transport_fingerprint=route.transport_fingerprint,
                instance_binding=route.instance_binding,
            )
            invalidate_inventory_head(db, route.route_id, _timestamp(snapshot.observed_at))
        return _committed_observation(observation)

    def adopt_pve(
        self,
        *,
        instance_id: str,
        route_id: str,
        agent_id: str,
        expected_generation: int,
        instance_binding: str,
        local_profile: LocalPveProfile | None = None,
    ) -> PveAdoptionAttachment:
        _generation(expected_generation)
        binding = _digest(instance_binding)
        with self._registry._write() as db:
            route = self._registry._connector_route(db, route_id)
            if (
                route is None
                or route.kind != "standalone"
                or route.instance_id != instance_id
                or route.instance_binding != binding
            ):
                raise FleetEnrollmentConflict("adoption requires the approved standalone route")
            if local_profile is not None and (
                local_profile.node != route.node
                or local_profile.instance_binding != binding
                or local_profile.observed_at > datetime.now(UTC)
            ):
                raise FleetEnrollmentConflict("local profile does not match the approved route")
            agent = _current_agent(db, agent_id, expected_generation)
            enrolled = db.execute(
                """SELECT 1 FROM fleet_agent_grants AS g JOIN fleet_hosts AS h ON h.id = ?
                   WHERE g.agent_id = ? AND g.route_id = ? AND g.capability = 'pve_inventory'
                     AND g.fingerprint IS NOT NULL AND h.site_id = ?""",
                (route.host_id, agent_id, route_id, agent["site_id"]),
            ).fetchone()
            if enrolled is None:
                raise FleetEnrollmentConflict("adoption requires a current grant for its route")
            profile = (
                AdoptedLocalProfile.model_validate(
                    local_profile.model_dump(exclude={"instance_binding"})
                ).model_dump_json()
                if local_profile is not None
                else None
            )
            prior = adoption_for_route(db, route_id)
            if prior is None:
                db.execute(
                    """INSERT INTO fleet_pve_adoptions
                       (instance_id, route_id, agent_id, revision,
                        status, grant_generation, local_profile)
                       VALUES (?, ?, ?, 1, 'attached', ?, ?)""",
                    (instance_id, route_id, agent_id, expected_generation, profile),
                )
            else:
                if (
                    prior["status"] != "detached"
                    or prior["agent_id"] != agent_id
                    or prior["grant_generation"] >= expected_generation
                ):
                    raise FleetEnrollmentConflict(
                        "rejoin requires the original adoption and freshly enrolled connector"
                    )
                db.execute(
                    """UPDATE fleet_pve_adoptions SET status = 'attached',
                       revision = revision + 1, grant_generation = ?, local_profile = ?
                       WHERE instance_id = ?""",
                    (expected_generation, profile, instance_id),
                )
            return attachment(adoption_for_instance(db, instance_id))

    def detach_pve(self, instance_id: str, *, expected_revision: int) -> PveAdoptionAttachment:
        with self._registry._write() as db:
            row = adoption_for_instance(db, instance_id)
            if (
                type(expected_revision) is not int
                or row["revision"] != expected_revision
                or row["status"] != "attached"
            ):
                raise FleetEnrollmentConflict("adoption attachment revision mismatch")
            grants = db.execute(
                "SELECT agent_id, generation FROM fleet_agent_grants WHERE route_id = ?",
                (row["route_id"],),
            ).fetchall()
            for grant in grants:
                _generation(grant["generation"])
                _advance(db, grant["agent_id"], grant["generation"] + 1)
            db.execute("DELETE FROM fleet_invitations WHERE route_id = ?", (row["route_id"],))
            clear_attempt_for_agent(db, row["agent_id"])
            db.execute(
                """UPDATE fleet_pve_adoptions SET status = 'detached',
                   revision = revision + 1, local_profile = NULL,
                   grant_generation = (
                       SELECT generation FROM fleet_agent_grants WHERE agent_id = ?
                   ) WHERE instance_id = ?""",
                (row["agent_id"], instance_id),
            )
            return attachment(adoption_for_instance(db, instance_id))

    def show_adoption(
        self, instance_id: str, *, history: bool = False, now: datetime | None = None
    ) -> PveAdoptionView:
        with self._registry._connection() as db:
            db.execute("BEGIN")
            return view_adoption(
                db,
                adoption_for_instance(db, instance_id),
                history=history,
                now=now if now is not None else datetime.now(UTC),
            )

    def _adoption_scope(
        self, db: sqlite3.Connection, fingerprint: str
    ) -> tuple[FleetGrant, PveConnectorRoute, sqlite3.Row]:
        grant, route = self._connector_scope(db, fingerprint)
        row = adoption_for_route(db, route.route_id)
        if row is None or row["agent_id"] != grant.agent_id:
            raise FleetEnrollmentConflict("connector grant does not match an active adoption")
        return grant, route, row

    def begin_adoption(
        self, key_fingerprint: str, *, now: datetime | None = None
    ) -> tuple[FleetGrant, PveConnectorRoute, int]:
        fingerprint = _fingerprint(key_fingerprint)
        with self._registry._write() as db:
            grant, route, row = self._adoption_scope(db, fingerprint)
            _generation(row["attempt"])
            attempt = row["attempt"] + 1
            db.execute(
                """UPDATE fleet_pve_adoptions SET attempt = ?, attempt_at = ?,
                   attempt_generation = ?, attempt_fingerprint = ?,
                   head_observation = NULL, current_projection = NULL WHERE route_id = ?""",
                (
                    attempt,
                    _timestamp(now if now is not None else datetime.now(UTC)),
                    grant.generation,
                    fingerprint,
                    route.route_id,
                ),
            )
        return grant, route, attempt

    def publish_adoption(
        self,
        key_fingerprint: str,
        *,
        generation: int,
        attempt: int,
        snapshot: InventorySnapshot,
        evidence: PveAdoptionEvidence,
        now: datetime | None = None,
    ) -> InventoryObservation:
        fingerprint = _fingerprint(key_fingerprint)
        _generation(generation)
        if type(attempt) is not int or attempt < 1:
            raise FleetEnrollmentConflict("invalid adoption attempt")
        with self._registry._write() as db:
            grant, route, row = self._adoption_scope(db, fingerprint)
            if (
                grant.generation != generation
                or row["attempt_generation"] != generation
                or row["attempt_fingerprint"] != fingerprint
                or row["attempt"] != attempt
                or row["attempt_at"] is None
                or row["head_observation"] is not None
            ):
                raise FleetEnrollmentConflict("adoption requires a fresh current attempt")
            received = now if now is not None else datetime.now(UTC)
            received_at = _timestamp(received)
            observed_at = _timestamp(snapshot.observed_at)
            if (
                not row["attempt_at"] <= observed_at <= received_at
                or received - datetime.fromisoformat(row["attempt_at"])
                > timedelta(seconds=MAX_ADOPTION_AGE_SECONDS)
                or evidence.observed_at != snapshot.observed_at
                or evidence.node != route.node
                or snapshot.evidence.source != "cluster_resources"
                or snapshot.evidence.state not in ("observed", "absent")
            ):
                raise FleetEnrollmentConflict("adoption requires fresh matching evidence")
            newer = db.execute(
                """SELECT 1 FROM fleet_observations WHERE route_id = ? AND observed_at >= ?
                   LIMIT 1""",
                (route.route_id, observed_at),
            ).fetchone()
            if newer is not None:
                raise FleetEnrollmentConflict("adoption publication requires a new observation")
            observation = self._registry._ingest_snapshot(
                db,
                snapshot,
                route_id=route.route_id,
                transport_fingerprint=route.transport_fingerprint,
                instance_binding=route.instance_binding,
                received_at=received,
            )
            if observation is not None:
                record_projection(db, observation, snapshot, evidence)
        return _committed_observation(observation)
