"""Coordinator-owned enrollment against verified TLS client key fingerprints."""

from __future__ import annotations

import re
import sqlite3
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from typing import Literal

from pydantic import AwareDatetime, SecretStr

from .fleet_identity import (
    FleetIdentityConflict,
    FleetIdentityRegistry,
    InventoryObservation,
    PveConnectorRoute,
    _committed_observation,
    _digest,
    _timestamp,
)
from .pve_inventory_models import InventorySnapshot, Projection

FleetCapability = Literal["heartbeat", "pve_inventory"]


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


def _authorize(db: sqlite3.Connection, fingerprint: str, capability: FleetCapability) -> FleetGrant:
    row = db.execute(
        """SELECT g.agent_id, a.host_id, g.generation, g.capability, g.route_id
           FROM fleet_agent_grants AS g JOIN fleet_agents AS a ON a.id = g.agent_id
           WHERE g.fingerprint = ? AND g.capability = ?""",
        (fingerprint, capability),
    ).fetchone()
    if row is None:
        raise FleetEnrollmentConflict("client key has no current grant for this capability")
    return FleetGrant(**dict(row))


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
        expected_generation: int = 0,
        ttl_seconds: int = 600,
        now: datetime | None = None,
    ) -> IssuedInvitation:
        fingerprint = _fingerprint(key_fingerprint)
        _generation(expected_generation)
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 900:
            raise FleetEnrollmentConflict("invitation lifetime must be between 1 and 900 seconds")
        if capability not in ("heartbeat", "pve_inventory") or (route_id is None) != (
            capability == "heartbeat"
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
            db.execute("DELETE FROM fleet_invitations WHERE expires_at <= ?", (timestamp,))
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
            generation = agent["generation"] + 1
            db.execute("INSERT INTO fleet_enrolled_keys VALUES (?)", (fingerprint,))
            _advance(
                db, agent_id, generation, fingerprint, invite["capability"], invite["route_id"]
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
            return _authorize(db, fingerprint, capability)

    def _connector_scope(
        self, db: sqlite3.Connection, fingerprint: str
    ) -> tuple[FleetGrant, PveConnectorRoute]:
        grant = _authorize(db, fingerprint, "pve_inventory")
        route = self._registry._connector_route(db, grant.route_id) if grant.route_id else None
        if route is None:
            raise FleetEnrollmentConflict("connector grant has no confirmed route")
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
        return _committed_observation(observation)
