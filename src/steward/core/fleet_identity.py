"""Private coordinator registry for fleet identity and qualified PVE inventory."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import AwareDatetime, field_validator

from .pve_inventory_models import (
    EvidenceSource,
    EvidenceState,
    Guest,
    GuestKind,
    InventorySnapshot,
    NodeName,
    Projection,
    Vmid,
)
from .pve_native import PreflightError, _validate_api_name

InstanceKind = Literal["standalone", "cluster"]
Coverage = Literal["token_scope", "full_guest_coverage"]
GuestState = Literal["present", "missing", "continuity_required", "replaced"]


class FleetIdentityConflict(ValueError):
    """The requested identity change conflicts with coordinator evidence."""


class SiteIdentity(Projection):
    id: str
    name: str


class HostIdentity(SiteIdentity):
    site_id: str


class AgentIdentity(SiteIdentity):
    host_id: str


class PveInstanceIdentity(Projection):
    id: str
    site_id: str
    kind: InstanceKind


class PveRouteIdentity(Projection):
    id: str
    instance_id: str
    host_id: str
    api_name: str
    node: NodeName


class PveConnectorRoute(Projection):
    route_id: str
    instance_id: str
    host_id: str
    api_name: str
    node: NodeName
    kind: InstanceKind
    instance_binding: str
    transport_fingerprint: str
    address: str

    @field_validator("address")
    @classmethod
    def canonical_address(cls, address: str) -> str:
        return _numeric_address(address)


class InventoryObservation(Projection):
    id: str
    instance_id: str
    route_id: str
    observed_at: AwareDatetime
    received_at: AwareDatetime
    coverage: Coverage
    source: EvidenceSource
    state: EvidenceState
    disputed: bool = False


class GuestIdentity(Projection):
    id: str
    instance_id: str
    kind: GuestKind
    vmid: Vmid
    generation: int
    node: NodeName
    name: str | None
    state: GuestState
    observation_id: str


_SCHEMA = """
CREATE TABLE IF NOT EXISTS fleet_sites (
    id TEXT PRIMARY KEY, name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_hosts (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, site_id TEXT NOT NULL REFERENCES fleet_sites(id)
);
CREATE TABLE IF NOT EXISTS fleet_agents (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, host_id TEXT NOT NULL REFERENCES fleet_hosts(id)
);
CREATE TABLE IF NOT EXISTS fleet_instances (
    id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES fleet_sites(id),
    kind TEXT NOT NULL, binding TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS fleet_routes (
    id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES fleet_instances(id),
    host_id TEXT NOT NULL UNIQUE REFERENCES fleet_hosts(id), api_name TEXT NOT NULL,
    node TEXT NOT NULL, fingerprint TEXT NOT NULL,
    UNIQUE (instance_id, api_name), UNIQUE (instance_id, node)
);
CREATE TABLE IF NOT EXISTS fleet_route_addresses (
    route_id TEXT PRIMARY KEY REFERENCES fleet_routes(id), address TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_agent_grants (
    agent_id TEXT PRIMARY KEY REFERENCES fleet_agents(id), generation INTEGER NOT NULL,
    fingerprint TEXT UNIQUE, capability TEXT, route_id TEXT REFERENCES fleet_routes(id)
);
CREATE TABLE IF NOT EXISTS fleet_enrolled_keys (
    fingerprint TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS fleet_invitations (
    token_hash TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES fleet_agents(id),
    expected_generation INTEGER NOT NULL, fingerprint TEXT NOT NULL,
    capability TEXT NOT NULL, route_id TEXT REFERENCES fleet_routes(id), expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS fleet_invitations_agent ON fleet_invitations(agent_id);
CREATE TABLE IF NOT EXISTS fleet_observations (
    id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES fleet_instances(id),
    route_id TEXT NOT NULL REFERENCES fleet_routes(id), observed_at TEXT NOT NULL,
    received_at TEXT NOT NULL, coverage TEXT NOT NULL, source TEXT NOT NULL, state TEXT NOT NULL,
    digest TEXT NOT NULL, disputed INTEGER NOT NULL DEFAULT 0,
    UNIQUE (route_id, observed_at)
);
CREATE INDEX IF NOT EXISTS fleet_observations_head
    ON fleet_observations(instance_id, source, state, observed_at);
CREATE TABLE IF NOT EXISTS fleet_guests (
    id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES fleet_instances(id),
    kind TEXT NOT NULL, vmid INTEGER NOT NULL, generation INTEGER NOT NULL,
    node TEXT NOT NULL, name TEXT, state TEXT NOT NULL,
    observation_id TEXT NOT NULL REFERENCES fleet_observations(id),
    pve_uid TEXT, registered_at_ms INTEGER,
    UNIQUE (instance_id, vmid, generation)
);
CREATE UNIQUE INDEX IF NOT EXISTS fleet_guests_current
    ON fleet_guests(instance_id, vmid) WHERE state != 'replaced';
CREATE TABLE IF NOT EXISTS fleet_guest_uids (
    instance_id TEXT NOT NULL REFERENCES fleet_instances(id), pve_uid TEXT NOT NULL,
    guest_id TEXT NOT NULL REFERENCES fleet_guests(id),
    PRIMARY KEY (instance_id, pve_uid)
);
CREATE TABLE IF NOT EXISTS fleet_pve_adoptions (
    instance_id TEXT PRIMARY KEY REFERENCES fleet_instances(id),
    route_id TEXT NOT NULL UNIQUE REFERENCES fleet_routes(id),
    agent_id TEXT NOT NULL REFERENCES fleet_agents(id),
    revision INTEGER NOT NULL, status TEXT NOT NULL, grant_generation INTEGER NOT NULL,
    local_profile TEXT,
    attempt INTEGER NOT NULL DEFAULT 0, attempt_at TEXT,
    attempt_generation INTEGER, attempt_fingerprint TEXT,
    head_observation TEXT REFERENCES fleet_observations(id), current_projection TEXT
);
CREATE TABLE IF NOT EXISTS fleet_pve_adoption_history (
    observation_id TEXT PRIMARY KEY REFERENCES fleet_observations(id),
    instance_id TEXT NOT NULL REFERENCES fleet_pve_adoptions(instance_id),
    observed_at TEXT NOT NULL, projection TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS fleet_pve_adoption_history_by_instance
    ON fleet_pve_adoption_history (instance_id, observed_at DESC);
CREATE TABLE IF NOT EXISTS fleet_policy_revisions (
    id TEXT PRIMARY KEY, parent TEXT REFERENCES fleet_policy_revisions(id), body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_policy_head (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision TEXT NOT NULL REFERENCES fleet_policy_revisions(id)
);
CREATE TABLE IF NOT EXISTS fleet_pending_guests (
    guest_id TEXT PRIMARY KEY REFERENCES fleet_guests(id),
    observation_id TEXT NOT NULL REFERENCES fleet_observations(id),
    kind TEXT NOT NULL, node TEXT NOT NULL, name TEXT, pve_uid TEXT, registered_at_ms INTEGER
);
"""


def _name(name: str) -> str:
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 255 or not name.isprintable():
        raise ValueError("invalid display name")
    return name.strip()


def _digest(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise ValueError("expected a SHA-256 fingerprint")
    return value.lower()


def _api_name(name: str) -> str:
    if not isinstance(name, str):
        raise ValueError("invalid API name")
    try:
        _validate_api_name(name)
    except PreflightError:
        raise ValueError("invalid API name") from None
    try:
        return str(ipaddress.ip_address(name))
    except ValueError:
        return name.lower()


def _numeric_address(address: str) -> str:
    if not isinstance(address, str) or "%" in address:
        raise ValueError("route address must be a numeric IP")
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        raise ValueError("route address must be a numeric IP") from None


def _timestamp(at: datetime) -> str:
    if at.utcoffset() is None:
        raise ValueError("expected a timezone-aware time")
    return at.astimezone(UTC).isoformat(timespec="microseconds")


def _snapshot_digest(
    snapshot: InventorySnapshot, full_guest_coverage: bool, standalone: bool
) -> str:
    guests = [
        (
            row.vmid,
            row.kind,
            row.node,
            row.name,
            row.pve_uid,
            row.registered_at_ms,
            row.evidence.source,
            row.evidence.state,
            _timestamp(row.evidence.observed_at),
        )
        for row in snapshot.guests
    ]
    # The snapshot's measurements and task details do not participate in identity decisions.
    identity = (
        snapshot.evidence.source,
        snapshot.evidence.state,
        snapshot.coverage,
        full_guest_coverage,
        sorted(guests, key=lambda item: json.dumps(item)),
        sorted(node.node for node in snapshot.nodes) if standalone else (),
    )
    return sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()


def _observation(row: sqlite3.Row) -> InventoryObservation:
    values = dict(row)
    del values["digest"]
    values["disputed"] = bool(values["disputed"])
    for field in ("observed_at", "received_at"):
        values[field] = datetime.fromisoformat(values[field])
    return InventoryObservation(**values)


def _committed_observation(observation: InventoryObservation | None) -> InventoryObservation:
    if observation is None:
        raise FleetIdentityConflict("conflicting inventory for the same route and observation time")
    return observation


def _guest(row: sqlite3.Row) -> GuestIdentity:
    return GuestIdentity(**{field: row[field] for field in GuestIdentity.model_fields})


class FleetIdentityRegistry:
    """Trusted methods for a private database in a coordinator-owned directory."""

    def __init__(self, path: str | Path):
        self._path = Path(path).absolute()
        fd = os.open(self._path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise ValueError("fleet registry must be a regular file owned by the coordinator")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        with self._connection() as db:
            db.executescript(_SCHEMA)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self._path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys = ON")
            yield db
        finally:
            db.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        try:
            with self._connection() as db, db:
                db.execute("BEGIN IMMEDIATE")
                yield db
        except sqlite3.IntegrityError:
            raise FleetIdentityConflict(
                "the change conflicts with an existing fleet identity"
            ) from None

    def register_site(self, name: str) -> SiteIdentity:
        record = SiteIdentity(id=uuid4().hex, name=_name(name))
        with self._write() as db:
            db.execute("INSERT INTO fleet_sites VALUES (?, ?)", (record.id, record.name))
        return record

    def register_host(self, site_id: str, name: str) -> HostIdentity:
        record = HostIdentity(id=uuid4().hex, site_id=site_id, name=_name(name))
        with self._write() as db:
            db.execute(
                "INSERT INTO fleet_hosts VALUES (?, ?, ?)", (record.id, record.name, site_id)
            )
        return record

    def register_agent(self, host_id: str, name: str) -> AgentIdentity:
        record = AgentIdentity(id=uuid4().hex, host_id=host_id, name=_name(name))
        with self._write() as db:
            db.execute(
                "INSERT INTO fleet_agents VALUES (?, ?, ?)", (record.id, record.name, host_id)
            )
        return record

    def register_instance(
        self, site_id: str, *, kind: InstanceKind, instance_binding: str
    ) -> PveInstanceIdentity:
        binding = _digest(instance_binding)
        with self._write() as db:
            existing = db.execute(
                "SELECT id, site_id, kind FROM fleet_instances WHERE binding = ?", (binding,)
            ).fetchone()
            if existing is not None:
                if (existing["site_id"], existing["kind"]) != (site_id, kind):
                    raise FleetIdentityConflict("instance binding already registered")
                return PveInstanceIdentity(**dict(existing))
            record = PveInstanceIdentity(id=uuid4().hex, site_id=site_id, kind=kind)
            db.execute(
                "INSERT INTO fleet_instances VALUES (?, ?, ?, ?)",
                (record.id, site_id, kind, binding),
            )
        return record

    def get_site(self, site_id: str) -> SiteIdentity | None:
        with self._connection() as db:
            row = db.execute("SELECT id, name FROM fleet_sites WHERE id = ?", (site_id,)).fetchone()
        return None if row is None else SiteIdentity(**dict(row))

    def get_host(self, host_id: str) -> HostIdentity | None:
        with self._connection() as db:
            row = db.execute(
                "SELECT id, name, site_id FROM fleet_hosts WHERE id = ?", (host_id,)
            ).fetchone()
        return None if row is None else HostIdentity(**dict(row))

    def get_agent(self, agent_id: str) -> AgentIdentity | None:
        with self._connection() as db:
            row = db.execute(
                "SELECT id, name, host_id FROM fleet_agents WHERE id = ?", (agent_id,)
            ).fetchone()
        return None if row is None else AgentIdentity(**dict(row))

    def get_instance(self, instance_id: str) -> PveInstanceIdentity | None:
        with self._connection() as db:
            row = db.execute(
                "SELECT id, site_id, kind FROM fleet_instances WHERE id = ?", (instance_id,)
            ).fetchone()
        return None if row is None else PveInstanceIdentity(**dict(row))

    def get_route(self, route_id: str) -> PveRouteIdentity | None:
        with self._connection() as db:
            row = db.execute(
                "SELECT id, instance_id, host_id, api_name, node FROM fleet_routes WHERE id = ?",
                (route_id,),
            ).fetchone()
        return None if row is None else PveRouteIdentity(**dict(row))

    def get_connector_route(self, route_id: str) -> PveConnectorRoute | None:
        with self._connection() as db:
            return self._connector_route(db, route_id)

    @staticmethod
    def _connector_route(db: sqlite3.Connection, route_id: str) -> PveConnectorRoute | None:
        row = db.execute(
            """SELECT r.id AS route_id, r.instance_id, r.host_id, r.api_name, r.node,
                      i.kind, i.binding AS instance_binding,
                      r.fingerprint AS transport_fingerprint, a.address
               FROM fleet_routes AS r JOIN fleet_instances AS i ON i.id = r.instance_id
               JOIN fleet_route_addresses AS a ON a.route_id = r.id WHERE r.id = ?""",
            (route_id,),
        ).fetchone()
        return None if row is None else PveConnectorRoute(**dict(row))

    def confirm_route(
        self,
        instance_id: str,
        *,
        host_id: str,
        api_name: str,
        node: str,
        instance_binding: str,
        transport_fingerprint: str,
        address: str | None = None,
    ) -> PveRouteIdentity:
        binding = _digest(instance_binding)
        fingerprint = _digest(transport_fingerprint)
        api_name = _api_name(api_name)
        if address is not None:
            address = _numeric_address(address)
            try:
                api_address = ipaddress.ip_address(api_name)
            except ValueError:
                pass  # DNS identity is verified independently of the pinned address.
            else:
                if str(api_address) != address:
                    raise FleetIdentityConflict("numeric API name must match the route address")
        record = PveRouteIdentity(
            id=uuid4().hex,
            instance_id=instance_id,
            host_id=host_id,
            api_name=api_name,
            node=node,
        )
        with self._write() as db:
            instance = db.execute(
                """SELECT i.kind FROM fleet_instances AS i JOIN fleet_hosts AS h
                   ON i.site_id = h.site_id WHERE i.id = ? AND i.binding = ? AND h.id = ?""",
                (instance_id, binding, host_id),
            ).fetchone()
            if instance is None:
                raise FleetIdentityConflict(
                    "route needs an approved instance binding and site host"
                )
            existing = db.execute(
                "SELECT * FROM fleet_routes WHERE instance_id = ? AND api_name = ?",
                (instance_id, record.api_name),
            ).fetchone()
            if existing is not None:
                if (existing["node"], existing["host_id"], existing["fingerprint"]) != (
                    node,
                    host_id,
                    fingerprint,
                ):
                    raise FleetIdentityConflict("route already registered with another identity")
                record = record.model_copy(update={"id": existing["id"]})
            elif (
                instance["kind"] == "standalone"
                and db.execute(
                    "SELECT 1 FROM fleet_routes WHERE instance_id = ?", (instance_id,)
                ).fetchone()
            ):
                raise FleetIdentityConflict("standalone instance already has a route")
            else:
                db.execute(
                    "INSERT INTO fleet_routes VALUES (?, ?, ?, ?, ?, ?)",
                    (record.id, instance_id, host_id, record.api_name, node, fingerprint),
                )
            if address is not None:
                db.execute(
                    "INSERT OR IGNORE INTO fleet_route_addresses VALUES (?, ?)",
                    (record.id, address),
                )
                confirmed = self._connector_route(db, record.id)
                if confirmed is None or confirmed.address != address:
                    raise FleetIdentityConflict("route already registered with another address")
        return record

    def ingest_snapshot(
        self,
        snapshot: InventorySnapshot,
        *,
        route_id: str,
        transport_fingerprint: str,
        instance_binding: str,
        full_guest_coverage: bool = False,
        received_at: datetime | None = None,
    ) -> InventoryObservation:
        """Record in-process evidence from a route whose bindings the caller verified.

        Set full_guest_coverage only with independent evidence that the snapshot's
        guest roster is complete for this instance, including when the roster is empty.
        The native collector's token scope alone cannot establish that coverage.
        """
        with self._write() as db:
            observation = self._ingest_snapshot(
                db,
                snapshot,
                route_id=route_id,
                transport_fingerprint=transport_fingerprint,
                instance_binding=instance_binding,
                full_guest_coverage=full_guest_coverage,
                received_at=received_at,
            )
        return _committed_observation(observation)

    def _ingest_snapshot(
        self,
        db: sqlite3.Connection,
        snapshot: InventorySnapshot,
        *,
        route_id: str,
        transport_fingerprint: str,
        instance_binding: str,
        full_guest_coverage: bool = False,
        received_at: datetime | None = None,
    ) -> InventoryObservation | None:
        """Return None for a dispute that must commit before the caller raises."""
        if type(full_guest_coverage) is not bool:
            raise ValueError("full_guest_coverage must be an explicit boolean attestation")
        fingerprint = _digest(transport_fingerprint)
        binding = _digest(instance_binding)
        source, state = snapshot.evidence.source, snapshot.evidence.state
        observed_at = _timestamp(snapshot.observed_at)
        received_at = received_at if received_at is not None else datetime.now(UTC)
        received = _timestamp(received_at)
        if observed_at > received or snapshot.evidence.observed_at != snapshot.observed_at:
            raise FleetIdentityConflict("inconsistent inventory observation times")
        successful = source == "cluster_resources" and state in ("observed", "absent")
        roster = {item.vmid: item for item in snapshot.guests}
        valid_roster = len(roster) == len(snapshot.guests) and all(
            item.evidence.source == "cluster_resources"
            and item.evidence.state == "observed"
            and item.evidence.observed_at == snapshot.observed_at
            for item in roster.values()
        )
        full = successful and full_guest_coverage
        coverage = "full_guest_coverage" if full else "token_scope"
        route = db.execute(
            """SELECT r.instance_id, r.node, i.kind FROM fleet_routes AS r
               JOIN fleet_instances AS i ON i.id = r.instance_id
               WHERE r.id = ? AND r.api_name = ? AND r.fingerprint = ? AND i.binding = ?""",
            (route_id, _api_name(snapshot.api_name), fingerprint, binding),
        ).fetchone()
        if route is None:
            raise FleetIdentityConflict("inventory route identity is unconfirmed")
        standalone = route["kind"] == "standalone"
        digest = _snapshot_digest(snapshot, full_guest_coverage, standalone)
        existing = db.execute(
            "SELECT * FROM fleet_observations WHERE route_id = ? AND observed_at = ?",
            (route_id, observed_at),
        ).fetchone()
        if existing is not None and existing["digest"] == digest:
            return _observation(existing)
        if existing is not None:
            db.execute("UPDATE fleet_observations SET disputed = 1 WHERE id = ?", (existing["id"],))
            db.execute(
                """UPDATE fleet_guests SET state = 'continuity_required'
                   WHERE observation_id = ? AND state != 'replaced'""",
                (existing["id"],),
            )
            return None
        if successful and (not valid_roster or (state == "absent" and roster)):
            raise FleetIdentityConflict("inconsistent guest roster")
        if (
            successful
            and standalone
            and any(item.node != route["node"] for item in (*snapshot.nodes, *roster.values()))
        ):
            raise FleetIdentityConflict("standalone inventory disagrees with its node")
        instance_id = route["instance_id"]
        newer = (
            successful
            and db.execute(
                """SELECT 1 FROM fleet_observations WHERE instance_id = ?
               AND source = 'cluster_resources' AND state IN ('observed', 'absent')
               AND observed_at >= ? LIMIT 1""",
                (instance_id, observed_at),
            ).fetchone()
            is None
        )
        record = InventoryObservation(
            id=uuid4().hex,
            instance_id=instance_id,
            route_id=route_id,
            observed_at=snapshot.observed_at,
            received_at=received_at.astimezone(UTC),
            coverage=coverage,
            source=source,
            state=state,
        )
        db.execute(
            """INSERT INTO fleet_observations
               (id, instance_id, route_id, observed_at, received_at,
                coverage, source, state, digest)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.id,
                instance_id,
                route_id,
                observed_at,
                received,
                coverage,
                source,
                state,
                digest,
            ),
        )
        if newer:
            self._apply_roster(db, record, roster)
        return record

    def get_observation(self, observation_id: str) -> InventoryObservation | None:
        with self._connection() as db:
            row = db.execute(
                "SELECT * FROM fleet_observations WHERE id = ?", (observation_id,)
            ).fetchone()
        return None if row is None else _observation(row)

    def guest_history(self, instance_id: str, vmid: int) -> tuple[GuestIdentity, ...]:
        with self._connection() as db:
            rows = db.execute(
                """SELECT id, instance_id, kind, vmid, generation, node, name, state, observation_id
                   FROM fleet_guests WHERE instance_id = ? AND vmid = ? ORDER BY generation""",
                (instance_id, vmid),
            ).fetchall()
        return tuple(_guest(row) for row in rows)

    def _apply_roster(
        self, db: sqlite3.Connection, observation: InventoryObservation, roster: dict[int, Guest]
    ) -> None:
        if observation.coverage == "full_guest_coverage":
            rows = db.execute(
                "SELECT id, vmid FROM fleet_guests WHERE instance_id = ? AND state != 'replaced'",
                (observation.instance_id,),
            )
            db.executemany(
                "UPDATE fleet_guests SET state = 'missing', observation_id = ? WHERE id = ?",
                (
                    (observation.id, row["id"])
                    for row in rows.fetchall()
                    if row["vmid"] not in roster
                ),
            )
        seen_uids: set[str] = set()
        duplicate_uids: set[str] = set()
        for guest in roster.values():
            if guest.pve_uid is not None:
                if guest.pve_uid in seen_uids:
                    duplicate_uids.add(guest.pve_uid)
                seen_uids.add(guest.pve_uid)
        for guest in roster.values():
            current = self._current_guest(db, observation.instance_id, guest.vmid)
            uid, registered = guest.pve_uid, guest.registered_at_ms
            if (
                uid is None
                or registered is None
                or registered > int(observation.observed_at.timestamp() * 1000)
                or uid in duplicate_uids
                or self._uid_owner(db, observation.instance_id, uid)
                not in (None, current["id"] if current is not None else None)
            ):
                uid = registered = None
            candidate = {
                "kind": guest.kind,
                "node": guest.node,
                "name": guest.name,
                "pve_uid": uid,
                "registered_at_ms": registered,
            }
            if current is None:
                created = self._new_guest(
                    db,
                    observation.instance_id,
                    guest.vmid,
                    1,
                    observation.id,
                    candidate,
                    qualified=uid is not None,
                )
                if uid is None:
                    self._hold_guest(db, created.id, observation.id, candidate)
                continue
            prior_uid, prior_registered = current["pve_uid"], current["registered_at_ms"]
            if uid is not None and prior_uid is not None:
                if (uid, registered, guest.kind, current["state"], current["pending"]) == (
                    prior_uid,
                    prior_registered,
                    current["kind"],
                    "present",
                    None,
                ):
                    self._update_guest(db, current, observation.id, candidate)
                    continue
                if (
                    uid != prior_uid
                    and registered > prior_registered
                    and self._uid_owner(db, observation.instance_id, uid) is None
                ):
                    self._replace_guest(db, current, observation.id, candidate)
                    continue
            self._hold_guest(db, current["id"], observation.id, candidate)

    @staticmethod
    def _current_guest(db: sqlite3.Connection, instance_id: str, vmid: int) -> sqlite3.Row | None:
        return db.execute(
            """SELECT g.*, p.observation_id AS pending FROM fleet_guests AS g
               LEFT JOIN fleet_pending_guests AS p ON p.guest_id = g.id
               WHERE g.instance_id = ? AND g.vmid = ? AND g.state != 'replaced'""",
            (instance_id, vmid),
        ).fetchone()

    @staticmethod
    def _uid_owner(db: sqlite3.Connection, instance_id: str, uid: str) -> str | None:
        owner = db.execute(
            "SELECT guest_id FROM fleet_guest_uids WHERE instance_id = ? AND pve_uid = ?",
            (instance_id, uid),
        ).fetchone()
        return None if owner is None else owner["guest_id"]

    @staticmethod
    def _record_uid(
        db: sqlite3.Connection, instance_id: str, guest_id: str, uid: str | None
    ) -> None:
        if uid is not None:
            db.execute(
                """INSERT INTO fleet_guest_uids VALUES (?, ?, ?)
                   ON CONFLICT(instance_id, pve_uid) DO NOTHING""",
                (instance_id, uid, guest_id),
            )

    def _new_guest(
        self,
        db: sqlite3.Connection,
        instance_id: str,
        vmid: int,
        generation: int,
        observation_id: str,
        candidate: dict | sqlite3.Row,
        *,
        qualified: bool = True,
    ) -> GuestIdentity:
        record = GuestIdentity(
            id=uuid4().hex,
            instance_id=instance_id,
            vmid=vmid,
            generation=generation,
            observation_id=observation_id,
            kind=candidate["kind"],
            node=candidate["node"],
            name=candidate["name"],
            state="present" if qualified else "continuity_required",
        )
        uid = candidate["pve_uid"]
        db.execute(
            "INSERT INTO fleet_guests (id, instance_id, kind, vmid, generation, node, name, state, "
            "observation_id, pve_uid, registered_at_ms) "
            "VALUES (:id, :instance_id, :kind, :vmid, :generation, :node, :name, :state, "
            ":observation_id, :pve_uid, :registered_at_ms)",
            record.model_dump()
            | {"pve_uid": uid, "registered_at_ms": candidate["registered_at_ms"]},
        )
        self._record_uid(db, instance_id, record.id, uid)
        return record

    def _update_guest(
        self,
        db: sqlite3.Connection,
        current: sqlite3.Row,
        observation_id: str,
        candidate: dict | sqlite3.Row,
    ) -> GuestIdentity:
        uid = candidate["pve_uid"]
        if uid is None:
            uid, registered = current["pve_uid"], current["registered_at_ms"]
        else:
            registered = candidate["registered_at_ms"]
        row = db.execute(
            """UPDATE fleet_guests SET node = ?, name = ?, state = 'present', observation_id = ?,
                   pve_uid = ?, registered_at_ms = ? WHERE id = ? RETURNING *""",
            (candidate["node"], candidate["name"], observation_id, uid, registered, current["id"]),
        ).fetchone()
        self._record_uid(db, current["instance_id"], current["id"], uid)
        return _guest(row)

    def _replace_guest(
        self,
        db: sqlite3.Connection,
        current: sqlite3.Row,
        observation_id: str,
        candidate: dict | sqlite3.Row,
    ) -> GuestIdentity:
        db.execute("DELETE FROM fleet_pending_guests WHERE guest_id = ?", (current["id"],))
        db.execute("UPDATE fleet_guests SET state = 'replaced' WHERE id = ?", (current["id"],))
        return self._new_guest(
            db,
            current["instance_id"],
            current["vmid"],
            current["generation"] + 1,
            observation_id,
            candidate,
        )

    @staticmethod
    def _hold_guest(
        db: sqlite3.Connection, guest_id: str, observation_id: str, candidate: dict
    ) -> None:
        db.execute(
            "UPDATE fleet_guests SET state = 'continuity_required', observation_id = ? "
            "WHERE id = ?",
            (observation_id, guest_id),
        )
        db.execute(
            """INSERT OR REPLACE INTO fleet_pending_guests
               (guest_id, observation_id, kind, node, name, pve_uid, registered_at_ms)
               VALUES (:guest_id, :observation_id, :kind, :node, :name,
                       :pve_uid, :registered_at_ms)""",
            candidate | {"guest_id": guest_id, "observation_id": observation_id},
        )

    def confirm_continuity(
        self, instance_id: str, vmid: int, *, generation: int, observation_id: str, same_guest: bool
    ) -> GuestIdentity:
        """Resolve ambiguity only against the currently observed candidate and lineage."""
        if type(same_guest) is not bool:
            raise ValueError("same_guest must be an explicit boolean decision")
        with self._write() as db:
            current = self._current_guest(db, instance_id, vmid)
            if (
                current is None
                or current["state"] != "continuity_required"
                or current["generation"] != generation
                or current["observation_id"] != observation_id
                or current["pending"] != observation_id
            ):
                raise FleetIdentityConflict("guest confirmation no longer matches current evidence")
            candidate = db.execute(
                """SELECT p.* FROM fleet_pending_guests AS p
                   JOIN fleet_observations AS o ON o.id = p.observation_id
                   WHERE p.guest_id = ? AND o.disputed = 0""",
                (current["id"],),
            ).fetchone()
            if candidate is None:
                raise FleetIdentityConflict("guest confirmation requires undisputed evidence")
            uid = candidate["pve_uid"]
            owner = self._uid_owner(db, instance_id, uid) if uid is not None else None
            if owner is not None and owner != current["id"]:
                raise FleetIdentityConflict("candidate UID is assigned to another guest")
            if same_guest:
                if current["kind"] != candidate["kind"]:
                    raise FleetIdentityConflict("a different guest kind requires a new generation")
                record = self._update_guest(db, current, observation_id, candidate)
                db.execute("DELETE FROM fleet_pending_guests WHERE guest_id = ?", (current["id"],))
            else:
                if owner is not None:
                    # An explicit decision can reassign this observation's UID to the
                    # new generation. Other historical UID assignments stay reserved.
                    db.execute(
                        "DELETE FROM fleet_guest_uids WHERE instance_id = ? AND pve_uid = ?",
                        (instance_id, uid),
                    )
                record = self._replace_guest(db, current, observation_id, candidate)
        return record
