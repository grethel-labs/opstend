"""Coordinator registry projections for read-only standalone PVE adoption."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from hashlib import sha256
from typing import Literal

from pydantic import AwareDatetime

from .fleet_adoption_models import AuditPrivilege, PveAdoptionEvidence, ScheduleState
from .fleet_identity import FleetIdentityConflict, InventoryObservation, _timestamp
from .pve_inventory_models import InventorySnapshot, Projection

MAX_ADOPTION_AGE_SECONDS = 300
ADOPTION_HISTORY_LIMIT = 20


class PveAdoptionAttachment(Projection):
    instance_id: str
    route_id: str
    agent_id: str
    revision: int
    status: Literal["attached", "detached"]
    grant_generation: int


class AdoptedLocalProfile(Projection):
    observed_at: AwareDatetime
    node: str
    version: str
    profile: Literal["pve-native/v1"]
    mode: Literal["standalone"]
    installed_roles: tuple[str, ...]
    source: Literal["operator_local_export"] = "operator_local_export"


class AdoptedSchedule(Projection):
    job_ref: str
    schedule: str | None
    enabled: bool
    guest_ids: tuple[str, ...]


class PveAdoptionCurrent(Projection):
    observation_id: str
    observed_at: AwareDatetime
    node: str
    pve_version: str
    audit_privileges: tuple[AuditPrivilege, ...]
    schedule_state: ScheduleState
    schedules: tuple[AdoptedSchedule, ...]
    capture_refs: tuple[str, ...]
    coverage: Literal["token_scope"] = "token_scope"
    schedule_source: Literal["pve_cluster_backup"] = "pve_cluster_backup"


class PveAdoptionHistory(Projection):
    observation_id: str
    observed_at: AwareDatetime
    job_refs: tuple[str, ...]
    capture_refs: tuple[str, ...]


class PveAdoptionView(Projection):
    attachment: PveAdoptionAttachment
    authority: Literal["local"] = "local"
    local_profile: AdoptedLocalProfile | None = None
    current: PveAdoptionCurrent | None = None
    history: tuple[PveAdoptionHistory, ...] = ()


def attachment(row: sqlite3.Row) -> PveAdoptionAttachment:
    return PveAdoptionAttachment(
        **{field: row[field] for field in PveAdoptionAttachment.model_fields}
    )


def adoption_for_route(db: sqlite3.Connection, route_id: str) -> sqlite3.Row | None:
    return db.execute(
        "SELECT * FROM fleet_pve_adoptions WHERE route_id = ?", (route_id,)
    ).fetchone()


def adoption_for_instance(db: sqlite3.Connection, instance_id: str) -> sqlite3.Row:
    row = db.execute(
        "SELECT * FROM fleet_pve_adoptions WHERE instance_id = ?", (instance_id,)
    ).fetchone()
    if row is None:
        raise FleetIdentityConflict("standalone instance has no adoption")
    return row


def clear_attempt_for_agent(db: sqlite3.Connection, agent_id: str) -> None:
    db.execute(
        """UPDATE fleet_pve_adoptions SET attempt_at = NULL, attempt_generation = NULL,
           attempt_fingerprint = NULL, head_observation = NULL, current_projection = NULL
           WHERE agent_id = ?""",
        (agent_id,),
    )


def invalidate_inventory_head(db: sqlite3.Connection, route_id: str, observed_at: str) -> None:
    db.execute(
        """UPDATE fleet_pve_adoptions SET head_observation = NULL, current_projection = NULL,
           attempt_at = NULL, attempt_generation = NULL, attempt_fingerprint = NULL
           WHERE route_id = ? AND (attempt_at <= ? OR head_observation IN (
               SELECT id FROM fleet_observations WHERE route_id = ? AND observed_at <= ?
           ))""",
        (route_id, observed_at, route_id, observed_at),
    )


def record_projection(
    db: sqlite3.Connection,
    observation: InventoryObservation,
    snapshot: InventorySnapshot,
    evidence: PveAdoptionEvidence,
) -> None:
    # Never link a selector to a guest absent from this snapshot or awaiting continuity.
    guests = {
        row["vmid"]: row["id"]
        for row in db.execute(
            """SELECT id, vmid FROM fleet_guests WHERE instance_id = ?
               AND observation_id = ? AND state = 'present'""",
            (observation.instance_id, observation.id),
        )
    }
    roster = {guest.vmid for guest in snapshot.guests}
    schedules = tuple(
        AdoptedSchedule(
            job_ref=schedule.job_ref,
            schedule=schedule.schedule,
            enabled=schedule.enabled,
            guest_ids=tuple(sorted(guests[vmid] for vmid in schedule.vmids)),
        )
        for schedule in evidence.schedules
        if all(vmid in roster and vmid in guests for vmid in schedule.vmids)
    )
    capture_refs = tuple(
        sorted(
            sha256(f"pve-capture:{observation.instance_id}:{guest_id}".encode()).hexdigest()
            for guest_id in guests.values()
        )
    )
    current = PveAdoptionCurrent(
        observation_id=observation.id,
        observed_at=observation.observed_at,
        node=evidence.node,
        pve_version=evidence.pve_version,
        audit_privileges=evidence.audit_privileges,
        schedule_state=evidence.schedule_state,
        schedules=schedules,
        capture_refs=capture_refs,
    )
    historical = PveAdoptionHistory(
        observation_id=observation.id,
        observed_at=observation.observed_at,
        job_refs=tuple(sorted({schedule.job_ref for schedule in schedules})),
        capture_refs=capture_refs,
    )
    db.execute(
        """INSERT INTO fleet_pve_adoption_history
           (observation_id, instance_id, observed_at, projection)
           SELECT id, instance_id, observed_at, ? FROM fleet_observations WHERE id = ?""",
        (historical.model_dump_json(), observation.id),
    )
    db.execute(
        """UPDATE fleet_pve_adoptions SET head_observation = ?, current_projection = ?
           WHERE instance_id = ?""",
        (observation.id, current.model_dump_json(), observation.instance_id),
    )


def view_adoption(
    db: sqlite3.Connection, row: sqlite3.Row, *, history: bool, now: datetime
) -> PveAdoptionView:
    current = None
    if row["status"] == "attached" and row["head_observation"] is not None:
        as_of = _timestamp(now)
        oldest = _timestamp(now - timedelta(seconds=MAX_ADOPTION_AGE_SECONDS))
        qualified = db.execute(
            """SELECT 1 FROM fleet_observations AS o
               JOIN fleet_agent_grants AS g ON g.agent_id = ? AND g.route_id = o.route_id
               WHERE o.id = ? AND o.disputed = 0 AND g.capability = 'pve_inventory'
                 AND g.generation = ? AND g.fingerprint = ?
                 AND o.observed_at BETWEEN ? AND ?
                 AND NOT EXISTS (
                     SELECT 1 FROM fleet_observations AS newer
                     WHERE newer.route_id = o.route_id AND newer.observed_at > o.observed_at
                 )""",
            (
                row["agent_id"],
                row["head_observation"],
                row["attempt_generation"],
                row["attempt_fingerprint"],
                oldest,
                as_of,
            ),
        ).fetchone()
        if qualified is not None:
            current = PveAdoptionCurrent.model_validate_json(row["current_projection"])
    previous = ()
    if history:
        previous = tuple(
            PveAdoptionHistory.model_validate_json(item["projection"])
            for item in db.execute(
                """SELECT h.projection FROM fleet_pve_adoption_history AS h
                   JOIN fleet_observations AS o ON o.id = h.observation_id
                   WHERE h.instance_id = ? AND o.disputed = 0
                   ORDER BY h.observed_at DESC LIMIT ?""",
                (row["instance_id"], ADOPTION_HISTORY_LIMIT),
            )
        )
    local_profile = (
        AdoptedLocalProfile.model_validate_json(row["local_profile"])
        if row["status"] == "attached" and row["local_profile"] is not None
        else None
    )
    return PveAdoptionView(
        attachment=attachment(row), current=current, local_profile=local_profile, history=previous
    )
