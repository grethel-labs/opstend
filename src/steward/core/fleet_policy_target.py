"""Co-located target's independently provisioned fleet-policy metadata store."""

from __future__ import annotations

import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .canonical import canonical_json, revision_id
from .fleet_identity import FleetIdentityRegistry
from .fleet_policy import (
    EffectiveFleetPolicy,
    FleetLocalPolicy,
    FleetPolicyValues,
    FleetTarget,
    RegistryId,
    RevisionId,
)
from .pve_inventory_models import Projection

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fleet_local_policy (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    target TEXT NOT NULL, limits TEXT NOT NULL,
    applied_revision TEXT, approval_id TEXT, effective TEXT,
    CHECK ((applied_revision IS NULL AND approval_id IS NULL AND effective IS NULL) OR
           (applied_revision IS NOT NULL AND approval_id IS NOT NULL AND effective IS NOT NULL))
)
"""


class FleetPolicyTargetConfig(Projection):
    target: FleetTarget
    limits: FleetPolicyValues


class FleetPolicyTargetState(Projection):
    local: FleetLocalPolicy
    applied_revision: RevisionId | None
    approval_id: RegistryId | None
    effective: EffectiveFleetPolicy | None


def _owned_directory(path: Path) -> None:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("target database directory must be owner-only with mode 0700")


def _owned_file(path: Path) -> os.stat_result:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise ValueError("policy database must be an owner-only regular file with mode 0600")
    return info


def _rollback_journal(db: sqlite3.Connection, schema: str) -> None:
    if db.execute(f"PRAGMA {schema}.journal_mode").fetchone()[0] != "delete":
        raise ValueError("atomic policy adoption requires SQLite DELETE journal mode")
    db.execute(f"PRAGMA {schema}.synchronous = FULL")


def _read(db: sqlite3.Connection, now: datetime, *, attached: bool) -> FleetPolicyTargetState:
    query = (
        "SELECT * FROM target_state.fleet_local_policy WHERE singleton = 1"
        if attached
        else "SELECT * FROM fleet_local_policy WHERE singleton = 1"
    )
    row = db.execute(query).fetchone()
    if row is None:
        raise ValueError("target policy state has not been provisioned")
    target = FleetTarget.model_validate_json(row["target"])
    limits = FleetPolicyValues.model_validate_json(row["limits"])
    applied = row["applied_revision"]
    effective = (
        EffectiveFleetPolicy.model_validate_json(row["effective"]) if row["effective"] else None
    )
    if effective is not None and (effective.revision != applied or effective.target != target):
        raise ValueError("target policy metadata does not match its applied revision")
    return FleetPolicyTargetState(
        local=FleetLocalPolicy(
            target=target,
            limits=limits,
            revision=revision_id({"target": target.model_dump(), "limits": limits.model_dump()}),
            observed_at=now,
        ),
        applied_revision=applied,
        approval_id=row["approval_id"],
        effective=effective,
    )


class FleetPolicyTargetStore:
    """Pin one local target, its local limits and its applied policy to a private file.

    This is a local entry point. The coordinator DB must be on the same local
    filesystem. SQLite's rollback-journal transaction commits both the durable
    coordinator result and the actual target metadata or neither.
    """

    def __init__(self, path: Path):
        self._path = path.absolute()
        _owned_directory(self._path.parent)
        _owned_file(self._path)

    @classmethod
    def configure(cls, path: Path, config: FleetPolicyTargetConfig) -> FleetPolicyTargetStore:
        """Provision or refresh local limits as the owner. Preserve target and applied policy."""
        path = path.absolute()
        _owned_directory(path.parent)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        store = cls(path)
        target = canonical_json(config.target.model_dump(mode="json"))
        limits = canonical_json(config.limits.model_dump(mode="json"))
        with store._connection() as db, db:
            _rollback_journal(db, "main")
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                """SELECT 1 FROM sqlite_schema WHERE type = 'table'
                   AND name NOT LIKE 'sqlite_%' AND name != 'fleet_local_policy'"""
            ).fetchone():
                raise ValueError("the target policy database has an unrelated schema")
            db.execute(_SCHEMA)
            row = db.execute("SELECT target FROM fleet_local_policy WHERE singleton = 1").fetchone()
            if row is not None and row["target"] != target:
                raise ValueError("target database is already pinned to a different target")
            db.execute(
                """INSERT INTO fleet_local_policy (singleton, target, limits) VALUES (1, ?, ?)
                   ON CONFLICT (singleton) DO UPDATE SET limits = excluded.limits""",
                (target, limits),
            )
        return store

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        _owned_file(self._path)
        with closing(sqlite3.connect(f"{self._path.as_uri()}?mode=rw", uri=True, timeout=10)) as db:
            db.row_factory = sqlite3.Row
            yield db

    def state(self) -> FleetPolicyTargetState:
        with self._connection() as db:
            return _read(db, datetime.now(UTC), attached=False)

    def check_coordinator_path(self, path: Path) -> None:
        _owned_directory(path.absolute().parent)
        main, target = _owned_file(path), _owned_file(self._path)
        if main.st_dev != target.st_dev or main.st_ino == target.st_ino:
            raise ValueError("target and coordinator require distinct databases on one filesystem")

    @contextmanager
    def transaction(self, registry: FleetIdentityRegistry) -> Iterator[sqlite3.Connection]:
        self.check_coordinator_path(registry._path)
        with registry._connection() as db:
            _rollback_journal(db, "main")
            db.execute("ATTACH DATABASE ? AS target_state", (str(self._path),))
            _rollback_journal(db, "target_state")
            with db:
                db.execute("BEGIN IMMEDIATE")
                yield db

    def read(self, db: sqlite3.Connection, now: datetime) -> FleetPolicyTargetState:
        return _read(db, now, attached=True)

    def apply(
        self, db: sqlite3.Connection, effective: EffectiveFleetPolicy, approval_id: str
    ) -> None:
        db.execute(
            """UPDATE target_state.fleet_local_policy SET
                   applied_revision = ?, approval_id = ?, effective = ? WHERE singleton = 1""",
            (effective.revision, approval_id, effective.model_dump_json()),
        )
        state = self.read(db, datetime.now(UTC))
        if state.effective != effective or state.approval_id != approval_id:
            raise ValueError("target policy readback does not match the approved policy")
