"""Co-located target's independently provisioned fleet-policy metadata store."""

from __future__ import annotations

import os
import sqlite3
import stat
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from fcntl import LOCK_EX, flock
from pathlib import Path
from time import monotonic

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
from .fleet_policy_reconcile import (
    MAX_POLICY_SYNC_BYTES,
    FleetPolicyClaim,
    FleetPolicyOutcome,
    FleetPolicyReceipt,
    FleetPolicySyncReply,
    FleetPolicySyncRequest,
    respects_limits,
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


_SYNC_SCHEMA = """
CREATE TABLE IF NOT EXISTS fleet_local_policy_sync (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    sequence INTEGER NOT NULL,
    receipt TEXT
)
"""

PolicyExchange = Callable[[FleetPolicySyncRequest], FleetPolicySyncReply]


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
    """Keep one target's local limits and applied policy in a private file.

    Co-located adoption commits through an attached coordinator database.
    Remote reconciliation commits local metadata together with its queued receipt.
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
                   AND name NOT LIKE 'sqlite_%'
                   AND name NOT IN ('fleet_local_policy', 'fleet_local_policy_sync')"""
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

    def reconcile(
        self, exchange: PolicyExchange, approval_id: str | None = None, digest: str | None = None
    ) -> FleetPolicySyncReply:
        """Report target state and apply only a fresh claim received in this exchange."""
        expected = _owned_file(self._path)
        fd = os.open(self._path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not os.path.samestat(expected, os.fstat(fd)):
                raise ValueError("target policy database changed before reconciliation")
            flock(fd, LOCK_EX)
            return self._reconcile(exchange, approval_id, digest)
        finally:
            os.close(fd)

    def _reconcile(
        self, exchange: PolicyExchange, approval_id: str | None, digest: str | None
    ) -> FleetPolicySyncReply:
        reply, receipt = self._exchange(exchange, approval_id, digest)
        if receipt is None:
            return reply

        # The metadata and queued receipt have committed before reporting the result.
        # If this exchange fails, the next invocation presents the exact same receipt.
        acknowledged, _ = self._exchange(exchange, None, None)
        if (
            acknowledged.acknowledged_receipt != receipt.claim_id
            or acknowledged.outcome is None
            or acknowledged.outcome.status != "applied"
        ):
            raise ValueError("coordinator did not acknowledge applied policy metadata")
        return acknowledged

    def _exchange(
        self, exchange: PolicyExchange, approval_id: str | None, digest: str | None
    ) -> tuple[FleetPolicySyncReply, FleetPolicyReceipt | None]:
        with self._connection() as db:
            _rollback_journal(db, "main")
            with db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(_SYNC_SCHEMA)
                sequence = db.execute(
                    """INSERT INTO fleet_local_policy_sync VALUES (1, 1, NULL)
                       ON CONFLICT (singleton) DO UPDATE SET sequence = sequence + 1
                       WHERE sequence < 9223372036854775807 RETURNING sequence"""
                ).fetchone()
                if sequence is None:
                    raise ValueError("target policy report sequence is exhausted")
                attempt = sequence["sequence"]
            # Reservation survives interruptions. Acquire the exclusive lock
            # before the live exchange so commit never waits for local readers.
            with db:
                db.execute("BEGIN EXCLUSIVE")
                row = db.execute(
                    "SELECT * FROM fleet_local_policy_sync WHERE singleton = 1"
                ).fetchone()
                if row["sequence"] != attempt:
                    raise ValueError("target policy report was superseded before exchange")
                state = _read(db, datetime.now(UTC), attached=False)
                queued = (
                    FleetPolicyReceipt.model_validate_json(row["receipt"])
                    if row["receipt"]
                    else None
                )
                request = FleetPolicySyncRequest(
                    sequence=attempt,
                    local=state.local,
                    applied_revision=state.applied_revision,
                    applied_approval_id=state.approval_id,
                    effective_digest=revision_id(state.effective.model_dump(mode="json"))
                    if state.effective is not None
                    else None,
                    approval_id=approval_id,
                    digest=digest,
                    receipt=queued,
                )
                started = monotonic()
                reply = exchange(request)
                if (
                    reply.target != request.local.target
                    or reply.sequence != request.sequence
                    or (reply.outcome is not None and reply.outcome.target != reply.target)
                ):
                    raise ValueError("coordinator reply does not match the live target report")
                if reply.acknowledged_receipt is not None:
                    if queued is None or reply.acknowledged_receipt != queued.claim_id:
                        raise ValueError("coordinator acknowledged a different policy receipt")
                    db.execute(
                        "UPDATE fleet_local_policy_sync SET receipt = NULL WHERE singleton = 1"
                    )
                claim = reply.claim
                if claim is None:
                    return reply, None
                if queued is not None and reply.acknowledged_receipt != queued.claim_id:
                    raise ValueError(
                        "queued receipt must be acknowledged before applying a new claim"
                    )
                if (
                    reply.outcome is None
                    or reply.outcome.status != "pending"
                    or claim.sequence != request.sequence
                    or claim.approval_id != request.approval_id
                    or claim.digest != request.digest
                    or claim.local_revision != state.local.revision
                    or claim.prior_applied_revision != state.applied_revision
                    or claim.prior_applied_approval_id != state.approval_id
                    or claim.prior_effective_digest != request.effective_digest
                    or claim.effective_digest
                    != revision_id(claim.effective.model_dump(mode="json"))
                    or len(reply.model_dump_json().encode()) > MAX_POLICY_SYNC_BYTES
                    or not respects_limits(claim.effective, state.local)
                ):
                    raise ValueError("coordinator claim does not match the live target report")
                if _claim_expired(claim, started):
                    return reply.model_copy(
                        update={
                            "claim": None,
                            "outcome": FleetPolicyOutcome(
                                target=reply.target, status="pending", reason="claim_expired"
                            ),
                        }
                    ), None

                receipt = FleetPolicyReceipt.model_validate(
                    {name: getattr(claim, name) for name in FleetPolicyReceipt.model_fields}
                )
                confirmation = request.model_copy(
                    update={
                        "sequence": attempt + 1,
                        "applied_revision": claim.effective.revision,
                        "applied_approval_id": claim.approval_id,
                        "effective_digest": receipt.effective_digest,
                        "approval_id": None,
                        "digest": None,
                        "receipt": receipt,
                    }
                )
                if (
                    attempt == 2**63 - 1
                    or len(confirmation.model_dump_json().encode()) > MAX_POLICY_SYNC_BYTES
                ):
                    raise ValueError("target policy receipt cannot be reported")
                self._apply(db, claim.effective, claim.approval_id, attached=False)
                db.execute(
                    "UPDATE fleet_local_policy_sync SET receipt = ? WHERE singleton = 1",
                    (receipt.model_dump_json(),),
                )
                if _claim_expired(claim, started):
                    raise ValueError("target policy claim expired before commit")
                return reply, receipt

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
        self._apply(db, effective, approval_id, attached=True)

    def _apply(
        self,
        db: sqlite3.Connection,
        effective: EffectiveFleetPolicy,
        approval_id: str,
        *,
        attached: bool,
    ) -> None:
        query = (
            "UPDATE target_state.fleet_local_policy SET applied_revision = ?, approval_id = ?, "
            "effective = ? WHERE singleton = 1"
            if attached
            else "UPDATE fleet_local_policy SET applied_revision = ?, approval_id = ?, "
            "effective = ? WHERE singleton = 1"
        )
        db.execute(
            query,
            (effective.revision, approval_id, effective.model_dump_json()),
        )
        state = _read(db, datetime.now(UTC), attached=attached)
        if state.effective != effective or state.approval_id != approval_id:
            raise ValueError("target policy readback does not match the approved policy")


def _claim_expired(claim: FleetPolicyClaim, started: float) -> bool:
    return (
        monotonic() - started >= claim.valid_for_ms / 1000 or datetime.now(UTC) >= claim.expires_at
    )
