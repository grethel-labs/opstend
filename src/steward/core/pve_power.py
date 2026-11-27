"""Private Proxmox guest power policy and durable job records."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from contextlib import closing, contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, Self

from pydantic import AwareDatetime, Field, ValidationError, field_validator, model_validator

from steward import __version__

from .pve_inventory_models import MAX_RESOURCES, GuestKind, NodeName, Projection, Vmid

if TYPE_CHECKING:
    from .pve_provision import ProvisionJob


PowerOperation = Literal["start", "shutdown", "reboot"]
LegOperation = Literal["start", "shutdown"]
GuestState = Literal["running", "stopped"]
JobState = Literal[
    "prepared", "dispatching", "accepted", "verifying", "succeeded", "failed", "uncertain"
]
LegState = Literal["dispatching", "accepted", "running", "succeeded", "failed", "uncertain"]
_JOB_ID = r"[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}"
JobId = Annotated[str, Field(pattern=f"^{_JOB_ID}$")]
_ACTOR = r"[A-Za-z0-9_.+%-]+@[A-Za-z][A-Za-z0-9_.-]*![A-Za-z][A-Za-z0-9_.-]*"
PowerActor = Annotated[str, Field(max_length=255, pattern=f"^{_ACTOR}$")]
UPID_PATTERN = (
    r"UPID:(?P<node>[A-Za-z0-9][A-Za-z0-9-]{0,62}):(?P<pid>[0-9A-F]{8}):"
    r"(?P<pstart>[0-9A-F]{8,9}):(?P<start>[0-9A-F]{8}):"
    rf"(?P<worker>(?:qm|vz)(?:start|shutdown)):(?P<vmid>[1-9][0-9]{{2,8}}):(?P<actor>{_ACTOR}):"
)
Upid = Annotated[str, Field(max_length=512, pattern=f"^{UPID_PATTERN}$")]
GuestUid = Annotated[str, Field(pattern=r"^[a-z2-7]{20}$")]
RegistrationTime = Annotated[int, Field(gt=0, le=999_999_999_999_999)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ErrorCode = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class _VersionedProjection(Projection):
    schema_version: Literal[1] = 1

    @field_validator("schema_version", mode="before")
    @classmethod
    def _strict_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("invalid schema version")
        return value


class GuestTarget(Projection):
    node: NodeName
    kind: GuestKind
    vmid: Vmid


class RegisteredGuest(Projection):
    kind: GuestKind
    vmid: Vmid
    pve_uid: GuestUid = Field(repr=False)
    registered_at_ms: RegistrationTime = Field(repr=False)
    operations: tuple[PowerOperation, ...] = Field(min_length=1, max_length=3)

    @field_validator("operations")
    @classmethod
    def _unique(cls, operations: tuple[PowerOperation, ...]) -> tuple[PowerOperation, ...]:
        if len(set(operations)) != len(operations):
            raise ValueError("duplicate power operations")
        return operations


class PowerPolicy(_VersionedProjection):
    node: NodeName
    write_token_file: str = Field(min_length=1, max_length=4096, repr=False)
    guests: tuple[RegisteredGuest, ...] = Field(max_length=MAX_RESOURCES)

    @field_validator("guests")
    @classmethod
    def _unique(cls, guests: tuple[RegisteredGuest, ...]) -> tuple[RegisteredGuest, ...]:
        if len({guest.vmid for guest in guests}) != len(guests):
            raise ValueError("duplicate registered VMID")
        return guests

    def guest(self, vmid: int) -> RegisteredGuest | None:
        return next((guest for guest in self.guests if guest.vmid == vmid), None)

    @property
    def revision(self) -> str:
        policy = self.model_dump(mode="json")
        # Guest and operation order do not affect what the policy authorizes.
        policy["guests"].sort(key=lambda guest: guest["vmid"])
        for guest in policy["guests"]:
            guest["operations"].sort()
        return _digest(json.dumps(policy, sort_keys=True, separators=(",", ":")))


class GuestObservation(Projection):
    pve_uid: GuestUid = Field(repr=False)
    registered_at_ms: RegistrationTime = Field(repr=False)
    state: GuestState
    pid: Annotated[int, Field(gt=0, le=2**31 - 1)] | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def _state_pid(self) -> Self:
        if (self.state == "running") != (self.pid is not None):
            raise ValueError("guest state and process ID disagree")
        return self


class PowerLeg(Projection):
    operation: LegOperation
    dispatched_at: AwareDatetime
    actor: PowerActor = Field(repr=False)
    upid: Upid | None = Field(default=None, repr=False)
    prior_upids: Annotated[tuple[Upid, ...], Field(max_length=8)] | None = Field(
        default=None, repr=False
    )
    state: LegState

    @field_validator("dispatched_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _task_state(self) -> Self:
        if self.state in {"accepted", "running", "succeeded"} and self.upid is None:
            raise ValueError("missing native task")
        if self.state == "dispatching" and self.upid is not None:
            raise ValueError("dispatch intent already has a native task")
        return self


class JobRecord(_VersionedProjection):
    job_id: JobId
    operation: PowerOperation
    target: GuestTarget
    policy_revision: Digest = Field(repr=False)
    binding: Digest = Field(repr=False)
    observation: GuestObservation = Field(repr=False)
    created_at: AwareDatetime
    expires_at: AwareDatetime
    updated_at: AwareDatetime
    state: JobState
    current_state: GuestState | None = None
    next_action: Literal["execute", "reconcile"] | None = None
    error_code: ErrorCode | None = None
    legs: tuple[PowerLeg, ...] = Field(default=(), max_length=2, repr=False)
    fleet_origin: Digest | None = Field(default=None, repr=False)

    @field_validator("created_at", "expires_at", "updated_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_record(self) -> Self:
        if self.expires_at <= self.created_at or self.updated_at < self.created_at:
            raise ValueError("invalid job timestamps")
        expected = ("shutdown", "start") if self.operation == "reboot" else (self.operation,)
        if tuple(leg.operation for leg in self.legs) != expected[: len(self.legs)]:
            raise ValueError("invalid power leg sequence")
        if self.state == "prepared" and self.legs:
            raise ValueError("prepared job has a dispatch intent")
        if self.fleet_origin is not None and self.operation != "start":
            raise ValueError("fleet origin requires a native start job")
        return self

    @property
    def desired_state(self) -> GuestState:
        return "stopped" if self.operation == "shutdown" else "running"

    def public(self) -> dict:
        projection = self.model_dump(
            mode="json",
            include={
                "schema_version",
                "job_id",
                "operation",
                "target",
                "state",
                "created_at",
                "expires_at",
                "updated_at",
                "current_state",
                "next_action",
                "error_code",
            },
        )
        projection.update(
            observed_state=self.observation.state,
            desired_state=self.desired_state,
            tasks=[
                {
                    "operation": leg.operation,
                    "task_ref": _digest(leg.upid),
                    "state": leg.state
                    if leg.state in {"running", "succeeded", "failed"}
                    else "accepted",
                }
                for leg in self.legs
                if leg.upid is not None
            ],
        )
        return projection


JournalErrorCode = Literal[
    "journal_unavailable", "journal_conflict", "target_busy", "task_conflict", "invalid_job_id"
]


class PowerJournalError(ValueError):
    """A journal failure with a code safe for operator output."""

    def __init__(self, code: JournalErrorCode) -> None:
        self.code = code
        super().__init__(code)


_FENCED = {"dispatching", "accepted", "verifying", "uncertain"}
_PLAN_FIELDS = {
    "schema_version",
    "job_id",
    "operation",
    "target",
    "policy_revision",
    "binding",
    "observation",
    "created_at",
    "expires_at",
    "fleet_origin",
    "source",
    "destination",
    "name",
}


class PowerJournal:
    """Store guest intents and task claims in a pre-verified private state directory."""

    def __init__(self, directory: Path) -> None:
        self._directory = Path(directory).absolute()
        self._database = self._directory / "power-jobs.sqlite3"

    @staticmethod
    def _private_file(file_stat: os.stat_result) -> None:
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != os.geteuid()
            or file_stat.st_mode & 0o077
            or file_stat.st_nlink != 1
        ):
            raise PowerJournalError("journal_unavailable")

    @contextmanager
    def _connect(self, *, create: bool):
        try:
            if create:
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW
                try:
                    fd = os.open(self._database, flags, 0o600)
                except FileExistsError:
                    pass
                else:
                    os.close(fd)
            self._private_file(self._database.lstat())
            # SQLite may read a rollback journal left after a crash.
            for suffix in ("-journal", "-wal", "-shm"):
                sidecar = self._database.with_name(self._database.name + suffix)
                with suppress(FileNotFoundError):
                    self._private_file(sidecar.lstat())
            with closing(
                sqlite3.connect(self._database.as_uri() + "?mode=rw", uri=True, timeout=5)
            ) as connection:
                connection.execute("PRAGMA trusted_schema = OFF")
                connection.execute("PRAGMA synchronous = FULL")
                yield connection
        except (OSError, sqlite3.Error, ValidationError):
            raise PowerJournalError("journal_unavailable") from None

    @staticmethod
    def _initialize(connection: sqlite3.Connection) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            connection.execute(
                """
                CREATE TABLE jobs (
                    job_id TEXT PRIMARY KEY,
                    fence_vmid INTEGER UNIQUE,
                    record TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE tasks (
                    upid TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    leg_index INTEGER NOT NULL
                )
                """
            )
            connection.execute("PRAGMA user_version = 1")
        elif version != 1:
            raise PowerJournalError("journal_unavailable")

    def get(self, job_id: str) -> JobRecord | None:
        record = self._read(job_id)
        return record if isinstance(record, JobRecord) else None

    def get_provision(self, job_id: str) -> ProvisionJob | None:
        from .pve_provision import ProvisionJob

        record = self._read(job_id)
        return record if isinstance(record, ProvisionJob) else None

    def _read(self, job_id: str) -> JobRecord | ProvisionJob | None:
        if not isinstance(job_id, str) or re.fullmatch(_JOB_ID, job_id) is None:
            raise PowerJournalError("invalid_job_id")
        try:
            self._database.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            raise PowerJournalError("journal_unavailable") from None
        with self._connect(create=False) as connection:
            # A reader can arrive during the very first transaction.
            connection.execute("BEGIN")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                return None
            if version != 1:
                raise PowerJournalError("journal_unavailable")
            return self._get(connection, job_id)

    @staticmethod
    def _get(connection: sqlite3.Connection, job_id: str) -> JobRecord | ProvisionJob | None:
        from .pve_provision import JOURNAL_RECORD_ADAPTER

        row = connection.execute("SELECT record FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        return JOURNAL_RECORD_ADAPTER.validate_json(row[0]) if row is not None else None

    def write(
        self, record: JobRecord | ProvisionJob, *, previous: JobRecord | ProvisionJob | None
    ) -> None:
        from .pve_provision import JOURNAL_RECORD_ADAPTER

        with self._connect(create=True) as connection, connection:
            # The write lock covers both the comparison and the constraint checks.
            connection.execute("BEGIN IMMEDIATE")
            self._initialize(connection)
            # Keep local jobs readable by prior signed PX03 packages.
            exclude = (
                {"fleet_origin"}
                if isinstance(record, JobRecord) and record.fleet_origin is None
                else None
            )
            record_json = record.model_dump_json(exclude=exclude)
            record = JOURNAL_RECORD_ADAPTER.validate_json(record_json)
            if self._get(connection, record.job_id) != previous:
                raise PowerJournalError("journal_conflict")
            if previous is not None:
                self._validate_update(record, previous)
            fence = record.target.vmid if record.state in _FENCED else None
            try:
                connection.execute(
                    """
                    INSERT INTO jobs (job_id, fence_vmid, record) VALUES (?, ?, ?)
                    ON CONFLICT(job_id) DO UPDATE SET fence_vmid = excluded.fence_vmid,
                                                      record = excluded.record
                    """,
                    (record.job_id, fence, record_json),
                )
            except sqlite3.IntegrityError:
                raise PowerJournalError("target_busy") from None

            for index, leg in enumerate(record.legs):
                if leg.upid is None:
                    continue
                connection.execute(
                    "INSERT INTO tasks VALUES (?, ?, ?) ON CONFLICT(upid) DO NOTHING",
                    (leg.upid, record.job_id, index),
                )
                claim = connection.execute(
                    "SELECT job_id, leg_index FROM tasks WHERE upid = ?", (leg.upid,)
                ).fetchone()
                if claim != (record.job_id, index):
                    raise PowerJournalError("task_conflict")
        # Sync the directory even if another writer created the file before this transaction.
        try:
            fd = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            raise PowerJournalError("journal_unavailable") from None

    @staticmethod
    def _validate_update(
        record: JobRecord | ProvisionJob, previous: JobRecord | ProvisionJob
    ) -> None:
        if (
            record.model_dump(include=_PLAN_FIELDS) != previous.model_dump(include=_PLAN_FIELDS)
            or len(record.legs) < len(previous.legs)
            or (previous.state in {"failed", "succeeded"} and record != previous)
            or (record.state == "prepared" and previous.state != "prepared")
        ):
            raise PowerJournalError("journal_conflict")
        for before, after in zip(previous.legs, record.legs, strict=False):
            if (
                before.operation != after.operation
                or before.actor != after.actor
                or before.dispatched_at != after.dispatched_at
                or before.prior_upids != after.prior_upids
                or (before.upid is not None and before.upid != after.upid)
            ):
                raise PowerJournalError("journal_conflict")


def _installed_power_runtime() -> tuple[dict[str, Path], dict, Path]:
    """Verify the sealed installation and resolve its active versioned interpreter."""
    from . import pve_native_install as install
    from . import pve_native_lifecycle as lifecycle

    paths = lifecycle.managed_paths()
    for directory in paths.values():
        for parent in reversed(directory.parents):
            install._secure_directory(parent)
    journal = lifecycle.load_journal(paths["config"])
    lifecycle._require_idle(journal)
    if journal["active"] != __version__:
        raise install.InstallError("Native power requires the active signed installation.")
    lifecycle.verify_package(paths, journal)
    python = paths["install"] / "releases" / journal["active"] / "venv" / "bin" / "python"
    return paths, journal, python
