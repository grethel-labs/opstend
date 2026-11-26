"""Durable application incident and quarantine state (L07 step 2, L08 step 1).

One record per application, written atomically (temp file, fsync, rename,
directory fsync) before and after every host effect, so a crash or reboot at
any point resumes from the recorded phase. The record is the authority for the
desired containment: a phase that implies "disconnected" keeps the route and
firewall block in force until a verified reactivation closes the incident.
Ordinary self-healing never reads or clears it.

Phases and legal transitions (anything else raises):

    notice -> disconnecting -> disconnected -> backup_pending -> backup_verified
           -> stopping -> quarantined -> fix_verification -> reactivating
           -> reactivated (closed)

Failure phases are explicit and resumable: `disconnect_failed`, `backup_failed`
(stack stays running but disconnected), `stop_failed`, `reactivation_failed`
(stays disconnected). `notice -> resolved` closes only on verified clean evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, ValidationError

from .config import Slug
from .inventory import Digest

Phase = Literal[
    "notice",
    "disconnecting",
    "disconnect_failed",
    "disconnected",
    "backup_pending",
    "backup_failed",
    "backup_verified",
    "stopping",
    "stop_failed",
    "quarantined",
    "fix_verification",
    "reactivating",
    "reactivation_failed",
    "reactivated",
    "resolved",
]
TERMINAL = frozenset({"reactivated", "resolved"})
# Phases in which the network block must be in force (and survive restart/reboot).
CONTAINED = frozenset(
    {
        "disconnecting",
        "disconnect_failed",
        "disconnected",
        "backup_pending",
        "backup_failed",
        "backup_verified",
        "stopping",
        "stop_failed",
        "quarantined",
        "fix_verification",
        "reactivating",
        "reactivation_failed",
    }
)
# Phases in which the stack must stay down across a (re)boot of the application units.
HOLD_DOWN = frozenset({"stopping", "stop_failed", "quarantined", "fix_verification"})
TRANSITIONS: dict[str, frozenset[str]] = {
    "notice": frozenset({"disconnecting", "resolved"}),
    "disconnecting": frozenset({"disconnected", "disconnect_failed"}),
    "disconnect_failed": frozenset({"disconnecting"}),
    "disconnected": frozenset({"backup_pending"}),
    "backup_pending": frozenset({"backup_verified", "backup_failed"}),
    "backup_failed": frozenset({"backup_pending"}),
    "backup_verified": frozenset({"stopping"}),
    "stopping": frozenset({"quarantined", "stop_failed"}),
    "stop_failed": frozenset({"stopping"}),
    "quarantined": frozenset({"fix_verification"}),
    "fix_verification": frozenset({"reactivating", "stopping"}),
    "reactivating": frozenset({"reactivated", "reactivation_failed"}),
    "reactivation_failed": frozenset({"reactivating"}),
    "reactivated": frozenset(),
    "resolved": frozenset(),
}
MAX_HISTORY = 64
MAX_INCIDENTS = 16
_NAME = re.compile(r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")


class IncidentError(Exception):
    def __init__(self, error_class: str):
        super().__init__(error_class)
        self.error_class = error_class


class FindingRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    service: Slug
    advisory: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,120}$")
    verdict: Literal["critical", "critical_exploited"]


class BackupRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    artifact: str = Field(pattern=r"^[a-f0-9]{32}$")
    capture_id: Digest


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    phase: Phase
    at: float = Field(ge=0)
    detail: str = Field("", max_length=120, pattern=r"^[\x20-\x7e]*$")


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    v: Literal[1] = 1
    id: str = Field(pattern=r"^inc-[a-f0-9]{16}$")
    application: Slug
    seq: StrictInt = Field(ge=1)
    phase: Phase
    opened_at: float = Field(ge=0)
    deadline: float = Field(ge=0)
    exploited: StrictBool = False
    on_critical: Literal["quarantine", "notify"] = "quarantine"
    escalated_at: float | None = Field(None, ge=0)
    config_revision: Digest
    findings: list[FindingRef] = Field(min_length=1, max_length=64)
    exposers: list[Slug] = Field(min_length=1, max_length=64)
    ports: list[int] = Field(min_length=1, max_length=64)
    vulnerable_images: dict[Slug, str] = Field(default_factory=dict, max_length=64)
    disconnected_at: float | None = Field(None, ge=0)
    backup_operation: str | None = Field(None, pattern=r"^[A-Za-z0-9-]{8,64}$")
    backup: BackupRef | None = None
    fix_started_at: float | None = Field(None, ge=0)
    error_class: str | None = Field(None, pattern=r"^[a-z_]{1,40}$")
    attempts: dict[str, int] = Field(default_factory=dict, max_length=16)
    history: list[Step] = Field(default_factory=list, max_length=MAX_HISTORY)

    @property
    def affected(self) -> list[str]:
        return sorted({f.service for f in self.findings})

    @property
    def correlation_id(self) -> str:
        return self.id

    @property
    def contained(self) -> bool:
        return self.phase in CONTAINED


def incident_id(application: str, opened_at: float) -> str:
    digest = hashlib.sha256(f"{application}/{opened_at!r}".encode()).hexdigest()
    return "inc-" + digest[:16]


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class IncidentStore:
    """File-backed store: `<dir>/<application>.json` (open) and `.closed.json` (last closed)."""

    def __init__(self, directory: str | Path):
        self.dir = Path(directory)

    def _ensure(self) -> None:
        self.dir.mkdir(mode=0o700, exist_ok=True)
        info = self.dir.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077 or not self.dir.is_dir():
            raise IncidentError("unsafe_store")

    def _path(self, application: str, suffix: str = "json") -> Path:
        if not _NAME.fullmatch(application):
            raise IncidentError("invalid_application")
        return self.dir / f"{application}.{suffix}"

    def _read(self, path: Path) -> Incident | None:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError:
            raise IncidentError("unreadable") from None
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 262144:
                raise IncidentError("unsafe_record")
            with os.fdopen(os.dup(fd), "rb") as handle:
                incident = Incident.model_validate_json(handle.read())
        except (ValidationError, ValueError, OSError):
            raise IncidentError("corrupt_record") from None
        finally:
            os.close(fd)
        if path.name.split(".")[0] != incident.application:
            raise IncidentError("corrupt_record")
        return incident

    def _write(self, path: Path, incident: Incident) -> None:
        self._ensure()
        data = incident.model_dump_json().encode()
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        _fsync_dir(self.dir)

    def get(self, application: str) -> Incident | None:
        if not self.dir.exists():
            self._path(application)  # validate the name
            return None
        return self._read(self._path(application))

    def closed(self, application: str) -> Incident | None:
        return self._read(self._path(application, "closed.json")) if self.dir.exists() else None

    def all(self) -> list[Incident]:
        """Every open record; an unreadable record raises (fail closed, never skipped)."""
        if not self.dir.exists():
            return []
        result = []
        for entry in sorted(self.dir.iterdir()):
            if entry.name.endswith(".tmp"):
                continue
            if entry.name.endswith(".closed.json"):
                continue
            if entry.suffix != ".json":
                raise IncidentError("unexpected_file")
            incident = self._read(entry)
            if incident is not None:
                result.append(incident)
            if len(result) > MAX_INCIDENTS:
                raise IncidentError("capacity")
        return result

    def contained(self) -> list[Incident]:
        return [i for i in self.all() if i.contained]

    def open(self, incident: Incident) -> Incident:
        """Create the application's incident; one open incident per application."""
        self._ensure()
        path = self._path(incident.application)
        existing = self._read(path)
        if existing is not None and existing.phase in TERMINAL:
            # A crash between archiving and unlinking left a finished record behind.
            self._write(self._path(existing.application, "closed.json"), existing)
            os.unlink(path)
            existing = None
        if existing is not None:
            raise IncidentError("exists")
        if incident.phase != "notice" or incident.seq != 1:
            raise IncidentError("invalid_open")
        incident = incident.model_copy(
            update={"history": [Step(phase="notice", at=incident.opened_at)]}
        )
        self._write(path, incident)
        return incident

    def update(self, incident: Incident, **changes: Any) -> Incident:
        """Persist non-phase changes (merge) against the stored sequence."""
        return self._commit(incident, None, 0.0, "", changes)

    def transition(
        self, incident: Incident, to: Phase, now: float, detail: str = "", **changes: Any
    ) -> Incident:
        if to not in TRANSITIONS[incident.phase]:
            raise IncidentError("illegal_transition")
        return self._commit(incident, to, now, detail, changes)

    def _commit(
        self, incident: Incident, to: Phase | None, now: float, detail: str, changes: dict
    ) -> Incident:
        path = self._path(incident.application)
        stored = self._read(path)
        if stored is None or stored.seq != incident.seq or stored.id != incident.id:
            raise IncidentError("stale_incident")
        data = {**stored.model_dump(), **changes, "seq": stored.seq + 1}
        if to is not None:
            history = [*stored.history, Step(phase=to, at=now, detail=detail[:120])]
            data.update(phase=to, history=[s.model_dump() for s in history[-MAX_HISTORY:]])
        updated = Incident.model_validate(data)
        self._write(path, updated)
        if updated.phase in TERMINAL:
            self._write(self._path(updated.application, "closed.json"), updated)
            os.unlink(path)
            _fsync_dir(self.dir)
        return updated


def summary(incident: Incident) -> dict[str, Any]:
    """Bounded status view; carries no paths, commands or secrets."""
    return json.loads(
        incident.model_dump_json(
            include={
                "id",
                "application",
                "phase",
                "opened_at",
                "deadline",
                "exploited",
                "on_critical",
                "escalated_at",
                "exposers",
                "findings",
                "disconnected_at",
                "backup",
                "error_class",
                "history",
            }
        )
    )
