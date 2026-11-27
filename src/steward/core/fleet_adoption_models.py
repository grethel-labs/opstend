"""Bounded evidence for the read-only adoption of a native PVE host."""

from hashlib import sha256
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from .pve_inventory_models import MAX_RESOURCES, NodeName, Projection, TimedProjection, Vmid

AuditPrivilege = Literal["Datastore.Audit", "Pool.Audit", "Sys.Audit", "VM.Audit"]
ScheduleState = Literal[
    "observed",
    "restricted",
    "missing",
    "unavailable",
    "invalid",
    "budget",
    "unsupported",
    "rate_limited",
]
Binding = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
NATIVE_BACKUP_JOB_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"
NativeBackupJobId = Annotated[str, Field(pattern=NATIVE_BACKUP_JOB_PATTERN)]
PveVersion = Annotated[str, Field(pattern=r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")]

_DAY = r"(?:mon|tue|wed|thu|fri|sat|sun)"
_DAYS = rf"{_DAY}(?:\.\.{_DAY})?"
_TIME = r"(?:[01]?[0-9]|2[0-3]):[0-5][0-9]"
Calendar = Annotated[
    str,
    Field(
        max_length=64,
        pattern=rf"^(?:hourly|daily|weekly|monthly|(?:{_DAYS}(?:,{_DAYS})* )?{_TIME})$",
    ),
]


def pve_backup_job_ref(instance_binding: str, native_job_id: str) -> str:
    return sha256(
        f"pve-backup-job:v1:{instance_binding}:{native_job_id}".encode("ascii")
    ).hexdigest()


class LocalPveProfile(TimedProjection):
    instance_binding: Binding
    node: NodeName
    version: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,39}$")]
    profile: Literal["pve-native/v1"] = "pve-native/v1"
    mode: Literal["standalone"] = "standalone"
    installed_roles: tuple[Literal["agent"], Literal["ui"]] = ("agent", "ui")


class PveBackupSchedule(Projection):
    job_ref: Binding
    schedule: Calendar | None = None
    enabled: bool
    vmids: tuple[Vmid, ...] = Field(min_length=1, max_length=MAX_RESOURCES)

    @field_validator("vmids")
    @classmethod
    def _ordered_vmids(cls, vmids: tuple[int, ...]) -> tuple[int, ...]:
        if vmids != tuple(sorted(set(vmids))):
            raise ValueError("invalid backup schedule selection")
        return vmids


class PveAdoptionEvidence(TimedProjection):
    node: NodeName
    pve_version: PveVersion
    audit_privileges: tuple[AuditPrivilege, ...] = Field(max_length=4)
    schedule_state: ScheduleState
    schedules: tuple[PveBackupSchedule, ...] = Field(default=(), max_length=MAX_RESOURCES)

    @model_validator(mode="after")
    def _consistent_evidence(self) -> "PveAdoptionEvidence":
        if self.audit_privileges != tuple(sorted(set(self.audit_privileges))):
            raise ValueError("invalid effective audit privileges")
        refs = tuple(job.job_ref for job in self.schedules)
        if refs != tuple(sorted(set(refs))) or (refs and self.schedule_state != "observed"):
            raise ValueError("inconsistent backup schedule evidence")
        return self
