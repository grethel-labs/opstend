"""Private Proxmox clone policy, evidence and durable job records."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, TypeAdapter, field_validator, model_validator

from .pve_inventory_models import (
    MAX_RESOURCES,
    GuestKind,
    NodeName,
    PoolName,
    Projection,
    ResourceName,
    Vmid,
)
from .pve_power import (
    UPID_PATTERN,
    Digest,
    ErrorCode,
    GuestTarget,
    GuestUid,
    JobId,
    JobRecord,
    JobState,
    LegState,
    PowerActor,
    RegistrationTime,
    _digest,
    _VersionedProjection,
)

ProvisionName = Annotated[str, Field(pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")]
ConfigDigest = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
CLONE_UPID_PATTERN = UPID_PATTERN.replace("(?:start|shutdown)", "clone")
CloneUpid = Annotated[str, Field(max_length=512, pattern=f"^{CLONE_UPID_PATTERN}$")]
PositiveSize = Annotated[int, Field(gt=0, le=2**63 - 1)]
NonnegativeSize = Annotated[int, Field(ge=0, le=2**63 - 1)]


class ProvisionNetwork(Projection):
    index: Annotated[int, Field(ge=0, le=255)]
    bridge: ResourceName
    vlan_tag: Annotated[int, Field(ge=1, le=4094)] | None = None
    link_down: bool = False


class _NetworkProfile(Projection):
    networks: tuple[ProvisionNetwork, ...] = Field(max_length=256)

    @field_validator("networks")
    @classmethod
    def _normalize_networks(
        cls, networks: tuple[ProvisionNetwork, ...]
    ) -> tuple[ProvisionNetwork, ...]:
        if len({network.index for network in networks}) != len(networks):
            raise ValueError("duplicate network index")
        return tuple(sorted(networks, key=lambda network: network.index))


class ProvisionLimits(Projection):
    max_vcpus: PositiveSize
    max_memory_mib: PositiveSize
    max_disk_bytes: PositiveSize
    max_swap_mib: NonnegativeSize


class ProvisionTemplate(Projection):
    kind: GuestKind
    vmid: Vmid
    pve_uid: GuestUid = Field(repr=False)
    registered_at_ms: RegistrationTime = Field(repr=False)
    config_digest: ConfigDigest = Field(repr=False)


class ProvisionTarget(_NetworkProfile):
    vmid: Vmid
    template_vmid: Vmid
    pool: PoolName
    storage: ResourceName
    limits: ProvisionLimits

    @model_validator(mode="after")
    def _distinct_vmids(self) -> Self:
        if self.vmid == self.template_vmid:
            raise ValueError("template and destination VMIDs must differ")
        return self


class ProvisionPolicy(_VersionedProjection):
    node: NodeName
    write_token_file: str = Field(min_length=1, max_length=4096, repr=False)
    templates: tuple[ProvisionTemplate, ...] = Field(max_length=MAX_RESOURCES)
    targets: tuple[ProvisionTarget, ...] = Field(max_length=MAX_RESOURCES)

    @model_validator(mode="after")
    def _consistent_vmids(self) -> Self:
        templates = {template.vmid for template in self.templates}
        targets = {target.vmid for target in self.targets}
        if len(templates) != len(self.templates) or len(targets) != len(self.targets):
            raise ValueError("duplicate provisioning VMID")
        if templates & targets:
            raise ValueError("template and destination VMIDs must be disjoint")
        if any(target.template_vmid not in templates for target in self.targets):
            raise ValueError("destination references an unregistered template")
        return self

    def template(self, vmid: int) -> ProvisionTemplate | None:
        return next((template for template in self.templates if template.vmid == vmid), None)

    def target(self, vmid: int) -> ProvisionTarget | None:
        return next((target for target in self.targets if target.vmid == vmid), None)

    @property
    def revision(self) -> str:
        policy = self.model_dump(mode="json")
        policy["templates"].sort(key=lambda template: template["vmid"])
        policy["targets"].sort(key=lambda target: target["vmid"])
        return _digest(json.dumps(policy, sort_keys=True, separators=(",", ":")))


class CloneProfile(_NetworkProfile):
    vcpus: PositiveSize
    memory_mib: PositiveSize
    disk_bytes: PositiveSize
    swap_mib: NonnegativeSize

    def fits(self, target: ProvisionTarget) -> bool:
        return (
            self.networks == target.networks
            and self.vcpus <= target.limits.max_vcpus
            and self.memory_mib <= target.limits.max_memory_mib
            and self.disk_bytes <= target.limits.max_disk_bytes
            and self.swap_mib <= target.limits.max_swap_mib
        )


class TemplateEvidence(Projection):
    pve_uid: GuestUid = Field(repr=False)
    registered_at_ms: RegistrationTime = Field(repr=False)
    config_digest: ConfigDigest = Field(repr=False)
    profile: CloneProfile

    def matches(self, template: ProvisionTemplate) -> bool:
        return (
            self.pve_uid == template.pve_uid
            and self.registered_at_ms == template.registered_at_ms
            and self.config_digest == template.config_digest
        )


class ProvisionedGuest(Projection):
    pve_uid: GuestUid = Field(repr=False)
    registered_at_ms: RegistrationTime = Field(repr=False)
    state: Literal["stopped"] = "stopped"

    @property
    def generation(self) -> str:
        return _digest(f"{self.pve_uid}:{self.registered_at_ms}")


class CloneLeg(Projection):
    operation: Literal["clone"] = "clone"
    dispatched_at: AwareDatetime
    actor: PowerActor = Field(repr=False)
    upid: CloneUpid | None = Field(default=None, repr=False)
    prior_upids: Annotated[tuple[CloneUpid, ...], Field(max_length=8)] | None = Field(
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
        if self.prior_upids is not None and self.upid in self.prior_upids:
            raise ValueError("native task predates dispatch intent")
        return self


class ProvisionJob(_VersionedProjection):
    job_id: JobId
    operation: Literal["clone"] = "clone"
    target: GuestTarget
    source: GuestTarget
    destination: ProvisionTarget
    name: ProvisionName
    observation: TemplateEvidence = Field(repr=False)
    policy_revision: Digest = Field(repr=False)
    binding: Digest = Field(repr=False)
    created_at: AwareDatetime
    expires_at: AwareDatetime
    updated_at: AwareDatetime
    state: JobState
    next_action: Literal["execute", "reconcile"] | None = None
    error_code: ErrorCode | None = None
    legs: tuple[CloneLeg, ...] = Field(default=(), max_length=1, repr=False)
    result: ProvisionedGuest | None = Field(default=None, repr=False)

    @field_validator("created_at", "expires_at", "updated_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_record(self) -> Self:
        if self.expires_at <= self.created_at or self.updated_at < self.created_at:
            raise ValueError("invalid job timestamps")
        if (
            self.source.node != self.target.node
            or self.source.kind != self.target.kind
            or self.source.vmid != self.destination.template_vmid
            or self.target.vmid != self.destination.vmid
        ):
            raise ValueError("clone source and destination disagree")
        if not self.observation.profile.fits(self.destination):
            raise ValueError("template profile exceeds destination policy")
        if self.state == "prepared" and self.legs:
            raise ValueError("prepared job has a dispatch intent")
        for leg in self.legs:
            if leg.upid is not None and not self._matches_task(leg, leg.upid):
                raise ValueError("native task does not match source and actor")
            if any(not self._matches_task(leg, upid) for upid in leg.prior_upids or ()):
                raise ValueError("prior native task does not match source and actor")
        if (self.result is not None) != (self.state == "succeeded"):
            raise ValueError("job state and result disagree")
        if self.result is not None and (not self.legs or self.legs[0].state != "succeeded"):
            raise ValueError("successful clone has no successful native task")
        return self

    def _matches_task(self, leg: CloneLeg, upid: CloneUpid) -> bool:
        # Native QEMU and LXC clone workers report the template VMID.
        task = re.fullmatch(CLONE_UPID_PATTERN, upid)
        worker = "qmclone" if self.source.kind == "qemu" else "vzclone"
        return task is not None and (task["node"], task["worker"], task["vmid"], task["actor"]) == (
            self.source.node,
            worker,
            str(self.source.vmid),
            leg.actor,
        )

    def public(self) -> dict:
        projection = self.model_dump(
            mode="json",
            include={
                "schema_version",
                "job_id",
                "operation",
                "target",
                "source",
                "name",
                "state",
                "created_at",
                "expires_at",
                "updated_at",
                "next_action",
                "error_code",
            },
        )
        projection.update(
            self.destination.model_dump(
                mode="json", include={"pool", "storage", "networks", "limits"}
            )
        )
        projection["resources"] = self.observation.profile.model_dump(
            mode="json", exclude={"networks"}
        )
        projection["tasks"] = [
            {
                "operation": leg.operation,
                "task_ref": _digest(leg.upid),
                "state": leg.state
                if leg.state in {"running", "succeeded", "failed"}
                else "accepted",
            }
            for leg in self.legs
            if leg.upid is not None
        ]
        projection["result"] = (
            {"state": self.result.state, "generation": self.result.generation}
            if self.result is not None
            else None
        )
        return projection


_JournalRecord = Annotated[JobRecord | ProvisionJob, Field(discriminator="operation")]
JOURNAL_RECORD_ADAPTER = TypeAdapter(_JournalRecord)
