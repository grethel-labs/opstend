"""Bounded command contract for the enrolled Proxmox power target."""

from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from .fleet_policy import FleetTarget, PolicyName, RegistryId, RevisionId
from .pve_inventory_models import GuestKind, NodeName, Projection, ResourceName, Vmid
from .pve_power import ErrorCode, GuestState, GuestTarget, GuestUid, JobId, RegistrationTime

PowerAction = Literal["start"]
CommandKey = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]
CommandPhase = Literal["prepare", "execute", "reconcile"]
ReportState = Literal["prepared", "refused", "accepted", "uncertain", "succeeded", "failed"]
CommandState = Literal[
    "preparing",
    "review",
    "queued",
    "released",
    "accepted",
    "uncertain",
    "succeeded",
    "failed",
    "refused",
    "expired",
]
EnrollmentGeneration = Annotated[int, Field(ge=1, le=2**63 - 1)]
CLAIM_MS = 10_000


class PowerScope(GuestTarget):
    instance_binding: RevisionId = Field(repr=False)
    pve_uid: GuestUid = Field(repr=False)
    registered_at_ms: RegistrationTime = Field(repr=False)


class CommandSpec(Projection):
    command_id: JobId
    target: FleetTarget
    scope: PowerScope
    policy_revision: RevisionId
    policy_approval: RegistryId
    local_revision: RevisionId
    subject: PolicyName
    role: Literal["operator"] = "operator"
    agent_id: RegistryId
    enrollment_generation: EnrollmentGeneration
    expires_at: AwareDatetime
    action: PowerAction = "start"

    @model_validator(mode="after")
    def _guest(self) -> Self:
        if self.target.kind != "pve_guest":
            raise ValueError("command requires a guest target")
        return self


class CommandWork(Projection):
    phase: CommandPhase
    spec: CommandSpec
    native_digest: RevisionId | None = None
    claim_id: RegistryId
    recipient_generation: EnrollmentGeneration
    claim_until: AwareDatetime
    valid_for_ms: Annotated[int, Field(ge=1, le=CLAIM_MS)]

    @model_validator(mode="after")
    def _phase(self) -> Self:
        if (self.phase == "prepare") != (self.native_digest is None):
            raise ValueError("native digest must agree with the work phase")
        if self.phase != "reconcile" and (
            self.claim_until > self.spec.expires_at
            or self.recipient_generation != self.spec.enrollment_generation
        ):
            raise ValueError("pre-dispatch claim exceeds its approved scope")
        if self.recipient_generation < self.spec.enrollment_generation:
            raise ValueError("work claim predates the enrolled target")
        return self


class CommandReport(Projection):
    command_id: JobId
    claim_id: RegistryId
    state: ReportState
    native_digest: RevisionId | None = None
    reason: ErrorCode | None = None
    task_ref: RevisionId | None = Field(default=None, repr=False)
    observed_state: GuestState | None = None

    @model_validator(mode="after")
    def _result(self) -> Self:
        if self.state not in ("refused", "failed") and self.native_digest is None:
            raise ValueError("native plan digest is required")
        if self.state in ("accepted", "succeeded") and self.task_ref is None:
            raise ValueError("native task reference is required")
        if self.state == "succeeded" and self.observed_state != "running":
            raise ValueError("start readback must show running")
        if self.state in ("prepared", "refused") and (
            self.task_ref is not None or self.observed_state is not None
        ):
            raise ValueError("pre-dispatch report carries execution evidence")
        return self


class CommandPoll(Projection):
    target: FleetTarget
    local_revision: RevisionId
    policy_revision: RevisionId
    policy_approval: RegistryId
    report: CommandReport | None = None

    @model_validator(mode="after")
    def _guest(self) -> Self:
        if self.target.kind != "pve_guest":
            raise ValueError("power polling requires a guest target")
        return self


class CommandReply(Projection):
    work: CommandWork | None = None


class _PublicTarget(Projection):
    target: FleetTarget
    name: ResourceName | None
    instance_id: RegistryId
    node: NodeName
    kind: GuestKind
    vmid: Vmid
    policy_revision: RevisionId


class CommandTarget(_PublicTarget):
    pass


class CommandStatus(_PublicTarget):
    command_id: JobId
    action: PowerAction
    subject: PolicyName
    role: Literal["operator"]
    expires_at: AwareDatetime
    state: CommandState
    digest: RevisionId | None = None
    reason: ErrorCode | None = None
    observed_state: GuestState | None = None
    task_ref: RevisionId | None = None


class CommandCatalog(Projection):
    targets: tuple[CommandTarget, ...]
    commands: tuple[CommandStatus, ...]
