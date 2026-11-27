"""Wire contracts for the handoff of one native PVE guest and schedule."""

from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from .canonical import revision_id
from .fleet_adoption_models import Calendar
from .fleet_policy import FleetTarget, PolicyName, RegistryId, RevisionId
from .fleet_power import CLAIM_MS, EnrollmentGeneration, PowerScope
from .pve_inventory_models import Projection
from .pve_power import JobId

Owner = Literal["standalone", "fleet"]
OwnershipState = Literal["pausing", "committed", "active", "canceled"]
OwnershipEpoch = Annotated[int, Field(ge=0, le=2**63 - 1)]


class OwnershipPlan(Projection):
    transition_id: JobId
    target: FleetTarget
    scope: PowerScope = Field(repr=False)
    instance_id: RegistryId
    schedule_ref: RevisionId
    calendar: Calendar
    profile: PolicyName
    previous_owner: Owner
    next_owner: Owner
    epoch: Annotated[OwnershipEpoch, Field(lt=2**63 - 1)]
    policy_revision: RevisionId
    policy_approval: RegistryId
    local_revision: RevisionId
    subject: PolicyName
    agent_id: RegistryId
    enrollment_generation: EnrollmentGeneration

    @model_validator(mode="after")
    def _validate_transition(self) -> Self:
        if self.target.kind != "pve_guest" or self.previous_owner == self.next_owner:
            raise ValueError("ownership handoff requires a guest and a change of owner")
        return self

    @property
    def digest(self) -> str:
        return revision_id(self.model_dump(mode="json"))


class OwnershipStatus(Projection):
    transition_id: JobId
    digest: RevisionId
    target: FleetTarget
    instance_id: RegistryId
    schedule_ref: RevisionId
    calendar: Calendar
    profile: PolicyName
    previous_owner: Owner
    next_owner: Owner
    owner: Owner
    epoch: OwnershipEpoch
    state: OwnershipState
    subject: PolicyName
    policy_revision: RevisionId

    @classmethod
    def from_plan(cls, plan: OwnershipPlan, state: OwnershipState) -> Self:
        changed = state in ("committed", "active")
        return cls(
            **plan.model_dump(
                include={
                    "transition_id",
                    "target",
                    "instance_id",
                    "schedule_ref",
                    "calendar",
                    "profile",
                    "previous_owner",
                    "next_owner",
                    "subject",
                    "policy_revision",
                }
            ),
            digest=plan.digest,
            owner=plan.next_owner if changed else plan.previous_owner,
            epoch=plan.epoch + changed,
            state=state,
        )


class OwnershipClaim(Projection):
    claim_until: AwareDatetime
    valid_for_ms: Annotated[int, Field(ge=1, le=CLAIM_MS)]


class OwnershipReceipt(Projection):
    state: Literal["committed", "active", "canceled"]
    epoch: OwnershipEpoch
    schedule_fingerprint: RevisionId


class OwnershipExchange(Projection):
    target: FleetTarget
    transition_id: JobId
    digest: RevisionId
    receipt: OwnershipReceipt | None = None

    @model_validator(mode="after")
    def _validate_target(self) -> Self:
        if self.target.kind != "pve_guest":
            raise ValueError("ownership exchanges require a guest target")
        return self


class OwnershipReply(Projection):
    status: OwnershipStatus
    plan: OwnershipPlan
    claim: OwnershipClaim | None = None

    @model_validator(mode="after")
    def _validate_plan(self) -> Self:
        if self.status != OwnershipStatus.from_plan(self.plan, self.status.state) or (
            self.claim is not None and self.status.state != "pausing"
        ):
            raise ValueError("ownership reply does not match its plan")
        return self


class LocalOwnershipRequest(Projection):
    action: Literal["prepare", "confirm", "resume", "cancel", "status"]
    transition_id: JobId | None = None
    digest: RevisionId | None = None

    @model_validator(mode="after")
    def _validate_identity(self) -> Self:
        if self.action == "status":
            if self.transition_id is not None or self.digest is not None:
                raise ValueError("local ownership status does not take a plan")
        elif self.transition_id is None or self.digest is None:
            raise ValueError("local ownership operation requires the exact transition and digest")
        return self


class NativeOwnershipRecord(Projection):
    plan: OwnershipPlan
    state: OwnershipState
    schedule_fingerprint: RevisionId

    @property
    def owner(self) -> Owner:
        return self.status.owner

    @property
    def epoch(self) -> int:
        return self.status.epoch

    @property
    def status(self) -> OwnershipStatus:
        return OwnershipStatus.from_plan(self.plan, self.state)

    @property
    def receipt(self) -> OwnershipReceipt | None:
        if self.state == "pausing":
            return None
        return OwnershipReceipt(
            state=self.state, epoch=self.epoch, schedule_fingerprint=self.schedule_fingerprint
        )
