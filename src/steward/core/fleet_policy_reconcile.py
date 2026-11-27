"""Typed live exchange for target-owned fleet policy metadata."""

from __future__ import annotations

from typing import Annotated, Literal, get_args

from pydantic import AwareDatetime, Field, model_validator

from .canonical import revision_id
from .fleet_policy import (
    EffectiveFleetPolicy,
    FleetLocalPolicy,
    FleetTarget,
    PolicyProperty,
    RegistryId,
    RevisionId,
)
from .pve_inventory_models import Projection

Sequence = Annotated[int, Field(ge=1, le=2**63 - 1)]
CLAIM_SECONDS = 10
MAX_POLICY_SYNC_BYTES = 256 * 1024


class FleetPolicyOutcome(Projection):
    target: FleetTarget
    status: Literal["pending", "applied", "rejected"]
    reason: str | None
    conflict_owner: Literal["local_operator"] | None = None


class FleetPolicyReceipt(Projection):
    claim_id: RegistryId
    sequence: Sequence
    approval_id: RegistryId
    digest: RevisionId
    local_revision: RevisionId
    effective_digest: RevisionId


class FleetPolicyClaim(FleetPolicyReceipt):
    effective: EffectiveFleetPolicy
    prior_applied_revision: RevisionId | None
    prior_applied_approval_id: RegistryId | None
    prior_effective_digest: RevisionId | None
    expires_at: AwareDatetime
    valid_for_ms: Annotated[int, Field(ge=1, le=CLAIM_SECONDS * 1000)]


class FleetPolicySyncRequest(Projection):
    sequence: Sequence
    local: FleetLocalPolicy
    applied_revision: RevisionId | None
    applied_approval_id: RegistryId | None
    effective_digest: RevisionId | None
    approval_id: RegistryId | None = None
    digest: RevisionId | None = None
    receipt: FleetPolicyReceipt | None = None

    @model_validator(mode="after")
    def _validate_state(self) -> FleetPolicySyncRequest:
        if (self.approval_id is None) != (self.digest is None):
            raise ValueError("approval and digest must be supplied together")
        if self.local.revision != revision_id(
            {"target": self.local.target.model_dump(), "limits": self.local.limits.model_dump()}
        ):
            raise ValueError("local policy revision does not match the reported limits")
        fields = (self.applied_revision, self.applied_approval_id, self.effective_digest)
        if any(value is None for value in fields) and any(value is not None for value in fields):
            raise ValueError("reported applied metadata is incomplete")
        if self.receipt is not None and (
            self.receipt.sequence >= self.sequence
            or self.receipt.approval_id != self.applied_approval_id
            or self.receipt.effective_digest != self.effective_digest
        ):
            raise ValueError("receipt does not match reported applied metadata")
        return self


class FleetPolicySyncReply(Projection):
    sequence: Sequence
    target: FleetTarget
    outcome: FleetPolicyOutcome | None = None
    claim: FleetPolicyClaim | None = None
    acknowledged_receipt: RegistryId | None = None


def respects_limits(effective: EffectiveFleetPolicy, local: FleetLocalPolicy) -> bool:
    return (
        effective.target == local.target
        and effective.status == "ready"
        and not effective.issues
        and all(
            set(getattr(effective.values, field)).issubset(getattr(local.limits, field))
            for field in get_args(PolicyProperty)
        )
    )
