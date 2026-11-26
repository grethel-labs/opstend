"""Fail-closed checkpoints for future executor-owned application groups.

The state machine has no host effects and grants no authority. The executor must
revalidate its plan against the root-owned registry and hold the derived locks
before using a checkpoint to perform or recover any operation.
"""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StringConstraints, model_validator

from .config import Slug
from .ids import graph_identifier
from .inventory import Digest

MAX_GROUP_CHECKPOINTS = 256
MAX_GROUP_GENERATION = 259

OperationId = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]


class DeploymentFence(BaseModel):
    """A durable, explicitly resumed deployment intent; it never expires itself."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    operation_id: OperationId
    base_revision: Digest
    desired_revision: Digest


class GroupPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    config_revision: Digest
    application: Slug
    target: Slug
    scope: Literal["dependents", "application"] = "dependents"
    data_contract_revision: Digest | None = None
    lock_targets: list[str] = Field(min_length=2, max_length=65)
    stop_order: list[Slug] = Field(min_length=1, max_length=64)
    start_order: list[Slug] = Field(min_length=1, max_length=64)
    external_dependencies: list[Slug] = Field(default_factory=list, max_length=64)
    external_desired_running: dict[Slug, StrictBool]
    desired_running: dict[Slug, StrictBool]

    @model_validator(mode="after")
    def _consistent(self) -> GroupPlan:
        affected = set(self.start_order)
        external = set(self.external_dependencies)
        if (
            len(affected) != len(self.start_order)
            or self.target not in affected
            or self.stop_order != list(reversed(self.start_order))
            or len(external) != len(self.external_dependencies)
            or self.external_dependencies != sorted(external)
            or affected & external
            or (self.scope == "application" and external)
            or (self.scope == "dependents" and self.data_contract_revision is not None)
            or set(self.desired_running) != affected
            or set(self.external_desired_running) != external
            or len(affected | external) > 64
        ):
            raise ValueError("inconsistent group plan")
        expected = sorted(
            ["application-" + graph_identifier("a", self.application)]
            + [
                "project-" + graph_identifier("s", self.application, name)
                for name in affected | external
            ]
        )
        if len(set(expected)) != len(expected) or self.lock_targets != expected:
            raise ValueError("invalid group lock bindings")
        return self


class PendingStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    kind: Literal["stop", "resume"]
    service: Slug


class GroupCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)

    v: Literal[1] = 1
    operation_id: OperationId
    generation: int = Field(0, ge=0, le=MAX_GROUP_GENERATION)
    plan: GroupPlan
    original_running: dict[Slug, StrictBool]
    phase: Literal["stopping", "paused", "resuming", "complete", "recovering", "recovered"] = (
        "stopping"
    )
    stop_index: int = Field(0, ge=0)
    resume_index: int = Field(0, ge=0)
    recovery_index: int = Field(0, ge=0)
    operator_managed: StrictBool = False
    recovery_from_pending: StrictBool = False
    pending: PendingStep | None = None

    def persisted_json(self) -> str:
        """Write the v1 checkpoint shape understood by previous releases."""
        return self.model_dump_json(exclude={"operator_managed"})

    def with_persisted_owner(self, marker_application: str | None) -> GroupCheckpoint:
        """Validate the separately stored operator ownership of a persisted row."""
        operator_id = UUID(self.operation_id).version == 5
        if (
            self.operator_managed
            or (marker_application is not None) != operator_id
            or (operator_id and marker_application != self.plan.application)
        ):
            raise ValueError("inconsistent persisted group checkpoint ownership")
        if operator_id:
            return GroupCheckpoint.model_validate(
                {**self.model_dump(mode="python"), "operator_managed": True}
            )
        return self

    @model_validator(mode="after")
    def _consistent(self) -> GroupCheckpoint:
        n = len(self.plan.start_order)
        if (
            (self.operator_managed and self.plan.scope != "dependents")
            or set(self.original_running) != set(self.plan.start_order)
            or any(
                running and not self.plan.desired_running[name]
                for name, running in self.original_running.items()
            )
            or self.stop_index > n
            or self.resume_index > n
            or self.recovery_index > self.stop_index
            or (
                self.phase not in ("recovering", "recovered")
                and (self.recovery_index != 0 or self.recovery_from_pending)
            )
        ):
            raise ValueError("invalid original group intent")
        if self.phase == "stopping":
            if self.resume_index != 0:
                raise ValueError("invalid stopping checkpoint")
            expected = self.plan.stop_order[self.stop_index] if self.stop_index < n else None
            kind = "stop"
            expected_generation = 2 * self.stop_index + int(self.pending is not None)
        elif self.phase == "paused":
            if self.stop_index != n or self.resume_index != 0 or self.pending is not None:
                raise ValueError("invalid paused checkpoint")
            expected, kind = None, None
            expected_generation = 2 * n + 1
        elif self.phase == "resuming":
            if self.stop_index != n:
                raise ValueError("invalid resuming checkpoint")
            expected = self.plan.start_order[self.resume_index] if self.resume_index < n else None
            kind = "resume"
            expected_generation = 2 * n + 2 + 2 * self.resume_index + int(self.pending is not None)
        elif self.phase == "complete":
            if self.stop_index != n or self.resume_index != n or self.pending is not None:
                raise ValueError("invalid completed checkpoint")
            expected, kind = None, None
            expected_generation = 4 * n + 3
        else:
            if self.resume_index != 0 or (self.recovery_from_pending and self.stop_index == n):
                raise ValueError("invalid group recovery checkpoint")
            recovery_order = list(reversed(self.plan.stop_order[: self.stop_index]))
            base = 2 * self.stop_index + 1 + int(self.recovery_from_pending)
            if self.phase == "recovering":
                expected = (
                    recovery_order[self.recovery_index]
                    if self.recovery_index < self.stop_index
                    else None
                )
                kind = "resume"
                expected_generation = base + 2 * self.recovery_index + int(self.pending is not None)
            else:
                if self.recovery_index != self.stop_index or self.pending is not None:
                    raise ValueError("invalid recovered checkpoint")
                expected, kind = None, None
                expected_generation = base + 2 * self.recovery_index + 1
        if self.pending is not None and (
            expected is None or self.pending.kind != kind or self.pending.service != expected
        ):
            raise ValueError("invalid pending group step")
        if self.generation != expected_generation:
            raise ValueError("invalid group checkpoint generation")
        return self

    def advance(self, transition: str, *, observed_running: bool | None = None) -> GroupCheckpoint:
        """Produce one validated transition; never alter host state."""
        data = self.model_dump(mode="python")
        n = len(self.plan.start_order)
        if transition == "prepare" and observed_running is None and self.pending is None:
            if self.phase == "stopping" and self.stop_index < n:
                data["pending"] = {"kind": "stop", "service": self.plan.stop_order[self.stop_index]}
            elif self.phase == "resuming" and self.resume_index < n:
                data["pending"] = {
                    "kind": "resume",
                    "service": self.plan.start_order[self.resume_index],
                }
            elif self.phase == "recovering" and self.recovery_index < self.stop_index:
                order = list(reversed(self.plan.stop_order[: self.stop_index]))
                data["pending"] = {"kind": "resume", "service": order[self.recovery_index]}
            else:
                raise ValueError("group step cannot be prepared")
        elif (
            transition == "confirm" and type(observed_running) is bool and self.pending is not None
        ):
            expected = (
                False
                if self.pending.kind == "stop"
                else self.original_running[self.pending.service]
            )
            if observed_running != expected:
                raise ValueError("observed group state does not match intent")
            key = (
                "stop_index"
                if self.pending.kind == "stop"
                else "recovery_index"
                if self.phase == "recovering"
                else "resume_index"
            )
            data[key] += 1
            data["pending"] = None
        elif transition == "recover" and self.phase == "stopping":
            if self.pending is None:
                if observed_running is not None:
                    raise ValueError("unexpected recovery observation")
            elif (
                type(observed_running) is not bool
                or observed_running != self.original_running[self.pending.service]
            ):
                raise ValueError("pending stop is not in its original state")
            data["recovery_from_pending"] = self.pending is not None
            data["pending"] = None
            data["phase"] = "recovering"
        elif (
            transition == "finish_recovery"
            and observed_running is None
            and self.phase == "recovering"
        ):
            if self.recovery_index != self.stop_index or self.pending is not None:
                raise ValueError("group recovery is incomplete")
            data["phase"] = "recovered"
        elif transition == "pause" and observed_running is None and self.phase == "stopping":
            if self.stop_index != n or self.pending is not None:
                raise ValueError("group has not stopped")
            data["phase"] = "paused"
        elif transition == "resume" and observed_running is None and self.phase == "paused":
            data["phase"] = "resuming"
        elif transition == "finish" and observed_running is None and self.phase == "resuming":
            if self.resume_index != n or self.pending is not None:
                raise ValueError("group has not resumed")
            data["phase"] = "complete"
        else:
            raise ValueError("invalid group checkpoint transition")
        data["generation"] += 1
        return GroupCheckpoint.model_validate(data)
