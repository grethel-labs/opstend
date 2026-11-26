"""Complete, checkpoint-bound local captures for an application group.

This record is not an off-host receipt or permission to restore production data.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from .backups import FilesystemCapture
from .canonical import revision_id
from .config import Slug
from .group_checkpoint import GroupCheckpoint, OperationId
from .ids import graph_identifier
from .inventory import Digest


class GroupCapture(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)

    v: Literal[1] = 1
    writer_coverage: Literal["registered_containers"] = "registered_containers"
    application_consistent: Literal[False] = False
    application: Slug
    config_revision: Digest
    data_contract_revision: Digest
    operation_id: OperationId
    checkpoint_generation: int = Field(ge=1, le=259)
    created_at: float = Field(ge=0)
    completed_at: float = Field(ge=0)
    original_running: dict[Slug, StrictBool] = Field(min_length=1, max_length=64)
    data_services: list[Slug] = Field(min_length=1, max_length=64)
    captures: dict[Slug, FilesystemCapture] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def _complete(self):
        if (
            self.completed_at < self.created_at
            or self.data_services != sorted(set(self.data_services))
            or set(self.data_services) != set(self.captures)
            or not set(self.data_services) <= set(self.original_running)
        ):
            raise ValueError("incomplete application capture")
        server = None
        for service, capture in self.captures.items():
            binding = capture.binding
            if (
                binding.project != graph_identifier("s", self.application, service)
                or binding.config_revision != self.config_revision
                or capture.created_at < self.created_at
                or capture.completed_at < capture.created_at
                or capture.completed_at > self.completed_at
                or (server is not None and binding.server != server)
            ):
                raise ValueError("application capture binding mismatch")
            server = binding.server
        return self

    @property
    def id(self) -> str:
        return revision_id(self.model_dump(mode="json"))


def load_group_capture(directory, *, expected_id: str) -> GroupCapture:
    """Recheck an exact private local group artifact, including all bytes.

    The caller supplies an executor-derived directory and holds its application
    lock. This validates stored evidence, not host writer quiescence, a remote
    receipt or production recovery authority.
    """
    import os
    import re
    from pathlib import Path

    from .backupexport import acl_attributes, owned_directory, protected_capture
    from .backups import BackupError, regular_file
    from .filebackups import ARCHIVE_OVERHEAD_MAX

    if not isinstance(expected_id, str) or re.fullmatch(r"[a-f0-9]{64}", expected_id) is None:
        raise BackupError("invalid_input")
    directory = Path(directory)
    try:
        info = owned_directory(directory)
        if info.st_mode & 0o777 != 0o700 or acl_attributes(directory):
            raise BackupError("unsafe_spool")
        fd, info = regular_file(directory / "manifest.json", limit=262144)
        with os.fdopen(fd, "rb") as handle:
            if info.st_uid != os.geteuid() or info.st_mode & 0o777 != 0o600 or info.st_nlink != 1:
                raise BackupError("unsafe_spool")
            if acl_attributes(directory / "manifest.json"):
                raise BackupError("unsafe_spool")
            manifest = GroupCapture.model_validate_json(handle.read())
        if manifest.id != expected_id:
            raise BackupError("evidence_mismatch")
        if sum(item.data_bytes for item in manifest.captures.values()) > 1024 * 1024 * 1024:
            raise BackupError("limit_exceeded")
        if sum(item.size for item in manifest.captures.values()) > (
            1024 * 1024 * 1024 + len(manifest.captures) * ARCHIVE_OVERHEAD_MAX
        ):
            raise BackupError("limit_exceeded")
        names = set()
        with os.scandir(directory) as entries:
            for entry in entries:
                names.add(entry.name)
                if len(names) > 65:
                    raise BackupError("limit_exceeded")
        if names != {"manifest.json", *manifest.data_services}:
            raise BackupError("evidence_mismatch")
        for name in manifest.data_services:
            child = directory / name
            child_info = owned_directory(child)
            if child_info.st_mode & 0o777 != 0o700 or acl_attributes(child):
                raise BackupError("unsafe_spool")
            for filename in ("manifest.json", "data.tar"):
                fd, info = regular_file(child / filename)
                os.close(fd)
                if (
                    info.st_uid != os.geteuid()
                    or info.st_mode & 0o777 != 0o600
                    or info.st_nlink != 1
                    or acl_attributes(child / filename)
                ):
                    raise BackupError("unsafe_spool")
            capture = protected_capture(child)
            if capture != manifest.captures[name]:
                raise BackupError("evidence_mismatch")
        return manifest
    except BackupError:
        raise
    except (OSError, ValueError, TypeError):
        raise BackupError("invalid_input") from None


class GroupCaptureWorkflow(BaseModel):
    """Root-owned recovery intent for one automatic local group capture."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    application: Slug
    operation_id: OperationId
    data_contract_revision: Digest
    phase: Literal["prepared", "captured", "failed"] = "prepared"
    artifact: str | None = Field(None, pattern=r"^[a-f0-9]{32}$")
    capture_id: Digest | None = None
    error_class: (
        Literal[
            "bad_request",
            "conflict",
            "policy_denied",
            "kill_switch",
            "target_busy",
            "budget_exhausted",
            "execution_failed",
            "unavailable",
            "internal",
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def _state(self):
        if self.phase == "prepared" and (self.artifact or self.capture_id or self.error_class):
            raise ValueError("invalid prepared capture workflow")
        if self.phase == "captured" and (
            not self.artifact or not self.capture_id or self.error_class
        ):
            raise ValueError("invalid captured workflow")
        if self.phase == "failed" and (
            not self.error_class or bool(self.artifact) != bool(self.capture_id)
        ):
            raise ValueError("invalid failed capture workflow")
        return self


class GroupHistory(BaseModel):
    """Retained checkpoint and optional capture outcome; not a verified receipt."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)

    v: Literal[1] = 1
    archived_at: float = Field(ge=0)
    checkpoint: GroupCheckpoint
    workflow: GroupCaptureWorkflow | None = None

    @model_validator(mode="after")
    def _terminal(self):
        checkpoint, workflow = self.checkpoint, self.workflow
        if checkpoint.phase not in ("complete", "recovered"):
            raise ValueError("group history must be terminal")
        if workflow is not None and (
            workflow.application != checkpoint.plan.application
            or workflow.operation_id != checkpoint.operation_id
            or workflow.data_contract_revision != checkpoint.plan.data_contract_revision
            or workflow.phase == "prepared"
            or (workflow.phase == "captured" and checkpoint.phase != "complete")
        ):
            raise ValueError("inconsistent group history")
        return self
