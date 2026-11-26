"""Recovery contract of a verified update (L06): when is image-only rollback enough?

The attestation (signed by the independent signer) declares one data-migration kind.
The root-owned contract lists the kinds that may be applied. This module maps the kind
to the recovery the executor must be able to perform *before* the update is admitted:

| migration          | rollback             | evidence required before admission                |
|--------------------|----------------------|---------------------------------------------------|
| `none`             | image only           | none beyond L05 (fresh backup when data exists)   |
| `reversible`       | image only, exact    | registered data, backup pause contract, fresh     |
|                    | capture as fallback  | backup (L05) and a capture taken by the update    |
|                    |                      | itself (no rehearsal); the old version reads the  |
|                    |                      | new data, the capture is the operator's exact     |
|                    |                      | fallback (`rollback --acknowledge-data-restore`)  |
| `restore_required` | exact capture restore| registered data, backup pause contract, capacity, |
|                    |                      | a capture taken by the update itself with the     |
|                    |                      | workload stopped and a verified restore rehearsal |

A migration kind without registered data cannot be recovered and is refused. Nothing
here touches the host; `executor/update_recovery.py` performs the effects.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .backups import FilesystemCapture
from .update_evidence import UpdateRejected

RecoveryMode = Literal["image_only", "reversible_capture", "restore_required"]
# Modes in which the update itself stops the workload and captures its data first.
CAPTURE_MODES = ("reversible_capture", "restore_required")
# Captures taken by an update are limited to what the restore primitive can verify.
MAX_PRESERVED_TREES = 8


class CaptureRef(BaseModel):
    """The exact capture a data restore is bound to; stored in the update journal."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    artifact: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]
    capture_id: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    sha256: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    completed_at: float = Field(ge=0)
    data_bytes: int = Field(ge=0)


def recovery_mode(migration: str, *, has_data: bool, allow_backup_pause: bool) -> RecoveryMode:
    """Decide the recovery for a declared migration, or refuse the update.

    Unknown kinds and migrations that cannot be recovered fail closed."""
    if migration == "none":
        return "image_only"
    if migration not in ("reversible", "restore_required"):
        raise UpdateRejected("recovery_unavailable", "unknown data migration kind")
    if not has_data:
        raise UpdateRejected(
            "recovery_unavailable", "a data migration needs registered data that can be backed up"
        )
    if not allow_backup_pause:
        raise UpdateRejected(
            "recovery_unavailable",
            "a data migration takes an update-time capture and requires a backup pause contract",
        )
    return "reversible_capture" if migration == "reversible" else "restore_required"


def capture_ref(manifest: FilesystemCapture, artifact: str) -> CaptureRef:
    return CaptureRef(
        artifact=artifact,
        capture_id=manifest.id,
        sha256=manifest.sha256,
        completed_at=manifest.completed_at,
        data_bytes=manifest.data_bytes,
    )


def capture_matches(
    manifest: object,
    ref: CaptureRef,
    *,
    server: str,
    project: str,
    image: str,
    source_revision: str,
    config_revision: str,
) -> bool:
    """True only for the exact filesystem capture the journal names, taken of the
    state that a rollback returns to (previous image, source and configuration)."""
    if not isinstance(manifest, FilesystemCapture):
        return False
    binding = manifest.binding
    return (
        manifest.id == ref.capture_id
        and manifest.sha256 == ref.sha256
        and binding.server == server
        and binding.project == project
        and binding.image == image
        and binding.source_revision == source_revision
        and binding.config_revision == config_revision
    )
