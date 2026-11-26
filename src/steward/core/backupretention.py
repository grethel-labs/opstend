"""Conservative selection rules for root-owned backup retention.

Selection returns identifiers only; the metadata inspector reads a fixed
executor-supplied namespace. Neither operation mutates the filesystem or grants
deletion authority.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .backups import BackupError

MAX_ARTIFACTS = 10
MIN_RECENT = 2
MIN_AGE_S = 7 * 24 * 60 * 60


@dataclass(frozen=True)
class RetentionItem:
    artifact: str
    capture_id: str | None
    created_at: float | None
    complete: bool
    protected: bool = False
    # These flags must be established by root from its own trusted records or
    # an explicit operator action, never from the upload worker's receipt.
    independent_restore: bool = False
    operator_acknowledged: bool = False


@dataclass(frozen=True)
class RetentionDecision:
    artifact: str
    eligible: bool
    reason: str


def classify(items: list[RetentionItem], *, now: float) -> list[RetentionDecision]:
    """Conservatively identify artifacts that can be considered for cleanup.

    The root caller is responsible for discovering *all* objects, deriving
    complete/protected/authority from trusted state and revalidating immediately
    before deletion. Incomplete and unrecognized objects count toward capacity.
    """
    if not math.isfinite(now) or now < 0 or len(items) > MAX_ARTIFACTS:
        raise BackupError("invalid_retention_state")
    if len({item.artifact for item in items}) != len(items):
        raise BackupError("invalid_retention_state")
    for item in items:
        if not re.fullmatch(r"[a-f0-9]{32}", item.artifact):
            raise BackupError("invalid_retention_state")
        if item.capture_id is not None and not re.fullmatch(r"[a-f0-9]{64}", item.capture_id):
            raise BackupError("invalid_retention_state")
    complete = [
        item
        for item in items
        if item.complete is True
        and item.capture_id is not None
        and item.created_at is not None
        and math.isfinite(item.created_at)
        and 0 <= item.created_at <= now
    ]
    newest_ids = []
    for item in sorted(complete, key=lambda item: (item.created_at, item.artifact), reverse=True):
        if item.capture_id not in newest_ids:
            newest_ids.append(item.capture_id)
            if len(newest_ids) == MIN_RECENT:
                break
    newest = {item.artifact for item in complete if item.capture_id in newest_ids}
    decisions = []
    for item in items:
        if item.protected is not False or item.complete is not True:
            reason = "protected"
        elif (
            item.capture_id is None
            or item.created_at is None
            or not math.isfinite(item.created_at)
            or item.created_at < 0
            or item.created_at > now
        ):
            reason = "unknown_age_or_identity"
        elif item.artifact in newest:
            reason = "newest"
        elif now - item.created_at < MIN_AGE_S:
            reason = "recent"
        elif item.independent_restore is not True and item.operator_acknowledged is not True:
            reason = "missing_authority"
        else:
            reason = "eligible"
        decisions.append(RetentionDecision(item.artifact, reason == "eligible", reason))
    return decisions


def inspect_namespace(directory, project: str, *, imported: bool, group_id: int | None = None):
    """Read bounded root-owned metadata; never infer deletion authority.

    A returned manifest describes metadata only: neither archive bytes nor
    active worker jobs have been verified. Invalid objects remain protected.
    The caller must supply a fixed, registered project directory.
    """
    import json
    import os
    import stat
    from pathlib import Path

    from .backupexport import acl_attributes, owned_directory
    from .backups import Capture, FilesystemCapture, regular_file

    directory = Path(directory)
    if not os.path.lexists(directory):
        return {"items": [], "unknown": 0, "truncated": False, "at_capacity": False}
    info = owned_directory(directory)
    expected_dir = 0o750 if imported else 0o700
    if (
        stat.S_IMODE(info.st_mode) != expected_dir
        or (imported and info.st_gid != group_id)
        or acl_attributes(directory)
    ):
        raise BackupError("unsafe_spool")
    entries = []
    with os.scandir(directory) as iterator:
        for entry in iterator:
            entries.append(entry.name)
            if len(entries) > MAX_ARTIFACTS:
                return {"items": [], "unknown": 0, "truncated": True, "at_capacity": True}
    records, unknown = [], 0
    for name in sorted(entries):
        if not re.fullmatch(r"[a-f0-9]{32}", name):
            unknown += 1
            continue
        result = {"artifact": name, "state": "protected_unknown"}
        try:
            path = directory / name
            info = owned_directory(path)
            if (
                stat.S_IMODE(info.st_mode) != (0o550 if imported else 0o700)
                or (imported and info.st_gid != group_id)
                or acl_attributes(path)
            ):
                raise BackupError("unsafe_spool")
            fd, manifest_info = regular_file(path / "manifest.json", limit=65536)
            with os.fdopen(fd, "rb") as handle:
                if (
                    manifest_info.st_uid != os.geteuid()
                    or manifest_info.st_nlink != 1
                    or stat.S_IMODE(manifest_info.st_mode) != (0o440 if imported else 0o600)
                    or (imported and manifest_info.st_gid != group_id)
                    or acl_attributes(path / "manifest.json")
                ):
                    raise BackupError("unsafe_spool")
                raw = json.load(handle)
            if not isinstance(raw, dict):
                raise BackupError("invalid_input")
            model = FilesystemCapture if raw.get("mechanism") == "verified_quiescence" else Capture
            manifest = model.model_validate(raw)
            if manifest.binding.project != project:
                raise BackupError("evidence_mismatch")
            with os.scandir(path) as contents:
                names = []
                for item in contents:
                    names.append(item.name)
                    if len(names) > 2:
                        raise BackupError("invalid_input")
            if set(names) != {"manifest.json", manifest.filename}:
                raise BackupError("invalid_input")
            fd, data_info = regular_file(path / manifest.filename, limit=manifest.size)
            os.close(fd)
            if (
                data_info.st_uid != os.geteuid()
                or data_info.st_nlink != 1
                or data_info.st_size != manifest.size
                or stat.S_IMODE(data_info.st_mode) != (0o440 if imported else 0o600)
                or (imported and data_info.st_gid != group_id)
                or acl_attributes(path / manifest.filename)
            ):
                raise BackupError("unsafe_spool")
            result.update(
                state="metadata_only",
                capture_id=manifest.id,
                capture_created_at=manifest.created_at,
                config_revision=manifest.binding.config_revision,
                size=manifest.size,
            )
        except (BackupError, OSError, ValueError, TypeError):
            pass
        records.append(result)
    return {
        "items": records,
        "unknown": unknown,
        "truncated": False,
        "at_capacity": len(entries) >= MAX_ARTIFACTS,
    }
