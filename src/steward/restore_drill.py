"""Unprivileged, isolated sample-application restore drill; no production replacement."""

from __future__ import annotations

import json
import math
import os
import pwd
import re
import shutil
import stat
import tempfile
import time
import uuid
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .core.backups import (
    BackupError,
    Binding,
    FilesystemCapture,
    Receipt,
    database_check,
    digest_file,
    regular_file,
)
from .core.inventory import Digest
from .core.process import CommandError, run_bounded

SOURCE_REVISION = "bundled:sample-notes@0.1.1"
SOURCE_SHA256 = "536dee6f2bd95a7163763a2cc803a2558b9b7b1f457ef941e7eaa03d5690eadb"
PODMAN = Path("/usr/bin/podman")

# Executed only inside the isolated sample container. Content never appears in
# the host process list or the resulting evidence; only SHA256 values cross out.
PROBE = r"""import hashlib,json,sys,urllib.request
base='http://127.0.0.1:8080'
with urllib.request.urlopen(base+'/healthz',timeout=3) as r: health=json.load(r)
with urllib.request.urlopen(base+'/notes',timeout=3) as r: notes=json.load(r)
with urllib.request.urlopen(base+'/attachments/'+sys.argv[1],timeout=3) as r:
    attachment=r.read(1048577)
assert len(attachment)<=1048576
result={'health':health.get('status'),
        'notes':[hashlib.sha256(x['text'].encode()).hexdigest() for x in notes],
        'attachment':hashlib.sha256(attachment).hexdigest()}
print(json.dumps(result))
"""


class DrillSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    v: Literal[1] = 1
    repository_id: Digest
    snapshot_id: Digest
    capture_id: Digest
    binding: Binding
    app_sha256: Digest
    note_sha256: Digest
    attachment_sha256: Digest


def validate_report(report, receipt: Receipt, spec: DrillSpec) -> None:
    """Refuse incomplete or unbound application evidence; never authorize recovery."""
    fields = {
        "v",
        "repository_id",
        "snapshot_id",
        "capture_id",
        "binding",
        "app_sha256",
        "bytes_verified_at",
        "application_verified_at",
        "health",
        "note_readback",
        "attachment_readback",
        "fresh_vm_proven",
        "production_restore_authorized",
    }
    if (
        not isinstance(report, dict)
        or set(report) != fields
        or type(report["v"]) is not int
        or report["v"] != 1
        or spec.repository_id != receipt.repository_id
        or spec.snapshot_id != receipt.snapshot_id
        or spec.capture_id != receipt.capture.id
        or spec.binding != receipt.capture.binding
        or spec.binding.source_revision != SOURCE_REVISION
        or spec.app_sha256 != SOURCE_SHA256
        or report["repository_id"] != receipt.repository_id
        or report["snapshot_id"] != receipt.snapshot_id
        or report["capture_id"] != receipt.capture.id
        or report["binding"] != spec.binding.model_dump(mode="json")
        or report["app_sha256"] != spec.app_sha256
        or report["health"] != "ok"
        or report["note_readback"] is not True
        or report["attachment_readback"] is not True
        or report["fresh_vm_proven"] is not False
        or report["production_restore_authorized"] is not False
        or type(report["bytes_verified_at"]) not in (int, float)
        or type(report["application_verified_at"]) not in (int, float)
        or not math.isfinite(report["bytes_verified_at"])
        or not math.isfinite(report["application_verified_at"])
        or report["bytes_verified_at"] < 0
        or report["application_verified_at"] < report["bytes_verified_at"]
    ):
        raise BackupError("evidence_mismatch")


class PodmanSample:
    """Run only the pinned bundled sample with no host network or privileges."""

    def __init__(self):
        if os.geteuid() == 0:
            raise BackupError("invalid_input")
        uid = os.geteuid()
        runtime = Path(f"/run/user/{uid}")
        info = runtime.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
            raise BackupError("unsafe_runtime")
        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": pwd.getpwuid(uid).pw_dir,
            "XDG_RUNTIME_DIR": str(runtime),
        }

    def _run(self, args, *, timeout=30):
        try:
            return run_bounded(
                [str(PODMAN), *args], cwd=Path("/"), env=self.env, timeout=timeout, max_bytes=65536
            ).decode("utf-8")
        except (CommandError, UnicodeError):
            raise BackupError("application_unavailable") from None

    def readback(self, data: Path, app: Path, spec: DrillSpec) -> dict:
        if any(
            not path.is_absolute() or ":" in str(path) or any(ord(c) < 32 for c in str(path))
            for path in (data, app)
        ):
            raise BackupError("invalid_input")
        if self._run(["info", "--format", "{{.Host.Security.Rootless}}"]).strip() != "true":
            raise BackupError("unsafe_runtime")
        try:
            digests = json.loads(
                self._run(
                    ["image", "inspect", spec.binding.image, "--format", "{{json .RepoDigests}}"]
                )
            )
        except (ValueError, TypeError):
            raise BackupError("image_unavailable") from None
        if not isinstance(digests, list) or spec.binding.image not in digests:
            raise BackupError("image_unavailable")
        token = uuid.uuid4().hex
        name = "steward-restore-drill-" + token
        label = "io.steward.restore-drill=" + token
        try:
            container_id = self._run(
                [
                    "run",
                    "--detach",
                    "--rm",
                    "--name",
                    name,
                    "--label",
                    label,
                    "--pull=never",
                    "--network=none",
                    "--read-only",
                    "--cap-drop=all",
                    "--security-opt=no-new-privileges",
                    "--pids-limit=64",
                    "--memory=256m",
                    "--user=0",
                    "--env=DATA_DIR=/data",
                    "--env=PORT=8080",
                    "--env=PYTHONDONTWRITEBYTECODE=1",
                    "--volume",
                    f"{data}:/data:rw",
                    "--volume",
                    f"{app}:/app/app.py:ro",
                    spec.binding.image,
                    "python",
                    "/app/app.py",
                ],
                timeout=60,
            ).strip()
            if not re.fullmatch(r"[a-f0-9]{64}", container_id):
                raise BackupError("application_unavailable")
            deadline = time.monotonic() + 30
            while True:
                try:
                    raw = self._run(
                        ["exec", container_id, "python", "-c", PROBE, spec.attachment_sha256],
                        timeout=8,
                    )
                    value = json.loads(raw)
                    break
                except (BackupError, ValueError):
                    if time.monotonic() >= deadline:
                        raise BackupError("application_unavailable") from None
                    time.sleep(0.5)
            if (
                not isinstance(value, dict)
                or value.get("health") != "ok"
                or not isinstance(value.get("notes"), list)
                or spec.note_sha256 not in value["notes"]
                or value.get("attachment") != spec.attachment_sha256
            ):
                raise BackupError("application_mismatch")
            return {"health": "ok", "note_readback": True, "attachment_readback": True}
        finally:
            try:
                actual = self._run(
                    [
                        "inspect",
                        "--format",
                        '{{index .Config.Labels "io.steward.restore-drill"}}',
                        name,
                    ],
                    timeout=10,
                ).strip()
            except BackupError:
                raise BackupError("cleanup_unconfirmed") from None
            if actual != token:
                raise BackupError("cleanup_unconfirmed")
            self._run(["rm", "--force", name], timeout=20)


def run_drill(adapter, receipt: Receipt, spec: DrillSpec, app_file: Path, runner) -> dict:
    """Check exact inputs and independent HTTP readback; never replace live data."""
    if os.geteuid() == 0:
        raise BackupError("invalid_input")
    if (
        not isinstance(receipt.capture, FilesystemCapture)
        or receipt.repository_id != spec.repository_id
        or receipt.snapshot_id != spec.snapshot_id
        or receipt.capture.id != spec.capture_id
        or receipt.capture.binding != spec.binding
        or spec.binding.source_revision != SOURCE_REVISION
        or spec.app_sha256 != SOURCE_SHA256
    ):
        raise BackupError("evidence_mismatch")
    app_hash, _ = digest_file(app_file, max_bytes=1024 * 1024)
    if app_hash != spec.app_sha256:
        raise BackupError("evidence_mismatch")
    with adapter.restored_tree(receipt) as (data, restored):
        if restored != receipt.capture:
            raise BackupError("evidence_mismatch")
        database_check(data / "notes.db")
        attachment_hash, _ = digest_file(
            data / "attachments" / spec.attachment_sha256, max_bytes=1024 * 1024
        )
        if attachment_hash != spec.attachment_sha256:
            raise BackupError("evidence_mismatch")
        bytes_verified_at = time.time()
        with tempfile.TemporaryDirectory(prefix="drill-app-", dir=adapter.state) as directory:
            private_app = Path(directory) / "app.py"
            fd, _ = regular_file(app_file, limit=1024 * 1024)
            with os.fdopen(fd, "rb") as source, private_app.open("xb") as target:
                shutil.copyfileobj(source, target, length=65536)
            private_app.chmod(0o400)
            if digest_file(private_app, max_bytes=1024 * 1024)[0] != spec.app_sha256:
                raise BackupError("source_changed")
            evidence = runner.readback(data, private_app, spec)
            if evidence != {"health": "ok", "note_readback": True, "attachment_readback": True}:
                raise BackupError("application_mismatch")
            if digest_file(private_app, max_bytes=1024 * 1024)[0] != spec.app_sha256:
                raise BackupError("source_changed")
        application_verified_at = time.time()
        if application_verified_at < bytes_verified_at:
            raise BackupError("clock_changed")
    return {
        "v": 1,
        "repository_id": spec.repository_id,
        "snapshot_id": spec.snapshot_id,
        "capture_id": spec.capture_id,
        "binding": spec.binding.model_dump(mode="json"),
        "app_sha256": spec.app_sha256,
        "bytes_verified_at": bytes_verified_at,
        "application_verified_at": application_verified_at,
        "health": "ok",
        "note_readback": True,
        "attachment_readback": True,
        "fresh_vm_proven": False,
        "production_restore_authorized": False,
    }
