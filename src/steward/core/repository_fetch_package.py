"""Installed entry points for the isolated repository-fetch candidate."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator

from .. import __version__
from .. import application_boot as boot
from ..executor.deployment_launcher import GateError
from .canonical import canonical_json, revision_id
from .config import ConfigError, GitCommit, Repository, WorkloadContract, effective
from .repositories import FetchError, FetchPolicy, fetch_repository, validate_endpoint

ACCOUNT = "steward-repo-fetch"
UNIT = "steward-repository-fetch.service"
HANDOFF_UNIT = "steward-repository-source-handoff.service"
BUILD_VERIFY_UNIT = "steward-repository-build-verify.service"
UNIT_DIRECTORY = Path("/etc/systemd/system")
CGROUP = Path("/sys/fs/cgroup")
UNIT_DESCRIPTIONS = {
    UNIT: "Steward repository fetch",
    HANDOFF_UNIT: "Steward repository source handoff",
    BUILD_VERIFY_UNIT: "Steward repository build input verification",
}
DIRECTORY = Path("/etc/steward/repository-fetch")
ACTIVE = DIRECTORY / "active.json"
SCOPE = DIRECTORY / "scope.json"
CREDENTIAL = DIRECTORY / "credential"
MARKER = Path("/etc/steward/config/deploy-run.json")
FIREWALL = Path("/etc/steward/nftables/firewall-policy.py")
STORE = Path("/var/lib/steward-repository-fetch")
SCRATCH = Path("/run/steward-repository-fetch")
CREDENTIAL_DIRECTORY = Path("/run/credentials") / UNIT
CREDENTIAL_REF = f"file:{CREDENTIAL_DIRECTORY}/git"
INPUT_LIMIT = 16 * 1024
HANDOFF_LIMIT = 64 * 1024
MANIFEST_LIMIT = INPUT_LIMIT + HANDOFF_LIMIT
CREDENTIAL_LIMIT = 16 * 1024

Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
RunID = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RepositoryInput(WireModel):
    id: str
    application: str
    service: str
    url: str
    ref: str
    revision: GitCommit
    host_key: str | None
    allow_private_network: bool


class HandoffInput(WireModel):
    contract: WorkloadContract | None
    generation: RunID | None = None


class Manifest(WireModel):
    version: int
    base_revision: Digest
    firewall_sha256: Digest
    endpoint: str
    credential_required: bool
    repository: RepositoryInput
    handoff: HandoffInput | None = None

    def configured_repository(self) -> Repository:
        reference = CREDENTIAL_REF if self.credential_required else None
        return Repository.model_validate(
            {**self.repository.model_dump(), "credential": reference}, strict=True
        )

    @model_validator(mode="after")
    def validate_manifest(self) -> Manifest:
        boot.require(self.version == 1, "unsupported repository fetch manifest")
        if self.handoff is not None:
            boot.require(
                len(self.handoff.model_dump_json().encode()) <= HANDOFF_LIMIT,
                "repository handoff input exceeds its limit",
            )
        repository = self.configured_repository()
        boot.require(repository.url == self.repository.url, "repository fetch URL is not canonical")
        validate_endpoint(repository, self.endpoint)
        return self


class SiteRunMarker(WireModel):
    base_revision: Digest
    desired_revision: Digest
    repository_fetch_run: RunID


class Publication(WireModel):
    manifest: Manifest
    marker: SiteRunMarker


def _decode(body: bytes) -> object:
    boot.require(len(body) <= MANIFEST_LIMIT, "repository fetch input exceeds its limit")

    def unique(pairs):
        data = dict(pairs)
        boot.require(len(data) == len(pairs), "duplicate repository fetch input field")
        return data

    data = json.loads(body, object_pairs_hook=unique)
    manifest = data.get("manifest", data) if isinstance(data, dict) else None
    if isinstance(manifest, dict) and manifest.get("handoff") is not None:
        # Bound both inputs independently, including ignored whitespace via the outer cap.
        legacy = manifest.copy()
        handoff = legacy.pop("handoff")
        original = {**data, "manifest": legacy} if "manifest" in data else legacy
        boot.require(
            len(canonical_json(original).encode()) <= INPUT_LIMIT,
            "repository fetch input exceeds its limit",
        )
        boot.require(
            len(canonical_json(handoff).encode()) <= HANDOFF_LIMIT,
            "repository handoff input exceeds its limit",
        )
    else:
        boot.require(len(body) <= INPUT_LIMIT, "repository fetch input exceeds its limit")
    return data


def _account() -> tuple[int, int]:
    account = pwd.getpwnam(ACCOUNT)
    gid = grp.getgrnam(ACCOUNT).gr_gid
    boot.require(account.pw_uid > 0 and gid > 0 and account.pw_gid == gid, "unsafe fetch account")
    return account.pw_uid, gid


def _directory(gid: int) -> None:
    boot.safe_directory(DIRECTORY)
    info = DIRECTORY.lstat()
    boot.require(
        (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, gid, 0o750),
        "unsafe repository fetch authority directory",
    )


def _read_active(gid: int) -> Manifest:
    with boot.protected(ACTIVE, 0o640, gid) as handle:
        return Manifest.model_validate(_decode(handle.read(MANIFEST_LIMIT + 1)))


def withdraw_active() -> None:
    """Revoke the published inputs while the caller holds the deployment lock."""
    # Import lazily: handoff reads the fetch authority defined in this module.
    from .repository_build_verify import withdraw_admission
    from .repository_source_handoff import withdraw_ready

    withdraw_admission()
    withdraw_ready()
    if not os.path.lexists(ACTIVE):
        return
    _, gid = _account()
    _directory(gid)
    with boot.protected(ACTIVE, 0o640, gid):
        pass
    ACTIVE.unlink()
    boot.sync_directory(DIRECTORY)


def _repository_unit_fields(unit: str, *, allow_absent: bool = False) -> dict[str, str]:
    boot.require(unit in UNIT_DESCRIPTIONS, "unknown repository unit")
    fragment = UNIT_DIRECTORY / unit
    try:
        with boot.protected(fragment, 0o644) as handle:
            expected = (
                f"# Generated by steward - do not edit.\n[Unit]\n"
                f"Description={UNIT_DESCRIPTIONS[unit]}\n"
            ).encode()
            boot.require(handle.read(len(expected)) == expected, "foreign repository unit fragment")
    except FileNotFoundError:
        boot.require(allow_absent, "missing managed repository unit")
        present = False
    else:
        present = True

    result = subprocess.run(  # noqa: S603 - fixed executable and allowlisted unit name
        [
            "/usr/bin/systemctl",
            "--system",
            "show",
            "--all",
            "--property=Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,"
            "DropInPaths,NeedDaemonReload,Job,ControlGroup,MainPID,ControlPID,InvocationID",
            unit,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        text=True,
        timeout=10,
    )
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines())
    expected_source = {
        "LoadState": "loaded" if present else "not-found",
        "FragmentPath": str(fragment) if present else "",
        "UnitFileState": "static" if present else "",
        "DropInPaths": "",
        "NeedDaemonReload": "no",
        "Id": unit,
    }
    boot.require(
        all(fields.get(name) == value for name, value in expected_source.items())
        and (result.returncode == 0 or not present),
        "repository unit is not quiescent or has a foreign source",
    )
    return fields


def require_unit_quiescent(unit: str, *, allow_absent: bool = False) -> None:
    """Check the fixed unit and its unified cgroup without waiting for a stop."""
    fields = _repository_unit_fields(unit, allow_absent=allow_absent)
    present = fields["LoadState"] == "loaded"
    expected_cgroup = f"/system.slice/{unit}"
    boot.require(
        fields.get("MainPID") == fields.get("ControlPID") == "0"
        and fields.get("Job") in ("", "0")
        and fields.get("ControlGroup") in ("", expected_cgroup)
        and (fields.get("ActiveState"), fields.get("SubState"))
        in ({("inactive", "dead"), ("failed", "failed")} if present else {("inactive", "dead")}),
        "repository unit is not quiescent or has a foreign source",
    )

    # cgroup.events reports population recursively, including delegated descendants.
    (CGROUP / "cgroup.controllers").stat()
    cgroup = CGROUP / expected_cgroup.lstrip("/")
    try:
        events = (cgroup / "cgroup.events").read_text().splitlines()
    except FileNotFoundError:
        boot.require(not os.path.lexists(cgroup), "cannot verify repository unit cgroup")
    else:
        boot.require("populated 0" in events, "repository unit cgroup remains populated")


def _require_incoming_manifest(manifest: Manifest) -> None:
    if manifest.handoff is not None:
        boot.require(
            "generation" not in manifest.handoff.model_fields_set,
            "repository handoff generation is assigned at publication",
        )


def _scope(manifest: Manifest, uid: int) -> dict:
    repo = manifest.configured_repository()
    return {
        "version": 1,
        "uid": uid,
        "url": repo.url,
        "id": repo.id,
        "application": repo.application,
        "service": repo.service,
    }


def _require_scope(manifest: Manifest, uid: int, *, create: bool = False) -> None:
    expected = _scope(manifest, uid)
    current = boot.read_optional(SCOPE)
    if create and current is None:
        boot.store(SCOPE, expected)
    else:
        boot.require(canonical_json(current) == canonical_json(expected), "fetch scope differs")


def _require_installed_release() -> str:
    from ..executor.site_deployment import active_release

    release = active_release()
    boot.require(release == __version__, "repository fetch release differs from installed release")
    return release


def _require_applied(manifest: Manifest) -> None:
    from ..executor.site_deployment import (
        deployment_registry,
        installed_config,
        read_marker,
        verify_registry,
    )

    release = _require_installed_release()
    installation = read_marker()
    boot.require(installation["schema_version"] == 1, "fetch requires a schema 1 installation")
    cfg, registry = installed_config()
    boot.require(
        installation["server_name"] == cfg.server.name
        and revision_id(effective(cfg)) == manifest.base_revision
        and registry.get("config_revision") == manifest.base_revision,
        "fetch base differs from the applied revision",
    )
    verify_registry(cfg, registry, deployment_registry(cfg, release))


def _require_firewall(manifest: Manifest) -> None:
    with boot.protected(FIREWALL, 0o700):
        pass
    subprocess.run(  # noqa: S603 - fixed helper and validated SHA-256
        ["/usr/bin/python3", "-I", str(FIREWALL), "require-active", manifest.firewall_sha256],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        check=True,
        timeout=30,
    )


def _require_no_marker() -> None:
    # lstat preserves permission errors and also detects a dangling link.
    try:
        MARKER.lstat()
    except FileNotFoundError:
        return
    raise boot.BootError("a site deployment is pending")


def _check_authority(manifest: Manifest, uid: int) -> None:
    _require_scope(manifest, uid)
    if manifest.credential_required:
        with boot.protected(CREDENTIAL, 0o600):
            pass
    _require_applied(manifest)
    _require_firewall(manifest)


def _write_active(manifest: Manifest, gid: int) -> None:
    if os.path.lexists(ACTIVE):
        with boot.protected(ACTIVE, 0o640, gid):
            pass
    body = (
        manifest.model_dump_json(exclude={"handoff"} if manifest.handoff is None else None).encode()
        + b"\n"
    )
    _decode(body)
    fd, name = tempfile.mkstemp(dir=DIRECTORY)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchown(handle.fileno(), 0, gid)
            os.fchmod(handle.fileno(), 0o640)
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, ACTIVE)
        boot.sync_directory(DIRECTORY)
    finally:
        Path(name).unlink(missing_ok=True)


def _credential(reference: str) -> str:
    boot.require(reference == CREDENTIAL_REF, "invalid repository credential reference")
    boot.require(
        os.environ.get("CREDENTIALS_DIRECTORY") == str(CREDENTIAL_DIRECTORY),
        "invalid systemd credentials directory",
    )
    fd = os.open(CREDENTIAL_DIRECTORY, os.O_PATH | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        directory_info = os.fstat(fd)
        boot.require(
            directory_info.st_uid in (0, os.geteuid()) and not directory_info.st_mode & 0o022,
            "unsafe systemd credentials directory",
        )
        key_fd = os.open("git", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(key_fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            # A root-owned systemd credential may have a named-user ACL. Its
            # read mask appears as a group-read bit in stat.
            access_mask = 0o077
            if (
                (directory_info.st_uid, directory_info.st_gid, info.st_uid, info.st_gid)
                == (0, 0, 0, 0)
                and directory_info.st_mode & stat.S_IXGRP
                and not directory_info.st_mode & 0o007
            ):
                access_mask = 0o037
            boot.require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid in (0, os.geteuid())
                and not info.st_mode & access_mask
                and info.st_nlink == 1,
                "unsafe systemd credential",
            )
            data = handle.read(CREDENTIAL_LIMIT + 1)
    finally:
        os.close(fd)
    boot.require(0 < len(data) <= CREDENTIAL_LIMIT, "invalid systemd credential size")
    value = data.decode("utf-8").strip()
    boot.require(bool(value), "empty systemd credential")
    return value


def _run(uid: int, gid: int) -> None:
    boot.require((os.geteuid(), os.getegid()) == (uid, gid), "unexpected fetch identity")
    _directory(gid)
    # ExecStartPre checks the protected marker as root. Withdrawal removes
    # this manifest and drains the unit before changing the host policy.
    manifest = _read_active(gid)
    repo = manifest.configured_repository()
    endpoint = validate_endpoint(repo, manifest.endpoint)

    def pinned_resolver(_host: str, _port: int) -> list[str]:
        return [endpoint]

    fetch_repository(
        repo, STORE, resolve_secret=_credential, policy=FetchPolicy(resolver=pinned_resolver),
        scratch=SCRATCH,
    )  # fmt: skip


def _root_command(command: str) -> None:
    boot.require(os.geteuid() == 0, "repository fetch authority requires root")
    uid, gid = _account()
    with boot.deployment_lock(timeout=30, create=command != "verify"):
        _directory(gid)
        if command == "verify":
            _require_no_marker()
            manifest = _read_active(gid)
            require_unit_quiescent(HANDOFF_UNIT, allow_absent=manifest.handoff is None)
            _check_authority(manifest, uid)
            return
        body = _decode(sys.stdin.buffer.read(MANIFEST_LIMIT + 1))
        if command == "seal":
            _require_installed_release()
            manifest = Manifest.model_validate(body)
            _require_incoming_manifest(manifest)
            _require_scope(manifest, uid, create=True)
            return
        publication = Publication.model_validate(body)
        manifest, marker = publication.manifest, publication.marker
        boot.require(
            manifest.base_revision == marker.base_revision == marker.desired_revision
            and boot.read_optional(MARKER) == marker.model_dump(),
            "repository fetch deployment marker differs",
        )
        _require_incoming_manifest(manifest)
        _check_authority(manifest, uid)
        if manifest.handoff is not None:
            manifest.handoff.generation = marker.repository_fetch_run
        _write_active(manifest, gid)
        MARKER.unlink()
        boot.sync_directory(MARKER.parent)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m steward.core.repository_fetch_package")
    parser.add_argument("command", choices=("run", "verify", "seal", "publish"))
    command = parser.parse_args(argv).command
    try:
        if command == "run":
            _run(*_account())
        else:
            _root_command(command)
    except (
        boot.BootError,
        ConfigError,
        FetchError,
        GateError,
        OSError,
        RecursionError,
        ValueError,
        KeyError,
        subprocess.SubprocessError,
    ):
        print(f"repository fetch {command} failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
