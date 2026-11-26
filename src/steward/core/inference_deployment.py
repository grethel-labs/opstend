"""Private deployment authority for the managed local inference candidate."""

from __future__ import annotations

import argparse
import grp
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints, model_serializer, model_validator

from .config import Ai, Config
from .inference_local import LISTEN

PROJECTION_PATH = Path("/etc/steward/inference/selection.json")
SOCKET_PATH = Path("/run/steward-inference-admin/admin.sock")
ADVICE_SOCKET_DIR = Path("/run/steward-inference-advice")
DESIRED_PATH = Path("/etc/steward/config/desired.json")
INPUT_LIMIT = 64 * 1024
GROUP = "steward-inference"
Digest = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}\z")]
Release = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,39}\z")]
RunId = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}\z")]


def _validate_local_ai(ai: Ai) -> None:
    from .ollama_install import MODEL

    if (
        ai.provider != "ollama"
        or ai.local_only is not True
        or ai.model is None
        or not MODEL.fullmatch(ai.model)
        or ai.local is None
        or ai.local.license_ack is not True
        or ai.local.device != "cpu"
        or ai.base_url not in (None, f"http://{LISTEN}")
        or ai.share
        or ai.api_key_ref is not None
        or ai.fx is not None
        or ai.model_policy is not None
    ):
        raise ValueError("invalid managed local Ollama declaration")


def _validate_advice_budget(ai: Ai) -> None:
    budget = ai.budget
    if (
        budget is None
        or budget.monthly.tokens is None
        or budget.monthly.tokens > 20_000
        or budget.monthly.seconds is None
        or budget.monthly.seconds > 120
        or budget.max_concurrent != 1
        or budget.price is not None
        or budget.monthly.cost_micro is not None
        or budget.per_project.cost_micro is not None
    ):
        raise ValueError("invalid managed local advice budget")


def _validate_advice_routes(cfg: Config) -> None:
    if cfg.admin.access != "private" or cfg.bot.public_hostname is not None:
        raise ValueError(
            "managed local advice requires private admin access and an unpublished bot"
        )


class _Candidate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    version: Literal[1]
    revision: Digest
    release: Release
    wheel_sha256: Digest
    manifest_sha256: Digest
    advice: bool = False

    @model_validator(mode="before")
    @classmethod
    def _wire_types(cls, data):
        if isinstance(data, dict):
            if type(data.get("version")) is not int:
                raise ValueError("invalid candidate schema version")
            if "advice" in data and data["advice"] is not True:
                raise ValueError("candidate advice opt-in must be true or absent")
        return data

    @model_serializer(mode="wrap")
    def _serialize(self, handler):
        data = handler(self)
        if not self.advice:
            data.pop("advice", None)
        return data


class CandidatePolicy(_Candidate):
    generation: RunId
    ai: Ai
    weekly_window: str | None

    @model_validator(mode="after")
    def _local(self) -> CandidatePolicy:
        from .maintenance import parse_window_spec

        _validate_local_ai(self.ai)
        if self.advice:
            _validate_advice_budget(self.ai)
        if self.weekly_window is not None:
            parse_window_spec(self.weekly_window)
        return self


class _Ollama(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    ai: Ai
    reserved_memory_mb: int


class _Run(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    candidate: _Candidate
    ollama: _Ollama
    run_id: RunId
    models: str


def _read(path: Path, mode: int, gid: int = 0) -> bytes:
    from .. import application_boot as boot

    with boot.protected(path, mode, gid) as handle:
        data = handle.read(INPUT_LIMIT + 1)
    boot.require(len(data) <= INPUT_LIMIT, "inference deployment document exceeds size limit")
    return data


def _projection_group(directory: Path, *, create: bool = False) -> int:
    from .. import application_boot as boot

    gid = grp.getgrnam(GROUP).gr_gid
    boot.require(gid != 0, "inference group must be distinct from root")
    boot.safe_directory(directory.parent)
    if create and not os.path.lexists(directory):
        directory.mkdir(mode=0o700)
        os.chown(directory, 0, gid)
        directory.chmod(0o750)
        boot.sync_directory(directory.parent)
    info = directory.lstat()
    boot.require(
        stat.S_ISDIR(info.st_mode)
        and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, gid, 0o750),
        "unsafe inference policy directory",
    )
    return gid


def _decode(data: bytes) -> dict:
    from .ollama_install import _object

    if len(data) > INPUT_LIMIT:
        raise ValueError("inference deployment document exceeds size limit")
    return _object(data)


def read_candidate_policy(path: Path = PROJECTION_PATH) -> CandidatePolicy | None:
    """Read the protected projection or return unavailable."""
    from ..application_boot import BootError

    try:
        gid = _projection_group(path.parent)
        data = _decode(_read(path, 0o640, gid))
        policy = CandidatePolicy.model_validate(data)
        return policy if policy.model_dump(mode="json") == data else None
    except (BootError, KeyError, OSError, ValueError, RecursionError):
        return None


def revoke_for_desired(desired: Path) -> None:
    """Withdraw authority before a canonical write. Caller holds the deployment lock."""
    path = desired.parent.parent / "inference" / PROJECTION_PATH.name
    if not os.path.lexists(path.parent):
        return
    if path.parent.is_symlink():
        raise ValueError("unsafe inference policy directory")
    if not os.path.lexists(path):
        return
    from .. import application_boot as boot

    try:
        gid = _projection_group(path.parent)
        with boot.protected(path, 0o640, gid):
            path.unlink()
        boot.sync_directory(path.parent)
    except (boot.BootError, KeyError) as error:
        raise ValueError("unsafe inference policy projection") from error


def _socket_preflight(path: Path | None = None) -> None:
    from .. import application_boot as boot

    path = SOCKET_PATH if path is None else path
    boot.safe_directory(path.parent.parent)
    try:
        info = path.parent.lstat()
    except FileNotFoundError:
        return
    boot.require(
        stat.S_ISDIR(info.st_mode)
        and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o755)
        and not os.path.lexists(path),
        "unsafe or occupied inference socket path",
    )


def _applied_policy(run: _Run) -> CandidatePolicy:
    from .. import __version__
    from .. import application_boot as boot
    from ..executor.site_deployment import (
        active_release,
        deployment_registry,
        installed_config,
        read_marker,
        verify_registry,
    )
    from .canonical import revision_id
    from .config import Ai, effective
    from .render import deployed

    candidate = run.candidate
    marker = read_marker()
    boot.require(marker["schema_version"] == 1, "candidate requires schema-1 installation")
    cfg, registry = installed_config()
    boot.require(
        cfg.profile == "api"
        and cfg.ai == Ai()
        and not cfg.unavailable_features()
        and marker["server_name"] == cfg.server.name
        and candidate.revision == registry.get("config_revision") == revision_id(effective(cfg))
        and candidate.release == registry.get("release") == active_release() == __version__,
        "applied configuration or release differs from the candidate",
    )
    verify_registry(cfg, registry, deployment_registry(cfg, candidate.release))
    if candidate.advice:
        _validate_advice_routes(cfg)
    wheel = (
        boot.RELEASES
        / candidate.release
        / "dist"
        / (f"steward-{candidate.release}-py3-none-any.whl")
    )
    with boot.protected(wheel, 0o644) as handle:
        boot.require(
            hashlib.file_digest(handle, "sha256").hexdigest() == candidate.wheel_sha256,
            "installed release wheel differs from the candidate",
        )
    reserved = (
        cfg.reserved_memory_mb
        + cfg.proxy.memory_mb
        + (768 if cfg.scanning.enabled else 0)
        + sum(project.resources.memory_mb for project in deployed(cfg))
    )
    boot.require(reserved == run.ollama.reserved_memory_mb, "candidate memory reservation changed")
    return CandidatePolicy(
        **candidate.model_dump(),
        generation=run.run_id,
        ai=run.ollama.ai,
        weekly_window=cfg.maintenance.weekly_window if cfg.maintenance else None,
    )


def _installed_model(run: _Run, policy: CandidatePolicy) -> list[list[int]]:
    from .. import application_boot as boot
    from .ollama_install import (
        MODEL,
        MODEL_ROOT,
        RECEIPT,
        REGISTRY,
        _read_staged,
        parse_staged_model,
    )

    root = Path(run.models)
    boot.require(
        root.parent == MODEL_ROOT and boot.is_digest(root.name) and str(root) == run.models,
        "invalid installed Ollama store",
    )
    model = policy.ai.model
    match = MODEL.fullmatch(model or "")
    if match is None or model is None:
        raise ValueError("invalid installed Ollama model name")
    name, tag = match.groups()

    receipt_path = root / RECEIPT
    manifest_path = root / "manifests" / REGISTRY / "library" / name / tag
    boot.safe_directory(manifest_path.parent)
    receipt = _read(receipt_path, 0o600)
    manifest = _read_staged(manifest_path)
    installed = parse_staged_model(model, receipt, manifest)
    boot.require(
        installed.key == root.name and boot.digest(manifest) == policy.manifest_sha256,
        "installed Ollama model differs from the candidate",
    )
    return _identity(root, receipt_path, manifest_path)


def _identity(*paths: Path) -> list[list[int]]:
    identity = []
    for path in paths:
        info = path.lstat()
        identity.append([info.st_dev, info.st_ino, info.st_ctime_ns])
    return identity


def _remove_proof(path: Path) -> None:
    from .. import application_boot as boot

    try:
        with boot.protected(path, 0o600):
            path.unlink()
    except FileNotFoundError:
        return
    boot.sync_directory(path.parent)


def _project(policy: CandidatePolicy) -> None:
    from .. import application_boot as boot

    directory = PROJECTION_PATH.parent
    gid = _projection_group(directory, create=True)
    fd, name = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchown(fd, 0, gid)
            os.fchmod(fd, 0o640)
            handle.write(policy.model_dump_json() + "\n")
            handle.flush()
            os.fsync(fd)
        os.replace(name, PROJECTION_PATH)
        try:
            boot.sync_directory(directory)
        except OSError:
            revoke_for_desired(DESIRED_PATH)
            raise
    finally:
        Path(name).unlink(missing_ok=True)


def _stage_or_publish(action: str, run: _Run, marker: Path, proof: Path) -> None:
    from .. import application_boot as boot
    from ..executor.server import REGISTRY_PATH

    expected_marker = {
        "base_revision": run.candidate.revision,
        "desired_revision": run.candidate.revision,
        "inference_run": run.run_id,
    }

    def require_marker() -> None:
        boot.require(
            _decode(_read(marker, 0o600)) == expected_marker,
            "inference deployment run was superseded",
        )
        boot.require(not os.path.lexists(PROJECTION_PATH), "inference policy is already present")

    def checked_proof() -> tuple[CandidatePolicy, dict]:
        require_marker()
        policy = _applied_policy(run)
        install_identity = _installed_model(run, policy)
        return policy, {
            "run": run.model_dump(mode="json"),
            "install": install_identity,
            "configuration": _identity(DESIRED_PATH, Path(REGISTRY_PATH)),
        }

    policy, record = checked_proof()
    if action == "stage":
        boot.store(proof, record)
        return
    boot.require(_decode(_read(proof, 0o600)) == record, "inference installer proof changed")
    subprocess.run(
        [
            "/opt/steward/current/venv/bin/steward-host",
            "verify",
            "--expect-revision",
            policy.revision,
        ],
        check=True,
        timeout=120,
    )
    boot.require(checked_proof() == (policy, record), "inference deployment evidence changed")
    _remove_proof(proof)
    require_marker()
    _remove_proof(marker)
    _project(policy)


def main(argv: list[str] | None = None) -> int:
    from .. import application_boot as boot
    from ..executor.config_apply import RUN_MARKER
    from ..executor.site_deployment import ERRORS

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=("revoke", "socket-preflight", "advice-socket-preflight", "stage", "publish"),
    )
    parser.add_argument("role", nargs="?", choices=("bot", "api"))
    args = parser.parse_args(argv)
    action = args.action
    if (action == "advice-socket-preflight") != (args.role is not None):
        parser.error("advice-socket-preflight requires a bot or api role")
    try:
        boot.require(os.geteuid() == 0, "inference deployment helper requires root")
        if action == "socket-preflight":
            _socket_preflight()
            return 0
        if action == "advice-socket-preflight":
            boot.require(grp.getgrnam(f"steward-{args.role}").gr_gid != 0, "unsafe advice group")
            _socket_preflight(ADVICE_SOCKET_DIR / f"{args.role}.sock")
            return 0
        marker = DESIRED_PATH.with_name(RUN_MARKER)
        proof = DESIRED_PATH.with_name("inference-stage.json")
        run = None
        if action != "revoke":
            data = _decode(sys.stdin.buffer.read(INPUT_LIMIT + 1))
            run = _Run.model_validate(data)
            boot.require(
                run.model_dump(mode="json") == data, "incomplete inference deployment input"
            )
        with boot.deployment_lock(timeout=30):
            if run is None:
                revoke_for_desired(DESIRED_PATH)
                _remove_proof(proof)
            else:
                _stage_or_publish(action, run, marker, proof)
    except (*ERRORS, RecursionError) as error:
        print(f"inference deployment refused ({type(error).__name__})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
