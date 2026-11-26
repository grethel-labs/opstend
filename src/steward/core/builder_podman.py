"""Rootless-container build tier (R03): "container isolation, no VM protection".

Activated only by ``build.allow_container_isolation``. The build runs under a
dedicated unprivileged builder user with a per-job private storage root, a transient
systemd user unit that enforces memory, CPU, task and run-time limits, a dedicated
build network whose egress the host firewall restricts to the package sources, and
no volumes, secrets, sockets or capabilities. A repository Dockerfile can still
attack the shared kernel, so this tier is weaker than a VM and says so everywhere.

All commands are fixed argument vectors (no shell). Argument construction is
separate from execution so it can be tested against a fake host; whether the host
really enforces the egress policy is established by the host gate, not here.
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .builder import (
    DIGEST,
    JOB_ID,
    BackendOutcome,
    BuildError,
    BuildJob,
    BuildLimits,
    RunResult,
    run_bounded,
)
from .builder_scope import CGROUP, REFUSED

SYSTEMD_RUN = "/usr/bin/systemd-run"
SYSTEMCTL = "/usr/bin/systemctl"
PODMAN = "/usr/bin/podman"
BUILD_NETWORK = "steward-build"
SAFE_PATH = "/usr/bin:/bin"
SAFE_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
REGISTRY = re.compile(r"^(127\.0\.0\.1|localhost|[a-z0-9]([a-z0-9.-]*[a-z0-9])?)(:[0-9]{1,5})$")
RUNTIME_ROOT = Path("/run/user")
SCOPE_HELPER = Path(__file__).resolve().with_name("builder_scope.py")
STAGES = ("probe", "build", "push", "clean")
SCOPE_MARKER = ".steward-podman-scopes"
# Sockets and paths a build must be unable to read or write.
DENIED_PATHS = (
    "/run/podman/podman.sock",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/steward",
    "/var/lib/steward",
    "/etc/steward",
)
EXIT_KILLED = (137, 143)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()[:200]
    except OSError:
        return ""


class Launcher(Protocol):
    def run(self, argv: list[str], **kw) -> RunResult: ...


class ProcessLauncher:
    """Runs argv as the current (builder) identity with bounded output and time."""

    def run(self, argv: list[str], *, env, cwd, spool, timeout_s, log_bytes, **kw) -> RunResult:
        return run_bounded(
            argv, env=env, cwd=cwd, spool=spool, timeout_s=timeout_s, log_bytes=log_bytes, **kw
        )


@dataclass(frozen=True)
class HostFacts:
    uid: int
    rootless: bool
    podman_version: str
    denied_reachable: tuple[str, ...]
    egress_ok: bool
    egress_detail: str
    cgroup_limits: bool

    def failures(self) -> list[str]:
        bad = []
        if self.uid < 100:
            bad.append("builder_is_privileged_user")
        if not self.rootless:
            bad.append("podman_not_rootless")
        if self.denied_reachable:
            bad.append("production_paths_reachable")
        if not self.egress_ok:
            bad.append("egress_not_enforced")
        if not self.cgroup_limits:
            bad.append("limits_not_delegated")
        return bad


def egress_attestation(sources: tuple[str, ...], uid: int, ruleset: str) -> dict:
    """The record host setup writes after installing the per-UID egress policy."""
    return {
        "scheme": "steward-build-egress-v1",
        "uid": uid,
        "sources": sorted(sources),
        "ruleset_sha256": hashlib.sha256(ruleset.encode()).hexdigest(),
    }


def build_env(home: Path, tmp: Path, uid: int) -> dict[str, str]:
    """The only environment a build sees: no tokens, proxies, engine sockets or agents."""
    runtime = RUNTIME_ROOT / str(uid)
    return {
        "PATH": SAFE_PATH,
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "XDG_RUNTIME_DIR": str(runtime),
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
        "LANG": "C.UTF-8",
    }


class RootlessPodmanBackend:
    level = "container_rootless"

    def __init__(
        self,
        *,
        user: str,
        registry: str,
        launcher: Launcher | None = None,
        egress_attestation_path: Path = Path("/etc/steward/build-egress.json"),
        nft_listing: str | None = None,
        uid: int | None = None,
    ):
        if not SAFE_NAME.fullmatch(user) or user == "root":
            raise ValueError("builder user must be an unprivileged account name")
        if not REGISTRY.fullmatch(registry):
            raise ValueError("registry must be host:port")
        self.user, self.registry = user, registry
        self.launcher = launcher or ProcessLauncher()
        self.attestation_path = egress_attestation_path
        self.nft_listing = nft_listing  # supplied by the privileged host setup, never by the build
        self._uid = uid

    # -- naming
    @staticmethod
    def unit(job_id: str, stage: str = "build") -> str:
        if not JOB_ID.fullmatch(job_id) or stage not in STAGES:
            raise ValueError("invalid build scope identity")
        return f"steward-build-{job_id}-{stage}.scope"

    @staticmethod
    def _scope(uid: int, unit: str) -> str:
        return f"/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/{unit}"

    @staticmethod
    def image(job) -> tuple[str, str]:
        name = f"steward-build/{job.request.record.application}-{job.request.record.service}"
        return name, f"in-{job.request.input_digest[:12]}"

    # -- host readiness
    def _runtime_uid(self) -> int:
        try:
            account = pwd.getpwnam(self.user)
        except KeyError:
            raise BuildError("builder_identity_mismatch") from None
        uid, gid = account.pw_uid, account.pw_gid
        if (
            uid < 100 or gid == 0 or (self._uid is not None and uid != self._uid)
            or os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid)
        ):  # fmt: skip
            raise BuildError("builder_identity_mismatch")
        runtime = RUNTIME_ROOT / str(uid)
        try:
            directory = runtime.lstat()
            manager = (runtime / "systemd").lstat()
            sockets = [(runtime / name).lstat() for name in ("bus", "systemd/private")]
        except OSError:
            raise BuildError("builder_runtime_unavailable") from None
        if (
            not stat.S_ISDIR(directory.st_mode) or directory.st_uid != uid
            or stat.S_IMODE(directory.st_mode) != 0o700
            or not stat.S_ISDIR(manager.st_mode) or manager.st_uid != uid
            or any(not stat.S_ISSOCK(sock.st_mode) or sock.st_uid != uid for sock in sockets)
        ):  # fmt: skip
            raise BuildError("builder_runtime_unavailable")
        return uid

    def _probe(
        self,
        argv: list[str],
        work: Path,
        env: dict[str, str],
        on_poll: Callable[[], bool] | None = None,
    ) -> RunResult:
        if on_poll is not None and not on_poll():
            raise BuildError("lost_lease")
        result = self.launcher.run(
            argv, env=env, cwd=work, spool=work, timeout_s=20,
            log_bytes=64 * 1024, on_poll=on_poll,
        )  # fmt: skip
        if result.reason == "lost_lease":
            raise BuildError("lost_lease")
        return result

    def host_facts(self, work: Path, sources: tuple[str, ...]) -> HostFacts:
        """Run a standalone probe with disposable storage and the same scope admission."""
        try:
            uid = self._runtime_uid()
        except BuildError as exc:
            return HostFacts(0, False, "", (), False, exc.code, False)
        job_id = secrets.token_hex(16)
        scratch = Path(tempfile.mkdtemp(prefix="probe-", dir=work))
        try:
            self._make_storage(scratch)
            return self._host_facts(scratch, sources, uid, job_id, BuildLimits(), None)
        finally:
            self._stop_scopes(job_id, uid, ("probe",))
            shutil.rmtree(scratch)

    def _host_facts(
        self,
        work: Path,
        sources: tuple[str, ...],
        uid: int,
        job_id: str,
        limits: BuildLimits,
        on_poll: Callable[[], bool] | None,
    ) -> HostFacts:
        env = build_env(work / "home", work / "tmp", uid)
        reachable = []
        for path in DENIED_PATHS:
            for flag in ("-r", "-w"):
                rc = self._probe(["/usr/bin/test", flag, path], work, env, on_poll).returncode
                if rc != 1:
                    reachable.append(path)
                    break
        ok, detail = self._egress(sources, uid)
        if reachable or not ok:
            return HostFacts(uid, False, "", tuple(reachable), ok, detail, False)

        info = self._run_scoped(
            job_id, "probe", uid, limits, self._podman(work, "info", "--format", "json"),
            work, env, timeout_s=min(20, limits.timeout_s), on_poll=on_poll,
            log_bytes=64 * 1024,
        )  # fmt: skip
        if info.reason == "lost_lease":
            raise BuildError("lost_lease")
        rootless, version = False, ""
        admitted = info.returncode == 0 and info.reason is None
        if admitted:
            try:
                data = json.loads(info.log)
                rootless = data["host"]["security"]["rootless"] is True
                version = str(data["version"]["Version"])
            except (ValueError, KeyError, TypeError):
                rootless = False
        return HostFacts(uid, rootless, version, (), ok, detail, admitted)

    def _egress(self, sources: tuple[str, ...], uid: int) -> tuple[bool, str]:
        if not sources:
            return False, "no_package_sources"
        try:
            attested = json.loads(self.attestation_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False, "no_attestation"
        if self.nft_listing is None:
            return False, "no_ruleset"
        if attested != egress_attestation(sources, uid, self.nft_listing):
            return False, "attestation_mismatch"
        return True, "attested"

    def available(self) -> tuple[bool, str]:
        # Real readiness is the host probe at the start of `build`, which fails closed.
        return True, ""

    # -- argument construction
    def _run_scoped(
        self,
        job_id: str,
        stage: str,
        uid: int,
        limits: BuildLimits,
        argv: list[str],
        work: Path,
        env: dict[str, str],
        *,
        timeout_s: float,
        on_poll: Callable[[], bool] | None,
        log_bytes: int,
        watch_disk: bool = True,
    ) -> RunResult:
        if on_poll is not None and not on_poll():
            return RunResult(None, b"", "lost_lease")
        unit = self.unit(job_id, stage)
        cpu_pct = max(1, int(limits.cpus * 100))
        props = [
            "Delegate=cpu memory pids",
            f"MemoryMax={limits.memory_mb}M",
            "MemorySwapMax=0",
            f"CPUQuota={cpu_pct}%",
            f"TasksMax={limits.pids}",
            f"RuntimeMaxSec={int(timeout_s) + 30}",
            "KillMode=control-group",
            "KillSignal=SIGKILL",
            "OOMPolicy=kill",
        ]
        out = [
            SYSTEMD_RUN, "--user", "--scope", "--quiet", "--collect",
            "--expand-environment=no", "--slice=app.slice", "--unit", unit,
        ]  # fmt: skip
        for prop in props:
            out += ["-p", prop]
        out += [
            "--", sys.executable, "-I", str(SCOPE_HELPER), str(uid), self._scope(uid, unit),
            str(limits.memory_mb * 2**20), str(cpu_pct), str(limits.pids), "--", *argv,
        ]  # fmt: skip
        # A scope inherits the launcher's exact environment and working directory.
        return self.launcher.run(
            out, env=env, cwd=work, spool=work, timeout_s=timeout_s, log_bytes=log_bytes,
            watch=work if watch_disk else None,
            max_watch_bytes=limits.disk_mb * 2**20, on_poll=on_poll,
        )  # fmt: skip

    @staticmethod
    def _podman(w: Path, *args: str) -> list[str]:
        return [
            PODMAN, "--cgroup-manager=cgroupfs", "--root", str(w / "graph"),
            "--runroot", str(w / "run"),
            "--tmpdir", str(w / "tmp"), *args,
        ]  # fmt: skip

    def build_argv(self, job: BuildJob, *, cgroup_parent: str | None = None) -> list[str]:
        """`podman build`: no volumes, secrets, ssh agent, build args, host network."""
        w, lim, recipe = job.work_dir, job.limits, job.request.recipe
        repo, tag = self.image(job)
        context = job.source_dir / recipe["context"] if recipe["context"] != "." else job.source_dir
        argv = self._podman(
            w, "build",
            "--file", str(job.source_dir / recipe["file"]),
            "--iidfile", str(w / "iid"),
            "--network", BUILD_NETWORK,
            "--pull=missing", "--no-cache", "--format", "oci", "--isolation", "oci",
            "--cap-drop", "all", "--security-opt", "no-new-privileges",
            "--memory", f"{lim.memory_mb}m",
            "--cpu-period", "100000", "--cpu-quota", str(max(1000, int(lim.cpus * 100000))),
            "--ulimit", f"nproc={lim.pids}:{lim.pids}", "--ulimit", "nofile=1024:4096",
            "--shm-size", "64m",
            "--label", f"steward.source-digest={job.request.record.source_digest}",
            "--label", f"steward.input-digest={job.request.input_digest}",
            "--tag", f"{repo}:{tag}",
        )  # fmt: skip
        if cgroup_parent is not None:
            argv += ["--cgroup-parent", cgroup_parent, "--cgroupns=private"]
        if recipe.get("target"):
            argv += ["--target", recipe["target"]]
        return [*argv, str(context)]

    def push_argv(self, job: BuildJob) -> list[str]:
        repo, tag = self.image(job)
        insecure = self.registry.split(":")[0] in ("127.0.0.1", "localhost")
        return self._podman(
            job.work_dir, "push", f"--tls-verify={'false' if insecure else 'true'}",
            "--digestfile", str(job.work_dir / "digest"), f"{repo}:{tag}",
            f"docker://{self.registry}/{repo}:{tag}",
        )  # fmt: skip

    # -- execution
    @staticmethod
    def _make_storage(w: Path) -> None:
        for name in ("graph", "run", "tmp", "home"):
            (w / name).mkdir(mode=0o700)

    def build(self, job: BuildJob) -> BackendOutcome:
        w = job.work_dir
        try:
            uid = self._runtime_uid()
        except BuildError as exc:
            return BackendOutcome("failed", "host_not_ready", log=exc.code.encode())
        self._make_storage(w)
        (w / SCOPE_MARKER).touch(mode=0o600, exist_ok=False)
        limit = job.limits
        facts = self._host_facts(w, job.package_sources, uid, job.job_id, limit, job.on_poll)
        toolchain = {"podman": facts.podman_version, "runner": "systemd-run --user --scope"}
        egress = {"enforcement": "host-firewall-attested" if facts.egress_ok else "none"}
        bad = facts.failures()
        if bad:
            return BackendOutcome(
                "failed", "host_not_ready", log=("; ".join(bad)).encode(), toolchain=toolchain,
                egress=egress,
            )  # fmt: skip
        env = build_env(w / "home", w / "tmp", uid)
        common = {"on_poll": job.on_poll, "log_bytes": limit.log_bytes}
        cgroup_parent = self._scope(uid, self.unit(job.job_id, "build"))
        res = self._run_scoped(
            job.job_id, "build", uid, limit, self.build_argv(job, cgroup_parent=cgroup_parent),
            w, env, timeout_s=limit.timeout_s, **common,
        )  # fmt: skip
        stop = self._stop(res, "build")
        if stop is not None:
            return BackendOutcome(*stop[:2], log=res.log, toolchain=toolchain, egress=egress)
        iid = _read(w / "iid")
        if not DIGEST.fullmatch(iid if iid.startswith("sha256:") else "sha256:" + iid):
            return BackendOutcome(
                "failed", "no_image_id", log=res.log, toolchain=toolchain, egress=egress
            )
        push = self._run_scoped(
            job.job_id, "push", uid, limit, self.push_argv(job), w, env, timeout_s=300, **common,
        )  # fmt: skip
        stop = self._stop(push, "push")
        if stop is not None:
            return BackendOutcome(
                *stop[:2], log=res.log + push.log, toolchain=toolchain, egress=egress
            )
        if job.on_poll is not None and not job.on_poll():
            return BackendOutcome("failed", "lost_lease", toolchain=toolchain, egress=egress)
        digest = _read(w / "digest")
        repo, _ = self.image(job)
        return BackendOutcome(
            "succeeded",
            "",
            digest,
            f"{self.registry}/{repo}@{digest}",
            res.log + push.log,
            toolchain,
            egress,
        )

    @staticmethod
    def _stop(res: RunResult, stage: str) -> tuple[str, str] | None:
        if res.reason == "timeout":
            return "timeout", f"{stage}_timeout"
        if res.reason in ("log_limit", "disk_limit"):
            return "limit_exceeded", res.reason
        if res.reason == "lost_lease":
            return "failed", "lost_lease"
        if res.returncode == REFUSED:
            return "failed", "scope_admission_failed"
        if res.returncode in (*EXIT_KILLED, -9, -15):
            return "limit_exceeded", f"{stage}_killed"
        if res.returncode != 0:
            return "failed", f"{stage}_failed"
        return None

    def cleanup_argv(self, job_id: str) -> list[list[str]]:
        """Stop only the exact transient scopes belonging to the full job ID."""
        return [[SYSTEMCTL, "--user", "stop", self.unit(job_id, stage)] for stage in STAGES]

    def cleanup(self, job_id: str) -> None:
        self._stop_scopes(job_id, self._runtime_uid(), STAGES)

    def cleanup_workspace(
        self,
        job_id: str,
        work: Path,
        *,
        legacy: bool,
        on_poll: Callable[[], bool] | None = None,
    ) -> None:
        """Drain the exact job and remove subordinate-ID storage inside its namespace."""
        self.unit(job_id)  # validate before deriving any paths
        if work.name != job_id:
            raise BuildError("scope_cleanup_failed")
        if not legacy and not (work / SCOPE_MARKER).is_file():
            return  # pre-launch refusal or an unrelated backend
        uid = self._runtime_uid()
        if legacy:
            # The old unit name used only half the job ID. Never stop it on the
            # basis of a prefix that can also identify another job.
            old_unit = f"steward-build-{job_id[:16]}.service"
            app_cgroup = CGROUP / self._scope(uid, old_unit).lstrip("/")
            # The old launcher left slice selection to systemd.
            root_cgroup = app_cgroup.parent.parent / old_unit
            if not all(self._quiescent(path) for path in (root_cgroup, app_cgroup)):
                raise BuildError("legacy_unit_not_quiescent")
        self._stop_scopes(job_id, uid, STAGES, on_poll=on_poll)
        paths = []
        for name in ("graph", "run", "tmp"):
            directory = work / name
            try:
                info = directory.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
                raise BuildError("scope_cleanup_failed")
            if next(directory.iterdir(), None) is not None:
                paths.append(str(directory))
        if not paths:
            return
        argv = self._podman(
            work, "unshare", "--", "/usr/bin/rm", "-rf", "--one-file-system", "--", *paths
        )
        env = build_env(work / "home", work / "tmp", uid)
        try:
            result = self._run_scoped(
                job_id, "clean", uid, BuildLimits(), argv, work, env,
                timeout_s=30, on_poll=on_poll, log_bytes=4096, watch_disk=False,
            )  # fmt: skip
            if result.reason == "lost_lease":
                raise BuildError("lost_lease")
            if result.reason is not None or result.returncode != 0:
                raise BuildError("storage_cleanup_failed")
        finally:
            self._stop_scopes(job_id, uid, ("clean",))

    def _stop_scopes(
        self,
        job_id: str,
        uid: int,
        stages: tuple[str, ...],
        *,
        on_poll: Callable[[], bool] | None = None,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="steward-cleanup-", dir="/var/tmp") as tmp:
            work = Path(tmp)
            env = build_env(work, work, uid)
            failures = []
            for stage in stages:
                unit = self.unit(job_id, stage)
                self._probe([SYSTEMCTL, "--user", "stop", unit], work, env, on_poll)
                cgroup = CGROUP / self._scope(uid, unit).lstrip("/")
                if not self._quiescent(cgroup):
                    failures.append(unit)
            if failures:
                raise BuildError("scope_cleanup_failed", ", ".join(failures))

    @staticmethod
    def _quiescent(cgroup: Path) -> bool:
        try:
            # A missing unit is normal with --collect. Require the v2 mount first.
            (CGROUP / "cgroup.controllers").stat()
            return "populated 0" in (cgroup / "cgroup.events").read_text().splitlines()
        except FileNotFoundError:
            return (CGROUP / "cgroup.controllers").is_file() and not os.path.lexists(cgroup)
        except OSError:
            return False
