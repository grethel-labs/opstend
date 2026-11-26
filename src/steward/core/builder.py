"""Run an isolated build of a fetched repository revision and record how isolated it was (R03).

The build consumes exactly the inputs R01 and R02 bound together: the source digest of
a fetched commit and the digest of a *suitable* workload contract. Repository content
and everything the build prints are untrusted. The build gets no production secrets,
host sockets or executor access; it yields an *artifact digest only* and authorizes
nothing by itself (R04 validates independently). Fail closed everywhere.

Isolation levels, strongest first (ADR 0002 section 3). The level that actually ran
is recorded, never inferred from the request, and a container build is always
labelled "container isolation, no VM protection".

Backends implement :class:`BuilderBackend`. Only the rootless-container backend
exists (``builder_podman``); VM and external-CI backends plug in through the same
interface. The container tier runs only under ``build.allow_container_isolation``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets as _secrets
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from collections import deque
from collections.abc import Callable, Set
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

from . import secrets as secretlib
from .canonical import canonical_json
from .config import BuildPolicy, WorkloadContract
from .config import Level as Level
from .repositories import (
    SHA1,
    FetchError,
    FetchPolicy,
    SourceRecord,
    git_env,
    run_git,
    source_digest,
    store_path,
)
from .repository_contract import ContractProposal, ProposalResult, check_suitability

if TYPE_CHECKING:
    from .repository_source_handoff import ExpectedInput

RECORD_SCHEMA = 1
BUILD_JOB_KIND = "repository.build"
MARKER = ".steward-build-owned"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
JOB_ID = re.compile(r"^[0-9a-f]{32}$")

# Strongest first. Rank decides selection and reuse; never a claim about a weaker level.
LEVEL_RANK: dict[str, int] = {"ephemeral_vm": 3, "external_ci": 2, "container_rootless": 1}
LEVEL_LABEL: dict[str, str] = {
    "ephemeral_vm": "ephemeral VM isolation",
    "external_ci": "external ephemeral CI runner",
    "container_rootless": "container isolation, no VM protection",
}
STATUSES = ("succeeded", "failed", "timeout", "limit_exceeded", "crashed")


class BuildError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BuildLimits:
    timeout_s: float = 1800
    memory_mb: int = 2048
    cpus: float = 2.0
    pids: int = 512
    disk_mb: int = 4096
    log_bytes: int = 1024 * 1024
    source_bytes: int = 256 * 2**20
    source_files: int = 10000

    @classmethod
    def from_policy(cls, policy: BuildPolicy) -> BuildLimits:
        return cls(
            timeout_s=policy.timeout_s,
            memory_mb=policy.memory_mb,
            cpus=policy.cpus,
            pids=policy.pids,
            disk_mb=policy.disk_mb,
            log_bytes=policy.log_kb * 1024,
        )


# --- immutable inputs -------------------------------------------------------


@dataclass(frozen=True)
class BuildRequest:
    """Verified, immutable build inputs. Create only with :meth:`create`."""

    record: SourceRecord
    contract: dict
    contract_digest: str
    inventory: dict
    input_digest: str
    store: Path

    @classmethod
    def create(cls, record: SourceRecord, proposal: ProposalResult, fetch_root: Path):
        """Bind a source record to a suitable contract; re-checks everything itself."""
        if not SHA1.fullmatch(record.commit) or not SHA1.fullmatch(record.tree):
            raise BuildError("bad_source", "record commit/tree must be full SHA-1")
        if source_digest(record.commit, record.tree) != record.source_digest:
            raise BuildError("bad_source", "source digest does not match commit and tree")
        if (proposal.state, proposal.commit, proposal.tree, proposal.source_digest) != (
            "suitable", record.commit, record.tree, record.source_digest,
        ):  # fmt: skip
            raise BuildError("not_authorized", "no suitable contract for exactly this source")
        if "isolated_build" not in proposal.authorizes or proposal.contract is None:
            raise BuildError("not_authorized", "the contract does not authorize a build")
        digest = hashlib.sha256(canonical_json(proposal.contract).encode()).hexdigest()
        if digest != proposal.contract_digest:
            raise BuildError("bad_contract", "contract digest does not match the contract")
        # The suitability rules run again here: a stored or relayed verdict is not trusted.
        try:
            contract = WorkloadContract.model_validate(proposal.contract)
            reasons = check_suitability(ContractProposal.model_validate(proposal.contract))
        except ValueError:
            raise BuildError("bad_contract", "contract fails validation") from None
        if reasons:
            raise BuildError("unsuitable", reasons[0]["code"])
        if proposal.inventory is None:
            raise BuildError("no_inventory", "dependency inventory is required")
        if (proposal.inventory.get("commit"), proposal.inventory.get("tree")) != (
            record.commit, record.tree,
        ):  # fmt: skip
            raise BuildError("bad_inventory", "inventory belongs to another source")
        store = store_path(fetch_root, record)
        if not store.is_dir():
            raise BuildError("bad_source", "fetched source is not in the store")
        inputs = {
            "scheme": "steward-build-input-v1",
            "source_digest": record.source_digest,
            "contract_digest": digest,
            "recipe": contract.build.model_dump(mode="json"),
            "inventory_digest": hashlib.sha256(
                canonical_json(proposal.inventory).encode()
            ).hexdigest(),
        }
        return cls(
            record,
            proposal.contract,
            digest,
            proposal.inventory,
            hashlib.sha256(canonical_json(inputs).encode()).hexdigest(),
            store,
        )

    @property
    def recipe(self) -> dict:
        return self.contract["build"]

    @property
    def subject(self) -> str:
        return f"{self.record.application}/{self.record.service}"


# --- source export (runs as the fetch identity, never the builder) -----------


MAX_SOURCE_LINK_BYTES = 4095
MAX_SOURCE_LISTING_BYTES = 8 * 2**20


def source_link(rel: str, data: bytes) -> str:
    link = os.fsdecode(data)
    resolved = os.path.normpath(os.path.join(os.path.dirname(rel), link))
    if (
        not link
        or len(data) > MAX_SOURCE_LINK_BYTES
        or os.path.isabs(link)
        or "\0" in link
        or resolved == ".."
        or resolved.startswith("../")
    ):
        raise BuildError("unsafe_symlink", rel[:100])
    return link


def check_source_links(links: dict[str, str], deadline: float) -> None:
    """Resolve symlink components in source-relative order, including before '..'."""
    for rel, link in links.items():
        if time.monotonic() >= deadline:
            raise BuildError("export_failed", "timeout")
        parent = rel.split("/")[:-1]
        pending = deque(link.split("/"))
        hops = 1
        while pending:
            part = pending.popleft()
            if part in ("", "."):
                continue
            if part == "..":
                if not parent:
                    raise BuildError("unsafe_symlink", rel[:100])
                parent.pop()
                continue
            nested = links.get("/".join([*parent, part]))
            if nested is None:
                parent.append(part)
                continue
            hops += 1
            if hops > 40:
                raise BuildError("unsafe_symlink", rel[:100])
            pending.extendleft(reversed(nested.split("/")))


def export_source(
    request: BuildRequest,
    dest: Path,
    limits: BuildLimits,
    policy: FetchPolicy | None = None,
    *,
    on_poll: Callable[[], bool] | None = None,
) -> dict:
    """Write the exact tree of the commit under ``dest`` without Git filters or hooks.

    Blobs are read with plumbing (no checkout, no attributes, so no ``export-subst``).
    Submodules and links that leave the tree are refused. Returns file/byte counts.
    """
    policy = policy or FetchPolicy()
    dest.mkdir(mode=0o755)
    scratch = Path(tempfile.mkdtemp(prefix="steward-export-"))
    deadline = time.monotonic() + 120
    env = git_env(policy, scratch)
    next_poll = 0.0

    def lease_valid() -> bool:
        nonlocal next_poll
        now = time.monotonic()
        if on_poll is None or now < next_poll:
            return True
        next_poll = now + 0.2
        return on_poll()

    def git(args: list[str], label: str, max_stdout: int) -> bytes:
        if not lease_valid():
            raise BuildError("lost_lease")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BuildError("export_failed", "timeout")
        try:
            return run_git(
                policy, ["--git-dir", str(request.store), *args], label=label, env=env,
                spool=scratch, cwd=scratch, timeout_s=remaining, max_stdout=max_stdout,
                on_poll=lease_valid if on_poll is not None else None,
            )  # fmt: skip
        except FetchError as exc:
            if exc.code == "lost_lease":
                raise BuildError("lost_lease") from None
            raise BuildError("export_failed", exc.code) from None

    try:
        listing = git(
            ["ls-tree", "-r", "-l", "-z", "--full-tree", request.record.tree],
            "ls-tree",
            MAX_SOURCE_LISTING_BYTES,
        )
        files = total = 0
        links: dict[str, str] = {}
        for item in listing.split(b"\0"):
            if not item:
                continue
            meta, _, raw = item.partition(b"\t")
            mode, otype, oid, size = meta.split()
            try:
                rel = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise BuildError("unsafe_path", "non-UTF-8 name") from None
            parts = rel.split("/")
            if (
                not rel or rel.startswith("/") or any(p in ("", ".", "..") for p in parts)
                or any(p.lower() == ".git" for p in parts)
                or any(ord(c) < 32 or ord(c) == 127 for c in rel)
            ):  # fmt: skip
                raise BuildError("unsafe_path", rel.encode("unicode_escape").decode()[:100])
            if otype != b"blob" or mode == b"160000":
                raise BuildError("submodule", "submodules are not built")
            files += 1
            total += int(size)
            if files > limits.source_files or total > limits.source_bytes:
                raise BuildError("source_too_large", f"{files} files, {total} bytes")
            if mode == b"120000" and int(size) > MAX_SOURCE_LINK_BYTES:
                raise BuildError("unsafe_symlink", rel[:100])
            target = dest.joinpath(*parts)
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            data = git(["cat-file", "blob", oid.decode()], "cat-file", int(size) + 1)
            if mode == b"120000":
                links[rel] = source_link(rel, data)
            elif mode in (b"100644", b"100755"):
                fd = os.open(
                    target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o755 if mode == b"100755" else 0o644,
                )  # fmt: skip
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
            else:
                raise BuildError("unsafe_path", "unsupported file mode")
        check_source_links(links, deadline)
        for rel, link in links.items():
            os.symlink(link, dest / rel)
        return {"files": files, "bytes": total}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# --- bounded process execution ---------------------------------------------


def tree_size(path: Path) -> int:
    total = 0
    stack = [path]
    while stack:
        with contextlib.suppress(OSError), os.scandir(stack.pop()) as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                else:
                    with contextlib.suppress(OSError):
                        total += entry.stat(follow_symlinks=False).st_size
    return total


@dataclass
class RunResult:
    returncode: int | None
    log: bytes
    reason: Literal["timeout", "log_limit", "disk_limit", "lost_lease"] | None = None


def run_bounded(
    argv: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    spool: Path,
    timeout_s: float,
    log_bytes: int,
    watch: Path | None = None,
    max_watch_bytes: int | None = None,
    on_poll: Callable[[], bool] | None = None,
    poll_s: float = 0.2,
) -> RunResult:
    """Run a fixed argv (no shell) under time, output and disk budgets.

    The whole process group is killed on any breach. ``on_poll`` returns False when
    the lease is lost; the run then stops.
    """
    out_path = spool / f"out-{_secrets.token_hex(4)}.spool"
    deadline = time.monotonic() + timeout_s
    reason = None
    with out_path.open("wb") as out:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=out,
            stderr=subprocess.STDOUT, start_new_session=True, close_fds=True,
        )  # fmt: skip
        try:
            while True:
                try:
                    proc.wait(timeout=poll_s)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() > deadline:
                    reason = "timeout"
                elif out_path.stat().st_size > log_bytes * 4:
                    reason = "log_limit"
                elif (
                    watch is not None and max_watch_bytes is not None
                    and tree_size(watch) > max_watch_bytes
                ):  # fmt: skip
                    reason = "disk_limit"
                elif on_poll is not None and not on_poll():
                    reason = "lost_lease"
                if reason:
                    break
        finally:
            if proc.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    if reason is None and out_path.stat().st_size > log_bytes * 4:
        reason = "log_limit"
    if (
        reason is None and watch is not None and max_watch_bytes is not None
        and tree_size(watch) > max_watch_bytes
    ):  # fmt: skip
        reason = "disk_limit"
    with out_path.open("rb") as handle:
        handle.seek(max(0, out_path.stat().st_size - log_bytes))
        tail = handle.read(log_bytes)
    out_path.unlink(missing_ok=True)
    return RunResult(proc.returncode, tail, reason)


# --- backend contract -------------------------------------------------------


@dataclass
class BuildJob:
    job_id: str
    request: BuildRequest
    source_dir: Path
    work_dir: Path
    limits: BuildLimits
    package_sources: tuple[str, ...]
    on_poll: Callable[[], bool] | None = None


@dataclass
class BackendOutcome:
    """What a backend reports. Everything in it is untrusted until sanitized."""

    status: str
    code: str = ""
    output_digest: str | None = None
    output_ref: str | None = None
    log: bytes = b""
    toolchain: dict[str, str] = field(default_factory=dict)
    egress: dict[str, Any] = field(default_factory=dict)


class BuilderBackend(Protocol):
    level: Level

    def available(self) -> tuple[bool, str]:
        """(ready, reason). A backend that cannot prove its isolation is not ready."""

    def build(self, job: BuildJob) -> BackendOutcome: ...

    def cleanup(self, job_id: str) -> None:
        """Destroy only resources this backend created for ``job_id``. Idempotent."""


def isolation_rejection(
    policy: BuildPolicy | None, level: object, *, minimum: Level | None = None
) -> str | None:
    """Check the isolation tier and both floors. A missing policy supports legacy validation."""
    if not isinstance(level, str) or level not in LEVEL_RANK:
        return "unknown_level"
    if (
        level == "container_rootless"
        and policy is not None
        and not policy.allow_container_isolation
    ):
        return "not_allowed"

    configured = policy.minimum_isolation if policy is not None else None
    for floor in (configured, minimum):
        if floor is None:
            continue
        if not isinstance(floor, str) or floor not in LEVEL_RANK:
            return "unknown_level"
        if LEVEL_RANK[level] < LEVEL_RANK[floor]:
            return "below_minimum"
    return None


def select_backend(
    policy: BuildPolicy, backends: list[BuilderBackend], *, minimum: Level | None = None
) -> tuple[BuilderBackend | None, list[dict]]:
    """Strongest ready backend; the container tier needs explicit activation."""
    notes: list[dict] = []
    ready: list[BuilderBackend] = []
    for backend in backends:
        rejection = isolation_rejection(policy, backend.level, minimum=minimum)
        if rejection is not None:
            notes.append({"level": str(backend.level), "skipped": rejection})
        else:
            ok, why = backend.available()
            if ok:
                ready.append(backend)
            else:
                notes.append(
                    {"level": backend.level, "skipped": "unavailable", "detail": why[:200]}
                )
    if not ready:
        return None, notes
    return max(ready, key=lambda b: LEVEL_RANK[b.level]), notes


# --- records ----------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_log(data: bytes, limit: int) -> str:
    text = data[-limit:].decode("utf-8", "replace")
    text = "".join(c if c in "\n\t" or 32 <= ord(c) < 127 or ord(c) > 159 else "?" for c in text)
    return secretlib.redact(text).strip()


def _write_json(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + ".new")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(data, sort_keys=True, indent=2) + "\n")
    os.replace(tmp, path)


class BuildRunner:
    """Runs builds in per-job workdirs under ``root`` and persists build records."""

    def __init__(
        self,
        root: Path,
        policy: BuildPolicy,
        backends: list[BuilderBackend],
        *,
        limits: BuildLimits | None = None,
        fetch_policy: FetchPolicy | None = None,
        minimum: Level | None = None,
    ):
        self.root = root
        self.policy = policy
        self.backends = backends
        self.limits = limits or BuildLimits.from_policy(policy)
        self.fetch_policy = fetch_policy
        self.minimum = minimum
        for name in ("work", "records"):
            (root / name).mkdir(mode=0o700, parents=True, exist_ok=True)
            info = (root / name).lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise BuildError("bad_root", f"{name} is not a private directory")

    # -- records
    def _record_dir(self, input_digest: str) -> Path:
        return self.root / "records" / input_digest

    def load_records(self, input_digest: str) -> list[dict]:
        out = []
        for path in sorted(self._record_dir(input_digest).glob("*.json")):
            with contextlib.suppress(OSError, ValueError):
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data.get("input_digest") == input_digest:
                    out.append(data)
        return out

    def find_reusable(
        self, request: BuildRequest, *, accepted: set[str] | None = None
    ) -> dict | None:
        """A prior successful build of identical inputs, by digest and never by tag.

        Reuse needs an isolation level that satisfies the current policy and, when
        ``accepted`` is given, an output digest that R04 has accepted.
        """
        for data in reversed(self.load_records(request.input_digest)):
            output = data.get("output")
            isolation = data.get("isolation")
            digest = output.get("digest") if isinstance(output, dict) else None
            level = isolation.get("level") if isinstance(isolation, dict) else None
            if (
                data.get("status") == "succeeded"
                and isinstance(digest, str)
                and DIGEST.fullmatch(digest)
                and isolation_rejection(self.policy, level, minimum=self.minimum) is None
                and (accepted is None or digest in accepted)
            ):
                return data
        return None

    # -- execution
    def run(
        self,
        request: BuildRequest,
        *,
        job_id: str | None = None,
        on_poll: Callable[[], bool] | None = None,
        accepted: set[str] | None = None,
    ) -> dict:
        """Build (or return the reusable accepted artifact) and persist the record."""
        job_id = job_id or _secrets.token_hex(16)
        if not JOB_ID.fullmatch(job_id):
            raise BuildError("bad_job", "job id must be 32 hex characters")
        return self._run_request(request, job_id, on_poll, accepted)

    def run_handoff(
        self,
        expected: ExpectedInput,
        *,
        job_id: str,
        input_digest: str | None = None,
        on_poll: Callable[[], bool] | None = None,
        accepted: set[str] | None = None,
    ) -> dict:
        """Verify a capsule and run it under the caller's active job lease."""
        from .repository_source_handoff import _open_handoff

        if not JOB_ID.fullmatch(job_id):
            raise BuildError("bad_job", "job id must be 32 hex characters")
        if on_poll is not None and not on_poll():
            raise BuildError("lease_lost")
        work = self.root / "work" / job_id
        self._create_workdir(work)
        with ExitStack() as retire, ExitStack() as workspace:
            retire.callback(self._remove_workdir, work)
            self._mark_workdir(work, job_id)
            request = workspace.enter_context(
                _open_handoff(expected, work, input_digest=input_digest)
            )
            if on_poll is not None and not on_poll():
                raise BuildError("lease_lost")
            return self._run_request(
                request, job_id, on_poll, accepted, workspace=workspace, retire=retire
            )

    @staticmethod
    def _create_workdir(work: Path) -> None:
        try:
            work.mkdir(mode=0o700)
        except FileExistsError:
            raise BuildError("job_workspace_exists") from None

    @staticmethod
    def _mark_workdir(work: Path, job_id: str) -> None:
        (work / MARKER).write_text(f"steward-build v2 {job_id}\n", encoding="utf-8")

    @staticmethod
    def _cleanup_backend(
        backend: BuilderBackend,
        job_id: str,
        work: Path,
        *,
        legacy: bool,
        on_poll: Callable[[], bool] | None = None,
    ) -> None:
        cleanup_workspace = getattr(backend, "cleanup_workspace", None)
        if cleanup_workspace is not None:
            cleanup_workspace(job_id, work, legacy=legacy, on_poll=on_poll)
        else:
            backend.cleanup(job_id)

    def _run_request(
        self,
        request: BuildRequest,
        job_id: str,
        on_poll: Callable[[], bool] | None,
        accepted: set[str] | None,
        *,
        workspace: ExitStack | None = None,
        retire: ExitStack | None = None,
    ) -> dict:
        reused = self.find_reusable(request, accepted=accepted) if accepted is not None else None
        if reused is not None:
            return {**reused, "reused": True}
        backend, notes = select_backend(self.policy, self.backends, minimum=self.minimum)
        started = _now()
        if backend is None:
            return self._persist(
                request, job_id, None, started,
                BackendOutcome("failed", "no_isolation_available"), notes, {},
            )  # fmt: skip
        work = self.root / "work" / job_id
        if workspace is None:
            self._create_workdir(work)
        cleanup = "ok"
        outcome: BackendOutcome
        exported: dict = {}
        entered_backend = False
        try:
            if workspace is None:
                self._mark_workdir(work, job_id)
            exported = export_source(
                request, work / "src", self.limits, self.fetch_policy, on_poll=on_poll
            )
            job = BuildJob(
                job_id, request, work / "src", work, self.limits,
                tuple(self.policy.package_sources), on_poll,
            )  # fmt: skip
            entered_backend = True
            outcome = backend.build(job)
        except BuildError as exc:
            outcome = BackendOutcome("failed", exc.code)
        except Exception as exc:  # noqa: BLE001 - a crashing backend must not leak or hang
            outcome = BackendOutcome("crashed", type(exc).__name__)
        finally:
            try:
                if entered_backend:
                    self._cleanup_backend(backend, job_id, work, legacy=False)
            except Exception:  # noqa: BLE001
                cleanup = "backend_failed"
            if cleanup != "ok" and retire is not None:
                retire.pop_all()
            if workspace is not None:
                workspace.close()
            if cleanup == "ok":
                if retire is None:
                    self._remove_workdir(work)
                else:
                    retire.close()
                if work.exists():
                    cleanup = "workdir_remains"
        return self._persist(request, job_id, backend, started, outcome, notes, exported, cleanup)

    def _persist(
        self, request, job_id, backend, started, outcome, notes, exported, cleanup="ok"
    ) -> dict:
        status = outcome.status if outcome.status in STATUSES else "crashed"
        code = re.sub(r"[^a-z0-9_]", "", str(outcome.code).lower())[:64]
        digest = outcome.output_digest
        if status == "succeeded" and cleanup != "ok":
            status, code = "failed", "cleanup_failed"
        if status == "succeeded" and not (isinstance(digest, str) and DIGEST.fullmatch(digest)):
            status, code, digest = "failed", "bad_output_digest", None
        if status != "succeeded":
            digest = None
        level = backend.level if backend is not None else None
        ref = outcome.output_ref if digest and isinstance(outcome.output_ref, str) else None
        if ref is not None and not ref.endswith("@" + digest):
            ref = None  # an artifact is identified by digest, never by a mutable tag
        record = {
            "schema": RECORD_SCHEMA,
            "job_id": job_id,
            "status": status,
            "code": code,
            "started_at": started,
            "finished_at": _now(),
            "repository": request.record.repository,
            "application": request.record.application,
            "service": request.record.service,
            "commit": request.record.commit,
            "tree": request.record.tree,
            "source_digest": request.record.source_digest,
            "contract_digest": request.contract_digest,
            "recipe": request.recipe,
            "recipe_digest": hashlib.sha256(canonical_json(request.recipe).encode()).hexdigest(),
            "inventory_digest": hashlib.sha256(
                canonical_json(request.inventory).encode()
            ).hexdigest(),
            "base_images": request.inventory.get("base_images", []),
            "unresolved": request.inventory.get("unresolved", []),
            "input_digest": request.input_digest,
            "toolchain": {
                str(k)[:40]: str(v)[:100] for k, v in list(outcome.toolchain.items())[:10]
            },
            "isolation": {
                "level": level,
                "label": LEVEL_LABEL.get(level) if level else None,
                "vm_protection": level == "ephemeral_vm",
                "considered": notes,
            },
            "limits": {
                "timeout_s": self.limits.timeout_s,
                "memory_mb": self.limits.memory_mb,
                "cpus": self.limits.cpus,
                "pids": self.limits.pids,
                "disk_mb": self.limits.disk_mb,
                "log_bytes": self.limits.log_bytes,
            },
            "egress": {
                "package_sources": list(self.policy.package_sources),
                **{
                    str(k)[:40]: v
                    for k, v in list(outcome.egress.items())[:8]
                    if isinstance(v, (bool, int, str))
                },
            },  # fmt: skip
            "source_export": exported,
            "output": {"digest": digest, "ref": ref},
            "log": _clean_log(outcome.log, self.limits.log_bytes),
            "cleanup": cleanup,
            "trust": "untrusted_candidate",
            "authorizes": [],
            "reproducibility": "not_measured",
        }
        directory = self._record_dir(request.input_digest)
        directory.mkdir(mode=0o700, exist_ok=True)
        _write_json(directory / f"{job_id}.json", record)
        return record

    # -- cleanup
    @staticmethod
    def _remove_workdir(path: Path) -> None:
        with contextlib.suppress(OSError):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid():
                marker = path / MARKER
                for child in path.iterdir():
                    if child == marker:
                        continue
                    if stat.S_ISDIR(child.lstat().st_mode):
                        shutil.rmtree(child)
                    else:
                        child.unlink()
                marker.unlink(missing_ok=True)
                path.rmdir()

    def reconcile(
        self,
        active: Set[str] = frozenset(),
        *,
        on_poll: Callable[[], bool] | None = None,
    ) -> list[str]:
        """Remove leftovers of builds whose lease is gone; only marked, owned workdirs."""
        removed = []
        for path in sorted((self.root / "work").iterdir()):
            job_id = path.name
            if job_id in active or not JOB_ID.fullmatch(job_id):
                continue
            if on_poll is not None and not on_poll():
                raise BuildError("lost_lease")
            try:
                info = path.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                    continue
                fd = os.open(path / MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as marker_file:
                    marker_info = os.fstat(marker_file.fileno())
                    if not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != info.st_uid:
                        continue
                    marker = marker_file.read(64)
            except OSError:
                continue
            legacy = marker == f"steward-build v1 {job_id}\n".encode()
            if not legacy and marker != f"steward-build v2 {job_id}\n".encode():
                continue
            try:
                for backend in self.backends:
                    self._cleanup_backend(backend, job_id, path, legacy=legacy, on_poll=on_poll)
            except BuildError as exc:
                if exc.code == "lost_lease":
                    raise
                continue
            except Exception:  # noqa: BLE001, S112 - leave the owned workspace for a later retry
                continue
            self._remove_workdir(path)
            if not path.exists():
                removed.append(job_id)
        return removed


# --- durable jobs (dispatched by the caller that owns the claim loop) ---------


def enqueue_build(store, request: BuildRequest, *, created_by: str, now: float | None = None):
    """Queue one build; identical inputs share one job (idempotency key)."""
    payload = {
        "application": request.record.application,
        "service": request.record.service,
        "commit": request.record.commit,
        "source_digest": request.record.source_digest,
        "contract_digest": request.contract_digest,
        "input_digest": request.input_digest,
    }
    return store.enqueue(
        BUILD_JOB_KIND,
        f"build:{request.subject}",
        payload,
        idempotency_key=f"{BUILD_JOB_KIND}:{request.input_digest}",
        created_by=created_by,
        max_attempts=2,
        now=now,
    )


def handle_build_job(
    store,
    runner: BuildRunner,
    load_request: Callable[[dict], BuildRequest],
    job: dict,
    worker: str,
    *,
    now: float | None = None,
    lease_s: float = 120.0,
) -> str | None:
    """Run one claimed ``repository.build`` job. Returns the job state (None: lease lost).

    Leftovers of an interrupted earlier attempt are reconciled first; a lost lease
    stops the build and cleans up. Only a crash is retried, never a failed build.
    """
    if job["kind"] != BUILD_JOB_KIND:
        raise ValueError("not a build job")
    clock = time.time if now is None else (lambda: now)

    def poll() -> bool:
        return store.heartbeat(job["id"], worker, lease_s=lease_s, now=clock())

    if not poll():
        return None
    others = {
        j["id"]
        for j in store.list_jobs(1000)
        if j["state"] == "running" and j["kind"] == BUILD_JOB_KIND and j["id"] != job["id"]
    }
    try:
        runner.reconcile(active=others, on_poll=poll)
        request = load_request(job["payload"])
        if request.input_digest != job["payload"].get("input_digest"):
            raise BuildError("bad_input", "job inputs changed")
    except BuildError as exc:
        if exc.code == "lost_lease":
            return None
        return store.finish(job["id"], worker, ok=False, error=exc.code, now=clock())
    try:
        record = runner.run(
            request,
            job_id=job["id"],
            on_poll=poll,
        )
    except BuildError as exc:
        return store.finish(job["id"], worker, ok=False, error=exc.code, now=clock())
    summary = {
        "status": record["status"],
        "code": record["code"],
        "input_digest": record["input_digest"],
        "output_digest": record["output"]["digest"],
        "isolation": record["isolation"]["level"],
    }
    return store.finish(
        job["id"], worker, ok=record["status"] == "succeeded", result=summary,
        error=record["code"] or None, retryable=record["status"] == "crashed", now=clock(),
    )  # fmt: skip
