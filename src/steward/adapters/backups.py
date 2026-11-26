"""BackupAdapter v1: fixed Restic REST/HTTPS operations as an unprivileged user."""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import logging
import os
import re
import ssl
import stat
import struct
import tempfile
import threading
import time
from contextlib import contextmanager, suppress
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Protocol
from urllib.parse import urlsplit

from ..core.backups import (
    BackupError,
    Capture,
    FilesystemCapture,
    Receipt,
    database_check,
    load_capture,
    regular_file,
)
from ..core.process import CommandError, run_bounded
from ..core.tools import RESTIC_BINARY, RESTIC_VERSION

MAX_OUTPUT = 1024 * 1024
REPOSITORY_LOOKUP_TIMEOUT_S = 30
logger = logging.getLogger(__name__)


class BackupAdapter(Protocol):
    version: int
    capabilities: tuple[str, ...]
    input_schema: dict
    timeout_s: int

    def health(self) -> dict: ...
    def repository_id(self) -> str: ...
    def backup(self, capture: Path) -> Receipt: ...
    def check(self, receipt: Receipt) -> Receipt: ...
    def restore_test(self, receipt: Receipt) -> Receipt: ...


def _systemd_acl(fd: int, uid: int, permission: int) -> bool:
    """Accept only systemd's root-owned ACL for this service identity."""
    try:
        data = os.getxattr(fd, "system.posix_acl_access")
        if len(data) != 44 or struct.unpack_from("<I", data)[0] != 2:
            return False
        entries = {struct.unpack_from("<HHI", data, offset) for offset in range(4, 44, 8)}
        return entries == {
            (1, permission, 0xFFFFFFFF),
            (2, permission, uid),
            (4, 0, 0xFFFFFFFF),
            (16, permission, 0xFFFFFFFF),
            (32, 0, 0xFFFFFFFF),
        }
    except (OSError, ValueError, struct.error):
        return False


def _systemd_credential(path: Path, fd: int, info: os.stat_result) -> bool:
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory:
        return False
    parent = Path(directory)
    if (
        parent.parent != Path("/run/credentials")
        or path.parent != parent
        or path.name in ("", ".", "..")
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o440
        or not _systemd_acl(fd, os.geteuid(), 4)
    ):
        return False
    try:
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory_fd)
            return (
                info.st_uid == 0
                and info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o550
                and _systemd_acl(directory_fd, os.geteuid(), 5)
            )
        finally:
            os.close(directory_fd)
    except OSError:
        return False


def secret_file(path: Path, *, minimum: int = 1) -> bytes:
    fd, info = regular_file(path, limit=8192)
    with os.fdopen(fd, "rb") as handle:
        private = info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o077
        if not private and not _systemd_credential(path, handle.fileno(), info):
            raise BackupError("invalid_credentials")
        value = handle.read(8193)
    if len(value.strip()) < minimum or b"\x00" in value:
        raise BackupError("invalid_credentials")
    return value


def line_secret(path: Path, *, minimum: int = 1) -> bytes:
    return credential_line(secret_file(path, minimum=minimum), minimum=minimum)


def credential_line(value: bytes, *, minimum: int = 1) -> bytes:
    if len(value) > 8192:
        raise BackupError("invalid_credentials")
    if value.endswith(b"\r\n"):
        value = value[:-2]
    elif value.endswith(b"\n"):
        value = value[:-1]
    if b"\n" in value or b"\r" in value or b"\0" in value or len(value.strip()) < minimum:
        raise BackupError("invalid_credentials")
    return value


def repository_url(raw: bytes) -> str:
    try:
        if len(raw) > 8192:
            raise ValueError("repository descriptor too large")
        value = raw.decode("utf-8").strip()
        if not value.startswith("rest:https://"):
            raise ValueError("REST over HTTPS required")
        parsed = urlsplit(value[5:])
        if any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise ValueError("invalid repository characters")
        if (
            not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not 1 <= (parsed.port if parsed.port is not None else 443) <= 65535
            or not re.fullmatch(r"/[A-Za-z0-9._~/-]*", parsed.path)
            or any(p in (".", "..") for p in parsed.path.split("/"))
            or "//" in parsed.path
        ):
            raise ValueError("invalid repository")
        return value
    except (ValueError, UnicodeError):
        raise BackupError("invalid_repository") from None


def repository_for_endpoint(raw: bytes, endpoint) -> str:
    value = repository_url(raw)
    parsed = urlsplit(value[5:])
    host = parsed.hostname
    with suppress(ValueError):
        host = str(ipaddress.ip_address(host))
    if host != endpoint.host or (parsed.port or 443) != endpoint.port:
        raise BackupError("repository_target_mismatch")
    return value


class Restic:
    version = 1
    capabilities = (
        "backup.encrypted",
        "backup.idempotent",
        "integrity.full_read",
        "restore.data_test",
    )
    input_schema = Capture.model_json_schema()
    timeout_s = 1800

    def __init__(
        self,
        *,
        repository_file: Path,
        password_file: Path,
        state_dir: Path,
        username_file: Path | None = None,
        auth_password_file: Path | None = None,
        ca_file: Path | None = None,
        binary: Path | None = None,
        endpoint=None,
        read_only: bool = False,
    ):
        if type(read_only) is not bool:
            raise BackupError("invalid_input")
        self.read_only = read_only
        self._job_context = None
        self.binary = (
            binary or (RESTIC_BINARY if RESTIC_BINARY.is_file() else Path("/usr/bin/restic"))
        ).resolve()
        self.state = state_dir.resolve()
        raw_repository = secret_file(repository_file)
        self.repository = (
            repository_for_endpoint(raw_repository, endpoint)
            if endpoint is not None
            else repository_url(raw_repository)
        )
        self.password = line_secret(password_file, minimum=32)
        if bool(username_file) != bool(auth_password_file):
            raise BackupError("invalid_credentials")
        self.username = line_secret(username_file).decode() if username_file else None
        self.auth_password = (
            line_secret(auth_password_file).decode() if auth_password_file else None
        )
        if self.username is not None and ":" in self.username:
            raise BackupError("invalid_credentials")
        self.ca_file = ca_file.resolve() if ca_file else None

    def set_job_context(self, *, job_id: str, repository_id: str, capture_id: str) -> None:
        """Bind child-process evidence to the current leased upload."""
        if self._job_context is not None:
            raise BackupError("invalid_input")
        self._job_context = (job_id, repository_id, capture_id)

    def clear_job_context(self) -> None:
        self._job_context = None

    def _observe_job_locks(self, journal, argv, env, stop):
        """Best-effort bounded observation; it never deletes or changes locks."""
        for _ in range(30):
            if stop.is_set() or not journal.process_is_live():
                return
            deadline = time.monotonic() + 4

            def read(*args, deadline=deadline):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or stop.is_set():
                    raise CommandError("timeout")
                return run_bounded(
                    [*argv, "--no-lock", *args],
                    cwd=self.state,
                    env=env,
                    timeout=remaining,
                    max_bytes=65536,
                )

            try:
                config = json.loads(read("cat", "config"))
                if not isinstance(config, dict) or config.get("id") != journal.repository_id:
                    return
                lock_ids = read("list", "locks").decode("ascii").splitlines()
                if len(lock_ids) > 64 or any(
                    re.fullmatch(r"[a-f0-9]{64}", lock_id) is None for lock_id in lock_ids
                ):
                    return
                for lock_id in lock_ids:
                    if stop.is_set() or not journal.process_is_live():
                        return
                    lock = json.loads(read("cat", "lock", lock_id))
                    journal.bind_observed_lock(lock_id, lock)
            except (CommandError, BackupError, OSError, ValueError, UnicodeError):
                pass  # Observation is advisory and cannot grant deletion authority.
            stop.wait(2)

    def _run(self, args, *, cwd=None, no_lock=False):
        if no_lock and not (
            args == ["cat", "config"]
            or args == ["list", "locks"]
            or (
                len(args) == 3
                and args[:2] == ["cat", "lock"]
                and re.fullmatch(r"[a-f0-9]{64}", args[2])
            )
        ):
            raise BackupError("policy_denied")
        if self.read_only and not (
            args == ["version"]
            or args == ["cat", "config"]
            or (
                len(args) == 3
                and args[:2] == ["cat", "snapshot"]
                and re.fullmatch(r"[a-f0-9]{64}", args[2])
            )
            or (
                len(args) == 5
                and args[0] == "restore"
                and args[2] == "--target"
                and args[4] == "--verify"
            )
        ):
            raise BackupError("policy_denied")
        # No inherited proxies, backend executables, password commands or other
        # service credentials. Repository/password values never appear in argv.
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="restic-credentials-", dir=self.state) as directory:
            root = Path(directory)
            repository, password = root / "repository", root / "password"
            repository.write_text(self.repository + "\n")
            password.write_bytes(self.password)
            repository.chmod(0o600)
            password.chmod(0o600)
            env = {
                "PATH": "/usr/bin:/bin",
                "HOME": directory,
                "TMPDIR": directory,
                "RESTIC_REPOSITORY_FILE": str(repository),
                "RESTIC_PASSWORD_FILE": str(password),
            }
            if self.username is not None:
                env.update(
                    RESTIC_REST_USERNAME=self.username, RESTIC_REST_PASSWORD=self.auth_password
                )
            argv = [
                str(self.binary),
                "--json",
                "--cache-dir",
                str(self.state / "cache"),
                "--retry-lock",
                "1s",
            ]
            if self.ca_file:
                argv += ["--cacert", str(self.ca_file)]
            if self.read_only or no_lock:
                argv.append("--no-lock")
            journal = None
            if (
                not no_lock
                and self._job_context is not None
                and args[0]
                in (
                    "backup",
                    "check",
                    "restore",
                    "snapshots",
                    "cat",
                )
            ):
                from ..core.restic_process_journal import ResticProcessJournal

                job_id, repository_id, capture_id = self._job_context
                journal = ResticProcessJournal(
                    self.state, job_id=job_id, repository_id=repository_id, capture_id=capture_id
                )
            observer = None
            stop_observer = threading.Event()

            def started(pid):
                nonlocal observer
                journal.record(pid, operation=args[0])
                observer = threading.Thread(
                    target=self._observe_job_locks,
                    args=(journal, argv, env, stop_observer),
                    daemon=True,
                    name="restic-lock-observer",
                )
                observer.start()

            try:
                options = {"on_start": started} if journal else {}
                result = run_bounded(
                    [*argv, *args],
                    cwd=cwd or self.state,
                    env=env,
                    timeout=(
                        min(self.timeout_s, REPOSITORY_LOOKUP_TIMEOUT_S)
                        if args == ["cat", "config"]
                        else self.timeout_s
                    ),
                    max_bytes=MAX_OUTPUT,
                    **options,
                )
                if observer:
                    stop_observer.set()
                    observer.join(5)
                    if observer.is_alive():
                        raise BackupError("process_identity_unknown")
                if journal:
                    journal.clear_success()
                return result
            except CommandError as exc:
                operation = args[0]
                if operation == "cat":
                    operation = f"cat {args[1]}"
                if exc.exit_code is None:
                    logger.warning("Restic %s failed (%s)", operation, exc.error_class)
                else:
                    logger.warning(
                        "Restic %s failed (%s, exit %d)",
                        operation,
                        exc.error_class,
                        exc.exit_code,
                    )
                if exc.error_class == "unavailable" and exc.exit_code == 11:
                    raise BackupError("repository_locked") from None
                raise BackupError(exc.error_class) from None
            finally:
                if observer and observer.is_alive():
                    stop_observer.set()
                    observer.join(5)

    def _delete_exact_lock(self, lock_id: str) -> None:
        """Delete only an already verified lock ID through the fixed REST endpoint."""
        if self.read_only or re.fullmatch(r"[a-f0-9]{64}", lock_id) is None:
            raise BackupError("policy_denied")
        parsed = urlsplit(self.repository[5:])
        context = ssl.create_default_context(cafile=str(self.ca_file) if self.ca_file else None)
        headers = {"Content-Length": "0"}
        if self.username is not None:
            token = base64.b64encode(f"{self.username}:{self.auth_password}".encode()).decode(
                "ascii"
            )
            headers["Authorization"] = "Basic " + token
        connection = http.client.HTTPSConnection(
            parsed.hostname, parsed.port or 443, timeout=10, context=context
        )
        try:
            connection.request(
                "DELETE", parsed.path.rstrip("/") + "/locks/" + lock_id, headers=headers
            )
            response = connection.getresponse()
            if response.status not in (200, 204, 404):
                raise BackupError("unavailable")
            response.read(65537)
        except (OSError, http.client.HTTPException):
            raise BackupError("unavailable") from None
        finally:
            connection.close()

    def recover_observed_locks(self, *, guard) -> int:
        """Remove only exact locks previously observed on this job's dead child."""
        from ..core.restic_process_journal import recoverable_lock_bindings

        if self.read_only or self._job_context is None:
            raise BackupError("policy_denied")
        job_id, repository_id, capture_id = self._job_context

        def candidates():
            return recoverable_lock_bindings(
                self.state, job_id=job_id, repository_id=repository_id, capture_id=capture_id
            )

        def current_locks():
            try:
                locks = self._run(["list", "locks"], no_lock=True).decode("ascii").splitlines()
            except UnicodeError:
                raise BackupError("invalid_response") from None
            if len(locks) > 4096 or any(
                re.fullmatch(r"[a-f0-9]{64}", item) is None for item in locks
            ):
                raise BackupError("invalid_response")
            return set(locks)

        recovered = 0
        for lock_id, expected, pid in candidates():
            guard()
            config = self._json(self._run(["cat", "config"], no_lock=True))
            if not isinstance(config, dict) or config.get("id") != repository_id:
                raise BackupError("repository_changed")
            if lock_id not in current_locks():
                continue
            try:
                actual = self._json(self._run(["cat", "lock", lock_id], no_lock=True))
            except BackupError as exc:
                # A lock can disappear between listing and reading. Only skip
                # it if a fresh, valid listing confirms that exact ID is gone.
                if exc.error_class == "unavailable" and lock_id not in current_locks():
                    continue
                raise
            canonical = json.dumps(expected, sort_keys=True, separators=(",", ":"))
            if json.dumps(actual, sort_keys=True, separators=(",", ":")) != canonical:
                continue
            # Re-read the complete binding and check absence immediately before mutation.
            if not any(
                item_id == lock_id
                and item_pid == pid
                and json.dumps(item_lock, sort_keys=True, separators=(",", ":")) == canonical
                for item_id, item_lock, item_pid in candidates()
            ):
                continue
            guard()
            self._delete_exact_lock(lock_id)
            if lock_id in current_locks():
                raise BackupError("unavailable")
            recovered += 1
        return recovered

    @staticmethod
    def _json(raw):
        try:
            return json.loads(raw)
        except (ValueError, RecursionError):
            raise BackupError("invalid_response") from None

    def health(self):
        body = self._json(self._run(["version"]))
        if not isinstance(body, dict) or body.get("version") != RESTIC_VERSION:
            raise BackupError("unsupported_version")
        return {"ready": True, "version": RESTIC_VERSION, "network_checked": False}

    def repository_id(self):
        body = self._json(self._run(["cat", "config"]))
        if (
            not isinstance(body, dict)
            or body.get("version") != 2
            or not re.fullmatch(r"[a-f0-9]{64}", str(body.get("id")))
        ):
            raise BackupError("invalid_response")
        return body["id"]

    def initialize(self):
        """Explicit only; a failed lookup never auto-initializes a new target."""
        self.health()
        self._run(["init", "--repository-version", "2"])
        return {"repository_id": self.repository_id()}

    @staticmethod
    def _tags(capture):
        return [f"steward.project={capture.binding.project}", f"steward.capture={capture.id}"]

    def _snapshot(self, snapshot_id, capture):
        body = self._json(self._run(["cat", "snapshot", snapshot_id]))
        if not isinstance(body, dict):
            raise BackupError("invalid_response")
        paths = body.get("paths", [])
        if (
            not isinstance(paths, list)
            or len(paths) != 1
            or not isinstance(paths[0], str)
            or len(paths[0]) > 4096
            or not PurePosixPath(paths[0]).is_absolute()
            or ".." in PurePosixPath(paths[0]).parts
            or any(ord(c) < 32 for c in paths[0])
            or body.get("hostname") != "steward"
            or not set(self._tags(capture)).issubset(body.get("tags", []))
        ):
            raise BackupError("evidence_mismatch")
        try:
            created = datetime.fromisoformat(body["time"].replace("Z", "+00:00"))
            if created.tzinfo is None or created.timestamp() < 0:
                raise ValueError("invalid snapshot date")
        except (ValueError, KeyError, TypeError, AttributeError):
            raise BackupError("invalid_response") from None
        return paths[0], created.timestamp()

    def backup(self, capture: Path):
        capture = capture.resolve()
        if self.state == capture or self.state.is_relative_to(capture):
            raise BackupError("invalid_input")
        self.health()
        manifest = load_capture(capture)
        repository = self.repository_id()
        tag = self._tags(manifest)[1]
        existing = self._json(
            self._run(
                [
                    "snapshots",
                    "--tag",
                    tag,
                    "--host",
                    "steward",
                    "--latest",
                    "1",
                ]
            )
        )
        if not isinstance(existing, list) or len(existing) > 1:
            raise BackupError("invalid_response")
        if existing and not isinstance(existing[0], dict):
            raise BackupError("invalid_response")
        snapshot_id = existing[0].get("id") if existing else None
        if existing and (
            not isinstance(existing[0], dict)
            or not isinstance(snapshot_id, str)
            or not re.fullmatch(r"[a-f0-9]{64}", snapshot_id)
        ):
            raise BackupError("invalid_response")
        if not snapshot_id:
            args = ["backup", "--host", "steward"]
            for value in self._tags(manifest):
                args += ["--tag", value]
            # Absolute source paths preserve the same path in the snapshot tree
            # and native header, allowing an exact snapshot:path restore.
            raw = self._run([*args, str(capture)], cwd=capture)
            try:
                messages = [json.loads(line) for line in raw.splitlines() if line]
                summaries = [m for m in messages if m.get("message_type") == "summary"]
                if len(summaries) != 1 or any(
                    m.get("message_type") in ("error", "exit_error") for m in messages
                ):
                    raise ValueError("incomplete backup")
                snapshot_id = summaries[0]["snapshot_id"]
            except (ValueError, KeyError, TypeError, AttributeError):
                raise BackupError("invalid_response") from None
        if not isinstance(snapshot_id, str) or not re.fullmatch(r"[a-f0-9]{64}", snapshot_id):
            raise BackupError("invalid_response")
        path, created_at = self._snapshot(snapshot_id, manifest)
        if load_capture(capture).id != manifest.id:
            raise BackupError("source_changed")
        return Receipt(
            capture=manifest,
            repository_id=repository,
            snapshot_id=snapshot_id,
            snapshot_path=path,
            snapshot_created_at=created_at,
            recorded_at=time.time(),
        )

    def _verify_binding(self, receipt):
        if self.repository_id() != receipt.repository_id or self._snapshot(
            receipt.snapshot_id, receipt.capture
        ) != (receipt.snapshot_path, receipt.snapshot_created_at):
            raise BackupError("evidence_mismatch")

    def check(self, receipt):
        self.health()
        self._verify_binding(receipt)
        raw = self._run(["check", "--read-data"])
        try:
            rows = [json.loads(line) for line in raw.splitlines() if line]
            summaries = [r for r in rows if r.get("message_type") == "summary"]
            if (
                len(summaries) != 1
                or summaries[0].get("num_errors", 0) != 0
                or any(r.get("message_type") in ("error", "exit_error") for r in rows)
            ):
                raise ValueError("repository integrity not proved")
        except (ValueError, TypeError, AttributeError):
            raise BackupError("integrity_failed") from None
        return receipt.model_copy(update={"integrity_checked_at": time.time()})

    @contextmanager
    def restored_capture(self, receipt: Receipt):
        """Yield an exact, verified snapshot in a private disposable directory.

        Repository, snapshot tags and manifest must all match the supplied
        receipt. No caller-selected restore destination or production data is
        involved; the directory is removed even if its consumer fails.
        """
        self.health()
        self._verify_binding(receipt)
        with tempfile.TemporaryDirectory(prefix="restore-test-", dir=self.state) as directory:
            target = Path(directory)
            self._run(
                [
                    "restore",
                    receipt.snapshot_id + ":" + receipt.snapshot_path,
                    "--target",
                    str(target),
                    "--verify",
                ]
            )
            restored = load_capture(target)
            if restored != receipt.capture:
                raise BackupError("evidence_mismatch")
            if not isinstance(restored, FilesystemCapture):
                database_check(target / restored.filename)
            yield target, restored

    @contextmanager
    def restored_tree(self, receipt: Receipt):
        """Yield a completely revalidated file tree in a private temporary area."""
        from ..core.filebackups import materialize_tree

        with self.restored_capture(receipt) as (capture, manifest):
            if not isinstance(manifest, FilesystemCapture):
                raise BackupError("invalid_input")
            with tempfile.TemporaryDirectory(prefix="restore-tree-", dir=self.state) as directory:
                data = materialize_tree(capture / manifest.filename, manifest, Path(directory))
                yield data, manifest

    def restore_test(self, receipt):
        with self.restored_capture(receipt):
            pass
        return receipt.model_copy(update={"restore_verified_at": time.time()})
