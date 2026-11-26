"""Durable identity records for Restic children started by backup jobs.

Records alone never authorize deletion of a repository lock.
"""

import json
import os
import re
import socket
import stat
import time
import uuid
from datetime import datetime
from pathlib import Path

from .backupexport import acl_attributes, sync_directory
from .backups import BackupError

MAX_RECORDS = 4096


def process_start_ticks(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    end = raw.rfind(")")
    fields = raw[end + 1 :].split() if end >= 0 else []
    if len(fields) < 20 or not fields[19].isascii() or not fields[19].isdecimal():
        raise BackupError("process_identity_unknown")
    return int(fields[19])


class ResticProcessJournal:
    def __init__(self, state: Path, *, job_id: str, repository_id: str, capture_id: str):
        if not (
            re.fullmatch(r"[a-f0-9]{32}", job_id)
            and re.fullmatch(r"[a-f0-9]{64}", repository_id)
            and re.fullmatch(r"[a-f0-9]{64}", capture_id)
        ):
            raise BackupError("invalid_input")
        self.state = state
        self.job_id, self.repository_id, self.capture_id = job_id, repository_id, capture_id
        self.path: Path | None = None
        self.inode: tuple[int, int] | None = None
        self.recorded: dict | None = None

    def record(self, pid: int, *, operation: str) -> None:
        if self.path is not None or type(pid) is not int or pid < 1:
            raise BackupError("process_identity_unknown")
        if operation not in ("backup", "check", "restore", "snapshots", "cat"):
            raise BackupError("invalid_input")
        try:
            boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
            host = socket.gethostname()
            if not re.fullmatch(r"[a-f0-9-]{36}", boot) or not 1 <= len(host) <= 253:
                raise BackupError("process_identity_unknown")
            directory = self.state / "process-journal"
            directory.mkdir(mode=0o700, exist_ok=True)
            info = directory.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or acl_attributes(directory)
            ):
                raise BackupError("unsafe_state")
            with os.scandir(directory) as entries:
                if sum(1 for _ in entries) >= MAX_RECORDS:
                    raise BackupError("process_journal_full")
            record = {
                "v": 1,
                "job_id": self.job_id,
                "repository_id": self.repository_id,
                "capture_id": self.capture_id,
                "pid": pid,
                "uid": os.geteuid(),
                "gid": os.getegid(),
                "boot_id": boot,
                "host": host,
                "start_ticks": process_start_ticks(pid),
                "created_ns": time.time_ns(),
                "operation": operation,
            }
            path = directory / (uuid.uuid4().hex + ".json")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            self.path = path
            try:
                info = os.fstat(fd)
                self.inode = (info.st_dev, info.st_ino)
                with os.fdopen(fd, "w", encoding="ascii") as handle:
                    json.dump(record, handle, sort_keys=True, separators=(",", ":"))
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                # Keep any incomplete record for fail-closed investigation.
                raise
            sync_directory(directory)
            self.recorded = record
        except (OSError, UnicodeError):
            raise BackupError("process_identity_unknown") from None

    def process_is_live(self) -> bool:
        """Reject reused, missing and zombie PIDs; uncertainty is not liveness."""
        if self.recorded is None:
            return False
        try:
            pid = self.recorded["pid"]
            raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
            end = raw.rfind(")")
            fields = raw[end + 1 :].split() if end >= 0 else []
            return (
                len(fields) >= 20
                and fields[0] not in ("Z", "X", "x")
                and fields[19].isascii()
                and fields[19].isdecimal()
                and int(fields[19]) == self.recorded["start_ticks"]
            )
        except (OSError, UnicodeError, KeyError, ValueError):
            return False

    def bind_observed_lock(self, lock_id: str, lock: dict) -> bool:
        """Persist a specific lock only while its exact creating process is alive.

        This evidence by itself does not authorize deletion.
        """
        if (
            self.recorded is None
            or self.path is None
            or not isinstance(lock_id, str)
            or not re.fullmatch(r"[a-f0-9]{64}", lock_id)
            or not isinstance(lock, dict)
            or not self.process_is_live()
        ):
            return False
        record = self.recorded
        try:
            created = datetime.fromisoformat(lock["time"].replace("Z", "+00:00"))
            if (
                created.tzinfo is None
                or created.timestamp() * 1_000_000_000 < record["created_ns"] - 1_000_000
                or created.timestamp() * 1_000_000_000 > time.time_ns() + 1_000_000_000
                or type(lock.get("pid")) is not int
                or lock["pid"] != record["pid"]
                or type(lock.get("uid")) is not int
                or lock["uid"] != record["uid"]
                or type(lock.get("gid")) is not int
                or lock["gid"] != record["gid"]
                or lock.get("hostname") != record["host"]
                or type(lock.get("exclusive")) is not bool
                or not self.process_is_live()
            ):
                return False
            with os.scandir(self.path.parent) as entries:
                if sum(1 for _ in entries) >= MAX_RECORDS:
                    return False
            path = self.path.with_name(self.path.stem + "-" + lock_id + ".lock")
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                return False
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                json.dump(
                    {"v": 1, "lock_id": lock_id, "process_record": self.path.name, "lock": lock},
                    handle,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                handle.flush()
                os.fsync(handle.fileno())
            sync_directory(path.parent)
            return True
        except (OSError, ValueError, TypeError, AttributeError, KeyError, OverflowError):
            return False

    def clear_success(self) -> None:
        if self.path is None or self.inode is None:
            raise BackupError("process_identity_unknown")
        try:
            info = self.path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or (info.st_dev, info.st_ino) != self.inode
                or info.st_nlink != 1
            ):
                raise BackupError("unsafe_state")
            prefix = self.path.stem + "-"
            with os.scandir(self.path.parent) as entries:
                bindings = [
                    Path(entry.path)
                    for entry in entries
                    if re.fullmatch(re.escape(prefix) + r"[a-f0-9]{64}\.lock", entry.name)
                ]
            for binding in bindings:
                item = binding.lstat()
                if (
                    not stat.S_ISREG(item.st_mode)
                    or item.st_uid != os.geteuid()
                    or item.st_nlink != 1
                ):
                    raise BackupError("unsafe_state")
                binding.unlink()
            self.path.unlink()
            sync_directory(self.path.parent)
            self.path = None
        except OSError:
            raise BackupError("process_identity_unknown") from None


def recoverable_lock_bindings(state: Path, *, job_id: str, repository_id: str, capture_id: str):
    """Read exact, locally observed locks whose original process is absent.

    Inaccessible state, other boots and even reused live PIDs fail closed. The
    result is only a candidate; the remote repository must be checked again.
    """
    from .backups import regular_file

    context = ResticProcessJournal(
        state, job_id=job_id, repository_id=repository_id, capture_id=capture_id
    )
    directory = state / "process-journal"
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return []
    try:
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or acl_attributes(directory)
        ):
            raise BackupError("unsafe_state")
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        host = socket.gethostname()
        with os.scandir(directory) as iterator:
            entries = []
            for entry in iterator:
                entries.append(entry.name)
                if len(entries) > MAX_RECORDS:
                    raise BackupError("process_journal_full")

        def load(name):
            fd, before = regular_file(directory / name, limit=65536)
            with os.fdopen(fd, "r", encoding="ascii") as handle:
                if (
                    before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_nlink != 1
                    or acl_attributes(directory / name)
                ):
                    raise BackupError("unsafe_state")
                value = json.load(handle)
                after = os.fstat(handle.fileno())
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                ):
                    raise BackupError("unsafe_state")
                return value

        candidates = []
        for name in sorted(entries):
            match = re.fullmatch(r"([a-f0-9]{32})-([a-f0-9]{64})\.lock", name)
            if match is None:
                continue
            parent_name, lock_id = match.group(1) + ".json", match.group(2)
            binding = load(name)
            record = load(parent_name)
            if not isinstance(binding, dict) or not isinstance(record, dict):
                raise BackupError("unsafe_state")
            if (
                type(binding.get("v")) is not int
                or binding["v"] != 1
                or binding.get("lock_id") != lock_id
                or binding.get("process_record") != parent_name
            ):
                raise BackupError("unsafe_state")
            if (
                record.get("job_id") != context.job_id
                or record.get("repository_id") != context.repository_id
                or record.get("capture_id") != context.capture_id
            ):
                continue
            lock = binding.get("lock")
            pid = record.get("pid")
            if (
                type(record.get("v")) is not int
                or record["v"] != 1
                or record.get("operation") not in ("backup", "check", "restore", "snapshots", "cat")
                or record.get("boot_id") != boot
                or record.get("host") != host
                or type(record.get("uid")) is not int
                or record["uid"] != os.geteuid()
                or type(record.get("gid")) is not int
                or record["gid"] != os.getegid()
                or type(pid) is not int
                or pid < 2
                or type(record.get("start_ticks")) is not int
                or record["start_ticks"] < 1
                or type(record.get("created_ns")) is not int
                or not 0 < record["created_ns"] <= time.time_ns() + 1_000_000_000
                or not isinstance(lock, dict)
                or type(lock.get("pid")) is not int
                or lock["pid"] != pid
                or type(lock.get("uid")) is not int
                or lock["uid"] != record["uid"]
                or type(lock.get("gid")) is not int
                or lock["gid"] != record["gid"]
                or lock.get("hostname") != host
                or type(lock.get("exclusive")) is not bool
            ):
                continue
            created = datetime.fromisoformat(lock["time"].replace("Z", "+00:00"))
            if (
                created.tzinfo is None
                or created.timestamp() * 1_000_000_000 < record["created_ns"] - 1_000_000
                or created.timestamp() * 1_000_000_000 > time.time_ns() + 1_000_000_000
            ):
                continue
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pass
            else:
                continue  # Existing or reused PID; never guess whether it is safe.
            candidates.append((lock_id, lock, pid))
            if len(candidates) > 8:
                raise BackupError("process_journal_full")
        return candidates
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise BackupError("process_identity_unknown") from None
