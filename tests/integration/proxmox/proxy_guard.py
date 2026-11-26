"""Root-side ownership and crash-safe lifecycle guard for one test proxy."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

FILES = frozenset({"proxy.py", "certificate.pem", "key.pem", "upstream-ca.pem", "reader", "writer"})
MAX_FILE = 1024 * 1024


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def rename_no_replace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.renameat2
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if function(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path: Path, body: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(os.dup(fd), "wb") as handle:
            handle.write(body)
            handle.flush()
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def read_owned(path: Path, *, uid: int, modes: tuple[int, ...], limit: int = MAX_FILE) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != uid
            or stat.S_IMODE(before.st_mode) not in modes
            or before.st_nlink != 1
            or before.st_size > limit
        ):
            raise ValueError("unsafe fixture file")
        with os.fdopen(os.dup(fd), "rb") as handle:
            data = handle.read(limit + 1)
        after = os.fstat(fd)
        if len(data) > limit or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("fixture file changed")
        return data
    finally:
        os.close(fd)


def safe_dir(path: Path, *, uid: int, modes: tuple[int, ...]) -> None:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) not in modes
    ):
        raise ValueError("unsafe fixture directory")


def credential_password(value: bytes) -> bytes:
    if value.count(b":") != 1:
        raise ValueError("invalid fixture credential")
    user, password = value.split(b":", 1)
    if (
        not re.fullmatch(rb"[A-Za-z0-9_-]{1,64}", user)
        or not 32 <= len(password) <= 512
        or any(byte < 33 or byte > 126 for byte in password)
    ):
        raise ValueError("invalid fixture credential")
    return password


def unit_content(root: Path, port: int, upstream_port: int) -> bytes:
    return f"""[Unit]
Description=Disposable Steward read-only Restic fixture proxy
[Service]
Type=simple
DynamicUser=yes
LoadCredential=certificate:{root}/certificate.pem
LoadCredential=key:{root}/key.pem
LoadCredential=upstream-ca:{root}/upstream-ca.pem
LoadCredential=reader:{root}/reader
LoadCredential=writer:{root}/writer
ExecStart=/usr/bin/python3 {root}/proxy.py --port {port} --upstream-port {upstream_port} --ca %d/upstream-ca --certificate %d/certificate --key %d/key --reader-credential %d/reader --writer-credential %d/writer
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_UNIX
KillMode=control-group
UMask=0077
MemoryMax=256M
TasksMax=64
LimitNOFILE=1024
RuntimeMaxSec=7200
StandardOutput=null
StandardError=journal
""".encode()


class Guard:
    def __init__(
        self,
        payload,
        *,
        opt=Path("/opt"),
        units=Path("/etc/systemd/system"),
        cgroups=Path("/sys/fs/cgroup"),
        uid=0,
        command=None,
    ):
        self.p = payload
        self.name, self.token = payload["namespace"], payload["token"]
        self.port, self.upstream_port = payload["port"], payload["upstream_port"]
        if (
            not re.fullmatch(r"stw-read-test-[0-9a-f]{24}", self.name)
            or not re.fullmatch(r"[0-9a-f]{64}", self.token)
            or type(self.port) is not int
            or type(self.upstream_port) is not int
            or not 1024 <= self.port <= 65535
            or not 1024 <= self.upstream_port <= 65535
            or self.port == self.upstream_port
        ):
            raise ValueError("invalid fixture scope")
        self.opt, self.units, self.cgroups, self.uid = opt, units, cgroups, uid
        self.root = opt / self.name
        self.unit = units / (self.name + ".service")
        suffix = digest((self.name + ":" + self.token).encode())[:32]
        self.stage = opt / (".stw-read-stage-" + suffix)
        self.unit_stage = units / (".stw-read-unit-" + suffix)
        self.command = command or self._command

    @staticmethod
    def _command(args, *, check=True):
        return subprocess.run(args, capture_output=True, text=True, check=check, timeout=30)

    def _read(self, path, modes=(0o600,), limit=MAX_FILE):
        return read_owned(path, uid=self.uid, modes=modes, limit=limit)

    def _upstream(self):
        name = self.p["upstream_namespace"]
        if not re.fullmatch(r"stw-rest-test-[0-9a-f]{24}", name):
            raise ValueError("invalid upstream scope")
        root = self.opt / name
        safe_dir(root, uid=self.uid, modes=(0o711,))
        marker = json.loads(self._read(root / "ownership.json", limit=16384))
        unit = self.units / (name + ".service")
        if (
            not hmac.compare_digest(marker["token"], self.p["upstream_token"])
            or marker["namespace"] != name
            or marker["port"] != self.upstream_port
            or digest(self._read(unit, modes=(0o644,), limit=65536)) != marker["unit_sha256"]
            or digest(self._read(root / "rest-server", modes=(0o755,), limit=128 * 1024 * 1024))
            != marker["binary_sha256"]
        ):
            raise ValueError("upstream ownership mismatch")
        fields = "Id,LoadState,ActiveState,SubState,MainPID,FragmentPath,NeedDaemonReload"
        result = self.command(["systemctl", "show", name + ".service", "--property=" + fields])
        info = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        pid = info.get("MainPID", "")
        if (
            info.get("Id") != name + ".service"
            or info.get("LoadState") != "loaded"
            or info.get("ActiveState") != "active"
            or info.get("SubState") != "running"
            or info.get("FragmentPath") != str(unit)
            or info.get("NeedDaemonReload") != "no"
            or not pid.isascii()
            or not pid.isdigit()
            or int(pid) < 1
        ):
            raise ValueError("upstream service identity mismatch")

    def _show(self):
        fields = "Id,LoadState,ActiveState,SubState,MainPID,ControlGroup,KillMode,FragmentPath,NeedDaemonReload"
        result = self.command(["systemctl", "show", self.name + ".service", "--property=" + fields])
        entries = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if entries.get("Id") != self.name + ".service":
            raise ValueError("service identity unavailable")
        return entries

    def _active(self):
        info = self._show()
        pid = info.get("MainPID", "")
        group = info.get("ControlGroup", "")
        if (
            info.get("LoadState") != "loaded"
            or info.get("ActiveState") != "active"
            or info.get("SubState") != "running"
            or info.get("FragmentPath") != str(self.unit)
            or info.get("NeedDaemonReload") != "no"
            or info.get("KillMode") != "control-group"
            or not pid.isascii()
            or not pid.isdigit()
            or int(pid) < 1
            or not re.fullmatch(r"/[A-Za-z0-9_./:@-]+", group)
            or ".." in group.split("/")
        ):
            raise ValueError("active proxy identity unavailable")

    def _quiescent(self, *, unit_present, started, stopped):
        info = self._show()
        if "ControlGroup" not in info:
            raise ValueError("service cgroup identity unavailable")
        if (
            info.get("ActiveState") not in ("inactive", "failed")
            or info.get("SubState") not in ("dead", "failed")
            or info.get("MainPID") != "0"
            or info.get("KillMode") != "control-group"
        ):
            raise ValueError("service quiescence not established")
        if info.get("LoadState") == "loaded":
            if (
                (not unit_present and not stopped)
                or info.get("FragmentPath") != str(self.unit)
                or (unit_present and info.get("NeedDaemonReload") != "no")
                or (not unit_present and info.get("NeedDaemonReload") not in ("yes", "no"))
            ):
                raise ValueError("loaded service identity mismatch")
        elif info.get("LoadState") == "not-found":
            if started and not stopped:
                raise ValueError("prior service stop is unproven")
            if info.get("FragmentPath"):
                raise ValueError("unexpected service fragment")
        else:
            raise ValueError("service load state unavailable")
        group = info.get("ControlGroup", "")
        if group:
            if not re.fullmatch(r"/[A-Za-z0-9_./:@-]+", group) or ".." in group.split("/"):
                raise ValueError("unsafe cgroup path")
            path = self.cgroups / group.lstrip("/")
            try:
                cgroup_info = os.stat(path, follow_symlinks=False)
            except FileNotFoundError:
                pass  # kernel removed the cgroup after all processes exited
            else:
                if not stat.S_ISDIR(cgroup_info.st_mode):
                    raise ValueError("unsafe service cgroup")
                fd = os.open(path / "cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    raw = os.read(fd, 4097)
                finally:
                    os.close(fd)
                if len(raw) > 4096:
                    raise ValueError("invalid service cgroup evidence")
                events = dict(line.split() for line in raw.decode("ascii").splitlines())
                if events.get("populated") != "0":
                    raise ValueError("service cgroup is not empty")
        return info

    def _expected_state(self):
        file_hashes = self.p.get("file_sha256")
        if (
            not isinstance(file_hashes, dict)
            or set(file_hashes) != FILES
            or any(
                not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value)
                for value in file_hashes.values()
            )
        ):
            raise ValueError("invalid fixture file hashes")
        return {
            "namespace": self.name,
            "token": self.token,
            "port": self.port,
            "upstream_port": self.upstream_port,
            "unit_sha256": digest(unit_content(self.root, self.port, self.upstream_port)),
            "files": file_hashes,
        }

    def _state(self):
        safe_dir(self.root, uid=self.uid, modes=(0o700, 0o711))
        state = json.loads(self._read(self.root / "ownership.json", limit=16384))
        if state != self._expected_state():
            raise ValueError("proxy ownership mismatch")
        allowed = FILES | {
            "ownership.json",
            "started",
            "stopped",
            ".started-staging",
            ".stopped-staging",
        }
        if set(entry.name for entry in self.root.iterdir()) - allowed:
            raise ValueError("unexpected proxy files")
        present = set()
        for name, expected in state["files"].items():
            path = self.root / name
            if path.exists() or path.is_symlink():
                if (
                    digest(self._read(path, modes=(0o755,) if name == "proxy.py" else (0o600,)))
                    != expected
                ):
                    raise ValueError("proxy file changed")
                present.add(name)
        for name in ("started", "stopped"):
            path = self.root / name
            if (path.exists() or path.is_symlink()) and self._read(path, limit=256) != (
                name + ":" + self.token
            ).encode():
                raise ValueError("proxy lifecycle marker mismatch")
        for name in (".started-staging", ".stopped-staging"):
            path = self.root / name
            if path.exists() or path.is_symlink():
                self._read(path, limit=256)
        return state, present

    def _write_marker(self, name):
        temporary = self.root / ("." + name + "-staging")
        write_new(temporary, (name + ":" + self.token).encode(), 0o600)
        rename_no_replace(temporary, self.root / name)
        sync_directory(self.root)

    def start(self):
        self._upstream()
        if any(
            path.exists() or path.is_symlink()
            for path in (self.root, self.unit, self.stage, self.unit_stage)
        ):
            raise ValueError("fixture namespace occupied")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", self.port))
        files = {
            name: base64.b64decode(body, validate=True) for name, body in self.p["files"].items()
        }
        if set(files) != FILES or any(len(body) > MAX_FILE for body in files.values()):
            raise ValueError("invalid fixture files")
        if digest(files["proxy.py"]) != self.p["proxy_sha256"]:
            raise ValueError("proxy source mismatch")
        if {name: digest(body) for name, body in files.items()} != self._expected_state()["files"]:
            raise ValueError("fixture file hashes do not match")
        if hmac.compare_digest(
            credential_password(files["reader"]), credential_password(files["writer"])
        ):
            raise ValueError("separate fixture credentials required")
        content = unit_content(self.root, self.port, self.upstream_port)
        state = self._expected_state()
        self.stage.mkdir(mode=0o700)
        write_new(self.stage / "ownership.json", json.dumps(state).encode(), 0o600)
        sync_directory(self.stage)
        for name, body in files.items():
            write_new(self.stage / name, body, 0o755 if name == "proxy.py" else 0o600)
        sync_directory(self.stage)
        rename_no_replace(self.stage, self.root)
        sync_directory(self.opt)
        os.chmod(self.root, 0o711, follow_symlinks=False)  # noqa: S103 - traverse-only for DynamicUser
        sync_directory(self.root)
        write_new(self.unit_stage, content, 0o644)
        rename_no_replace(self.unit_stage, self.unit)
        sync_directory(self.units)
        self.command(["systemctl", "daemon-reload"])
        self._quiescent(unit_present=True, started=False, stopped=False)
        self._write_marker("started")
        self.command(["systemctl", "start", self.name + ".service"])
        for attempt in range(50):
            try:
                probe = self.probe()
                break
            except (OSError, urllib.error.URLError):
                if attempt == 49:
                    raise
                time.sleep(0.1)
        self._active()
        return {"namespace": self.name, "active": "active", "probe": probe}

    def probe(self):
        context = ssl.create_default_context(cafile=str(self.root / "certificate.pem"))
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
        )
        reader = base64.b64encode(self._read(self.root / "reader")).decode()
        url = f"https://127.0.0.1:{self.port}/fixture/fixture/config"
        statuses = []
        for method, auth in (("GET", False), ("GET", True), ("POST", True)):
            request = urllib.request.Request(
                url, method=method, data=b"x" if method == "POST" else None
            )
            if auth:
                request.add_header("Authorization", "Basic " + reader)
            try:
                with opener.open(request, timeout=5) as response:
                    statuses.append(response.status)
            except urllib.error.HTTPError as exc:
                statuses.append(exc.code)
        if statuses[0] != 401 or statuses[1] not in (200, 404) or statuses[2] != 405:
            raise ValueError("proxy fixture probe failed")
        return {
            "unauthenticated": statuses[0],
            "authenticated_read": statuses[1],
            "write_refused": statuses[2],
        }

    def status(self):
        state, present = self._state()
        if (
            present != FILES
            or not (self.root / "started").exists()
            or self.unit_stage.exists()
            or self.unit_stage.is_symlink()
            or any(
                (self.root / name).exists()
                for name in (".started-staging", ".stopped-staging", "stopped")
            )
            or digest(self._read(self.unit, modes=(0o644,), limit=65536)) != state["unit_sha256"]
        ):
            raise ValueError("proxy fixture incomplete")
        self._active()
        return {"namespace": self.name, "active": "active", "probe": self.probe()}

    def cleanup(self):
        if self.stage.exists() or self.stage.is_symlink():
            if (
                self.root.exists()
                or self.root.is_symlink()
                or self.unit.exists()
                or self.unit.is_symlink()
                or self.unit_stage.exists()
                or self.unit_stage.is_symlink()
            ):
                raise ValueError("ambiguous fixture staging")
            safe_dir(self.stage, uid=self.uid, modes=(0o700,))
            self._quiescent(unit_present=False, started=False, stopped=False)
            allowed = FILES | {"ownership.json"}
            entries = list(self.stage.iterdir())
            if any(entry.name not in allowed for entry in entries):
                raise ValueError("unexpected staging file")
            marker = self.stage / "ownership.json"
            if not marker.exists() and any(entry.name != "ownership.json" for entry in entries):
                raise ValueError("staging marker missing")
            for entry in entries:
                body = self._read(entry, modes=(0o600, 0o755))
                if entry.name == "ownership.json":
                    expected = json.dumps(self._expected_state()).encode()
                    if not expected.startswith(body):
                        raise ValueError("staged ownership mismatch")
                    if len(body) < len(expected) and len(entries) != 1:
                        raise ValueError("incomplete staging marker with additional files")
            for entry in entries:
                if entry.name == "ownership.json":
                    continue
                entry.unlink()
            sync_directory(self.stage)
            if marker.exists():
                marker.unlink()
                sync_directory(self.stage)
            self.stage.rmdir()
            sync_directory(self.opt)
            return {"namespace": self.name, "staged_files_removed": True}
        state, present = self._state()
        unit_present = self.unit.exists() or self.unit.is_symlink()
        if (
            unit_present
            and digest(self._read(self.unit, modes=(0o644,), limit=65536)) != state["unit_sha256"]
        ):
            raise ValueError("proxy unit changed")
        if self.unit_stage.exists() or self.unit_stage.is_symlink():
            self._read(self.unit_stage, modes=(0o600, 0o644), limit=65536)
        started = (self.root / "started").exists()
        stopped = (self.root / "stopped").exists()
        if unit_present and started and not stopped:
            info = self._show()
            if (
                info.get("LoadState") != "loaded"
                or info.get("FragmentPath") != str(self.unit)
                or info.get("NeedDaemonReload") != "no"
                or info.get("KillMode") != "control-group"
                or "ControlGroup" not in info
            ):
                raise ValueError("loaded service identity mismatch")
            self.command(["systemctl", "stop", self.name + ".service"])
        info = self._quiescent(unit_present=unit_present, started=started, stopped=stopped)
        if not unit_present and info["LoadState"] == "loaded":
            self.command(["systemctl", "daemon-reload"])
            info = self._quiescent(unit_present=False, started=started, stopped=stopped)
            if info["LoadState"] != "not-found":
                raise ValueError("removed service remains loaded")
        if started and not stopped:
            temporary = self.root / ".stopped-staging"
            if temporary.exists():
                temporary.unlink()
                sync_directory(self.root)
            self._write_marker("stopped")
        if unit_present:
            self.unit.unlink()
            sync_directory(self.units)
            self.command(["systemctl", "daemon-reload"])
        if self.unit_stage.exists():
            self.unit_stage.unlink()
            sync_directory(self.units)
        for name in (".started-staging", ".stopped-staging"):
            temporary = self.root / name
            if temporary.exists():
                temporary.unlink()
        for name in ("key.pem", "reader", "writer"):
            if name in present:
                (self.root / name).unlink()
        sync_directory(self.root)
        return {"namespace": self.name, "stopped": True, "credentials_removed": True}


def main():
    payload = json.load(sys.stdin)
    guard = Guard(payload)
    action = payload["action"]
    if action not in ("start", "status", "cleanup"):
        raise ValueError("invalid action")
    print(json.dumps(getattr(guard, action)()))


if __name__ == "__main__":
    main()
