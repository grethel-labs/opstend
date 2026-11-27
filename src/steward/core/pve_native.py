"""Read-only readiness and installation preview for the first native PVE profile."""

import http.client
import io
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import stat
import subprocess
import time
from pathlib import Path

PROFILE = "pve-native/v1"
MODES = ("standalone", "agent")
PVE_RELEASE = "9.3"
PVE_VERSION = "9.3.1"
API_HOST = "127.0.0.1"
API_PORT = 8006
UI_HOST = "127.0.0.1"
UI_PORT = 8447
_PATHS = {
    "install": "/opt/opstend-pve",
    "config": "/etc/opstend-pve",
    "state": "/var/lib/opstend-pve",
}
_AGENT = "opstend-pve-agent"
_UI = "opstend-pve-ui"
_LEGACY_PATHS = ("/opt/steward", "/etc/steward", "/var/lib/steward")
_UNIT_DIR = Path("/etc/systemd/system")
_MIN_MEMORY_KIB = 256 * 1024
_MIN_DISK = 1024**3
_TIMEOUT = 5
_API_VERSION = "/api2/json/version"
_MAX_RESPONSE = 64 * 1024
_TOKEN = re.compile(
    r"([A-Za-z0-9_.+%-]+)@([A-Za-z][A-Za-z0-9_.-]*)!"
    r"[A-Za-z][A-Za-z0-9_.-]*=[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"
)
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


class PreflightError(ValueError):
    """An invalid operator input to the native profile."""


def _finding(ok: bool, detail: str) -> dict:
    return {"ok": ok, "detail": detail}


def install_plan(mode: str) -> dict:
    if mode not in MODES:
        raise PreflightError("Choose standalone or agent mode.")
    standalone = mode == "standalone"
    return {
        "profile": PROFILE,
        "mode": mode,
        "artifact": "signed-isolated-bundle",
        "paths": _PATHS.copy(),
        "services": [
            {
                "user": name,
                "unit": f"{name}.service",
                "path": str(_UNIT_DIR / f"{name}.service"),
            }
            for name in ((_AGENT, _UI) if standalone else (_AGENT,))
        ],
        "listeners": [{"host": UI_HOST, "port": UI_PORT}] if standalone else [],
        "api": {"host": API_HOST, "port": API_PORT},
    }


def _validate_api_name(name: str) -> None:
    if "%" not in name:
        try:
            ipaddress.ip_address(name)
        except ValueError:
            if len(name) <= 253 and all(_DNS_LABEL.fullmatch(label) for label in name.split(".")):
                return
        else:
            return
    raise PreflightError("The API certificate identity must be a DNS name or IP address.")


def _read_file(path: Path, limit: int, *, private: bool = False) -> bytes:
    # O_NONBLOCK makes opening a substituted FIFO safe before the descriptor check.
    flags = os.O_RDONLY | os.O_NONBLOCK
    if private:
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Expected a regular file.")
        if private and (metadata.st_mode & 0o077 or metadata.st_uid not in (0, os.geteuid())):
            raise ValueError("Expected a private token file.")
        contents = handle.read(limit + 1)
    if not contents or len(contents) > limit:
        raise ValueError("Unexpected file size.")
    return contents


def _load_token(path: Path) -> str:
    try:
        token = _read_file(path, 1024, private=True).decode("ascii").removesuffix("\n")
    except (OSError, ValueError):
        raise PreflightError("Use a private, readable regular PVE token file.") from None
    match = _TOKEN.fullmatch(token)
    if match is None or tuple(part.lower() for part in match.groups()) == ("root", "pam"):
        raise PreflightError("Use a full PVE token with a UUID secret and a non-root@pam identity.")
    return token


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        encoding="utf-8",
        timeout=_TIMEOUT,
        env={"LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        check=False,
    )


def _host() -> dict:
    machine = platform.uname()
    if machine.system != "Linux" or machine.machine != "x86_64":
        return _finding(False, "Requires Linux x86_64.")
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        return _finding(False, "Could not read the operating system release.")
    supported = release.get("ID") == "debian" and release.get("VERSION_ID") == "13"
    return _finding(supported, "Debian 13 on Linux x86_64." if supported else "Requires Debian 13.")


_DPKG_FORMAT = "${db:Status-Status}\t${binary:Package}\t${Architecture}\t${Version}\n"


def _package() -> dict:
    result = _run(["/usr/bin/dpkg-query", "--show", f"--showformat={_DPKG_FORMAT}", "pve-manager"])
    # pve-manager is architecture-independent. The host check verifies x86_64.
    expected = f"installed\tpve-manager\tall\t{PVE_VERSION}"
    supported = result.returncode == 0 and result.stdout.strip() == expected
    return _finding(
        supported,
        f"Installed pve-manager {PVE_VERSION} verified."
        if supported
        else f"Requires installed pve-manager {PVE_VERSION}.",
    )


def _resources() -> dict:
    cpus = os.cpu_count()
    with Path("/proc/meminfo").open(encoding="ascii") as handle:
        memory = next((line for line in handle if line.startswith("MemAvailable:")), "")
    if not (match := re.fullmatch(r"MemAvailable:\s+(\d+)\s+kB\s*", memory)):
        raise ValueError("Could not read available memory.")
    available_kib = int(match[1])
    parents = [Path(_PATHS[key]).parent for key in ("install", "state")]
    devices = [parent.stat().st_dev for parent in parents]
    filesystems = [os.statvfs(parent) for parent in parents]
    free = [fs.f_bavail * fs.f_frsize for fs in filesystems]
    system_filesystems = [os.statvfs(path) for path in (Path(_PATHS["config"]).parent, _UNIT_DIR)]
    writable = all(not fs.f_flag & os.ST_RDONLY for fs in (*filesystems, *system_filesystems))
    shared = devices[0] == devices[1]
    enough_disk = min(free) >= (2 * _MIN_DISK if shared else _MIN_DISK)
    ok = bool(cpus and cpus >= 1 and available_kib >= _MIN_MEMORY_KIB and enough_disk and writable)
    return {
        "ok": ok,
        "detail": "Requires one CPU, 256 MiB available RAM, writable filesystems and disk space.",
        "cpus": cpus,
        "available_memory_kib": available_kib,
        "install_free_bytes": free[0],
        "state_free_bytes": free[1],
        "shared_filesystem": shared,
        "writable_filesystems": writable,
    }


def _exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _conflicts(
    *,
    owned_paths: frozenset[Path] = frozenset(),
    owned_units: frozenset[str] = frozenset(),
    owned_identities: frozenset[str] = frozenset(),
) -> dict:
    # The full native namespace is reserved in either mode.
    names = [_AGENT, _UI]
    units = [service["unit"] for service in install_plan("standalone")["services"]]
    paths = [*_PATHS.values(), *_LEGACY_PATHS]
    for unit in units:
        paths.extend((str(_UNIT_DIR / unit), str(_UNIT_DIR / f"{unit}.d")))
    for path in paths:
        if Path(path) not in owned_paths and _exists(Path(path)):
            return _finding(False, f"Reserved or conflicting installation path exists ({path}).")

    packages = _run(["/usr/bin/dpkg-query", "--show", f"--showformat={_DPKG_FORMAT}"])
    if packages.returncode != 0 or not packages.stdout:
        raise ValueError("Could not inspect the package database.")
    for line in packages.stdout.splitlines():
        status, package, _, _ = line.split("\t")
        name = package.split(":")[0]
        if status != "not-installed" and (
            name in ("steward", "opstend") or name.startswith(("steward-", "opstend-"))
        ):
            return _finding(False, "A package occupies the Steward or OpsTend namespace.")

    prefixes = ("steward-", "opstend-", "steward.", "opstend.")
    systemctl = ["/usr/bin/systemctl", "--system", "--no-pager", "--no-legend", "--plain"]
    for operation in ("list-unit-files", "list-units"):
        args = ["--all"] if operation == "list-units" else []
        # A pattern with no matches exits 1 on the target's systemd version.
        result = _run([*systemctl, operation, *args])
        if result.returncode != 0:
            raise ValueError("Could not inspect systemd units.")
        unit_names = (
            line.split(maxsplit=1)[0] for line in result.stdout.splitlines() if line.strip()
        )
        if any(name.startswith(prefixes) and name not in owned_units for name in unit_names):
            return _finding(False, "A systemd unit occupies the Steward or OpsTend namespace.")

    for database in ("passwd", "group"):
        for name in names:
            if name in owned_identities:
                continue
            result = _run(["/usr/bin/getent", database, name])
            if result.returncode == 0:
                return _finding(False, f"A reserved service identity already exists ({name}).")
            if result.returncode != 2 or result.stdout:
                raise ValueError("Could not inspect service identities.")
    return _finding(True, "Reserved paths, packages, units and service identities are available.")


def _listener_inodes() -> set[str]:
    # Linux renders each 32-bit word in the hex address in native byte order.
    matches = set()
    target = ipaddress.IPv4Address(UI_HOST)
    for name, width in (("tcp", 4), ("tcp6", 16)):
        with Path(f"/proc/net/{name}").open(encoding="ascii") as handle:
            if "local_address" not in next(handle, "").split():
                raise ValueError("Could not inspect local TCP sockets.")
            for line in handle:
                fields = line.split()
                local, state, inode = fields[1], fields[3], fields[9]
                address, port = local.split(":")
                if int(port, 16) != UI_PORT or state != "0A":
                    continue
                encoded = bytes.fromhex(address)
                if len(encoded) != width:
                    raise ValueError("Unexpected TCP address.")
                packed = b"".join(encoded[i : i + 4][::-1] for i in range(0, width, 4))
                ip = ipaddress.ip_address(packed)
                if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
                    ip = ip.ipv4_mapped
                # The passive tables omit IPV6_V6ONLY. Reserve wildcard IPv6
                # listeners too, as a dual-stack socket could own the IPv4 port.
                if ip.is_unspecified or ip == target:
                    matches.add(inode)
    return matches


def _socket_conflict() -> bool:
    return bool(_listener_inodes())


def _listener(mode: str) -> dict:
    if mode == "agent":
        return _finding(True, "Agent mode requests zero listeners.")
    busy = _socket_conflict()
    return _finding(
        not busy,
        f"TCP {UI_HOST}:{UI_PORT} has a possible listener conflict."
        if busy
        else f"No conflicting TCP listener observed on {UI_HOST}:{UI_PORT}.",
    )


class _DeadlineReader(io.RawIOBase):
    def __init__(self, tls_socket: ssl.SSLSocket, deadline: float):
        super().__init__()
        self.socket = tls_socket
        self.deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        self.socket.settimeout(_remaining(self.deadline))
        return self.socket.recv_into(buffer)

    def makefile(self, mode: str) -> io.BufferedReader:
        # HTTPResponse requests an ordinary buffered binary stream.
        return io.BufferedReader(self)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


class _ApiPayloadError(ValueError):
    """The API response is invalid or exceeds the per-response limit."""


class _ApiReadError(OSError):
    """The HTTP exchange failed after TLS was established."""


def _read_api_response(
    api_name: str,
    context: ssl.SSLContext,
    token: str,
    path: str,
    *,
    deadline: float,
    max_response: int,
) -> tuple[int, object]:
    host = f"[{api_name}]" if ":" in api_name else api_name
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {host}:{API_PORT}\r\n"
        f"Authorization: PVEAPIToken={token}\r\n"
        "Connection: close\r\nAccept: application/json\r\n\r\n"
    ).encode("ascii")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(_remaining(deadline))
        connection.connect((API_HOST, API_PORT))
        connection.settimeout(_remaining(deadline))
        with context.wrap_socket(connection, server_hostname=api_name) as tls_socket:
            try:
                tls_socket.settimeout(_remaining(deadline))
                tls_socket.sendall(request)
                reader = _DeadlineReader(tls_socket, deadline)
                with http.client.HTTPResponse(reader, method="GET") as response:
                    response.begin()
                    if response.status != 200:
                        return response.status, None
                    contents = response.read(max_response + 1)
                    if len(contents) > max_response or response.length:
                        raise _ApiPayloadError
                document = json.loads(
                    contents, object_pairs_hook=_unique_object, parse_constant=_reject_api_constant
                )
                if not isinstance(document, dict) or "data" not in document:
                    raise _ApiPayloadError
            except ssl.SSLCertVerificationError:
                raise
            except OSError:
                raise _ApiReadError from None
            except (http.client.HTTPException, ValueError, RecursionError):
                raise _ApiPayloadError from None
    return 200, document["data"]


def _get_api_data(api_name: str, context: ssl.SSLContext, token: str, path: str):
    try:
        _, data = _read_api_response(
            api_name,
            context,
            token,
            path,
            deadline=time.monotonic() + _TIMEOUT,
            max_response=_MAX_RESPONSE,
        )
    except (_ApiPayloadError, _ApiReadError):
        return None
    return data


def _api_context(ca_file: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ca = _read_file(ca_file, 1024 * 1024).decode("ascii")
    context.load_verify_locations(cadata=ca)
    return context


def _unique_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate API response keys.")
    return result


def _reject_api_constant(_: str) -> None:
    raise _ApiPayloadError


def _supports_api_version(data: object) -> bool:
    if not isinstance(data, dict):
        raise _ApiPayloadError("Invalid PVE API version.")
    release, version = data.get("release"), data.get("version")
    if not isinstance(release, str) or not isinstance(version, str) or not release or not version:
        raise _ApiPayloadError("Invalid PVE API version.")
    return (release, version) == (PVE_RELEASE, PVE_VERSION)


def _probe_api(api_name: str, ca_file: Path, token: str, package_ok: bool) -> dict:
    findings = {
        "tls": _finding(False, "Skipped API TLS after the local compatibility check failed."),
        "permissions": _finding(False, "Skipped the effective token permissions check."),
        "api_version": _finding(False, "Skipped the API version check."),
    }
    if not package_ok:
        return findings
    try:
        context = _api_context(ca_file)
    except (OSError, ValueError):
        findings["tls"] = _finding(False, "Could not load the operator's PEM CA.")
        return findings
    try:
        permissions = _get_api_data(api_name, context, token, "/api2/json/access/permissions")
    except ssl.SSLCertVerificationError:
        findings["tls"] = _finding(False, "The loopback API certificate failed verification.")
        return findings
    except (OSError, http.client.HTTPException, ValueError, RecursionError):
        findings["tls"] = _finding(False, "Could not establish verified TLS to the loopback API.")
        return findings
    findings["tls"] = _finding(True, "Verified the loopback API certificate identity.")
    if permissions != {}:
        findings["permissions"] = _finding(False, "Expected an empty effective permissions object.")
        return findings
    findings["permissions"] = _finding(True, "The token has no effective PVE permissions.")
    try:
        version = _get_api_data(api_name, context, token, _API_VERSION)
        matches = _supports_api_version(version)
    except (OSError, http.client.HTTPException, ValueError, RecursionError):
        matches = False
    findings["api_version"] = _finding(
        matches, f"Expected matching API and package versions ({PVE_VERSION})."
    )
    return findings


def _check(probe, failure: str) -> dict:
    try:
        return probe()
    except (OSError, subprocess.SubprocessError, ValueError):
        return _finding(False, failure)


def collect_preflight(
    *,
    mode: str,
    api_name: str,
    ca_file: Path,
    token_file: Path,
    _conflict_probe=None,
    _listener_probe=None,
) -> dict:
    install_plan(mode)
    _validate_api_name(api_name)
    if not ca_file.is_absolute() or not token_file.is_absolute():
        raise PreflightError("Use absolute paths for the operator CA and token files.")
    token = _load_token(token_file)
    findings = {
        "host": _check(_host, "Could not inspect the operating system and architecture."),
        "package": _check(_package, "Could not inspect pve-manager with dpkg-query."),
        "resources": _check(_resources, "Could not inspect CPU, memory or disk space."),
        "conflicts": _check(
            _conflict_probe or _conflicts, "Could not inspect paths, packages, units or accounts."
        ),
        "listener": _check(
            _listener_probe or (lambda: _listener(mode)),
            "Could not inspect local TCP socket tables.",
        ),
    }
    compatible = findings["host"]["ok"] and findings["package"]["ok"]
    findings.update(_probe_api(api_name, ca_file, token, compatible))
    return {
        "profile": PROFILE,
        "mode": mode,
        "ready": all(finding["ok"] for finding in findings.values()),
        "findings": findings,
    }
