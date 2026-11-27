"""Native PVE runtime for the unprivileged agent and status UI."""

import base64
import hmac
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import sys
import tempfile
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography import x509

from steward.core.pve_native import (
    API_HOST,
    PROFILE,
    UI_HOST,
    UI_PORT,
    _load_token,
    _probe_api,
    _read_file,
    _unique_object,
    _validate_api_name,
)

_STATE = Path("/var/lib/opstend-pve/agent")
_BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
_PYTHON = "/opt/opstend-pve/current/venv/bin/python"
_INTERVAL = 30
_STALE_AFTER = 90
_CHECKS = ("tls", "permissions", "api_version")
_HOSTS = {f"{UI_HOST}:{UI_PORT}", f"localhost:{UI_PORT}"}


def _credential_path(path: Path) -> str:
    if not path.is_absolute() or not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)):
        raise ValueError("Use an absolute systemd credential path with safe characters.")
    return str(path)


def render_unit(
    role: str,
    *,
    api_name: str,
    ca_file: Path,
    token_file: Path,
    admin_token_file: Path | None,
    ui_cert_file: Path | None = None,
    ui_key_file: Path | None = None,
) -> str:
    _validate_api_name(api_name)
    if role == "agent":
        dependencies = "After=pveproxy.service\n"
        access = (
            f"LoadCredential=pve-ca:{_credential_path(ca_file)}\n"
            f"LoadCredential=pve-token:{_credential_path(token_file)}\n"
            f"ReadWritePaths={_STATE}\n"
        )
        args = f"agent {api_name}"
    elif role == "ui" and admin_token_file and ui_cert_file and ui_key_file:
        dependencies = "After=opstend-pve-agent.service\nRequires=opstend-pve-agent.service\n"
        access = (
            f"LoadCredential=admin-token:{_credential_path(admin_token_file)}\n"
            f"LoadCredential=ui-cert:{_credential_path(ui_cert_file)}\n"
            f"LoadCredential=ui-key:{_credential_path(ui_key_file)}\n"
            "SupplementaryGroups=opstend-pve-agent\n"
            f"SocketBindAllow=ipv4:tcp:{UI_PORT}\n"
        )
        args = "ui"
    else:
        raise ValueError("Choose agent or ui with its required credentials.")
    return (
        f"[Unit]\nDescription=OpsTend native PVE {role}\n{dependencies}"
        "\n[Service]\nType=notify\nNotifyAccess=main\nTimeoutStartSec=30s\n"
        f"User=opstend-pve-{role}\nGroup=opstend-pve-{role}\n"
        f"ExecStart={_PYTHON} -I -B -m steward.pve_native_runtime {args}\n"
        "Restart=on-failure\nRestartSec=10s\nUMask=0027\n"
        "NoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n"
        "ProtectSystem=strict\nProtectHome=yes\nPrivateDevices=yes\nPrivateTmp=yes\n"
        "ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\n"
        "RestrictSUIDSGID=yes\nRestrictNamespaces=yes\n"
        "RestrictAddressFamilies=AF_INET AF_UNIX\nSocketBindDeny=any\n"
        f"IPAddressDeny=any\nIPAddressAllow={API_HOST}/32\n"
        f"{access}\n[Install]\nWantedBy=multi-user.target\n"
    )


def read_admin_token(path: Path) -> str:
    try:
        token = _read_file(path, 129, private=True).decode("ascii").removesuffix("\n")
    except (OSError, ValueError):
        raise ValueError("Use a readable private admin token file.") from None
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
        raise ValueError(
            "Use an admin token of 32 to 128 ASCII letters, digits, underscores or hyphens."
        )
    return token


def validate_ui_tls(cert_file: Path, key_file: Path) -> ssl.SSLContext:
    try:
        cert = x509.load_pem_x509_certificate(_read_file(cert_file, 1024 * 1024))
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if ipaddress.ip_address(UI_HOST) not in san.get_values_for_type(x509.IPAddress):
            raise ValueError
        if not cert.not_valid_before_utc <= datetime.now(UTC) < cert.not_valid_after_utc:
            raise ValueError
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # Reject encrypted keys without prompting on stdin.
        context.load_cert_chain(cert_file, key_file, password=lambda: b"")
    except (OSError, ValueError, x509.ExtensionNotFound, x509.DuplicateExtension):
        raise ValueError(
            f"Use a current UI certificate for IP {UI_HOST} and its unencrypted key."
        ) from None
    return context


def _credentials() -> Path:
    directory = Path(os.environ.get("CREDENTIALS_DIRECTORY", ""))
    if not directory.is_absolute():
        raise ValueError("Systemd credentials are required.")
    return directory


def _notify_ready() -> None:
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        raise ValueError("Systemd readiness notification is required.")
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(b"READY=1", address)


def _boottime() -> float:
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def _publish(checks: dict[str, bool]) -> None:
    snapshot = {
        "profile": PROFILE,
        "observed_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "boot_id": _BOOT_ID.read_text(encoding="ascii").strip(),
        "observed_boottime": _boottime(),
        "checks": checks,
    }
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="ascii", dir=_STATE, delete=False
    ) as handle:
        temporary = Path(handle.name)
        try:
            json.dump(snapshot, handle, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fchmod(handle.fileno(), 0o640)
            os.replace(temporary, _STATE / "status.json")
        finally:
            temporary.unlink(missing_ok=True)


def _load_snapshot():
    fd = os.open(_STATE / "status.json", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("Expected a regular snapshot.")
        contents = handle.read(2049)
    if len(contents) > 2048:
        raise ValueError("Snapshot is too large.")
    return json.loads(contents, object_pairs_hook=_unique_object)


def _status() -> dict:
    unavailable = {"profile": PROFILE, "status": "unavailable", "observed_at": None, "checks": {}}
    try:
        snapshot = _load_snapshot()
        if not isinstance(snapshot, dict) or snapshot["profile"] != PROFILE:
            return unavailable
        checks = snapshot["checks"]
        if not isinstance(checks, dict) or checks.keys() != set(_CHECKS):
            return unavailable
        if any(type(result) is not bool for result in checks.values()):
            return unavailable
        timestamp = snapshot["observed_at"]
        if not isinstance(timestamp, str):
            return unavailable
        timestamp = datetime.fromisoformat(timestamp)
        if timestamp.tzinfo != UTC:
            return unavailable
        boottime = snapshot.get("observed_boottime")
        age = _boottime() - boottime if type(boottime) in (int, float) else -1
        current_boot = _BOOT_ID.read_text(encoding="ascii").strip()
        fresh = snapshot.get("boot_id") == current_boot and 0 <= age < _STALE_AFTER
    except (OSError, KeyError, ValueError, OverflowError, RecursionError):
        return unavailable
    status = "healthy" if all(checks.values()) else "unhealthy"
    return {
        "profile": PROFILE,
        "status": status if fresh else "stale",
        "observed_at": timestamp.isoformat(timespec="seconds"),
        "checks": checks,
    }


def read_status() -> dict:
    if os.geteuid() != 0:
        raise ValueError("Run native status as root.")
    return _status()


def _run_agent(api_name: str) -> None:
    _validate_api_name(api_name)
    credentials = _credentials()
    token = _load_token(credentials / "pve-token")
    ca_file = credentials / "pve-ca"

    def observe() -> bool:
        probe = _probe_api(api_name, ca_file, token, package_ok=True)
        checks = {name: probe[name]["ok"] for name in _CHECKS}
        _publish(checks)
        return all(checks.values())

    if not observe():
        raise ValueError("The initial local PVE API probe did not pass.")
    _notify_ready()
    while True:
        time.sleep(_INTERVAL)
        observe()


class _StatusServer(HTTPServer):
    def __init__(self, token: str, context: ssl.SSLContext):
        self.admin_identity = b"admin:" + token.encode("ascii")
        self.context = context
        super().__init__((UI_HOST, UI_PORT), _StatusHandler)

    def get_request(self):
        connection, address = super().get_request()
        try:
            connection.settimeout(3)
            return self.context.wrap_socket(connection, server_side=True), address
        except OSError:
            connection.close()
            raise

    def handle_error(self, request, client_address):
        # Requests can contain credentials. Keep request logs disabled.
        pass


class _StatusHandler(BaseHTTPRequestHandler):
    timeout = 3

    def log_message(self, format, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        self.close_connection = True
        self._respond(code)

    def _respond(self, code: int, body: bytes = b"", content_type: str = "text/plain") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if code == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="OpsTend native PVE"')
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        headers = self.headers.get_all("Authorization", [])
        if len(headers) != 1 or len(headers[0]) > 200:
            return False
        scheme, _, encoded = headers[0].partition(" ")
        if scheme.lower() != "basic":
            return False
        try:
            value = base64.b64decode(encoded, validate=True)
        except ValueError:
            return False
        return hmac.compare_digest(value, self.server.admin_identity)

    def do_GET(self):
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1 or hosts[0].lower() not in _HOSTS:
            self._respond(400)
            return
        if self.path not in ("/", "/status"):
            self._respond(404)
            return
        if not self._authorized():
            self._respond(401)
            return
        status = _status()
        if self.path == "/status":
            self._respond(200, json.dumps(status).encode("ascii"), "application/json")
            return
        checks = "".join(
            f"<dt>{name}</dt><dd>{'Passed' if result else 'Failed'}</dd>"
            for name, result in status["checks"].items()
        )
        document = (
            "<!doctype html><html lang=en><meta charset=utf-8><title>OpsTend native PVE</title>"
            f"<h1>OpsTend native PVE</h1><p>Status: {status['status']}</p>"
            f"<p>Observed at: {status['observed_at'] or 'Unavailable'}</p><dl>{checks}</dl></html>"
        )
        self._respond(200, document.encode("ascii"), "text/html; charset=utf-8")


def _run_ui() -> None:
    credentials = _credentials()
    token = read_admin_token(credentials / "admin-token")
    context = validate_ui_tls(credentials / "ui-cert", credentials / "ui-key")
    if _status()["status"] == "unavailable":
        raise ValueError("An agent snapshot is required for UI startup.")
    with _StatusServer(token, context) as server:
        _notify_ready()
        server.serve_forever()


def main() -> int:
    try:
        if os.geteuid() == 0:
            raise ValueError("The native runtime requires an unprivileged service account.")
        if len(sys.argv) == 3 and sys.argv[1] == "agent":
            _run_agent(sys.argv[2])
        elif sys.argv[1:] == ["ui"]:
            _run_ui()
        else:
            raise ValueError("Choose the native agent or UI runtime.")
    except (OSError, ValueError):
        print("The native PVE service could not complete its operation.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
