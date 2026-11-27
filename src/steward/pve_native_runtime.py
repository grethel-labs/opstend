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
from contextlib import suppress
from datetime import UTC, datetime
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography import x509

from steward.core.pve_inventory import RegisteredLocalTarget, collect_inventory
from steward.core.pve_inventory_models import InventorySnapshot
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
from steward.core.pve_native_credentials import _SystemdCredential

_STATE = Path("/var/lib/opstend-pve/agent")
_BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
_PYTHON = "/opt/opstend-pve/current/venv/bin/python"
_INTERVAL = 30
_STALE_AFTER = 90
_CHECKS = ("tls", "permissions", "api_version")
_HOSTS = {f"{UI_HOST}:{UI_PORT}", f"localhost:{UI_PORT}"}
_INVENTORY = "inventory.json"
_INVENTORY_LIMIT = 8 * 1024 * 1024
_GUEST_PATH = re.compile(r"/guests/([1-9][0-9]{2,8})")


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
    inventory_token_file: Path | None = None,
) -> str:
    _validate_api_name(api_name)
    if role == "agent":
        dependencies = "After=pveproxy.service\n"
        access = (
            f"LoadCredential=pve-ca:{_credential_path(ca_file)}\n"
            f"LoadCredential=pve-token:{_credential_path(token_file)}\n"
            f"ReadWritePaths={_STATE}\n"
        )
        if inventory_token_file is not None:
            # A missing source leaves inventory unavailable while the agent starts.
            access += (
                "SetCredential=pve-inventory-token:unavailable\n"
                f"LoadCredential=pve-inventory-token:{_credential_path(inventory_token_file)}\n"
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


def read_admin_token(path: Path | _SystemdCredential) -> str:
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


def _publish_inventory(inventory: InventorySnapshot | None, observed_boottime: float) -> None:
    boot_id = _BOOT_ID.read_text(encoding="ascii").strip()
    payload = inventory.model_dump(mode="json") if inventory is not None else None
    document = json.dumps(
        {"boot_id": boot_id, "observed_boottime": observed_boottime, "inventory": payload},
        allow_nan=False,
    ).encode("ascii")
    if len(document) > _INVENTORY_LIMIT:
        raise ValueError("Inventory snapshot is too large.")
    # The agent is the only writer. Reuse one staging path after an unclean
    # exit so repeated interruptions cannot accumulate inventory files.
    temporary = _STATE / ".inventory.tmp"
    temporary.unlink(missing_ok=True)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(document)
            handle.flush()
            os.fchmod(handle.fileno(), 0o640)
        temporary.replace(_STATE / _INVENTORY)
    finally:
        temporary.unlink(missing_ok=True)


def _load_inventory_document() -> dict:
    directory = os.open(_STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        owner = os.fstat(directory)
        if stat.S_IMODE(owner.st_mode) & 0o022:
            raise ValueError("Inventory state directory is writable by other users.")
        fd = os.open(_INVENTORY, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(fd, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o640
                or (metadata.st_uid, metadata.st_gid) != (owner.st_uid, owner.st_gid)
                or metadata.st_nlink != 1
            ):
                raise ValueError("Expected an agent-owned inventory snapshot.")
            contents = handle.read(_INVENTORY_LIMIT + 1)
    finally:
        os.close(directory)
    if len(contents) > _INVENTORY_LIMIT:
        raise ValueError("Inventory snapshot is too large.")
    document = json.loads(contents, object_pairs_hook=_unique_object)
    if not isinstance(document, dict) or document.keys() != {
        "boot_id",
        "observed_boottime",
        "inventory",
    }:
        raise ValueError("Invalid inventory snapshot.")
    return document


def _inventory(vmid: int | None = None) -> dict:
    result = {
        "profile": PROFILE,
        "status": "unavailable",
        "coverage": "token_scope",
        "observed_at": None,
        "evidence": None,
    }
    if vmid is None:
        result.update(nodes=[], guests=[], pools=[], datastores=[])
    else:
        result["guest"] = None
    try:
        document = _load_inventory_document()
        payload = document["inventory"]
        if payload is None:
            return result
        observed = document["observed_boottime"]
        if type(observed) not in (int, float) or not observed >= 0:
            return result
        age = _boottime() - observed
        boot_id = document["boot_id"]
        if not isinstance(boot_id, str) or not boot_id:
            return result
        if age >= _STALE_AFTER or boot_id != _BOOT_ID.read_text(encoding="ascii").strip():
            result["status"] = "stale"
            return result
        if not age >= 0:
            return result
        snapshot = InventorySnapshot.model_validate_json(json.dumps(payload, allow_nan=False))
    except (OSError, ValueError, OverflowError, RecursionError):
        return result

    result["observed_at"] = snapshot.observed_at.isoformat()
    result["evidence"] = snapshot.evidence.model_dump(mode="json")
    state = snapshot.evidence.state
    if state not in ("observed", "absent"):
        result["status"] = "restricted" if state == "restricted" else "unavailable"
        return result
    result["status"] = state
    if state == "absent":
        if vmid is not None:
            result["status"] = "restricted"
        return result
    if vmid is None:
        for field in ("nodes", "guests", "pools", "datastores"):
            result[field] = [row.model_dump(mode="json") for row in getattr(snapshot, field)]
        return result

    guest = next((row for row in snapshot.guests if row.vmid == vmid), None)
    if guest is None:
        result["status"] = "restricted"
    else:
        result["guest"] = guest.model_dump(mode="json")
    return result


def read_inventory(vmid: int | None = None) -> dict:
    if os.geteuid() != 0:
        raise ValueError("Run native inventory as root.")
    if vmid is not None and (type(vmid) is not int or not 100 <= vmid <= 999_999_999):
        raise ValueError("Use a PVE guest ID from 100 to 999999999.")
    return _inventory(vmid)


def _refresh_inventory(target: RegisteredLocalTarget) -> None:
    started = _clear_inventory()
    if started is None:
        return
    try:
        snapshot = collect_inventory(target)
        if snapshot.evidence.state != "observed":
            snapshot = InventorySnapshot(
                api_name=snapshot.api_name,
                observed_at=snapshot.observed_at,
                evidence=snapshot.evidence,
            )
        _publish_inventory(snapshot, started)
    except (OSError, ValueError):
        # Health/readiness are independent; the barrier is already visible.
        pass


def _clear_inventory() -> float | None:
    try:
        started = _boottime()
        _publish_inventory(None, started)
    except (OSError, ValueError):
        # A failed barrier must not allow collection to proceed.
        with suppress(OSError):
            (_STATE / _INVENTORY).unlink(missing_ok=True)
        return None
    return started


def _run_agent(api_name: str) -> None:
    _validate_api_name(api_name)
    health_token_file = _SystemdCredential("agent", "pve-token")
    token = _load_token(health_token_file)
    ca_file = _SystemdCredential("agent", "pve-ca")
    target = RegisteredLocalTarget(
        api_name, ca_file, _SystemdCredential("agent", "pve-inventory-token"), health_token_file
    )

    def observe() -> bool:
        probe = _probe_api(api_name, ca_file, token, package_ok=True)
        checks = {name: probe[name]["ok"] for name in _CHECKS}
        _publish(checks)
        return all(checks.values())

    _clear_inventory()
    if not observe():
        raise ValueError("The initial local PVE API probe did not pass.")
    _notify_ready()
    while True:
        _refresh_inventory(target)
        time.sleep(_INTERVAL)
        observe()


def _html_document(title: str, body: str) -> bytes:
    return (
        f"<!doctype html><html lang=en><meta charset=utf-8><title>{title}</title>"
        f"<h1>{title}</h1>{body}</html>"
    ).encode()


def _html_fields(fields: dict) -> str:
    entries = []
    for key, value in fields.items():
        if value is None or value == []:
            continue
        label = key.replace("_", " ").capitalize()
        if isinstance(value, dict):
            content = _html_fields(value)
        elif isinstance(value, list):
            items = (
                _html_fields(item) if isinstance(item, dict) else escape(str(item))
                for item in value
            )
            content = "<ol>" + "".join(f"<li>{item}</li>" for item in items) + "</ol>"
        else:
            content = escape(str(value))
        entries.append(f"<dt>{escape(label)}</dt><dd>{content}</dd>")
    return "<dl>" + "".join(entries) + "</dl>"


def _inventory_html(inventory: dict, *, detail: bool) -> bytes:
    title = "PVE guest detail" if detail else "PVE inventory"
    status = inventory["status"]
    message = {
        "observed": "Observed in the inventory token scope.",
        "absent": "No resources were observed in the inventory token scope.",
        "restricted": "The inventory token lacks access.",
        "unavailable": "Inventory is unavailable.",
        "stale": "The inventory snapshot expired.",
    }[status]
    if detail and status == "restricted" and inventory["evidence"]["state"] != "restricted":
        message = "No guest was visible in this inventory token scope."
    parts = [
        '<nav><a href="/">Status</a> <a href="/inventory">Inventory</a></nav>',
        f"<p>{message}</p>",
        _html_fields({"evidence": inventory["evidence"]}),
    ]
    if detail:
        guest = inventory["guest"]
        if guest is not None:
            parts.extend(
                (
                    _html_fields(guest),
                    "<p>Guest operating system and guest agent data unprobed.</p>",
                )
            )
    else:
        for section in ("nodes", "guests", "pools", "datastores"):
            if not inventory[section]:
                continue
            parts.append(f"<h2>{section.capitalize()}</h2>")
            for row in inventory[section]:
                if section == "guests":
                    vmid = row["vmid"]
                    parts.append(f'<a href="/guests/{vmid}">Guest {vmid}</a>')
                    row = {
                        key: value
                        for key, value in row.items()
                        if key not in {"network", "measurements", "tasks"}
                    }
                parts.append(_html_fields(row))
    return _html_document(title, "".join(parts))


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

    def _respond(
        self,
        code: int,
        body: bytes = b"",
        content_type: str = "text/plain",
        *,
        vary_accept: bool = False,
    ) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if vary_accept:
            self.send_header("Vary", "Accept")
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
        guest_path = _GUEST_PATH.fullmatch(self.path)
        if self.path not in ("/", "/status", "/inventory") and guest_path is None:
            self._respond(404)
            return
        if not self._authorized():
            self._respond(401)
            return
        if self.path == "/inventory" or guest_path:
            vmid = int(guest_path[1]) if guest_path else None
            inventory = _inventory(vmid)
            accept = self.headers.get_all("Accept", [])
            if len(accept) == 1 and accept[0].strip().lower() == "application/json":
                body = json.dumps(inventory).encode("ascii")
                self._respond(200, body, "application/json", vary_accept=True)
            else:
                body = _inventory_html(inventory, detail=guest_path is not None)
                self._respond(200, body, "text/html; charset=utf-8", vary_accept=True)
            return
        status = _status()
        if self.path == "/status":
            self._respond(200, json.dumps(status).encode("ascii"), "application/json")
            return
        checks = "".join(
            f"<dt>{name}</dt><dd>{'Passed' if result else 'Failed'}</dd>"
            for name, result in status["checks"].items()
        )
        document = _html_document(
            "OpsTend native PVE",
            '<nav><a href="/inventory">Inventory</a></nav>'
            f"<p>Status: {status['status']}</p>"
            f"<p>Observed at: {status['observed_at'] or 'Unavailable'}</p><dl>{checks}</dl>",
        )
        self._respond(200, document, "text/html; charset=utf-8")


def _run_ui() -> None:
    token = read_admin_token(_SystemdCredential("ui", "admin-token"))
    with (
        _SystemdCredential("ui", "ui-cert").open() as cert,
        _SystemdCredential("ui", "ui-key").open() as key,
    ):
        # The certificate checks and OpenSSL load use the same checked files.
        context = validate_ui_tls(
            Path(f"/proc/self/fd/{cert.fileno()}"), Path(f"/proc/self/fd/{key.fileno()}")
        )
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
