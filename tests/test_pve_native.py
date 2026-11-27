import json
import os
import socket
import ssl
import threading
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from steward.cli import main as cli
from steward.core import pve_native

API_NAME = "px01-fixture.invalid"
API_TOKEN = "px01@pve!preflight=14aa8f43-4390-4b66-875f-464814c048df"  # noqa: S105
PERMISSIONS_PATH = "/api2/json/access/permissions"
VERSION_PATH = "/api2/json/version"


@pytest.fixture
def token_file(tmp_path):
    path = tmp_path / "pve-token"
    path.write_text(API_TOKEN + "\n")
    path.chmod(0o600)
    return path


@pytest.fixture
def compatible_host(monkeypatch):
    for probe in ("_host", "_package", "_resources", "_conflicts"):
        monkeypatch.setattr(pve_native, probe, lambda *a: {"ok": True, "detail": "fixture"})
    monkeypatch.setattr(pve_native, "_socket_conflict", lambda: False)


def write_certificate(directory, name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / (name + ".pem")
    key_path = directory / (name + ".key")
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture
def pve_tls():
    return ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)


@pytest.fixture
def pve_api(tmp_path, monkeypatch, pve_tls):
    cert_path, key_path = write_certificate(tmp_path, API_NAME)
    calls = []
    responses = {
        PERMISSIONS_PATH: (200, b'{"data":{}}'),
        VERSION_PATH: (
            200,
            json.dumps(
                {"data": {"version": pve_native.PVE_VERSION, "release": pve_native.PVE_RELEASE}}
            ).encode(),
        ),
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            calls.append((self.command, self.path, self.headers.get("Authorization")))
            response = responses.get(self.path, (404, b""))
            code, payload = response() if callable(response) else response
            with suppress(BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                self.send_response(code)
                if code == 302:
                    self.send_header(
                        "Location", f"https://127.0.0.1:{self.server.server_port}/other"
                    )
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if payload:
                    self.wfile.write(payload)

        def log_message(self, *_):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        pve_tls.load_cert_chain(cert_path, key_path)
        server.socket = pve_tls.wrap_socket(server.socket, server_side=True)
        monkeypatch.setattr(pve_native, "API_PORT", server.server_port)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()
        try:
            yield cert_path, responses, calls
        finally:
            server.shutdown()
            thread.join(timeout=2)


def test_preflight_verifies_tls_and_uses_only_fixed_gets(compatible_host, pve_api, token_file):
    ca, _, calls = pve_api
    result = pve_native.collect_preflight(
        mode="agent", api_name=API_NAME, ca_file=ca, token_file=token_file
    )
    assert result["ready"] is True
    assert result["profile"] == "pve-native/v1"
    assert calls == [
        ("GET", PERMISSIONS_PATH, "PVEAPIToken=" + API_TOKEN),
        ("GET", VERSION_PATH, "PVEAPIToken=" + API_TOKEN),
    ]
    assert API_TOKEN not in json.dumps(result)


@pytest.mark.parametrize("failure", ["wrong-name", "wrong-ca"])
def test_preflight_sends_no_secret_on_tls_failure(
    compatible_host, pve_api, token_file, tmp_path, failure
):
    ca, _, calls = pve_api
    name = API_NAME
    if failure == "wrong-name":
        name = "different-name.invalid"
    else:
        ca, _ = write_certificate(tmp_path, "untrusted.invalid")
    result = pve_native.collect_preflight(
        mode="agent", api_name=name, ca_file=ca, token_file=token_file
    )
    assert result["ready"] is False
    assert result["findings"]["tls"]["ok"] is False
    assert calls == []


@pytest.mark.parametrize(
    "response",
    [
        (200, b'{"data":{"/":{"Sys.Modify":1}}}'),
        (200, b'{"data":[]}'),
        (200, b'{"data":{"/":{"Sys.Modify":1}},"data":{}}'),
        (200, b'{"data":{}}' + b" " * (64 * 1024)),
        (200, b"invalid json"),
        (401, API_TOKEN.encode()),
        (302, b""),
    ],
)
def test_preflight_refuses_invalid_or_overbroad_authentication(
    compatible_host, pve_api, token_file, response
):
    ca, responses, calls = pve_api
    responses[PERMISSIONS_PATH] = response
    result = pve_native.collect_preflight(
        mode="agent", api_name=API_NAME, ca_file=ca, token_file=token_file
    )
    assert result["ready"] is False
    assert result["findings"]["tls"]["ok"] is True
    assert result["findings"]["permissions"]["ok"] is False
    assert [target for _, target, _ in calls] == [PERMISSIONS_PATH]
    assert API_TOKEN not in json.dumps(result)


def test_preflight_refuses_api_package_version_mismatch(compatible_host, pve_api, token_file):
    ca, responses, _ = pve_api
    responses[VERSION_PATH] = (200, b'{"data":{"version":"9.2.2","release":"9.2"}}')
    result = pve_native.collect_preflight(
        mode="agent", api_name=API_NAME, ca_file=ca, token_file=token_file
    )
    assert result["ready"] is False
    assert result["findings"]["api_version"]["ok"] is False


def test_preflight_refuses_insecure_secret_file_before_contact(
    compatible_host, pve_api, token_file
):
    ca, _, calls = pve_api
    token_file.chmod(0o640)
    with pytest.raises(pve_native.PreflightError) as error:
        pve_native.collect_preflight(
            mode="agent", api_name=API_NAME, ca_file=ca, token_file=token_file
        )
    assert API_TOKEN not in str(error.value)
    assert calls == []


def test_preflight_refuses_unsupported_host_without_contact(
    compatible_host, pve_api, token_file, monkeypatch
):
    ca, _, calls = pve_api
    monkeypatch.setattr(pve_native, "_host", lambda: {"ok": False, "detail": "not Debian 13"})
    result = pve_native.collect_preflight(
        mode="agent", api_name=API_NAME, ca_file=ca, token_file=token_file
    )
    assert result["ready"] is False
    assert result["findings"]["host"]["ok"] is False
    assert calls == []


def test_passive_port_check_detects_real_listener(monkeypatch):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        monkeypatch.setattr(pve_native, "UI_PORT", listener.getsockname()[1])
        assert pve_native._socket_conflict() is True
    assert pve_native._socket_conflict() is False


def test_reserved_package_conflict_blocks_even_without_unit_or_path(monkeypatch):
    monkeypatch.setattr(pve_native, "_exists", lambda _: False)

    def read_package_database(command):
        assert command[0] == "/usr/bin/dpkg-query"
        return SimpleNamespace(
            returncode=0,
            stdout=(
                f"installed\tpve-manager\tall\t{pve_native.PVE_VERSION}\n"
                "installed\topstend-pve-agent\tamd64\t0.1\n"
            ),
        )

    monkeypatch.setattr(pve_native, "_run", read_package_database)
    result = pve_native._conflicts()
    assert result["ok"] is False
    assert "package" in result["detail"].lower()


def test_reserved_unit_namespace_includes_sockets(monkeypatch):
    monkeypatch.setattr(pve_native, "_exists", lambda _: False)

    def read_metadata(command):
        if command[0] == "/usr/bin/dpkg-query":
            package = f"installed\tpve-manager\tall\t{pve_native.PVE_VERSION}\n"
            return SimpleNamespace(returncode=0, stdout=package)
        assert command[0] == "/usr/bin/systemctl"
        assert not any("*" in argument for argument in command)
        return SimpleNamespace(
            returncode=0,
            stdout="pveproxy.service enabled -\nsteward-inference-egress.socket enabled -\n",
        )

    monkeypatch.setattr(pve_native, "_run", read_metadata)
    result = pve_native._conflicts()
    assert result["ok"] is False
    assert "unit" in result["detail"].lower()


def test_architecture_independent_manager_on_compatible_host(monkeypatch):
    manager = f"installed\tpve-manager\tall\t{pve_native.PVE_VERSION}\n"
    monkeypatch.setattr(
        pve_native, "_run", lambda argv: SimpleNamespace(returncode=0, stdout=manager)
    )
    assert pve_native._package()["ok"]


@pytest.mark.parametrize(
    ("disk_gib", "readonly_path", "ready"),
    [(1, None, False), (2, "/etc", False), (2, "/etc/systemd/system", False), (2, None, True)],
)
def test_resources_reserve_shared_disk_and_check_config_mounts(
    monkeypatch, tmp_path, disk_gib, readonly_path, ready
):
    proc_fixture = tmp_path / "meminfo"
    proc_fixture.write_text("MemAvailable:     524288 kB\n")
    real_open = Path.open

    def open_meminfo(path, *args, **kwargs):
        return real_open(proc_fixture if path == Path("/proc/meminfo") else path, *args, **kwargs)

    def filesystem(path):
        return SimpleNamespace(
            f_bavail=disk_gib * 1024**2,
            f_frsize=1024,
            f_flag=os.ST_RDONLY if str(path) == readonly_path else 0,
        )

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", open_meminfo)
        patch.setattr(Path, "stat", lambda path: SimpleNamespace(st_dev=1))
        patch.setattr(os, "statvfs", filesystem)
        patch.setattr(os, "cpu_count", lambda: 1)
        result = pve_native._resources()
    assert result["ok"] is ready


@pytest.mark.parametrize("mode, expected_port", [("standalone", 8447), ("agent", None)])
def test_native_plan_isolated_paths_users_units_and_ports(mode, expected_port):
    plan = pve_native.install_plan(mode)
    assert plan["paths"] == {
        "install": "/opt/opstend-pve",
        "config": "/etc/opstend-pve",
        "state": "/var/lib/opstend-pve",
    }
    assert plan["artifact"] == "signed-isolated-bundle"
    assert plan["api"] == {"host": "127.0.0.1", "port": 8006}
    assert plan["listeners"] == (
        [{"host": "127.0.0.1", "port": expected_port}] if expected_port else []
    )
    users = [service["user"] for service in plan["services"]]
    assert users == (
        ["opstend-pve-agent", "opstend-pve-ui"] if expected_port else ["opstend-pve-agent"]
    )
    assert [service["unit"] for service in plan["services"]] == [
        user + ".service" for user in users
    ]
    assert all(
        service["path"] == "/etc/systemd/system/" + service["unit"] for service in plan["services"]
    )


@pytest.mark.parametrize("action, ready", [("plan", False), ("preflight", True)])
def test_native_cli_emits_json_and_refusal_exit(
    compatible_host, pve_api, token_file, monkeypatch, capsys, action, ready
):
    ca, _, _ = pve_api
    if not ready:
        monkeypatch.setattr(
            pve_native, "_conflicts", lambda *a: {"ok": False, "detail": "reserved path in use"}
        )
    args = [
        "pve-native",
        action,
        "--mode",
        "agent",
        "--api-name",
        API_NAME,
        "--ca-file",
        str(ca),
        "--token-file",
        str(token_file),
    ]
    with pytest.raises(SystemExit) as exit_info:
        cli.main(args)
    assert exit_info.value.code == (0 if ready else cli.EXIT_UNAVAILABLE)
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result["ready"] is ready
    assert ("install_plan" in result) is (action == "plan")
    assert API_TOKEN not in output.out + output.err


@pytest.mark.parametrize("requested_vmid", [None, 123])
def test_native_inventory_cli_reads_local_projection(monkeypatch, capsys, requested_vmid):
    from steward import pve_native_runtime

    projection = {"status": "unavailable"}

    def read_inventory(*, vmid):
        assert vmid == requested_vmid
        return projection

    monkeypatch.setattr(pve_native_runtime, "read_inventory", read_inventory)
    args = ["pve-native", "inventory"]
    if requested_vmid is not None:
        args.extend(("--vmid", str(requested_vmid)))
    with pytest.raises(SystemExit) as result:
        cli.main(args)
    assert result.value.code == 0
    assert json.loads(capsys.readouterr().out) == projection


def test_native_install_cli_binds_inventory_reference(monkeypatch, capsys):
    from steward.core import pve_native_install

    def install(**kwargs):
        assert kwargs["inventory_token_file"] == Path("/root/fixture/inventory")
        return {"mode": "agent"}

    monkeypatch.setattr(pve_native_install, "install", install)
    with pytest.raises(SystemExit) as result:
        cli.main(
            [
                "pve-native",
                "install",
                "--mode",
                "agent",
                "--api-name",
                API_NAME,
                "--ca-file",
                "/root/fixture/ca",
                "--token-file",
                "/root/fixture/health",
                "--inventory-token-file",
                "/root/fixture/inventory",
                "--release-archive",
                "/root/fixture/release",
                "--release-public-key",
                "/root/fixture/key",
                "--wheelhouse",
                "/root/fixture/wheels",
            ]
        )
    assert result.value.code == 0
    assert json.loads(capsys.readouterr().out) == {"mode": "agent"}
