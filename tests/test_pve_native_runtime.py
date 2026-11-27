import base64
import http.client
import ipaddress
import json
import ssl
import stat
import threading
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from steward import pve_native_runtime as runtime
from test_pve_native import API_NAME, API_TOKEN, PERMISSIONS_PATH, VERSION_PATH
from test_pve_native import pve_api as pve_api

ADMIN_TOKEN = "synthetic-test-token-used-only-in-tests"


def ui_certificate(directory, *, san=None, expired=False, name="ui"):
    if san is None:
        san = x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "native fixture")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 1))
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / f"{name}.pem", directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cert_path.chmod(0o644)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return cert_path, key_path


@pytest.fixture
def snapshot(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    boot = tmp_path / "boot-id"
    boot.write_text("boot-one")
    clock = [300.0]
    monkeypatch.setattr(runtime, "_STATE", state)
    monkeypatch.setattr(runtime, "_BOOT_ID", boot)
    monkeypatch.setattr(runtime, "_boottime", lambda: clock[0])
    return state / "status.json", boot, clock


@pytest.mark.parametrize("failure", [None, "tls", "permissions", "api_version"])
def test_agent_publishes_readiness_from_fixed_https_gets(
    tmp_path, monkeypatch, pve_api, snapshot, failure
):
    ca, responses, calls = pve_api
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    (credentials / "pve-ca").write_bytes(ca.read_bytes())
    token = credentials / "pve-token"
    token.write_text(API_TOKEN)
    token.chmod(0o600)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials))
    ready = []
    monkeypatch.setattr(runtime, "_notify_ready", lambda: ready.append(True))

    class EndIteration(Exception):
        pass

    def end_iteration(seconds):
        assert seconds == 30
        raise EndIteration

    monkeypatch.setattr(runtime.time, "sleep", end_iteration)
    if failure == "permissions":
        responses[PERMISSIONS_PATH] = (200, b'{"data":{"/":{"VM.Audit":1}}}')
    if failure == "api_version":
        responses[VERSION_PATH] = (200, b'{"data":{"version":"0","release":"0"}}')
    if failure:
        with pytest.raises(ValueError, match="initial local PVE API probe"):
            runtime._run_agent("wrong.invalid" if failure == "tls" else API_NAME)
    else:
        with pytest.raises(EndIteration):
            runtime._run_agent(API_NAME)

    paths = [] if failure == "tls" else [PERMISSIONS_PATH]
    if failure in (None, "api_version"):
        paths.append(VERSION_PATH)
    assert calls == [("GET", path, f"PVEAPIToken={API_TOKEN}") for path in paths]
    assert ready == ([] if failure else [True])
    status = runtime._status()
    assert status["status"] == ("unhealthy" if failure else "healthy")
    assert status["checks"] == {
        "tls": failure != "tls",
        "permissions": failure not in {"tls", "permissions"},
        "api_version": failure is None,
    }
    path, _, _ = snapshot
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert API_TOKEN not in path.read_text()


def test_snapshot_freshness_and_projection(snapshot, monkeypatch):
    path, boot, clock = snapshot
    assert runtime._status()["status"] == "unavailable"
    runtime._publish(dict.fromkeys(("tls", "permissions", "api_version"), True))
    document = json.loads(path.read_text())
    document["pve-token"] = API_TOKEN
    path.write_text(json.dumps(document))
    assert set(runtime._status()) == {"status", "profile", "observed_at", "checks"}
    assert API_TOKEN not in json.dumps(runtime._status())

    clock[0] += 89
    assert runtime._status()["status"] == "healthy"
    clock[0] += 1
    assert runtime._status()["status"] == "stale"
    clock[0] -= 90
    boot.write_text("boot-two")
    assert runtime._status()["status"] == "stale"
    path.write_text('{"checks": {}, "checks": {}}')
    assert runtime._status()["status"] == "unavailable"

    monkeypatch.setattr(runtime.os, "geteuid", lambda: 1000)
    with pytest.raises(ValueError, match="as root"):
        runtime.read_status()
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0)
    assert runtime.read_status() == runtime._status()


@pytest.mark.parametrize("problem", ["dns-only", "wrong-ip", "expired", "wrong-key"])
def test_ui_tls_rejects_wrong_identity_or_key(tmp_path, problem):
    san = {
        "dns-only": x509.DNSName("localhost"),
        "wrong-ip": x509.IPAddress(ipaddress.ip_address("127.0.0.2")),
    }.get(problem)
    cert, key = ui_certificate(tmp_path, san=san, expired=problem == "expired")
    if problem == "wrong-key":
        _, key = ui_certificate(tmp_path, name="other")
    with pytest.raises(ValueError, match="current UI certificate"):
        runtime.validate_ui_tls(cert, key)


@pytest.fixture
def native_ui(tmp_path, monkeypatch, snapshot):
    cert, key = ui_certificate(tmp_path)
    context = runtime.validate_ui_tls(cert, key)
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    runtime._publish({"tls": True, "permissions": False, "api_version": False})
    monkeypatch.setattr(runtime, "UI_PORT", 0)
    with runtime._StatusServer(ADMIN_TOKEN, context) as server:
        assert server.server_address[0] == "127.0.0.1"
        port = server.server_port
        host = f"127.0.0.1:{port}"
        monkeypatch.setattr(runtime, "_HOSTS", {host, f"localhost:{port}"})
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()

        def request(method, path, *, hosts=(host,), authorization=()):
            connection = http.client.HTTPSConnection(
                "127.0.0.1", port, timeout=2, context=ssl.create_default_context(cafile=str(cert))
            )
            try:
                connection.putrequest(method, path, skip_host=True)
                for name in hosts:
                    connection.putheader("Host", name)
                for value in authorization:
                    connection.putheader("Authorization", value)
                connection.endheaders()
                response = connection.getresponse()
                return response.status, dict(response.getheaders()), response.read()
            finally:
                connection.close()

        try:
            yield request, host
        finally:
            server.shutdown()
            thread.join(timeout=2)


def basic(identity):
    return "Basic " + base64.b64encode(identity.encode()).decode()


def test_ui_https_auth_host_and_read_only_status(native_ui, capsys):
    request, host = native_ui
    correct = (basic(f"admin:{ADMIN_TOKEN}"),)
    for authorization in ((), ("Basic ???",), (basic("admin:wrong"),), correct * 2):
        code, headers, body = request("GET", "/status", authorization=authorization)
        assert code == 401
        assert headers["WWW-Authenticate"].startswith("Basic ")
        assert not body
    for hosts in ((), (host, host), ("attacker.invalid",), ("127.0.0.1",)):
        assert request("GET", "/status", hosts=hosts, authorization=correct)[0] == 400
    assert request("GET", "/status?token=ignored", authorization=correct)[0] == 404
    assert request("GET", "/api2/json/version", authorization=correct)[0] == 404
    assert request("POST", "/status", authorization=correct)[0] == 501

    code, headers, body = request("GET", "/status", authorization=correct)
    assert code == 200
    assert headers["Content-Type"] == "application/json"
    assert headers["Cache-Control"] == "no-store"
    assert json.loads(body) == runtime._status()
    assert ADMIN_TOKEN.encode() not in body
    assert API_TOKEN.encode() not in body
    code, headers, body = request("GET", "/", authorization=correct)
    assert code == 200
    assert headers["Content-Type"].startswith("text/html")
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert b"unhealthy" in body
    assert ADMIN_TOKEN.encode() not in body
    assert API_TOKEN.encode() not in body
    assert capsys.readouterr() == ("", "")
