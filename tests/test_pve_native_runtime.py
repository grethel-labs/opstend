import base64
import http.client
import ipaddress
import json
import ssl
import stat
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from steward import pve_native_runtime as runtime
from steward.core import pve_native
from steward.core.pve_inventory_models import (
    Evidence,
    Guest,
    InventorySnapshot,
    Node,
    NodeMeasurementObservation,
    NodeMeasurementPoint,
)
from test_pve_inventory import INDEX, NODE, READ_TOKEN, guest, payload
from test_pve_inventory import local_target as local_target
from test_pve_native import API_NAME, API_TOKEN, PERMISSIONS_PATH, VERSION_PATH
from test_pve_native import pve_api as pve_api
from test_pve_native import pve_tls as pve_tls
from test_pve_native import token_file as token_file

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
    state.mkdir(mode=0o750)
    boot = tmp_path / "boot-id"
    boot.write_text("boot-one")
    clock = [300.0]
    monkeypatch.setattr(runtime, "_STATE", state)
    monkeypatch.setattr(runtime, "_BOOT_ID", boot)
    monkeypatch.setattr(runtime, "_boottime", lambda: clock[0])
    return state / "status.json", boot, clock


@pytest.mark.parametrize("failure", [None, "tls", "permissions", "api_version"])
@pytest.mark.parametrize("bad_inventory_token", [False, True])
def test_agent_publishes_readiness_from_fixed_https_gets(
    tmp_path, monkeypatch, pve_api, snapshot, failure, bad_inventory_token
):
    ca, responses, calls = pve_api
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    (credentials / "pve-ca").write_bytes(ca.read_bytes())
    token = credentials / "pve-token"
    token.write_text(API_TOKEN)
    token.chmod(0o600)
    if bad_inventory_token:
        inventory_token = credentials / "pve-inventory-token"
        inventory_token.write_text("incomplete")
        inventory_token.chmod(0o600)
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
    assert runtime._inventory()["status"] == "unavailable"


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

        def request(method, path, *, hosts=(host,), authorization=(), accept=None):
            connection = http.client.HTTPSConnection(
                "127.0.0.1", port, timeout=2, context=ssl.create_default_context(cafile=str(cert))
            )
            try:
                connection.putrequest(method, path, skip_host=True)
                for name in hosts:
                    connection.putheader("Host", name)
                for value in authorization:
                    connection.putheader("Authorization", value)
                if accept is not None:
                    connection.putheader("Accept", accept)
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


def inventory_model(*, state="observed", rows=True):
    now = datetime.now(UTC)
    evidence = Evidence(source="cluster_resources", state=state, observed_at=now)
    node_rrd = NodeMeasurementObservation(
        evidence=Evidence(source="node_rrd", state="observed", observed_at=now),
        items=(NodeMeasurementPoint(time=now, cpu_fraction=0.25, memory_bytes=512),),
    )
    return InventorySnapshot(
        api_name=API_NAME,
        observed_at=now,
        evidence=evidence,
        nodes=(Node(node="local", evidence=evidence, uptime_seconds=18, measurements=node_rrd),)
        if rows
        else (),
        guests=(
            Guest(
                node="local",
                vmid=321,
                kind="qemu",
                name="visible",
                evidence=evidence,
                pve_uid="a" * 20,
                registered_at_ms=100,
            ),
            Guest(node="local", vmid=322, kind="lxc", name="container", evidence=evidence),
        )
        if rows
        else (),
    )


def test_inventory_ui_auth_and_scoped_snapshot(native_ui, snapshot, monkeypatch):
    request, host = native_ui
    correct = (basic(f"admin:{ADMIN_TOKEN}"),)
    _, boot, clock = snapshot
    payload = inventory_model()
    runtime._publish_inventory(payload, clock[0])
    with monkeypatch.context() as auth_check:

        def forbid_snapshot(*args):
            pytest.fail("Unauthenticated requests must not read inventory")

        auth_check.setattr(runtime, "_inventory", forbid_snapshot)
        for path in ("/inventory", "/guests/321"):
            assert request("GET", path)[0] == 401
            assert request("GET", path, hosts=("evil.invalid",), authorization=correct)[0] == 400
    for path in ("/inventory?vmid=321", "/guests/0321", "/guests/321/config", "/guests/%33%32%31"):
        assert request("GET", path, authorization=correct)[0] == 404
    assert request("POST", "/guests/321", authorization=correct)[0] == 501
    assert b'href="/inventory"' in request("GET", "/", authorization=correct)[2]
    code, headers, body = request("GET", "/inventory", authorization=correct)
    assert code == 200
    assert headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert b'href="/guests/321"' in body
    assert b'href="/guests/322"' in body
    assert b"node_rrd" in body
    assert b"<dt>Uptime seconds</dt><dd>18</dd>" in body
    assert b"<dt>Cpu fraction</dt><dd>0.25</dd>" in body
    detail = request("GET", "/guests/321", authorization=correct)[2]
    assert b"visible" in detail
    assert b"guest agent data unprobed" in detail
    assert b"aaaaaaaaaaaaaaaaaaaa" not in detail
    assert b"container" not in detail
    hidden = request("GET", "/guests/777", authorization=correct)
    unknown = request("GET", "/guests/888", authorization=correct)
    assert hidden[0] == unknown[0] == 200
    assert hidden[2] == unknown[2]
    assert b"No guest was visible" in hidden[2]
    assert runtime._inventory(777) == runtime._inventory(888)

    clock[0] += 90
    assert b"expired" in request("GET", "/inventory", authorization=correct)[2]
    assert runtime._inventory()["guests"] == []
    clock[0] = 1
    boot.write_text("boot-two")
    assert runtime._inventory(321)["status"] == "stale"
    assert runtime._inventory(321)["guest"] is None
    runtime._publish_inventory(inventory_model(state="absent", rows=False), clock[0])
    assert b"No resources were observed" in request("GET", "/inventory", authorization=correct)[2]
    assert b"No guest was visible" in request("GET", "/guests/321", authorization=correct)[2]

    assert runtime._html_fields({"<label>": "<script>&"}) == (
        "<dl><dt>&lt;label&gt;</dt><dd>&lt;script&gt;&amp;</dd></dl>"
    )


def test_inventory_json_uses_same_authenticated_projection(native_ui, snapshot, monkeypatch):
    request, _ = native_ui
    _, _, clock = snapshot
    runtime._publish_inventory(inventory_model(), clock[0])
    authorized = {"authorization": (basic(f"admin:{ADMIN_TOKEN}"),), "accept": "application/json"}

    def unexpected_read(*args):
        pytest.fail("Unauthorized JSON requests must not read inventory")

    with monkeypatch.context() as patch:
        patch.setattr(runtime, "_inventory", unexpected_read)
        for path in ("/inventory", "/guests/321"):
            assert request("GET", path, accept="application/json")[0] == 401
            assert request("GET", path, hosts=("wrong.invalid",), **authorized)[0] == 400

    for path, vmid in (("/inventory", None), ("/guests/321", 321)):
        code, headers, body = request("GET", path, **authorized)
        assert code == 200
        assert headers["Content-Type"] == "application/json"
        assert headers["Cache-Control"] == "no-store"
        assert headers["Vary"] == "Accept"
        assert json.loads(body) == runtime._inventory(vmid)

    hidden = request("GET", "/guests/777", **authorized)
    missing = request("GET", "/guests/888", **authorized)
    assert hidden[0] == missing[0] == 200
    assert hidden[2] == missing[2]
    assert json.loads(hidden[2])["status"] == "restricted"
    assert json.loads(hidden[2])["guest"] is None

    clock[0] += 90
    expired = json.loads(request("GET", "/inventory", **authorized)[2])
    assert expired["status"] == "stale"
    assert expired["guests"] == []


def test_inventory_refresh_barrier_drops_rows_and_cleans_abandoned_staging(
    snapshot,
    monkeypatch,
):
    status_path, _, clock = snapshot
    inventory_path = status_path.with_name("inventory.json")
    staging = inventory_path.with_name(".inventory.tmp")
    runtime._publish_inventory(inventory_model(), clock[0])
    assert runtime._inventory(321)["guest"]["kind"] == "qemu"
    staging.write_text("interrupted staging file")
    target = runtime.RegisteredLocalTarget(API_NAME, inventory_path, inventory_path, inventory_path)

    def deny(registered):
        assert registered is target
        assert runtime._inventory(321)["status"] == "unavailable"
        assert runtime._inventory(321)["guest"] is None
        return inventory_model(state="restricted")

    monkeypatch.setattr(runtime, "collect_inventory", deny)
    runtime._refresh_inventory(target)
    assert runtime._inventory(321) == runtime._inventory(777)
    assert runtime._inventory()["status"] == "restricted"
    assert runtime._inventory()["guests"] == []
    assert "visible" not in inventory_path.read_text()
    assert not staging.exists()
    assert stat.S_IMODE(inventory_path.stat().st_mode) == 0o640

    runtime._publish_inventory(inventory_model(), clock[0])

    def interrupted(registered):
        assert runtime._inventory()["guests"] == []
        raise ValueError("Incomplete collection")

    monkeypatch.setattr(runtime, "collect_inventory", interrupted)
    runtime._refresh_inventory(target)
    assert runtime._inventory()["status"] == "unavailable"
    assert "visible" not in inventory_path.read_text()

    runtime._publish_inventory(inventory_model(), clock[0])

    def fail_barrier(*args):
        raise OSError("Could not create marker")

    monkeypatch.setattr(runtime, "_publish_inventory", fail_barrier)
    monkeypatch.setattr(runtime, "collect_inventory", lambda target: pytest.fail("No barrier"))
    runtime._refresh_inventory(target)
    assert not inventory_path.exists()
    assert runtime._inventory()["status"] == "unavailable"


def test_inventory_refreshes_from_scoped_local_https(native_ui, local_target, snapshot):
    target, responses, calls = local_target
    request, _ = native_ui
    correct = (basic(f"admin:{ADMIN_TOKEN}"),)
    runtime._refresh_inventory(target)
    status_path, _, _ = snapshot
    persisted = status_path.with_name("inventory.json").read_text()
    for secret in (READ_TOKEN, API_TOKEN, "secret-config-canary", "principal-canary@pam"):
        assert secret not in persisted
    assert all(auth == f"PVEAPIToken={READ_TOKEN}" for _, _, auth in calls)
    overview = request("GET", "/inventory", authorization=correct)[2]
    assert all(text in overview for text in (b"guest-190", b"guest-191", b"local-lvm", b"node_rrd"))
    guest_detail = request("GET", "/guests/190", authorization=correct)[2]
    assert all(text in guest_detail for text in (b"vmbr0", b"123", b"guest_rrd", b"succeeded"))

    # Simulate removing one guest's audit permission while leaving another
    # visible. Even if the fixture roster returns the revoked row, it is hidden.
    responses[PERMISSIONS_PATH] = payload(
        {f"/nodes/{NODE}": {"Sys.Audit": 0}, "/vms/191": {"VM.Audit": 0}}
    )
    responses[INDEX] = payload([guest("qemu", 190), guest("lxc", 191)])
    runtime._refresh_inventory(target)
    overview = request("GET", "/inventory", authorization=correct)[2]
    assert b"guest-190" not in overview
    assert b"guest-191" in overview
    assert (
        request("GET", "/guests/190", authorization=correct)[2]
        == request("GET", "/guests/999", authorization=correct)[2]
    )
    responses[PERMISSIONS_PATH] = (403, b'{"data":null}')
    runtime._refresh_inventory(target)
    assert b"lacks access" in request("GET", "/inventory", authorization=correct)[2]
    assert runtime._inventory()["guests"] == []


@pytest.mark.parametrize(
    ("endpoint", "response", "state"),
    [
        (VERSION_PATH, payload({"version": "9.3.2", "release": "9.3"}), "unsupported"),
        (INDEX, (429, b"raw-throttle-canary"), "rate_limited"),
    ],
)
def test_unavailable_inventory_replaces_public_rows(
    local_target, snapshot, endpoint, response, state
):
    target, responses, _ = local_target
    runtime._refresh_inventory(target)
    assert runtime._inventory(190)["guest"]["vmid"] == 190

    responses[endpoint] = response
    runtime._refresh_inventory(target)
    overview = runtime._inventory()
    assert overview["status"] == "unavailable"
    assert overview["evidence"]["state"] == state
    assert not any(overview[field] for field in ("nodes", "guests", "pools", "datastores"))
    assert runtime._inventory(190)["guest"] is None
    status_path, _, _ = snapshot
    persisted = status_path.with_name("inventory.json").read_text()
    assert "raw-throttle-canary" not in persisted
    assert "guest-190" not in persisted


def test_interrupted_https_refresh_is_cleared_until_fresh_process_refills(local_target, snapshot):
    target, responses, calls = local_target
    status_path, boot, clock = snapshot
    inventory_path = status_path.with_name("inventory.json")
    runtime._refresh_inventory(target)
    assert runtime._inventory(190)["guest"]["vmid"] == 190

    entered = threading.Event()
    release = threading.Event()
    roster = responses[INDEX]

    def pause_roster():
        entered.set()
        release.wait(timeout=5)
        return roster

    child = """\
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from steward import pve_native_runtime as runtime
from steward.core import pve_native

source, state, boot, clock, port, api_name, ca, inventory_token, health_token = sys.argv[1:]
runtime._STATE = Path(state)
runtime._BOOT_ID = Path(boot)
runtime._boottime = lambda: float(clock)
pve_native.API_PORT = int(port)
runtime._refresh_inventory(
    runtime.RegisteredLocalTarget(api_name, Path(ca), Path(inventory_token), Path(health_token))
)
"""
    command = [
        sys.executable,
        "-c",
        child,
        str(Path(runtime.__file__).resolve().parents[1]),
        str(status_path.parent),
        str(boot),
        str(clock[0]),
        str(pve_native.API_PORT),
        target.api_name,
        str(target.ca_file),
        str(target.inventory_token_file),
        str(target.health_token_file),
    ]
    responses[INDEX] = pause_roster
    with subprocess.Popen(command) as process:  # noqa: S603
        try:
            assert entered.wait(timeout=5)
            assert process.poll() is None
            assert calls[-1][1] == INDEX
            assert runtime._inventory()["status"] == "unavailable"
            assert runtime._inventory(190)["guest"] is None
            assert json.loads(inventory_path.read_text())["inventory"] is None
        finally:
            if process.poll() is None:
                process.kill()
            release.set()
        assert process.wait(timeout=5) < 0
    assert runtime._inventory()["status"] == "unavailable"

    responses[INDEX] = payload([guest("lxc", 191)])
    calls.clear()
    subprocess.run(command, check=True, timeout=10)  # noqa: S603
    assert runtime._inventory()["status"] == "observed"
    assert runtime._inventory(190)["guest"] is None
    assert runtime._inventory(191)["guest"]["vmid"] == 191
    assert [path for _, path, _ in calls].count(VERSION_PATH) == 2


@pytest.mark.parametrize("problem", ["symlink", "directory", "mode", "duplicate", "fields", "size"])
def test_inventory_rejects_unsafe_state(snapshot, monkeypatch, problem):
    status_path, _, clock = snapshot
    path = status_path.with_name("inventory.json")
    runtime._publish_inventory(inventory_model(), clock[0])
    if problem == "symlink":
        other = path.rename(path.with_name("other"))
        path.symlink_to(other)
    elif problem == "directory":
        path.unlink()
        path.mkdir()
    elif problem == "mode":
        path.chmod(0o666)
    elif problem == "duplicate":
        path.write_text('{"inventory": null, "inventory": {}}')
    elif problem == "fields":
        payload = json.loads(path.read_text())
        payload["inventory"]["guests"][0]["raw_config"] = API_TOKEN
        path.write_text(json.dumps(payload))
    else:
        monkeypatch.setattr(runtime, "_INVENTORY_LIMIT", 1)
    assert runtime._inventory(321)["status"] == "unavailable"
    assert runtime._inventory(321)["guest"] is None


def test_inventory_cli_is_root_only_and_validates_guest_selector(snapshot, monkeypatch):
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 1000)
    with pytest.raises(ValueError, match="as root"):
        runtime.read_inventory()
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0)
    for vmid in (False, 99, "321", 1_000_000_000):
        with pytest.raises(ValueError, match="PVE guest ID"):
            runtime.read_inventory(vmid)
    runtime._publish_inventory(inventory_model(), runtime._boottime())
    assert runtime.read_inventory(321)["guest"]["name"] == "visible"


def test_inventory_systemd_credentials_are_optional_and_agent_only(tmp_path):
    args = {
        "api_name": API_NAME,
        "ca_file": tmp_path / "ca",
        "token_file": tmp_path / "health",
        "admin_token_file": tmp_path / "admin",
        "ui_cert_file": tmp_path / "cert",
        "ui_key_file": tmp_path / "key",
    }
    token = tmp_path / "inventory"
    assert "pve-inventory-token" not in runtime.render_unit("agent", **args)
    agent = runtime.render_unit("agent", inventory_token_file=token, **args)
    assert (
        f"SetCredential=pve-inventory-token:\nLoadCredential=pve-inventory-token:{token}\n" in agent
    )
    assert "pve-inventory-token" not in runtime.render_unit(
        "ui", inventory_token_file=token, **args
    )
    with pytest.raises(ValueError, match="safe characters"):
        runtime.render_unit("agent", inventory_token_file=tmp_path / "unsafe file", **args)
