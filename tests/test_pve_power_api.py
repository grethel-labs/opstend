import json
import ssl
import threading
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from steward.core import pve_native as native
from steward.core.pve_power import GuestTarget
from steward.executor import pve_power_api
from steward.executor.protocol import ExecutorError
from steward.executor.pve_power_api import PowerApi
from test_pve_native import API_NAME, API_TOKEN, write_certificate

ACTOR = API_TOKEN.partition("=")[0]
USER, TOKEN_ID = ACTOR.split("!")
NODE = "px03"
UID = "abcdefghijklmnopqrst"
RTIME = 1_700_000_000_000
DISPATCH = 1_800_000_000.9
ROSTER = "/api2/json/cluster/resources?type=vm"
VERSION = "/api2/json/version"
ACL = "/api2/json/access/permissions"


def guest_path(kind, vmid=190):
    return f"/api2/json/nodes/{NODE}/{kind}/{vmid}"


def task_evidence(kind, operation, vmid=190, actor=ACTOR, started=int(DISPATCH)):
    worker = ("qm" if kind == "qemu" else "vz") + operation
    upid = f"UPID:{NODE}:0000002A:100000001:{started:08X}:{worker}:{vmid}:{actor}:"
    return upid, {
        "upid": upid,
        "node": NODE,
        "type": worker,
        "id": str(vmid),
        "user": USER,
        "tokenid": TOKEN_ID,
        "pid": 42,
        "pstart": 0x100000001,
        "starttime": started,
        "status": "stopped",
        "exitstatus": "OK",
    }


@pytest.fixture
def api_stub(monkeypatch):
    calls = []
    responses = {
        VERSION: (200, {"release": "9.3", "version": "9.3.1"}),
        ACL: (200, {"/vms/190": {"VM.Audit": 0, "VM.PowerMgmt": 0}}),
    }

    def request(name, context, token, path, *, deadline, max_response, method, body):
        assert name == API_NAME
        assert token == API_TOKEN
        assert max_response == 256 * 1024
        calls.append((method, path, body))
        response = responses[path]
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(native, "_api_context", lambda path: None)
    monkeypatch.setattr(native, "_request_api_response", request)
    return PowerApi(API_NAME, Path("/unused"), API_TOKEN), responses, calls


@pytest.mark.parametrize(
    "permissions",
    [
        {},
        {"/vms": {"VM.Audit": 1}},
        {"/vms/190": {"VM.Audit": 0, "VM.PowerMgmt": 0}, "/pool/pool-a": {"VM.Audit": 0}},
        {"/vms/190": {"VM.Audit": 0, "VM.PowerMgmt": 0}, "/vms/999": {"VM.PowerMgmt": 0}},
        {"/vms/190": {"VM.Audit": 0, "VM.PowerMgmt": 0, "VM.Config.Options": 0}},
        {"/vms/190": {"VM.Audit": 0}},
        {"/vms/190": {"VM.Audit": False, "VM.PowerMgmt": 0}},
    ],
)
def test_permissions_rejects_wrong_paths_or_privileges(api_stub, permissions):
    api, responses, calls = api_stub
    policy = SimpleNamespace(node=NODE, guests=(GuestTarget(node=NODE, kind="qemu", vmid=190),))
    api.validate_permissions(policy)
    responses[ACL] = 200, permissions
    with pytest.raises(ExecutorError, match="policy_denied"):
        api.validate_permissions(policy)
    responses[VERSION] = 200, {"release": "9.3", "version": "9.3.2"}
    with pytest.raises(ExecutorError, match="policy_denied"):
        api.validate_permissions(policy)
    assert calls == [("GET", path, b"") for path in (VERSION, ACL, VERSION, ACL, VERSION)]


def guest_evidence(responses, kind, state="running"):
    roster = {
        "id": f"{kind}/190",
        "type": kind,
        "node": NODE,
        "vmid": 190,
        "uid": UID,
        "rtime": RTIME,
        "status": "unknown",
    }
    detail = {"vmid": 190, "uid": UID, "status": state, "ha": {"managed": 0}}
    if kind == "qemu":
        detail["qmpstatus"] = state
    if state == "running":
        detail["pid"] = 1234
    path = guest_path(kind)
    responses.update(
        {
            ROSTER: (200, [roster]),
            f"{path}/status/current": (200, detail),
            f"{path}/pending": (200, [{"key": "cores", "value": 1}]),
        }
    )
    return roster, detail


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
@pytest.mark.parametrize("state", ["running", "stopped"])
def test_observe_exact_generation_and_current_state(api_stub, kind, state):
    api, responses, calls = api_stub
    guest_evidence(responses, kind, state)
    observed = api.observe(GuestTarget(node=NODE, kind=kind, vmid=190))
    assert observed.pve_uid == UID
    assert observed.registered_at_ms == RTIME
    assert observed.state == state
    assert observed.pid == (1234 if state == "running" else None)
    assert calls == [
        ("GET", ROSTER, b""),
        ("GET", f"{guest_path(kind)}/status/current", b""),
        ("GET", f"{guest_path(kind)}/pending", b""),
    ]


@pytest.mark.parametrize(
    ("source", "changes"),
    [
        ("roster", {"node": "other"}),
        ("roster", {"type": "lxc"}),
        ("roster", {"id": "lxc/190"}),
        ("roster", {"vmid": "190"}),
        ("roster", {"rtime": str(RTIME)}),
        ("roster", {"hastate": "disabled"}),
        ("roster", {"lock": "backup"}),
        ("detail", {"vmid": 191}),
        ("detail", {"uid": "b" * 20}),
        ("detail", {"ha": None}),
        ("detail", {"ha": {"managed": 1}}),
        ("detail", {"ha": {"managed": "unknown"}}),
        ("detail", {"ha": {}}),
        ("detail", {"status": "suspended"}),
        ("detail", {"qmpstatus": "paused"}),
        ("detail", {"pid": 0}),
        ("detail", {"pid": "1234"}),
        ("detail", {"status": "stopped", "qmpstatus": "stopped", "pid": 4}),
        ("detail", {"template": 1}),
        ("detail", {"lock": "suspended"}),
    ],
)
def test_observe_fails_closed_on_guest_disagreement(api_stub, source, changes):
    api, responses, _ = api_stub
    roster, detail = guest_evidence(responses, "qemu")
    (roster if source == "roster" else detail).update(changes)
    with pytest.raises(ExecutorError, match="policy_denied"):
        api.observe(GuestTarget(node=NODE, kind="qemu", vmid=190))


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
@pytest.mark.parametrize("change", [{"pending": ""}, {"pending": 2}, {"delete": 2}])
def test_observe_refuses_pending_changes(api_stub, kind, change):
    api, responses, _ = api_stub
    guest_evidence(responses, kind)
    responses[f"{guest_path(kind)}/pending"] = (200, [{"key": "cores", "value": 1} | change])
    with pytest.raises(ExecutorError, match="policy_denied"):
        api.observe(GuestTarget(node=NODE, kind=kind, vmid=190))


def test_local_pending_requires_root_and_exact_node_and_detects_hidden_change(monkeypatch):
    target = GuestTarget(node=NODE, kind="lxc", vmid=190)
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return b'[{"key":"env","pending":"fixture-secret"}]'

    monkeypatch.setattr(pve_power_api, "run_bounded", run)
    monkeypatch.setattr(pve_power_api.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(pve_power_api.socket, "gethostname", lambda: f"{NODE}.invalid")
    with pytest.raises(ExecutorError, match="policy_denied"):
        pve_power_api.verify_local_pending(target)
    monkeypatch.setattr(pve_power_api.os, "geteuid", lambda: 0)
    monkeypatch.setattr(pve_power_api.socket, "gethostname", lambda: "other.invalid")
    with pytest.raises(ExecutorError, match="policy_denied"):
        pve_power_api.verify_local_pending(target)
    assert calls == []
    monkeypatch.setattr(pve_power_api.socket, "gethostname", lambda: f"{NODE}.invalid")
    with pytest.raises(ExecutorError, match="policy_denied") as error:
        pve_power_api.verify_local_pending(target)
    assert "fixture-secret" not in str(error.value)
    [(argv, options)] = calls
    assert argv == [
        "/usr/bin/pvesh",
        "--noproxy",
        "get",
        f"/nodes/{NODE}/lxc/190/pending",
        "--output-format",
        "json",
    ]
    assert options["max_bytes"] == 256 * 1024
    assert options["timeout"] == 2


@pytest.mark.parametrize(
    ("observed", "expected", "error"),
    [
        (b"RUNNING\n", "running", None),
        (b"FROZEN\n", "running", "policy_denied"),
        (b"STOPPED\n", "running", "policy_denied"),
        (b"RUNNING\nFROZEN\n", "running", "unavailable"),
    ],
)
def test_local_lxc_state_requires_exact_native_state(monkeypatch, observed, expected, error):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return observed

    monkeypatch.setattr(pve_power_api, "run_bounded", run)
    monkeypatch.setattr(pve_power_api.os, "geteuid", lambda: 0)
    monkeypatch.setattr(pve_power_api.socket, "gethostname", lambda: NODE)
    target = GuestTarget(node=NODE, kind="lxc", vmid=190)
    if error:
        with pytest.raises(ExecutorError, match=error):
            pve_power_api.verify_local_lxc_state(target, expected)
    else:
        pve_power_api.verify_local_lxc_state(target, expected)
    pve_power_api.verify_local_lxc_state(GuestTarget(node=NODE, kind="qemu", vmid=190), expected)
    [(argv, options)] = calls
    assert argv == ["/usr/bin/lxc-info", "-n", "190", "-sH"]
    assert options["max_bytes"] == 64


def test_stopped_lxc_does_not_require_a_runtime_record(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("A configured but never-started container can lack a runtime record")

    monkeypatch.setattr(pve_power_api, "run_bounded", unexpected)
    target = GuestTarget(node=NODE, kind="lxc", vmid=195)
    pve_power_api.verify_local_lxc_state(target, "stopped")


def recent_task_path(until=None):
    path = (
        f"/api2/json/nodes/{NODE}/tasks?vmid=190&typefilter=vzshutdown"
        f"&source=all&limit=9&since={int(DISPATCH)}"
    )
    return path if until is None else f"{path}&until={until}"


def test_recent_tasks_scopes_both_returned_actor_shapes(api_stub):
    api, responses, calls = api_stub
    target = GuestTarget(node=NODE, kind="lxc", vmid=190)
    first, archived = task_evidence("lxc", "shutdown")
    until = int(DISPATCH) + 1
    second, active = task_evidence("lxc", "shutdown", started=until)
    active["user"] = ACTOR
    del active["tokenid"]
    responses[recent_task_path(until)] = (200, [archived, active])
    responses[recent_task_path()] = (200, [])
    assert api.recent_tasks(target, "shutdown", since=int(DISPATCH), until=until) == (first, second)
    assert api.recent_tasks(target, "shutdown", since=int(DISPATCH)) == ()
    assert calls == [("GET", path, b"") for path in (recent_task_path(until), recent_task_path())]


@pytest.mark.parametrize(
    "rows",
    [
        [{}],
        [task_evidence("lxc", "shutdown", actor="other@pam!power")[1]],
        [task_evidence("lxc", "shutdown", started=int(DISPATCH) + 2)[1]],
        [task_evidence("lxc", "shutdown")[1] | {"starttime": str(int(DISPATCH))}],
        [task_evidence("lxc", "shutdown")[1] | {"tokenid": "other"}],
        [task_evidence("lxc", "shutdown")[1]] * 2,
        [task_evidence("lxc", "shutdown")[1]] * 9,
    ],
)
def test_recent_tasks_refuses_ambiguous_or_incomplete_evidence(api_stub, rows):
    api, responses, _ = api_stub
    target = GuestTarget(node=NODE, kind="lxc", vmid=190)
    until = int(DISPATCH) + 1
    responses[recent_task_path(until)] = (200, rows)
    with pytest.raises(ExecutorError, match="unavailable"):
        api.recent_tasks(target, "shutdown", since=int(DISPATCH), until=until)


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
@pytest.mark.parametrize("operation", ["start", "shutdown"])
def test_dispatch_and_poll_typed_worker_evidence(api_stub, kind, operation):
    api, responses, calls = api_stub
    target = GuestTarget(node=NODE, kind=kind, vmid=190)
    upid, evidence = task_evidence(kind, operation)
    dispatch_path = f"{guest_path(kind)}/status/{operation}"
    task_path = f"/api2/json/nodes/{NODE}/tasks/{quote(upid, safe='')}/status"
    responses[dispatch_path] = (200, upid)
    responses[task_path] = (200, evidence)
    assert api.actor == ACTOR
    assert api.dispatch(target, operation, dispatched_at=DISPATCH) == upid
    assert api.task(target, operation, upid, dispatched_at=DISPATCH) == "succeeded"
    evidence["exitstatus"] = "WARNINGS: 1"
    assert api.task(target, operation, upid, dispatched_at=DISPATCH) == "failed"
    del evidence["exitstatus"]
    evidence["status"] = "running"
    assert api.task(target, operation, upid, dispatched_at=DISPATCH) == "running"
    evidence["tokenid"] = "different"
    with pytest.raises(ExecutorError, match="unavailable"):
        api.task(target, operation, upid, dispatched_at=DISPATCH)
    assert calls == [
        ("POST", dispatch_path, b"" if operation == "start" else b"forceStop=0"),
        *[("GET", task_path, b"")] * 4,
    ]


@pytest.mark.parametrize(
    ("response", "classification", "unknown"),
    [
        ((401, None), "policy_denied", False),
        ((403, None), "policy_denied", False),
        ((302, None), "unavailable", True),
        ((400, None), "unavailable", True),
        ((500, None), "unavailable", True),
        ((200, task_evidence("qemu", "start", actor="other@pam!power")[0]), "unavailable", True),
        ((200, task_evidence("qemu", "start", started=int(DISPATCH) - 1)[0]), "unavailable", True),
        ((200, task_evidence("qemu", "start", started=int(DISPATCH) + 3)[0]), "unavailable", True),
        ((200, task_evidence("lxc", "start")[0]), "unavailable", True),
        ((200, task_evidence("qemu", "shutdown")[0]), "unavailable", True),
        ((200, task_evidence("qemu", "start", vmid=191)[0]), "unavailable", True),
        (native._ApiPayloadError(API_TOKEN), "unavailable", True),
        (native._ApiReadError(API_TOKEN), "unavailable", True),
        (OSError(API_TOKEN), "unavailable", True),
        (ssl.SSLCertVerificationError(API_TOKEN), "unavailable", False),
    ],
)
def test_dispatch_never_retries_or_exposes_api_errors(api_stub, response, classification, unknown):
    api, responses, calls = api_stub
    path = f"{guest_path('qemu')}/status/start"
    responses[path] = response
    with pytest.raises(ExecutorError) as error:
        api.dispatch(GuestTarget(node=NODE, kind="qemu", vmid=190), "start", dispatched_at=DISPATCH)
    assert error.value.error_class == classification
    assert error.value.outcome_unknown is unknown
    assert API_TOKEN not in str(error.value)
    assert error.value.__cause__ is None
    assert calls == [("POST", path, b"")]


def test_real_verified_tls_power_request(monkeypatch, tmp_path):
    upid, evidence = task_evidence("lxc", "shutdown")
    status_path = f"/api2/json/nodes/{NODE}/tasks/{quote(upid, safe='')}/status"
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def record(self, response):
            length = self.headers.get("Content-Length")
            body = self.rfile.read(int(length)) if length else b""
            calls.append(
                (
                    self.command,
                    self.path,
                    self.headers.get("Authorization"),
                    self.headers.get("Content-Type"),
                    length,
                    body,
                )
            )
            payload = json.dumps({"data": response}).encode()
            with suppress(BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        def do_POST(self):  # noqa: N802
            self.record(upid)

        def do_GET(self):  # noqa: N802
            self.record(evidence)

        def log_message(self, *_):
            pass

    cert, key = write_certificate(tmp_path, API_NAME)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        monkeypatch.setattr(native, "API_PORT", server.server_port)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()
        target = GuestTarget(node=NODE, kind="lxc", vmid=190)
        try:
            api = PowerApi(API_NAME, cert, API_TOKEN)
            assert api.dispatch(target, "shutdown", dispatched_at=DISPATCH) == upid
            assert api.task(target, "shutdown", upid, dispatched_at=DISPATCH) == "succeeded"
            bad_name = PowerApi("wrong.invalid", cert, API_TOKEN)
            with pytest.raises(ExecutorError, match="unavailable") as error:
                bad_name.dispatch(target, "shutdown", dispatched_at=DISPATCH)
            assert not error.value.outcome_unknown
        finally:
            server.shutdown()
            thread.join(timeout=2)

    auth = f"PVEAPIToken={API_TOKEN}"
    assert calls == [
        (
            "POST",
            f"{guest_path('lxc')}/status/shutdown",
            auth,
            "application/x-www-form-urlencoded",
            "11",
            b"forceStop=0",
        ),
        ("GET", status_path, auth, None, None, b""),
    ]
