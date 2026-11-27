"""Synthetic PX03 response loss at the verified TLS boundary."""

import json
import ssl
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import quote

import pytest

from steward.core import pve_native
from steward.core.audit import AuditLog
from steward.core.pve_power import PowerJournal, PowerPolicy, RegisteredGuest
from steward.core.pve_provision import ProvisionedGuest, ProvisionPolicy
from steward.executor import pve_power, pve_provision
from steward.executor.protocol import ExecutorError
from steward.executor.pve_power_api import DISPATCH_TASK_WINDOW_S, PowerApi
from steward.executor.pve_provision_api import CLONE_TASK_WINDOW_S, ProvisionApi, ProvisionEvidence
from test_pve_native import API_NAME, API_TOKEN, write_certificate
from test_pve_power_api import (
    ACL,
    DISPATCH,
    NODE,
    RTIME,
    UID,
    VERSION,
    guest_evidence,
    guest_path,
    task_evidence,
)
from test_pve_power_executor import frame as power_frame
from test_pve_provision_api import DISPATCHED, NEW_UID, TOKEN, native_job, native_task
from test_pve_provision_executor import frame as provision_frame


@pytest.fixture
def wire(monkeypatch, tmp_path):
    cert, key = write_certificate(tmp_path, API_NAME)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    endpoint = SimpleNamespace(
        reads={VERSION: {"release": "9.3", "version": "9.3.1"}},
        posts=[],
        rejected=[],
        cert=cert,
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if (
                self.headers.get("Authorization") != endpoint.auth
                or self.path not in endpoint.reads
            ):
                endpoint.rejected.append(("GET", self.path))
                self.send_error(404)
                return
            envelope = {"data": endpoint.reads[self.path]}
            if self.path.endswith("/log?start=0&limit=500"):
                envelope["total"] = len(envelope["data"])
            payload = json.dumps(envelope).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            received = (self.path, self.rfile.read(length))
            if (
                self.headers.get("Authorization") != endpoint.auth
                or self.headers.get("Content-Type") != "application/x-www-form-urlencoded"
                or received != endpoint.expected_post
            ):
                endpoint.rejected.append(("POST", self.path))
                self.send_error(404)
                return
            # Read a separate journal at TLS receipt, then close without a response.
            endpoint.posts.append((received, endpoint.read_job()))
            self.close_connection = True

        def log_message(self, *_):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        monkeypatch.setattr(pve_native, "API_HOST", "127.0.0.1")
        monkeypatch.setattr(pve_native, "API_PORT", server.server_port)
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()
        try:
            yield endpoint
        finally:
            server.shutdown()
            thread.join(timeout=2)
    assert endpoint.rejected == []


def _call(executor, frame, action, **params):
    response = executor.handle(frame(action, **params))
    assert response["ok"], response
    return response["result"]


def _assert_lost_and_reopen(reopen, frame, plan, wire):
    initial = reopen()
    job_id = _call(initial, frame, "plan", **plan)["job_id"]
    wire.read_job = lambda: wire.lookup(job_id)
    lost = _call(initial, frame, "execute", job_id=job_id)
    assert (lost["state"], lost["error_code"]) == ("uncertain", "dispatch_unknown")
    [(request, durable)] = wire.posts
    assert request == wire.expected_post
    assert durable.job_id == job_id
    assert durable.state == "dispatching"
    [leg] = durable.legs
    assert (leg.state, leg.upid, leg.prior_upids) == ("dispatching", None, ())

    restarted = reopen()
    for action in ("status", "execute", "reconcile"):
        assert _call(restarted, frame, action, job_id=job_id) == lost
    return restarted, job_id, lost


def _assert_task_rejected(executor, frame, job_id, upid, lost, wire, error):
    response = executor.handle(frame("reconcile", job_id=job_id, upid=upid))
    assert (response["ok"], response["error_class"]) == (False, error)
    assert _call(executor, frame, "status", job_id=job_id) == lost
    assert wire.lookup(job_id).legs[0].upid is None


def _assert_replay(executor, frame, job_id, wire, upid, finished):
    assert finished["state"] == "succeeded"
    assert wire.lookup(job_id).legs[0].upid == upid
    assert _call(executor, frame, "execute", job_id=job_id) == finished
    assert len(wire.posts) == 1


def test_power_lost_tls_response_fences_shutdown(tmp_path, wire):
    policy = PowerPolicy(
        node=NODE,
        write_token_file="/unused/token",
        guests=(
            RegisteredGuest(
                kind="qemu", vmid=190, pve_uid=UID, registered_at_ms=RTIME, operations=("shutdown",)
            ),
        ),
    )
    wire.auth = f"PVEAPIToken={API_TOKEN}"
    wire.lookup = lambda job_id: PowerJournal(tmp_path).get(job_id)
    wire.expected_post = (f"{guest_path('qemu')}/status/shutdown", b"forceStop=0")
    wire.reads[ACL] = {"/vms/190": {"VM.Audit": 0, "VM.PowerMgmt": 0}}

    def set_state(state):
        reports = {}
        guest_evidence(reports, "qemu", state)
        wire.reads.update({path: data for path, (_, data) in reports.items()})

    set_state("running")
    start = int(DISPATCH)
    listing = (
        f"/api2/json/nodes/{NODE}/tasks?vmid=190&typefilter=qmshutdown"
        f"&source=all&limit=9&since={start}"
    )
    recovery = f"{listing}&until={start + DISPATCH_TASK_WINDOW_S}"
    wire.reads[listing] = wire.reads[recovery] = []

    def reopen():
        api = PowerApi(API_NAME, wire.cert, API_TOKEN)
        return pve_power.PowerExecutor(
            PowerJournal(tmp_path),
            AuditLog(tmp_path / "audit.jsonl"),
            lambda: pve_power._Authority(policy, "a" * 64, api),
            lambda: policy,
            lambda: False,
            lambda target: None,
            lambda target, state: None,
            lambda: datetime.fromtimestamp(DISPATCH, UTC),
        )

    resumed, job_id, lost = _assert_lost_and_reopen(
        reopen, power_frame, {"vmid": 190, "operation": "shutdown"}, wire
    )
    upid, task = task_evidence("qemu", "shutdown")
    _assert_task_rejected(resumed, power_frame, job_id, upid, lost, wire, "conflict")
    archived = {**task, "status": "OK", "endtime": start}
    wrong = upid.replace(":0000002A:", ":0000002B:")
    wire.reads[recovery] = [archived, {**archived, "upid": wrong, "pid": 43}]
    _assert_task_rejected(resumed, power_frame, job_id, upid, lost, wire, "conflict")
    wire.reads[recovery] = [archived]
    _assert_task_rejected(resumed, power_frame, job_id, wrong, lost, wire, "conflict")

    wire.reads[f"/api2/json/nodes/{NODE}/tasks/{quote(upid, safe='')}/status"] = task
    unfinished = _call(resumed, power_frame, "reconcile", job_id=job_id, upid=upid)
    assert (unfinished["state"], unfinished["error_code"]) == ("verifying", "state_mismatch")
    set_state("stopped")
    finished = _call(resumed, power_frame, "reconcile", job_id=job_id)
    assert finished["current_state"] == "stopped"
    _assert_replay(resumed, power_frame, job_id, wire, upid, finished)


@pytest.mark.parametrize(
    "kind,noun,name_key", [("qemu", "VM", "name"), ("lxc", "container", "hostname")]
)
def test_clone_lost_tls_response_fences_destination(tmp_path, wire, kind, noun, name_key):
    job, template = native_job(kind)
    source, target = job.source.vmid, job.target.vmid
    policy = ProvisionPolicy(
        node="pve",
        write_token_file="/unused/token",
        templates=(template,),
        targets=(job.destination,),
    )
    wire.auth = f"PVEAPIToken={TOKEN}"
    wire.lookup = lambda job_id: PowerJournal(tmp_path).get_provision(job_id)
    wire.expected_post = (
        f"/api2/json/nodes/pve/{kind}/{source}/clone",
        f"newid={target}&full=1&pool=rc2-managed&storage=local-lvm&{name_key}=clone-guest".encode(),
    )
    wire.reads[ACL] = {
        f"/vms/{source}": {"VM.Clone": 0, "VM.Audit": 0},
        f"/vms/{target}": {"VM.Allocate": 0},
        "/storage/local-lvm": {"Datastore.AllocateSpace": 0},
        "/sdn/zones/localnetwork/vmbr0": {"SDN.Use": 0},
    }
    upid, task = native_task(job)
    start = int(DISPATCHED)
    worker = task["type"]
    tasks = f"/api2/json/nodes/pve/tasks?vmid={source}&typefilter={worker}"
    listing = f"{tasks}&source=all&limit=9&since={start}"
    recovery = f"{listing}&until={start + CLONE_TASK_WINDOW_S}"
    archive = f"{tasks}&source=archive&limit=9&since={start}&until={start}"
    wire.reads[listing] = wire.reads[recovery] = wire.reads[archive] = []
    task_path = f"/api2/json/nodes/pve/tasks/{quote(upid, safe='')}"
    evidence = Mock(spec=ProvisionEvidence)
    evidence.observe_source.return_value = job.observation
    evidence.verify_target.side_effect = ExecutorError("conflict", "Readback mismatch.")

    def reopen():
        api = ProvisionApi(API_NAME, wire.cert, TOKEN)
        return pve_provision.ProvisionExecutor(
            PowerJournal(tmp_path),
            AuditLog(tmp_path / "audit.jsonl"),
            lambda: pve_provision._Authority(policy, "a" * 64, api),
            lambda: False,
            evidence,
            now=lambda: datetime.fromtimestamp(DISPATCHED, UTC),
        )

    resumed, job_id, lost = _assert_lost_and_reopen(
        reopen, provision_frame, {"template_vmid": source, "vmid": target, "name": job.name}, wire
    )
    _assert_task_rejected(resumed, provision_frame, job_id, upid, lost, wire, "conflict")
    archived = {**task, "status": "OK", "endtime": start + 5}
    wrong = upid.replace(":0000000A:", ":0000000C:")
    wire.reads[recovery] = [archived, {**archived, "upid": wrong, "pid": 12}]
    _assert_task_rejected(resumed, provision_frame, job_id, upid, lost, wire, "conflict")
    wire.reads[recovery] = [archived]
    wire.reads[f"{task_path}/status"] = {**task, "status": "stopped", "exitstatus": "OK"}
    log = f"{task_path}/log?start=0&limit=500"
    wire.reads[log] = [
        {"n": 1, "t": f"creating a clone of {noun} {source} with ID {target + 1}"},
        {"n": 2, "t": "TASK OK"},
    ]
    _assert_task_rejected(resumed, provision_frame, job_id, upid, lost, wire, "unavailable")
    wire.reads[log][0]["t"] = f"creating a clone of {noun} {source} with ID {target}"
    unfinished = _call(resumed, provision_frame, "reconcile", job_id=job_id, upid=upid)
    assert (unfinished["state"], unfinished["error_code"]) == ("verifying", "target_unverified")
    evidence.verify_target.assert_not_called()

    wire.reads[archive] = [archived]
    unfinished = _call(resumed, provision_frame, "reconcile", job_id=job_id)
    assert (unfinished["state"], unfinished["error_code"]) == ("verifying", "target_mismatch")
    evidence.verify_target.side_effect = None
    evidence.verify_target.return_value = ProvisionedGuest(
        pve_uid=NEW_UID, registered_at_ms=int(DISPATCHED * 1000) + 1
    )
    finished = _call(resumed, provision_frame, "reconcile", job_id=job_id)
    assert evidence.verify_target.call_args.kwargs == {
        "dispatched_at": DISPATCHED,
        "completed_at": start + 5,
    }
    assert finished["result"]["state"] == "stopped"
    _assert_replay(resumed, provision_frame, job_id, wire, upid, finished)
