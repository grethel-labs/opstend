import json
import ssl
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

import pytest

from steward.core.pve_power import GuestTarget
from steward.core.pve_provision import (
    CloneProfile,
    ProvisionJob,
    ProvisionLimits,
    ProvisionNetwork,
    ProvisionPolicy,
    ProvisionTarget,
    ProvisionTemplate,
    TemplateEvidence,
)
from steward.executor import pve_provision_api as module
from steward.executor.protocol import ExecutorError
from test_pve_native import write_certificate

ACTOR = "clone@pve!clone"
TOKEN = ACTOR + "=01234567-0123-4567-89ab-0123456789ab"
DISPATCHED = 1_796_000_000.25
UID = "abcdefghijklmnopqrst"
NEW_UID = "bcdefghijklmnopqrstu"
DIGEST = "a" * 40


def native_job(kind):
    source_id, target_id = (194, 196) if kind == "qemu" else (195, 197)
    source = GuestTarget(node="pve", kind=kind, vmid=source_id)
    target = GuestTarget(node="pve", kind=kind, vmid=target_id)
    template = ProvisionTemplate(
        kind=kind, vmid=source_id, pve_uid=UID, registered_at_ms=100, config_digest=DIGEST
    )
    network = ProvisionNetwork(index=0, bridge="vmbr0", link_down=True)
    profile = CloneProfile(
        vcpus=1,
        memory_mib=384 if kind == "qemu" else 256,
        disk_bytes=(3 if kind == "qemu" else 2) << 30,
        swap_mib=0 if kind == "qemu" else 64,
        networks=(network,),
    )
    destination = ProvisionTarget(
        vmid=target_id,
        template_vmid=source_id,
        pool="rc2-managed",
        storage="local-lvm",
        networks=(network,),
        limits=ProvisionLimits(
            max_vcpus=1, max_memory_mib=384, max_disk_bytes=3 << 30, max_swap_mib=64
        ),
    )
    now = datetime.fromtimestamp(DISPATCHED, UTC)
    job = ProvisionJob(
        job_id=uuid4().hex,
        target=target,
        source=source,
        destination=destination,
        name="clone-guest",
        observation=TemplateEvidence(
            pve_uid=UID, registered_at_ms=100, config_digest=DIGEST, profile=profile
        ),
        policy_revision="b" * 64,
        binding="c" * 64,
        created_at=now,
        expires_at=now + timedelta(minutes=2),
        updated_at=now,
        state="prepared",
    )
    return job, template


def native_task(job, *, delay=0):
    source = job.source
    worker = "qmclone" if source.kind == "qemu" else "vzclone"
    start = int(DISPATCHED) + delay
    upid = f"UPID:pve:0000000A:0000000B:{start:08X}:{worker}:{source.vmid}:{ACTOR}:"
    fields = {
        "upid": upid,
        "node": "pve",
        "type": worker,
        "id": str(source.vmid),
        "user": "clone@pve",
        "tokenid": "clone",
        "pid": 10,
        "pstart": 11,
        "starttime": start,
    }
    return upid, fields


def api(monkeypatch):
    monkeypatch.setattr(module.native, "_api_context", lambda _: None)
    return module.ProvisionApi("pve.example", Path("/unused"), TOKEN)


@pytest.mark.parametrize("kind,name_key", [("qemu", "name"), ("lxc", "hostname")])
def test_dispatch_has_one_fixed_full_clone_post(monkeypatch, kind, name_key):
    job, _ = native_job(kind)
    upid, _ = native_task(job)

    def request(api_name, context, token, path, **options):
        assert api_name == "pve.example" and token == TOKEN
        assert path == f"/api2/json/nodes/pve/{kind}/{job.source.vmid}/clone"
        assert options["method"] == "POST"
        assert (
            options["body"]
            == (
                f"newid={job.target.vmid}&full=1&pool=rc2-managed&storage=local-lvm&{name_key}=clone-guest"
            ).encode()
        )
        return 200, upid

    client = api(monkeypatch)
    monkeypatch.setattr(module.native, "_request_api_response", request)
    assert client.dispatch(job, dispatched_at=DISPATCHED) == upid


@pytest.mark.parametrize(
    "status,reason,error,unknown",
    [
        (500, "CT 197 already exists on node 'pve'", "conflict", False),
        (500, "VM 197 already exists on node 'peer-1'", "conflict", False),
        (500, "unable to create VM 197: config file already exists", "conflict", False),
        (500, "CT 198 already exists on node 'pve'", "unavailable", True),
        (500, "internal error: CT 197 already exists on node 'pve'", "unavailable", True),
        (401, None, "policy_denied", False),
        (403, None, "unavailable", True),
        (200, "unrecognized task", "unavailable", True),
    ],
)
def test_dispatch_classifies_exact_conflict_and_retains_unknown(
    monkeypatch, status, reason, error, unknown
):
    client = api(monkeypatch)
    monkeypatch.setattr(module.native, "_request_api_response", lambda *a, **kw: (status, reason))
    job, _ = native_job("lxc")
    with pytest.raises(ExecutorError) as denied:
        client.dispatch(job, dispatched_at=DISPATCHED)
    assert denied.value.error_class == error
    assert denied.value.outcome_unknown is unknown


def test_permissions_require_exact_scoped_effective_map(monkeypatch):
    client = api(monkeypatch)
    job, template = native_job("qemu")
    policy = ProvisionPolicy(
        node="pve",
        write_token_file="/private/token",
        templates=(template,),
        targets=(job.destination,),
    )
    acl = {
        "/vms/194": {"VM.Clone": 0, "VM.Audit": 0},
        "/vms/196": {"VM.Allocate": 0},
        "/storage/local-lvm": {"Datastore.AllocateSpace": 0},
        "/sdn/zones/localnetwork/vmbr0": {"SDN.Use": 0},
    }
    responses = {"/version": {"release": "9.3", "version": "9.3.1"}, "/access/permissions": acl}
    monkeypatch.setattr(client, "_request", lambda path: responses[path])
    client.validate_permissions(policy)
    acl["/vms/196"]["VM.PowerMgmt"] = 0
    with pytest.raises(ExecutorError, match="policy_denied"):
        client.validate_permissions(policy)


@pytest.mark.parametrize("kind,noun", [("qemu", "VM"), ("lxc", "container")])
def test_recovery_uses_source_upid_and_complete_exact_destination_log(monkeypatch, kind, noun):
    client = api(monkeypatch)
    job, _ = native_job(kind)
    upid, fields = native_task(job)
    task = {**fields, "status": "stopped", "exitstatus": "OK"}
    listing = [fields]
    marker = f"creating a clone of {noun} {job.source.vmid} with ID {job.target.vmid}"
    log = {"total": 2, "data": [{"n": 1, "t": marker}, {"n": 2, "t": "TASK OK"}]}

    def request(path, *, envelope=False):
        assert "!" not in path
        if "/tasks?" in path:
            return listing
        if "/log?" in path:
            assert envelope
            return log
        assert path.endswith("/status") and not envelope
        return task

    monkeypatch.setattr(client, "_request", request)
    assert client.recent_tasks(job, since=int(DISPATCHED), until=int(DISPATCHED) + 2) == (upid,)
    assert client.task(job, upid, dispatched_at=DISPATCHED) == "succeeded"
    client.verify_task_target(job, upid, dispatched_at=DISPATCHED)
    log["total"] = 3
    with pytest.raises(ExecutorError, match="unavailable"):
        client.verify_task_target(job, upid, dispatched_at=DISPATCHED)
    log["total"] = 2
    log["data"][0]["t"] = marker + "0"
    with pytest.raises(ExecutorError, match="unavailable"):
        client.verify_task_target(job, upid, dispatched_at=DISPATCHED)
    with pytest.raises(ExecutorError, match="policy_denied"):
        client.task(
            job,
            upid.replace(f":{job.source.vmid}:", f":{job.target.vmid}:"),
            dispatched_at=DISPATCHED,
        )
    task["exitstatus"] = f"VM {job.target.vmid} already exists on node 'pve'"
    assert client.task(job, upid, dispatched_at=DISPATCHED) == "vmid_conflict"


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
def test_root_evidence_verifies_source_and_target_without_prechecking_vmid(monkeypatch, kind):
    job, template = native_job(kind)
    evidence = module.ProvisionEvidence()
    source_path = f"/nodes/pve/{kind}/{job.source.vmid}"
    target_path = f"/nodes/pve/{kind}/{job.target.vmid}"
    registered_at = int(DISPATCHED * 1000) + 1
    profile = job.observation.profile

    def roster(guest, uid, generation):
        return {
            "id": f"{kind}/{guest.vmid}",
            "type": kind,
            "node": "pve",
            "vmid": guest.vmid,
            "uid": uid,
            "rtime": generation,
            "status": "running",
        }

    target_row = roster(job.target, NEW_UID, registered_at)
    source_row = roster(job.source, UID, template.registered_at_ms)
    source_vol = f"local-lvm:base-{job.source.vmid}-disk-0"
    target_vol = f"local-lvm:vm-{job.target.vmid}-disk-0"
    mac = "16:BB:CC:DD:EE:FF"
    disk_key = "scsi0" if kind == "qemu" else "rootfs"
    size = "3G" if kind == "qemu" else "2G"
    name_key = "name" if kind == "qemu" else "hostname"
    common = {
        "digest": DIGEST,
        "cores": 1,
        "memory": str(profile.memory_mib),
        "onboot": 0,
        "meta": "creation-qemu=9.3.1,ctime=100",
    }
    if kind == "qemu":
        common.update(
            ostype="l26",
            boot="order=scsi0",
            scsihw="virtio-scsi-single",
            serial0="socket",
            smbios1="uuid=01234567-0123-4567-89ab-0123456789ab",
            vmgenid="12345678-1234-5678-89ab-0123456789ab",
            net0=f"virtio={mac},bridge=vmbr0,link_down=1",
        )
    else:
        common.update(
            arch="amd64",
            ostype="debian",
            swap=64,
            unprivileged=1,
            net0=f"name=eth0,bridge=vmbr0,hwaddr={mac},ip=manual,link_down=1,type=veth",
        )
    source_config = {
        **common,
        "template": 1,
        disk_key: f"{source_vol},size={size}",
        name_key: "source",
    }
    target_config = {**common, disk_key: f"{target_vol},size={size}", name_key: job.name}
    status = {"status": "stopped", "ha": {"managed": 0}, "qmpstatus": "stopped"}
    content = "images" if kind == "qemu" else "rootdir"
    responses = {
        ("/pools", "--poolid", "rc2-managed"): [{"poolid": "rc2-managed", "members": [target_row]}],
        ("/nodes/pve/network", "--type", "bridge"): [
            {"iface": "vmbr0", "type": "bridge", "active": 1}
        ],
        ("/nodes/pve/storage/local-lvm/status",): {
            "active": 1,
            "enabled": 1,
            "content": "rootdir,images",
        },
        ("/cluster/resources", "--type", "vm"): [target_row, source_row],
        (source_path + "/status/current",): {
            **status,
            "vmid": job.source.vmid,
            "uid": UID,
            "template": 1,
        },
        (target_path + "/status/current",): {**status, "vmid": job.target.vmid, "uid": NEW_UID},
        (source_path + "/config", "--current", "1"): source_config,
        (target_path + "/config", "--current", "1"): target_config,
        (source_path + "/snapshot",): [{"name": "current", "digest": DIGEST, "running": 0}],
        (target_path + "/snapshot",): [{"name": "current", "digest": DIGEST, "running": 0}],
        ("/nodes/pve/storage/local-lvm/content", "--vmid", str(job.source.vmid)): [
            {
                "volid": source_vol,
                "size": profile.disk_bytes,
                "vmid": job.source.vmid,
                "content": content,
            }
        ],
        ("/nodes/pve/storage/local-lvm/content", "--vmid", str(job.target.vmid)): [
            {
                "volid": target_vol,
                "size": profile.disk_bytes,
                "vmid": job.target.vmid,
                "content": content,
            }
        ],
    }
    monkeypatch.setattr(evidence, "_get", lambda guest, *args: responses[args])
    monkeypatch.setattr(module, "verify_local_lxc_state", lambda guest, state: None)
    monkeypatch.setattr(module, "verify_local_pending", lambda guest: None)
    # RRD is stale and the chosen destination already appears in the cluster roster.
    assert evidence.observe_source(job.source, template, job.destination) == job.observation
    assert (
        evidence.verify_target(job, dispatched_at=DISPATCHED, completed_at=int(DISPATCHED)).pve_uid
        == NEW_UID
    )

    for key, unsafe in (
        ("hookscript", "local:snippets/test.pl"),
        (disk_key, "/dev/sda,size=2G"),
        (disk_key, f"{source_vol},size=1024"),
        ("net0", common["net0"] + ",trunks=10;20"),
        ("net0", common["net0"] + ",bridge=vmbr1"),
        ("onboot", 1),
    ):
        before = source_config.get(key)
        source_config[key] = unsafe
        with pytest.raises(ExecutorError, match="policy_denied"):
            evidence.observe_source(job.source, template, job.destination)
        if before is None:
            del source_config[key]
        else:
            source_config[key] = before

    source_config["digest"] = "e" * 40
    with pytest.raises(ExecutorError, match="policy_denied"):
        evidence.observe_source(job.source, template, job.destination)
    # A replacement with the same destination profile and name is too new.
    target_row["rtime"] = (int(DISPATCHED) + 1) * 1000
    with pytest.raises(ExecutorError, match="policy_denied"):
        evidence.verify_target(job, dispatched_at=DISPATCHED, completed_at=int(DISPATCHED))
    target_row["rtime"] = int(DISPATCHED * 1000) - 1
    with pytest.raises(ExecutorError, match="policy_denied"):
        evidence.verify_target(job, dispatched_at=DISPATCHED, completed_at=int(DISPATCHED))


def test_verified_tls_preserves_native_collision_reason_and_task_log_total(monkeypatch, tmp_path):
    job, _ = native_job("lxc")
    upid, fields = native_task(job)
    task = {**fields, "status": "stopped", "exitstatus": "OK"}
    log = {
        "total": 2,
        "data": [
            {"n": 1, "t": "creating a clone of container 195 with ID 197"},
            {"n": 2, "t": "TASK OK"},
        ],
    }
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def respond(self, code, envelope, message=None):
            seen.append((self.command, self.path, self.headers["Authorization"]))
            payload = json.dumps(envelope).encode()
            self.send_response(code, message)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            self.respond(500, {"data": None}, "CT 197 already exists on node 'pve'")

        def do_GET(self):  # noqa: N802
            self.respond(200, {"data": task} if self.path.endswith("/status") else log)

        def log_message(self, *_):
            pass

    cert, key = write_certificate(tmp_path, "pve.example")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        monkeypatch.setattr(module.native, "API_PORT", server.server_port)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()
        try:
            client = module.ProvisionApi("pve.example", cert, TOKEN)
            with pytest.raises(ExecutorError, match="conflict") as raised:
                client.dispatch(job, dispatched_at=DISPATCHED)
            assert not raised.value.outcome_unknown
            client.verify_task_target(job, upid, dispatched_at=DISPATCHED)
        finally:
            server.shutdown()
            thread.join(timeout=2)
    task_path = f"/api2/json/nodes/pve/tasks/{quote(upid, safe='')}"
    assert seen == [
        ("POST", "/api2/json/nodes/pve/lxc/195/clone", f"PVEAPIToken={TOKEN}"),
        ("GET", task_path + "/status", f"PVEAPIToken={TOKEN}"),
        ("GET", task_path + "/log?start=0&limit=500", f"PVEAPIToken={TOKEN}"),
    ]


def test_clone_dispatch_accepts_delayed_worker_within_native_window(monkeypatch):
    client = api(monkeypatch)
    job, _ = native_job("lxc")
    upid, _ = native_task(job, delay=15)
    monkeypatch.setattr(client, "_request", lambda *a, **kw: upid)
    assert client.dispatch(job, dispatched_at=DISPATCHED) == upid

    upid, _ = native_task(job, delay=31)
    with pytest.raises(ExecutorError, match="unavailable") as rejected:
        client.dispatch(job, dispatched_at=DISPATCHED)
    assert rejected.value.outcome_unknown


def test_completion_time_requires_exact_owned_successful_archived_row(monkeypatch):
    client = api(monkeypatch)
    job, _ = native_job("lxc")
    upid, fields = native_task(job, delay=15)
    start = fields["starttime"]
    finish = start + 4
    row = {**fields, "status": "OK", "endtime": finish}
    listing = [row]

    def request(path):
        assert path == (
            f"/nodes/pve/tasks?vmid=195&typefilter=vzclone&source=archive&limit=9"
            f"&since={start}&until={start}"
        )
        return listing

    monkeypatch.setattr(client, "_request", request)
    assert client.completion_time(job, upid, dispatched_at=DISPATCHED) == finish
    for invalid in (
        [],
        [row, row],
        [{**row, "endtime": start - 1}],
        [{**row, "endtime": str(finish)}],
        [{**row, "status": "RUNNING"}],
        [{**row, "tokenid": "other"}],
    ):
        listing[:] = invalid
        with pytest.raises(ExecutorError, match="unavailable"):
            client.completion_time(job, upid, dispatched_at=DISPATCHED)
