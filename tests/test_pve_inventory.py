import json
from types import SimpleNamespace

import pytest

from steward.core import pve_inventory
from test_pve_native import API_NAME, API_TOKEN, PERMISSIONS_PATH, write_certificate
from test_pve_native import pve_api as pve_api
from test_pve_native import token_file as token_file

READ_TOKEN = "px02@pve!inventory=14aa8f43-4390-4b66-875f-464814c048de"
NODE = "pve-rc2"
NODE_PERMISSIONS = f"{PERMISSIONS_PATH}?path=/nodes/{NODE}"
INDEX = "/api2/json/cluster/resources"
VM = f"/api2/json/nodes/{NODE}/qemu/190"
CT = f"/api2/json/nodes/{NODE}/lxc/191"
TASKS = f"/api2/json/nodes/{NODE}/tasks"


def payload(data):
    return 200, json.dumps({"data": data}).encode()


def guest(kind, vmid, **extra):
    return {
        "id": f"{kind}/{vmid}",
        "type": kind,
        "node": NODE,
        "vmid": vmid,
        "uid": ("a" if kind == "qemu" else "b") * 20,
        "rtime": 1_789_999_000_123,
        "name": f"guest-{vmid}",
        "status": "running",
        "pool": "rc2-visible",
        "cpu": 0.25,
        "maxcpu": 2,
        "mem": 64 * 1024**2,
        "maxmem": 128 * 1024**2,
        "uptime": 37,
        **extra,
    }


def node(name):
    return {"id": f"node/{name}", "type": "node", "node": name, "status": "online"}


def task(kind, vmid, status):
    return {
        "type": kind,
        "id": str(vmid),
        "node": NODE,
        "starttime": 1_790_000_000,
        "endtime": 1_790_000_020,
        "upid": "UPID:principal-canary@pam",
        "user": "principal-canary@pam",
        "pid": 123,
        "pstart": 34567,
        "status": status,
    }


@pytest.fixture
def local_target(pve_api, token_file, tmp_path):
    ca, responses, calls = pve_api
    inventory_token = tmp_path / "inventory-token"
    inventory_token.write_text(READ_TOKEN)
    inventory_token.chmod(0o600)
    target = pve_inventory.RegisteredLocalTarget(
        api_name=API_NAME,
        ca_file=ca,
        inventory_token_file=inventory_token,
        health_token_file=token_file,
    )
    responses.update(
        {
            PERMISSIONS_PATH: payload(
                {
                    f"/nodes/{NODE}": {"Sys.Audit": 0},
                    "/vms/190": {"VM.Audit": 0},
                    "/vms/191": {"VM.Audit": 0},
                    "/storage/local-lvm": {"Datastore.Audit": 0},
                    "/pool/rc2-visible": {"Pool.Audit": 0},
                }
            ),
            NODE_PERMISSIONS: payload({f"/nodes/{NODE}": {"Sys.Audit": 0}}),
            f"{PERMISSIONS_PATH}?path=/nodes/hidden-node": payload({"/nodes/hidden-node": {}}),
            INDEX: payload(
                [
                    node(NODE),
                    node("hidden-node"),
                    guest("qemu", 190),
                    guest("lxc", 191),
                    {
                        "id": "/pool/rc2-visible",
                        "type": "pool",
                        "pool": "rc2-visible",
                        "cpu": 9_765_432,
                        "mem": 9_765_432,
                        "members": ["qemu/190", "qemu/192"],
                    },
                    {
                        "id": f"storage/{NODE}/local-lvm",
                        "type": "storage",
                        "node": NODE,
                        "storage": "local-lvm",
                        "status": "available",
                        "content": "images,rootdir",
                        "plugintype": "lvmthin",
                        "shared": 0,
                        "disk": 4096,
                        "maxdisk": 8192,
                    },
                    {"id": "network/ignore-canary", "type": "network", "password": "raw-canary"},
                ]
            ),
            VM + "/config?current=1": payload(
                {
                    "net1": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=123",
                    "cipassword": "secret-config-canary",
                    "sshkeys": "secret-config-canary",
                }
            ),
            CT + "/config?current=1": payload(
                {
                    "net0": "name=eth0,bridge=vmbr1,tag=42,ip=192.0.2.55/24",
                    "rootfs": "sensitive-volume-canary",
                }
            ),
            VM + "/rrddata?timeframe=hour&cf=AVERAGE": payload(
                [
                    {"time": 1_790_000_000},
                    {"time": 1_790_000_060, "cpu": 0.25, "mem": 4096, "netin": 30.5},
                ]
            ),
            CT + "/rrddata?timeframe=hour&cf=AVERAGE": payload([]),
            TASKS + "?vmid=190&source=all&limit=20": payload(
                [
                    task("qmstart", 190, "OK"),
                    task("qmstop", 190, "sensitive PVE diagnostic"),
                    task("qmcreate", 192, "OK"),
                    task("qmstart", 192, "OK"),
                    task("vzstart", 190, "OK"),
                    {**task("qmstart", 190, "OK"), "node": "hidden-node"},
                ]
            ),
            TASKS + "?vmid=191&source=all&limit=20": payload([]),
        }
    )
    return target, responses, calls


def test_inventory_projects_authorized_resources_with_scoped_guest_details(local_target):
    target, _, calls = local_target
    inventory = pve_inventory.collect_inventory(target)

    assert inventory.evidence.state == "observed"
    assert inventory.coverage == "token_scope"
    assert [item.node for item in inventory.nodes] == [NODE]
    assert [item.pool for item in inventory.pools] == ["rc2-visible"]
    assert [item.storage for item in inventory.datastores] == ["local-lvm"]
    assert inventory.datastores[0].max_disk_bytes == 8192
    guests = {item.vmid: item for item in inventory.guests}
    assert set(guests) == {190, 191}
    vm, ct = guests[190], guests[191]
    assert vm.cpu_fraction == 0.25
    assert vm.memory_bytes == 64 * 1024**2
    assert vm.network.evidence.source == "guest_config"
    assert [(net.index, net.bridge, net.vlan_tag) for net in vm.network.items] == [
        (1, "vmbr0", 123)
    ]
    assert [(net.index, net.bridge, net.vlan_tag) for net in ct.network.items] == [(0, "vmbr1", 42)]
    assert vm.measurements.evidence.source == "guest_rrd"
    assert vm.measurements.evidence.state == "observed"
    assert vm.measurements.items[0].cpu_fraction is None
    assert vm.measurements.items[1].net_in_bytes_per_second == 30.5
    assert ct.measurements.evidence.state == "absent"
    assert sorted(t.state for t in vm.tasks.items) == ["failed", "succeeded"]
    assert ct.tasks.evidence.state == "absent"

    body = inventory.model_dump_json()
    for canary in (
        READ_TOKEN,
        API_TOKEN,
        "hidden-node",
        "192.0.2.55",
        "AA:BB:CC:DD:EE:FF",
        "principal-canary",
        "raw-canary",
        "secret-config-canary",
        "sensitive-volume-canary",
        "sensitive PVE diagnostic",
        "9765432",
        "qemu/192",
        "aaaaaaaaaaaaaaaaaaaa",
        "1789999000123",
    ):
        assert canary not in body
    assert all(
        method == "GET" and token == "PVEAPIToken=" + READ_TOKEN for method, _, token in calls
    )
    assert any(path == INDEX for _, path, _ in calls)
    assert all("/192" not in path and "vmid=192" not in path for _, path, _ in calls)
    assert all("/pools/" not in path for _, path, _ in calls)


@pytest.mark.parametrize(
    ("result", "state"),
    [
        ((401, READ_TOKEN.encode()), "restricted"),
        ((403, READ_TOKEN.encode()), "restricted"),
        ((404, READ_TOKEN.encode()), "missing"),
        ((429, READ_TOKEN.encode()), "unavailable"),
        ((503, READ_TOKEN.encode()), "unavailable"),
        ((302, b""), "unavailable"),
        ((200, b'{"data":{},"data":{}}'), "invalid"),
        ((200, b'{"data":{}}' + b" " * (1024 * 1024)), "invalid"),
        (payload({"net0": ["malformed"]}), "invalid"),
        (payload({}), "absent"),
    ],
)
def test_guest_endpoint_evidence_keeps_failures_and_observed_absence_distinct(
    local_target, result, state
):
    target, responses, calls = local_target
    responses[VM + "/config?current=1"] = result
    inventory = pve_inventory.collect_inventory(target)
    vm = next(item for item in inventory.guests if item.vmid == 190)
    assert vm.network.evidence.state == state
    assert vm.network.items == ()
    assert READ_TOKEN not in inventory.model_dump_json()
    assert all(path != "/other" for _, path, _ in calls)


def test_task_scope_requires_sys_audit_even_when_the_pve_index_lists_node(local_target):
    target, responses, calls = local_target
    status, body = responses[PERMISSIONS_PATH]
    rights = json.loads(body)["data"]
    rights.pop(f"/nodes/{NODE}")
    responses[PERMISSIONS_PATH] = payload(rights)
    responses[NODE_PERMISSIONS] = payload({f"/nodes/{NODE}": {}})
    inventory = pve_inventory.collect_inventory(target)
    assert not inventory.nodes
    assert {item.vmid for item in inventory.guests} == {190, 191}
    assert all(item.tasks.evidence.state == "restricted" for item in inventory.guests)
    assert all(not path.startswith(TASKS) for _, path, _ in calls)


def test_collection_refuses_non_read_privileges(local_target):
    target, responses, calls = local_target
    responses[PERMISSIONS_PATH] = payload({"/vms/190": {"VM.Audit": 0, "VM.PowerMgmt": 0}})
    inventory = pve_inventory.collect_inventory(target)
    assert inventory.evidence.state == "restricted"
    assert not inventory.guests
    assert all(path == PERMISSIONS_PATH for _, path, _ in calls)


def test_scope_can_be_empty_without_exposing_public_node_rows(local_target):
    target, responses, calls = local_target
    responses[PERMISSIONS_PATH] = payload({})
    responses[NODE_PERMISSIONS] = payload({f"/nodes/{NODE}": {}})
    responses[INDEX] = payload([node(NODE), node("hidden-node")])
    inventory = pve_inventory.collect_inventory(target)
    assert inventory.evidence.state == "absent"
    assert not (inventory.nodes or inventory.guests or inventory.datastores or inventory.pools)
    assert all(not path.startswith(TASKS) for _, path, _ in calls)


def test_resource_identity_is_validated_before_building_endpoint_paths(local_target):
    target, responses, calls = local_target
    responses[INDEX] = payload([guest("qemu", 190, node="../other?token=canary")])
    inventory = pve_inventory.collect_inventory(target)
    assert inventory.evidence.state == "invalid"
    assert not inventory.guests
    assert all("other" not in path for _, path, _ in calls)


def test_uncovered_guest_row_never_drives_a_detail_request(local_target):
    target, responses, calls = local_target
    rights = json.loads(responses[PERMISSIONS_PATH][1])["data"]
    rights["/vms"] = {"VM.Audit": 0}
    responses[PERMISSIONS_PATH] = payload(rights)
    resources = json.loads(responses[INDEX][1])["data"]
    responses[INDEX] = payload([*resources, guest("qemu", 192)])
    inventory = pve_inventory.collect_inventory(target)
    assert {item.vmid for item in inventory.guests} == {190, 191}
    assert all("/192" not in path and "vmid=192" not in path for _, path, _ in calls)


def test_pool_scope_supports_nested_names_and_visible_guest_links(local_target):
    target, responses, _ = local_target
    rights = json.loads(responses[PERMISSIONS_PATH][1])["data"]
    rights["/pool/rc2-visible/child"] = rights.pop("/pool/rc2-visible")
    responses[PERMISSIONS_PATH] = payload(rights)
    resources = json.loads(responses[INDEX][1])["data"]
    for row in resources:
        if row.get("pool") == "rc2-visible":
            row["pool"] = "rc2-visible/child"
            if row["type"] == "pool":
                row["id"] = "/pool/rc2-visible/child"
    responses[INDEX] = payload(resources)
    inventory = pve_inventory.collect_inventory(target)
    assert [pool.pool for pool in inventory.pools] == ["rc2-visible/child"]
    assert {item.vmid: item.pool for item in inventory.guests} == {
        190: "rc2-visible/child",
        191: "rc2-visible/child",
    }


def test_running_pve_tasks_keep_running_status(local_target):
    target, responses, _ = local_target
    running = task("qmstart", 190, "RUNNING")
    del running["endtime"]
    responses[TASKS + "?vmid=190&source=all&limit=20"] = payload([running])
    inventory = pve_inventory.collect_inventory(target)
    vm = next(item for item in inventory.guests if item.vmid == 190)
    assert vm.tasks.evidence.state == "observed"
    assert vm.tasks.items[0].state == "running"
    assert vm.tasks.items[0].finished_at is None


def test_mid_collection_revocation_clears_guest_details_and_pool_membership(
    local_target, monkeypatch
):
    target, responses, calls = local_target
    original_read = pve_inventory._read_api_response

    def revoke_after_details(api_name, context, token, path, **limits):
        result = original_read(api_name, context, token, path, **limits)
        if path == TASKS + "?vmid=191&source=all&limit=20":
            rights = json.loads(responses[PERMISSIONS_PATH][1])["data"]
            rights.pop("/vms/191")
            responses[PERMISSIONS_PATH] = payload(rights)
            resources = json.loads(responses[INDEX][1])["data"]
            pool = next(row for row in resources if row["type"] == "pool")
            pool["members"].append("lxc/191")
            responses[INDEX] = payload([row for row in resources if row["id"] != "lxc/191"])
        return result

    monkeypatch.setattr(pve_inventory, "_read_api_response", revoke_after_details)
    inventory = pve_inventory.collect_inventory(target)
    assert [item.vmid for item in inventory.guests] == [190]
    assert [item.pool for item in inventory.pools] == ["rc2-visible"]
    assert "lxc/191" not in inventory.model_dump_json()
    assert "secret-config-canary" not in inventory.model_dump_json()
    assert sum(path == INDEX for _, path, _ in calls) == 2


def test_new_child_deny_is_observed_after_final_inherited_rights_read(local_target, monkeypatch):
    target, responses, _ = local_target
    rights = json.loads(responses[PERMISSIONS_PATH][1])["data"]
    rights.pop("/vms/190")
    rights["/vms"] = {"VM.Audit": 1}
    responses[PERMISSIONS_PATH] = payload(rights)
    original_read = pve_inventory._read_api_response
    permission_reads = 0

    def add_child_deny(api_name, context, token, path, **limits):
        nonlocal permission_reads
        if path == PERMISSIONS_PATH:
            permission_reads += 1
            if permission_reads == 2:
                visible = json.loads(responses[INDEX][1])["data"]
                # PVE omits child NoAccess paths from the full permissions map.
                responses[INDEX] = payload([row for row in visible if row.get("vmid") != 190])
        return original_read(api_name, context, token, path, **limits)

    monkeypatch.setattr(pve_inventory, "_read_api_response", add_child_deny)
    inventory = pve_inventory.collect_inventory(target)
    assert [item.vmid for item in inventory.guests] == [191]


def test_history_drops_old_vmids_and_partial_registration_buckets(local_target):
    target, responses, _ = local_target
    resources = json.loads(responses[INDEX][1])["data"]
    vm = next(row for row in resources if row.get("vmid") == 190)
    vm["rtime"] = 1_790_000_000_700
    responses[INDEX] = payload(resources)
    current_task = task("qmstop", 190, "OK")
    current_task.update(starttime=1_790_000_001)
    responses[TASKS + "?vmid=190&source=all&limit=20"] = payload(
        [task("qmstart", 190, "OK"), current_task]
    )
    responses[VM + "/rrddata?timeframe=hour&cf=AVERAGE"] = payload(
        [
            {"time": 1_789_999_940, "cpu": 9},
            {"time": 1_790_000_060, "cpu": 8},
            {"time": 1_790_000_180, "cpu": 7},
            {"time": 1_790_000_240, "cpu": 0.16},
        ]
    )

    inventory = pve_inventory.collect_inventory(target)
    vm = next(row for row in inventory.guests if row.vmid == 190)
    assert [item.operation for item in vm.tasks.items] == ["stop"]
    assert [item.cpu_fraction for item in vm.measurements.items] == [0.16]


def test_guest_without_registered_identity_cannot_claim_vmid_history(local_target):
    target, responses, calls = local_target
    resources = json.loads(responses[INDEX][1])["data"]
    vm = next(row for row in resources if row.get("vmid") == 190)
    del vm["uid"], vm["rtime"]
    responses[INDEX] = payload(resources)
    inventory = pve_inventory.collect_inventory(target)
    vm = next(row for row in inventory.guests if row.vmid == 190)
    assert vm.network.evidence.state == "observed"
    assert vm.measurements.evidence.state == vm.tasks.evidence.state == "missing"
    assert all(
        not path.startswith(VM + "/rrddata") and "vmid=190" not in path for _, path, _ in calls
    )


def test_replaced_guest_never_inherits_details_of_prior_inflight_generation(
    local_target, monkeypatch
):
    target, responses, _ = local_target
    original_read = pve_inventory._read_api_response

    def replace_guest(api_name, context, token, path, **limits):
        result = original_read(api_name, context, token, path, **limits)
        if path == VM + "/config?current=1":
            resources = json.loads(responses[INDEX][1])["data"]
            vm = next(row for row in resources if row.get("vmid") == 190)
            vm.update(uid="z" * 20, rtime=vm["rtime"] + 500)
            responses[INDEX] = payload(resources)
        return result

    monkeypatch.setattr(pve_inventory, "_read_api_response", replace_guest)
    inventory = pve_inventory.collect_inventory(target)
    assert [item.vmid for item in inventory.guests] == [191]


def test_failed_final_visibility_check_withholds_previously_read_rows(local_target, monkeypatch):
    target, _, _ = local_target
    original_read = pve_inventory._read_api_response
    seen_index = False

    def fail_final_index(api_name, context, token, path, **limits):
        nonlocal seen_index
        if path == INDEX:
            if seen_index:
                return 503, None
            seen_index = True
        return original_read(api_name, context, token, path, **limits)

    monkeypatch.setattr(pve_inventory, "_read_api_response", fail_final_index)
    inventory = pve_inventory.collect_inventory(target)
    assert inventory.evidence.state == "unavailable"
    assert not (inventory.nodes or inventory.guests or inventory.datastores or inventory.pools)


def test_collection_reserves_time_for_visibility_after_detail_budget(local_target, monkeypatch):
    target, responses, _ = local_target
    now = [600.0]
    calls = []
    monkeypatch.setattr(pve_inventory, "time", SimpleNamespace(monotonic=lambda: now[0]))

    def read(api_name, context, token, path, *, deadline, max_response):
        calls.append((path, deadline))
        if path == VM + "/config?current=1":
            now[0] += pve_inventory._TIMEOUT - pve_inventory._FINAL_RESERVE
            raise TimeoutError
        status, body = responses[path]
        return status, json.loads(body)["data"]

    monkeypatch.setattr(pve_inventory, "_read_api_response", read)
    inventory = pve_inventory.collect_inventory(target)
    assert [path for path, _ in calls].count(INDEX) == 2
    assert all(deadline <= 600 + pve_inventory._TIMEOUT for _, deadline in calls)
    vm = next(item for item in inventory.guests if item.vmid == 190)
    assert vm.measurements.evidence.state == "budget"


@pytest.mark.parametrize("problem", ["wrong-name", "wrong-ca", "same-token-id", "public-token"])
def test_inventory_requires_verified_tls_and_a_distinct_private_token(
    local_target, tmp_path, problem
):
    target, _, calls = local_target
    name, ca = target.api_name, target.ca_file
    inventory_token = target.inventory_token_file
    if problem == "wrong-name":
        name = "different-native.invalid"
    elif problem == "wrong-ca":
        ca, _ = write_certificate(tmp_path, "untrusted-native.invalid")
    elif problem == "same-token-id":
        inventory_token.write_text(API_TOKEN.split("=")[0] + "=" + READ_TOKEN.split("=")[1])
    else:
        inventory_token.chmod(0o640)
    changed = pve_inventory.RegisteredLocalTarget(
        api_name=name,
        ca_file=ca,
        inventory_token_file=inventory_token,
        health_token_file=target.health_token_file,
    )
    if problem in ("same-token-id", "public-token"):
        with pytest.raises(ValueError) as error:
            pve_inventory.collect_inventory(changed)
        assert READ_TOKEN not in str(error.value)
        assert API_TOKEN not in str(error.value)
    else:
        inventory = pve_inventory.collect_inventory(changed)
        assert inventory.evidence.state == "unavailable"
        assert not inventory.guests
    assert not calls
