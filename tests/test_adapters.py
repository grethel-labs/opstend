import json

import httpx
import pytest

from opstend.adapters import linux
from opstend.adapters.base import GuestAction, Unsupported
from opstend.adapters.proxmox import Proxmox, ProxmoxError, parse_net
from opstend.adapters.runner import Runner
from opstend.adapters.unifi import Unifi
from opstend.core.models import DeviceKind, GuestKind, GuestState

# -- runner -------------------------------------------------------------------


async def test_runner_refuses_unlisted_programs_and_strings():
    r = Runner()
    with pytest.raises(PermissionError):
        await r.run(["rm", "-rf", "/"])
    with pytest.raises(ValueError):
        await r.run("uname -a")  # type: ignore[arg-type]
    out = await r.run(["uname", "-s"])
    assert out.stdout.strip() == "Linux"


def test_ssh_arguments_are_quoted_for_the_remote_shell():
    import shlex

    remote = ["env", "LC_ALL=C", "podman", "stop", "x; rm -rf /"]
    assert shlex.split(shlex.join(remote))[-1] == "x; rm -rf /"


# -- linux parsers ------------------------------------------------------------


def test_arch_and_package_manager_detection():
    assert linux.normalize_arch("aarch64") == "arm64"
    assert linux.normalize_arch("armv7l") == "armv7"
    assert linux.normalize_arch("riscv64") == "riscv64"
    assert linux.normalize_arch("s390x") == "s390x"
    cases = {
        "ID=ubuntu\nID_LIKE=debian": "apt",
        "ID=raspbian\nID_LIKE=debian": "apt",
        'ID="rocky"\nID_LIKE="rhel centos fedora"': "dnf",
        "ID=alpine": "apk",
        "ID=arch": "pacman",
        'ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"': "zypper",
        "ID=nixos": "unknown",
    }
    for text, manager in cases.items():
        assert linux.package_manager_for(linux.parse_os_release(text)) == manager


def test_apt_simulate_parsing():
    text = (
        "Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64])\n"
        "Inst htop [3.3.0-4] (3.3.0-5 Ubuntu:24.04/noble-updates [amd64])\n"
        "Conf htop (3.3.0-5 Ubuntu:24.04/noble-updates [amd64])\n"
    )
    ups = linux.parse_apt_simulate(text)
    assert [(u["name"], u["security"]) for u in ups] == [("libssl3t64", True), ("htop", False)]
    assert ups[0]["current"] == "3.0.13-0ubuntu3.4"


def test_dnf_apk_pacman_zypper_parsing():
    sec = linux.parse_dnf_security(
        "FEDORA-2026-1 Important/Sec. openssl-libs-3.2.4-1.fc41.x86_64\n"
    )
    assert sec == {"openssl-libs"}
    dnf = linux.parse_dnf_check_update(
        "\nopenssl-libs.x86_64   1:3.2.4-1.fc41   updates\nkernel.x86_64 6.12.1-200.fc41 updates\n",
        sec,
    )
    assert [(u["name"], u["security"]) for u in dnf] == [("openssl-libs", True), ("kernel", False)]
    apk = linux.parse_apk_upgradable(
        "busybox-1.37.0-r13 aarch64 {busybox} (GPL-2.0-only) [upgradable from: busybox-1.37.0-r12]\n"
    )
    assert apk == [
        {"name": "busybox", "current": "1.37.0-r12", "available": "1.37.0-r13", "security": False}
    ]
    assert (
        linux.parse_checkupdates("linux 6.12.1.arch1-1 -> 6.12.2.arch1-1\n")[0]["name"] == "linux"
    )
    zyp = linux.parse_zypper_lu(
        "S | Repository | Name | Current Version | Available Version | Arch\n"
        "--+------------+------+-----------------+-------------------+-------\n"
        "v | Update     | curl | 8.11.0-1.1      | 8.11.1-1.1        | x86_64\n"
    )
    assert zyp[0]["name"] == "curl" and zyp[0]["available"] == "8.11.1-1.1"


def test_installed_packages_parsing():
    assert linux.parse_installed("apt", "openssl\t3.0.13-0ubuntu3.4\tamd64\n") == [
        ("openssl", "3.0.13-0ubuntu3.4")
    ]
    assert linux.parse_installed("dnf", "bash\t0:5.2.26-3.fc41\tx86_64\n") == [
        ("bash", "5.2.26-3.fc41")
    ]
    assert linux.parse_installed("apk", "musl-1.2.5-r8\n") == [("musl", "1.2.5-r8")]
    assert linux.parse_installed("pacman", "glibc 2.40+r16-1\n") == [("glibc", "2.40+r16-1")]


def test_podman_and_virsh_parsing():
    ps = json.dumps(
        [
            {
                "Names": ["sensorik"],
                "State": "running",
                "Image": "ghcr.io/x/s:1",
                "Labels": {"opstend.service": "sensorik", "other": "x"},
                "Networks": ["svc"],
            }
        ]
    )
    g = linux.parse_podman_ps(ps, "linux:host-b")[0]
    assert g.kind == GuestKind.CONTAINER and g.state == GuestState.RUNNING
    assert g.tags == ["opstend.service=sensorik"]
    vms = linux.parse_virsh_list(
        " Id   Name     State\n-----------------------\n 1    dev-vm   running\n"
        " -    old-vm   shut off\n"
    )
    assert vms == [("dev-vm", "running"), ("old-vm", "shut off")]
    nics = linux.parse_virsh_domiflist(
        " Interface   Type     Source   Model    MAC\n"
        "-------------------------------------------------------\n"
        " vnet0       bridge   br0      virtio   52:54:00:aa:bb:cc\n"
    )
    assert nics[0].bridge == "br0" and nics[0].mac == "52:54:00:aa:bb:cc"


class FakeRunner:
    def __init__(self):
        self.calls = []

    async def run(self, argv, **kw):
        self.calls.append(argv)
        from opstend.adapters.runner import Result

        return Result(argv, 0, "", "")


async def test_linux_power_maps_to_native_commands_and_refuses_unsupported():
    runner = FakeRunner()
    lx = linux.Linux("linux:h", "10.0.0.5", runner)  # type: ignore[arg-type]
    from opstend.core.models import Guest

    c = Guest(id="c", host_id="linux:h", kind=GuestKind.CONTAINER, native_id="web", name="web")
    vm = Guest(id="v", host_id="linux:h", kind=GuestKind.VM, native_id="dev", name="dev")
    await lx.power(c, GuestAction.SHUTDOWN)
    await lx.power(vm, GuestAction.SHUTDOWN)
    await lx.snapshot(vm, "pre-update")
    assert runner.calls[:2] == [["podman", "stop", "web"], ["virsh", "shutdown", "dev"]]
    assert runner.calls[2][:4] == ["virsh", "snapshot-create-as", "dev", "pre-update"]
    with pytest.raises(Unsupported):
        await lx.snapshot(c, "x")


# -- proxmox ------------------------------------------------------------------


def pve_handler(calls):
    def handler(request: httpx.Request):
        path = request.url.path.removeprefix("/api2/json")
        calls.append((request.method, path))
        assert request.headers["authorization"].startswith("PVEAPIToken=opstend@pve!ops=")
        data = {
            "/cluster/resources": [
                {
                    "type": "node",
                    "node": "nuc-a",
                    "status": "online",
                    "maxcpu": 8,
                    "maxmem": 32 * 1024**3,
                    "mem": 8 * 1024**3,
                    "cpu": 0.12,
                },
                {
                    "type": "storage",
                    "node": "nuc-a",
                    "maxdisk": 500 * 1024**3,
                    "disk": 100 * 1024**3,
                },
                {
                    "type": "qemu",
                    "node": "nuc-a",
                    "vmid": 101,
                    "name": "medien",
                    "status": "running",
                    "maxcpu": 2,
                    "maxmem": 4 * 1024**3,
                    "tags": "media;prod",
                },
                {"type": "lxc", "node": "nuc-a", "vmid": 102, "name": "fotos", "status": "stopped"},
            ],
            "/nodes/nuc-a/network": [
                {
                    "iface": "vmbr0",
                    "type": "bridge",
                    "bridge_ports": "enp1s0",
                    "bridge_vlan_aware": 1,
                    "cidr": "10.20.10.11/24",
                }
            ],
            "/nodes/nuc-a/apt/update": [
                {
                    "Package": "pve-manager",
                    "OldVersion": "9.3.1",
                    "Version": "9.3.2",
                    "Origin": "Proxmox",
                }
            ],
            "/nodes/nuc-a/qemu/101/config": {
                "net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=20,firewall=1"
            },
            "/nodes/nuc-a/lxc/102/config": {
                "net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:02,ip=10.20.20.22/24,tag=20"
            },
            "/nodes/nuc-a/qemu/101/snapshot": [{"name": "before-update"}, {"name": "current"}],
            "/nodes/nuc-a/lxc/102/snapshot": [{"name": "current"}],
        }
        if request.method == "POST" and path.endswith("/status/start"):
            return httpx.Response(200, json={"data": "UPID:nuc-a:1"})
        if "/tasks/" in path:
            return httpx.Response(200, json={"data": {"status": "stopped", "exitstatus": "OK"}})
        if path in data:
            return httpx.Response(200, json={"data": data[path]})
        return httpx.Response(500, json={"errors": {"path": "unknown"}})

    return handler


async def test_proxmox_inventory_and_actions():
    calls = []
    pve = Proxmox(
        "https://10.20.10.11:8006",
        "opstend@pve!ops",
        "secret",
        cluster="home",
        transport=httpx.MockTransport(pve_handler(calls)),
        task_poll=0,
    )
    inv = await pve.inventory()
    assert inv.hosts[0].capacity.memory_mb == 32768 and inv.hosts[0].capacity.disk_gb == 500
    assert inv.bridges[0].vlan_aware
    vm = next(g for g in inv.guests if g.native_id == "101")
    ct = next(g for g in inv.guests if g.native_id == "102")
    assert vm.nics[0].vlan == 20 and vm.nics[0].mac == "BC:24:11:00:00:01" and vm.nics[0].firewall
    assert [s.name for s in vm.snapshots] == ["before-update"]
    assert ct.kind == GuestKind.LXC and ct.nics[0].ips == ["10.20.20.22/24"]
    assert inv.updates[0].available == "9.3.2"
    await pve.power(ct, GuestAction.START)
    assert ("POST", "/nodes/nuc-a/lxc/102/status/start") in calls
    with pytest.raises(Unsupported):
        await pve.power(ct, GuestAction.SUSPEND)
    assert "console=lxc" in pve.console_url(ct)


async def test_proxmox_failed_task_raises():
    def handler(request):
        if "/tasks/" in request.url.path:
            return httpx.Response(
                200, json={"data": {"status": "stopped", "exitstatus": "lock timeout"}}
            )
        return httpx.Response(200, json={"data": "UPID:x"})

    pve = Proxmox(
        "https://x:8006", "a@pve!b", "s", transport=httpx.MockTransport(handler), task_poll=0
    )
    from opstend.core.models import Guest

    g = Guest(id="g", host_id="pve:pve:node:x", kind=GuestKind.VM, native_id="1", name="g")
    with pytest.raises(ProxmoxError):
        await pve.power(g, GuestAction.START)


def test_proxmox_token_format_validated():
    with pytest.raises(ValueError):
        Proxmox("https://x:8006", "root", "s")
    assert parse_net("virtio=AA,bridge=vmbr1")["hwaddr"] == "AA"


# -- unifi --------------------------------------------------------------------

UNIFI = {
    "/proxy/network/api/s/default/rest/networkconf": [
        {"_id": "lan", "name": "LAN", "purpose": "corporate", "ip_subnet": "10.20.10.1/24"},
        {
            "_id": "srv",
            "name": "Server",
            "purpose": "corporate",
            "vlan_enabled": True,
            "vlan": 20,
            "ip_subnet": "10.20.20.1/24",
        },
        {
            "_id": "iot",
            "name": "IoT",
            "purpose": "corporate",
            "vlan_enabled": True,
            "vlan": 30,
            "network_isolation_enabled": True,
        },
        {"_id": "wan", "name": "WAN", "purpose": "wan"},
    ],
    "/proxy/network/api/s/default/rest/portconf": [
        {"_id": "p-all", "name": "All", "forward": "all"},
        {
            "_id": "p-srv",
            "name": "Server trunk",
            "forward": "customize",
            "native_networkconf_id": "lan",
            "tagged_networkconf_ids": ["srv"],
        },
    ],
    "/proxy/network/api/s/default/stat/device": [
        {
            "mac": "AA:00:00:00:00:01",
            "name": "sw-werkstatt",
            "type": "usw",
            "model": "USW-Lite-8-PoE",
            "state": 1,
            "version": "7.1.26",
            "upgradable": True,
            "upgrade_to_firmware": "7.2.1",
            "total_max_power": 52,
            "port_table": [
                {"port_idx": 1, "up": True, "speed": 1000, "speed_caps": 0x2F, "is_uplink": True},
                {
                    "port_idx": 2,
                    "up": True,
                    "speed": 100,
                    "speed_caps": 0x2F,
                    "portconf_id": "p-srv",
                    "poe_enable": True,
                    "poe_power": "4.2",
                    "rx_errors": 12,
                },
            ],
            "lldp_table": [
                {
                    "local_port_idx": 2,
                    "chassis_id": "BC:24:11:FF:00:01",
                    "port_id": "enp1s0",
                    "chassis_name": "nuc-a",
                }
            ],
            "uplink": {"uplink_mac": "AA:00:00:00:00:00", "uplink_remote_port": 4},
        },
    ],
    "/proxy/network/api/s/default/stat/sta": [
        {
            "mac": "11:22:33:44:55:66",
            "hostname": "laptop",
            "ip": "10.20.10.50",
            "network_id": "lan",
            "is_wired": False,
            "ap_mac": "AA:00:00:00:00:09",
            "signal": -61,
        },
    ],
    "/proxy/network/api/s/default/rest/firewallrule": [
        {
            "_id": "r1",
            "name": "IoT to Server",
            "action": "drop",
            "src_networkconf_id": "iot",
            "dst_networkconf_id": "srv",
            "rule_index": 2000,
            "enabled": True,
        },
    ],
}


async def test_unifi_snapshot_maps_everything():
    state = {"logged_in": False}

    def handler(request: httpx.Request):
        if request.url.path == "/api/auth/login":
            state["logged_in"] = True
            return httpx.Response(200, headers={"x-csrf-token": "t"}, json={})
        if not state["logged_in"]:
            return httpx.Response(401)
        if request.method == "POST":
            assert request.headers["x-csrf-token"] == "t"
            return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": []})
        return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": UNIFI[request.url.path]})

    u = Unifi("https://10.20.10.1", "opstend", "pw", transport=httpx.MockTransport(handler))
    snap = await u.snapshot()
    assert [n.name for n in snap["networks"]] == ["LAN", "Server", "IoT"]
    sw = snap["devices"][0]
    assert sw.kind == DeviceKind.SWITCH and sw.upgrade_to == "7.2.1"
    p2 = sw.ports[1]
    assert p2.native_vlan == 1 and p2.tagged_vlans == [20] and p2.profile == "Server trunk"
    assert p2.max_speed_mbps == 1000 and p2.speed_mbps == 100
    assert p2.lldp and p2.lldp.chassis == "bc:24:11:ff:00:01"
    assert sw.ports[0].tagged_vlans == [20, 30]
    assert snap["clients"][0].vlan is None and not snap["clients"][0].wired
    assert snap["firewall"][0].src == "net:IoT" and snap["firewall"][0].action == "drop"
    await u.power_cycle_port("AA:00:00:00:00:01", 2)
