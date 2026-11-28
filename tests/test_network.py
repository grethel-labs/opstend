from opstend.adapters.base import Bridge
from opstend.core.models import (
    Client,
    Device,
    DeviceKind,
    FirewallRule,
    Guest,
    GuestKind,
    GuestState,
    Host,
    Lldp,
    Network,
    Nic,
    Platform,
    Port,
    RuleAction,
)
from opstend.network import analysis, graph, plantuml

NETS = [
    Network(id="lan", name="LAN", subnet="10.20.10.0/24"),
    Network(id="srv", name="Server", vlan=20, subnet="10.20.20.0/24"),
    Network(id="iot", name="IoT", vlan=30, subnet="10.20.30.0/24"),
]


def fixture(port_vlans=(20,), rules=None, iot_isolated=False):
    nets = [n.model_copy() for n in NETS]
    nets[2].isolated = iot_isolated
    gw = Device(
        id="unifi:gw",
        name="gw",
        kind=DeviceKind.GATEWAY,
        mac="aa:00",
        ports=[Port(index=4, name="P4", up=True, speed_mbps=1000)],
    )
    sw = Device(
        id="unifi:sw",
        name="sw-werkstatt",
        kind=DeviceKind.SWITCH,
        mac="aa:01",
        uplink_mac="aa:00",
        uplink_port=4,
        poe_budget_watts=50,
        ports=[
            Port(index=1, name="P1", up=True, speed_mbps=1000, is_uplink=True),
            Port(
                index=2,
                name="P2",
                up=True,
                speed_mbps=100,
                max_speed_mbps=1000,
                native_vlan=1,
                tagged_vlans=list(port_vlans),
                poe_watts=45,
                lldp=Lldp(chassis="bc:00", port="enp1s0", name="nuc-a"),
            ),
            Port(index=3, name="P3", up=True, speed_mbps=1000, rx_errors=500),
        ],
    )
    ap = Device(
        id="unifi:ap",
        name="ap-flur",
        kind=DeviceKind.ACCESS_POINT,
        mac="aa:02",
        uplink_mac="aa:01",
        uplink_port=3,
        ports=[Port(index=1, name="P1", up=True, is_uplink=True, speed_mbps=1000)],
    )
    host = Host(id="pve:node:nuc-a", name="nuc-a", platform=Platform.PROXMOX, address="10.20.10.11")
    guest = Guest(
        id="pve:101",
        host_id=host.id,
        kind=GuestKind.VM,
        native_id="101",
        name="medien",
        state=GuestState.RUNNING,
        nics=[Nic(name="net0", mac="bc:24:00:00:00:01", bridge="vmbr0", vlan=30)],
    )
    bridge = Bridge(host_id=host.id, name="vmbr0", vlan_aware=True, mac="bc:00")
    laptop = Client(
        mac="11:22",
        name="laptop",
        ip="10.20.30.50",
        network_id="iot",
        vlan=30,
        device_mac="aa:02",
        wired=False,
        signal_dbm=-80,
    )
    fw = rules or []
    g = graph.build(
        devices=[gw, sw, ap],
        clients=[laptop],
        networks=nets,
        firewall=fw,
        hosts=[host],
        guests=[guest],
        bridges=[bridge],
    )
    return g, [gw, sw, ap]


def test_graph_joins_unifi_and_proxmox():
    g, _ = fixture()
    kinds = {(g.vertices[e.a].kind, g.vertices[e.b].kind) for e in g.edges}
    assert ("switch", "host") in kinds  # via LLDP chassis = bridge MAC
    assert ("gateway", "switch") in kinds and ("switch", "ap") in kinds
    assert ("guest", "bridge") in kinds and ("ap", "client") in kinds


def test_vlan_mismatch_is_found_with_fix():
    g, devices = fixture(port_vlans=(20,))
    found = [i for i in analysis.analyze(g, devices) if i.code == "vlan-not-carried"]
    assert len(found) == 1
    assert "VLAN 30" in found[0].title and found[0].fix["add_vlan"] == 30
    g2, devices2 = fixture(port_vlans=(20, 30))
    assert not [i for i in analysis.analyze(g2, devices2) if i.code == "vlan-not-carried"]


def test_link_poe_errors_wifi_findings():
    g, devices = fixture()
    codes = {i.code for i in analysis.analyze(g, devices)}
    assert {"link-downgraded", "poe-budget", "port-errors", "weak-wifi"} <= codes


def test_explain_path_through_firewall():
    rules = [
        FirewallRule(
            id="r",
            name="IoT to Server",
            action=RuleAction.DROP,
            src="net:IoT",
            dst="net:Server",
            order=1,
        )
    ]
    g, _ = fixture(port_vlans=(20, 30), rules=rules)
    # laptop (IoT, VLAN 30) to guest (VLAN 30): same VLAN, switched.
    same = graph.explain(g, "client:11:22", "pve:101")
    assert same.reachable and "same VLAN" in same.steps[0]
    g.vertices["pve:101"]  # guest exists
    # Move the guest to VLAN 20 (Server): the firewall rule blocks.
    for e in g.edges:
        if e.kind == "vnic":
            e.native_vlan, e.vlans = 20, [20]
    blocked = graph.explain(g, "client:11:22", "pve:101")
    assert not blocked.reachable and "IoT to Server" in blocked.steps[1]


def test_segmentation_insight_respects_isolation():
    g, devices = fixture()
    assert any(i.code == "segmentation-open" for i in analysis.analyze(g, devices))
    g2, devices2 = fixture(iot_isolated=True)
    assert not any(i.code == "segmentation-open" for i in analysis.analyze(g2, devices2))


def test_plantuml_has_hooks_and_marks_problems():
    g, devices = fixture()
    insights = analysis.analyze(g, devices)
    src = plantuml.render(g, {"physical", "network"}, insights)
    assert src.startswith("@startuml") and src.endswith("@enduml")
    assert "@hook #unifi_sw alias:unifi_sw" in src
    assert "#FDE7E7" in src  # flagged switch
    assert "-[#C2410C,dashed]-" in src  # 100 Mbit link
    assert "Allow VLAN 30" in src
    assert plantuml.hook_id("9abc") == "n_9abc"
    assert len(plantuml.hook_id("x" * 200)) <= 64
