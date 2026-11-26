"""Application graphs remain revision-compatible and unavailable for deployment."""

import os
import re
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from steward.core.canonical import revision_id
from steward.core.config import ConfigError, effective, parse_config


def graph(raw):
    base = raw["projects"][0]
    services = []
    for name, port, dependencies in (
        ("database", 21001, []),
        ("backend", 21002, ["database"]),
        ("frontend", 21003, ["backend"]),
        ("worker", 21004, ["database"]),
    ):
        service = deepcopy(base)
        service.update(id=name, host_port=port, container_port=port - 2000, depends_on=dependencies)
        services.append(service)
    raw["applications"] = [{"id": "shop", "isolation": "separate", "services": services}]
    return raw["applications"][0]


def test_legacy_example_revisions_and_empty_applications_remain_unchanged(raw_config):
    expected = {
        "server.api.yml": "572957dc0aab43a377b60f1a630925866f236e9454ca5361b41f770c2dbd7d5b",
        "server.local-ai.yml": "77e098362697edf539494e3f24b872c505215e7f2e6534eaa28ed1468f31728c",
    }
    for name, digest in expected.items():
        data = yaml.safe_load((Path(__file__).resolve().parents[1] / "examples" / name).read_text())
        assert revision_id(effective(parse_config(data, allow_unavailable=True))) == digest
        data["applications"] = []
        assert revision_id(effective(parse_config(data, allow_unavailable=True))) == digest


def test_planned_example_is_valid_but_blocked():
    path = Path(__file__).resolve().parents[1] / "examples/server.application-planned.yml"
    raw = yaml.safe_load(path.read_text())
    assert parse_config(raw, allow_unavailable=True).applications[0].start_order() == [
        "notes-a",
        "notes-b",
    ]
    with pytest.raises(ConfigError, match="applications.*not available"):
        parse_config(raw)


def test_graph_order_is_stable_and_unavailable_for_deployment(raw_config):
    app = graph(raw_config)
    with pytest.raises(ConfigError, match="applications.*not available"):
        parse_config(raw_config)
    cfg = parse_config(raw_config, allow_unavailable=True)
    model = cfg.applications[0]
    assert model.start_order() == ["database", "backend", "frontend", "worker"]
    assert model.stop_order() == ["worker", "frontend", "backend", "database"]
    assert model.dependents("database") == ["backend", "frontend", "worker"]
    assert model.dependents("backend") == ["frontend"]
    with pytest.raises(ValueError, match="unknown service"):
        model.dependents("missing")
    app["services"].reverse()
    assert (
        parse_config(raw_config, allow_unavailable=True).applications[0].start_order()
        == model.start_order()
    )
    assert effective(cfg)["applications"][0]["id"] == "shop"


@pytest.mark.parametrize(
    "failure", ["missing", "cycle", "self", "duplicate_edge", "duplicate_id", "port", "shared_port"]
)
def test_invalid_graphs_are_rejected(raw_config, failure):
    app = graph(raw_config)
    services = app["services"]
    if failure == "missing":
        services[0]["depends_on"] = ["missing"]
    elif failure == "cycle":
        services[0]["depends_on"] = ["frontend"]
    elif failure == "self":
        services[0]["depends_on"] = ["database"]
    elif failure == "duplicate_edge":
        services[1]["depends_on"] = ["database", "database"]
    elif failure == "duplicate_id":
        services[1]["id"] = "database"
    elif failure == "shared_port":
        app["isolation"] = "shared"
        services[1]["container_port"] = services[0]["container_port"]
    else:
        services[0]["host_port"] = raw_config["projects"][0]["host_port"]
    with pytest.raises(ConfigError):
        parse_config(raw_config, allow_unavailable=True)


@pytest.mark.parametrize("isolation", ["shared", "separate"])
def test_prepared_bindings_are_deterministic_and_do_not_enable_deployment(raw_config, isolation):
    from steward.core.render import (
        has_public_routes,
        prepare_application_graphs,
        render_nftables,
        render_registry,
        render_traefik_dynamic,
        render_vars,
    )

    app = graph(raw_config)
    app["isolation"] = isolation
    cfg = parse_config(raw_config, allow_unavailable=True)
    prepared = prepare_application_graphs(cfg)[0]
    services = prepared["services"]
    assert [service["id"] for service in services] == prepared["start_order"]
    assert prepared["stop_order"] == list(reversed(prepared["start_order"]))
    assert [service["host_port"] for service in services] == [21001, 21002, 21003, 21004]
    assert all(
        service["data_source"].startswith("/srv/steward/applications/shop/data/")
        for service in services
    )
    users = {service["user"] for service in services}
    assert len(users) == (1 if isolation == "shared" else 4)
    assert (prepared["network"] is not None) is (isolation == "shared")
    assert prepared["service_hosts"] == (
        [
            {"name": name, "address": "127.0.0.1"}
            for name in ("backend", "database", "frontend", "worker")
        ]
        if isolation == "shared"
        else []
    )
    edges = {service["id"]: service["loopback_dependencies"] for service in services}
    if isolation == "separate":
        assert edges == {
            "database": [],
            "backend": [{"service": "database", "port": 21001}],
            "frontend": [{"service": "backend", "port": 21002}],
            "worker": [{"service": "database", "port": 21001}],
        }
    else:
        assert all(not dependencies for dependencies in edges.values())
    app["services"].reverse()
    assert prepare_application_graphs(parse_config(raw_config, allow_unavailable=True)) == [
        prepared
    ]
    with pytest.raises(ValueError, match="application deployment is not available"):
        render_vars(cfg, release={"version": "1", "files": {}}, ssh_port=22)
    with pytest.raises(ValueError, match="application deployment is not available"):
        render_registry(cfg)
    with pytest.raises(ValueError, match="application deployment is not available"):
        render_nftables(cfg, 22)
    with pytest.raises(ValueError, match="application deployment is not available"):
        render_traefik_dynamic(cfg)
    with pytest.raises(ValueError, match="application deployment is not available"):
        has_public_routes(cfg)
    cfg.bot.public_hostname = "bot.example.com"
    with pytest.raises(ValueError, match="application deployment is not available"):
        has_public_routes(cfg)


def test_prepared_bindings_reject_legacy_user_collisions(raw_config):
    from steward.core.render import _graph_identifier, prepare_application_graphs

    app = graph(raw_config)
    app["isolation"] = "shared"
    raw_config["projects"][0]["id"] = _graph_identifier("a", "shop")
    cfg = parse_config(raw_config, allow_unavailable=True)
    with pytest.raises(ValueError, match="identity collision"):
        prepare_application_graphs(cfg)


def test_prepared_bindings_reject_legacy_pod_unit_collisions(raw_config):
    from steward.core.render import _graph_identifier, prepare_application_graphs

    app = graph(raw_config)
    app["isolation"] = "shared"
    raw_config["projects"][0]["id"] = _graph_identifier("a", "shop") + "-pod"
    cfg = parse_config(raw_config, allow_unavailable=True)
    with pytest.raises(ValueError, match="identity collision"):
        prepare_application_graphs(cfg)


def test_separate_services_may_reuse_container_ports(raw_config):
    app = graph(raw_config)
    app["isolation"] = "separate"
    app["services"][1]["container_port"] = app["services"][0]["container_port"]
    assert len(parse_config(raw_config, allow_unavailable=True).applications[0].services) == 4


@pytest.mark.parametrize("isolation", ["shared", "separate"])
def test_inert_quadlets_bind_services_without_enabling_them(raw_config, isolation):
    from steward.core.render import HOST_LOOPBACK_ALIAS, render_application_quadlets

    app = graph(raw_config)
    app["isolation"] = isolation
    app["services"][1]["run_as"] = 10002
    app["services"][2]["deploy"] = False
    app["services"][3]["manage"] = False
    cfg = parse_config(raw_config, allow_unavailable=True)
    rendered = render_application_quadlets(cfg, "/opt/steward/releases/test")[0]
    units = {unit["id"]: unit for unit in rendered["services"]}
    assert list(units) == ["database", "backend", "frontend"]
    assert all("[Install]" not in unit["content"] for unit in units.values())
    assert all("Pull=never" in unit["content"] for unit in units.values())
    assert all(":rw,nosuid,nodev,U" not in unit["content"] for unit in units.values())
    assert units["backend"]["data_source"].endswith("/shop/data/backend")
    assert units["backend"]["data_owner_container_uid"] == 10002
    assert units["backend"]["deploy"] and not units["frontend"]["deploy"]
    if isolation == "shared":
        pod = rendered["pod"]
        assert pod["unit"] == pod["filename"].removesuffix(".pod") + "-pod.service"
        assert pod["user"] == units["database"]["user"]
        assert "UserNS=keep-id:uid=10001,gid=10001" in pod["content"]
        assert "AddHost=database:127.0.0.1" in pod["content"]
        assert "PublishPort=127.0.0.1:21001:19001" in pod["content"]
        assert "PublishPort=127.0.0.1:21003:19003" not in pod["content"]
        assert all(f"Pod={pod['filename']}" in unit["content"] for unit in units.values())
        assert all("StartWithPod=false" in unit["content"] for unit in units.values())
        assert all("UserNS=" not in unit["content"] for unit in units.values())
        assert units["backend"]["data_needs_mapped_owner"]
        assert not units["database"]["data_needs_mapped_owner"]
    else:
        assert rendered["pod"] is None
        assert "UserNS=keep-id:uid=10002,gid=10002" in units["backend"]["content"]
        assert (
            f"Network=pasta:--map-host-loopback,{HOST_LOOPBACK_ALIAS}"
            in units["backend"]["content"]
        )
        assert "Network=pasta\n" in units["database"]["content"]
        assert all(not unit["data_needs_mapped_owner"] for unit in units.values())
    app["services"].reverse()
    assert render_application_quadlets(
        parse_config(raw_config, allow_unavailable=True), "/opt/steward/releases/test"
    ) == [rendered]


def test_unmanaged_shared_application_has_no_quadlets(raw_config):
    from steward.core.render import prepare_application_registry, render_application_quadlets

    app = graph(raw_config)
    app["isolation"] = "shared"
    for service in app["services"]:
        service["manage"] = False
    cfg = parse_config(raw_config, allow_unavailable=True)
    assert render_application_quadlets(cfg, "/opt/steward/releases/test") == [
        {"id": "shop", "pod": None, "services": []}
    ]
    assert prepare_application_registry(cfg)["applications"]["shop"]["pod_unit"] is None


def test_separate_uid_egress_allows_only_direct_active_dependencies(raw_config):
    from steward.core.render import prepare_separate_application_egress, render_nftables

    app = graph(raw_config)
    app["services"][3]["deploy"] = False
    cfg = parse_config(raw_config, allow_unavailable=True)
    preview = prepare_separate_application_egress(cfg)
    chains = {item["service"]: item for item in preview}
    assert set(chains) == {"database", "backend", "frontend", "worker"}
    assert not chains["worker"]["deploy"] and not chains["worker"]["loopback_ports"]
    assert chains["worker"]["content"].strip().endswith("counter reject\n    }")
    assert chains["database"]["loopback_ports"] == []
    assert chains["backend"]["loopback_ports"] == [21001]
    assert chains["frontend"]["loopback_ports"] == [21002]
    backend = chains["backend"]["content"]
    allowed = 'oifname "lo" ip daddr 127.0.0.1 tcp dport { 21001 } accept'
    assert allowed in backend and backend.index(allowed) < backend.index(
        'oifname "lo" counter reject'
    )
    assert backend.index("ct direction reply accept") < backend.index(allowed)
    assert "ct state established,related accept" not in backend
    assert "21002" not in backend and "21003" not in backend
    assert "21001" not in chains["frontend"]["content"]  # no transitive grant
    assert 'oifname "lo" ip6' not in backend
    assert len({item["user"] for item in preview}) == 4
    # The live firewall remains unavailable for application graphs.
    with pytest.raises(ValueError, match="application deployment is not available"):
        render_nftables(cfg, 22)

    app["services"][0]["deploy"] = False
    cfg = parse_config(raw_config, allow_unavailable=True)
    chains = {item["service"]: item for item in prepare_separate_application_egress(cfg)}
    assert not chains["database"]["deploy"] and chains["backend"]["loopback_ports"] == []
    app["services"][0]["deploy"] = True
    app["services"][0]["manage"] = False
    cfg = parse_config(raw_config, allow_unavailable=True)
    chains = {item["service"]: item for item in prepare_separate_application_egress(cfg)}
    assert "database" not in chains and chains["backend"]["loopback_ports"] == []
    app["isolation"] = "shared"
    assert (
        prepare_separate_application_egress(parse_config(raw_config, allow_unavailable=True)) == []
    )


def test_separate_dependency_preserves_explicit_egress_policy(raw_config):
    from steward.core.render import prepare_separate_application_egress

    app = graph(raw_config)
    app["services"][1]["egress"] = {
        "mode": "rules",
        "rules": [{"proto": "tcp", "cidr": "10.20.0.5/32", "ports": [5432]}],
    }
    cfg = parse_config(raw_config, allow_unavailable=True)
    backend = next(
        item for item in prepare_separate_application_egress(cfg) if item["service"] == "backend"
    )["content"]
    assert "ip daddr 127.0.0.1 tcp dport { 21001 } accept" in backend
    assert "ip daddr 10.20.0.5/32 tcp dport { 5432 } accept" in backend
    assert backend.index('oifname "lo" counter reject') < backend.index("ip daddr 10.20.0.5/32")


def test_shared_uid_egress_is_explicit_union_of_active_contracts(raw_config):
    from steward.core.render import prepare_shared_application_egress, render_nftables

    app = graph(raw_config)
    app["isolation"] = "shared"
    app["services"][0]["egress"] = {"mode": "public-web"}
    app["services"][1]["egress"] = {
        "mode": "rules",
        "rules": [{"proto": "tcp", "cidr": "10.20.0.5/32", "ports": [5432, 443]}],
    }
    app["services"][2]["egress"] = {
        "mode": "rules",
        "rules": [{"proto": "tcp", "cidr": "10.20.0.5/32", "ports": [5432, 8443]}],
    }
    app["services"][3]["deploy"] = False
    app["services"][3]["egress"] = {
        "mode": "rules",
        "rules": [{"proto": "udp", "cidr": "10.30.0.5/32", "ports": [53]}],
    }
    cfg = parse_config(raw_config, allow_unavailable=True)
    result = prepare_shared_application_egress(cfg)[0]
    assert result["active_services"] == ["backend", "database", "frontend"]
    assert result["inactive_services"] == ["worker"]
    assert result["public_web"]
    assert result["rules"] == [{"cidr": "10.20.0.5/32", "proto": "tcp", "ports": [443, 5432, 8443]}]
    chain = result["content"]
    assert 'oifname "lo" ip daddr 127.0.0.53' in chain
    assert "ip daddr 10.20.0.5/32 tcp dport { 443, 5432, 8443 } accept" in chain
    assert chain.index("169.254.0.0/16") < chain.index("10.20.0.5/32") < chain.index("@private4")
    assert "10.30.0.5" not in chain
    assert "ct state established,related ct direction reply accept" in chain
    assert "ct state established,related accept" not in chain
    app["services"].reverse()
    assert prepare_shared_application_egress(parse_config(raw_config, allow_unavailable=True)) == [
        result
    ]
    with pytest.raises(ValueError, match="application deployment is not available"):
        render_nftables(cfg, 22)


def test_shared_uid_egress_ignores_inactive_and_separate_services(raw_config):
    from steward.core.render import prepare_shared_application_egress

    app = graph(raw_config)
    assert prepare_shared_application_egress(parse_config(raw_config, allow_unavailable=True)) == []
    app["isolation"] = "shared"
    for service in app["services"]:
        service["deploy"] = False
    stopped = prepare_shared_application_egress(parse_config(raw_config, allow_unavailable=True))
    assert len(stopped) == 1 and stopped[0]["active_services"] == []
    assert not stopped[0]["public_web"] and stopped[0]["rules"] == []
    assert stopped[0]["content"].strip().endswith("counter reject\n    }")
    for service in app["services"]:
        service["manage"] = False
    assert prepare_shared_application_egress(parse_config(raw_config, allow_unavailable=True)) == []


def _candidate_apps(raw):
    separate = graph(raw)
    separate["services"][3]["deploy"] = False
    shared = deepcopy(separate)
    shared.update(id="store", isolation="shared")
    unmanaged = deepcopy(separate)
    unmanaged.update(id="external")
    for service in shared["services"]:
        service["host_port"] += 10
        service["deploy"] = False
    for service in unmanaged["services"]:
        service["host_port"] += 20
        service["manage"] = False
    raw["applications"].extend((shared, unmanaged))
    return separate, shared, unmanaged


def test_private_candidate_vars_preserve_legacy_and_render_graph(raw_config, tmp_path):
    from steward.core.render import _render_application_candidate_vars, render_vars

    args = {"release": {"version": "test"}, "ssh_port": 22}
    legacy = render_vars(parse_config(raw_config), **args)
    assert _render_application_candidate_vars(parse_config(raw_config), **args) == legacy
    separate, shared, _ = _candidate_apps(raw_config)
    for service in shared["services"][:2]:
        service["deploy"] = True
    separate["services"][1]["secrets"] = [{"name": "TOKEN", "ref": f"file:{tmp_path / 'absent'}"}]
    cfg = parse_config(raw_config, allow_unavailable=True)
    with pytest.raises(ValueError, match="application deployment is not available"):
        render_vars(cfg, **args)
    variables = _render_application_candidate_vars(cfg, **args)
    shop, store = variables["steward_applications"]
    assert [app["id"] for app in (shop, store)] == ["shop", "store"]
    assert shop["pod"] is None and shop["isolation"] == "separate"
    assert store["pod"] and store["isolation"] == "shared"
    assert [service["id"] for service in shop["services"]] == [
        "database",
        "backend",
        "frontend",
        "worker",
    ]
    backend = shop["services"][1]
    assert backend["secrets"] == [
        {"name": "TOKEN", "kind": "file", "target": str(tmp_path / "absent")}
    ]
    assert f"Image={backend['image_tag']}\n" in backend["content"]
    assert backend["image"] == cfg.applications[0].services[1].image
    assert (backend["host_port"], backend["health_path"], backend["health_timeout_s"]) == (
        21002,
        cfg.applications[0].services[1].health.path,
        cfg.applications[0].services[1].health.timeout_s,
    )
    assert not shop["services"][-1]["deploy"]
    assert variables["steward_projects"] == legacy["steward_projects"]
    assert variables["steward_service_users"] == legacy["steward_service_users"]
    assert variables["steward_backup"]["projects"] == legacy["steward_backup"]["projects"]
    assert variables["steward_config_revision"] == revision_id(effective(cfg))
    assert variables["steward_registry"]["config_revision"] == variables["steward_config_revision"]
    assert variables["steward_backup"]["config_revision"] == variables["steward_config_revision"]
    assert variables["steward_desired_config"] == effective(cfg)
    assert (
        variables["steward_registry"]["applications"]["shop"]["services"]["backend"]["unit"]
        == (backend["unit"])
    )
    external = variables["steward_registry"]["applications"]["external"]
    assert external["pod_unit"] is None
    assert external["services"] and not any(s["manage"] for s in external["services"].values())
    assert variables["steward_listen_ports"] == sorted(
        legacy["steward_listen_ports"] + [21001, 21002, 21003, 21011, 21012]
    )
    assert variables["steward_required_memory_mb"] == legacy["steward_required_memory_mb"] + 5 * 128
    names = sorted({s["user"] for app in (shop, store) for s in app["services"]})
    assert len(names) == 5
    assert variables["steward_application_users"] == [
        {"name": name, "home": f"/srv/steward/application-users/{name}"} for name in names
    ]
    chains = variables["steward_application_egress"]
    assert sorted(chain["user"] for chain in chains) == names
    assert all(
        f'"{item["user"]}" : jump {item["chain"]}' in variables["steward_nftables"]
        for item in chains
    )

    raw_config["applications"].reverse()
    for app in raw_config["applications"]:
        app["services"].reverse()
    reordered = _render_application_candidate_vars(
        parse_config(raw_config, allow_unavailable=True), **args
    )
    for field in ("applications", "application_users", "application_egress", "nftables"):
        assert reordered[f"steward_{field}"] == variables[f"steward_{field}"]


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("unavailable", "profile.local-ai"),
        ("firewall", "requires managed firewall"),
        ("route", "application ACME routes are not available"),
        ("ssh_collision", "host port collides with SSH port 21001"),
        ("stopped_prerequisite", "prerequisite database must be active"),
        ("unmanaged_prerequisite", "prerequisite database must be active"),
        ("identity_collision", "identity collision"),
    ],
)
def test_private_candidate_vars_refuse_unsafe_config(raw_config, failure, message):
    from steward.core.ids import graph_identifier
    from steward.core.render import _render_application_candidate_vars

    app = graph(raw_config)
    if failure == "unavailable":
        raw_config["profile"] = "local-ai"
    elif failure == "firewall":
        raw_config["hardening"]["firewall"]["manage"] = False
    elif failure == "route":
        raw_config["proxy"] = {"acme_email": "ops@example.org"}
        app["services"][0]["routes"] = [{"host": "shop.example.org", "tls": "acme"}]
    elif failure == "stopped_prerequisite":
        app["services"][0]["deploy"] = False
    elif failure == "unmanaged_prerequisite":
        app["services"][0]["manage"] = False
    elif failure == "identity_collision":
        raw_config["projects"][0]["id"] = graph_identifier("s", "shop", "database")
    cfg = parse_config(raw_config, allow_unavailable=True)
    ssh_port = 21001 if failure == "ssh_collision" else 22
    with pytest.raises(ValueError, match=message):
        _render_application_candidate_vars(cfg, release={"version": "test"}, ssh_port=ssh_port)


def test_private_candidate_marks_mixed_shared_data_for_runtime_verification(raw_config):
    from steward.core.render import _render_application_candidate_vars, render_vars

    app = graph(raw_config)
    app["isolation"] = "shared"
    app["services"][1]["run_as"] = 10002
    cfg = parse_config(raw_config, allow_unavailable=True)
    with pytest.raises(ValueError, match="application deployment is not available"):
        render_vars(cfg, release={"version": "test"}, ssh_port=22)
    variables = _render_application_candidate_vars(cfg, release={"version": "test"}, ssh_port=22)
    [application] = variables["steward_applications"]
    services = {service["id"]: service for service in application["services"]}
    assert not services["database"]["data_needs_mapped_owner"]
    assert services["backend"]["data_needs_mapped_owner"]
    assert services["backend"]["data_owner_container_uid"] == 10002


@pytest.mark.parametrize("isolation", ["shared", "separate"])
def test_private_candidate_quadlet_generator_leaves_units_off_boot(raw_config, tmp_path, isolation):
    from steward.core.render import _render_application_candidate_vars

    generator = Path("/usr/libexec/podman/quadlet")
    if not generator.is_file():
        pytest.skip("needs the Podman Quadlet generator")
    app = graph(raw_config)
    app["isolation"] = isolation
    app["services"] = app["services"][:2]
    cfg = parse_config(raw_config, allow_unavailable=True)
    variables = _render_application_candidate_vars(cfg, release={"version": "test"}, ssh_port=22)
    application = variables["steward_applications"][0]
    quadlets = application["services"] + ([application["pod"]] if application["pod"] else [])
    source, output = tmp_path / "quadlets", tmp_path / "generated"
    source.mkdir()
    output.mkdir()
    for unit in quadlets:
        (source / unit["filename"]).write_text(unit["content"])
    # A control with an install section proves this invocation emits boot links.
    (source / "boot-control.container").write_text(
        "[Container]\nImage=localhost/test:x\n[Install]\nWantedBy=default.target\n"
    )
    subprocess.run(
        [str(generator), "--user", str(output), str(output), str(output)],
        env={**os.environ, "QUADLET_UNIT_DIRS": str(source)},
        check=True,
    )
    assert (output / "default.target.wants" / "boot-control.service").is_symlink()
    assert all((output / unit["unit"]).is_file() for unit in quadlets)
    assert not any(
        path.is_symlink() and path.name == unit["unit"]
        for path in output.rglob("*")
        for unit in quadlets
    )


def test_application_firewall_candidate_dispatch_and_port_reservations(raw_config):
    from steward.core.render import (
        _render_application_nftables_candidate,
        prepare_application_graphs,
        prepare_separate_application_egress,
        prepare_shared_application_egress,
        render_nftables,
    )

    _candidate_apps(raw_config)
    cfg = parse_config(raw_config, allow_unavailable=True)
    rules = _render_application_nftables_candidate(cfg, 22)
    with pytest.raises(ValueError, match="application deployment is not available"):
        render_nftables(cfg, 22)
    chains = prepare_separate_application_egress(cfg) + prepare_shared_application_egress(cfg)
    verdicts = re.findall(r'"([^"]+)" : jump (\w+)', rules)
    bindings = prepare_application_graphs(cfg)
    application_users = {
        service["user"] for application in bindings for service in application["services"]
    }
    assert len(chains) == 5
    assert [(user, chain) for user, chain in verdicts if user in application_users] == [
        (item["user"], item["chain"]) for item in chains
    ]
    for item in chains:
        assert rules.count(item["content"]) == 1
    assert chains[-1]["active_services"] == []
    assert chains[-1]["content"].endswith("counter reject\n    }")

    legacy = sorted([cfg.projects[0].host_port, cfg.admin.backend_port, cfg.bot.port])
    reservations = [21001, 21002, 21003, 21004, 21011, 21012, 21013, 21014]
    proxy_ports = ", ".join(map(str, legacy))
    denied = ", ".join(map(str, reservations))
    allowed_users = ", ".join(["0", '"steward-proxy"', *(f'"{item["user"]}"' for item in chains)])
    guard = (
        f'oifname "lo" tcp dport {{ {denied} }} meta skuid != {{ {allowed_users} }} '
        "ct direction original counter reject with tcp reset"
    )
    assert rules.index(guard) < rules.index("meta skuid vmap")
    assert f"tcp dport {{ {proxy_ports} }} meta skuid != 0 ct state new counter reject" in rules
    proxy = rules.split("    chain egress_proxy {")[1].split("\n    }")[0]
    assert f'oifname "lo" tcp dport {{ {proxy_ports} }} accept' in proxy
    assert proxy.index(f"tcp dport {{ {denied} }} ct direction original counter reject") < (
        proxy.index("ct state established,related accept")
    )
    assert "redirect" not in rules
    assert all(str(port) not in rules for port in range(21021, 21025))


def test_only_active_managed_application_routes_change_candidate_ingress(raw_config):
    import yaml

    from steward.core.render import (
        APPLICATION_PROXY_DYNAMIC,
        HOST_LOOPBACK_ALIAS,
        ApplicationProxyRoute,
        _render_application_candidate_vars,
        _render_application_nftables_candidate,
        application_proxy_routes,
        render_application_proxy_configuration,
        render_application_proxy_routes,
        render_vars,
    )

    separate, shared, unmanaged = _candidate_apps(raw_config)
    shared["services"][0]["routes"] = [{"host": "stopped.example.org", "tls": "internal"}]
    unmanaged["services"][0]["routes"] = [{"host": "external.example.org", "tls": "internal"}]
    args = {"release": {"version": "test"}, "ssh_port": 22}
    cfg = parse_config(raw_config, allow_unavailable=True)
    legacy = render_vars(cfg.model_copy(update={"applications": []}), **args)["steward_proxy"]
    without_routes = _render_application_candidate_vars(cfg, **args)
    assert without_routes["steward_proxy"] == legacy
    assert not without_routes["steward_public_routes"]
    assert "redirect" not in without_routes["steward_nftables"]

    frontend = separate["services"][2]
    frontend["routes"] = [
        {"host": "shop.example.org", "tls": "internal"},
        {"host": "alias.example.org", "tls": "internal"},
    ]
    cfg = parse_config(raw_config, allow_unavailable=True)
    routes = application_proxy_routes(cfg)
    assert routes == tuple(
        ApplicationProxyRoute(separate["id"], frontend["id"], host, 21003)
        for host in ["alias.example.org", "shop.example.org"]
    )
    http = yaml.safe_load(render_application_proxy_routes(routes))["http"]
    assert len(http["services"]) == 1
    service, backend = next(iter(http["services"].items()))
    assert backend["loadBalancer"]["servers"] == [{"url": f"http://{HOST_LOOPBACK_ALIAS}:21003"}]
    assert {router["rule"] for router in http["routers"].values()} == {
        "Host(`alias.example.org`)",
        "Host(`shop.example.org`)",
    }
    for router in http["routers"].values():
        assert router["service"] == service
        assert router["entryPoints"] == ["websecure"]
        assert router["tls"] == {}
        assert router["middlewares"] == ["security-headers"]

    candidate = _render_application_candidate_vars(cfg, **args)
    settings = candidate["steward_proxy"]
    artifacts = render_application_proxy_configuration(cfg, routes)
    assert artifacts == {key: settings[key] for key in artifacts}
    assert candidate["steward_public_routes"]
    assert settings["dynamic"] == legacy["dynamic"]
    assert settings["application_runtime"] == APPLICATION_PROXY_DYNAMIC
    assert f"Volume={APPLICATION_PROXY_DYNAMIC}:/etc/traefik/dynamic:ro" in settings["quadlet"]
    assert [
        line for line in settings["quadlet"].splitlines() if line.startswith("PublishPort=")
    ] == [
        f"PublishPort=127.0.0.1:{cfg.admin.port}:{cfg.admin.port}",
        "PublishPort=8080:8080",
        "PublishPort=8443:8443",
    ]
    assert yaml.safe_load(settings["static"])["entryPoints"].keys() == {"admin", "web", "websecure"}
    assert settings["internal_hosts"] == sorted(
        set(legacy["internal_hosts"]) | {"alias.example.org", "shop.example.org"}
    )
    rules = candidate["steward_nftables"]
    assert rules == _render_application_nftables_candidate(cfg, 22)
    assert "tcp dport { 8080, 8443 } ct status dnat accept" in rules
    assert "tcp dport 443 redirect to :8443" in rules
    proxy = rules.split("    chain egress_proxy {")[1].split("\n    }")[0]
    ports = sorted([cfg.projects[0].host_port, cfg.admin.backend_port, cfg.bot.port, 21003])
    assert f'oifname "lo" tcp dport {{ {", ".join(map(str, ports))} }} accept' in proxy
    assert "tcp dport 443 accept" not in proxy

    frontend["routes"].reverse()
    raw_config["applications"].reverse()
    for app in raw_config["applications"]:
        app["services"].reverse()
    cfg = parse_config(raw_config, allow_unavailable=True)
    assert application_proxy_routes(cfg) == routes


@pytest.mark.parametrize("index", [0, 1, 2])
def test_application_candidate_refuses_acme_even_for_inactive_services(raw_config, index):
    from steward.core.render import _render_application_nftables_candidate

    apps = _candidate_apps(raw_config)
    raw_config["proxy"] = {"acme_email": "ops@example.org"}
    apps[index]["services"][0]["routes"] = [{"host": "shop.example.org", "tls": "acme"}]
    cfg = parse_config(raw_config, allow_unavailable=True)
    with pytest.raises(ValueError, match="application ACME routes are not available"):
        _render_application_nftables_candidate(cfg, 22)


def test_application_firewall_candidate_requires_managed_firewall(raw_config):
    from steward.core.render import _render_application_nftables_candidate, render_nftables

    cfg = parse_config(raw_config)
    assert _render_application_nftables_candidate(cfg, 22) == render_nftables(cfg, 22)
    graph(raw_config)
    raw_config.setdefault("hardening", {})["firewall"] = {"manage": False}
    cfg = parse_config(raw_config, allow_unavailable=True)
    with pytest.raises(ValueError, match="requires managed firewall"):
        _render_application_nftables_candidate(cfg, 22)


@pytest.mark.skipif(not shutil.which("nft") or not shutil.which("unshare"), reason="needs nft")
def test_application_firewall_candidate_loads_in_private_namespace(raw_config, tmp_path):
    from steward.core.render import _render_application_nftables_candidate

    probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True)
    if probe.returncode:
        pytest.skip("unprivileged user namespaces unavailable")
    _candidate_apps(raw_config)
    rules = _render_application_nftables_candidate(
        parse_config(raw_config, allow_unavailable=True), 22
    )
    users = re.findall(r'"([^"]+)" : jump', rules)
    numeric_rules = rules
    for uid, user in enumerate(users, 21000):
        numeric_rules = numeric_rules.replace(f'"{user}"', str(uid))
    path = tmp_path / "steward.nft"
    path.write_text(numeric_rules)
    subprocess.run(
        ["unshare", "-rn", "sh", "-c", 'nft -f "$1" && nft -f "$1"', "sh", str(path)],
        check=True,
    )


@pytest.mark.parametrize("isolation", ["shared", "separate"])
def test_application_registry_bindings_match_quadlets_and_group_locks(
    raw_config, executor, isolation
):
    import json

    from steward.core.render import prepare_application_registry, render_application_quadlets
    from steward.executor.protocol import ExecutorError

    app = graph(raw_config)
    app["isolation"] = isolation
    app["services"][3]["manage"] = False
    app["services"][1]["secrets"] = [{"name": "KEY", "ref": "env:TEST_PRIVATE_SECRET"}]
    cfg = parse_config(raw_config, allow_unavailable=True)
    registry = prepare_application_registry(cfg)
    registered = registry["applications"]["shop"]
    quadlets = render_application_quadlets(cfg, "/opt/steward/releases/test")[0]
    assert registry["config_revision"] == revision_id(effective(cfg))
    assert "TEST_PRIVATE_SECRET" not in json.dumps(registry)
    assert registered["services"]["worker"]["manage"] is False
    assert registered["services"]["backend"]["depends_on"] == ["database"]
    for unit in quadlets["services"]:
        spec = registered["services"][unit["id"]]
        assert (spec["user"], spec["unit"], spec["data_source"]) == (
            unit["user"],
            unit["unit"],
            unit["data_source"],
        )
    assert (registered["pod_unit"] is not None) is (isolation == "shared")
    targets = [registered["lock"], *(spec["lock"] for spec in registered["services"].values())]
    with executor.target_locks(targets):
        with (
            pytest.raises(ExecutorError) as error,
            executor.target_lock(registered["services"]["backend"]["lock"]),
        ):
            pytest.fail("a registered service lock must conflict with the group")
        assert error.value.error_class == "target_busy"


def test_stateless_marker_is_explicit_validated_and_absent_from_canonical_data_until_set(
    raw_config,
):
    from steward.core.render import prepare_application_registry

    app = graph(raw_config)
    plain = parse_config(raw_config, allow_unavailable=True)
    revision = revision_id(effective(plain))
    assert plain.applications[0].stateless is False
    assert "stateless" not in effective(plain)["applications"][0]
    app["stateless"] = False
    assert revision_id(effective(parse_config(raw_config, allow_unavailable=True))) == revision
    app["stateless"] = True
    with pytest.raises(ConfigError, match="stateless application cannot register data"):
        parse_config(raw_config, allow_unavailable=True)  # data registered: not stateless
    for service in app["services"]:
        service["data_path"] = None
    marked = parse_config(raw_config, allow_unavailable=True)
    assert effective(marked)["applications"][0]["stateless"] is True
    assert prepare_application_registry(marked)["applications"]["shop"]["stateless"] is True
    app["stateless"] = False  # merely having no data registered is not the marker
    unmarked = prepare_application_registry(parse_config(raw_config, allow_unavailable=True))
    assert "stateless" not in unmarked["applications"]["shop"]
