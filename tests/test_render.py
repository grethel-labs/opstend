import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from steward.core import render
from steward.core.config import Backup, BackupEndpoint, ConfigError, effective, parse_config
from steward.core.repositories import FetchError
from steward.core.repository_fetch_package import Manifest
from test_repositories import with_repository

QUADLET = "/usr/libexec/podman/quadlet"


def with_routes(raw):
    raw["proxy"] = {"acme_email": "ops@example.org"}
    raw["projects"][0]["routes"] = [{"host": "notes.example.org", "tls": "acme"}]
    raw["projects"][0]["egress"] = {"mode": "public-web"}
    raw["projects"].append(
        {
            **raw["projects"][0],
            "id": "worker",
            "host_port": 20081,
            "routes": [],
            "egress": {
                "mode": "rules",
                "rules": [
                    {"proto": "tcp", "cidr": "10.20.0.5/32", "ports": [5432]},
                    {"proto": "udp", "cidr": "2001:db8::/32", "ports": [53, 123]},
                ],
            },
        }
    )
    return parse_config(raw)


def test_without_routes_no_public_port_is_opened(cfg):
    rules = render.render_nftables(cfg, 22)
    assert "redirect" not in rules and "8443" not in rules and "prerouting" not in rules
    assert "tcp dport 22 accept" in rules
    ports = [
        line
        for line in render.render_proxy_quadlet(cfg).splitlines()
        if line.startswith("PublishPort=")
    ]
    assert ports == [f"PublishPort=127.0.0.1:{cfg.admin.port}:{cfg.admin.port}"]
    assert "websecure" not in render.render_traefik_static(cfg)
    variables = render.render_vars(cfg, release={"version": "1"}, ssh_port=22)
    assert variables["steward_admin"]["access"] == "private"
    assert variables["steward_admin"]["lan"] is None
    assert variables["steward_admin"]["allowed_origins"] == [
        f"https://localhost:{cfg.admin.port}",
        f"https://127.0.0.1:{cfg.admin.port}",
    ]
    assert variables["steward_proxy"]["internal_sans"] == ["DNS:localhost", "IP:127.0.0.1"]


@pytest.mark.parametrize(
    ("access", "lan"),
    [
        ("private", None),
        ("private-loopback", None),
        ("private-lan", None),
        ("private-lan", {"advertise_ipv4": "192.168.7.5"}),
    ],
)
def test_admin_without_resolved_scope_stays_on_loopback(raw_config, access, lan):
    raw_config["admin"].update(access=access, lan=lan)
    cfg = parse_config(raw_config)
    port = cfg.admin.port
    quadlet = render.render_proxy_quadlet(cfg)
    assert [line for line in quadlet.splitlines() if line.startswith("PublishPort=")] == [
        f"PublishPort=127.0.0.1:{port}:{port}"
    ]
    assert "admin-lan" not in render.render_traefik_static(cfg)
    assert "admin-lan" not in render.render_traefik_dynamic(cfg)
    fence = f'iifname != "lo" ct direction original tcp dport {port} drop'
    different = render.render_nftables(cfg, 2222)
    assert different.index(fence) < different.index("ct state established,related accept")
    provisional = render.render_vars(cfg, release={"version": "1"}, ssh_port=port)
    assert fence not in provisional["steward_nftables"]
    assert f"tcp dport {port} accept" in provisional["steward_nftables"]
    assert provisional["steward_admin"]["allowed_origins"] == [
        f"https://localhost:{port}",
        f"https://127.0.0.1:{port}",
    ]
    assert provisional["steward_proxy"]["internal_sans"] == ["DNS:localhost", "IP:127.0.0.1"]


def test_resolved_lan_admin_is_fenced_and_separate_from_bot_and_public_routes(raw_config):
    lan = {
        "interface": "enp1s0",
        "bind": "192.168.7.4/24",
        "allowed_sources": ["192.168.7.128/25", "10.5.0.0/16"],
        "advertise_ipv4": "192.168.7.5",
    }
    raw_config["admin"].update(access="private-lan", lan=lan, port=8079)
    raw_config["bot"] = {
        "public_hostname": "bot.example.org",
        "endpoints": [
            {
                "id": "ops",
                "adapter": "discord",
                "application_id": "123",
                "verification_key_ref": "env:DISCORD_KEY",
                "grants": [],
            }
        ],
    }
    cfg = with_routes(raw_config)
    variables = render.render_vars(cfg, release={"version": "1"}, ssh_port=2222)
    proxy = variables["steward_proxy"]
    assert variables["steward_admin"]["lan"] == lan
    assert variables["steward_admin"]["allowed_origins"] == [
        "https://localhost:8079",
        "https://127.0.0.1:8079",
        "https://192.168.7.4:8079",
        "https://192.168.7.5:8079",
    ]
    assert proxy["internal_sans"] == [
        "DNS:localhost",
        "IP:127.0.0.1",
        "IP:192.168.7.4",
        "IP:192.168.7.5",
    ]
    entrypoints = yaml.safe_load(proxy["static"])["entryPoints"]
    assert entrypoints["admin"] == {"address": ":8079"}
    assert entrypoints["admin-lan"] == {"address": ":8078"}
    assert [line for line in proxy["quadlet"].splitlines() if line.startswith("PublishPort=")] == [
        "PublishPort=127.0.0.1:8079:8079",
        "PublishPort=192.168.7.4:8079:8078",
        "PublishPort=8080:8080",
        "PublishPort=8443:8443",
    ]
    dynamic = yaml.safe_load(proxy["dynamic"])
    routers = dynamic["http"]["routers"]
    assert routers["admin-lan"]["rule"] == (
        "(Host(`192.168.7.4`) || Host(`192.168.7.5`)) && !PathPrefix(`/bot/`)"
    )
    assert routers["admin-lan"]["service"] == "admin"
    assert routers["admin-lan"]["entryPoints"] == ["admin-lan"]
    assert routers["bot-private"]["entryPoints"] == ["admin"]
    assert (
        routers["bot-public"]["entryPoints"] == routers["p-notes-0"]["entryPoints"] == ["websecure"]
    )
    assert (
        dynamic["tls"]["stores"]["default"]["defaultCertificate"]
        == dynamic["tls"]["certificates"][0]
    )

    rules = variables["steward_nftables"]
    permit = (
        'iifname "enp1s0" ip saddr { 192.168.7.128/25, 10.5.0.0/16 } '
        "ip daddr 192.168.7.4 tcp dport 8079 "
        "ct direction original ct state new,established ct status != dnat accept"
    )
    drop = 'iifname != "lo" ct direction original tcp dport 8079 drop'
    original_drop = (
        'iifname != "lo" ct direction original meta l4proto tcp ct original proto-dst 8079 drop'
    )
    assert rules.index(permit) < rules.index(original_drop) < rules.index(drop)
    assert rules.index(drop) < rules.index("ct state established,related accept")
    assert 'iifname "lo" accept' in rules
    assert "tcp dport 2222 accept" in rules
    assert "tcp dport { 8080, 8443 } ct status dnat accept" in rules

    application_proxy = render.render_application_proxy_configuration(
        cfg, (render.ApplicationProxyRoute("notes", "app", "app.example.org", 20082),)
    )
    assert application_proxy["internal_sans"] == ["DNS:app.example.org", *proxy["internal_sans"]]


def test_resolved_lan_admin_defaults_sources_to_bind_network(raw_config):
    raw_config["admin"].update(
        access="private-lan", lan={"interface": "enp1s0", "bind": "10.5.0.4/24"}
    )
    rules = render.render_nftables(parse_config(raw_config), 22)
    assert 'iifname "enp1s0" ip saddr { 10.5.0.0/24 } ip daddr 10.5.0.4' in rules


def test_public_routes_open_only_proxy_ports(raw_config):
    cfg = with_routes(raw_config)
    rules = render.render_nftables(cfg, 2222)
    assert "tcp dport 2222 accept" in rules and "tcp dport 22 accept" not in rules
    assert "tcp dport { 8080, 8443 } ct status dnat accept" in rules
    ports = [
        line
        for line in render.render_proxy_quadlet(cfg).splitlines()
        if line.startswith("PublishPort=")
    ]
    assert ports == [
        f"PublishPort=127.0.0.1:{cfg.admin.port}:{cfg.admin.port}",
        "PublishPort=8080:8080",
        "PublishPort=8443:8443",
    ]
    static = yaml.safe_load(render.render_traefik_static(cfg))
    assert "api" not in static and "dashboard" not in str(static)
    assert static["providers"] == {"file": {"directory": "/etc/traefik/dynamic", "watch": True}}
    dynamic = yaml.safe_load(render.render_traefik_dynamic(cfg))
    assert dynamic["http"]["routers"]["p-notes-0"]["rule"] == "Host(`notes.example.org`)"
    assert "p-worker" not in dynamic["http"]["services"]  # no route, not exposed


def test_egress_modes(raw_config):
    rules = render.render_nftables(with_routes(raw_config), 22)
    notes = rules.split("chain egress_notes {")[1].split("\n    }")[0]
    worker = rules.split("chain egress_worker {")[1].split("\n    }")[0]
    # metadata/link-local and private ranges are rejected before public web is allowed
    assert (
        notes.index("169.254.0.0/16")
        < notes.index("@private4")
        < notes.index("tcp dport { 80, 443 }")
    )
    assert "ip6 daddr @private6" in notes and "fe80::/10" in notes
    assert "ip daddr 10.20.0.5/32 tcp dport { 5432 } accept" in worker
    assert "ip6 daddr 2001:db8::/32 udp dport { 53, 123 } accept" in worker
    assert "th dport 53" not in worker  # DNS is not implied by explicit rules
    for chain in (notes, worker):
        assert chain.strip().endswith("counter reject")


def test_stopped_and_unmanaged_projects(raw_config):
    raw_config["projects"][0]["deploy"] = False
    cfg = parse_config(raw_config)
    assert "[Install]" not in render.render_project_quadlet(cfg.projects[0], "/opt/x")
    assert "20080" not in render.render_nftables(cfg, 22)
    variables = render.render_vars(cfg, release={"version": "1"}, ssh_port=22)
    assert variables["steward_projects"][0]["deploy"] is False
    raw_config["projects"][0]["manage"] = False
    variables = render.render_vars(parse_config(raw_config), release={"version": "1"}, ssh_port=22)
    assert variables["steward_projects"] == []  # skipped, nothing removed


def test_quadlet_hardening_flags(cfg):
    unit = render.render_project_quadlet(cfg.projects[0], "/opt/steward/releases/1")
    for line in (
        "ReadOnly=true",
        "NoNewPrivileges=true",
        "DropCapability=all",
        "PidsLimit=64",
        "User=10001:10001",
        "Pull=never",
        "PublishPort=127.0.0.1:20080:8080",
        "Network=pasta",
    ):
        assert line in unit.splitlines()
    for forbidden in ("Network=host", "podman.sock", "--privileged", "0.0.0.0"):
        assert forbidden not in unit
    assert "localhost/steward/notes:sha256-5862d971" in unit


def test_vars_contain_references_never_secret_values(raw_config, monkeypatch):
    monkeypatch.setenv("NOTES_KEY", "super-secret-value")
    raw_config["projects"][0]["secrets"] = [{"name": "API_KEY", "ref": "env:NOTES_KEY"}]
    variables = render.render_vars(parse_config(raw_config), release={"version": "1"}, ssh_port=22)
    assert "super-secret-value" not in str(variables)
    assert variables["steward_projects"][0]["secrets"] == [
        {"name": "API_KEY", "kind": "env", "target": "NOTES_KEY"}
    ]


@pytest.mark.parametrize("notifier", [False, True])
@pytest.mark.parametrize("bot", [False, True])
@pytest.mark.parametrize("scanner", [False, True])
def test_optional_platform_units_follow_configuration(raw_config, notifier, bot, scanner):
    raw_config["channels"] = (
        [{"id": "ops", "adapter": "discord", "url_ref": "env:DISCORD_URL"}] if notifier else []
    )
    raw_config["bot"] = {
        "endpoints": (
            [{"id": "local", "adapter": "webhook", "verification_key_ref": "env:BOT_KEY"}]
            if bot
            else []
        )
    }
    raw_config["scanning"] = {"enabled": scanner}
    cfg = parse_config(raw_config)
    variables = render.render_vars(cfg, release={"version": "1"}, ssh_port=22)
    active = set(variables["steward_active_platform_units"])
    inactive = set(variables["steward_inactive_platform_units"])
    assert active.isdisjoint(inactive)
    assert active | inactive == set(variables["steward_platform_units"])
    assert inactive == {
        unit
        for unit, configured in (
            ("steward-notifier.service", notifier),
            ("steward-bot.service", bot),
            ("steward-scanner.service", scanner),
        )
        if not configured
    }
    registry = set(variables["steward_registry"]["platform_units"])
    assert registry == active | {"steward-firewall.service"}


@pytest.mark.parametrize("scanner_enabled", [False, True])
@pytest.mark.parametrize("backup_enabled", [False, True])
@pytest.mark.parametrize("containment_policy", [None, {"enabled": False}, {"enabled": True}])
def test_controller_observation_access_follows_configuration(
    raw_config, scanner_enabled, backup_enabled, containment_policy
):
    raw_config["scanning"] = {"enabled": scanner_enabled}
    raw_config["backup"] = {
        "enabled": backup_enabled,
        "endpoint": {"host": "backup.test", "addresses": ["192.0.2.1"]},
        "repository_ref": "env:BACKUP_REPOSITORY",
        "password_ref": "env:BACKUP_PASSWORD",
    }
    if backup_enabled:
        with pytest.raises(ConfigError, match=r"backup\.enabled: not available"):
            parse_config(raw_config)
    cfg = parse_config(raw_config, allow_unavailable=backup_enabled)
    variables = render.render_vars(cfg, release={"version": "1"}, ssh_port=22)
    assert "containment" not in variables["steward_registry"]
    if containment_policy is not None:
        variables["steward_registry"]["containment"] = containment_policy
    scan_observations = scanner_enabled and bool((containment_policy or {}).get("enabled"))
    templates = Path(__file__).resolve().parents[1] / "ansible/roles/platform/templates"
    env = Environment(
        loader=FileSystemLoader(str(templates)),
        undefined=StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,  # noqa: S701 - systemd unit, not HTML
    )
    unit = env.get_template("steward-controller.service.j2").render(**variables)
    lines = unit.splitlines()
    groups = ["steward-exec"]
    if scan_observations or backup_enabled:
        groups.append("steward-obs")
    assert [line for line in lines if line.startswith("SupplementaryGroups=")] == [
        "SupplementaryGroups=" + " ".join(groups)
    ]
    command = ["ExecStart=/opt/steward/current/venv/bin/steward-controller"]
    if backup_enabled:
        command.extend(["--backup-socket", "/run/steward-backup/query.sock"])
    if scan_observations:
        command.append("--scan-observations")
    assert [line for line in lines if line.startswith("ExecStart=")] == [" ".join(command)]
    assert "PrivateNetwork=yes" in lines
    assert "NoNewPrivileges=yes" in lines
    assert "ProtectSystem=strict" in lines
    assert "ReadWritePaths=/var/lib/steward-controller" in lines


@pytest.mark.skipif(not shutil.which("nft") or not shutil.which("unshare"), reason="needs nft")
@pytest.mark.parametrize("backup_enabled", [False, True])
def test_nftables_ruleset_loads_in_private_namespace(raw_config, tmp_path, backup_enabled):
    raw_config["admin"].update(
        access="private-lan", lan={"interface": "enp1s0", "bind": "192.168.7.4/24"}
    )
    cfg = with_routes(raw_config)
    cfg.backup = Backup(
        enabled=backup_enabled,
        endpoint=BackupEndpoint(
            host="backup.test",
            port=8443,
            addresses=["192.0.2.1", "2001:db8::1"],
        ),
        repository_ref="env:BACKUP_REPOSITORY",
        password_ref="env:BACKUP_PASSWORD",
    )
    rules = render.render_nftables(cfg, 22)
    for index, user in enumerate(
        [
            "stw-notes",
            "stw-worker",
            "steward-proxy",
            "steward-api",
            "steward-ctl",
            "steward-col",
            "steward-notify",
            "steward-bot",
            "steward-scan",
            "steward-backup",
            "steward-repo-fetch",
        ]
    ):
        rules = rules.replace(f'"{user}"', str(21000 + index))
    path = tmp_path / "steward.nft"
    path.write_text(rules)
    probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True)
    if probe.returncode != 0:
        pytest.skip("unprivileged user namespaces unavailable")
    # load twice: the ruleset must replace itself atomically
    subprocess.run(["unshare", "-rn", "sh", "-c", f"nft -f {path} && nft -f {path}"], check=True)


@pytest.mark.skipif(not os.path.exists(QUADLET), reason="needs podman quadlet")
def test_quadlet_generator_accepts_units(raw_config, tmp_path):
    raw_config["admin"].update(
        access="private-lan", lan={"interface": "enp1s0", "bind": "192.168.7.4/24"}
    )
    cfg = with_routes(raw_config)
    (tmp_path / "notes.container").write_text(render.render_project_quadlet(cfg.projects[0], "/o"))
    (tmp_path / "proxy.container").write_text(render.render_proxy_quadlet(cfg))
    result = subprocess.run(
        [QUADLET, "--user", "--dryrun"],
        capture_output=True,
        text=True,
        env={**os.environ, "QUADLET_UNIT_DIRS": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr
    assert "--read-only" in result.stdout and "--cap-drop all" in result.stdout
    assert f"--publish 192.168.7.4:{cfg.admin.port}:{cfg.admin.port + 1}" in result.stdout
    assert "converting" not in result.stderr.lower() or "error" not in result.stderr.lower()


def test_notifier_has_own_identity_credentials_and_https_egress(raw_config):
    from steward.core.config import parse_config

    raw_config["channels"] = [
        {
            "id": "ops",
            "adapter": "webhook",
            "url_ref": "env:OPS_URL",
            "signing_key_ref": "env:OPS_KEY",
        }
    ]
    cfg = parse_config(raw_config)
    variables = render.render_vars(cfg, release={"version": "test"}, ssh_port=22)
    assert variables["steward_channel_secrets"] == [
        {"name": "ops-url", "kind": "env", "target": "OPS_URL"},
        {"name": "ops-key", "kind": "env", "target": "OPS_KEY"},
    ]
    firewall = render.render_nftables(cfg, 22)
    assert '"steward-notify" : jump egress_notifications' in firewall
    chain = firewall.split("chain egress_notifications {")[1].split("    }")[0]
    assert "tcp dport 443 accept" in chain and "tcp dport 80 accept" not in chain


def test_bot_public_router_exposes_only_bot_path(raw_config):
    raw_config["bot"] = {
        "public_hostname": "bot.example.org",
        "endpoints": [
            {
                "id": "ops",
                "adapter": "discord",
                "application_id": "123",
                "verification_key_ref": "env:DISCORD_KEY",
                "grants": [],
            },
        ],
    }
    raw_config["proxy"] = {"acme_email": "ops@example.org"}
    cfg = parse_config(raw_config)
    dynamic = yaml.safe_load(render.render_traefik_dynamic(cfg))
    router = dynamic["http"]["routers"]["bot-public"]
    assert router["rule"] == "Host(`bot.example.org`) && PathPrefix(`/bot/`)"
    assert router["service"] == "bot" and router["tls"] == {"certResolver": "le"}
    assert render.has_public_routes(cfg)
    assert "tcp dport 443 accept" in render.render_nftables(cfg, 22)


def repository_fetch_config(raw_config, **fields):
    raw = with_repository(raw_config, revision="e" * 40, **fields)
    services = raw["applications"][0]["services"]
    backend = next(service for service in services if service["id"] == "backend")
    backend.update(manage=False, deploy=False, depends_on=[])
    services[:] = [backend]
    return parse_config(raw, allow_unavailable=True)


@pytest.mark.parametrize(
    ("credential", "endpoint", "family"),
    [
        (None, "93.184.216.34", "ip"),
        ("env:SHOP_BACKEND_TOKEN", "2606:4700::1111", "ip6"),
    ],
)
def test_repository_fetch_candidate_binds_exact_firewall_source(
    raw_config, credential, endpoint, family
):
    cfg = repository_fetch_config(raw_config, credential=credential)
    variables = render._render_repository_fetch_candidate_vars(
        cfg, release={"version": "1"}, ssh_port=2222, endpoint=endpoint
    )
    nft_source = variables["steward_nftables"]
    candidate = variables["steward_repository_fetch"]
    assert candidate == {
        "manifest": {
            "version": 1,
            "base_revision": variables["steward_config_revision"],
            "firewall_sha256": hashlib.sha256(nft_source.encode()).hexdigest(),
            "endpoint": endpoint,
            "credential_required": credential is not None,
            "handoff": {"contract": None},
            "repository": {
                "id": "shop-backend",
                "application": "shop",
                "service": "backend",
                "url": "https://git.example.org/shop/backend.git",
                "ref": cfg.repositories[0].ref,
                "revision": cfg.repositories[0].revision,
                "host_key": None,
                "allow_private_network": False,
            },
        },
        "credential": {"kind": "env", "target": "SHOP_BACKEND_TOKEN"} if credential else None,
    }
    Manifest.model_validate(candidate["manifest"])
    assert "SHOP_BACKEND_TOKEN" not in json.dumps(candidate["manifest"])
    assert '"steward-repo-fetch" : jump egress_repository_fetch' in nft_source
    fetch_chain = nft_source.split("chain egress_repository_fetch {", 1)[1].split("}", 1)[0]
    assert fetch_chain.strip().splitlines() == [
        "ct status dnat counter drop",
        f"        {family} daddr {endpoint} tcp dport 443 accept",
        "        counter drop",
    ]


def test_repository_fetch_candidate_carries_only_operator_contract(raw_config):
    cfg = repository_fetch_config(
        raw_config, contract={"container_port": 8080}, instruction="operator notes"
    )
    release = {"version": "1"}
    variables = render._render_repository_fetch_candidate_vars(
        cfg, release=release, ssh_port=2222, endpoint="93.184.216.34"
    )
    manifest = variables["steward_repository_fetch"]["manifest"]
    assert manifest["handoff"] == {"contract": cfg.repositories[0].contract.model_dump(mode="json")}
    assert "operator notes" not in json.dumps(manifest)
    assert Manifest.model_validate(manifest).handoff.contract == cfg.repositories[0].contract

    base = cfg.model_copy(update={"applications": [], "repositories": []})
    normal = render.render_vars(base, release=release, ssh_port=2222)
    assert variables["steward_config_revision"] == normal["steward_config_revision"]
    assert "steward_repository_fetch" not in normal


@pytest.mark.parametrize("endpoint", ["git.example.org", "169.254.169.254"])
def test_repository_fetch_candidate_rejects_unsafe_pin(raw_config, endpoint):
    cfg = repository_fetch_config(raw_config, allow_private_network=True)
    with pytest.raises(FetchError, match="endpoint"):
        render._render_repository_fetch_candidate_vars(
            cfg, release={"version": "1"}, ssh_port=22, endpoint=endpoint
        )


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0", "2001:db8::1%eth0/128"])
def test_repository_egress_rule_patterns_require_fixed_cidrs(raw_config, cidr):
    with pytest.raises(ConfigError, match="egress_rule_patterns"):
        repository_fetch_config(
            raw_config, egress_rule_patterns=[{"proto": "tcp", "cidr": cidr, "ports": [443]}]
        )


def test_repository_egress_rule_patterns_are_revision_bound_and_unset_stays_legacy(raw_config):
    from copy import deepcopy

    unset = repository_fetch_config(deepcopy(raw_config))
    empty = repository_fetch_config(deepcopy(raw_config), egress_rule_patterns=[])
    rule = {"proto": "udp", "cidr": "2001:db8::/48", "ports": [53]}
    configured = repository_fetch_config(deepcopy(raw_config), egress_rule_patterns=[rule])

    legacy_registry = render.prepare_application_registry(unset)
    assert "egress_rule_patterns" not in effective(unset)["repositories"][0]
    assert effective(empty) == effective(unset)
    assert render.prepare_application_registry(empty) == legacy_registry
    assert effective(configured)["repositories"][0]["egress_rule_patterns"] == [rule]
    assert (
        render.prepare_application_registry(configured)["config_revision"]
        != legacy_registry["config_revision"]
    )
    assert render.prepare_separate_application_egress(configured) == (
        render.prepare_separate_application_egress(unset)
    )
