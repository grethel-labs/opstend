import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from steward.adapters.backups import Restic, repository_for_endpoint
from steward.backupworker import service_endpoint
from steward.cli import main as cli
from steward.core import render
from steward.core.backups import BackupError
from steward.core.config import BackupEndpoint, parse_config


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "0.1.2.3",
        "::",
        "169.254.169.254",
        "fe80::1",
        "239.1.1.1",
        "ff02::1",
        "255.255.255.255",
        "::ffff:192.0.2.1",
        "2001:db8::1%eth0",
        "192.0.2.0/24",
    ],
)
def test_backup_pins_reject_local_metadata_multicast_and_ambiguous_addresses(address):
    with pytest.raises(ValidationError):
        BackupEndpoint(host="backup.test", addresses=[address])


@pytest.mark.parametrize(
    "host", ["localhost", "backup.localhost", "backup.test\nother", "backup.test/path"]
)
def test_backup_host_cannot_inject_a_hosts_mapping(host):
    with pytest.raises(ValidationError):
        BackupEndpoint(host=host, addresses=["192.0.2.1"])


def test_literal_endpoint_requires_exact_pin_and_normalized_unique_addresses():
    assert BackupEndpoint(host="2001:db8::1", addresses=["2001:0db8::1"]).addresses == [
        "2001:db8::1"
    ]
    with pytest.raises(ValidationError):
        BackupEndpoint(host="192.0.2.1", addresses=["192.0.2.2"])
    with pytest.raises(ValidationError):
        BackupEndpoint(host="backup.test", addresses=["2001:db8::1", "2001:0db8::1"])


@pytest.mark.parametrize(
    "url,valid",
    [
        ("rest:https://backup.test:8443/repository/", True),
        ("rest:https://other.test:8443/repository/", False),
        ("rest:https://backup.test/repository/", False),
        ("rest:http://backup.test:8443/repository/", False),
    ],
)
def test_repository_secret_is_bound_to_the_declared_tls_host_and_port(url, valid):
    endpoint = BackupEndpoint(host="backup.test", port=8443, addresses=["192.0.2.1"])
    if valid:
        assert repository_for_endpoint(url.encode(), endpoint) == url
    else:
        with pytest.raises(BackupError):
            repository_for_endpoint(url.encode(), endpoint)


def test_worker_rejects_wrong_repository_before_starting(tmp_path):
    repository = tmp_path / "repository"
    password = tmp_path / "password"
    repository.write_text("rest:https://wrong.test:8443/private/\n")
    password.write_text("x" * 48)
    repository.chmod(0o600)
    password.chmod(0o600)
    endpoint = BackupEndpoint(host="backup.test", port=8443, addresses=["192.0.2.1"])
    with pytest.raises(BackupError):
        Restic(
            repository_file=repository,
            password_file=password,
            state_dir=tmp_path / "state",
            endpoint=endpoint,
        )
    assert not (tmp_path / "state").exists()


def prepared(raw_config, *, enabled=True):
    raw_config["backup"] = {
        "enabled": enabled,
        "endpoint": {
            "host": "backup.test",
            "port": 8443,
            "addresses": ["192.0.2.1", "2001:db8::1"],
        },
        "repository_ref": "env:TEST_BACKUP_REPOSITORY",
        "password_ref": "env:TEST_BACKUP_PASSWORD",
    }
    return parse_config(raw_config, allow_unavailable=True)


def test_backup_egress_and_hosts_map_have_exact_pins_without_dns_or_loopback_escape(raw_config):
    cfg = prepared(raw_config)
    rules = render.render_nftables(cfg, 22)
    chain = rules.split("chain egress_backup {", 1)[1].split("\n    }", 1)[0]
    assert '"steward-backup" : jump egress_backup' in rules
    assert "ip daddr 192.0.2.1 tcp dport 8443 accept" in chain
    assert "ip6 daddr 2001:db8::1 tcp dport 8443 accept" in chain
    assert chain.index('oifname "lo" counter reject') < chain.index("ip daddr 192.0.2.1")
    assert "53 accept" not in chain
    assert "192.0.2.1 backup.test\n2001:db8::1 backup.test\n" in render.render_backup_hosts(cfg)
    cfg.backup.enabled = False
    assert (
        "tcp dport 8443 accept"
        not in render.render_nftables(cfg, 22).split("chain egress_backup {")[1]
    )
    assert "backup.test" not in render.render_backup_hosts(cfg)


def test_generated_backup_artifacts_include_only_references_and_activation_bindings(raw_config):
    cfg = prepared(raw_config)
    variables = render.render_vars(cfg, release={"version": "1", "files": {}}, ssh_port=22)
    assert variables["steward_backup"]["credentials"] == ["repository", "password"]
    assert {s["name"] for s in variables["steward_backup_secrets"]} == {"repository", "password"}
    assert not any(s["name"].startswith("backup-") for s in variables["steward_activation_secrets"])
    assert "TEST_BACKUP_PASSWORD" in json.dumps(variables)
    assert variables["steward_backup"]["endpoint"]["addresses"] == ["192.0.2.1", "2001:db8::1"]


def test_controller_rejects_backup_target_mismatch_without_printing_secrets(
    raw_config, monkeypatch
):
    cfg = prepared(raw_config)
    cfg.admin.token_ref = "env:TEST_ADMIN_TOKEN"
    monkeypatch.setenv("TEST_ADMIN_TOKEN", "a" * 48)
    monkeypatch.setenv("TEST_BACKUP_REPOSITORY", "rest:https://wrong.test:8443/private-repository/")
    monkeypatch.setenv("TEST_BACKUP_PASSWORD", "secret-fixture-" + "x" * 48)
    with pytest.raises(cli.CliError) as exc:
        cli.check_secrets(cfg)
    assert "backup:" in str(exc.value)
    assert "private-repository" not in str(exc.value) and "secret-fixture" not in str(exc.value)
    monkeypatch.setenv(
        "TEST_BACKUP_REPOSITORY", "rest:https://backup.test:8443/private-repository/"
    )
    cli.check_secrets(cfg)


def test_service_endpoint_requires_a_protected_enabled_configuration(tmp_path):
    path = tmp_path / "backup.json"
    path.write_text(
        json.dumps(
            {
                "enabled": True,
                "endpoint": {"host": "backup.test", "port": 8443, "addresses": ["192.0.2.1"]},
            }
        )
    )
    path.chmod(0o640)
    assert service_endpoint(path, owner_uid=path.stat().st_uid).host == "backup.test"
    path.chmod(0o666)
    with pytest.raises(BackupError, match="invalid_service_config"):
        service_endpoint(path, owner_uid=path.stat().st_uid)
    path.chmod(0o600)
    path.write_text(json.dumps({"enabled": False, "endpoint": None}))
    with pytest.raises(BackupError, match="invalid_service_config"):
        service_endpoint(path, owner_uid=path.stat().st_uid)


def test_backup_unit_loads_only_declared_credentials_and_pins_hosts(raw_config):
    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    cfg = prepared(raw_config)
    cfg.backup.username_ref = "env:BACKUP_USER"
    cfg.backup.auth_password_ref = "env:BACKUP_AUTH"
    cfg.backup.ca_ref = "env:BACKUP_CA"
    variables = render.render_vars(cfg, release={"version": "1", "files": {}}, ssh_port=22)
    templates = Path(__file__).resolve().parents[1] / "ansible/roles/platform/templates"
    unit = (
        Environment(loader=FileSystemLoader(str(templates)), undefined=StrictUndefined)  # noqa: S701 -- systemd, not HTML
        .get_template("steward-backup.service.j2")
        .render(**variables)
    )
    for entry in ("repository", "password", "username", "auth-password", "ca"):
        assert f"LoadCredential={entry}:/etc/steward/secrets/backup/{entry}" in unit
    assert "BindReadOnlyPaths=/etc/steward/backup-hosts:/etc/hosts" in unit
    assert "ReadOnlyPaths=/var/lib/steward-backup-import" in unit
    assert "CapabilityBoundingSet=" in unit and "NoNewPrivileges=yes" in unit
    assert "SupplementaryGroups=steward-exec steward-obs" in unit
    assert "RuntimeDirectory=steward-backup" in unit
    assert "RuntimeDirectoryMode=0755" in unit


@pytest.mark.skipif(
    not all(shutil.which(c) for c in ("unshare", "ip", "nft")), reason="needs namespaces/nft"
)
def test_actual_backup_packets_only_reach_pinned_ip_and_port(raw_config, tmp_path):
    if subprocess.run(["unshare", "-Urn", "true"], capture_output=True).returncode:
        pytest.skip("unprivileged network namespaces unavailable")
    cfg = prepared(raw_config)
    cfg.backup.endpoint.addresses = ["192.0.2.2", "fd00:1::2"]
    body = (
        render.render_nftables(cfg, 22).split("chain egress_backup {", 1)[1].split("\n    }", 1)[0]
    )
    rules = tmp_path / "policy.nft"
    rules.write_text(
        "table inet probe {\nchain output { type filter hook output priority filter; policy accept; "
        "meta skuid 0 jump egress_backup; }\nchain egress_backup {" + body + "\n}\n}\n"
    )
    helper = Path(__file__).with_name("integration") / "backup_network.py"
    result = subprocess.run(
        ["unshare", "-Urn", sys.executable, str(helper), str(rules)],
        capture_output=True,
        timeout=45,
    )
    assert result.returncode == 0, result.stderr.decode()
    assert all(json.loads(result.stdout).values())


def test_scheduler_configuration_is_protected_and_contains_only_registered_projects(
    raw_config, tmp_path
):
    from steward.backupscheduler import read_config

    cfg = prepared(raw_config)
    variables = render.render_vars(cfg, release={"version": "1", "files": {}}, ssh_port=22)
    path = tmp_path / "backup.json"
    path.write_text(json.dumps(variables["steward_backup"]))
    path.chmod(0o640)
    parsed = read_config(path, owner_uid=path.stat().st_uid)
    assert parsed.projects == variables["steward_backup"]["projects"]
    assert parsed.config_revision == variables["steward_backup"]["config_revision"]
    path.chmod(0o666)
    with pytest.raises(BackupError, match="invalid_service_config"):
        read_config(path, owner_uid=path.stat().st_uid)


def test_backup_executor_role_only_authorizes_schedule_permit_and_wakeup():
    from steward.executor.server import ACTIONS

    assert {name for name, action in ACTIONS.items() if "backup" in action.roles} == {
        "backup_schedule",
        "backup_upload_permit",
        "backup_lock_cleanup_permit",
        "backup_retention_hint",
        "backup_worker_capacity_report",
    }


def test_collector_only_monitors_backup_socket_when_backup_is_enabled(raw_config):
    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    cfg = prepared(raw_config)
    templates = Path(__file__).resolve().parents[1] / "ansible/roles/platform/templates"
    template = Environment(  # noqa: S701 - systemd unit, not HTML
        loader=FileSystemLoader(str(templates)), undefined=StrictUndefined
    ).get_template("steward-collector.service.j2")
    cfg.backup.enabled = True
    variables = render.render_vars(cfg, release={"version": "1", "files": {}}, ssh_port=22)
    assert "--backup-socket /run/steward-backup/query.sock" in template.render(**variables)
    cfg.backup.enabled = False
    variables = render.render_vars(cfg, release={"version": "1", "files": {}}, ssh_port=22)
    assert "--backup-socket" not in template.render(**variables)
    controller = Environment(  # noqa: S701 - systemd unit, not HTML
        loader=FileSystemLoader(str(templates)), undefined=StrictUndefined
    ).get_template("steward-controller.service.j2")
    assert "--backup-socket" not in controller.render(**variables)
    cfg.backup.enabled = True
    variables = render.render_vars(cfg, release={"version": "1", "files": {}}, ssh_port=22)
    unit = controller.render(**variables)
    assert "--backup-socket /run/steward-backup/query.sock" in unit
    assert "SupplementaryGroups=steward-exec steward-obs" in unit


@pytest.mark.parametrize("enabled", [False, True])
def test_systemd_templates_preserve_directive_lines_with_ansible_whitespace(raw_config, enabled):
    import re

    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    cfg = prepared(raw_config, enabled=enabled)
    variables = render.render_vars(cfg, release={"version": "1", "files": {}}, ssh_port=22)
    templates = Path(__file__).resolve().parents[1] / "ansible/roles/platform/templates"
    env = Environment(  # noqa: S701 - systemd units, not HTML
        loader=FileSystemLoader(str(templates)),
        undefined=StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["regex_replace"] = lambda value, pattern, replacement: re.sub(
        pattern, replacement, str(value)
    )
    for name in (
        "steward-api",
        "steward-backup",
        "steward-bot",
        "steward-collector",
        "steward-controller",
        "steward-notifier",
        "steward-scanner",
    ):
        unit = env.get_template(name + ".service.j2").render(**variables)
        lines = unit.splitlines()
        assert "TasksMax=64" in lines
        assert any(line.startswith("ExecStart=") for line in lines)
        assert not any("#" in line and not line.startswith("#") for line in lines)
        assert not any("ExecStart=" in line and not line.startswith("ExecStart=") for line in lines)
        assert not any("Restart=" in line and not line.startswith("Restart=") for line in lines)
    controller = env.get_template("steward-controller.service.j2").render(**variables)
    assert ("SupplementaryGroups=steward-exec steward-obs" in controller.splitlines()) is enabled
    assert ("--backup-socket /run/steward-backup/query.sock" in controller) is enabled
