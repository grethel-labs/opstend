from ipaddress import IPv4Address, IPv4Interface, IPv4Network

import pytest

from steward.core import canonical
from steward.core.config import AdminLan, ConfigError, effective, parse_config


def test_example_is_valid_and_starts_in_observe(cfg):
    assert cfg.automation.profile == "observe"
    assert cfg.projects[0].egress.mode == "none"
    assert cfg.admin.access == "private"


def test_revision_is_stable_and_content_addressed(raw_config, cfg):
    first = canonical.revision_id(effective(cfg))
    assert first == canonical.revision_id(effective(parse_config(raw_config)))
    raw_config["projects"][0]["resources"]["memory_mb"] = 200
    assert canonical.revision_id(effective(parse_config(raw_config))) != first


def test_admin_loopback_modes_preserve_legacy_hostname_and_revision(raw_config):
    admin = raw_config["admin"]
    admin.update(access="private", hostname="steward.example")
    legacy = effective(parse_config(raw_config))
    del admin["access"]
    assert effective(parse_config(raw_config)) == legacy
    admin.update(access="private-loopback", lan=None)
    loopback = effective(parse_config(raw_config))["admin"]
    assert loopback == {**legacy["admin"], "access": "private-loopback"}


def test_admin_lan_scope_is_typed_and_canonical(raw_config):
    raw_config["admin"].update(
        access="private-lan",
        lan={
            "interface": "enp1s0.42",
            "bind": "192.168.42.3/24",
            "allowed_sources": ["192.168.42.0/24", "10.1.0.0/16"],
            "advertise_ipv4": "192.168.42.4",
        },
    )
    cfg = parse_config(raw_config)
    assert isinstance(cfg.admin.lan, AdminLan)
    assert type(cfg.admin.lan.bind) is IPv4Interface
    assert all(type(network) is IPv4Network for network in cfg.admin.lan.allowed_sources)
    assert type(cfg.admin.lan.advertise_ipv4) is IPv4Address
    body = effective(cfg)
    assert body["admin"]["lan"] == raw_config["admin"]["lan"]
    assert effective(parse_config(body)) == body


def test_admin_lan_omits_empty_options_from_canonical_config(raw_config):
    admin = raw_config["admin"]
    admin.update(access="private-lan")
    deferred = effective(parse_config(raw_config))["admin"]
    assert "lan" not in deferred
    admin["lan"] = {"interface": None, "bind": None, "allowed_sources": [], "advertise_ipv4": None}
    assert effective(parse_config(raw_config))["admin"] == deferred
    admin["lan"]["advertise_ipv4"] = "172.16.1.0"
    assert effective(parse_config(raw_config))["admin"]["lan"] == {"advertise_ipv4": "172.16.1.0"}
    admin["lan"]["advertise_ipv4"] = None
    admin["lan"].update(interface="ens1", bind="172.16.1.0/31")
    cfg = parse_config(raw_config)
    assert cfg.admin.lan.bind.network == IPv4Network("172.16.1.0/31")
    assert effective(cfg)["admin"]["lan"] == {"interface": "ens1", "bind": "172.16.1.0/31"}
    admin["lan"].update(bind="172.16.1.0/32", allowed_sources=["172.16.2.0/24"])
    assert effective(parse_config(raw_config))["admin"]["lan"]["bind"] == "172.16.1.0/32"


@pytest.mark.parametrize(
    "scope",
    [
        {"interface": None},
        {"bind": None},
        {"interface": "enp1s0:1"},
        {"interface": "enp1s0\n"},
        {"interface": "a" * 16},
        {"bind": "192.168.1.3"},
        {"bind": "127.0.0.1/8"},
        {"bind": "169.254.1.3/16"},
        {"bind": "192.0.2.3/24"},
        {"bind": "192.168.1.3/15"},
        {"bind": "192.168.1.0/24"},
        {"bind": "192.168.1.255/24"},
        {"bind": "192.168.1.3/32"},
        {"allowed_sources": ["192.168.1.3/24"]},
        {"allowed_sources": ["192.168.1.3"]},
        {"allowed_sources": ["0.0.0.0/0"]},
        {"allowed_sources": ["fd00::/8"]},
        {"allowed_sources": ["192.168.1.0/24"] * 2},
        {"allowed_sources": [f"10.0.{index}.0/24" for index in range(33)]},
        {"advertise_ipv4": "0.0.0.0"},
        {"advertise_ipv4": "100.64.1.3"},
        {"advertise_ipv4": "192.168.1.255"},
        {"advertise_ipv4": "192.168.1.4/32"},
        {"advertise_ipv4": "steward.example"},
        {"advertise_ipv4": int(IPv4Address("192.168.1.4"))},
    ],
)
def test_admin_lan_rejects_invalid_scope(raw_config, scope):
    raw_config["admin"].update(
        access="private-lan", lan={"interface": "ens1", "bind": "192.168.1.3/24", **scope}
    )
    with pytest.raises(ConfigError, match=r"admin\.lan"):
        parse_config(raw_config)


def test_admin_lan_requires_managed_firewall_and_lan_access(raw_config):
    raw_config["hardening"]["firewall"]["manage"] = False
    raw_config["admin"]["access"] = "private-lan"
    with pytest.raises(ConfigError, match="managed firewall"):
        parse_config(raw_config)
    for access in ("private", "private-loopback", "public"):
        raw_config["admin"].update(access=access, lan={})
        with pytest.raises(ConfigError, match=r"admin\.lan requires"):
            parse_config(raw_config)


def test_application_instruction_preserves_old_revision_when_unset(raw_config):
    from test_application_graph import graph

    app = graph(raw_config)
    old = effective(parse_config(raw_config, allow_unavailable=True))
    old_revision = "2785a043e8034dfba0663a5cc206a87dbf6ea042586b53547f1e10bc5597e885"
    assert "instruction" not in old["applications"][0]
    assert canonical.revision_id(old) == old_revision

    app["instruction"] = None
    assert effective(parse_config(raw_config, allow_unavailable=True)) == old

    instruction = "Keep data under /data.\n" + "x" * (2000 - len("Keep data under /data.\n"))
    app["instruction"] = instruction
    updated = effective(parse_config(raw_config, allow_unavailable=True))
    assert updated["applications"][0]["instruction"] == instruction
    assert canonical.revision_id(updated) != old_revision


@pytest.mark.parametrize("instruction", ["x" * 2001, "bad\x00text"])
def test_application_instruction_rejects_oversized_or_control_text(raw_config, instruction):
    from test_application_graph import graph

    graph(raw_config)["instruction"] = instruction
    with pytest.raises(ConfigError, match="applications.0.instruction"):
        parse_config(raw_config, allow_unavailable=True)


def test_diff_reports_paths_by_project_id(raw_config, cfg):
    raw_config["projects"][0]["resources"]["memory_mb"] = 200
    changes = canonical.diff(effective(cfg), effective(parse_config(raw_config)))
    assert changes == [
        {"path": "projects[notes].resources.memory_mb", "change": "changed", "old": 128, "new": 200}
    ]


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda c: c.update(profile="local-ai"), "profile.local-ai"),
        (lambda c: c["automation"].update(profile="patch"), "automation.patch"),
        (lambda c: c.update(ai={"provider": "ollama", "model": "test-model:1b"}), "ai.provider"),
        (
            lambda c: c.update(
                backup={
                    "enabled": True,
                    "endpoint": {"host": "backup.example", "addresses": ["192.0.2.1"]},
                    "repository_ref": "env:BACKUP_REPOSITORY",
                    "password_ref": "env:BACKUP_PASSWORD",
                }
            ),
            "backup.enabled",
        ),
        (lambda c: c["admin"].update(access="public"), "admin.access.public"),
    ],
)
def test_enabled_but_unimplemented_features_are_rejected(raw_config, mutate, needle):
    mutate(raw_config)
    with pytest.raises(ConfigError) as exc:
        parse_config(raw_config)
    assert any(needle in p and "not available" in p for p in exc.value.problems)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c["projects"][0].update(image="docker.io/library/python:3.14"),  # tag, no digest
        lambda c: c["projects"][0].update(image="python@sha256:" + "a" * 64),  # no registry
        lambda c: c["projects"][0].update(id="Notes; rm -rf /"),
        lambda c: c["projects"][0].update(command=["sh", "-c", "curl x | sh"]),
        lambda c: c["projects"][0].update(command=["python", "/app/app.py\nUser=0"]),
        lambda c: c["projects"][0].update(routes=[{"host": "a.example.org`) || PathPrefix(`/"}]),
        lambda c: c["projects"][0].update(host_port=80),
        lambda c: c["projects"][0].update(host_port=9080),  # collides with admin backend
        lambda c: c["projects"][0].update(run_as=0),
        lambda c: c["projects"][0].update(privileged=True),  # unknown keys are forbidden
        lambda c: c["projects"][0].update(health={"path": "/healthz\nExecStartPre=/bin/sh"}),
        lambda c: c["projects"][0].update(egress={"mode": "rules", "rules": []}),
        lambda c: c["projects"][0].update(
            egress={
                "mode": "none",
                "rules": [{"proto": "tcp", "cidr": "10.0.0.0/8", "ports": [5432]}],
            }
        ),
        lambda c: c["projects"][0].update(secrets=[{"name": "A", "ref": "plain-value"}]),
        lambda c: c["projects"].append(dict(c["projects"][0])),  # duplicate id and port
        lambda c: c["projects"][0].update(routes=[{"host": "notes.example.org"}]),  # acme w/o email
        lambda c: c["server"].update(os_profile="debian-13"),
        lambda c: c.update(schema_version=2),
        lambda c: c["admin"].update(token_ref="hunter2"),
    ],
)
def test_unsafe_or_inconsistent_values_are_rejected(raw_config, mutate):
    mutate(raw_config)
    with pytest.raises(ConfigError):
        parse_config(raw_config)


def test_all_problems_are_reported_together(raw_config):
    raw_config["projects"][0]["run_as"] = 0
    raw_config["server"]["port"] = 0
    with pytest.raises(ConfigError) as exc:
        parse_config(raw_config)
    assert len(exc.value.problems) == 2


def test_committed_json_schema_is_current():
    from steward.core import schema

    assert schema.TARGET.read_text() == schema.render(), "run: python -m steward.core.schema"


def test_local_ai_example_is_rejected_until_implemented():
    import yaml

    from steward.core.config import ROOT_EXAMPLES

    data = yaml.safe_load((ROOT_EXAMPLES / "server.local-ai.yml").read_text())
    with pytest.raises(ConfigError, match="profile.local-ai"):
        parse_config(data)
    assert parse_config(data, allow_unavailable=True).profile == "local-ai"


def test_notification_channels_require_references_and_unique_ids(raw_config):
    raw_config["channels"] = [
        {
            "id": "ops",
            "adapter": "webhook",
            "url_ref": "env:OPS_URL",
            "signing_key_ref": "env:OPS_KEY",
        }
    ]
    assert parse_config(raw_config).channels[0].adapter == "webhook"
    raw_config["channels"].append(dict(raw_config["channels"][0]))
    with pytest.raises(ConfigError, match="duplicate channel"):
        parse_config(raw_config)
    raw_config["channels"] = [{"id": "ops", "adapter": "webhook", "url_ref": "env:OPS_URL"}]
    with pytest.raises(ConfigError, match="signing_key_ref"):
        parse_config(raw_config)


def test_bot_requires_authorized_scopes_and_explicit_public_hostname(raw_config):
    endpoint = {
        "id": "ops",
        "adapter": "webhook",
        "verification_key_ref": "env:BOT_KEY",
        "grants": [{"tenant": "team", "user": "alice", "projects": ["notes"]}],
    }
    raw_config["bot"] = {"endpoints": [endpoint]}
    assert parse_config(raw_config).bot.public_hostname is None
    raw_config["bot"]["public_hostname"] = "bot.example.org"
    with pytest.raises(ConfigError, match="acme_email"):
        parse_config(raw_config)
    raw_config["proxy"] = {"acme_email": "ops@example.org"}
    assert parse_config(raw_config).bot.public_hostname == "bot.example.org"
    endpoint["grants"][0]["projects"] = ["unregistered"]
    with pytest.raises(ConfigError, match="unknown project"):
        parse_config(raw_config)


def test_discord_cannot_enable_structured_audit_export(raw_config):
    raw_config["channels"] = [
        {"id": "ops", "adapter": "discord", "url_ref": "env:URL", "audit_export": True}
    ]
    with pytest.raises(ConfigError, match="audit export requires"):
        parse_config(raw_config)


def test_scanning_requires_explicit_opt_in_and_valid_schedule(raw_config):
    assert not parse_config(raw_config).scanning.enabled
    raw_config["scanning"] = {"enabled": True, "osv": False, "trivy": False}
    with pytest.raises(ConfigError, match="at least one provider"):
        parse_config(raw_config)
    raw_config["scanning"] = {"enabled": True, "interval_s": 3600, "max_age_s": 300}
    with pytest.raises(ConfigError, match="freshness limit"):
        parse_config(raw_config)
    raw_config["scanning"] = {"enabled": True, "trivy": False}
    assert parse_config(raw_config).scanning.osv


@pytest.mark.parametrize(
    "mutation",
    [
        lambda backup: backup.pop("endpoint"),
        lambda backup: backup.update(endpoint=None),
        lambda backup: backup.pop("repository_ref"),
        lambda backup: backup.update(repository_ref=None),
        lambda backup: backup.pop("password_ref"),
        lambda backup: backup.update(password_ref=None),
        lambda backup: backup.update(username_ref="env:BACKUP_USER"),
        lambda backup: backup.update(auth_password_ref="env:BACKUP_AUTH"),
        lambda backup: backup.update(username_ref=None, auth_password_ref="env:BACKUP_AUTH"),
    ],
)
def test_enabled_backup_contract_is_required_by_model_and_json_schema(raw_config, mutation):
    import jsonschema

    from steward.core.config import Config

    backup = {
        "enabled": True,
        "endpoint": {"host": "backup.example", "addresses": ["192.0.2.1"]},
        "repository_ref": "env:BACKUP_REPOSITORY",
        "password_ref": "env:BACKUP_PASSWORD",
    }
    mutation(backup)
    raw_config["backup"] = backup
    with pytest.raises(ConfigError):
        parse_config(raw_config, allow_unavailable=True)
    assert list(jsonschema.Draft202012Validator(Config.model_json_schema()).iter_errors(raw_config))


def test_complete_backup_contract_still_obeys_availability_gate_and_schema(raw_config):
    import jsonschema

    from steward.core.config import Config

    raw_config["backup"] = {
        "enabled": True,
        "endpoint": {"host": "backup.example", "addresses": ["192.0.2.1"]},
        "repository_ref": "env:BACKUP_REPOSITORY",
        "password_ref": "env:BACKUP_PASSWORD",
        "username_ref": "env:BACKUP_USER",
        "auth_password_ref": "env:BACKUP_AUTH",
    }
    assert not list(
        jsonschema.Draft202012Validator(Config.model_json_schema()).iter_errors(raw_config)
    )
    assert parse_config(raw_config, allow_unavailable=True).backup.enabled
    with pytest.raises(ConfigError, match="backup.enabled.*not available"):
        parse_config(raw_config)


def test_disabled_backup_remains_inert_without_endpoint_or_secrets(raw_config):
    import jsonschema

    from steward.core.config import Config

    raw_config["backup"] = {"enabled": False}
    assert not list(
        jsonschema.Draft202012Validator(Config.model_json_schema()).iter_errors(raw_config)
    )
    assert parse_config(raw_config).backup.enabled is False
