import json

from steward.cli.main import build_parser
from steward.core.fleet_identity import FleetIdentityRegistry
from steward.core.fleet_policy_apply import FleetPolicyActor, FleetPolicyApply


def _private_json(path, payload):
    path.touch(mode=0o600)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def _fleet(command, *args):
    parsed = build_parser().parse_args(["fleet", "policy-" + command, *args])
    return parsed.func(parsed)


def _run(db, command, *args):
    return _fleet(command, "--db", str(db), *args)


def test_fleet_policy_uses_shared_revisions_previews_approvals_and_grants(tmp_path, capsys):
    tmp_path.chmod(0o700)
    db = tmp_path / "coordinator.db"
    registry = FleetIdentityRegistry(db)
    site = registry.register_site("site")
    host = registry.register_host(site.id, "host")
    target = {"kind": "host", "id": host.id, "generation": 1}
    policy = {"targets": [{"target": target, "exception": {"credential_refs": []}}]}
    policy_file = _private_json(tmp_path / "policy.json", policy)
    targets_file = _private_json(tmp_path / "targets.json", [target])

    assert _run(db, "commit", "--policy", policy_file, "--initial") == 0
    revision = json.loads(capsys.readouterr().out)
    assert revision["policy"] == policy
    assert _run(db, "export", "--revision", revision["id"]) == 0
    assert json.loads(capsys.readouterr().out) == revision
    assert _run(db, "commit", "--policy", policy_file, "--initial") == 1
    assert json.loads(capsys.readouterr().err)["head"] == revision["id"]

    target_db = ("--target-db", str(tmp_path / "target.db"))
    local_config = _private_json(tmp_path / "local.json", {"target": target, "limits": {}})
    assert _fleet("target-configure", *target_db, "--config", local_config) == 0
    assert json.loads(capsys.readouterr().out)["applied_revision"] is None
    assert _run(db, "target-report", *target_db) == 0
    assert json.loads(capsys.readouterr().out)["local"]["target"] == target
    assert _run(db, "preview", "--revision", revision["id"], "--targets", targets_file) == 0
    preview = json.loads(capsys.readouterr().out)
    assert [item["target"] for item in preview["targets"]] == [target]
    assert _run(db, "approve", "--digest", preview["digest"], "--idempotency-key", "review") == 0
    approval = json.loads(capsys.readouterr().out)
    assert approval["outcomes"][0]["status"] == "pending"
    assert (
        _run(
            db,
            "target-adopt",
            *target_db,
            "--approval",
            approval["id"],
            "--digest",
            preview["digest"],
        )
        == 0
    )
    outcome = json.loads(capsys.readouterr().out)
    assert outcome["status"] == "applied"
    assert _fleet("target-show", *target_db) == 0
    assert json.loads(capsys.readouterr().out)["applied_revision"] == revision["id"]
    assert _run(db, "status", "--approval-id", approval["id"]) == 0
    assert json.loads(capsys.readouterr().out)["outcomes"] == [outcome]
    assert _run(db, "head") == 0
    assert json.loads(capsys.readouterr().out)["head"] == revision["id"]

    grant = _private_json(
        tmp_path / "grant.json", {"subject": "reviewer", "permission": "read", "target": target}
    )
    assert _run(db, "grant", "--grant", grant) == 0
    assert json.loads(capsys.readouterr().out) == {"enabled": True}
    service = FleetPolicyApply(registry)
    reviewer = FleetPolicyActor("reviewer")
    assert not service.head(reviewer).targets[0].can_write
    assert _run(db, "grant", "--grant", grant, "--revoke") == 0
    assert json.loads(capsys.readouterr().out) == {"enabled": False}
    assert not service.head(reviewer).targets

    browser = FleetPolicyActor("browser-admin", coordinator=True, source="browser")
    assert _run(db, "coordinator", "--subject", browser.subject) == 0
    assert json.loads(capsys.readouterr().out) == {"enabled": True}
    assert service.head(browser).can_manage
    assert _run(db, "coordinator", "--subject", browser.subject, "--revoke") == 0
    assert json.loads(capsys.readouterr().out) == {"enabled": False}
    assert not service.head(browser).can_manage

    new_policy = _private_json(tmp_path / "new-policy.json", {})
    assert _run(db, "commit", "--policy", new_policy, "--parent", revision["id"]) == 0
    new = json.loads(capsys.readouterr().out)
    assert _run(db, "rollback", "--revision", revision["id"], "--parent", new["id"]) == 0
    rolled = json.loads(capsys.readouterr().out)
    assert rolled["policy"] == policy
    assert rolled["parent"] == new["id"]


def test_fleet_policy_cli_sanitizes_invalid_private_input(tmp_path, capsys):
    tmp_path.chmod(0o700)
    sensitive = "credential-that-must-not-appear"
    file = tmp_path / "policy.json"
    file.touch(mode=0o600)
    file.write_text('{"defaults":{"credential_refs":["' + sensitive + '"]}}', encoding="utf-8")
    assert _run(tmp_path / "fleet.db", "commit", "--policy", str(file), "--initial") == 1
    assert sensitive not in capsys.readouterr().err
