"""L06: `steward rollback` and `steward-host rollback` (thin, bound-identifier wrappers)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from steward import hostcli
from steward.cli import main as cli
from steward.core.config import UpdatePolicy
from update_support import NEW_DIGEST, contract_data

APPROVAL = "approval-0123456789"
DIGEST = "sha256:" + NEW_DIGEST


def parse(cfg, *extra, project=None):
    return cli.build_parser().parse_args(
        [
            "rollback",
            "--config",
            "server.yml",
            "--limit",
            cfg.server.name,
            "--project",
            project or cfg.managed_projects[0].id,
            "--approval-id",
            extra[0] if extra else APPROVAL,
            "--digest",
            extra[1] if len(extra) > 1 else DIGEST,
            *extra[2:],
        ]
    )


@pytest.fixture
def with_contract(cfg, monkeypatch):
    cfg.managed_projects[0].update = UpdatePolicy.model_validate(contract_data())
    monkeypatch.setattr(cli, "load", lambda _: cfg)
    return cfg


def result_for(cfg, **over):
    body = {
        "project_id": cfg.managed_projects[0].id,
        "approval_id": APPROVAL,
        "state": "rolled_back",
        "image": "registry.example/shop/app@sha256:" + "a" * 64,
        "config_revision": "c" * 64,
        "preserved_data": None,
        "verified": {"image_verified": True, "health": "healthy"},
    }
    body.update(over)
    return body


def test_rollback_requires_its_bound_identifiers(cfg):
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["rollback", "--config", "x", "--limit", cfg.server.name])
    args = parse(cfg)
    assert args.func is cli.cmd_rollback and args.acknowledge_data_restore is False


def test_rollback_is_unavailable_without_a_verified_update_contract(cfg, monkeypatch):
    monkeypatch.setattr(cli, "load", lambda _: cfg)
    monkeypatch.setattr(cli, "generate", lambda *_: pytest.fail("reached the network"))
    with pytest.raises(cli.CliError, match="no verified update contract") as caught:
        cli.cmd_rollback(parse(cfg))
    assert caught.value.code == cli.EXIT_UNAVAILABLE
    with pytest.raises(cli.CliError, match="no verified update contract"):
        cli.cmd_rollback(parse(cfg, project="ghost"))


@pytest.mark.parametrize(
    "approval,digest",
    [("short", DIGEST), (APPROVAL, "sha256:xyz"), (APPROVAL, "b" * 64), ("a b" * 8, DIGEST)],
)
def test_malformed_identifiers_are_rejected_before_the_network(
    with_contract, monkeypatch, approval, digest
):
    monkeypatch.setattr(cli, "generate", lambda *_: pytest.fail("reached the network"))
    with pytest.raises(cli.CliError) as caught:
        cli.cmd_rollback(parse(with_contract, approval, digest))
    assert caught.value.code == cli.EXIT_INVALID


def test_rollback_passes_only_bound_variables_and_reports_preserved_data(
    with_contract, tmp_path, monkeypatch, capsys
):
    (tmp_path / "vars.json").write_text("{}")
    monkeypatch.setattr(cli, "generate", lambda *_: tmp_path)
    calls = []

    def ansible(playbook, connection, out, **kwargs):
        variables = json.loads((out / "vars.json").read_text())
        calls.append((playbook, variables))
        (out / "rollback-result.json").write_text(
            json.dumps(result_for(with_contract, preserved_data="data.preserved-abc"))
        )

    monkeypatch.setattr(cli, "ansible", ansible)
    args = parse(with_contract, APPROVAL, DIGEST, "--acknowledge-data-restore")
    assert cli.cmd_rollback(args) == 0
    (playbook, variables) = calls[0]
    assert playbook == "rollback.yml"
    assert variables == {
        "steward_rollback_project": with_contract.managed_projects[0].id,
        "steward_rollback_approval": APPROVAL,
        "steward_rollback_digest": DIGEST,
        "steward_rollback_restore": True,
    }
    out = capsys.readouterr().out
    assert "data.preserved-abc" in out and "nothing was deleted" in out
    assert "Pending web UI revisions were not touched" in out
    assert (tmp_path / "vars.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "over",
    [
        {"state": "failed"},
        {"state": "rolling_back"},
        {"project_id": "other"},
        {"approval_id": "approval-other-9999"},
        {"config_revision": "nothex"},
        {"verified": {"image_verified": False}},
        {"verified": None},
        {"image": None},
    ],
)
def test_unbound_or_unverified_results_are_not_reported_as_success(
    with_contract, tmp_path, monkeypatch, over
):
    (tmp_path / "vars.json").write_text("{}")
    monkeypatch.setattr(cli, "generate", lambda *_: tmp_path)
    monkeypatch.setattr(
        cli,
        "ansible",
        lambda *a, **k: (tmp_path / "rollback-result.json").write_text(
            json.dumps(result_for(with_contract, **over))
        ),
    )
    with pytest.raises(cli.CliError, match="does not match"):
        cli.cmd_rollback(parse(with_contract))


def test_missing_result_is_not_success(with_contract, tmp_path, monkeypatch):
    (tmp_path / "vars.json").write_text("{}")
    monkeypatch.setattr(cli, "generate", lambda *_: tmp_path)
    monkeypatch.setattr(cli, "ansible", lambda *a, **k: None)
    with pytest.raises(cli.CliError, match="does not match"):
        cli.cmd_rollback(parse(with_contract))


@pytest.mark.parametrize("restore", [False, True])
def test_rollback_playbook_preserves_exact_argv(tmp_path, restore):
    binary = Path(sys.executable).parent / "ansible-playbook"
    if not binary.exists():
        pytest.skip("Ansible is unavailable")
    root = Path(__file__).resolve().parents[1]
    stub = tmp_path / "steward-host-fixture"
    captured = tmp_path / "argv.json"
    stub.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys\n"
        f"pathlib.Path({str(captured)!r}).write_text(json.dumps(sys.argv[1:]))\n"
        "print(json.dumps({'state': 'rolled_back'}))\n"
    )
    stub.chmod(0o700)
    play = tmp_path / "rollback.yml"
    play.write_text(
        (root / "ansible/playbooks/rollback.yml")
        .read_text()
        .replace("become: true", "become: false")
        .replace("/opt/steward/current/venv/bin/steward-host", str(stub))
    )
    variables = tmp_path / "vars.json"
    variables.write_text(
        json.dumps(
            {
                "steward_rollback_project": "shop",
                "steward_rollback_approval": APPROVAL,
                "steward_rollback_digest": DIGEST,
                "steward_rollback_restore": restore,
                "steward_local_dir": str(tmp_path),
            }
        )
    )
    env = {
        **os.environ,
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-local"),
        "ANSIBLE_NOCOLOR": "1",
    }
    result = subprocess.run(
        [str(binary), "-i", "localhost,", "-c", "local", "-e", f"@{variables}", str(play)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    expected = ["rollback", "shop", "--approval-id", APPROVAL, "--digest", DIGEST]
    assert json.loads(captured.read_text()) == expected + (
        ["--acknowledge-data-restore"] if restore else []
    )
    assert json.loads((tmp_path / "rollback-result.json").read_text())["state"] == "rolled_back"


@pytest.mark.parametrize("restore", [False, True])
def test_host_command_sends_only_bound_identifiers_to_the_registered_action(
    monkeypatch, capsys, restore
):
    calls = []
    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        hostcli,
        "call",
        lambda action, params, **kwargs: calls.append((action, params, kwargs)) or {"ok": True},
    )
    argv = ["steward-host", "rollback", "shop", "--approval-id", APPROVAL, "--digest", DIGEST]
    monkeypatch.setattr(sys, "argv", argv + (["--acknowledge-data-restore"] if restore else []))
    hostcli.main()
    assert calls == [
        (
            "rollback",
            {
                "project_id": "shop",
                "approval_id": APPROVAL,
                "digest": DIGEST,
                "acknowledge_data_restore": restore,
            },
            {"socket_path": hostcli.DEFAULT_SOCKET, "timeout": 1800},
        )
    ]


@pytest.mark.parametrize("yes", [False, True])
def test_stale_controller_file_after_an_executor_applied_update_is_a_conflict(
    cfg, tmp_path, monkeypatch, yes
):
    from argparse import Namespace

    from steward.core.canonical import revision_id
    from steward.core.config import effective

    monkeypatch.setattr(cli, "WORK", tmp_path)
    local = effective(cfg)
    local_rev = revision_id(local)
    path = cli.local_state_path(cfg)
    path.parent.mkdir()
    path.write_text(json.dumps({"applied": local_rev}))  # this controller deployed the file
    updated = json.loads(json.dumps(local))
    updated["projects"][0]["image"] = "registry.example/shop/app@sha256:" + "b" * 64
    # the API has not observed the executor's change: its head is still the old revision
    state = {"applied": updated, "head": {"head": local_rev, "applied": local_rev, "config": local}}
    args = Namespace(config="server.yml", limit=cfg.server.name, yes=yes, discard_pending=False)
    with pytest.raises(cli.CliError, match="config pull") as caught:
        cli.check_conflicts(cfg, state, args)
    assert caught.value.code == cli.EXIT_CONFLICT
    # after `config pull` the file equals the applied revision: no conflict, empty diff
    state["head"] = {"head": revision_id(updated), "applied": revision_id(updated)}
    monkeypatch.setattr(cli, "effective", lambda _cfg: updated)
    assert cli.check_conflicts(cfg, state, args) == []
