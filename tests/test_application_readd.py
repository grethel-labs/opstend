"""L09 step 3 wiring: deployment helper, ansible hook and operator command."""

import json
import os
from pathlib import Path

import pytest
import yaml

from steward import application_archive, application_layout, hostcli
from steward.core import app_archive as archive
from steward.core.config import parse_config
from steward.core.ids import graph_identifier
from steward.core.render import image_tag
from test_app_archive import IMAGE, MINE, identity

ROLES = Path(__file__).resolve().parents[1] / "ansible/roles"


@pytest.fixture
def layout(tmp_path, monkeypatch):
    base = tmp_path / "srv"
    monkeypatch.setattr(application_layout, "DATA_ROOT", base)
    monkeypatch.setattr(archive, "ARCHIVE_ROOT", base / "archive")
    monkeypatch.setattr(archive, "IMAGE_CACHE", tmp_path / "images")
    (base / "archive").mkdir(parents=True, mode=0o700)
    (tmp_path / "images").mkdir(mode=0o755)
    data = base / "applications" / "shop" / "data"
    data.mkdir(parents=True, mode=0o755)
    stem = graph_identifier("s", "shop", "database")
    user = "stw-" + stem
    ident = identity(0)
    configuration = {
        "application": {
            "id": "shop",
            "isolation": "separate",
            "pod": None,
            "services": [
                {
                    "id": "database",
                    "user": user,
                    "unit": stem + ".service",
                    "filename": stem + ".container",
                    "manage": True,
                    "deploy": False,
                    "data_source": str(data / "database"),
                    "data_owner_container_uid": 10001,
                    "data_needs_mapped_owner": False,
                    "image": IMAGE,
                    "image_tag": image_tag(stem, IMAGE),
                }
            ],
        },
        "ids": {user: ident},
    }
    return configuration, data, user, ident


def test_helper_is_a_no_op_without_an_archive(layout):
    configuration, data, _user, _ident = layout
    assert application_archive.reactivate(configuration) == {"changed": False, "state": "none"}
    assert not (data / "database").exists()


def test_helper_restores_through_the_layout_binding_and_pinned_identity(layout, monkeypatch):
    configuration, data, user, ident = layout
    source = data / "database"
    source.mkdir(mode=0o700)
    (source / "value.txt").write_text("precious")
    (source / "value.txt").chmod(0o644)
    root = archive.ARCHIVE_ROOT
    state = archive.start_operation(
        root, "shop", "3" * 32, applied_revision="a" * 64, desired_revision="b" * 64
    )
    service = configuration["application"]["services"][0]
    manifest = archive.write_archive(
        root / "shop" / state.operation_id,
        state,
        server="test-server",
        services=[
            archive.ServiceInput(
                service="database",
                user=user,
                unit=service["unit"],
                identity=ident,
                image=IMAGE,
                image_tag=service["image_tag"],
                source_revision="bundled:test@1",
                data_source=source,
            )
        ],
        image_cache=archive.IMAGE_CACHE,
        is_quiescent=lambda: True,
        max_data_bytes=1024 * 1024,
    )
    state = archive.advance(root, state, "archived", manifest_id=manifest.id)
    state = archive.advance(root, state, "verified")
    state = archive.advance(root, state, "releasing", released={"database": "moved"})
    archive.release_data(data, state.operation_id, "database")
    archive.advance(root, state, "released", released={"database": "deleted"})
    source.mkdir(mode=0o700)

    pinned = []
    monkeypatch.setattr(application_layout, "pinned_account", lambda u, i: pinned.append((u, i)))
    monkeypatch.setattr(application_archive, "pinned_account", application_layout.pinned_account)
    real = archive.reactivate
    monkeypatch.setattr(
        archive,
        "reactivate",
        lambda *a, **k: real(*a, **{**k, "owner_of": lambda _i: MINE}),
    )
    result = application_archive.reactivate(configuration)
    assert result["state"] == "reactivated" and result["restored"] == ["database"]
    assert pinned == [(user, ident)]
    assert (source / "value.txt").read_text() == "precious"
    # Once reactivated the archive is consumed; later deployments change nothing.
    configuration["ids"][user] = {**ident, "uid": ident["uid"] + 1}
    assert application_archive.reactivate(configuration) == {"changed": False, "state": "none"}


def test_helper_is_root_only_with_a_fixed_command(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["x", "reactivate"])
    with pytest.raises(SystemExit) as error:
        application_archive.main()
    assert "root only" in str(error.value)
    monkeypatch.setattr(application_archive.os, "geteuid", lambda: 0)
    monkeypatch.setattr("sys.argv", ["x", "delete"])
    with pytest.raises(SystemExit):
        application_archive.main()


def test_ansible_restores_before_secrets_images_and_units():
    tasks = yaml.safe_load((ROLES / "workloads/tasks/application.yml").read_text())
    names = [task["name"] for task in tasks]
    layout_step = names.index("Create protected application paths and verify data ownership")
    restore = names.index(
        "Verify and restore any retired archive before this application can start"
    )
    assert restore == layout_step + 1
    task = tasks[restore]
    assert task["ansible.builtin.command"]["argv"][-3:] == [
        "-m",
        "steward.application_archive",
        "reactivate",
    ]
    assert task["no_log"] is True and "shell" not in json.dumps(task)
    for later in (
        "Read and hash planned protected application environment files",
        "Provide tag-specific local images to enabled services",
        "Install root-owned application Quadlets",
    ):
        assert names.index(later) > restore


def test_operator_command_sends_only_revisions_and_ids(tmp_path, monkeypatch, raw_config):
    from test_application_graph import graph

    graph(raw_config)
    raw_config["applications"] = []
    path = tmp_path / "desired.yml"
    path.write_text(yaml.safe_dump(raw_config))
    calls = []

    def fake_call(action, params=None, **kwargs):
        calls.append((action, params, kwargs))
        return {"config_revision": "a" * 64} if action == "platform_status" else {"state": "ok"}

    monkeypatch.setattr(hostcli, "call", fake_call)
    monkeypatch.setattr(hostcli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        "sys.argv", ["steward-host", "application-retire", "shop", "--desired-config", str(path)]
    )
    hostcli.main()
    action, params, kwargs = calls[-1]
    assert action == "application_retire" and kwargs["timeout"] == 900
    assert set(params) == {
        "application",
        "expected_revision",
        "desired_revision",
        "desired_applications",
    }
    assert params["expected_revision"] == "a" * 64 and params["desired_applications"] == []
    assert parse_config(raw_config, allow_unavailable=True) and os.path.isfile(path)
    monkeypatch.setattr(
        "sys.argv", ["steward-host", "application-retire", "../x", "--desired-config", str(path)]
    )
    with pytest.raises(SystemExit):
        hostcli.main()
