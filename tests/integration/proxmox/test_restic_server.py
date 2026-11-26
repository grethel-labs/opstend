"""Preflight guards must reject unsafe input before any remote mutation."""

import importlib.util
import io
import json
import os
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

SPEC = importlib.util.spec_from_file_location(
    "restic_fixture", Path(__file__).with_name("restic_server.py")
)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


@pytest.fixture(autouse=True)
def restore_process_umask():
    previous = os.umask(0o077)
    os.umask(previous)
    try:
        yield
    finally:
        os.umask(previous)


def test_bad_archive_hash_never_contacts_node(tmp_path, monkeypatch):
    archive = tmp_path / "bad.tar.gz"
    archive.write_bytes(b"corrupt archive")
    remote = Mock(side_effect=AssertionError("SSH must not run"))
    monkeypatch.setattr(fixture.subprocess, "run", remote)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fixture",
            "--workdir",
            str(tmp_path / "work"),
            "start",
            "--ssh-config",
            "/unused",
            "--alias",
            "node",
            "--archive",
            str(archive),
            "--archive-sha256",
            "0" * 64,
            "--port",
            "28473",
        ],
    )
    with pytest.raises(SystemExit):
        fixture.main()
    remote.assert_not_called()
    assert not (tmp_path / "work").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("namespace", "foreign-service"),
        ("namespace", "stw-rest-test-../../etc"),
        ("token", "not-a-token"),
        ("port", 22),
    ],
)
def test_remote_rejects_invalid_scope_before_commands(monkeypatch, field, value):
    payload = {
        "namespace": "stw-rest-test-" + "a" * 24,
        "token": "b" * 64,
        "port": 28473,
        "action": "cleanup",
    }
    payload[field] = value
    remote = Mock(side_effect=AssertionError("remote commands must not run"))
    monkeypatch.setattr(fixture.subprocess, "run", remote)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    with pytest.raises(AssertionError):
        exec(compile(fixture.REMOTE, "<remote-fixture>", "exec"), {})  # noqa: S102 -- execute our fixed remote guard under mocks
    remote.assert_not_called()
