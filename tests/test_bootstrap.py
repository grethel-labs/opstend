"""Exercise the real Linux atomic ownership claim without touching system paths."""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "ansible/roles/bootstrap/files/claim.py"
spec = importlib.util.spec_from_file_location("bootstrap_claim", SCRIPT)
claim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(claim)
REVISION = "a" * 64


@pytest.fixture
def root(tmp_path):
    for directory in ("etc", "srv", "run"):
        (tmp_path / directory).mkdir()
    return tmp_path


def test_claim_is_complete_before_atomic_publication_and_resumable(root, monkeypatch):
    original = claim.publish

    def checked(staging, target):
        assert not target.exists()
        marker = json.loads((staging / "install.json").read_text())
        assert marker["state"] == "initializing"
        assert marker["initial_revision"] == REVISION
        assert (staging / "install.json").stat().st_mode & 0o777 == 0o644
        return original(staging, target)

    monkeypatch.setattr(claim, "publish", checked)
    assert claim.claim(root, "test-host", REVISION)
    # Simulate interruption after identities created the workload root.
    (root / "srv/steward").mkdir()
    assert not claim.claim(root, "test-host", "b" * 64)
    assert not list((root / "etc").glob(".steward-bootstrap-*"))


@pytest.mark.parametrize("foreign", ["etc/steward", "srv/steward", "srv/isobox", "run/docker.sock"])
def test_foreign_layout_is_never_adopted(root, foreign):
    (root / foreign).mkdir()
    with pytest.raises((ValueError, FileNotFoundError)):
        claim.claim(root, "test-host", REVISION)
    assert not (root / "etc/steward/install.json").exists()


def test_atomic_noreplace_does_not_overwrite_concurrent_empty_directory(root, monkeypatch):
    original = claim.publish

    def race(staging, target):
        target.mkdir(mode=0o755)
        return original(staging, target)

    monkeypatch.setattr(claim, "publish", race)
    with pytest.raises(FileNotFoundError):
        claim.claim(root, "test-host", REVISION)
    assert list((root / "etc/steward").iterdir()) == []
    assert not list((root / "etc").glob(".steward-bootstrap-*"))


def test_failed_publication_leaves_no_unmarked_layout(root, monkeypatch):
    def fail(*args):
        raise OSError("injected publication failure")

    monkeypatch.setattr(claim, "publish", fail)
    with pytest.raises(OSError, match="injected"):
        claim.claim(root, "test-host", REVISION)
    assert not (root / "etc/steward").exists()
    assert not list((root / "etc").glob(".steward-bootstrap-*"))


@pytest.mark.parametrize("after_publication", [False, True])
def test_process_death_during_claim_remains_recoverable(root, after_publication):
    code = """
import importlib.util, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('claim', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
original = module.publish
def stop(staging, target):
    if sys.argv[3] == 'after':
        original(staging, target)
    os._exit(77)
module.publish = stop
module.claim(Path(sys.argv[2]), 'test-host', 'a' * 64)
"""
    process = subprocess.run(
        [
            sys.executable,
            "-c",
            code,
            str(SCRIPT),
            str(root),
            "after" if after_publication else "before",
        ],
        timeout=10,
        check=False,
    )
    assert process.returncode == 77
    target = root / "etc/steward"
    assert target.exists() == after_publication
    assert claim.claim(root, "test-host", REVISION) == (not after_publication)
    assert json.loads((target / "install.json").read_text())["state"] == "initializing"


@pytest.mark.parametrize("tamper", ["server", "marker_mode", "directory_mode", "symlink", "owner"])
def test_untrusted_marker_cannot_authorize_resumption(root, monkeypatch, tamper):
    claim.claim(root, "test-host", REVISION)
    target = root / "etc/steward"
    marker = target / "install.json"
    if tamper == "server":
        marker.write_text(json.dumps({"server_name": "foreign", "schema_version": 1}))
    elif tamper == "marker_mode":
        marker.chmod(0o666)
    elif tamper == "directory_mode":
        target.chmod(0o777)
    elif tamper == "symlink":
        real = target / "real.json"
        marker.rename(real)
        marker.symlink_to(real)
    else:
        monkeypatch.setattr(claim.os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(ValueError):
        claim.claim(root, "test-host", REVISION)


def test_legacy_installed_marker_is_preserved(root):
    target = root / "etc/steward"
    target.mkdir(mode=0o755)
    marker = target / "install.json"
    body = json.dumps({"server_name": "test-host", "schema_version": 1})
    marker.write_text(body)
    marker.chmod(0o644)
    assert not claim.claim(root, "test-host", REVISION)
    assert marker.read_text() == body


def test_guarded_claim_requires_and_preserves_exact_installed_marker(root):
    with pytest.raises(ValueError, match="requires an installed marker"):
        claim.claim(root, "test-host", REVISION, guarded=True)
    assert not (root / "etc/steward").exists()

    assert claim.claim(root, "test-host", REVISION)
    marker = root / "etc/steward/install.json"
    with pytest.raises(ValueError, match="unsupported"):
        claim.claim(root, "test-host", REVISION, guarded=True)

    enrolled = json.dumps({"schema_version": 2, "server_name": "test-host", "state": "installed"})
    marker.write_text(enrolled)
    with pytest.raises(ValueError, match="unsupported"):
        claim.claim(root, "test-host", REVISION)
    assert not claim.claim(root, "test-host", REVISION, guarded=True)
    assert marker.read_text() == enrolled
