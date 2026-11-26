import os
import struct
from types import SimpleNamespace

import pytest

from steward.core.backupexport import export_capture
from steward.core.backups import BackupError, Binding, load_capture
from steward.core.filebackups import capture_files


@pytest.fixture
def capture(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "state").write_bytes(b"private application state")
    source = tmp_path / "capture"
    manifest = capture_files(
        data,
        source,
        Binding(
            server="test-server",
            project="notes",
            config_revision="a" * 64,
            image="docker.io/library/python@sha256:" + "b" * 64,
            source_revision="bundled:sample-notes@0.1.0",
        ),
        is_quiescent=lambda: True,
    )
    imports = tmp_path / "imports"
    imports.mkdir(mode=0o750)
    return source, imports / "artifact", manifest


def test_export_is_read_only_idempotent_and_preserves_capture_identity(capture):
    source, target, manifest = capture
    result = export_capture(source, target, capture_id=manifest.id, gid=os.getgid())
    inode = target.stat().st_ino
    assert result == manifest == load_capture(target)
    assert target.stat().st_mode & 0o777 == 0o550
    for file in target.iterdir():
        assert file.stat().st_mode & 0o777 == 0o440
        assert file.stat().st_gid == os.getgid()
    assert export_capture(source, target, capture_id=manifest.id, gid=os.getgid()) == manifest
    assert target.stat().st_ino == inode


def test_wrong_capture_id_never_publishes_any_data(capture):
    source, target, _manifest = capture
    with pytest.raises(BackupError, match="evidence_mismatch"):
        export_capture(source, target, capture_id="0" * 64, gid=os.getgid())
    assert not target.exists() and list(target.parent.iterdir()) == []


@pytest.mark.parametrize("unsafe", ["writable", "symlink", "hardlink"])
def test_export_rejects_unsealed_source(capture, tmp_path, unsafe):
    source, target, manifest = capture
    if unsafe == "writable":
        (source / "data.tar").chmod(0o660)
    elif unsafe == "symlink":
        archive = tmp_path / "archive"
        (source / "data.tar").rename(archive)
        (source / "data.tar").symlink_to(archive)
    else:
        os.link(source / "data.tar", tmp_path / "other-link")
    with pytest.raises((BackupError, OSError)):
        export_capture(source, target, capture_id=manifest.id, gid=os.getgid())
    assert not target.exists()


def test_tampered_existing_export_is_never_overwritten(capture):
    source, target, manifest = capture
    export_capture(source, target, capture_id=manifest.id, gid=os.getgid())
    (target / "data.tar").chmod(0o600)
    (target / "data.tar").write_bytes(b"tampered")
    with pytest.raises(BackupError, match="evidence_mismatch"):
        export_capture(source, target, capture_id=manifest.id, gid=os.getgid())
    assert (target / "data.tar").read_bytes() == b"tampered"


def test_publish_failure_keeps_source_and_removes_temporary_export(capture, monkeypatch):
    source, target, manifest = capture

    def fail_sync(_fd):
        raise OSError("test failure")

    monkeypatch.setattr(os, "fsync", fail_sync)
    with pytest.raises(OSError):
        export_capture(source, target, capture_id=manifest.id, gid=os.getgid())
    assert list(target.parent.iterdir()) == []
    assert load_capture(source) == manifest


def test_inherited_named_acl_cannot_leak_export_outside_backup_group(capture):
    source, target, manifest = capture
    # Linux POSIX ACL v2: owner, named nobody user, group, mask, other.
    acl = struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", tag, perms, uid)
        for tag, perms, uid in (
            (1, 7, 0xFFFFFFFF),
            (2, 5, 65534),
            (4, 5, 0xFFFFFFFF),
            (16, 5, 0xFFFFFFFF),
            (32, 0, 0xFFFFFFFF),
        )
    )
    os.setxattr(target.parent, "system.posix_acl_default", acl)
    export_capture(source, target, capture_id=manifest.id, gid=os.getgid())
    for path in (target, *target.iterdir()):
        assert not {"system.posix_acl_access", "system.posix_acl_default"} & set(os.listxattr(path))


def test_export_space_reserve_is_checked_before_publishing(capture, monkeypatch):
    from steward.core import backupexport

    source, target, manifest = capture
    monkeypatch.setattr(backupexport.shutil, "disk_usage", lambda _: SimpleNamespace(free=0))
    with pytest.raises(BackupError, match="insufficient_space"):
        export_capture(source, target, capture_id=manifest.id, gid=os.getgid())
    assert not target.exists() and load_capture(source) == manifest


def test_export_protection_hook_runs_after_validation_before_publication(capture):
    source, target, manifest = capture
    seen = []

    def protect(value):
        seen.append(value.id)
        assert not target.exists()
        raise BackupError("unavailable")

    with pytest.raises(BackupError, match="evidence_mismatch"):
        export_capture(source, target, capture_id="0" * 64, gid=os.getgid(), before_publish=protect)
    assert seen == []
    with pytest.raises(BackupError, match="unavailable"):
        export_capture(
            source, target, capture_id=manifest.id, gid=os.getgid(), before_publish=protect
        )
    assert seen == [manifest.id] and not target.exists()
