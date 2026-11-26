import os

import pytest

from steward.core.backupretire import RetirementIntent, retire_capture
from steward.core.backups import BackupError


@pytest.fixture
def retirement(tmp_path):
    parent = tmp_path / "spool"
    parent.mkdir(mode=0o700)
    target = parent / ("a" * 32)
    target.mkdir(mode=0o700)
    for name in ("data.tar", "manifest.json"):
        path = target / name
        path.write_bytes(name.encode())
        path.chmod(0o600)
    directory, data, manifest = (
        target.stat(),
        (target / "data.tar").stat(),
        (target / "manifest.json").stat(),
    )
    intent = RetirementIntent(
        artifact=target.name,
        capture_id="b" * 64,
        data_name="data.tar",
        directory_device=directory.st_dev,
        directory_inode=directory.st_ino,
        data_device=data.st_dev,
        data_inode=data.st_ino,
        manifest_device=manifest.st_dev,
        manifest_inode=manifest.st_ino,
    )
    return parent, target, intent


def test_retirement_removes_only_journaled_files_and_is_idempotent(retirement):
    parent, target, intent = retirement
    other = parent / "unrelated"
    other.write_text("keep")
    retire_capture(parent, intent)
    assert not target.exists()
    assert other.read_text() == "keep"
    retire_capture(parent, intent)
    assert other.read_text() == "keep"


def test_retirement_resumes_after_interrupted_unlink(retirement, monkeypatch):
    parent, target, intent = retirement
    original_unlink = os.unlink
    calls = []

    def interrupt(name, *, dir_fd=None):
        calls.append(name)
        if len(calls) == 2:
            raise OSError("injected interruption")
        return original_unlink(name, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "unlink", interrupt)
        with pytest.raises(OSError):
            retire_capture(parent, intent)
    hidden = parent / (".retiring-" + target.name)
    assert not target.exists() and hidden.is_dir()
    assert sorted(p.name for p in hidden.iterdir()) == ["manifest.json"]
    retire_capture(parent, intent)
    assert not hidden.exists()


@pytest.mark.parametrize("corruption", ["extra", "replace", "symlink", "hardlink", "unsafe_mode"])
def test_retirement_refuses_unrecognized_or_changed_objects(retirement, tmp_path, corruption):
    parent, target, intent = retirement
    data = target / "data.tar"
    if corruption == "extra":
        (target / "unknown").write_text("keep")
    elif corruption == "replace":
        data.rename(tmp_path / "original")
        data.write_bytes(b"replacement")
        data.chmod(0o600)
    elif corruption == "symlink":
        data.unlink()
        data.symlink_to(tmp_path / "outside")
    elif corruption == "hardlink":
        os.link(data, tmp_path / "outside")
    else:
        data.chmod(0o666)
    with pytest.raises(BackupError):
        retire_capture(parent, intent)
    assert target.exists()


def test_retirement_refuses_ambiguous_existing_quarantine(retirement):
    parent, target, intent = retirement
    hidden = parent / (".retiring-" + target.name)
    hidden.mkdir(mode=0o700)
    with pytest.raises(BackupError, match="ambiguous_retirement"):
        retire_capture(parent, intent)
    assert target.exists() and hidden.exists()


def test_import_retirement_resumes_after_sealing_before_rename(retirement, monkeypatch):
    from steward.core import backupretire

    parent, target, intent = retirement
    parent.chmod(0o750)
    target.chmod(0o550)
    for path in target.iterdir():
        path.chmod(0o440)
    intent = intent.model_copy(update={"namespace": "import"})
    with monkeypatch.context() as patch:
        patch.setattr(
            backupretire, "_rename_noreplace", lambda *_: (_ for _ in ()).throw(OSError("failure"))
        )
        with pytest.raises(OSError):
            retire_capture(parent, intent, import_gid=os.getgid())
    assert target.is_dir() and target.stat().st_mode & 0o777 == 0o700
    assert sorted(p.name for p in target.iterdir()) == ["data.tar", "manifest.json"]
    assert retire_capture(parent, intent, import_gid=os.getgid()) == "removed"
    assert not target.exists()


def test_import_retirement_rejects_unbound_group(retirement):
    parent, target, intent = retirement
    parent.chmod(0o750)
    target.chmod(0o550)
    for path in target.iterdir():
        path.chmod(0o440)
    intent = intent.model_copy(update={"namespace": "import"})
    with pytest.raises(BackupError, match="unsafe_spool"):
        retire_capture(parent, intent, import_gid=os.getgid() + 1)
    assert target.is_dir()
