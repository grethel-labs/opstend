import os
import sqlite3
import tarfile

import pytest

from steward.core.backups import BackupError, Binding, load_capture
from steward.core.filebackups import capture_files


@pytest.fixture
def binding():
    return Binding(
        server="test-server",
        project="notes",
        config_revision="a" * 64,
        image="docker.io/library/python@sha256:" + "b" * 64,
        source_revision="bundled:sample-notes@0.1.0",
    )


def test_whole_quiescent_tree_preserves_files_and_empty_directories(tmp_path, binding):
    source = tmp_path / "data"
    source.mkdir()
    (source / "empty").mkdir()
    db = sqlite3.connect(source / "notes.db")
    db.execute("CREATE TABLE notes (value TEXT)")
    db.execute("INSERT INTO notes VALUES ('durable')")
    db.commit()
    db.close()
    (source / "attachment").write_bytes(b"attachment contents")
    probes = []

    def quiescent():
        probes.append(True)
        return True

    destination = tmp_path / "capture"
    manifest = capture_files(source, destination, binding, is_quiescent=quiescent)
    assert len(probes) == 2
    assert manifest == load_capture(destination)
    assert manifest.entries == 3 and manifest.origin == "operator_local"
    with tarfile.open(destination / "data.tar") as archive:
        assert archive.getmember("empty").isdir()
        assert archive.extractfile("attachment").read() == b"attachment contents"
        recovered = tmp_path / "recovered.db"
        recovered.write_bytes(archive.extractfile("notes.db").read())
    with sqlite3.connect(recovered) as restored:
        assert restored.execute("SELECT value FROM notes").fetchone() == ("durable",)


@pytest.mark.parametrize("initial", [True, False])
def test_capture_requires_quiescence_before_and_after_copy(tmp_path, binding, initial):
    source = tmp_path / "data"
    source.mkdir()
    (source / "file").write_text("data")
    probes = iter([initial, False])
    target = tmp_path / "capture"
    with pytest.raises(BackupError, match="not_quiescent"):
        capture_files(source, target, binding, is_quiescent=lambda: next(probes))
    assert not target.exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_unsafe_files_fail_without_following_or_leaving_partial_capture(tmp_path, binding, kind):
    source = tmp_path / "data"
    source.mkdir()
    secret = tmp_path / "external-secret"
    secret.write_text("never captured")
    if kind == "symlink":
        (source / "bad").symlink_to(secret)
    elif kind == "hardlink":
        os.link(secret, source / "bad")
    else:
        os.mkfifo(source / "bad")
    target = tmp_path / "capture"
    with pytest.raises(BackupError, match="unsafe_entry"):
        capture_files(source, target, binding, is_quiescent=lambda: True)
    assert not target.exists()
    assert secret.read_text() == "never captured"


def test_capture_bounds_bytes_and_refuses_self_capture(tmp_path, binding):
    source = tmp_path / "data"
    source.mkdir()
    (source / "large").write_bytes(b"x" * 100)
    target = tmp_path / "capture"
    with pytest.raises(BackupError, match="limit_exceeded"):
        capture_files(source, target, binding, is_quiescent=lambda: True, max_bytes=99)
    assert not target.exists()
    with pytest.raises(BackupError, match="invalid_input"):
        capture_files(source, source / "self", binding, is_quiescent=lambda: True)


def test_changed_source_after_copy_is_refused(tmp_path, binding, monkeypatch):
    source = tmp_path / "data"
    source.mkdir()
    data = source / "file"
    data.write_text("original")
    original = tarfile.TarFile.addfile

    def change_after_read(archive, item, fileobj=None):
        original(archive, item, fileobj)
        data.write_text("changed!")

    monkeypatch.setattr(tarfile.TarFile, "addfile", change_after_read)
    with pytest.raises(BackupError, match="source_changed"):
        capture_files(source, tmp_path / "capture", binding, is_quiescent=lambda: True)


def test_restore_tree_revalidates_full_contents_empty_directories_and_modes(tmp_path, binding):
    from steward.core.filebackups import materialize_tree

    source = tmp_path / "source"
    source.mkdir()
    (source / "empty").mkdir(mode=0o750)
    (source / "nested").mkdir(mode=0o750)
    (source / "nested" / "attachment").write_bytes(b"restored attachment")
    (source / "nested" / "attachment").chmod(0o640)
    db = sqlite3.connect(source / "notes.db")
    db.execute("CREATE TABLE notes (value TEXT)")
    db.execute("INSERT INTO notes VALUES ('saved note')")
    db.commit()
    db.close()
    capture = tmp_path / "capture"
    manifest = capture_files(source, capture, binding, is_quiescent=lambda: True)
    workspace = tmp_path / "private"
    workspace.mkdir(mode=0o700)
    data = materialize_tree(capture / "data.tar", manifest, workspace)
    assert (data / "empty").is_dir()
    assert (data / "nested" / "attachment").read_bytes() == b"restored attachment"
    assert (data / "nested" / "attachment").stat().st_mode & 0o777 == 0o640
    with sqlite3.connect(data / "notes.db") as restored:
        assert restored.execute("SELECT value FROM notes").fetchone() == ("saved note",)
        assert restored.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    assert sorted(path.name for path in workspace.iterdir()) == ["data"]


@pytest.mark.parametrize("kind", ["traversal", "symlink", "tampered"])
def test_restore_tree_rejects_unsafe_or_modified_archives(tmp_path, binding, kind):
    import io

    from steward.core.backups import digest_file
    from steward.core.filebackups import materialize_tree

    source = tmp_path / "source"
    source.mkdir()
    (source / "file").write_text("safe")
    capture = tmp_path / "capture"
    manifest = capture_files(source, capture, binding, is_quiescent=lambda: True)
    archive_path = capture / "data.tar"
    if kind == "tampered":
        with archive_path.open("ab") as out:
            out.write(b"changed")
    else:
        with tarfile.open(archive_path, "w") as archive:
            entry = tarfile.TarInfo("../escape" if kind == "traversal" else "link")
            if kind == "symlink":
                entry.type, entry.linkname = tarfile.SYMTYPE, "/etc/passwd"
            else:
                entry.size = 1
            archive.addfile(entry, io.BytesIO(b"x") if kind == "traversal" else None)
        digest, size = digest_file(archive_path, max_bytes=1024 * 1024)
        manifest = manifest.model_copy(
            update={
                "sha256": digest,
                "size": size,
                "entries": 1,
                "data_bytes": 1 if kind == "traversal" else 0,
            }
        )
    workspace = tmp_path / "private"
    workspace.mkdir(mode=0o700)
    with pytest.raises(BackupError):
        materialize_tree(archive_path, manifest, workspace)
    assert not (tmp_path / "escape").exists()
    assert not (workspace / "data").exists()


@pytest.mark.parametrize("field", ["data_bytes", "size"])
def test_restore_tree_refuses_oversized_capture_before_extraction(tmp_path, binding, field):
    from steward.core.filebackups import ARCHIVE_OVERHEAD_MAX, MAX_RESTORE_BYTES, materialize_tree

    source = tmp_path / "source"
    source.mkdir()
    (source / "file").write_text("safe")
    capture = tmp_path / "capture"
    manifest = capture_files(source, capture, binding, is_quiescent=lambda: True)
    limit = MAX_RESTORE_BYTES + (ARCHIVE_OVERHEAD_MAX if field == "size" else 0)
    manifest = manifest.model_copy(update={field: limit + 1})
    workspace = tmp_path / "private"
    workspace.mkdir(mode=0o700)
    with pytest.raises(BackupError, match="limit_exceeded"):
        materialize_tree(capture / "data.tar", manifest, workspace)
    assert not list(workspace.iterdir())


@pytest.mark.parametrize("kind", ["nonempty", "world_readable", "symlink"])
def test_restore_tree_requires_empty_private_owned_workspace(tmp_path, binding, kind):
    from steward.core.filebackups import materialize_tree

    source = tmp_path / "source"
    source.mkdir()
    (source / "file").write_text("capture")
    capture = tmp_path / "capture"
    manifest = capture_files(source, capture, binding, is_quiescent=lambda: True)
    workspace = tmp_path / "workspace"
    if kind == "symlink":
        foreign = tmp_path / "foreign"
        foreign.mkdir(mode=0o700)
        (foreign / "sentinel").write_text("unchanged")
        workspace.symlink_to(foreign, target_is_directory=True)
    else:
        workspace.mkdir(mode=0o700)
        if kind == "nonempty":
            (workspace / "sentinel").write_text("unchanged")
        else:
            workspace.chmod(0o755)
    with pytest.raises(BackupError, match="invalid_input"):
        materialize_tree(capture / "data.tar", manifest, workspace)
    if kind != "world_readable":
        assert (workspace / "sentinel").read_text() == "unchanged"
    assert not (workspace / "data").exists()
