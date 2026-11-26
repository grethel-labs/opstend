import os
import time

import pytest

from steward.core.backups import BackupError
from steward.core.data_ownership import inspect_data_ownership


def inspect(path, **kwargs):
    return inspect_data_ownership(
        path,
        service_uid=kwargs.get("uid", os.geteuid()),
        max_bytes=kwargs.get("maximum", 100),
        deadline=kwargs.get("deadline", time.monotonic() + 10),
    )


@pytest.fixture
def tree(tmp_path):
    tmp_path.chmod(0o700)
    (tmp_path / "file").write_text("original")
    (tmp_path / "file").chmod(0o600)
    return tmp_path


def test_stable_tree_has_stable_fingerprint_and_detects_change(tree):
    before = inspect(tree)
    assert inspect(tree) == before
    (tree / "file").write_text("changed content")
    assert inspect(tree) != before


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_rejects_shared_writable_file(tree, mode):
    (tree / "file").chmod(mode)
    with pytest.raises(BackupError, match="unsafe_owner"):
        inspect(tree)


def test_rejects_shared_writable_directory(tree):
    tree.chmod(0o770)
    with pytest.raises(BackupError, match="unsafe_owner"):
        inspect(tree)


def test_rejects_acl(tree, monkeypatch):
    monkeypatch.setattr(os, "listxattr", lambda fd: ["system.posix_acl_access"])
    with pytest.raises(BackupError, match="unsafe_owner"):
        inspect(tree)


def test_rejects_untrusted_owner(tree, monkeypatch):
    actual = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: actual + 10000)
    with pytest.raises(BackupError, match="unsafe_owner"):
        inspect(tree, uid=actual + 10001)


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_rejects_links(tree, kind):
    if kind == "symlink":
        (tree / "link").symlink_to("file")
    else:
        os.link(tree / "file", tree / "link")
    with pytest.raises(BackupError, match="unsafe_entry"):
        inspect(tree)


def test_limits_and_deadline(tree):
    with pytest.raises(BackupError, match="limit_exceeded"):
        inspect(tree, maximum=1)
    with pytest.raises(BackupError, match="timeout"):
        inspect(tree, deadline=time.monotonic() - 1)
