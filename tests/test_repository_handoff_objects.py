from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import zlib
from dataclasses import replace

import pytest

from steward.core.builder import BuildError, BuildLimits, BuildRequest, export_source
from steward.core.repositories import FetchError, SourceRecord, source_digest
from steward.core.repository_handoff_objects import MAX_PACK_BYTES, import_pack, stage_pack


def _git(cwd, *args):
    return (
        subprocess.check_output(  # noqa: S603
            ["/usr/bin/git", *args],
            cwd=cwd,
            umask=0o077,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(cwd),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_AUTHOR_NAME": "Fixture",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "Fixture",
                "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            },
        )
        .strip()
        .decode()
    )


@pytest.fixture
def source(tmp_path):
    repo = tmp_path / "work"
    repo.mkdir(mode=0o700)
    _git(repo, "init", "--quiet")
    (repo / "old").write_text("parent-only")
    _git(repo, "add", "--", "old")
    _git(repo, "commit", "--quiet", "-m", "parent")
    parent = _git(repo, "rev-parse", "HEAD")
    (repo / "old").unlink()
    (repo / "data").mkdir()
    (repo / "data" / "app").write_bytes(b"current" * 50000)
    (repo / "link").symlink_to("data/app")
    _git(repo, "add", "--all")
    _git(repo, "commit", "--quiet", "-m", "current")
    commit = _git(repo, "rev-parse", "HEAD")
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    store = tmp_path / f"{commit}.git"
    _git(repo, "clone", "--quiet", "--bare", "--no-hardlinks", "--", str(repo), str(store))
    store.chmod(0o700)
    record = SourceRecord(
        "example",
        "app",
        "service",
        "https://example.invalid/repo",
        "refs/heads/main",
        commit,
        commit,
        tree,
        source_digest(commit, tree),
        store.name,
        "2026-11-26T00:00:00Z",
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    return store, record, scratch, parent


@pytest.mark.parametrize("repack", [False, True], ids=["loose", "packed"])
def test_only_exact_source_survives_and_retained_config_is_ignored(source, tmp_path, repack):
    store, record, scratch, parent = source
    if repack:
        _git(store, "repack", "-ad")
    # If read by Git, this broken config would terminate the operation.
    (store / "config").write_text("[broken\n")
    pack = tmp_path / "source.pack"
    stage_pack(store, record, pack, scratch)
    target = tmp_path / "normalized.git"
    import_pack(pack, record, target, scratch)
    assert (target / "shallow").read_text() == record.commit + "\n"
    assert _git(target, "rev-list", "--all") == record.commit
    assert _git(target, "rev-parse", "refs/steward/fetched^{tree}") == record.tree
    assert _git(target, "show", f"{record.commit}:link") == "data/app"
    assert len(_git(target, "cat-file", "--batch-all-objects", "--batch-check").splitlines()) == 5
    with pytest.raises(subprocess.CalledProcessError):
        _git(target, "cat-file", "-t", parent)


@pytest.mark.parametrize(
    "marker", ["info/alternates", "info/http-alternates", "pack/test.promisor"]
)
def test_retained_external_objects_are_rejected(source, tmp_path, marker):
    store, record, scratch, _ = source
    (store / "objects" / marker).touch()
    pack = tmp_path / "source.pack"
    with pytest.raises(FetchError):
        stage_pack(store, record, pack, scratch)
    assert not pack.exists()


def _packed(kind, data, size=None):
    size = len(data) if size is None else size
    header = bytearray([(kind << 4) | (size & 15)])
    size >>= 4
    while size:
        header[-1] |= 128
        header.append(size & 127)
        size >>= 7
    return bytes(header) + zlib.compress(data)


def _pack(*items, count=None):
    data = struct.pack(">4sII", b"PACK", 2, len(items) if count is None else count)
    data += b"".join(items)
    return data + hashlib.sha1(data, usedforsecurity=False).digest()


@pytest.mark.parametrize(
    "data",
    [
        _pack(_packed(6, b"delta")),
        _pack(_packed(3, b"x", size=2**30)),
        _pack(_packed(3, b"x" * 65537, size=65536)),
        _pack(_packed(3, b"x", size=2)),
        _pack(_packed(3, b"x"), count=2**32 - 1),
        _pack(_packed(3, b"x"), _packed(3, b"x")),
        _pack(_packed(3, b"x")) + b"suffix",
        _pack(_packed(3, b"x"))[:-1],
    ],
    ids=[
        "delta",
        "declared-size",
        "inflate-overrun",
        "inflate-underrun",
        "count",
        "duplicate",
        "trailing",
        "truncated",
    ],
)
def test_invalid_packs_leave_no_store(source, tmp_path, data):
    _, record, scratch, _ = source
    pack = tmp_path / "invalid.pack"
    pack.write_bytes(data)
    target = tmp_path / "normalized.git"
    with pytest.raises(FetchError):
        import_pack(pack, record, target, scratch)
    assert not target.exists()


def _with_pack_object(packed, item):
    count = struct.unpack(">I", packed[8:12])[0]
    payload = packed[:8] + struct.pack(">I", count + 1) + packed[12:-20] + item
    return payload + hashlib.sha1(payload, usedforsecurity=False).digest()


def test_valid_checksum_does_not_authorize_extra_objects_or_wrong_tree(source, tmp_path):
    store, record, scratch, parent = source
    pack = tmp_path / "source.pack"
    target = tmp_path / "normalized.git"
    stage_pack(store, record, pack, scratch)
    wrong = replace(record, tree=parent, source_digest=source_digest(record.commit, parent))
    with pytest.raises(FetchError, match="does not bind"):
        import_pack(pack, wrong, target, scratch)
    pack.write_bytes(_with_pack_object(pack.read_bytes(), _packed(3, b"unrelated")))
    with pytest.raises(FetchError, match="outside the exact source closure"):
        import_pack(pack, record, target, scratch)
    assert not target.exists()


def test_nested_symlink_escape_is_rejected_from_retained_source(source, tmp_path):
    _, prior, scratch, _ = source
    repo = tmp_path / "work"
    (repo / "data" / "up").symlink_to("..")
    (repo / "escape").symlink_to("data/up/../outside")
    _git(repo, "add", "--all")
    _git(repo, "commit", "--quiet", "-m", "escape")
    commit = _git(repo, "rev-parse", "HEAD")
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    store = tmp_path / f"{commit}.git"
    _git(repo, "clone", "--quiet", "--bare", "--no-hardlinks", "--", str(repo), str(store))
    store.chmod(0o700)
    record = replace(
        prior, commit=commit, tree=tree, store=store.name, source_digest=source_digest(commit, tree)
    )
    with pytest.raises(FetchError, match="symlink"):
        stage_pack(store, record, tmp_path / "source.pack", scratch)
    request = BuildRequest(record, {}, "", {}, "", store)
    with pytest.raises(BuildError, match="unsafe_symlink"):
        export_source(request, tmp_path / "export", BuildLimits())


def test_root_denied_before_git(source, tmp_path, monkeypatch):
    store, record, scratch, _ = source
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(FetchError, match="non-root"):
        stage_pack(store, record, tmp_path / "source.pack", scratch)


def test_exact_commit_with_missing_tree_is_rejected(source, tmp_path):
    _, record, scratch, _ = source
    tree = b"1" * 40
    commit_data = b"tree " + tree + b"\n"
    digest = hashlib.sha1(
        b"commit " + str(len(commit_data)).encode() + b"\0" + commit_data,
        usedforsecurity=False,
    ).hexdigest()
    record = replace(
        record,
        commit=digest,
        tree=tree.decode(),
        store=f"{digest}.git",
        source_digest=source_digest(digest, tree.decode()),
    )
    pack = tmp_path / "missing-tree.pack"
    pack.write_bytes(_pack(_packed(1, commit_data)))
    target = tmp_path / "normalized.git"
    with pytest.raises(FetchError, match="missing, invalid or deeply nested tree"):
        import_pack(pack, record, target, scratch)
    assert not target.exists()


def test_packed_file_size_is_checked_before_parsing(source, tmp_path):
    _, record, scratch, _ = source
    pack = tmp_path / "oversize.pack"
    with pack.open("wb") as handle:
        handle.truncate(MAX_PACK_BYTES + 1)
    with pytest.raises(FetchError, match="size is outside limits"):
        import_pack(pack, record, tmp_path / "normalized.git", scratch)


def test_git_rejects_malformed_commit_with_correct_hash_and_closure(source, tmp_path):
    _, record, scratch, _ = source
    tree = hashlib.sha1(b"tree 0\0", usedforsecurity=False).hexdigest()
    data = f"tree {tree}\n".encode()
    commit = hashlib.sha1(
        f"commit {len(data)}\0".encode() + data,
        usedforsecurity=False,
    ).hexdigest()
    record = replace(
        record,
        commit=commit,
        tree=tree,
        store=f"{commit}.git",
        source_digest=source_digest(commit, tree),
    )
    pack = tmp_path / "malformed-commit.pack"
    pack.write_bytes(_pack(_packed(1, data), _packed(2, b"")))
    target = tmp_path / "normalized.git"
    with pytest.raises(FetchError, match="git_failed"):
        import_pack(pack, record, target, scratch)
    assert not target.exists()
