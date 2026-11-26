"""Offline, bounded Git object transfer for the packaged repository builder."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import struct
import tempfile
import time
import zlib
from contextlib import contextmanager
from pathlib import Path

from .builder import (
    MAX_SOURCE_LINK_BYTES,
    MAX_SOURCE_LISTING_BYTES,
    BuildError,
    BuildLimits,
    check_source_links,
    source_link,
)
from .repositories import (
    FETCH_REF,
    SHA1,
    FetchError,
    FetchLimits,
    FetchPolicy,
    SourceRecord,
    _check_retained_store,
    _private_dir,
    _write_private,
    git_env,
    run_git,
    source_digest,
)

_LIMITS = BuildLimits()
_MAX_EXPANDED_BYTES = _LIMITS.source_bytes
MAX_PACK_BYTES = _MAX_EXPANDED_BYTES + 2**20
_MAX_OBJECTS = 2 * _LIMITS.source_files + 1
_MAX_ENTRIES = 2 * _LIMITS.source_files
_MAX_METADATA_BYTES = 16 * 2**20
_MAX_PATH_BYTES = 4095
_MAX_TREE_DEPTH = 128
_TIMEOUT = 120.0
_CHUNK = 64 * 1024
_TYPE = {1: b"commit", 2: b"tree", 3: b"blob"}
_MODES = {b"40000": 2, b"100644": 3, b"100755": 3, b"120000": 3}
_PACK_FILE = re.compile(r"pack-[0-9a-f]{40}\.(pack|idx)")


def _bad(message: str) -> FetchError:
    return FetchError("bad_pack", message)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise FetchError("timeout", "repository object transfer timed out")
    return remaining


def _check_inputs(record: SourceRecord, scratch: Path) -> float:
    if os.geteuid() == 0:
        raise FetchError("bad_identity", "repository object transfer requires a non-root user")
    if (
        not SHA1.fullmatch(record.commit)
        or not SHA1.fullmatch(record.tree)
        or record.store != f"{record.commit}.git"
        or record.source_digest != source_digest(record.commit, record.tree)
    ):
        raise _bad("invalid exact source identity")
    _private_dir(scratch.parent, scratch.name, create=False)
    return time.monotonic() + _TIMEOUT


def _git(scratch: Path, deadline: float, args: list[str], **kwargs) -> bytes:
    policy = FetchPolicy()
    env = {
        **git_env(policy, scratch),
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CEILING_DIRECTORIES": str(scratch.parent),
    }
    return run_git(
        policy,
        args,
        label="repository object transfer",
        env=env,
        spool=scratch,
        cwd=scratch,
        timeout_s=_remaining(deadline),
        address_space=768 * 2**20,
        stderr_bytes=0,
        **kwargs,
    )


def _init(store: Path, record: SourceRecord, scratch: Path, deadline: float) -> None:
    _git(
        scratch,
        deadline,
        ["init", "--bare", "--quiet", "--object-format=sha1", "--template=", str(store)],
    )
    _write_private(store / "shallow", f"{record.commit}\n")


@contextmanager
def _object_directory(path: Path | str, parent: int | None = None):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise _bad("unsafe retained object directory")
        yield fd
    finally:
        os.close(fd)


def _copy_retained_objects(source: Path, dest: Path, deadline: float) -> None:
    """Copy Git object files from pinned directories into a clean repository."""
    remaining = FetchLimits().max_bytes
    count = 0
    with (
        _object_directory(source) as root,
        _object_directory("objects", root) as objects,
        os.scandir(objects) as directories,
    ):
        for entry in directories:
            _remaining(deadline)
            if entry.name == "pack":
                pattern = _PACK_FILE
            elif re.fullmatch(r"[0-9a-f]{2}", entry.name):
                pattern = re.compile(r"[0-9a-f]{38}")
                (dest / entry.name).mkdir(mode=0o700)
            else:
                continue
            with (
                _object_directory(entry.name, objects) as directory,
                os.scandir(directory) as files,
            ):
                for item in files:
                    _remaining(deadline)
                    if entry.name == "pack" and item.name.endswith(".promisor"):
                        raise _bad("promisor packs are unsupported")
                    if not pattern.fullmatch(item.name):
                        continue
                    count += 1
                    if count > 8192:
                        raise _bad("retained object count exceeds its limit")
                    remaining -= _copy_object_file(
                        directory, item.name, dest / entry.name, remaining, deadline
                    )


def _copy_object_file(directory: int, name: str, dest: Path, limit: int, deadline: float) -> int:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o022
            or info.st_nlink != 1
            or info.st_size > limit
        ):
            raise _bad("unsafe or oversized retained object file")
        with (dest / name).open("xb") as target:
            remaining = info.st_size
            while remaining:
                _remaining(deadline)
                data = source.read(min(remaining, _CHUNK))
                if not data:
                    raise _bad("retained object file was truncated")
                target.write(data)
                remaining -= len(data)
        if source.read(1) or os.fstat(fd).st_ctime_ns != info.st_ctime_ns:
            raise _bad("retained object file changed during copy")
    return info.st_size


def _object_header(handle, pack_hash, remaining_bytes: int) -> tuple[int, int]:
    header = handle.read(1)
    if not header:
        raise _bad("missing pack object")
    first = header[0]
    kind, size, shift = (first >> 4) & 7, first & 15, 4
    while header[-1] & 128:
        byte = handle.read(1)
        if not byte or shift > 25:
            raise _bad("invalid pack object size")
        header += byte
        size |= (byte[0] & 127) << shift
        shift += 7
    if kind not in _TYPE or size > remaining_bytes:
        raise _bad("unsupported pack object type or expanded size")
    pack_hash.update(header)
    return kind, size


def _read_object(handle, pack_hash, kind: int, size: int, deadline: float):
    # A Git object ID covers its header as well as its raw payload.
    oid = hashlib.sha1(_TYPE[kind] + b" " + str(size).encode() + b"\0", usedforsecurity=False)
    inflate = zlib.decompressobj()
    keep_payload = kind != 3 or size <= MAX_SOURCE_LINK_BYTES
    payload = bytearray()
    produced = 0
    while not inflate.eof:
        _remaining(deadline)
        data = handle.peek(_CHUNK)[:_CHUNK]
        if not data:
            raise _bad("truncated object stream")
        try:
            chunk = inflate.decompress(data, min(_CHUNK, size - produced + 1))
        except zlib.error:
            raise _bad("invalid compressed object stream") from None
        consumed = len(data) - len(inflate.unused_data or inflate.unconsumed_tail)
        if consumed == 0 and not chunk:
            raise _bad("stalled object stream")
        pack_hash.update(handle.read(consumed))
        produced += len(chunk)
        if produced > size:
            raise _bad("expanded object exceeds declared size")
        oid.update(chunk)
        if keep_payload:
            payload.extend(chunk)
    if produced != size:
        raise _bad("expanded object does not match declared size")
    return oid.digest(), bytes(payload)


def _read_pack(pack: Path, deadline: float) -> dict[bytes, tuple[int, int, bytes]]:
    objects = {}
    fd = os.open(pack, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb", buffering=_CHUNK) as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or not 32 <= info.st_size <= MAX_PACK_BYTES:
            raise _bad("pack type or size is outside limits")
        header = handle.read(12)
        if len(header) != 12:
            raise _bad("truncated pack header")
        magic, version, count = struct.unpack(">4sII", header)
        if magic != b"PACK" or version not in (2, 3) or not 1 <= count <= _MAX_OBJECTS:
            raise _bad("invalid pack header or object count")
        digest = hashlib.sha1(header, usedforsecurity=False)
        expanded = metadata = 0
        for _ in range(count):
            kind, size = _object_header(handle, digest, _MAX_EXPANDED_BYTES - expanded)
            expanded += size
            if kind != 3:
                metadata += size
                if metadata > _MAX_METADATA_BYTES:
                    raise _bad("pack metadata exceeds its size limit")
            oid, payload = _read_object(handle, digest, kind, size, deadline)
            if oid in objects:
                raise _bad("pack contains duplicate objects")
            objects[oid] = kind, size, payload
        if handle.read(20) != digest.digest() or handle.read(1):
            raise _bad("invalid pack checksum or trailing data")
    return objects


def _tree_entries(tree: bytes):
    offset = 0
    seen = set()
    while offset < len(tree):
        # Bound delimiter searches before slicing untrusted metadata.
        space = tree.find(b" ", offset, offset + 7)
        end = tree.find(b"\0", space + 1, space + 257) if space >= 0 else -1
        if end < 0 or end + 21 > len(tree):
            raise _bad("invalid tree entry")
        mode, name = tree[offset:space], tree[space + 1 : end]
        if (
            mode not in _MODES
            or name.lower() in (b"", b".", b"..", b".git")
            or name in seen
            or b"/" in name
            or any(c < 32 or c == 127 for c in name)
        ):
            raise _bad("unsafe tree entry")
        try:
            name.decode("utf-8")
        except UnicodeDecodeError:
            raise _bad("non-UTF-8 source path") from None
        seen.add(name)
        yield mode, name, tree[end + 1 : end + 21]
        offset = end + 21


def _verify(pack: Path, record: SourceRecord, deadline: float) -> None:
    objects = _read_pack(pack, deadline)
    commit, tree = bytes.fromhex(record.commit), bytes.fromhex(record.tree)
    top = objects.get(commit)
    if top is None or top[0] != 1 or not top[2].startswith(b"tree " + tree.hex().encode() + b"\n"):
        raise _bad("pack does not bind the exact commit to its recorded tree")
    visited = {commit}
    stack = [(b"", tree, 0)]
    links = {}
    entries = files = source_bytes = listing_bytes = 0
    while stack:
        _remaining(deadline)
        parent, oid, depth = stack.pop()
        obj = objects.get(oid)
        if obj is None or obj[0] != 2 or depth > _MAX_TREE_DEPTH:
            raise _bad("missing, invalid or deeply nested tree")
        visited.add(oid)
        for mode, name, child in _tree_entries(obj[2]):
            entries += 1
            path = parent + name
            if entries > _MAX_ENTRIES or len(path) > _MAX_PATH_BYTES:
                raise _bad("expanded tree exceeds path or entry limits")
            value = objects.get(child)
            if value is None or value[0] != _MODES[mode]:
                raise _bad("tree has a missing object or an invalid object type")
            if mode == b"40000":
                stack.append((path + b"/", child, depth + 1))
                continue
            visited.add(child)
            files += 1
            source_bytes += value[1]
            # Match ls-tree -r -l -z: mode, type, hex OID, padded size, path and NUL.
            listing_bytes += 55 + max(7, len(str(value[1]))) + len(path)
            if (
                files > _LIMITS.source_files
                or source_bytes > _LIMITS.source_bytes
                or listing_bytes > MAX_SOURCE_LISTING_BYTES
            ):
                raise _bad("expanded source exceeds build limits")
            if mode == b"120000":
                rel = path.decode("utf-8")
                try:
                    links[rel] = source_link(rel, value[2])
                except BuildError as exc:
                    raise _bad("unsafe source symlink") from exc
    if visited != objects.keys():
        raise _bad("pack contains objects outside the exact source closure")
    try:
        check_source_links(links, deadline)
    except BuildError as exc:
        raise FetchError(exc.code, "source symlink preflight failed") from exc


def _install(pack: Path, record: SourceRecord, store: Path, scratch: Path, deadline: float) -> None:
    store.mkdir(mode=0o700)
    try:
        _init(store, record, scratch, deadline)
        (store / FETCH_REF).parent.mkdir(mode=0o700)
        _write_private(store / FETCH_REF, f"{record.commit}\n")
        _git(
            scratch,
            deadline,
            [
                "--git-dir",
                str(store),
                "index-pack",
                "--stdin",
                "--no-rev-index",
                "--threads=1",
                f"--max-input-size={MAX_PACK_BYTES}",
            ],
            stdin_path=pack,
            watch=store,
            max_bytes=MAX_PACK_BYTES + 2**20,
        )
        _git(
            scratch,
            deadline,
            [
                "--git-dir",
                str(store),
                "fsck",
                "--full",
                "--strict",
                "--no-reflogs",
                "--no-dangling",
                record.commit,
            ],
        )
    except BaseException:
        shutil.rmtree(store)
        raise


def stage_pack(store: Path, record: SourceRecord, pack: Path, scratch: Path) -> None:
    """Stage a verified no-delta SHA-1 pack at a new path under private custody.

    Run as the W37 store owner after verifying the retained receipt and scope.
    Scratch must be an existing private directory. The caller seals the result.
    """
    deadline = _check_inputs(record, scratch)
    store = store.absolute()
    _private_dir(store.parent, store.name, create=False)
    _check_retained_store(store, FetchLimits().max_bytes)
    with tempfile.TemporaryDirectory(dir=scratch.absolute()) as work:
        private = Path(work)
        bare = private / "source.git"
        _init(bare, record, private, deadline)
        _copy_retained_objects(store, bare / "objects", deadline)
        revision = private / "revision"
        revision.write_text(f"{record.commit}\n", encoding="ascii")
        candidate = private / "source.pack"
        _git(
            private,
            deadline,
            [
                "--git-dir",
                str(bare),
                "pack-objects",
                "--stdout",
                "--revs",
                "--window=0",
                "--no-reuse-object",
                "--no-reuse-delta",
                "--no-use-bitmap-index",
                "--threads=1",
            ],
            stdin_path=revision,
            stdout_path=candidate,
            max_stdout=MAX_PACK_BYTES,
        )
        _verify(candidate, record, deadline)
        shutil.rmtree(bare)
        _install(candidate, record, bare, private, deadline)
        shutil.rmtree(bare)
        _remaining(deadline)
        fd = os.open(pack, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as target, candidate.open("rb") as source:
                while chunk := source.read(_CHUNK):
                    _remaining(deadline)
                    target.write(chunk)
        except BaseException:
            pack.unlink()
            raise


def import_pack(pack: Path, record: SourceRecord, store: Path, scratch: Path) -> None:
    """Verify a sealed pack and create a bare store for proposal and build reuse/export.

    Run as the destination owner. The pack and the new store path must be under
    private, validated ancestors, and scratch must be an existing private directory.
    The caller provides the matching source receipt in the fetch-root layout.
    """
    deadline = _check_inputs(record, scratch)
    pack, store = pack.absolute(), store.absolute()
    _verify(pack, record, deadline)
    with tempfile.TemporaryDirectory(dir=scratch.absolute()) as work:
        _install(pack, record, store, Path(work), deadline)
