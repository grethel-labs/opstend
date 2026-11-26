"""L09 archive core: write, verify, release and restore with real files.

Ownership uses the test process's own UID/GID (no root here), so restore runs
through the `owner_of` seam; everything else is the production code path.
"""

import errno
import hashlib
import os
import re
import shutil
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from steward.core import app_archive as archive
from steward.core.backups import BackupError
from steward.core.ids import graph_identifier
from steward.core.render import image_tag

IMAGE = "docker.io/library/python@sha256:" + "a" * 64
OPERATION = "1" * 32
APPLIED, DESIRED = "a" * 64, "b" * 64
MINE = (os.geteuid(), os.getegid())


def identity(number):
    return {
        "uid": 31000 + number,
        "gid": 31000 + number,
        "subuid": [400000 + number * 65536, 65536],
        "subgid": [400000 + number * 65536, 65536],
    }


@pytest.fixture
def world(tmp_path):
    root = tmp_path / "archive"
    root.mkdir(mode=0o700)
    data_root = tmp_path / "applications" / "shop" / "data"
    data_root.mkdir(parents=True, mode=0o755)
    cache = tmp_path / "images"
    cache.mkdir(mode=0o755)
    inputs = []
    for number, name in enumerate(("database", "backend")):
        stem = graph_identifier("s", "shop", name)
        tag = image_tag(stem, IMAGE)
        source = None
        if name == "database":
            source = data_root / name
            source.mkdir(mode=0o700)
            (source / "value.txt").write_text("precious")
            (source / "value.txt").chmod(0o644)
            (source / "nested").mkdir(mode=0o755)
            (source / "nested").chmod(0o755)
            (source / "nested" / "blob.bin").write_bytes(b"\x00\x01" * 100)
            (source / "nested" / "blob.bin").chmod(0o644)
        cached = cache / archive.image_cache_name(IMAGE, tag)
        cached.write_bytes(b"image-" + name.encode())
        cached.chmod(0o644)
        inputs.append(
            archive.ServiceInput(
                service=name,
                user="stw-" + stem,
                unit=stem + ".service",
                identity=identity(number),
                image=IMAGE,
                image_tag=tag,
                source_revision="bundled:test@1",
                data_source=source,
            )
        )
    return SimpleNamespace(root=root, data=data_root, cache=cache, inputs=inputs, tmp=tmp_path)


def build(world, *, operation=OPERATION, verify=True):
    state = archive.start_operation(
        world.root, "shop", operation, applied_revision=APPLIED, desired_revision=DESIRED
    )
    path = world.root / "shop" / operation
    manifest = archive.write_archive(
        path,
        state,
        server="test-server",
        services=world.inputs,
        image_cache=world.cache,
        is_quiescent=lambda: True,
        max_data_bytes=1024 * 1024,
    )
    state = archive.advance(world.root, state, "archived", manifest_id=manifest.id)
    if verify:
        archive.verify_archive(path, expected_id=manifest.id)
        state = archive.advance(world.root, state, "verified")
    return state, manifest, path


def reactivation(world, **overrides):
    services = {
        item.service: archive.ReactivationService(
            user=item.user,
            identity=item.identity,
            data_source=item.data_source,
            image=item.image,
            image_tag=item.image_tag,
        )
        for item in world.inputs
    }
    services.update(overrides.pop("services", {}))
    options = {
        "services": services,
        "isolation": "separate",
        "image_cache": world.cache,
        "check_identity": lambda user, ident: None,
        "owner_of": lambda ident: MINE,
    }
    options.update(overrides)
    return archive.reactivate(world.root, "shop", **options)


def release_all(world, state):
    state = archive.advance(
        world.root, state, "releasing", released={"database": "pending", "backend": "pending"}
    )
    for item in world.inputs:
        if item.data_source is not None:
            state = archive.advance(
                world.root, state, released={**state.released, item.service: "moved"}
            )
            archive.release_data(world.data, state.operation_id, item.service)
            state = archive.advance(
                world.root, state, released={**state.released, item.service: "deleted"}
            )
    for item in world.inputs:
        archive.release_image_cache(
            world.cache,
            archive.ArchiveManifest.model_validate_json(
                (world.root / "shop" / state.operation_id / "manifest.json").read_text()
            )
            .services[item.service]
            .image_copy,
        )
    return archive.advance(world.root, state, "released")


def test_archive_binds_exact_data_and_images_and_verifies_by_rereading(world):
    state, manifest, path = build(world)
    assert state.phase == "verified" and state.manifest_id == manifest.id
    database = manifest.services["database"]
    assert database.data.entries == 3 and database.data_source == str(world.data / "database")
    assert database.image_copy.cache_name == archive.image_cache_name(IMAGE, database.image_tag)
    assert manifest.services["backend"].data is None
    assert {item.name for item in path.iterdir()} == {
        "manifest.json",
        "state.json",
        "data",
        "images",
    }
    assert path.stat().st_mode & 0o777 == 0o700
    assert (path / "manifest.json").stat().st_mode & 0o777 == 0o600
    assert archive.verify_archive(path, expected_id=manifest.id) == manifest
    # The cache name pins ansible's `[ref, tag] | to_json | hash('sha256')`.
    expected = hashlib.sha256(f'["{IMAGE}", "{database.image_tag}"]'.encode()).hexdigest() + ".tar"
    assert database.image_copy.cache_name == expected
    # Working data was only read.
    assert (world.data / "database" / "value.txt").read_text() == "precious"


@pytest.mark.parametrize(
    "tamper",
    [
        lambda p: (p / "data" / "database" / "data.tar").write_bytes(b"x" * 10),
        lambda p: (p / "images" / "backend.tar").write_bytes(b"other"),
        lambda p: (p / "manifest.json").write_text("{}"),
        lambda p: (p / "images" / "extra.tar").write_bytes(b"1"),
        lambda p: (p / "data" / "stray").mkdir(),
        lambda p: (p / "data" / "database" / "data.tar").chmod(0o644),
        lambda p: os.unlink(p / "images" / "backend.tar"),
        lambda p: os.link(p / "manifest.json", p / "manifest.link"),
    ],
)
def test_corrupt_archive_never_verifies(world, tamper):
    _, manifest, path = build(world, verify=False)
    tamper(path)
    with pytest.raises(BackupError):
        archive.verify_archive(path, expected_id=manifest.id)


def test_flipped_bit_in_data_tar_is_detected(world):
    _, manifest, path = build(world, verify=False)
    target = path / "data" / "database" / "data.tar"
    raw = bytearray(target.read_bytes())
    raw[len(raw) // 2] ^= 1
    target.write_bytes(bytes(raw))
    with pytest.raises(BackupError) as error:
        archive.verify_archive(path, expected_id=manifest.id)
    assert error.value.error_class in ("evidence_mismatch", "invalid_archive")
    with pytest.raises(BackupError):
        archive.verify_archive(path, expected_id="c" * 64)


def test_full_disk_is_refused_before_any_copy_and_leaves_no_partial_archive(world, monkeypatch):
    state = archive.start_operation(
        world.root, "shop", OPERATION, applied_revision=APPLIED, desired_revision=DESIRED
    )
    path = world.root / "shop" / OPERATION
    monkeypatch.setattr(
        archive.shutil, "disk_usage", lambda _p: SimpleNamespace(total=1, used=1, free=1024)
    )
    with pytest.raises(BackupError) as error:
        archive.write_archive(
            path,
            state,
            server="test-server",
            services=world.inputs,
            image_cache=world.cache,
            is_quiescent=lambda: True,
            max_data_bytes=1024 * 1024,
        )
    assert error.value.error_class == "insufficient_space"
    assert {item.name for item in path.iterdir()} == {"state.json"}
    failed = archive.discard_unverified(world.root, state, error.value.error_class)
    assert failed.phase == "failed" and archive.active_operation(world.root, "shop") is None
    assert (world.data / "database" / "value.txt").read_text() == "precious"


def test_disk_filling_during_the_copy_discards_the_partial_output(world, monkeypatch):
    state = archive.start_operation(
        world.root, "shop", OPERATION, applied_revision=APPLIED, desired_revision=DESIRED
    )
    path = world.root / "shop" / OPERATION
    real = archive.capture_files

    def fill(*args, **kwargs):
        real(*args, **kwargs)
        raise BackupError("capture_failed")

    monkeypatch.setattr(archive, "capture_files", fill)
    with pytest.raises(BackupError):
        archive.write_archive(
            path,
            state,
            server="test-server",
            services=world.inputs,
            image_cache=world.cache,
            is_quiescent=lambda: True,
            max_data_bytes=1024 * 1024,
        )
    assert (path / "data" / "database" / "data.tar").exists()  # partial output exists...
    archive.discard_unverified(world.root, state, "capture_failed")
    assert {item.name for item in path.iterdir()} == {
        "state.json"
    }  # ...and is the only thing removed
    assert (world.data / "database" / "value.txt").read_text() == "precious"


def test_image_copy_write_error_is_a_stable_failure(world, monkeypatch):
    state = archive.start_operation(
        world.root, "shop", OPERATION, applied_revision=APPLIED, desired_revision=DESIRED
    )
    original = Path.open

    def failing(self, *args, **kwargs):
        if self.parent.name == "images":
            raise OSError(errno.ENOSPC, "No space left on device")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing)
    with pytest.raises(BackupError) as error:
        archive.write_archive(
            world.root / "shop" / OPERATION,
            state,
            server="test-server",
            services=world.inputs,
            image_cache=world.cache,
            is_quiescent=lambda: True,
            max_data_bytes=1024 * 1024,
        )
    assert error.value.error_class == "capture_failed"


def test_data_over_the_limit_or_unsafe_trees_are_refused(world):
    state = archive.start_operation(
        world.root, "shop", OPERATION, applied_revision=APPLIED, desired_revision=DESIRED
    )
    args = dict(
        server="test-server",
        services=world.inputs,
        image_cache=world.cache,
        is_quiescent=lambda: True,
    )
    path = world.root / "shop" / OPERATION
    with pytest.raises(BackupError):
        archive.write_archive(path, state, max_data_bytes=10, **args)
    (world.data / "database" / "link").symlink_to("/etc/passwd")
    with pytest.raises(BackupError):
        archive.write_archive(path, state, max_data_bytes=1024 * 1024, **args)
    with pytest.raises(BackupError):
        archive.write_archive(
            path,
            state,
            max_data_bytes=1024 * 1024,
            **{**args, "is_quiescent": lambda: False},
        )


def test_verified_archives_cannot_be_discarded_by_any_function(world):
    state, manifest, path = build(world)
    assert not [
        name
        for name in dir(archive)
        if re.search(r"delete|purge|wipe|erase|prune|destroy", name, re.I)
    ]
    with pytest.raises(BackupError) as error:
        archive.discard_unverified(world.root, state, "x")
    assert error.value.error_class == "state_conflict"
    state = release_all(world, state)
    for phase_state in (state,):
        with pytest.raises(BackupError):
            archive.discard_unverified(world.root, phase_state, "x")
    assert archive.verify_archive(path, expected_id=manifest.id) == manifest
    assert not (world.data / "database").exists()


def test_journal_only_allows_declared_transitions_and_detects_tampering(world):
    state = archive.start_operation(
        world.root, "shop", OPERATION, applied_revision=APPLIED, desired_revision=DESIRED
    )
    for phase in ("verified", "released", "reactivated"):
        with pytest.raises(BackupError) as error:
            archive.advance(world.root, state, phase)
        assert error.value.error_class == "state_conflict"
    with pytest.raises(BackupError):
        archive.start_operation(
            world.root, "shop", "2" * 32, applied_revision=APPLIED, desired_revision=DESIRED
        )
    stale = state
    state = archive.advance(world.root, state, "archived", manifest_id="d" * 64)
    with pytest.raises(BackupError):
        archive.advance(world.root, stale, "failed")
    (world.root / "shop" / OPERATION / "state.json").write_text('{"v": 1}')
    with pytest.raises(BackupError):
        archive.operations(world.root, "shop")
    (world.root / "shop" / "stray").mkdir()
    with pytest.raises(BackupError):
        archive.operations(world.root, "shop")


def test_archive_root_must_be_private_and_owned(world):
    world.root.chmod(0o755)
    with pytest.raises(BackupError) as error:
        archive.application_directory(world.root, "shop", create=True)
    assert error.value.error_class == "unsafe_archive"
    world.root.chmod(0o700)
    with pytest.raises(BackupError):
        archive.application_directory(world.root, "../shop")


def test_release_is_interruption_safe_and_restore_finishes_it(world, monkeypatch):
    state, manifest, path = build(world)
    state = archive.advance(
        world.root, state, "releasing", released={"database": "pending", "backend": "pending"}
    )
    state = archive.advance(world.root, state, released={**state.released, "database": "moved"})
    rmtree = shutil.rmtree

    def crash(*_a, **_k):
        raise KeyboardInterrupt

    monkeypatch.setattr(archive.shutil, "rmtree", crash)
    with pytest.raises(KeyboardInterrupt):
        archive.release_data(world.data, OPERATION, "database")
    monkeypatch.setattr(archive.shutil, "rmtree", rmtree)
    leftover = world.data / archive.retired_name(OPERATION, "database")
    assert leftover.is_dir() and not (world.data / "database").exists()
    # Re-addition before the release finished: the layout step prepares an empty directory.
    (world.data / "database").mkdir(mode=0o700)
    result = reactivation(world)
    assert result["state"] == "reactivated" and result["restored"] == ["database"]
    assert not leftover.exists()
    assert (world.data / "database" / "value.txt").read_text() == "precious"
    assert (world.data / "database" / "nested" / "blob.bin").read_bytes() == b"\x00\x01" * 100
    assert archive.verify_archive(path, expected_id=manifest.id) == manifest


def test_release_retries_after_rename_and_refuses_ambiguous_leftovers(world):
    state, _manifest, _path = build(world)
    live, leftover = (
        world.data / "database",
        world.data / archive.retired_name(OPERATION, "database"),
    )
    live.rename(leftover)
    assert archive.release_data(world.data, OPERATION, "database") == "deleted"
    assert not leftover.exists() and not live.exists()
    assert archive.release_data(world.data, OPERATION, "database") == "deleted"
    live.mkdir()
    leftover.mkdir()
    with pytest.raises(BackupError) as error:
        archive.release_data(world.data, OPERATION, "database")
    assert error.value.error_class == "state_conflict"
    assert state.phase == "verified"


def test_reactivation_restores_released_data_images_and_identity(world):
    state, manifest, path = build(world)
    release_all(world, state)
    assert not (world.data / "database").exists() and not list(world.cache.iterdir())
    (world.data / "database").mkdir(mode=0o700)  # what the layout step prepares
    result = reactivation(world)
    assert result == {
        "changed": True,
        "state": "reactivated",
        "operation": OPERATION,
        "restored": ["database"],
        "kept": [],
    }
    assert (world.data / "database" / "value.txt").read_text() == "precious"
    assert stat_mode(world.data / "database") == 0o700
    for item in world.inputs:
        name = archive.image_cache_name(item.image, item.image_tag)
        assert (world.cache / name).read_bytes() == b"image-" + item.service.encode()
        assert stat_mode(world.cache / name) == 0o644
    assert archive.operations(world.root, "shop")[0].phase == "reactivated"
    assert reactivation(world) == {"changed": False, "state": "none"}
    assert archive.verify_archive(path, expected_id=manifest.id) == manifest  # archive is kept


def stat_mode(path):
    return path.stat().st_mode & 0o777


def test_corrupt_archive_blocks_reactivation_without_touching_anything(world):
    state, _manifest, path = build(world)
    release_all(world, state)
    (world.data / "database").mkdir(mode=0o700)
    (path / "data" / "database" / "data.tar").write_bytes(b"broken")
    with pytest.raises(BackupError):
        reactivation(world)
    assert list((world.data / "database").iterdir()) == []
    assert archive.active_operation(world.root, "shop").phase == "released"
    assert not any(world.cache.iterdir())


def test_changed_uid_or_binding_blocks_reactivation(world):
    state, _manifest, _path = build(world)
    release_all(world, state)
    (world.data / "database").mkdir(mode=0o700)
    services = reactivation_services(world)
    services["database"] = services["database"].__class__(
        user=services["database"].user,
        identity={**identity(0), "uid": 31999},
        data_source=services["database"].data_source,
        image=IMAGE,
        image_tag=services["database"].image_tag,
    )
    with pytest.raises(BackupError) as error:
        reactivation(world, services=services)
    assert error.value.error_class == "identity_changed"

    def pinned_changed(user, ident):
        raise BackupError("identity_changed")

    with pytest.raises(BackupError) as error:
        reactivation(world, check_identity=pinned_changed)
    assert error.value.error_class == "identity_changed"
    other = dict(reactivation_services(world))
    other["database"] = other["database"].__class__(
        user=other["database"].user,
        identity=other["database"].identity,
        data_source=world.data / "elsewhere",
        image=IMAGE,
        image_tag=other["database"].image_tag,
    )
    with pytest.raises(BackupError) as error:
        reactivation(world, services=other)
    assert error.value.error_class == "binding_changed"
    del other["backend"]
    with pytest.raises(BackupError) as error:
        reactivation(world, services=other)
    assert error.value.error_class == "binding_changed"
    with pytest.raises(BackupError) as error:
        reactivation(world, isolation="shared")
    assert error.value.error_class == "shared_unavailable"
    assert archive.active_operation(world.root, "shop").phase == "released"
    assert list((world.data / "database").iterdir()) == []


def reactivation_services(world):
    return {
        item.service: archive.ReactivationService(
            user=item.user,
            identity=item.identity,
            data_source=item.data_source,
            image=item.image,
            image_tag=item.image_tag,
        )
        for item in world.inputs
    }


def test_reactivation_refuses_a_non_empty_or_unsafe_target(world):
    state, _manifest, _path = build(world)
    release_all(world, state)
    target = world.data / "database"
    target.mkdir(mode=0o700)
    (target / "someone-elses.txt").write_text("keep")
    with pytest.raises(BackupError) as error:
        reactivation(world)
    assert error.value.error_class == "target_not_empty"
    assert (target / "someone-elses.txt").read_text() == "keep"
    (target / "someone-elses.txt").unlink()
    target.chmod(0o755)
    with pytest.raises(BackupError) as error:
        reactivation(world)
    assert error.value.error_class == "unsafe_target"
    target.chmod(0o700)
    other = (os.geteuid() + 1, os.getegid())
    with pytest.raises(BackupError) as error:
        reactivation(world, owner_of=lambda ident: other)
    assert error.value.error_class == "unsafe_target"
    assert archive.active_operation(world.root, "shop").phase == "released"


def test_retirement_that_never_released_data_is_cancelled_on_readd(world):
    state, _manifest, path = build(world)
    result = reactivation(world)
    assert result["state"] == "cancelled" and result["kept"] == ["database"]
    assert (world.data / "database" / "value.txt").read_text() == "precious"
    assert archive.operations(world.root, "shop")[0].phase == "cancelled"
    assert archive.verify_archive(path, expected_id=state.manifest_id).id == state.manifest_id


def test_crash_before_release_with_changed_working_data_is_refused(world):
    build(world)
    (world.data / "database" / "value.txt").write_text("changed after the archive")
    with pytest.raises(BackupError) as error:
        reactivation(world)
    assert error.value.error_class == "source_changed"
    assert archive.active_operation(world.root, "shop").phase == "verified"


def test_intent_journaled_but_not_renamed_keeps_the_intact_tree(world):
    state, _manifest, _path = build(world)
    state = archive.advance(
        world.root, state, "releasing", released={"database": "pending", "backend": "pending"}
    )
    archive.advance(world.root, state, released={"database": "moved", "backend": "pending"})
    result = reactivation(world)
    assert result["state"] == "reactivated" and result["kept"] == ["database"]
    assert (world.data / "database" / "value.txt").read_text() == "precious"


def test_unfinished_build_is_discarded_on_readd(world):
    state = archive.start_operation(
        world.root, "shop", OPERATION, applied_revision=APPLIED, desired_revision=DESIRED
    )
    (world.root / "shop" / OPERATION / "data").mkdir()
    result = reactivation(world)
    assert result["state"] == "cancelled"
    assert archive.operations(world.root, "shop")[0].phase == "failed"
    assert state.phase == "archiving" and (world.data / "database" / "value.txt").exists()


def test_cached_image_is_never_replaced_and_mismatch_fails_closed(world):
    state, manifest, path = build(world)
    release_all(world, state)
    (world.data / "database").mkdir(mode=0o700)
    name = manifest.services["backend"].image_copy.cache_name
    (world.cache / name).write_bytes(b"different image bytes")
    with pytest.raises(BackupError) as error:
        reactivation(world)
    assert error.value.error_class == "evidence_mismatch"
    assert (world.cache / name).read_bytes() == b"different image bytes"
    assert archive.active_operation(world.root, "shop").phase == "released"
    assert archive.verify_archive(path, expected_id=manifest.id) == manifest


def test_archive_capacity_is_bounded(world, monkeypatch):
    monkeypatch.setattr(archive, "MAX_OPERATIONS", 1)
    state, _manifest, _path = build(world)
    archive.advance(world.root, state, "cancelled")
    with pytest.raises(BackupError) as error:
        archive.start_operation(
            world.root, "shop", "2" * 32, applied_revision=APPLIED, desired_revision=DESIRED
        )
    assert error.value.error_class == "archive_capacity"


def test_restored_tar_members_are_validated_not_trusted(world, tmp_path):
    state, manifest, path = build(world, verify=False)
    tar = path / "data" / "database" / "data.tar"
    with tarfile.open(tar, "a") as handle:
        info = tarfile.TarInfo("../escape")
        info.size = 0
        handle.addfile(info)
    with pytest.raises(BackupError):
        archive.verify_archive(path, expected_id=manifest.id)
    assert not (tmp_path / "escape").exists() and state.phase == "archived"
