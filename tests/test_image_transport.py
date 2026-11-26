"""Exercise image transport with synthetic archives and focused Podman fakes."""

import hashlib
import io
import json
import os
import tarfile
from types import SimpleNamespace

import pytest

from steward.core import image_transport as transport

REF = "docker.io/filebrowser/filebrowser@sha256:" + "a" * 64
TAG = "localhost/steward/filebrowser:sha256-" + "b" * 32
HEALTHCHECK = {"Test": ["CMD-SHELL", "/healthcheck.sh"]}
CONFIG = json.dumps({"config": {"Healthcheck": HEALTHCHECK}}).encode()
LEGACY_CONFIG = b'{"config":{}}'
IMAGE_ID = "sha256:" + hashlib.sha256(CONFIG).hexdigest()
LEGACY_ID = "sha256:" + hashlib.sha256(LEGACY_CONFIG).hexdigest()


def write_archive(path, *members):
    with tarfile.open(path, "w") as archive:
        for name, data in members:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    path.chmod(0o644)


def docker_members(config=CONFIG):
    name = hashlib.sha256(config).hexdigest() + ".json"
    manifest = {"Config": name, "RepoTags": [TAG], "Layers": []}
    return ("manifest.json", json.dumps([manifest]).encode()), (name, config)


def oci_members():
    def descriptor(payload, media_type):
        return {
            "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "mediaType": "application/vnd.oci.image." + media_type,
        }

    config = descriptor(LEGACY_CONFIG, "config.v1+json")
    manifest = json.dumps({"schemaVersion": 2, "config": config, "layers": []}).encode()
    entry = descriptor(manifest, "manifest.v1+json")
    entry["annotations"] = {transport.OCI_REF_NAME: TAG}
    index = {"schemaVersion": 2, "manifests": [entry]}
    return (
        ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
        ("index.json", json.dumps(index).encode()),
        ("blobs/sha256/" + entry["digest"][7:], manifest),
        ("blobs/sha256/" + config["digest"][7:], LEGACY_CONFIG),
    )


@pytest.fixture
def cache(tmp_path, monkeypatch):
    # Substitute only the owner of test files so the real type and mode checks run.
    protected = transport.protected
    uid = os.geteuid()

    def local_custody(info, *, directory=False):
        assert info.st_uid == uid
        protected(SimpleNamespace(st_uid=0, st_mode=info.st_mode), directory=directory)

    monkeypatch.setattr(transport, "protected", local_custody)
    path = tmp_path / ("c" * 64 + ".tar")
    return path


@pytest.mark.parametrize(
    "failure", ["partial save", "wrong config ID", "wrong format", "replace error"]
)
def test_prepare_preserves_legacy_cache_on_failure_and_retries(cache, monkeypatch, failure):
    write_archive(cache, *oci_members())
    before = cache.read_bytes()
    original_inode = cache.stat().st_ino
    seen_saves = []

    def podman(*args, **kwargs):
        if args == ("image", "exists", REF):
            assert kwargs["allow_absent"]
            return ""
        if args == ("image", "inspect", REF):
            return json.dumps(
                [
                    {
                        "Id": IMAGE_ID[7:],
                        "Digest": "sha256:" + "d" * 64,
                        "Config": {"Entrypoint": ["tini", "--", "/init.sh"]},
                        "Healthcheck": HEALTHCHECK,
                    }
                ]
            )
        if args == ("tag", REF, TAG):
            return ""
        assert args[:5] == ("save", "--quiet", "--format", "docker-archive", "--output")
        output = cache.parent / args[5]
        assert output != cache
        assert args[6:] == (TAG,)
        assert cache.read_bytes() == before
        seen_saves.append(output)
        if len(seen_saves) == 1:
            if failure == "partial save":
                output.write_bytes(b"interrupted save")
                raise transport.TransportError("save interrupted")
            if failure == "wrong config ID":
                write_archive(output, *docker_members(LEGACY_CONFIG))
                return ""
            if failure == "wrong format":
                write_archive(output, *oci_members())
                return ""
        write_archive(output, *docker_members())
        return ""

    def fail_replace(source, destination):
        assert destination == cache
        assert transport.archive_image(source, TAG) == ("docker-archive", IMAGE_ID)
        raise OSError("replace failed")

    monkeypatch.setattr(transport, "podman", podman)
    with monkeypatch.context() as attempt:
        if failure == "replace error":
            attempt.setattr(transport.os, "replace", fail_replace)
        with pytest.raises(OSError if failure == "replace error" else transport.TransportError):
            transport.prepare_archive(cache, REF, TAG)

    assert len(seen_saves) == 1
    assert list(cache.parent.iterdir()) == [cache]
    assert cache.read_bytes() == before
    assert cache.stat().st_ino == original_inode
    assert transport.prepare_archive(cache, REF, TAG) == {"changed": True, "image_id": IMAGE_ID}
    assert transport.archive_image(cache, TAG) == ("docker-archive", IMAGE_ID)
    assert list(cache.parent.iterdir()) == [cache]
    assert transport.prepare_archive(cache, REF, TAG) == {"changed": False, "image_id": IMAGE_ID}
    assert len(seen_saves) == 2


@pytest.mark.parametrize("loaded_id", [IMAGE_ID[7:], LEGACY_ID, IMAGE_ID[:19], None])
def test_reuse_offline_archive_and_verify_reloaded_tag(cache, monkeypatch, loaded_id):
    write_archive(cache, *docker_members())
    before = cache.read_bytes()
    tagged_id = LEGACY_ID
    loads = 0

    def podman(*args, **kwargs):
        nonlocal tagged_id, loads
        if args == ("image", "exists", REF):
            assert kwargs["allow_absent"]
            return None
        if args == ("image", "exists", TAG):
            assert kwargs["allow_absent"]
            return "" if tagged_id is not None else None
        if args == ("image", "inspect", "--format", "{{.ID}}", TAG):
            return tagged_id
        assert args == ("load", "--quiet", "--input", str(cache))
        loads += 1
        tagged_id = loaded_id
        return f"Loaded image: {TAG}"

    monkeypatch.setattr(transport, "podman", podman)
    assert transport.prepare_archive(cache, REF, TAG) == {"changed": False, "image_id": IMAGE_ID}
    if loaded_id == IMAGE_ID[7:]:
        assert transport.load_image(cache, TAG, IMAGE_ID) == {"changed": True}
        assert transport.load_image(cache, TAG, IMAGE_ID) == {"changed": False}
    else:
        with pytest.raises(transport.TransportError):
            transport.load_image(cache, TAG, IMAGE_ID)
    assert loads == 1
    assert cache.read_bytes() == before


@pytest.mark.parametrize(
    "problem",
    ["invalid JSON", "duplicate member", "duplicate tag", "both formats", "OCI digest mismatch"],
)
def test_archive_rejects_malformed_or_ambiguous_metadata(cache, problem):
    (manifest_name, manifest), config = docker_members()
    match problem:
        case "invalid JSON":
            members = ((manifest_name, b"["), config)
        case "duplicate member":
            members = ((manifest_name, manifest), config, ("./" + config[0], config[1]))
        case "duplicate tag":
            entries = json.loads(manifest) * 2
            members = ((manifest_name, json.dumps(entries).encode()), config)
        case "both formats":
            members = (*docker_members(), *oci_members())
        case "OCI digest mismatch":
            *metadata, (name, payload) = oci_members()
            members = (*metadata, (name, payload.replace(b"{}", b"[]")))

    write_archive(cache, *members)
    with pytest.raises(transport.TransportError):
        transport.archive_image(cache, TAG)


@pytest.mark.parametrize("problem", ["symlink", "writable archive", "writable directory"])
def test_prepare_rejects_unprotected_cache_even_with_exact_source(cache, monkeypatch, problem):
    if problem == "symlink":
        target = cache.with_name("target.tar")
        write_archive(target, *docker_members())
        cache.symlink_to(target)
    else:
        write_archive(cache, *docker_members())
        if problem == "writable archive":
            cache.chmod(0o664)
        else:
            cache.parent.chmod(0o777)

    def podman(*args, **kwargs):
        if args == ("image", "exists", REF):
            return ""
        assert args == ("image", "inspect", REF)
        return json.dumps([{"Id": IMAGE_ID, "Healthcheck": HEALTHCHECK}])

    monkeypatch.setattr(transport, "podman", podman)
    with pytest.raises(transport.TransportError):
        transport.prepare_archive(cache, REF, TAG)


def test_custody_requires_root_ownership():
    info = SimpleNamespace(st_uid=1000, st_mode=0o100644)
    with pytest.raises(transport.TransportError):
        transport.protected(info)
