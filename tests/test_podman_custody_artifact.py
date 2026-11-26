"""Negative admission checks for the experimental Podman artifact."""

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

VERIFIER = Path(__file__).parent / "integration/podman_custody/verify.py"
SPEC = importlib.util.spec_from_file_location("custody_verify_test", VERIFIER)
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


def test_probe_hooks_are_readable_under_restrictive_umask(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "verify", verify)
    spec = importlib.util.spec_from_file_location(
        "custody_probe_test", VERIFIER.with_name("probe.py")
    )
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)

    root = tmp_path / "fixture"
    root.mkdir()
    owner = root.stat()
    previous_umask = os.umask(0o077)
    try:
        probe.Fixture(root, os.geteuid(), os.getegid(), "fixture", None)
    finally:
        os.umask(previous_umask)

    hooks = root / "hooks"
    assert stat.S_IMODE(root.stat().st_mode) == 0o711
    hooks_info = hooks.stat()
    assert stat.S_IMODE(hooks_info.st_mode) == 0o755
    assert (hooks_info.st_uid, hooks_info.st_gid) == (owner.st_uid, owner.st_gid)
    assert not list(hooks.iterdir())


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    build_input = tmp_path / "build-input"
    build_input.write_text("fixture patch")
    monkeypatch.setattr(verify, "PATCH", build_input)
    docs_input = tmp_path / "docs-input"
    docs_input.write_text("fixture documentation patch")
    monkeypatch.setattr(verify, "DOCS_PATCH", docs_input)
    real_fstat = os.fstat
    ancestors = {(path.stat().st_dev, path.stat().st_ino) for path in tmp_path.parents}
    foreign = set()

    def fstat(fd):
        info = real_fstat(fd)
        identity = info.st_dev, info.st_ino
        return SimpleNamespace(
            st_uid=1000 if identity in foreign else 0,
            st_mode=info.st_mode if identity not in ancestors else info.st_mode & ~0o022,
            st_nlink=info.st_nlink,
        )

    monkeypatch.setattr(
        verify, "os", SimpleNamespace(**(vars(os) | {"fstat": fstat, "geteuid": lambda: 0}))
    )
    lock = verify.load_lock()
    artifact_dir = tmp_path / "bundle"
    artifact_dir.mkdir(mode=0o755)
    executable = artifact_dir / verify.BINARY_NAME
    executable.write_bytes(b"\x7fELF\x02\x01\x01" + bytes(11) + b"\x3e\x00" + b"fixture")
    executable.chmod(0o755)
    buildinfo = artifact_dir / verify.BUILDINFO_NAME
    buildinfo.write_text("Installed-Build-Depends: golang-go (= 1.25)\n")
    buildinfo.chmod(0o644)
    manifest = {
        "schema": 1,
        "protocol": verify.PROTOCOL,
        "profile": lock["profile"],
        "package": lock["package"],
        "version": lock["version"],
        "architecture": lock["architecture"],
        "runtime": lock["runtime"],
        "builder": verify.BUILDER,
        "build_isolation": verify.BUILD_ISOLATION,
        "build_options": verify.BUILD_OPTIONS,
        **verify.input_hashes(),
        "binary_sha256": verify.file_hash(executable),
        "buildinfo_sha256": verify.file_hash(buildinfo),
    }
    return artifact_dir, manifest, foreign


def _verify(bundle):
    directory, manifest, _foreign = bundle
    file = directory / verify.MANIFEST_NAME
    file.write_text(json.dumps(manifest))
    file.chmod(0o644)
    return verify.verify_bundle(directory, verify.file_hash(file), verify.load_lock()["profile"])


def test_verified_descriptor_retains_original_inode(bundle):
    directory, _manifest, _foreign = bundle
    fd = _verify(bundle)
    try:
        binary = directory / verify.BINARY_NAME
        original = binary.read_bytes()
        binary.rename(directory / "original")
        binary.write_bytes(b"replacement")
        with os.fdopen(os.dup(fd), "rb") as stream:
            assert stream.read() == original
        assert not os.get_inheritable(fd)
    finally:
        os.close(fd)


@pytest.mark.parametrize("digest", [None, "", "bad", "a" * 64])
def test_requires_independently_pinned_manifest(bundle, digest):
    directory, _manifest, _foreign = bundle
    os.close(_verify(bundle))
    with pytest.raises(verify.VerificationError, match="manifest"):
        verify.verify_bundle(directory, digest, verify.load_lock()["profile"])


def test_requires_pinned_profile(bundle):
    directory, _manifest, _foreign = bundle
    os.close(_verify(bundle))
    manifest_file = directory / verify.MANIFEST_NAME
    with pytest.raises(verify.VerificationError, match="profile"):
        verify.verify_bundle(directory, verify.file_hash(manifest_file), "unsupported")


@pytest.mark.parametrize(
    "field", ["architecture", "version", "runtime", "builder", "binary_sha256", "docs_patch_sha256"]
)
def test_manifest_rejects_unbound_or_invalid_metadata(bundle, field):
    _directory, manifest, _foreign = bundle
    manifest[field] = "wrong"
    with pytest.raises(verify.VerificationError, match="unbound"):
        _verify(bundle)


@pytest.mark.parametrize("patch_attribute", ["PATCH", "DOCS_PATCH"])
def test_rejects_changed_patch(bundle, patch_attribute):
    getattr(verify, patch_attribute).write_text("new patch contents")
    with pytest.raises(verify.VerificationError, match="unbound"):
        _verify(bundle)


def test_rejects_missing_docs_patch_binding(bundle):
    _directory, manifest, _foreign = bundle
    del manifest["docs_patch_sha256"]
    with pytest.raises(verify.VerificationError, match="unbound"):
        _verify(bundle)


@pytest.mark.parametrize("name", [verify.MANIFEST_NAME, verify.BINARY_NAME, verify.BUILDINFO_NAME])
@pytest.mark.parametrize("mutation", ["symlink", "hardlink", "foreign", "writable", "setuid"])
def test_rejects_unsafe_bundle_files(bundle, name, mutation):
    directory, _manifest, foreign = bundle
    os.close(_verify(bundle))
    file = directory / name
    if mutation == "symlink":
        target = file.rename(directory / "target")
        file.symlink_to(target)
    elif mutation == "hardlink":
        (directory / "target").hardlink_to(file)
    elif mutation == "foreign":
        info = file.stat()
        foreign.add((info.st_dev, info.st_ino))
    elif mutation == "writable":
        file.chmod(0o775)
    else:
        file.chmod(0o4755)
    with pytest.raises(verify.VerificationError):
        verify.verify_bundle(
            directory,
            verify.file_hash(directory / verify.MANIFEST_NAME),
            verify.load_lock()["profile"],
        )


@pytest.mark.parametrize("mutation", ["symlink", "foreign", "writable"])
def test_rejects_unsafe_ancestors(bundle, tmp_path, mutation):
    directory, _manifest, foreign = bundle
    os.close(_verify(bundle))
    if mutation == "symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(directory, target_is_directory=True)
        directory = alias
    elif mutation == "foreign":
        info = tmp_path.stat()
        foreign.add((info.st_dev, info.st_ino))
    else:
        tmp_path.chmod(0o777)
    with pytest.raises(verify.VerificationError):
        verify.verify_bundle(
            directory,
            verify.file_hash(directory / verify.MANIFEST_NAME),
            verify.load_lock()["profile"],
        )


@pytest.mark.parametrize("name", [verify.BINARY_NAME, verify.BUILDINFO_NAME])
def test_rejects_modified_artifact(bundle, name):
    directory, _manifest, _foreign = bundle
    os.close(_verify(bundle))
    with (directory / name).open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(verify.VerificationError, match="does not match"):
        _verify(bundle)


def test_rejects_executable_file_capabilities(bundle, monkeypatch):
    def capability(_fd, _name):
        return b"present"

    monkeypatch.setattr(verify.os, "getxattr", capability)
    with pytest.raises(verify.VerificationError, match="file capabilities"):
        _verify(bundle)


@pytest.mark.parametrize("data", ['{"schema": 1, "schema": 1}', '{"schema":'])
def test_rejects_malformed_manifest(bundle, data):
    directory, _manifest, _foreign = bundle
    file = directory / verify.MANIFEST_NAME
    file.write_text(data)
    file.chmod(0o644)
    with pytest.raises(verify.VerificationError):
        verify.verify_bundle(directory, verify.file_hash(file), verify.load_lock()["profile"])
