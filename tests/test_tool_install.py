import bz2
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from steward.core import ollama_install
from steward.core.tool_install import install


def test_verified_executable_is_installed_atomically_and_idempotently(tmp_path):
    data = b"\x7fELF" + b"test executable bytes"
    archive = tmp_path / "archive.bz2"
    archive.write_bytes(bz2.compress(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    target = tmp_path / "restic"
    assert install(archive, target, digest)
    assert target.read_bytes() == data and target.stat().st_mode & 0o777 == 0o755
    inode = target.stat().st_ino
    assert not install(archive, target, digest)
    assert target.stat().st_ino == inode
    target.write_bytes(b"corrupted")
    assert install(archive, target, digest) and target.read_bytes() == data


def test_invalid_archive_never_replaces_existing_tool(tmp_path):
    archive = tmp_path / "archive.bz2"
    archive.write_bytes(bz2.compress(b"not an executable"))
    target = tmp_path / "restic"
    target.write_bytes(b"old executable")
    for digest in ("0" * 64, hashlib.sha256(archive.read_bytes()).hexdigest()):
        with pytest.raises(ValueError):
            install(archive, target, digest)
        assert target.read_bytes() == b"old executable"


def test_archive_and_destination_symlinks_are_not_followed(tmp_path):
    archive = tmp_path / "archive.bz2"
    archive.write_bytes(bz2.compress(b"\x7fELFfixture"))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    other = tmp_path / "other"
    other.write_bytes(b"untouched")
    link = tmp_path / "link"
    link.symlink_to(other)
    with pytest.raises(OSError):
        install(archive, link, digest)
    with pytest.raises(OSError):
        install(link, tmp_path / "target", digest)
    assert other.read_bytes() == b"untouched"


@pytest.mark.parametrize("trailing", [False, True])
def test_oversized_or_concatenated_archive_is_rejected(tmp_path, monkeypatch, trailing):
    from steward.core import tool_install

    monkeypatch.setattr(tool_install, "MAX_EXECUTABLE", 16)
    data = bz2.compress(b"\x7fELF" + b"x" * (4 if trailing else 32))
    if trailing:
        data += bz2.compress(b"extra")
    archive = tmp_path / "archive.bz2"
    archive.write_bytes(data)
    with pytest.raises(ValueError):
        install(archive, tmp_path / "target", hashlib.sha256(data).hexdigest())
    assert not (tmp_path / "target").exists()


@pytest.fixture
def model_manifest():
    def descriptor(media_type, data):
        return {
            "mediaType": media_type,
            "digest": f"sha256:{hashlib.sha256(data).hexdigest()}",
            "size": len(data),
        }

    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "config": descriptor("application/vnd.oci.image.config.v1+json", b"{}"),
            "layers": [descriptor("application/vnd.ollama.image.model", b"tiny")],
        }
    ).encode()
    receipt = json.dumps(
        {
            "model": "fixture:tiny",
            "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            "license": "Apache-2.0",
            "license_source": "synthetic fixture",
        }
    ).encode()
    return receipt, manifest


def test_staged_model_checks_exact_name_and_raw_manifest_digest(model_manifest):
    receipt, manifest = model_manifest
    staged = ollama_install.parse_staged_model("fixture:tiny", receipt, manifest)
    assert staged.relative_manifest.as_posix() == (
        "manifests/registry.ollama.ai/library/fixture/tiny"
    )
    assert sorted(blob.size for blob in staged.blobs) == [2, 4]
    with pytest.raises(ollama_install.InstallError, match="does not match"):
        ollama_install.parse_staged_model("fixture:other", receipt, manifest)
    with pytest.raises(ollama_install.InstallError, match="bare Ollama name:tag"):
        ollama_install.parse_staged_model("elsewhere/fixture:tiny", receipt, manifest)
    with pytest.raises(ollama_install.InstallError, match="manifest SHA256 mismatch"):
        ollama_install.parse_staged_model("fixture:tiny", receipt, manifest + b"\n")


def test_staged_model_preserves_ollama_from_provenance_without_using_it_as_a_path(model_manifest):
    receipt, manifest = model_manifest
    metadata = json.loads(receipt)
    document = json.loads(manifest)
    layer = document["layers"][0]
    digest = layer["digest"].removeprefix("sha256:")

    def parse():
        raw = json.dumps(document, indent=2).encode() + b"\n"
        metadata["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        return ollama_install.parse_staged_model("fixture:tiny", json.dumps(metadata).encode(), raw)

    layer["from"] = "/Users/example/.ollama/models/blobs/sha256-" + "a" * 64
    staged = parse()
    assert staged.manifest == json.dumps(document, indent=2).encode() + b"\n"
    assert staged.blobs[-1].file == f"sha256-{digest}"

    document["config"]["from"] = layer["from"]
    with pytest.raises(ollama_install.InstallError, match="invalid model blob descriptor"):
        parse()
    del document["config"]["from"]
    for bad in (None, "\n", "x" * 2049):
        layer["from"] = bad
        with pytest.raises(ollama_install.InstallError, match="invalid model blob provenance"):
            parse()


@pytest.mark.parametrize("data", [b"tin", b"tiny!", b"fake"])
def test_ollama_blob_fails_on_short_long_or_corrupt_bytes(data):
    digest = hashlib.sha256(b"tiny").hexdigest()
    with pytest.raises(ollama_install.InstallError, match="size or SHA256"):
        ollama_install._verify_bytes(io.BytesIO(data), 4, digest)


def _synthetic_runtime(member_name=None, link_target=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        payload = b"\x7fELFsynthetic"
        executable = tarfile.TarInfo("bin/ollama")
        executable.size = len(payload)
        archive.addfile(executable, io.BytesIO(payload))
        if member_name:
            member = tarfile.TarInfo(member_name)
            member.type = tarfile.SYMTYPE
            member.linkname = link_target
            archive.addfile(member)
    stream.seek(0)
    return stream


@pytest.mark.parametrize(
    ("member_name", "link_target", "message"),
    [
        ("../escape", "bin/ollama", "unsafe runtime archive path"),
        ("lib/ollama/escape", "../../bin/ollama", "leaves lib/ollama"),
    ],
)
def test_ollama_runtime_rejects_unsafe_archive_paths(tmp_path, member_name, link_target, message):
    destination = tmp_path / "runtime"
    destination.mkdir()
    with pytest.raises(ollama_install.InstallError, match=message):
        ollama_install.extract_runtime(_synthetic_runtime(member_name, link_target), destination)
    assert not (tmp_path / "escape").exists()
    assert not (destination / "lib/ollama/escape").is_symlink()


def test_ollama_runtime_has_an_expanded_size_bound(tmp_path):
    with pytest.raises(ollama_install.InstallError, match="expanded size"):
        ollama_install.extract_runtime(_synthetic_runtime(), tmp_path, limit=40)


def test_ollama_staging_rejects_symlinks_and_writable_directories(tmp_path):
    staged = tmp_path / "target"
    staged.write_bytes(b"fixture")
    link = tmp_path / "symlink"
    link.symlink_to(staged)
    with pytest.raises(OSError), ollama_install._staged_file(link, 100):
        pytest.fail("staging symlink was opened")
    tmp_path.chmod(0o777)
    with pytest.raises(ollama_install.InstallError, match="protected and root-owned"):
        ollama_install._check_directory(tmp_path, private=True)


@pytest.mark.parametrize(
    ("case", "diagnostic"),
    [
        ("reserved RAM and headroom", "insufficient RAM: model needs 128 MB, 127 free"),
        ("extraction disk", "insufficient disk for the staged runtime and its extraction"),
        ("shared model disk", "insufficient disk: 1027 MB needed, 1026 free"),
        ("unconfigured model", "invalid ai configuration"),
        (
            "missing staged bundle",
            "staging must contain the runtime archive, model.json, manifest.json and blobs",
        ),
        ("different staged tag", "staged model does not match ai.model"),
        ("uncontrolled pull", "invalid ai configuration"),
        ("GPU", "invalid ai configuration"),
    ],
)
def test_ollama_role_installer_refuses_without_publishing(
    tmp_path, monkeypatch, capsys, model_manifest, case, diagnostic
):
    staging = tmp_path / "staging"
    staging.mkdir(mode=0o700)
    if case != "missing staged bundle":
        blobs = staging / "blobs"
        blobs.mkdir()
        receipt, manifest = model_manifest
        (staging / "model.json").write_bytes(receipt)
        (staging / "manifest.json").write_bytes(manifest)
        for data in (b"{}", b"tiny"):
            (blobs / f"sha256-{hashlib.sha256(data).hexdigest()}").write_bytes(data)
    # All refusals precede extraction, which is covered by the artifact test.
    runtime = b"staged runtime placeholder"
    (staging / ollama_install.OLLAMA_ARCHIVE).write_bytes(runtime)

    tools = tmp_path / "tools"
    models = tmp_path / "models"
    monkeypatch.setattr(ollama_install, "STAGING", staging)
    monkeypatch.setattr(ollama_install, "OLLAMA_BINARY", tools / "version/bin/ollama")
    monkeypatch.setattr(ollama_install, "MODEL_ROOT", models)
    monkeypatch.setattr(ollama_install, "OLLAMA_SHA256", hashlib.sha256(runtime).hexdigest())
    monkeypatch.setattr(ollama_install.os, "geteuid", lambda: 0)
    monkeypatch.setattr(ollama_install.platform, "system", lambda: "Linux")
    monkeypatch.setattr(ollama_install.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(ollama_install, "_protected", lambda *args, **kwargs: True)

    local = {"download_mb": 1, "ram_mb": 128, "disk_mb": 2, "license_ack": True, "device": "cpu"}
    ai = {"provider": "ollama", "model": "fixture:tiny", "local_only": True, "local": local}
    payload = {"ai": ai, "reserved_memory_mb": 1024}
    ram_mb = 4096
    free_mb = 8192
    if case == "reserved RAM and headroom":
        # 1024 MB reserved + 256 MB headroom leaves 127 MB.
        ram_mb = 1407
    elif case == "extraction disk":
        free_mb = 4095
    elif case == "shared model disk":
        # Both roots resolve to the same filesystem. After reserving 4096 MB
        # for extraction, 1025 MB remains for the model's 1026 MB requirement.
        free_mb = 5121
    elif case == "unconfigured model":
        del ai["model"]
    elif case == "different staged tag":
        ai["model"] = "fixture:other"
    elif case == "uncontrolled pull":
        local["allow_pull"] = True
    elif case == "GPU":
        local["device"] = "gpu"

    read_text = Path.read_text

    def read_host_memory(path, *args, **kwargs):
        if path == Path("/proc/meminfo"):
            return f"MemTotal: {ram_mb * 1024} kB\n"
        return read_text(path, *args, **kwargs)

    def disk_space(path):
        assert path == tmp_path
        return SimpleNamespace(f_bavail=free_mb * 256, f_frsize=4096)

    monkeypatch.setattr(Path, "read_text", read_host_memory)
    monkeypatch.setattr(ollama_install.os, "statvfs", disk_space)
    monkeypatch.setattr(sys, "argv", [ollama_install.__file__])
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode())))

    assert ollama_install.main() != 0
    stdout, stderr = capsys.readouterr()
    assert stdout == ""
    assert f"Ollama installation refused: {diagnostic}" in stderr
    # Both installed trees and their pending directories live under these roots.
    assert not tools.exists()
    assert not models.exists()


def test_ollama_install_refuses_bad_artifacts_then_retries_unchanged(
    tmp_path, monkeypatch, model_manifest
):
    from steward.core.config import Ai

    zstd = pytest.importorskip("compression.zstd")
    receipt, manifest = model_manifest
    staging = tmp_path / "staging"
    blobs = staging / "blobs"
    blobs.mkdir(parents=True)
    (staging / "model.json").write_bytes(receipt)
    (staging / "manifest.json").write_bytes(manifest)
    for data in (b"{}", b"tiny"):
        blob = blobs / f"sha256-{hashlib.sha256(data).hexdigest()}"
        blob.write_bytes(data)

    runtime = zstd.compress(_synthetic_runtime().read())
    archive = staging / ollama_install.OLLAMA_ARCHIVE
    archive.write_bytes(runtime + b"extra")
    binary = tmp_path / "tools/version/bin/ollama"
    model_root = tmp_path / "models"
    pending = (
        binary.parent.parent.parent / ".steward-ollama-runtime.pending",
        model_root / ".steward-ollama-model.pending",
    )

    resource_error = False

    def check_resources(*args):
        assert not any(path.exists() for path in pending)
        if resource_error:
            raise ollama_install.InstallError("insufficient resources")

    monkeypatch.setattr(ollama_install, "OLLAMA_SHA256", hashlib.sha256(runtime).hexdigest())
    monkeypatch.setattr(ollama_install.os, "geteuid", lambda: 0)
    monkeypatch.setattr(ollama_install.platform, "system", lambda: "Linux")
    monkeypatch.setattr(ollama_install.platform, "machine", lambda: "x86_64")
    protected = ollama_install._protected
    monkeypatch.setattr(ollama_install, "_protected", lambda *args, **kwargs: True)
    monkeypatch.setattr(ollama_install, "_check_resources", check_resources)
    ai = Ai.model_validate(
        {
            "provider": "ollama",
            "model": "fixture:tiny",
            "local": {"download_mb": 1, "ram_mb": 128, "disk_mb": 2, "license_ack": True},
        }
    )
    paths = {"staging": staging, "binary": binary, "model_root": model_root}

    with pytest.raises(ollama_install.InstallError, match="SHA256 mismatch"):
        ollama_install.install(ai, 0, **paths)
    assert not binary.exists()

    archive.write_bytes(runtime)
    blob.write_bytes(b"fake")
    with pytest.raises(ollama_install.InstallError, match="SHA256 mismatch"):
        ollama_install.install(ai, 0, **paths)
    assert not binary.exists()
    assert list(model_root.iterdir()) == []

    for path in pending:
        path.mkdir(mode=0o700, parents=True)
        (path / "partial").write_bytes(b"interrupted fixture")
    blob.write_bytes(b"tiny")
    previous_umask = os.umask(0o077)
    try:
        result = ollama_install.install(ai, 0, **paths)
    finally:
        os.umask(previous_umask)
    assert result["changed"] is True
    assert result["binary"] == str(binary)
    assert binary.read_bytes() == b"\x7fELFsynthetic"
    models = model_root / hashlib.sha256(receipt).hexdigest()
    assert result["models"] == str(models)
    installed_manifest = models / "manifests/registry.ollama.ai/library/fixture/tiny"
    assert installed_manifest.read_bytes() == manifest
    v2 = models / "manifests-v2"
    assert stat.S_IMODE(v2.stat().st_mode) == 0o755
    assert list(v2.iterdir()) == []
    fresh_inode = v2.stat().st_ino
    assert ollama_install.install(ai, 0, **paths) == {**result, "changed": False}
    assert v2.stat().st_ino == fresh_inode

    v2.rmdir()
    installed_blob = models / "blobs" / blob.name
    installed_receipt = models / ollama_install.RECEIPT

    def legacy_snapshot():
        runtime_root = binary.parent.parent
        entries = [models, runtime_root, *models.rglob("*"), *runtime_root.rglob("*")]
        return {
            path: (path.lstat().st_ino, path.lstat().st_mode, path.read_bytes())
            if path.is_file()
            else (path.lstat().st_ino, path.lstat().st_mode)
            for path in entries
            if path != v2
        }

    for artifact, bad_bytes, diagnostic in (
        (installed_receipt, receipt + b"\n", "installed manifest or receipt"),
        (installed_manifest, manifest + b"\n", "installed manifest or receipt"),
        (installed_blob, b"fake", "SHA256 mismatch"),
        (blob, b"fake", "SHA256 mismatch"),
        (archive, runtime + b"extra", "SHA256 mismatch"),
        (binary, b"\x7fELFesthetic", "installed runtime does not match"),
    ):
        original = artifact.read_bytes()
        artifact.write_bytes(bad_bytes)
        before = legacy_snapshot()
        with pytest.raises(ollama_install.InstallError, match=diagnostic):
            ollama_install.install(ai, 0, **paths)
        assert not os.path.lexists(v2)
        assert legacy_snapshot() == before
        artifact.write_bytes(original)

    before = legacy_snapshot()
    resource_error = True
    with pytest.raises(ollama_install.InstallError, match="insufficient resources"):
        ollama_install.install(ai, 0, **paths)
    assert not os.path.lexists(v2)
    assert legacy_snapshot() == before
    resource_error = False

    previous_umask = os.umask(0o077)
    try:
        assert ollama_install.install(ai, 0, **paths) == result
    finally:
        os.umask(previous_umask)
    assert stat.S_IMODE(v2.stat().st_mode) == 0o755
    assert list(v2.iterdir()) == []
    assert installed_receipt.read_bytes() == receipt
    assert legacy_snapshot() == before
    assert not any(path.exists() for path in pending)
    repaired_inode = v2.stat().st_ino
    assert ollama_install.install(ai, 0, **paths) == {**result, "changed": False}
    assert v2.stat().st_ino == repaired_inode
    assert legacy_snapshot() == before

    for mode in (0o777, 0o700, 0o2755):
        v2.chmod(mode)
        with pytest.raises(ollama_install.InstallError, match="empty 0755"):
            ollama_install.install(ai, 0, **paths)
        assert stat.S_IMODE(v2.stat().st_mode) == mode
    v2.chmod(0o755)
    entry = v2 / "unexpected"
    entry.touch()
    with pytest.raises(ollama_install.InstallError, match="empty 0755"):
        ollama_install.install(ai, 0, **paths)
    assert entry.is_file()
    entry.unlink()

    for uid, gid in ((1000, 0), (0, 1000)):

        def foreign_owner(info, *, uid=uid, gid=gid, **kwargs):
            if info.st_ino == repaired_inode:
                return protected(
                    SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=info.st_mode), **kwargs
                )
            return True

        with monkeypatch.context() as foreign:
            foreign.setattr(ollama_install, "_protected", foreign_owner)
            with pytest.raises(ollama_install.InstallError, match="root-owned: .*manifests-v2"):
                ollama_install.install(ai, 0, **paths)
    assert v2.stat().st_ino == repaired_inode
    v2.rmdir()
    v2.symlink_to(models / "blobs", target_is_directory=True)
    with pytest.raises(ollama_install.InstallError, match="root-owned: .*manifests-v2"):
        ollama_install.install(ai, 0, **paths)
    assert v2.is_symlink()
    v2.unlink()

    (models / "unexpected").touch()
    with pytest.raises(ollama_install.InstallError, match="unexpected entries"):
        ollama_install.install(ai, 0, **paths)
    assert not os.path.lexists(v2)
    assert (models / "unexpected").is_file()
