"""Install the staged AMD64 Ollama runtime and one verified local model."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import sys
import tarfile
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from pydantic import ValidationError

from .config import Ai
from .inference_local import LISTEN, LocalInstallRejected, plan_local_install
from .tools import OLLAMA_ARCHIVE, OLLAMA_BINARY, OLLAMA_SHA256

if TYPE_CHECKING:
    from collections.abc import Iterator

STAGING = Path("/var/cache/steward-tools/ollama")
MODEL_ROOT = Path("/var/lib/steward/ollama")
RECEIPT = ".steward-receipt"
MIB = 1024**2
MAX_JSON = MIB
MAX_ARCHIVE = 4 * 1024 * MIB
# The pinned v0.40.18 expands to 2,672,960,538 regular-file bytes. Allow
# headroom for tar metadata, padding and filesystem overhead.
MAX_EXPANDED = 4 * 1024 * MIB
MAX_MEMBERS = 8192
MAX_TAR_METADATA = 64 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}")
MODEL = re.compile(r"([a-z0-9][a-z0-9_-]{0,127}):([a-z0-9][a-z0-9._-]{0,127})")
REGISTRY = "registry.ollama.ai"
MODEL_LAYER = "application/vnd.ollama.image.model"
LAYER_TYPES = {
    f"application/vnd.ollama.image.{kind}"
    for kind in ("model", "license", "template", "params", "system", "messages", "projector")
}
CONFIG_TYPES = {
    "application/vnd.docker.container.image.v1+json",
    "application/vnd.oci.image.config.v1+json",
}


class InstallError(ValueError):
    """An input or host prerequisite failed verification."""


class Blob(NamedTuple):
    file: str
    sha256: str
    size: int


@dataclass(frozen=True)
class StagedModel:
    name: str
    tag: str
    manifest: bytes
    receipt: bytes
    blobs: tuple[Blob, ...]

    @property
    def relative_manifest(self) -> Path:
        return Path("manifests", REGISTRY, "library", self.name, self.tag)

    @property
    def key(self) -> str:
        return hashlib.sha256(self.receipt).hexdigest()

    @property
    def size(self) -> int:
        return sum(blob.size for blob in self.blobs) + len(self.manifest) + len(self.receipt)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InstallError("duplicate JSON key")
        result[key] = value
    return result


def _object(raw: bytes) -> dict:
    if len(raw) > MAX_JSON:
        raise InstallError("JSON exceeds size limit")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(value, dict):
        raise InstallError("expected a JSON object")
    return value


def _descriptor(value: object, types: set[str]) -> Blob:
    if not isinstance(value, dict):
        raise InstallError("invalid model blob descriptor")
    keys = {"mediaType", "digest", "size"}
    if value.get("mediaType") == MODEL_LAYER and "from" in value:
        # Ollama records model provenance here. Blob paths still come from the digest.
        provenance = value["from"]
        if (
            not isinstance(provenance, str)
            or not 0 < len(provenance) <= 2048
            or not provenance.isprintable()
        ):
            raise InstallError("invalid model blob provenance")
        keys.add("from")
    if value.keys() != keys:
        raise InstallError("invalid model blob descriptor")
    media, digest, size = value["mediaType"], value["digest"], value["size"]
    if (
        not isinstance(media, str)
        or media not in types
        or not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or not DIGEST.fullmatch(digest[7:])
        or type(size) is not int
        or size <= 0
    ):
        raise InstallError("invalid model blob media type, SHA256 or size")
    return Blob(f"sha256-{digest[7:]}", digest[7:], size)


def parse_staged_model(model: str, receipt: bytes, manifest: bytes) -> StagedModel:
    """Check the operator receipt and the raw OCI/Docker schema 2 manifest."""
    match = MODEL.fullmatch(model)
    if match is None:
        raise InstallError("an explicit bare Ollama name:tag is required")
    name, tag = match.groups()
    metadata = _object(receipt)
    if metadata.keys() != {"model", "manifest_sha256", "license", "license_source"}:
        raise InstallError("invalid model.json keys")
    if metadata["model"] != model:
        raise InstallError("staged model does not match ai.model")
    if metadata["manifest_sha256"] != hashlib.sha256(manifest).hexdigest():
        raise InstallError("model manifest SHA256 mismatch")
    for field in ("license", "license_source"):
        value = metadata[field]
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > 2048
            or not value.isprintable()
        ):
            raise InstallError(f"invalid model {field}")

    document = _object(manifest)
    layers = document.get("layers")
    if (
        document.keys() - {"schemaVersion", "mediaType", "config", "layers"}
        or type(document.get("schemaVersion")) is not int
        or document["schemaVersion"] != 2
        or document.get("mediaType")
        not in (
            None,
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
        )
        or not isinstance(layers, list)
        or not 1 <= len(layers) <= 128
    ):
        raise InstallError("expected a schema 2 manifest for a local model")
    config = _descriptor(document.get("config"), CONFIG_TYPES)
    descriptors = [_descriptor(layer, LAYER_TYPES) for layer in layers]
    if sum(layer["mediaType"] == MODEL_LAYER for layer in layers) != 1:
        raise InstallError("manifest must describe exactly one local model layer")
    blobs = {blob.file: blob for blob in (config, *descriptors)}
    if any(blobs[blob.file] != blob for blob in (config, *descriptors)):
        raise InstallError("conflicting sizes for the same blob digest")
    return StagedModel(name, tag, manifest, receipt, tuple(blobs.values()))


def _protected(info: os.stat_result, *, private: bool = False) -> bool:
    forbidden = 0o077 if private else 0o022
    return (info.st_uid, info.st_gid) == (0, 0) and not info.st_mode & forbidden


def _check_directory(path: Path, *, private: bool = False) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or not _protected(info, private=private):
        raise InstallError(f"directory must be protected and root-owned: {path}")


def _directory_chain(path: Path, *, create: bool = False) -> None:
    for directory in reversed((path, *path.parents)):
        if create:
            directory.mkdir(mode=0o755, exist_ok=True)
        _check_directory(directory)


@contextmanager
def _staged_file(path: Path, limit: int) -> Iterator[tuple[BinaryIO, int]]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or not _protected(info)
            or info.st_nlink != 1
            or not 0 < info.st_size <= limit
        ):
            raise InstallError(f"invalid staged file ownership, type or size: {path.name}")
        yield stream, info.st_size


def _read_staged(path: Path) -> bytes:
    with _staged_file(path, MAX_JSON) as (stream, size):
        raw = stream.read(MAX_JSON + 1)
        if len(raw) != size:
            raise InstallError(f"staged file changed: {path.name}")
        return raw


def _verify_bytes(
    stream: BinaryIO, size: int, expected: str, output: BinaryIO | None = None
) -> None:
    fingerprint = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, MIB))
        if not chunk:
            break
        fingerprint.update(chunk)
        remaining -= len(chunk)
        if output is not None:
            output.write(chunk)
    if remaining or stream.read(1) or fingerprint.hexdigest() != expected:
        raise InstallError("staged artifact size or SHA256 mismatch")


class _BoundedTar:
    def __init__(self, raw: BinaryIO, limit: int):
        self.raw = raw
        self.remaining = limit

    def read(self, size: int) -> bytes:
        chunk = self.raw.read(min(size, self.remaining + 1))
        self.remaining -= len(chunk)
        if self.remaining < 0:
            raise InstallError("runtime archive exceeds expanded size limit")
        return chunk


def _archive_path(name: str) -> PurePosixPath:
    if name.startswith("./"):
        name = name[2:]
    if len(name) > 512 or any(
        component in {"", ".", ".."} or not re.fullmatch(r"[a-zA-Z0-9_.+-]+", component)
        for component in name.split("/")
    ):
        raise InstallError("unsafe runtime archive path")
    return PurePosixPath(name)


def _internal_link(path: PurePosixPath, target: str) -> None:
    parts = list(path.parent.parts)
    for component in target.split("/"):
        if component == "..":
            if len(parts) <= 2:
                raise InstallError("runtime symlink leaves lib/ollama")
            parts.pop()
        elif not re.fullmatch(r"[a-zA-Z0-9_.+-]+", component):
            raise InstallError("unsafe runtime symlink target")
        elif component != ".":
            parts.append(component)


def extract_runtime(raw: BinaryIO, destination: Path, *, limit: int = MAX_EXPANDED) -> None:
    """Extract a bounded decompressed tar stream into an empty private directory."""
    headers = 0
    metadata_depth = 0
    metadata_types = {tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK}
    allowed_types = metadata_types | {
        tarfile.REGTYPE,
        tarfile.AREGTYPE,
        tarfile.DIRTYPE,
        tarfile.SYMTYPE,
    }

    class TarMember(tarfile.TarInfo):
        def _proc_gnusparse_10(self, *_args: object) -> None:
            # This PAX sparse variant reads an unbounded map from the payload.
            raise InstallError("unsupported runtime archive sparse member")

        def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
            nonlocal headers, metadata_depth
            headers += 1
            if headers > MAX_MEMBERS or self.size < 0:
                raise InstallError("invalid runtime archive header count or size")
            if self.type not in allowed_types:
                raise InstallError("unsupported runtime archive member type")
            if self.type not in metadata_types:
                return super()._proc_member(archive)
            if self.size > MAX_TAR_METADATA or metadata_depth >= 4:
                raise InstallError("runtime archive metadata exceeds limit")
            metadata_depth += 1
            try:
                return super()._proc_member(archive)
            finally:
                metadata_depth -= 1

    bounded = _BoundedTar(raw, limit)
    seen: set[PurePosixPath] = set()
    links: list[tuple[Path, str]] = []
    with tarfile.open(fileobj=bounded, mode="r|", tarinfo=TarMember, bufsize=64 * 1024) as archive:
        for member in archive:
            if member.isdir() and member.name in (".", "./"):
                continue
            path = _archive_path(member.name)
            library = path.parts[:2] == ("lib", "ollama")
            binary = path == PurePosixPath("bin/ollama")
            if (
                path in seen
                or member.issparse()
                or not 0 <= member.size <= limit
                or (not member.isfile() and member.size != 0)
                or not (
                    library
                    or binary
                    or (member.isdir() and path in (PurePosixPath("bin"), PurePosixPath("lib")))
                )
                or (
                    path in (PurePosixPath("bin/ollama"), PurePosixPath("lib/ollama"))
                    and not (member.isfile() if binary else member.isdir())
                )
            ):
                raise InstallError("unexpected runtime archive member")
            seen.add(path)
            output = destination / path
            if member.isdir():
                output.mkdir(mode=0o755, parents=True, exist_ok=True)
            elif member.issym():
                _internal_link(path, member.linkname)
                output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                links.append((output, member.linkname))
            elif member.isfile():
                output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                with archive.extractfile(member) as source, output.open("xb") as target:
                    if member.size == 0 and binary:
                        raise InstallError("empty Ollama executable")
                    shutil.copyfileobj(source, target, MIB)
                output.chmod(0o755 if binary or member.mode & 0o111 else 0o644)

    if PurePosixPath("bin/ollama") not in seen:
        raise InstallError("runtime archive is missing bin/ollama")
    for output, target in links:
        output.symlink_to(target)
    library_root = destination.resolve() / "lib/ollama"
    for output, _ in links:
        if not output.resolve(strict=True).is_relative_to(library_root):
            raise InstallError("runtime symlink leaves lib/ollama")


def _existing_tree(path: Path) -> bool:
    try:
        _check_directory(path)
    except FileNotFoundError:
        return False
    return True


def _runtime_receipt(runtime: Path) -> bytes:
    def fail_walk(error: OSError) -> None:
        raise error

    digest = hashlib.sha256()
    for directory, subdirs, files in runtime.walk(on_error=fail_walk):
        subdirs.sort()
        for name in sorted((*subdirs, *files)):
            path = directory / name
            relative = str(path.relative_to(runtime))
            if relative == RECEIPT:
                continue
            info = path.lstat()
            mode = info.st_mode
            payload = ""
            if stat.S_ISLNK(mode) and (info.st_uid, info.st_gid) == (0, 0):
                payload = os.readlink(path)
            elif not _protected(info):
                raise InstallError(f"untrusted installed runtime entry: {relative}")
            elif stat.S_ISREG(mode) and info.st_nlink == 1:
                with path.open("rb") as stream:
                    payload = hashlib.file_digest(stream, "sha256").hexdigest()
            elif not stat.S_ISDIR(mode):
                raise InstallError(f"invalid installed runtime entry: {relative}")
            digest.update(json.dumps((relative, mode, payload)).encode())
    return f"{OLLAMA_SHA256}\n{digest.hexdigest()}".encode("ascii")


def _remove_pending(path: Path) -> None:
    # The fixed pending directory is reserved to this installer and protected by
    # the staging lock. A previous process can have stopped before publication.
    if _existing_tree(path):
        shutil.rmtree(path)


@contextmanager
def _pending_tree(path: Path, *, present: bool) -> Iterator[Path | None]:
    if present:
        yield None
        return
    _directory_chain(path.parent, create=True)
    path.mkdir(mode=0o700)
    try:
        yield path
    finally:
        _remove_pending(path)


def _available(path: Path) -> tuple[int, int]:
    for directory in (path, *path.parents):
        if os.path.lexists(directory):
            _directory_chain(directory)
            fs = os.statvfs(directory)
            return directory.stat().st_dev, fs.f_bavail * fs.f_frsize
    raise InstallError(f"cannot determine available disk space for {path}")


def _check_resources(
    ai: Ai,
    reserved_memory_mb: int,
    model: StagedModel,
    runtime_present: bool,
    models_present: bool,
    runtime_root: Path,
    model_root: Path,
) -> None:
    meminfo = Path("/proc/meminfo").read_text()
    memory = re.search(r"^MemTotal:\s+(\d+) kB$", meminfo, re.MULTILINE)
    if memory is None:
        raise InstallError("cannot determine host RAM")
    tool_device, tool_free = _available(runtime_root)
    model_device, model_free = _available(model_root)
    # statvfs already excludes occupied staging and finished trees. Reserve only
    # new writes here, and keep the planner's ordinary free-space headroom.
    runtime_need = 0 if runtime_present else MAX_EXPANDED
    if runtime_need > tool_free:
        raise InstallError("insufficient disk for the staged runtime and its extraction")
    if tool_device == model_device:
        model_free -= runtime_need
    local = ai.local
    assert local is not None  # install requires ai.local before auditing resources
    occupied_mb = local.download_mb + (local.disk_mb if models_present else 0)
    plan = plan_local_install(
        ai,
        ram_total_mb=int(memory[1]) // 1024,
        disk_free_mb=model_free // MIB + occupied_mb,
        reserved_memory_mb=reserved_memory_mb,
    )
    if model.size > min(plan.download_mb, local.disk_mb) * MIB:
        raise InstallError("staged model exceeds ai.local download or disk size limit")


def _verify_blobs(blobs: Path, model: StagedModel, destination: Path | None = None) -> None:
    _check_directory(blobs)
    if {item.name for item in blobs.iterdir()} != {blob.file for blob in model.blobs}:
        raise InstallError("model blobs do not match the manifest")
    for blob in model.blobs:
        with _staged_file(blobs / blob.file, blob.size) as (source, size):
            if size != blob.size:
                raise InstallError("staged blob size does not match manifest")
            if destination is None:
                _verify_bytes(source, size, blob.sha256)
            else:
                output = destination / blob.file
                with output.open("xb") as target:
                    _verify_bytes(source, size, blob.sha256, target)
                output.chmod(0o644)


def _prepare_manifests_v2(root: Path) -> Path:
    directory = root / "manifests-v2"
    directory.mkdir(mode=0o700)
    directory.chmod(0o755)
    _check_directory(directory)
    return directory


def _prepare_model(staging: Path, model: StagedModel, destination: Path | None) -> None:
    if destination is None:
        _verify_blobs(staging / "blobs", model)
        return
    (destination / "blobs").mkdir(mode=0o755)
    manifest = destination / model.relative_manifest
    manifest.parent.mkdir(mode=0o755, parents=True)
    manifest.write_bytes(model.manifest)
    manifest.chmod(0o644)
    _verify_blobs(staging / "blobs", model, destination / "blobs")
    _prepare_manifests_v2(destination)


def _verify_installed_model(root: Path, model: StagedModel) -> bool:
    entries = {entry.name for entry in root.iterdir()}
    has_v2 = "manifests-v2" in entries
    if entries - {"manifests-v2"} != {"manifests", "blobs", RECEIPT}:
        raise InstallError("unexpected entries in the installed model tree")
    if has_v2:
        directory = root / "manifests-v2"
        _check_directory(directory)
        if stat.S_IMODE(directory.lstat().st_mode) != 0o755 or any(directory.iterdir()):
            raise InstallError("installed manifests-v2 must be an empty 0755 directory")
    manifest = root / model.relative_manifest
    _directory_chain(manifest.parent)
    child = manifest
    while child.parent != root:
        if {entry.name for entry in child.parent.iterdir()} != {child.name}:
            raise InstallError("unexpected entries in the installed manifest tree")
        child = child.parent
    if _read_staged(root / RECEIPT) != model.receipt or _read_staged(manifest) != model.manifest:
        raise InstallError("installed manifest or receipt does not match the staged model")
    _verify_blobs(root / "blobs", model)
    return has_v2


def _prepare_runtime(source: BinaryIO, size: int, destination: Path) -> None:
    if sys.version_info < (3, 14):
        raise InstallError("Ollama runtime installation requires Python 3.14 or later")
    from compression import zstd

    source.seek(0)
    try:
        with zstd.open(
            source, "rb", options={zstd.DecompressionParameter.window_log_max: 27}
        ) as raw:
            extract_runtime(raw, destination)
    except zstd.ZstdError as exc:
        raise InstallError("invalid Zstandard runtime archive") from exc
    source.seek(0)
    _verify_bytes(source, size, OLLAMA_SHA256)


def install(
    ai: Ai, reserved_memory_mb: int, *, staging: Path, binary: Path, model_root: Path
) -> dict[str, bool | str]:
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() != 0:
        raise InstallError("Ollama installation requires root on AMD64 Linux")
    if (
        ai.provider != "ollama"
        or not ai.local_only
        or ai.model is None
        or ai.local is None
        or not ai.local.license_ack
        or ai.base_url not in (None, f"http://{LISTEN}")
        or ai.fx is not None
        or type(reserved_memory_mb) is not int
        or reserved_memory_mb < 0
    ):
        raise InstallError("invalid local-only Ollama installation configuration")

    runtime = binary.parent.parent
    _directory_chain(staging)
    _check_directory(staging, private=True)
    with ExitStack() as stack:
        lock = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, lock)
        fcntl.flock(lock, fcntl.LOCK_EX)
        if {item.name for item in staging.iterdir()} != {
            OLLAMA_ARCHIVE,
            "model.json",
            "manifest.json",
            "blobs",
        }:
            raise InstallError(
                "staging must contain the runtime archive, model.json, manifest.json and blobs"
            )
        model = parse_staged_model(
            ai.model, _read_staged(staging / "model.json"), _read_staged(staging / "manifest.json")
        )
        models = model_root / model.key
        _available(runtime.parent)
        _available(model_root)
        runtime_pending = runtime.parent / ".steward-ollama-runtime.pending"
        models_pending = model_root / ".steward-ollama-model.pending"
        _remove_pending(runtime_pending)
        _remove_pending(models_pending)
        runtime_present = _existing_tree(runtime)
        models_present = _existing_tree(models)
        if runtime_present and _read_staged(runtime / RECEIPT) != _runtime_receipt(runtime):
            raise InstallError("installed runtime does not match its verified receipt")
        repair_model = models_present and not _verify_installed_model(models, model)
        source, size = stack.enter_context(_staged_file(staging / OLLAMA_ARCHIVE, MAX_ARCHIVE))
        _check_resources(
            ai,
            reserved_memory_mb,
            model,
            runtime_present,
            models_present,
            runtime.parent,
            model_root,
        )
        _verify_bytes(source, size, OLLAMA_SHA256)

        model_work = stack.enter_context(_pending_tree(models_pending, present=models_present))
        _prepare_model(staging, model, model_work)
        runtime_work = stack.enter_context(_pending_tree(runtime_pending, present=runtime_present))
        if runtime_work is not None:
            _prepare_runtime(source, size, runtime_work)
            _publish_tree(runtime_work, runtime, _runtime_receipt(runtime_work))
        if model_work is not None:
            _publish_tree(model_work, models, model.receipt)
        elif repair_model:
            repair_work = stack.enter_context(_pending_tree(models_pending, present=False))
            assert repair_work is not None
            _prepare_manifests_v2(repair_work).rename(models / "manifests-v2")

    return {
        "changed": repair_model or not (runtime_present and models_present),
        "binary": str(binary),
        "models": str(models),
    }


def _publish_tree(work: Path, destination: Path, receipt: bytes) -> None:
    stamp = work / RECEIPT
    stamp.write_bytes(receipt)
    stamp.chmod(0o600)
    work.chmod(0o755)
    work.rename(destination)


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise InstallError("read the Ollama installation payload from stdin")
        payload = _object(sys.stdin.buffer.read(MAX_JSON + 1))
        if payload.keys() != {"ai", "reserved_memory_mb"}:
            raise InstallError("invalid Ollama installation payload keys")
        result = install(
            Ai.model_validate(payload["ai"]),
            payload["reserved_memory_mb"],
            staging=STAGING,
            binary=OLLAMA_BINARY,
            model_root=MODEL_ROOT,
        )
    except ValidationError:
        print("Ollama installation refused: invalid ai configuration", file=sys.stderr)
        return 1
    except (
        OSError,
        ValueError,
        RuntimeError,
        LocalInstallRejected,
        tarfile.TarError,
        EOFError,
    ) as exc:
        print(f"Ollama installation refused: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
