"""Image transfer for ordinary projects with the registered container probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from steward.core.images import image_id

ARCHIVE_DIR = Path("/var/lib/steward/images")
METADATA_LIMIT = 1024 * 1024
MEMBER_LIMIT = 8192
OCI_REF_NAME = "org.opencontainers.image.ref.name"
PINNED_REF = re.compile(
    r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[a-f0-9]{64}"
)
LOCAL_TAG = re.compile(r"localhost/steward/[a-z][a-z0-9-]{1,30}[a-z0-9]:sha256-[a-f0-9]{32}")
CONTAINER_NAME = re.compile(r"[a-z][a-z0-9-]{1,30}[a-z0-9]")


class TransportError(Exception):
    pass


class ArchiveMetadataError(TransportError):
    """A protected cache entry has unreadable or invalid metadata."""


class BoundedTarInfo(tarfile.TarInfo):
    """Limit the extended headers tarfile reads while walking the archive."""

    def _bounded_header(self, archive):
        total = getattr(archive, "_steward_extended_bytes", 0) + self.size + tarfile.BLOCKSIZE
        if self.size < 0 or total > METADATA_LIMIT:
            raise TransportError("oversized archive extended headers")
        archive._steward_extended_bytes = total

    def _proc_pax(self, archive):
        self._bounded_header(archive)
        return super()._proc_pax(archive)

    def _proc_gnulong(self, archive):
        self._bounded_header(archive)
        return super()._proc_gnulong(archive)

    def _proc_sparse(self, archive):
        raise TransportError("sparse tar members are unsupported")

    def _proc_gnusparse_10(self, member, headers, archive):
        raise TransportError("sparse tar members are unsupported")

    def _proc_gnusparse_00(self, member, headers):
        raise TransportError("sparse tar members are unsupported")

    def _proc_gnusparse_01(self, member, headers):
        raise TransportError("sparse tar members are unsupported")


def json_document(raw: str | bytes) -> object:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise TransportError("duplicate JSON object member")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique_object)


def podman(*args: str, timeout: int = 30, allow_absent: bool = False) -> str | None:
    result = subprocess.run(
        ["/usr/bin/podman", *args],
        cwd="/",
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    if allow_absent and result.returncode == 1:
        return None
    raise TransportError(
        f"Podman {args[0]} exited {result.returncode}: {result.stderr.strip()[:500]}"
    )


def present(kind: str, name: str) -> bool:
    return podman(kind, "exists", name, allow_absent=True) is not None


def require_image_id(value: object) -> str:
    identity = image_id(value)
    if identity is None:
        raise TransportError("expected a full sha256 image config ID")
    return identity


def exact_source(ref: str) -> tuple[str, bool] | None:
    if not present("image", ref):
        return None
    # Podman's exact digest-reference lookup can resolve a pinned upstream
    # index to its selected manifest. The selected Digest can differ from ref.
    raw = podman("image", "inspect", ref)
    if len(raw) > METADATA_LIMIT:
        raise TransportError("oversized Podman image inspection")
    entries = json_document(raw)
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        raise TransportError("expected one Podman image inspection record")
    (info,) = entries
    # Stock Podman reports Docker health metadata separately from its OCI Config.
    config = info.get("Config") or {}
    healthcheck = info.get("Healthcheck", config.get("Healthcheck")) or {}
    if not isinstance(healthcheck, dict):
        raise TransportError("invalid Podman health check metadata")
    test = healthcheck.get("Test") or []
    runnable = (
        isinstance(test, list)
        and len(test) > 1
        and test[0] in ("CMD", "CMD-SHELL")
        and isinstance(test[1], str)
        and bool(test[1].strip())
        and all(isinstance(arg, str) for arg in test)
    )
    return require_image_id(info.get("Id")), runnable


def protected(info: os.stat_result, *, directory: bool = False) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise TransportError("archive custody requires root ownership and protected permissions")


def metadata(archive: tarfile.TarFile, member: tarfile.TarInfo) -> tuple[object, str]:
    if not member.isfile() or member.issparse() or not 0 < member.size <= METADATA_LIMIT:
        raise TransportError("invalid archive metadata member")
    with archive.extractfile(member) as stream:
        raw = stream.read(METADATA_LIMIT + 1)
    if len(raw) != member.size:
        raise TransportError("truncated archive metadata")
    return json_document(raw), "sha256:" + hashlib.sha256(raw).hexdigest()


def tagged_entry(entries: list, matches):
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        raise TransportError("invalid archive manifest list")
    selected = [entry for entry in entries if matches(entry)]
    if len(selected) != 1:
        raise TransportError("archive must bind the desired tag exactly once")
    return selected[0]


def archive_image(path: Path, tag: str) -> tuple[str, str] | None:
    """Read only archive metadata and return (format, tagged config ID)."""
    protected(path.parent.lstat(), directory=True)
    try:
        protected(path.lstat())
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        protected(os.fstat(stream.fileno()))
        try:
            return read_archive_image(stream, tag)
        except (
            TransportError,
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
            RecursionError,
            tarfile.TarError,
        ) as exc:
            raise ArchiveMetadataError("invalid image archive metadata") from exc


def member_name(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise TransportError("invalid archive member path")
    return str(path)


def docker_tag_count(entry: dict, tag: str) -> int:
    tags = entry.get("RepoTags")
    if tags is None:
        return 0
    if not isinstance(tags, list) or any(not isinstance(name, str) for name in tags):
        raise TransportError("invalid Docker archive tag list")
    count = tags.count(tag)
    if count > 1:
        raise TransportError("archive must bind the desired tag exactly once")
    return count


def read_archive_image(stream, tag: str) -> tuple[str, str]:
    # Podman save emits an uncompressed tar. Seek over layer data.
    with tarfile.open(fileobj=stream, mode="r:", tarinfo=BoundedTarInfo) as archive:
        members = {}
        for count, member in enumerate(archive, 1):
            name = member_name(member.name)
            if count > MEMBER_LIMIT or name in members:
                raise TransportError("too many or duplicate archive members")
            if member.size < 0 or member.issparse():
                raise TransportError("invalid archive member size or sparse member")
            members[name] = member
        # tarfile can report a malformed subsequent header as end of archive.
        stream.seek(archive.offset)
        if stream.read(tarfile.BLOCKSIZE * 2) != bytes(tarfile.BLOCKSIZE * 2):
            raise TransportError("missing archive end marker")

        def read(name):
            return metadata(archive, members[name])

        def blob_member(descriptor):
            identity = descriptor["digest"]
            if not isinstance(identity, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", identity):
                raise TransportError("invalid archive blob digest")
            name = "blobs/sha256/" + identity.removeprefix("sha256:")
            member = members[name]
            size = descriptor["size"]
            if not member.isfile() or type(size) is not int or size != member.size:
                raise TransportError("archive blob differs from its descriptor")
            return member, identity

        def blob(descriptor):
            member, identity = blob_member(descriptor)
            document, actual = metadata(archive, member)
            if identity != actual:
                raise TransportError("archive blob differs from its descriptor")
            return document, identity

        if "manifest.json" in members and "index.json" not in members:
            manifests, _ = read("manifest.json")
            entry = tagged_entry(manifests, lambda item: docker_tag_count(item, tag))
            config_path = member_name(entry["Config"])
            config, identity = read(config_path)
            filename = re.fullmatch(r"(?:blobs/sha256/)?([a-f0-9]{64})(?:\.json)?", config_path)
            if filename and identity != "sha256:" + filename[1]:
                raise TransportError("Docker archive config differs from its filename")
            layers = entry["Layers"]
            if not isinstance(layers, list) or any(
                not members[member_name(layer)].isfile() for layer in layers
            ):
                raise TransportError("invalid Docker archive layers")
            archive_format = "docker-archive"
        elif "index.json" in members and "manifest.json" not in members:
            index, _ = read("index.json")
            entry = tagged_entry(
                index["manifests"],
                lambda item: (item.get("annotations") or {}).get(OCI_REF_NAME) == tag,
            )
            manifest, _ = blob(entry)
            config, identity = blob(manifest["config"])
            if not isinstance(manifest["layers"], list):
                raise TransportError("invalid OCI archive layers")
            for layer in manifest["layers"]:
                blob_member(layer)
            archive_format = "oci-archive"
        else:
            raise TransportError("unrecognized or ambiguous image archive format")
        if not isinstance(config, dict):
            raise TransportError("invalid archive image config")
        return archive_format, identity


def prepare_archive(archive: Path, ref: str, tag: str, *, rebuild: bool = False) -> dict:
    protected(archive.parent.lstat(), directory=True)
    source = exact_source(ref)
    try:
        cached = archive_image(archive, tag)
    except ArchiveMetadataError:
        # The direct-to-final save in older releases could leave a partial file.
        cached = None
    if source is None:
        # A protected Docker preseed can establish the config ID for delivery
        # when the pinned upstream manifest is absent from the rootful store.
        if not rebuild and cached and cached[0] == "docker-archive":
            return {"changed": False, "image_id": cached[1]}
        try:
            podman("pull", "--quiet", "--retry=0", ref, timeout=600)
        except (TransportError, subprocess.TimeoutExpired):
            if rebuild or cached is None:
                raise
            print(
                "Using the protected OCI archive offline. Original health check metadata "
                "cannot be verified or recovered without the pinned source.",
                file=sys.stderr,
            )
            return {"changed": False, "image_id": cached[1]}
        source = exact_source(ref)
        if source is None:
            raise TransportError("pulled image cannot be resolved by its exact reference")
    source_id, runnable = source
    if (
        not rebuild
        and cached
        and cached[1] == source_id
        and (cached[0] == "docker-archive" or not runnable)
    ):
        return {"changed": False, "image_id": source_id}
    podman("tag", ref, tag)
    with tempfile.TemporaryDirectory(prefix=".image-", dir=archive.parent) as directory:
        temporary = Path(directory) / "image.tar"
        formats = ("docker-archive",) if runnable else ("oci-archive", "docker-archive")
        for archive_format in formats:
            podman(
                "save",
                "--quiet",
                "--format",
                archive_format,
                "--output",
                str(temporary),
                tag,
                timeout=600,
            )
            saved = archive_image(temporary, tag)
            if saved == (archive_format, source_id):
                break
            if saved is None or saved[0] != archive_format:
                raise TransportError("saved archive does not match the expected format")
            # OCI conversion can change a Docker config even without a health check.
            temporary.unlink()
        else:
            raise TransportError("saved archive does not match the pinned image config ID")
        with temporary.open("rb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary, archive)
    return {"changed": True, "image_id": source_id}


def load_image(archive: Path, tag: str, expected: str, *, reload: bool = False) -> dict:
    def tagged_id():
        if not present("image", tag):
            return None
        return require_image_id(podman("image", "inspect", "--format", "{{.ID}}", tag))

    if not reload and tagged_id() == expected:
        return {"changed": False}
    cached = archive_image(archive, tag)
    if cached is None or cached[1] != expected:
        raise TransportError("archive does not match the expected image config ID")
    podman("load", "--quiet", "--input", str(archive), timeout=600)
    if tagged_id() != expected:
        raise TransportError("loaded tag does not match the expected image config ID")
    return {"changed": True}


def container_drift(name: str, expected: str) -> dict:
    if not present("container", name):
        return {"drift": False}
    actual = require_image_id(podman("container", "inspect", "--format", "{{.Image}}", name))
    return {"drift": actual != expected}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("archive", type=Path)
    prepare.add_argument("ref")
    prepare.add_argument("tag")
    prepare.add_argument("--rebuild", action="store_true")
    load = commands.add_parser("load")
    load.add_argument("archive", type=Path)
    load.add_argument("tag")
    load.add_argument("expected")
    load.add_argument("--reload", action="store_true")
    drift = commands.add_parser("drift")
    drift.add_argument("container")
    drift.add_argument("expected")
    args = parser.parse_args()
    try:
        if args.operation != "drift" and (
            args.archive.parent != ARCHIVE_DIR
            or not re.fullmatch(r"[a-f0-9]{64}\.tar", args.archive.name)
            or not LOCAL_TAG.fullmatch(args.tag)
        ):
            raise TransportError("invalid image archive path or local tag")
        if args.operation == "prepare":
            if os.geteuid() != 0 or not PINNED_REF.fullmatch(args.ref):
                raise TransportError(
                    "archive preparation requires root and a pinned image reference"
                )
            result = prepare_archive(args.archive, args.ref, args.tag, rebuild=args.rebuild)
        elif args.operation == "load":
            result = load_image(
                args.archive, args.tag, require_image_id(args.expected), reload=args.reload
            )
        else:
            if not CONTAINER_NAME.fullmatch(args.container):
                raise TransportError("invalid managed container name")
            result = container_drift(args.container, require_image_id(args.expected))
    except (
        TransportError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        tarfile.TarError,
        subprocess.TimeoutExpired,
    ) as exc:
        parser.exit(1, f"Image transport failed: {exc}\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
