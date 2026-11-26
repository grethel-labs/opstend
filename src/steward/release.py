"""Verifiable release: SBOM, provenance, detached signature and fail-closed verifier.

A release directory (``dist/release``) holds the artifacts listed in
``manifest.json``. This module adds, next to them:

* ``accepted-subset.json``: the feature subset the release claims, taken from the
  maintained file ``release/accepted-subset.yml``;
* ``sbom.cdx.json``: a CycloneDX 1.5 software bill of materials built from the
  exported ``requirements.txt`` pins, the wheel and the web UI lock file;
* ``provenance.intoto.json``: an in-toto statement (SLSA provenance v1 predicate)
  naming every released file as a subject plus the source commit and lock files;
* ``manifest.json.sig``: a detached Ed25519 signature over the exact bytes of
  ``manifest.json``. The manifest binds the hashes of every other file.

Trust model: the verifier takes the *public* key from the caller (obtained out of
band), never from the release directory. The private key is supplied only by
reference (``file:`` or ``env:``, see ``core.secrets``) and is never written to
the release, logs or errors. Everything here fails closed: any unreadable,
unlisted, modified, mismatched or unsigned input is an error, and the success
message states only what was checked. Provenance is a statement made by the
signing build host; it is not an independent build attestation.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import uuid
import zlib
from collections.abc import Callable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any, BinaryIO

import yaml
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .core import canonical
from .core.secrets import SecretError, resolve

SCHEMA = 1
MANIFEST = "manifest.json"
SIGNATURE = "manifest.json.sig"
SBOM = "sbom.cdx.json"
PROVENANCE = "provenance.intoto.json"
SUBSET = "accepted-subset.json"
ATTESTATIONS = {"sbom": SBOM, "provenance": PROVENANCE, "subset": SUBSET}
SIGN_DOMAIN = b"steward-release-signature-v1\n"
BUILDER_ID = "steward:release-build/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
DEFAULT_SUBSET = Path("release") / "accepted-subset.yml"
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5000
_SHA256 = re.compile(r"[0-9a-f]{64}")
# Match executor.site_deployment.release_binding without a host runtime import.
_DEPLOY_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,39}")
_DEPLOY_FILE = re.compile(r"[A-Za-z0-9_+.-]+")
_ANSIBLE_VAULT_HEADER = b"$ANSIBLE_VAULT"
_GIT_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_FEATURE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")
_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")


class ReleaseError(Exception):
    """Raised for release preparation problems; verification collects errors instead."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(data: Any) -> bytes:
    return (json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def _safe_relative(name: Any) -> bool:
    if not isinstance(name, str) or not name or "\\" in name or "\x00" in name:
        return False
    parts = name.split("/")
    return not name.startswith("/") and all(p not in ("", ".", "..") for p in parts)


# ---- accepted subset ----------------------------------------------------------------


def parse_accepted_subset(data: Any) -> dict[str, Any]:
    """Validate and normalise the subset document (YAML or JSON content)."""
    if not isinstance(data, dict) or set(data) - {"schema", "features", "unsupported"}:
        raise ReleaseError("accepted subset: expected keys schema, features, unsupported")
    if data.get("schema") != SCHEMA:
        raise ReleaseError(f"accepted subset: schema must be {SCHEMA}")
    features = data.get("features")
    if not isinstance(features, list) or not features:
        raise ReleaseError("accepted subset: features must be a non-empty list")
    seen: set[str] = set()
    out = []
    for item in features:
        if not isinstance(item, dict) or set(item) != {"id", "description", "evidence"}:
            raise ReleaseError("accepted subset: each feature needs id, description, evidence")
        fid = item["id"]
        if not isinstance(fid, str) or not _FEATURE_ID.fullmatch(fid) or fid in seen:
            raise ReleaseError(f"accepted subset: invalid or duplicate feature id {fid!r}")
        seen.add(fid)
        for key in ("description", "evidence"):
            if not isinstance(item[key], str) or not item[key].strip() or len(item[key]) > 500:
                raise ReleaseError(f"accepted subset: feature {fid}: {key} must be 1-500 chars")
        out.append(
            {k: item[k].strip() if k != "id" else fid for k in ("id", "description", "evidence")}
        )
    unsupported = data.get("unsupported", [])
    if not isinstance(unsupported, list) or not all(
        isinstance(u, str) and u.strip() and len(u) <= 500 for u in unsupported
    ):
        raise ReleaseError("accepted subset: unsupported must be a list of short strings")
    return {
        "schema": SCHEMA,
        "features": sorted(out, key=lambda f: f["id"]),
        "unsupported": sorted(u.strip() for u in unsupported),
    }


def load_accepted_subset(path: Path) -> dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ReleaseError(f"accepted subset {path}: unreadable ({type(exc).__name__})") from None
    return parse_accepted_subset(data)


# ---- dependency pins ----------------------------------------------------------------


@dataclass(frozen=True)
class Pin:
    name: str
    version: str
    hashes: tuple[str, ...]


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str) -> list[Pin]:
    """Parse an exported, hash-pinned requirements file. Anything unpinned is an error."""
    pins: list[Pin] = []
    current: tuple[str, str, list[str]] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if match := _PIN.match(line):
            if current:
                pins.append(Pin(current[0], current[1], tuple(current[2])))
            current = (normalize_name(match.group(1)), match.group(2), [])
        elif not line.startswith("--hash=sha256:"):
            raise ReleaseError(f"requirements: line is not an exact pin: {line[:80]!r}")
        if current is None:
            raise ReleaseError("requirements: hash before any requirement")
        current[2].extend(_HASH.findall(line))
    if current:
        pins.append(Pin(current[0], current[1], tuple(current[2])))
    for pin in pins:
        if not pin.hashes:
            raise ReleaseError(f"requirements: {pin.name}=={pin.version} has no sha256 hash")
    if len({p.name for p in pins}) != len(pins):
        raise ReleaseError("requirements: duplicate package pin")
    return sorted(pins, key=lambda p: p.name)


def installed_license(name: str) -> str | None:
    """License string from installed distribution metadata, if any (build environment)."""
    try:
        meta = metadata.metadata(name)
    except metadata.PackageNotFoundError:
        return None
    value = meta.get("License-Expression") or meta.get("License")
    if value and len(value) <= 100 and "\n" not in value:
        return value.strip()
    return None


# ---- SBOM ---------------------------------------------------------------------------


def build_sbom(
    *,
    version: str,
    wheel: str,
    wheel_sha256: str,
    requirements: str,
    npm_lock: Mapping[str, Any] | None,
    license_lookup: Callable[[str], str | None] = installed_license,
    project_license: str = "Apache-2.0",
) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for pin in parse_requirements(requirements):
        item: dict[str, Any] = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{pin.name}@{pin.version}",
            "name": pin.name,
            "version": pin.version,
            "purl": f"pkg:pypi/{pin.name}@{pin.version}",
            "scope": "required",
            "hashes": [{"alg": "SHA-256", "content": h} for h in sorted(set(pin.hashes))],
        }
        lic = license_lookup(pin.name)
        if lic:
            item["licenses"] = [{"expression": lic}]
        else:
            item["properties"] = [{"name": "steward:license", "value": "unknown"}]
        components.append(item)
    for key, entry in sorted((npm_lock or {}).get("packages", {}).items()):
        if not key.startswith("node_modules/") or not entry.get("version"):
            continue
        name = key.rsplit("node_modules/", 1)[1]
        purl = f"pkg:npm/{name.replace('@', '%40', 1)}@{entry['version']}"
        item = {
            "type": "library",
            "bom-ref": f"{purl}#{key}",
            "name": name,
            "version": entry["version"],
            "purl": purl,
            # Dev dependencies are build tools: recorded, but not shipped in the release.
            "scope": "excluded" if entry.get("dev") else "required",
        }
        integrity = entry.get("integrity", "")
        if integrity.startswith("sha512-"):
            try:
                digest = base64.b64decode(integrity[7:], validate=True).hex()
                item["hashes"] = [{"alg": "SHA-512", "content": digest}]
            except (binascii.Error, ValueError):
                pass
        if isinstance(entry.get("license"), str):
            item["licenses"] = [{"expression": entry["license"]}]
        else:
            item["properties"] = [{"name": "steward:license", "value": "unknown"}]
        components.append(item)
    serial = uuid.uuid5(uuid.NAMESPACE_URL, canonical.canonical_json([version, wheel_sha256]))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": f"pkg:pypi/steward@{version}",
                "name": "steward",
                "version": version,
                "purl": f"pkg:pypi/steward@{version}",
                "licenses": [{"license": {"id": project_license}}],
                "hashes": [{"alg": "SHA-256", "content": wheel_sha256}],
                "properties": [{"name": "steward:wheel", "value": wheel}],
            },
            "tools": {"components": [{"type": "application", "name": "steward-release"}]},
        },
        "components": components,
    }


# ---- provenance ---------------------------------------------------------------------


def build_provenance(
    *,
    version: str,
    files: Mapping[str, str],
    subset_sha256: str,
    source: Mapping[str, Any],
    lock_digests: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": name, "digest": {"sha256": digest}} for name, digest in sorted(files.items())
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILDER_ID,
                "externalParameters": {"version": version, "accepted_subset_sha256": subset_sha256},
                "resolvedDependencies": [
                    {"name": name, "digest": {"sha256": digest}}
                    for name, digest in sorted(lock_digests.items())
                ],
            },
            "runDetails": {
                "builder": {"id": BUILDER_ID},
                "metadata": {
                    "source_commit": source.get("commit", ""),
                    "source_dirty": bool(source.get("dirty", True)),
                    "self_attested": True,
                },
            },
        },
    }


def source_state(root: Path) -> dict[str, Any]:
    """Commit id and dirtiness of the source tree; unknown state counts as dirty."""

    def git(*args: str) -> str | None:
        try:
            done = subprocess.run(
                ["git", *args], cwd=root, capture_output=True, text=True, timeout=30, check=True
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return done.stdout.strip()

    commit = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--untracked-files=no")
    if not commit or not _GIT_COMMIT.fullmatch(commit):
        return {"commit": "", "dirty": True}
    return {"commit": commit, "dirty": status is None or bool(status)}


# ---- signing ------------------------------------------------------------------------


def key_id(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def generate_keypair(private_path: Path, public_path: Path) -> str:
    """Write a new Ed25519 pair (private 0600, never overwritten). Returns the key id."""
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(private_pem)
    with open(public_path, "xb") as handle:
        handle.write(public_pem)
    return key_id(key.public_key())


def load_private_key(ref: str, *, forbidden_root: Path | None = None) -> Ed25519PrivateKey:
    """Resolve a signing key by reference. Keys inside the repository tree are refused."""
    kind, _, target = ref.partition(":")
    if kind not in {"file", "env"} or not target or any(c in ref for c in "\n\r\0"):
        raise ReleaseError("signing key reference must use file:/path or env:NAME")
    try:
        pem = (
            _read_private_key_file(target, forbidden_root)
            if kind == "file"
            else resolve(ref).encode()
        )
        key = serialization.load_pem_private_key(pem, password=None)
    except SecretError as exc:
        raise ReleaseError(f"signing key reference unusable: {exc}") from None
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ReleaseError("signing key reference does not hold an unencrypted PEM key") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise ReleaseError("signing key must be Ed25519")
    return key


def _open_without_following(path: str, flags: int) -> int:
    return os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)


def _read_private_key_file(target: str, forbidden_root: Path | None) -> bytes:
    try:
        path = Path(target).expanduser().resolve(strict=True)
        if forbidden_root is not None and path.is_relative_to(forbidden_root.resolve()):
            raise ReleaseError("signing key file must be outside the repository tree")
        with open(path, "rb", opener=_open_without_following) as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ReleaseError("signing key file must be a regular file")
            if info.st_mode & 0o077:
                raise ReleaseError("signing key file permissions too open, expected 0600")
            if path.resolve(strict=True) != path or not os.path.samestat(info, path.lstat()):
                raise ReleaseError("signing key file changed while opening")
            return handle.read().strip()
    except (OSError, RuntimeError) as exc:
        raise ReleaseError(f"signing key file is unreadable ({type(exc).__name__})") from None


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError):
        raise ReleaseError(f"trusted public key {path} is unreadable or not PEM") from None
    if not isinstance(key, Ed25519PublicKey):
        raise ReleaseError("trusted public key must be Ed25519")
    return key


def sign_manifest(release_dir: Path, private: Ed25519PrivateKey) -> dict[str, Any]:
    manifest_bytes = (release_dir / MANIFEST).read_bytes()
    document = {
        "schema": SCHEMA,
        "algorithm": "ed25519",
        "key_id": key_id(private.public_key()),
        "signed_file": MANIFEST,
        "manifest_sha256": _sha256_bytes(manifest_bytes),
        "signature": base64.b64encode(private.sign(SIGN_DOMAIN + manifest_bytes)).decode(),
    }
    (release_dir / SIGNATURE).write_bytes(_json_bytes(document))
    return document


# ---- build --------------------------------------------------------------------------


def finalize_release(
    release_dir: Path,
    *,
    version: str,
    files: Mapping[str, str],
    wheel: str,
    root: Path,
    subset_path: Path,
    signing_key: Ed25519PrivateKey | None = None,
    license_lookup: Callable[[str], str | None] = installed_license,
    source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Write subset, SBOM, provenance, manifest and (optionally) the signature.

    ``files`` is the hash map of the already built artifacts (without manifest and
    attestations). Returns the manifest document.
    """
    if wheel not in files:
        raise ReleaseError("wheel is not part of the release files")
    if f"steward-{version}-" not in wheel:
        raise ReleaseError(f"wheel {wheel} does not match version {version}")
    subset = load_accepted_subset(subset_path)
    requirements = (release_dir / "requirements.txt").read_text(encoding="utf-8")
    lock_path = root / "webapp" / "package-lock.json"
    npm_lock = json.loads(lock_path.read_text(encoding="utf-8")) if lock_path.is_file() else None
    subset_bytes = _json_bytes(subset)
    (release_dir / SUBSET).write_bytes(subset_bytes)
    sbom = build_sbom(
        version=version,
        wheel=wheel,
        wheel_sha256=files[wheel],
        requirements=requirements,
        npm_lock=npm_lock,
        license_lookup=license_lookup,
    )
    (release_dir / SBOM).write_bytes(_json_bytes(sbom))
    locks = {
        str(p.relative_to(root)): sha256_file(p)
        for p in (root / "uv.lock", lock_path)
        if p.is_file()
    }
    provenance = build_provenance(
        version=version,
        files=files,
        subset_sha256=_sha256_bytes(subset_bytes),
        source=source if source is not None else source_state(root),
        lock_digests=locks,
    )
    (release_dir / PROVENANCE).write_bytes(_json_bytes(provenance))
    manifest = {
        "version": version,
        "wheel": wheel,
        "files": dict(files),
        "attestations": {
            key: {"path": name, "sha256": sha256_file(release_dir / name)}
            for key, name in ATTESTATIONS.items()
        },
    }
    (release_dir / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
    (release_dir / SIGNATURE).unlink(missing_ok=True)
    if signing_key is not None:
        sign_manifest(release_dir, signing_key)
    return manifest


# ---- archive ------------------------------------------------------------------------


def pack_release(release_dir: Path, output: Path) -> str:
    """Deterministic tar.gz of a release directory. Returns its sha256."""
    top = f"steward-release-{json.loads((release_dir / MANIFEST).read_bytes())['version']}"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(release_dir.rglob("*")):
            relative = path.relative_to(release_dir).as_posix()
            if path.is_symlink():
                raise ReleaseError(f"release contains a symlink: {relative}")
            info = tarfile.TarInfo(f"{top}/{relative}")
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if path.is_dir():
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            elif path.is_file():
                info.size, info.mode = path.stat().st_size, 0o644
                with open(path, "rb") as handle:
                    tar.addfile(info, handle)
            else:
                raise ReleaseError(f"release contains a special file: {relative}")
    with (
        open(output, "xb") as raw,
        gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz,
    ):
        gz.write(buffer.getvalue())
    return sha256_file(output)


def _extract_archive(archive: Path, destination: Path, *, strict: bool = False) -> Path:
    """Extract only regular files and directories under a single top directory."""
    if strict:
        # Read the gzip trailer before trusting the tar. TarFile normally stops
        # at the tar end marker, which can leave a broken gzip trailer unread.
        with tempfile.TemporaryFile(dir=destination) as decoded:
            _decode_archive(archive, decoded)
            with tarfile.open(fileobj=decoded, mode="r:") as tar:
                return _extract_tar(tar, destination, strict=True)
    with tarfile.open(archive, "r:gz") as tar:
        return _extract_tar(tar, destination)


def _decode_archive(archive: Path, decoded: BinaryIO) -> None:
    # Allow tar headers, file padding and extended names in addition to file bytes.
    remaining = MAX_FILE_BYTES + 8 * tarfile.BLOCKSIZE * MAX_ARCHIVE_MEMBERS + tarfile.RECORDSIZE
    with open(archive, "rb", opener=_open_without_following) as raw:
        if not stat.S_ISREG(os.fstat(raw.fileno()).st_mode):
            raise ReleaseError("input must be a regular release archive")
        with gzip.GzipFile(fileobj=raw, mode="rb") as compressed:
            for chunk in iter(lambda: compressed.read(1 << 20), b""):
                remaining -= len(chunk)
                if remaining < 0:
                    raise ReleaseError("archive content is too large")
                decoded.write(chunk)
    decoded.seek(0)


def _extract_tar(tar: tarfile.TarFile, destination: Path, *, strict: bool = False) -> Path:
    members = []
    paths = set()
    total = 0
    for member in tar:
        if len(members) >= MAX_ARCHIVE_MEMBERS:
            raise ReleaseError("archive has too many members")
        if not (member.isfile() or member.isdir()) or not _safe_relative(member.name):
            raise ReleaseError(f"archive member not allowed: {member.name[:80]!r}")
        if strict:
            if member.name in paths:
                raise ReleaseError(f"archive has a duplicate member: {member.name[:80]!r}")
            if (
                member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                or member.size < 0
                or member.issparse()
                or (member.isdir() and member.size != 0)
                or (member.isfile() and "/" not in member.name)
            ):
                raise ReleaseError(f"archive member not allowed: {member.name[:80]!r}")
            paths.add(member.name)
        total += member.size
        if total > MAX_FILE_BYTES:
            raise ReleaseError("archive content is too large")
        members.append(member)
    tops = {m.name.split("/", 1)[0] for m in members}
    if len(tops) != 1:
        raise ReleaseError("archive must contain exactly one top-level directory")
    if strict:
        tar.fileobj.seek(tar.offset)
        end_marker = b"\0" * (2 * tarfile.BLOCKSIZE)
        if tar.fileobj.read(len(end_marker)) != end_marker or any(
            chunk.strip(b"\0") for chunk in iter(lambda: tar.fileobj.read(1 << 20), b"")
        ):
            raise ReleaseError("archive has an invalid tar end marker or trailing content")
    tar.extractall(destination, members=members, filter="data")
    return destination / tops.pop()


# ---- verification -------------------------------------------------------------------


@dataclass
class VerifyReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    version: str = ""
    key_id: str = ""
    features: list[str] = field(default_factory=list)
    file_count: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors

    def fail(self, message: str) -> None:
        self.errors.append(message)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate JSON key")
    return obj


def _load_json(path: Path, report: VerifyReport, label: str) -> Any | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("too large")
        data = path.read_bytes()
    except (OSError, ValueError):
        report.fail(f"{label} is missing or not valid JSON")
        return None
    return _parse_json(data, report, label)


def _parse_json(data: bytes, report: VerifyReport, label: str) -> Any | None:
    try:
        if len(data) > MAX_FILE_BYTES:
            raise ValueError("too large")
        doc = json.loads(data, object_pairs_hook=_unique_json_object)
        if doc is None:
            raise ValueError("unexpected null document")
        return doc
    except (ValueError, RecursionError):
        report.fail(f"{label} is missing or not valid JSON")
        return None


def _regular(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _check_signature(
    release_dir: Path, trusted: Ed25519PublicKey, report: VerifyReport
) -> bytes | None:
    if not _regular(release_dir / SIGNATURE):
        report.fail(f"release is unsigned: {SIGNATURE} is missing")
        return None
    if not _regular(release_dir / MANIFEST):
        report.fail(f"{MANIFEST} is missing")
        return None
    doc = _load_json(release_dir / SIGNATURE, report, SIGNATURE)
    if doc is None:
        return None
    expected_keys = {"schema", "algorithm", "key_id", "signed_file", "manifest_sha256", "signature"}
    if not isinstance(doc, dict) or set(doc) != expected_keys:
        report.fail("signature file has an unexpected structure")
        return None
    if doc["schema"] != SCHEMA or doc["algorithm"] != "ed25519" or doc["signed_file"] != MANIFEST:
        report.fail("signature file declares an unsupported scheme")
        return None
    trusted_id = key_id(trusted)
    if doc["key_id"] != trusted_id:
        report.fail("signature was made by a key that is not the trusted key")
        return None
    manifest_bytes = (release_dir / MANIFEST).read_bytes()
    if doc["manifest_sha256"] != _sha256_bytes(manifest_bytes):
        report.fail("manifest does not match the signed manifest hash")
        return None
    try:
        signature = base64.b64decode(str(doc["signature"]), validate=True)
        trusted.verify(signature, SIGN_DOMAIN + manifest_bytes)
    except (binascii.Error, ValueError, InvalidSignature):
        report.fail("signature is invalid for this manifest")
        return None
    report.key_id = trusted_id
    return manifest_bytes


def _check_manifest_shape(manifest: Any, report: VerifyReport) -> bool:
    ok = isinstance(manifest, dict) and set(manifest) == {
        "version",
        "wheel",
        "files",
        "attestations",
    }
    ok = ok and isinstance(manifest["version"], str) and isinstance(manifest["wheel"], str)
    ok = ok and isinstance(manifest["files"], dict) and isinstance(manifest["attestations"], dict)
    if ok:
        ok = all(
            _safe_relative(n) and isinstance(h, str) and _SHA256.fullmatch(h)
            for n, h in manifest["files"].items()
        )
        ok = ok and manifest["wheel"] in manifest["files"] and manifest["files"]
        att = manifest["attestations"]
        ok = ok and set(att) == set(ATTESTATIONS)
        ok = ok and all(
            isinstance(att[k], dict)
            and att[k].get("path") == name
            and isinstance(att[k].get("sha256"), str)
            and _SHA256.fullmatch(att[k]["sha256"])
            for k, name in ATTESTATIONS.items()
        )
        ok = ok and not set(manifest["files"]) & set(ATTESTATIONS.values())
    if not ok:
        report.fail("manifest has an unexpected structure")
    return bool(ok)


def _check_files(release_dir: Path, manifest: dict[str, Any], report: VerifyReport) -> bool:
    expected = dict(manifest["files"])
    expected.update({a["path"]: a["sha256"] for a in manifest["attestations"].values()})
    clean = True
    for name, digest in sorted(expected.items()):
        path = release_dir / name
        if not _regular(path):
            report.fail(f"listed file is missing or not a regular file: {name}")
            clean = False
        elif sha256_file(path) != digest:
            report.fail(f"file does not match the manifest: {name}")
            clean = False
    present = set()
    for path in release_dir.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        relative = path.relative_to(release_dir).as_posix()
        if not stat.S_ISREG(mode):
            report.fail(f"release contains a non-regular entry: {relative}")
            clean = False
        present.add(relative)
    for extra in sorted(present - set(expected) - {MANIFEST, SIGNATURE}):
        report.fail(f"file is not listed in the manifest: {extra}")
        clean = False
    report.file_count = len(expected)
    return clean


def _check_subset(release_dir: Path, report: VerifyReport) -> dict[str, Any] | None:
    raw = _load_json(release_dir / SUBSET, report, SUBSET)
    if raw is None:
        return None
    try:
        subset = parse_accepted_subset(raw)
    except ReleaseError as exc:
        report.fail(str(exc))
        return None
    if subset != raw:
        report.fail("accepted subset is not in normalised form")
        return None
    report.features = [f["id"] for f in subset["features"]]
    return subset


def _check_sbom(release_dir: Path, manifest: dict[str, Any], report: VerifyReport) -> None:
    sbom = _load_json(release_dir / SBOM, report, SBOM)
    if sbom is None:
        return
    if (
        not isinstance(sbom, dict)
        or sbom.get("bomFormat") != "CycloneDX"
        or sbom.get("specVersion") != "1.5"
    ):
        report.fail("SBOM is not CycloneDX 1.5")
        return
    sbom_metadata = sbom.get("metadata")
    root = sbom_metadata.get("component") if isinstance(sbom_metadata, dict) else None
    components = sbom.get("components")
    if (
        not isinstance(root, dict)
        or not isinstance(components, list)
        or not all(isinstance(component, dict) for component in components)
    ):
        report.fail("SBOM has an unexpected structure")
        return
    python_components = [
        component
        for component in components
        if isinstance(component.get("purl"), str) and component["purl"].startswith("pkg:pypi/")
    ]
    try:
        hashes = _sbom_hashes(root)
        listed = {
            (component["name"], component["version"], _sbom_hashes(component))
            for component in python_components
        }
    except (KeyError, TypeError, ValueError):
        report.fail("SBOM has an unexpected structure")
        return
    wheel_hash = manifest["files"][manifest["wheel"]]
    if root.get("version") != manifest["version"] or hashes != {wheel_hash}:
        report.fail("SBOM root component does not match the released version and wheel")
    try:
        pins = parse_requirements((release_dir / "requirements.txt").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ReleaseError) as exc:
        report.fail(f"requirements.txt cannot be checked against the SBOM: {exc}")
        return
    wanted = {(p.name, p.version, frozenset(p.hashes)) for p in pins}
    if listed != wanted or len(listed) != len(python_components):
        report.fail("SBOM Python components differ from the pinned requirements.txt")
    unknown = sorted(
        str(c.get("name"))
        for c in components
        if c.get("scope") != "excluded" and not c.get("licenses")
    )
    if unknown:
        report.warnings.append(
            f"license unknown for {len(unknown)} shipped component(s): " + ", ".join(unknown[:5])
        )


def _sbom_hashes(component: dict[str, Any]) -> frozenset[str]:
    hashes = component.get("hashes")
    if not isinstance(hashes, list) or not all(
        isinstance(item, dict)
        and item.get("alg") == "SHA-256"
        and isinstance(item.get("content"), str)
        and _SHA256.fullmatch(item["content"])
        for item in hashes
    ):
        raise ValueError("unexpected SBOM hashes")
    return frozenset(item["content"] for item in hashes)


def _check_provenance(
    release_dir: Path, manifest: dict[str, Any], allow_dirty: bool, report: VerifyReport
) -> None:
    prov = _load_json(release_dir / PROVENANCE, report, PROVENANCE)
    if prov is None:
        return
    try:
        subjects = {s["name"]: s["digest"]["sha256"] for s in prov["subject"]}
        params = prov["predicate"]["buildDefinition"]["externalParameters"]
        meta = prov["predicate"]["runDetails"]["metadata"]
        valid = prov["_type"] == STATEMENT_TYPE and prov["predicateType"] == PREDICATE_TYPE
        valid = valid and len(subjects) == len(prov["subject"])
    except (KeyError, TypeError):
        report.fail("provenance has an unexpected structure")
        return
    if not isinstance(params, dict) or not isinstance(meta, dict):
        report.fail("provenance has an unexpected structure")
        return
    if not valid:
        report.fail("provenance is not an in-toto SLSA provenance v1 statement")
        return
    if subjects != manifest["files"]:
        report.fail("provenance subjects differ from the manifest files")
    if params.get("version") != manifest["version"]:
        report.fail("provenance version differs from the manifest")
    if params.get("accepted_subset_sha256") != manifest["attestations"]["subset"]["sha256"]:
        report.fail("provenance binds a different accepted subset")
    if not isinstance(meta.get("source_commit"), str) or not _GIT_COMMIT.fullmatch(
        meta["source_commit"]
    ):
        report.fail("provenance has no valid source commit")
    if meta.get("source_dirty") is not False:
        message = "release was built from a dirty or unknown source tree"
        (report.warnings if allow_dirty else report.errors).append(message)


def verify_release(
    target: Path, trusted_key: Ed25519PublicKey, *, allow_dirty: bool = False
) -> VerifyReport:
    """Verify a release directory or ``.tar.gz`` archive against a trusted public key."""
    report = VerifyReport()
    target = Path(target)
    try:
        if target.is_dir():
            return _verify_dir(target, trusted_key, allow_dirty, report)
        if target.is_file():
            with tempfile.TemporaryDirectory(prefix="steward-verify-") as scratch:
                try:
                    root = _extract_archive(target, Path(scratch))
                except (tarfile.TarError, OSError, EOFError, zlib.error, ReleaseError) as exc:
                    report.fail(f"archive cannot be read safely: {type(exc).__name__}")
                    return report
                return _verify_dir(root, trusted_key, allow_dirty, report)
        report.fail(f"{target}: no such release")
    except OSError as exc:
        report.fail(f"release cannot be read: {exc.strerror or type(exc).__name__}")
    return report


def _verify_dir(
    release_dir: Path, trusted: Ed25519PublicKey, allow_dirty: bool, report: VerifyReport
) -> VerifyReport:
    _verified_manifest(release_dir, trusted, allow_dirty, report)
    return report


def _verified_manifest(
    release_dir: Path, trusted: Ed25519PublicKey, allow_dirty: bool, report: VerifyReport
) -> dict[str, Any] | None:
    manifest_bytes = _check_signature(release_dir, trusted, report)
    if manifest_bytes is None:
        return None
    manifest = _parse_json(manifest_bytes, report, MANIFEST)
    _check_release_content(release_dir, manifest, allow_dirty, report)
    return manifest if report.ok else None


def _check_release_content(
    release_dir: Path, manifest: Any, allow_dirty: bool, report: VerifyReport
) -> None:
    if not _check_manifest_shape(manifest, report):
        return
    report.version = manifest["version"]
    if not _check_files(release_dir, manifest, report):
        return
    _check_subset(release_dir, report)
    _check_sbom(release_dir, manifest, report)
    _check_provenance(release_dir, manifest, allow_dirty, report)


def _deployment_payload(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    version, files, wheel = (manifest[key] for key in ("version", "files", "wheel"))
    if (
        not _DEPLOY_VERSION.fullmatch(version)
        or wheel != f"steward-{version}-py3-none-any.whl"
        or not 3 <= len(files) <= 4096
        or "requirements.txt" not in files
    ):
        raise ReleaseError("incomplete deployment release")
    expected_dirs = set()
    for name in files:
        # Ansible copy auto-decrypts files with this prefix before transfer.
        with (root / name).open("rb") as handle:
            if handle.read(len(_ANSIBLE_VAULT_HEADER)) == _ANSIBLE_VAULT_HEADER:
                raise ReleaseError(
                    f"deployment release contains an Ansible Vault file: {name[:80]!r}"
                )
        if name in (wheel, "requirements.txt"):
            continue
        parts = name.split("/")
        if (
            len(parts) < 3
            or parts[0] != "bundles"
            or not all(_DEPLOY_FILE.fullmatch(part) for part in parts)
        ):
            raise ReleaseError(f"invalid deployment release artifact: {name[:80]!r}")
        expected_dirs.update(Path(name).parents)

    # Recursive bundle copy must only create directories implied by signed files.
    for path in root.rglob("*"):
        if path.is_dir() and path.relative_to(root) not in expected_dirs:
            raise ReleaseError("deployment release contains an unlisted directory")
    return {"version": version, "files": files, "wheel": wheel, "dir": str(root)}


@contextmanager
def staged_verified_release(
    archive: Path, trusted_key: Ed25519PublicKey
) -> Iterator[dict[str, Any]]:
    """Yield the host payload from a private, verified deployment snapshot."""
    with ExitStack() as cleanup:
        try:
            scratch = Path(
                cleanup.enter_context(tempfile.TemporaryDirectory(prefix="steward-deploy-"))
            ).absolute()
            root = _extract_archive(Path(archive), scratch, strict=True)
            root = root.rename(scratch / "release")
        except ReleaseError as exc:
            raise ReleaseError(f"archive cannot be read safely: {exc}") from None
        except (
            tarfile.TarError,
            OSError,
            EOFError,
            zlib.error,
            ValueError,
            OverflowError,
            RecursionError,
        ) as exc:
            raise ReleaseError(f"archive cannot be read safely: {type(exc).__name__}") from None

        try:
            report = VerifyReport()
            manifest = _verified_manifest(root, trusted_key, False, report)
            if manifest is None:
                raise ReleaseError("\n".join(report.errors))
            payload = _deployment_payload(root, manifest)
        except (OSError, ValueError, RecursionError) as exc:
            raise ReleaseError(f"release cannot be verified: {type(exc).__name__}") from None
        yield payload


def sign_release_archive(
    archive: Path,
    output: Path,
    *,
    signing_key_ref: str,
    forbidden_root: Path | None = None,
) -> tuple[VerifyReport, str]:
    """Validate a clean unsigned archive, then sign and publish a new local file."""
    output = Path(output)
    report = VerifyReport()
    try:
        with tempfile.TemporaryDirectory(
            prefix=".steward-sign-", dir=output.parent, ignore_cleanup_errors=True
        ) as stage:
            staged = Path(stage) / "release.tar.gz"
            with tempfile.TemporaryDirectory(prefix="steward-sign-") as scratch:
                try:
                    root = _extract_archive(Path(archive), Path(scratch), strict=True)
                except ReleaseError as exc:
                    raise ReleaseError(f"archive cannot be read safely: {exc}") from None
                except OSError as exc:
                    reason = exc.strerror or type(exc).__name__
                    raise ReleaseError(f"archive cannot be read safely: {reason}") from None
                except (
                    tarfile.TarError,
                    EOFError,
                    zlib.error,
                    ValueError,
                    OverflowError,
                    RecursionError,
                ) as exc:
                    raise ReleaseError(
                        f"archive cannot be read safely: {type(exc).__name__}"
                    ) from None
                if (root / SIGNATURE).exists():
                    raise ReleaseError(f"release already contains {SIGNATURE}")
                manifest = _load_json(root / MANIFEST, report, MANIFEST)
                _check_release_content(root, manifest, False, report)
                if not report.ok:
                    raise ReleaseError("\n".join(report.errors))
                top = f"steward-release-{report.version}"
                if (
                    not _safe_relative(report.version)
                    or "/" in report.version
                    or not report.version.isprintable()
                    or len(os.fsencode(top)) > os.pathconf(root, "PC_NAME_MAX")
                ):
                    raise ReleaseError("manifest version is unsafe for an archive directory name")

                # Packing emits implicit parent directories as members too.
                members = list(root.rglob("*"))
                if len(members) + 1 > MAX_ARCHIVE_MEMBERS:
                    raise ReleaseError("signed archive would have too many members")
                file_bytes = sum(path.stat().st_size for path in members if path.is_file())
                private = load_private_key(signing_key_ref, forbidden_root=forbidden_root)
                signature = sign_manifest(root, private)
                if file_bytes + (root / SIGNATURE).stat().st_size > MAX_FILE_BYTES:
                    raise ReleaseError("signed archive content is too large")
                report.key_id = signature["key_id"]
                digest = pack_release(root, staged)

            # The extracted snapshot is cleaned up before committing the output.
            try:
                os.link(staged, output)
            except FileExistsError:
                raise ReleaseError(f"output already exists: {output}") from None
    except (OSError, ValueError, RuntimeError) as exc:
        reason = (exc.strerror or str(exc)) if isinstance(exc, OSError) else type(exc).__name__
        raise ReleaseError(f"cannot sign release archive: {reason}") from None
    return report, digest
