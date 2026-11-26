"""Verify the experimental custody artifact before passing its fd to the fixture."""

import errno
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOCK = HERE / "resolute-amd64.json"
PATCH = HERE / "podman.patch"
DOCS_PATCH = HERE / "podman-docs.patch"
RECIPE = HERE / "build.py"
MANIFEST_NAME = "manifest.json"
BINARY_NAME = "podman"
BUILDINFO_NAME = "podman.buildinfo"
PROTOCOL = "steward-pod-custody-v1"
BUILDER = "dpkg-buildpackage -B -us -uc"
BUILD_ISOLATION = "unshare --user --map-current-user --net"
BUILD_OPTIONS = {"DEB_BUILD_OPTIONS": "parallel=1 nocheck", "GOMAXPROCS": "1", "GOFLAGS": "-p=1"}
ELF_AMD64 = b"\x02\x01\x01"
MAX_MANIFEST_BYTES = 64 * 1024


class VerificationError(ValueError):
    """The artifact or host failed an admission check."""


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_lock() -> dict:
    return json.loads(LOCK.read_bytes())


def input_hashes() -> dict:
    return {
        "lock_sha256": file_hash(LOCK),
        "patch_sha256": file_hash(PATCH),
        "docs_patch_sha256": file_hash(DOCS_PATCH),
        "recipe_sha256": file_hash(RECIPE),
    }


def require_host(lock: dict) -> None:
    release = platform.freedesktop_os_release()
    if (
        platform.system() != "Linux"
        or platform.machine() != "x86_64"
        or release.get("ID") != "ubuntu"
        or release.get("VERSION_CODENAME") != lock["ubuntu_codename"]
    ):
        raise VerificationError("custody profile requires Ubuntu Resolute on Linux x86_64")


def _check_directory(fd: int) -> None:
    info = os.fstat(fd)
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise VerificationError("artifact directory and ancestors must be root-owned and protected")


def _check_file(fd: int, executable: bool) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o7022
        or (executable and not info.st_mode & stat.S_IXOTH)
    ):
        raise VerificationError(
            "artifact files must be protected, regular, root-owned single links"
        )
    if executable:
        try:
            os.getxattr(fd, "security.capability")
        except OSError as error:
            if error.errno not in (errno.ENODATA, errno.EOPNOTSUPP):
                raise
        else:
            raise VerificationError("artifact executable must have no file capabilities")


def _protected_file(path: Path, *, executable: bool = False) -> int:
    if not path.is_absolute() or ".." in path.parts or path.anchor != "/":
        raise VerificationError("artifact path must be absolute without parent traversal")
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", dir_flags)
    try:
        _check_directory(directory)
        for component in path.parts[1:-1]:
            child = os.open(component, dir_flags, dir_fd=directory)
            os.close(directory)
            directory = child
            _check_directory(directory)
        # Nonblocking open avoids hanging on a FIFO before fstat rejects it.
        fd = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=directory,
        )
        try:
            _check_file(fd, executable)
        except BaseException:
            os.close(fd)
            raise
        return fd
    finally:
        os.close(directory)


def _fd_hash(fd: int) -> str:
    with os.fdopen(os.dup(fd), "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch("[a-f0-9]{64}", value) is not None


def _unique_keys(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("duplicate manifest key")
        result[key] = value
    return result


def verify_runtime_package() -> None:
    """Check the fixture host against the authenticated distro package pin."""
    lock = load_lock()
    require_host(lock)
    installed = subprocess.check_output(
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${db:Status-Status} ${Version} ${Architecture}\n",
            lock["package"],
        ],
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        text=True,
    )
    if installed != f"installed {lock['version']} {lock['architecture']}\n":
        raise VerificationError("installed Podman package does not match the custody profile")
    fd = _protected_file(Path("/usr/bin/podman"), executable=True)
    try:
        if _fd_hash(fd) != lock["archive"]["binary_package"]["podman_sha256"]:
            raise VerificationError(
                "installed Podman executable does not match the published package"
            )
    finally:
        os.close(fd)


def verify_bundle(bundle: Path, expected_manifest_sha256: str, expected_profile: str) -> int:
    """Return the pinned Podman fd. The root caller owns it and must execute as fixture UID."""
    try:
        return _verify_bundle(bundle, expected_manifest_sha256, expected_profile)
    except (OSError, RecursionError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot verify custody artifact: {error}") from error


def _verify_bundle(bundle: Path, expected_manifest_sha256: str, expected_profile: str) -> int:
    if os.geteuid() != 0:
        raise VerificationError("artifact verification requires a root caller")
    if not _digest(expected_manifest_sha256):
        raise VerificationError("a trusted manifest SHA-256 is required")
    lock = load_lock()
    if expected_profile != lock["profile"]:
        raise VerificationError("unsupported custody profile")
    manifest_fd = _protected_file(bundle / MANIFEST_NAME)
    with os.fdopen(manifest_fd, "rb") as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES or hashlib.sha256(raw).hexdigest() != expected_manifest_sha256:
        raise VerificationError("manifest does not match the trusted digest")
    manifest = json.loads(raw, object_pairs_hook=_unique_keys)
    expected = {
        "schema": 1,
        "protocol": PROTOCOL,
        "profile": expected_profile,
        "package": lock["package"],
        "version": lock["version"],
        "architecture": lock["architecture"],
        "runtime": lock["runtime"],
        "builder": BUILDER,
        "build_isolation": BUILD_ISOLATION,
        "build_options": BUILD_OPTIONS,
        **input_hashes(),
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != expected.keys() | {"binary_sha256", "buildinfo_sha256"}
        or type(manifest["schema"]) is not int
        or any(manifest[field] != value for field, value in expected.items())
        or not _digest(manifest["binary_sha256"])
        or not _digest(manifest["buildinfo_sha256"])
        or manifest["binary_sha256"] == lock["archive"]["binary_package"]["podman_sha256"]
    ):
        raise VerificationError("manifest has stale or unbound artifact inputs")
    buildinfo_fd = _protected_file(bundle / BUILDINFO_NAME)
    try:
        if _fd_hash(buildinfo_fd) != manifest["buildinfo_sha256"]:
            raise VerificationError("build dependency record does not match the manifest")
    finally:
        os.close(buildinfo_fd)
    binary_fd = _protected_file(bundle / BINARY_NAME, executable=True)
    try:
        header = os.pread(binary_fd, 20, 0)
        if (
            len(header) != 20
            or header[:7] != b"\x7fELF" + ELF_AMD64
            or header[18:20] != b"\x3e\x00"
            or _fd_hash(binary_fd) != manifest["binary_sha256"]
        ):
            raise VerificationError("Podman ELF or digest does not match the manifest")
        os.lseek(binary_fd, 0, os.SEEK_SET)
    except BaseException:
        os.close(binary_fd)
        raise
    return binary_fd
