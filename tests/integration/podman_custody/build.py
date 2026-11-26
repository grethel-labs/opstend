#!/usr/bin/env python3
"""Authenticate pinned Ubuntu inputs and build a private custody fixture bundle."""

import argparse
import json
import lzma
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from verify import (
    BINARY_NAME,
    BUILD_ISOLATION,
    BUILD_OPTIONS,
    BUILDER,
    BUILDINFO_NAME,
    DOCS_PATCH,
    MANIFEST_NAME,
    PATCH,
    PROTOCOL,
    VerificationError,
    file_hash,
    input_hashes,
    load_lock,
    require_host,
)

ARCHIVE_KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"


def _fields(stanza: list[str]) -> dict[str, str]:
    fields = {}
    key = ""
    for line in stanza:
        if not line:
            continue
        if line.startswith((" ", "\t")):
            fields[key] += "\n" + line.strip()
        else:
            key, value = line.split(":", 1)
            fields[key] = value.strip()
    return fields


def _archive_record(index: Path, lock: dict) -> dict[str, str]:
    with lzma.open(index, "rt") as stream:
        stanza = []
        for line in stream:
            if line.strip():
                stanza.append(line.rstrip("\n"))
                continue
            if f"Package: {lock['package']}" in stanza and f"Version: {lock['version']}" in stanza:
                return _fields(stanza)
            stanza.clear()
    raise VerificationError(f"pinned Podman version missing from {index.name}")


def _checksum_table(value: str) -> dict[str, str]:
    return {
        name: digest for digest, _size, name in (row.split() for row in value.splitlines() if row)
    }


def _copy_checked(source: Path, target: Path, expected_sha256: str) -> None:
    shutil.copyfile(source, target)
    if file_hash(target) != expected_sha256:
        raise VerificationError(f"SHA-256 mismatch for {source.name}")


def authenticate_sources(input_dir: Path, work: Path, lock: dict) -> Path:
    """Verify the signed indexes and stage the exact distro source files."""
    archive = lock["archive"]
    signed = work / "InRelease"
    _copy_checked(input_dir / signed.name, signed, archive["inrelease"]["sha256"])
    release = work / "Release"
    status = subprocess.check_output(
        [
            "/usr/bin/gpgv",
            "--keyring",
            ARCHIVE_KEYRING,
            "--status-fd",
            "1",
            "--output",
            str(release),
            str(signed),
        ],
        text=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(work)},
    )
    valid_signers = [
        line.split()[2] for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")
    ]
    if valid_signers != [archive["inrelease"]["signing_key"]]:
        raise VerificationError("Ubuntu InRelease signer does not match the lock")
    release_metadata = _fields(release.read_text().splitlines())
    if release_metadata["Codename"] != lock["ubuntu_codename"]:
        raise VerificationError("signed archive codename does not match the lock")
    released = _checksum_table(release_metadata["SHA256"])
    records = {}
    for name in ("sources", "packages"):
        index = archive[name]
        if index["sha256"] != released.get(index["path"]):
            raise VerificationError("signed Ubuntu index digest does not match the lock")
        staged = work / Path(index["path"]).name
        _copy_checked(input_dir / staged.name, staged, index["sha256"])
        records[name] = _archive_record(staged, lock)
    source_record = records["sources"]
    if (
        source_record["Directory"] != archive["source_directory"]
        or _checksum_table(source_record["Checksums-Sha256"]) != archive["source_files"]
    ):
        raise VerificationError("signed Podman source inputs do not match the lock")
    binary_record = records["packages"]
    if (
        binary_record["Architecture"] != lock["architecture"]
        or binary_record["Filename"] != archive["binary_package"]["path"]
        or binary_record["SHA256"] != archive["binary_package"]["sha256"]
    ):
        raise VerificationError("signed Podman binary package metadata does not match the lock")
    for name, digest in archive["source_files"].items():
        _copy_checked(input_dir / name, work / name, digest)
    return work / f"{lock['package']}_{lock['version']}.dsc"


def _one(work: Path, pattern: str) -> Path:
    paths = list(work.glob(pattern))
    if len(paths) != 1:
        raise VerificationError(f"expected exactly one native build output matching {pattern}")
    return paths[0]


def _build(input_dir: Path, work: Path, output: Path) -> None:
    lock = load_lock()
    require_host(lock)
    hashes = input_hashes()
    dsc = authenticate_sources(input_dir, work, lock)
    source = work / "source"
    home = work / "home"
    home.mkdir(mode=0o700)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "LC_ALL": "C.UTF-8",
        "GOTOOLCHAIN": "local",
        "GOPROXY": "off",
        **BUILD_OPTIONS,
    }
    subprocess.run(["/usr/bin/dpkg-source", "--no-check", "-x", dsc, source], check=True, env=env)
    subprocess.run(["/usr/bin/dpkg-checkbuilddeps", "-B"], check=True, cwd=source, env=env)
    for patch_input, hash_field in ((PATCH, "patch_sha256"), (DOCS_PATCH, "docs_patch_sha256")):
        patch = work / patch_input.name
        _copy_checked(patch_input, patch, hashes[hash_field])
        subprocess.run(
            ["/usr/bin/patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", patch],
            cwd=source,
            env=env,
            check=True,
        )
    subprocess.run(
        [*BUILD_ISOLATION.split(), *BUILDER.split()],
        cwd=source,
        env=env,
        umask=0o022,
        check=True,
    )
    artifact = work / Path(lock["archive"]["binary_package"]["path"]).name
    package_metadata = subprocess.check_output(
        [
            "/usr/bin/dpkg-deb",
            "--show",
            "--showformat=${Package} ${Version} ${Architecture}",
            artifact,
        ],
        text=True,
        env=env,
    )
    if package_metadata != f"{lock['package']} {lock['version']} {lock['architecture']}":
        raise VerificationError("native binary package does not match the custody profile")
    extracted = work / "package"
    subprocess.run(["/usr/bin/dpkg-deb", "-x", artifact, extracted], check=True, env=env)
    binary = output / BINARY_NAME
    shutil.copyfile(extracted / "usr/bin/podman", binary)
    binary.chmod(0o700)
    if file_hash(binary) == lock["archive"]["binary_package"]["podman_sha256"]:
        raise VerificationError("native build returned the stock Ubuntu executable")
    capability = subprocess.check_output(
        [*BUILD_ISOLATION.split(), binary, "pod", "steward-custody-v1", "protocol"],
        cwd=home,
        env=env,
        text=True,
    )
    if capability != f"{PROTOCOL}\n":
        raise VerificationError("native binary did not advertise the expected custody protocol")
    buildinfo = _one(work, f"podman_*_{lock['architecture']}.buildinfo")
    record = _fields(buildinfo.read_text().splitlines())
    if (
        not record.get("Installed-Build-Depends")
        or record.get("Build-Architecture") != lock["architecture"]
    ):
        raise VerificationError("native build did not record its installed build dependencies")
    shutil.copyfile(buildinfo, output / BUILDINFO_NAME)

    manifest = {
        "schema": 1,
        "protocol": PROTOCOL,
        "profile": lock["profile"],
        "package": lock["package"],
        "version": lock["version"],
        "architecture": lock["architecture"],
        "runtime": lock["runtime"],
        "builder": BUILDER,
        "build_isolation": BUILD_ISOLATION,
        "build_options": BUILD_OPTIONS,
        **hashes,
        "binary_sha256": file_hash(binary),
        "buildinfo_sha256": file_hash(output / BUILDINFO_NAME),
    }
    manifest_path = output / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    print(f"{file_hash(manifest_path)}  {manifest_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path, help="directory containing the pinned archive inputs")
    parser.add_argument("output", type=Path, nargs="?", help="new private bundle directory")
    parser.add_argument(
        "--authenticate-only", action="store_true", help="check pinned archive files"
    )
    args = parser.parse_args()
    if args.authenticate_only == (args.output is not None):
        parser.error("select either --authenticate-only or a new output directory")
    if not args.authenticate_only and os.geteuid() == 0:
        parser.error("build the fixture in an unprivileged native build environment")
    os.umask(0o077)
    try:
        if args.authenticate_only:
            with tempfile.TemporaryDirectory() as temporary:
                dsc = authenticate_sources(args.inputs, Path(temporary), load_lock())
                print(f"{file_hash(dsc)}  {dsc.name}")
            return
        args.output.mkdir(mode=0o700)
        try:
            with tempfile.TemporaryDirectory(dir=args.output) as temporary:
                _build(args.inputs, Path(temporary).resolve(), args.output)
        except BaseException:
            shutil.rmtree(args.output)
            raise
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"custody build failed: {error}\n")


if __name__ == "__main__":
    main()
