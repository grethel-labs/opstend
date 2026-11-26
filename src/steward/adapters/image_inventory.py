"""Offline package inventory of the validator's private, verified OCI layout."""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from tempfile import TemporaryFile

from steward.core.artifact_validation import MAX_COMPONENTS, SbomComponent
from steward.core.builder import DIGEST
from steward.core.process import CommandError, run_bounded
from steward.core.tools import TRIVY_BINARY, TRIVY_VERSION

_MAX_REPORT_BYTES = 8 * 1024 * 1024
_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_MAX_LOG_BYTES = 512 * 1024
_MAX_SECONDS = 120
_LOG = re.compile(rb"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\t(?:INFO|DEBUG)\t([^\t]+)")
_INCOMPLETE_MESSAGES = {b"Analysis error", b"Permission error"}
_LAYER_ENCODINGS = {
    "application/vnd.oci.image.layer.v1.tar": False,
    "application/vnd.oci.image.layer.v1.tar+gzip": True,
    "application/vnd.docker.image.rootfs.diff.tar": False,
    "application/vnd.docker.image.rootfs.diff.tar.gzip": True,
}
_OS = {
    "alpine": ("apk", "Alpine:v", r"(\d+\.\d+)(?:\.\d+)?"),
    "debian": ("dpkg", "Debian:", r"(\d+)(?:\.\d+)*"),
}
_LANGUAGE = {
    "node-pkg": ("node-pkg", "npm"),
    "python-pkg": ("python-pkg", "PyPI"),
}


class TrivyImageInventory:
    """Use pinned Trivy without a cache, advisory DB, sockets or network."""

    def __init__(self, binary: Path = TRIVY_BINARY):
        self._binary = binary

    def __call__(
        self, layout: Path, *, timeout: float = _MAX_SECONDS
    ) -> list[SbomComponent] | None:
        """Withhold inventory if the report is unavailable, unsupported or incomplete."""
        deadline = time.monotonic() + min(timeout, _MAX_SECONDS)
        try:
            if not self._binary.is_file():
                return None
            (descriptor,) = json.loads((layout / "index.json").read_bytes())["manifests"]
            digest = descriptor["digest"]
            if not DIGEST.fullmatch(digest):
                return None
            manifest = json.loads((layout / "blobs" / "sha256" / digest[7:]).read_bytes())
            diff_ids = _verified_diff_ids(layout, manifest, deadline)
            if diff_ids is None:
                return None
            target = f"/image@{digest}"
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                return None
            with TemporaryFile(dir=layout.parent) as log:
                raw = run_bounded(
                    [
                        "/usr/bin/prlimit",
                        "--as=2147483648:2147483648",
                        "--fsize=33554432:33554432",
                        "--",
                        "/usr/bin/bwrap",
                        "--unshare-all",
                        "--unshare-user",
                        "--disable-userns",
                        "--cap-drop",
                        "ALL",
                        "--die-with-parent",
                        "--ro-bind",
                        str(self._binary),
                        "/trivy",
                        "--ro-bind",
                        str(layout),
                        "/image",
                        "--dev",
                        "/dev",
                        "--proc",
                        "/proc",
                        "--size",
                        "134217728",
                        "--tmpfs",
                        "/scratch",
                        "--chdir",
                        "/scratch",
                        "/trivy",
                        "image",
                        "--input",
                        target,
                        "--scanners=",
                        "--list-all-pkgs",
                        "--detection-priority",
                        "comprehensive",
                        "--format",
                        "json",
                        "--offline-scan",
                        "--skip-db-update",
                        "--skip-java-db-update",
                        "--skip-version-check",
                        "--disable-telemetry",
                        "--debug",
                        "--cache-backend",
                        "memory",
                        "--cache-dir",
                        "/scratch",
                        "--parallel",
                        "1",
                        "--config",
                        "/dev/null",
                        "--ignorefile",
                        "/dev/null",
                        # Keep the embedded SBOM analyzer from substituting a producer's claims.
                        "--skip-files",
                        "**/*.spdx,**/*.spdx.json,**/*.cdx,**/*.cdx.json",
                        "--timeout",
                        f"{timeout:.3f}s",
                    ],
                    cwd=layout,
                    env={
                        "HOME": "/scratch",
                        "TMPDIR": "/scratch",
                        "GOMEMLIMIT": "512MiB",
                        "GOMAXPROCS": "2",
                    },
                    timeout=timeout,
                    max_bytes=_MAX_REPORT_BYTES,
                    stderr=log,
                )
                log.seek(0)
                messages = log.read(_MAX_LOG_BYTES + 1)
            if len(messages) > _MAX_LOG_BYTES:
                return None
            for line in messages.splitlines():
                match = _LOG.match(line)
                if match is None or match[1] in _INCOMPLETE_MESSAGES:
                    return None
            return _components(json.loads(raw), target, manifest, diff_ids)
        except (
            CommandError,
            OSError,
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
            RecursionError,
        ):
            return None


def _verified_diff_ids(layout: Path, manifest: dict, deadline: float) -> list[str] | None:
    config_digest = manifest["config"]["digest"]
    if not DIGEST.fullmatch(config_digest):
        return None
    with (layout / "blobs" / "sha256" / config_digest[7:]).open("rb") as stream:
        raw = stream.read(_MAX_CONFIG_BYTES + 1)
    if len(raw) > _MAX_CONFIG_BYTES:
        return None
    config = json.loads(raw)
    diff_ids = config["rootfs"]["diff_ids"]
    layers = manifest["layers"]
    if (
        config["os"] != "linux"
        or config["rootfs"]["type"] != "layers"
        or not isinstance(diff_ids, list)
        or len(diff_ids) != len(layers)
        or any(not isinstance(d, str) or not DIGEST.fullmatch(d) for d in diff_ids)
        or len(set(diff_ids)) != len(diff_ids)
    ):
        return None
    jobs = []
    for layer, diff_id in zip(layers, diff_ids, strict=True):
        digest = layer["digest"]
        if not DIGEST.fullmatch(digest):
            return None
        jobs.append((digest, _LAYER_ENCODINGS[layer["mediaType"]], diff_id))
    if jobs:
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            return None
        run_bounded(
            [
                "/usr/bin/prlimit",
                "--as=268435456:268435456",
                "--",
                sys.executable,
                "-I",
                str(Path(__file__).with_name("_image_layers.py")),
                json.dumps(jobs),
            ],
            cwd=layout,
            env={},
            timeout=timeout,
            max_bytes=1,
        )
    return diff_ids


def _components(
    report: dict, target: str, manifest: dict, diff_ids: list[str]
) -> list[SbomComponent] | None:
    if (
        report.get("SchemaVersion") != 2
        or report["Trivy"]["Version"] != TRIVY_VERSION
        or report.get("ArtifactType") != "container_image"
        or report.get("ArtifactName") != target
    ):
        return None
    metadata = report["Metadata"]
    layer_digests = [layer["digest"] for layer in manifest["layers"]]
    layers = metadata.get("Layers", [])
    if (
        metadata.get("ImageID") != manifest["config"]["digest"]
        or metadata["ImageConfig"].get("os") != "linux"
        or metadata["ImageConfig"]["rootfs"]["diff_ids"] != diff_ids
        or metadata.get("DiffIDs", []) != diff_ids
        or not isinstance(layers, list)
        or [layer["Digest"] for layer in layers] != layer_digests
        or [layer["DiffID"] for layer in layers] != diff_ids
    ):
        return None
    results = report.get("Results", [])
    if not isinstance(results, list):
        return None
    if not layer_digests:
        # An explicitly scanned layerless Linux image has no filesystem packages.
        return [] if not results and "OS" not in metadata else None
    os_info = metadata["OS"]
    family = os_info["Family"]
    analyzer, prefix, pattern = _OS[family]
    release = re.fullmatch(pattern, os_info["Name"])
    if release is None:
        return None
    components = []
    os_packages = False
    for result in results:
        system = result["Class"] == "os-pkgs" and result["Type"] == family
        if system:
            expected_analyzer, ecosystem = analyzer, prefix + release[1]
            os_packages = True
        elif result["Class"] == "lang-pkgs":
            expected_analyzer, ecosystem = _LANGUAGE[result["Type"]]
        else:
            return None
        packages = result["Packages"]
        if not isinstance(packages, list) or not packages:
            return None
        if len(components) + len(packages) > MAX_COMPONENTS:
            return None
        for package in packages:
            if package["AnalyzedBy"] != expected_analyzer:
                return None
            if system:
                # OSV keys distro advisories by source package identity.
                name, version = package["SrcName"], package["SrcVersion"]
                epoch, revision = package.get("SrcEpoch", 0), package.get("SrcRelease", "")
                if type(epoch) is not int or epoch < 0 or not isinstance(revision, str):
                    return None
                if not isinstance(version, str) or not version:
                    return None
                if revision:
                    version += f"-{revision}"
                if epoch:
                    version = f"{epoch}:{version}"
            else:
                name, version = package["Name"], package["Version"]
                if ecosystem == "PyPI":
                    name = re.sub(r"[-_.]+", "-", name).lower()
            components.append(SbomComponent(ecosystem=ecosystem, name=name, version=version))
    return components if os_packages else None
