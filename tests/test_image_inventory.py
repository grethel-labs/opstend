"""Unit report contracts and an opt-in smoke using an existing stock Trivy binary."""

import gzip
import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

import pytest

from steward.adapters import image_inventory
from steward.adapters.image_inventory import TrivyImageInventory
from steward.core.process import CommandError, run_bounded


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _layout(root, files=None, *, diff_id=None):
    blobs = root / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    def store(data, media_type):
        digest = _digest(data)
        (blobs / digest[7:]).write_bytes(data)
        return {"digest": digest, "size": len(data), "mediaType": media_type}

    layers, diff_ids = [], []
    if files is not None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, data in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        data = buffer.getvalue()
        diff_ids.append(diff_id or _digest(data))
        layers.append(
            store(gzip.compress(data, mtime=0), "application/vnd.oci.image.layer.v1.tar+gzip")
        )
    config = {
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
        "config": {"Labels": {"org.opencontainers.image.sbom": "builder-inventory-claim"}},
    }
    manifest = {
        "schemaVersion": 2,
        "config": store(json.dumps(config).encode(), "application/vnd.oci.image.config.v1+json"),
        "layers": layers,
    }
    index_entry = store(json.dumps(manifest).encode(), "application/vnd.oci.image.manifest.v1+json")
    (root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    (root / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [index_entry]}))
    return {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.76.2"},
        "ArtifactName": f"/image@{index_entry['digest']}",
        "ArtifactType": "container_image",
        "Metadata": {
            "ImageID": manifest["config"]["digest"],
            "ImageConfig": config,
            "DiffIDs": diff_ids,
            "Layers": [
                {"Digest": layer["digest"], "DiffID": diff}
                for layer, diff in zip(layers, diff_ids, strict=True)
            ],
        },
    }


def _mock_trivy(tmp_path, monkeypatch, report, *, messages=b""):
    binary = tmp_path / "trivy"
    binary.touch()

    def run(argv, *, cwd, env, timeout, max_bytes, stderr=None):
        if "/usr/bin/bwrap" not in argv:
            return run_bounded(argv, cwd=cwd, env=env, timeout=timeout, max_bytes=max_bytes)
        assert argv[0] == "/usr/bin/prlimit"
        assert "--unshare-all" in argv and "--ro-bind" in argv
        assert argv[argv.index("--input") + 1] == report["ArtifactName"]
        assert "--offline-scan" in argv and "--scanners=" in argv
        assert cwd == tmp_path / "layout"
        assert set(env) == {"HOME", "TMPDIR", "GOMEMLIMIT", "GOMAXPROCS"}
        assert 0 < timeout <= 7 and max_bytes == 8 * 1024**2
        stderr.write(messages)
        return json.dumps(report).encode()

    monkeypatch.setattr(image_inventory, "run_bounded", run)
    return TrivyImageInventory(binary)(tmp_path / "layout", timeout=7)


def _apk_report(report):
    report["Metadata"]["OS"] = {"Family": "alpine", "Name": "3.22.0"}
    report["Results"] = [
        {
            "Class": "os-pkgs",
            "Type": "alpine",
            "Packages": [
                {
                    "AnalyzedBy": "apk",
                    "Name": "fixture-binary",
                    "Version": "1.2.3-r0",
                    "SrcName": "fixture",
                    "SrcVersion": "1.2.3-r0",
                }
            ],
        }
    ]
    return report


def test_unit_trivy_report_binds_packages_to_exact_input(tmp_path, monkeypatch):
    report = _apk_report(_layout(tmp_path / "layout", {"fixture": b""}))
    (component,) = _mock_trivy(tmp_path, monkeypatch, report)
    assert (component.ecosystem, component.name, component.version) == (
        "Alpine:v3.22",
        "fixture",
        "1.2.3-r0",
    )


def test_unit_empty_inventory_requires_explicit_layerless_image(tmp_path, monkeypatch):
    report = _layout(tmp_path / "layout")
    assert _mock_trivy(tmp_path, monkeypatch, report) == []


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.pop("Results"),
        lambda r: r["Results"][0].pop("Packages"),
        lambda r: r["Results"][0]["Packages"][0].update(AnalyzedBy="sbom"),
        lambda r: r["Results"][0]["Packages"][0].update(SrcVersion=""),
        lambda r: r["Metadata"].pop("OS"),
        lambda r: r["Metadata"].update(OS={"Family": "unknown", "Name": "1"}),
        lambda r: r["Metadata"].update(ImageID="sha256:" + "4" * 64),
        lambda r: r["Metadata"].update(Layers=[]),
        lambda r: r["Metadata"]["Layers"][0].update(Digest="sha256:" + "4" * 64),
        lambda r: r["Trivy"].update(Version="0.1.0"),
    ],
)
def test_unit_trivy_withholds_unqualified_inventory(tmp_path, monkeypatch, change):
    report = _apk_report(_layout(tmp_path / "layout", {"fixture": b""}))
    change(report)
    assert _mock_trivy(tmp_path, monkeypatch, report) is None


@pytest.mark.parametrize(
    "message",
    [
        b"WARN\tpartial",
        b'DEBUG\tAnalysis error\terr="package metadata unreadable"',
        b'DEBUG\tPermission error\tfile_path="metadata"',
    ],
)
def test_unit_trivy_incomplete_diagnostics_withhold_inventory(tmp_path, monkeypatch, message):
    report = _apk_report(_layout(tmp_path / "layout", {"fixture": b""}))
    assert (
        _mock_trivy(tmp_path, monkeypatch, report, messages=b"2026-11-26T00:00:00Z\t" + message)
        is None
    )


@pytest.mark.parametrize(
    ("files", "diff_id"),
    [
        ({"fixture": b""}, "sha256:" + "4" * 64),
        ({"lib/apk/db/installed": b"P:first\nV:1\n\nD:" + b"x" * (64 * 1024)}, None),
        ({"app/program.jar": b"fixture"}, None),
    ],
)
def test_unit_layer_preflight_rejects_uncovered_or_unbound_layers(
    tmp_path, monkeypatch, files, diff_id
):
    layout = tmp_path / "layout"
    _layout(layout, files, diff_id=diff_id)
    binary = tmp_path / "trivy"
    binary.touch()

    def run(argv, **kwargs):
        assert "/usr/bin/bwrap" not in argv, "Trivy ran on an unqualified layer"
        return run_bounded(argv, **kwargs)

    monkeypatch.setattr(image_inventory, "run_bounded", run)
    assert TrivyImageInventory(binary)(layout) is None


def test_unit_debian_source_version_keeps_epoch_and_revision(tmp_path, monkeypatch):
    report = _layout(tmp_path / "layout", {"fixture": b""})
    report["Metadata"]["OS"] = {"Family": "debian", "Name": "12.8"}
    report["Results"] = [
        {
            "Class": "os-pkgs",
            "Type": "debian",
            "Packages": [
                {
                    "AnalyzedBy": "dpkg",
                    "Name": "fixture-binary",
                    "SrcName": "fixture",
                    "SrcVersion": "2.1",
                    "SrcEpoch": 1,
                    "SrcRelease": "3+deb12u1",
                }
            ],
        }
    ]
    (component,) = _mock_trivy(tmp_path, monkeypatch, report)
    assert (component.ecosystem, component.name, component.version) == (
        "Debian:12",
        "fixture",
        "1:2.1-3+deb12u1",
    )


@pytest.mark.parametrize("failure", ["timeout", "output_limit", "unavailable"])
def test_unit_trivy_command_failure_withholds_inventory(tmp_path, monkeypatch, failure):
    layout = tmp_path / "layout"
    _layout(layout)
    binary = tmp_path / "trivy"
    binary.touch()

    def run(*args, **kwargs):
        raise CommandError(failure)

    monkeypatch.setattr(image_inventory, "run_bounded", run)
    assert TrivyImageInventory(binary)(layout) is None


def test_native_trivy_inventories_synthetic_layers_offline(tmp_path):
    binary = os.environ.get("STEWARD_TEST_CACHED_TRIVY")
    if binary is None:
        pytest.skip("no explicitly supplied cached Trivy 0.76.2 binary")
    layout = tmp_path / "layout"
    _layout(
        layout,
        {
            "etc/alpine-release": b"3.22.0\n",
            "lib/apk/db/installed": b"P:fixture\nV:1.2.3-r0\nA:x86_64\nS:1\nI:1\nT:fixture\no:fixture\nL:MIT\n\n",
            "app/node_modules/example/package.json": b'{"name":"example","version":"4.5.6"}',
            "app/lib/python3.12/site-packages/example-7.8.9.dist-info/METADATA": (
                b"Metadata-Version: 2.1\nName: example\nVersion: 7.8.9\n"
            ),
            "builder.cdx.json": b'{"bomFormat":"CycloneDX","components":[{"name":"producer-claim"}]}',
        },
    )
    components = TrivyImageInventory(Path(binary))(layout)
    assert components is not None
    assert {(c.ecosystem, c.name, c.version) for c in components} == {
        ("Alpine:v3.22", "fixture", "1.2.3-r0"),
        ("npm", "example", "4.5.6"),
        ("PyPI", "example", "7.8.9"),
    }
