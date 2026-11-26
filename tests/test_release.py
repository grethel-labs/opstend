"""Verifiable release (S01): SBOM, provenance, detached signature and the verifier.

All keys are generated here at test time and live in temporary directories; no key
material is stored in the repository. These tests prove the local build/verify
logic. They do not prove installation of an archive on a host.
"""

import base64
import errno
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from contextlib import nullcontext
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from steward import release
from steward.cli import main as cli

COMMIT = "a" * 40
REQUIREMENTS = (
    "# generated\n"
    "annotated-types==0.8.0 \\\n"
    f"    --hash=sha256:{'1' * 64} \\\n"
    f"    --hash=sha256:{'2' * 64}\n"
    "    # via pydantic\n"
    "colorama==0.4.6 ; sys_platform == 'win32' \\\n"
    f"    --hash=sha256:{'3' * 64}\n"
    "    # via pytest\n"
    "PyYAML==6.0.3 \\\n"
    f"    --hash=sha256:{'4' * 64}\n"
)
NPM_LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {"version": "0.1.0"},
        "node_modules/react": {
            "version": "19.3.1",
            "integrity": "sha512-" + base64.b64encode(b"x" * 64).decode(),
            "license": "MIT",
        },
        "node_modules/vite": {"version": "8.3.8", "dev": True, "license": "MIT"},
    },
}
SUBSET = {
    "schema": 1,
    "features": [
        {
            "id": "stage1-core",
            "description": "Install and isolation",
            "evidence": "Synthetic test evidence",
        },
        {"id": "service-graph", "description": "Graph validation", "evidence": "STATUS L01"},
    ],
    "unsupported": ["arm64"],
}


def licenses(name):
    return "MIT" if name != "colorama" else None


def new_key():
    return Ed25519PrivateKey.generate()


def pem_private(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def write_public(key, path):
    path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return path


@pytest.fixture
def source_tree(tmp_path):
    root = tmp_path / "source"
    (root / "webapp").mkdir(parents=True)
    (root / "webapp" / "package-lock.json").write_text(json.dumps(NPM_LOCK))
    (root / "uv.lock").write_text("version = 1\n")
    (root / "subset.yml").write_text(yaml.safe_dump(SUBSET))
    return root


def make_release(tmp_path, source_tree, *, key=None, version="0.1.0.dev0", dirty=False, name="rel"):
    """Create a built-artifact directory and finalize it like `release build`."""
    out = tmp_path / name
    (out / "bundles" / "app").mkdir(parents=True)
    wheel = f"steward-{version}-py3-none-any.whl"
    (out / wheel).write_bytes(b"wheel-bytes")
    (out / "requirements.txt").write_text(REQUIREMENTS)
    (out / "bundles" / "app" / "main.py").write_text("print('hi')\n")
    files = {
        p.relative_to(out).as_posix(): release.sha256_file(p)
        for p in sorted(out.rglob("*"))
        if p.is_file()
    }
    manifest = release.finalize_release(
        out,
        version=version,
        files=files,
        wheel=wheel,
        root=source_tree,
        subset_path=source_tree / "subset.yml",
        signing_key=key,
        license_lookup=licenses,
        source={"commit": COMMIT, "dirty": dirty},
    )
    return out, manifest


@pytest.fixture
def signed(tmp_path, source_tree):
    key = new_key()
    out, manifest = make_release(tmp_path, source_tree, key=key)
    return out, key, manifest


def resign(out, key):
    """Re-hash attestations into the manifest and sign it: an attacker holding a key."""
    manifest = json.loads((out / release.MANIFEST).read_text())
    for entry in manifest["attestations"].values():
        entry["sha256"] = release.sha256_file(out / entry["path"])
    (out / release.MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
    release.sign_manifest(out, key)


def check(out, key, **kwargs):
    return release.verify_release(out, key.public_key(), **kwargs)


def assert_rejected(report, fragment):
    assert not report.ok
    assert any(fragment in e for e in report.errors), report.errors


# ---- accepted subset -----------------------------------------------------------------


def test_subset_is_normalised_and_loaded_from_file(tmp_path):
    path = tmp_path / "s.yml"
    path.write_text(yaml.safe_dump({**SUBSET, "features": SUBSET["features"][::-1]}))
    loaded = release.load_accepted_subset(path)
    assert [f["id"] for f in loaded["features"]] == ["service-graph", "stage1-core"]
    assert release.parse_accepted_subset(loaded) == loaded


def test_shipped_default_subset_file_is_valid():
    path = Path(__file__).resolve().parents[1] / release.DEFAULT_SUBSET
    assert release.load_accepted_subset(path)["features"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(schema=2),
        lambda d: d.update(features=[]),
        lambda d: d.update(extra=1),
        lambda d: d["features"].append(dict(d["features"][0])),
        lambda d: d["features"][0].pop("evidence"),
        lambda d: d["features"][0].update(evidence="  "),
        lambda d: d["features"][0].update(id="Bad Id"),
        lambda d: d["features"][0].update(unexpected="x"),
        lambda d: d.update(unsupported="arm64"),
    ],
)
def test_subset_rejects_malformed_documents(mutate):
    data = json.loads(json.dumps(SUBSET))
    mutate(data)
    with pytest.raises(release.ReleaseError):
        release.parse_accepted_subset(data)


def test_subset_file_errors_are_release_errors(tmp_path):
    with pytest.raises(release.ReleaseError):
        release.load_accepted_subset(tmp_path / "missing.yml")
    bad = tmp_path / "bad.yml"
    bad.write_text("features: [unterminated")
    with pytest.raises(release.ReleaseError):
        release.load_accepted_subset(bad)


# ---- pins ----------------------------------------------------------------------------


@pytest.mark.parametrize("indent", ["", "  "])
def test_requirements_parse_pins_hashes_and_markers(indent):
    pins = release.parse_requirements(
        "\n".join(indent + line for line in REQUIREMENTS.splitlines())
    )
    assert [(p.name, p.version, len(p.hashes)) for p in pins] == [
        ("annotated-types", "0.8.0", 2),
        ("colorama", "0.4.6", 1),
        ("pyyaml", "6.0.3", 1),
    ]


@pytest.mark.parametrize(
    "text",
    [
        "requests>=2\n",
        f"requests==2.0 \\\n    --hash=sha256:{'1' * 64}\nrequests==2.1 \\\n    --hash=sha256:{'2' * 64}\n",
        "requests==2.0\n",
        f"    --hash=sha256:{'1' * 64}\n",
        "git+https://example.invalid/x.git\n",
    ],
)
def test_requirements_reject_unpinned_or_unhashed(text):
    with pytest.raises(release.ReleaseError):
        release.parse_requirements(text)


# ---- build output --------------------------------------------------------------------


def test_signed_release_verifies_and_reports_only_what_was_checked(signed):
    out, key, manifest = signed
    report = check(out, key)
    assert report.ok, report.errors
    assert report.version == "0.1.0.dev0"
    assert report.features == ["service-graph", "stage1-core"]
    assert report.key_id == release.key_id(key.public_key())
    assert report.file_count == len(manifest["files"]) + 3
    assert any("colorama" in w for w in report.warnings)  # license unknown is reported


def test_sbom_lists_pins_wheel_hash_and_marks_dev_tools_excluded(signed):
    out, _, manifest = signed
    sbom = json.loads((out / release.SBOM).read_text())
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    root = sbom["metadata"]["component"]
    assert root["hashes"][0]["content"] == manifest["files"][manifest["wheel"]]
    by_purl = {c["purl"]: c for c in sbom["components"]}
    assert by_purl["pkg:pypi/annotated-types@0.8.0"]["hashes"][0]["content"] == "1" * 64
    assert by_purl["pkg:pypi/pyyaml@6.0.3"]["licenses"] == [{"expression": "MIT"}]
    assert by_purl["pkg:npm/react@19.3.1"]["scope"] == "required"
    assert by_purl["pkg:npm/vite@8.3.8"]["scope"] == "excluded"


def test_provenance_names_every_file_source_and_locks(signed):
    out, _, manifest = signed
    prov = json.loads((out / release.PROVENANCE).read_text())
    assert prov["_type"] == release.STATEMENT_TYPE
    assert prov["predicateType"] == release.PREDICATE_TYPE
    assert {s["name"]: s["digest"]["sha256"] for s in prov["subject"]} == manifest["files"]
    meta = prov["predicate"]["runDetails"]["metadata"]
    assert meta["source_commit"] == COMMIT and meta["source_dirty"] is False
    deps = {d["name"] for d in prov["predicate"]["buildDefinition"]["resolvedDependencies"]}
    assert deps == {"uv.lock", "webapp/package-lock.json"}


def test_build_is_deterministic(tmp_path, source_tree):
    key = new_key()
    a, _ = make_release(tmp_path, source_tree, key=key, name="a")
    b, _ = make_release(tmp_path, source_tree, key=key, name="b")
    for name in (release.MANIFEST, release.SIGNATURE, release.SBOM, release.PROVENANCE):
        assert (a / name).read_bytes() == (b / name).read_bytes()


def test_no_private_key_material_in_release_output(signed):
    out, key, _ = signed
    secret = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    for path in out.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert b"PRIVATE KEY" not in data and secret not in data
            assert base64.b64encode(secret) not in data and secret.hex().encode() not in data


def test_build_rejects_wheel_for_other_version(tmp_path, source_tree):
    out = tmp_path / "rel"
    out.mkdir()
    (out / "steward-9.9.9-py3-none-any.whl").write_bytes(b"x")
    (out / "requirements.txt").write_text(REQUIREMENTS)
    with pytest.raises(release.ReleaseError):
        release.finalize_release(
            out,
            version="0.1.0.dev0",
            files={"steward-9.9.9-py3-none-any.whl": "0" * 64},
            wheel="steward-9.9.9-py3-none-any.whl",
            root=source_tree,
            subset_path=source_tree / "subset.yml",
            source={"commit": COMMIT, "dirty": False},
        )


# ---- verifier rejections -------------------------------------------------------------


def test_unsigned_release_is_rejected(tmp_path, source_tree):
    out, _ = make_release(tmp_path, source_tree, key=None)
    assert_rejected(check(out, new_key()), "unsigned")


def test_signature_file_removed_is_rejected(signed):
    out, key, _ = signed
    (out / release.SIGNATURE).unlink()
    assert_rejected(check(out, key), "unsigned")


def test_untrusted_signer_is_rejected(signed):
    out, _, _ = signed
    assert_rejected(check(out, new_key()), "not the trusted key")


def test_attacker_resigned_release_is_rejected(signed):
    out, _, _ = signed
    attacker = new_key()
    (out / "bundles" / "app" / "main.py").write_text("evil\n")
    manifest = json.loads((out / release.MANIFEST).read_text())
    manifest["files"]["bundles/app/main.py"] = release.sha256_file(out / "bundles/app/main.py")
    (out / release.MANIFEST).write_text(json.dumps(manifest))
    release.sign_manifest(out, attacker)
    victim_key = new_key()  # verifier trusts a different key than the attacker's
    assert_rejected(check(out, victim_key), "not the trusted key")


@pytest.mark.parametrize("target", ["wheel", "requirements.txt", "bundles/app/main.py"])
def test_tampered_artifact_is_rejected(signed, target):
    out, key, manifest = signed
    path = out / (manifest["wheel"] if target == "wheel" else target)
    path.write_bytes(path.read_bytes() + b"x")
    assert_rejected(check(out, key), "does not match the manifest")


@pytest.mark.parametrize("name", [release.SBOM, release.PROVENANCE, release.SUBSET])
def test_tampered_attestation_is_rejected(signed, name):
    out, key, _ = signed
    (out / name).write_bytes((out / name).read_bytes() + b" ")
    assert_rejected(check(out, key), "does not match the manifest")


def test_missing_listed_file_is_rejected(signed):
    out, key, _ = signed
    (out / "bundles" / "app" / "main.py").unlink()
    assert_rejected(check(out, key), "missing")


def test_unlisted_extra_file_is_rejected(signed):
    out, key, _ = signed
    (out / "bundles" / "extra.sh").write_text("#!/bin/sh\n")
    assert_rejected(check(out, key), "not listed")


def test_symlink_entry_is_rejected(signed):
    out, key, _ = signed
    (out / "link").symlink_to("requirements.txt")
    report = check(out, key)
    assert_rejected(report, "non-regular")


def test_modified_manifest_breaks_signature(signed):
    out, key, _ = signed
    manifest = json.loads((out / release.MANIFEST).read_text())
    manifest["version"] = "9.9.9"
    (out / release.MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
    assert_rejected(check(out, key), "signed manifest hash")


def test_manifest_and_signature_from_different_releases_are_rejected(tmp_path, source_tree):
    key = new_key()
    a, _ = make_release(tmp_path, source_tree, key=key, name="a")
    b, _ = make_release(tmp_path, source_tree, key=key, version="0.2.0", name="b")
    shutil.copy(b / release.SIGNATURE, a / release.SIGNATURE)
    assert not check(a, key).ok


def test_signature_with_forged_manifest_hash_field_is_rejected(signed):
    out, key, _ = signed
    doc = json.loads((out / release.SIGNATURE).read_text())
    manifest = json.loads((out / release.MANIFEST).read_text())
    manifest["version"] = "6.6.6"
    new_bytes = (json.dumps(manifest, indent=2) + "\n").encode()
    (out / release.MANIFEST).write_bytes(new_bytes)
    doc["manifest_sha256"] = hashlib.sha256(new_bytes).hexdigest()
    (out / release.SIGNATURE).write_text(json.dumps(doc))
    assert_rejected(check(out, key), "signature is invalid")


@pytest.mark.parametrize(
    "content",
    [b"", b"not json", b"[]", b'{"schema": 1}', b"\xff\xfe"],
)
def test_malformed_signature_file_is_rejected_without_exception(signed, content):
    out, key, _ = signed
    (out / release.SIGNATURE).write_bytes(content)
    assert not check(out, key).ok


def test_bad_base64_signature_is_rejected(signed):
    out, key, _ = signed
    doc = json.loads((out / release.SIGNATURE).read_text())
    doc["signature"] = "!!!not-base64!!!"
    (out / release.SIGNATURE).write_text(json.dumps(doc))
    assert_rejected(check(out, key), "signature is invalid")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.pop("attestations"),
        lambda m: m["files"].update({"../escape": "0" * 64}),
        lambda m: m["files"].update({"/abs": "0" * 64}),
        lambda m: m["files"].update({"x": "short"}),
        lambda m: m.update(wheel="missing.whl"),
        lambda m: m["attestations"]["sbom"].update(path="other.json"),
        lambda m: m.update(extra=1),
    ],
)
def test_signed_but_malformed_manifest_is_rejected(signed, mutate):
    out, key, _ = signed
    manifest = json.loads((out / release.MANIFEST).read_text())
    mutate(manifest)
    (out / release.MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
    release.sign_manifest(out, key)
    assert_rejected(check(out, key), "unexpected structure")


def test_signed_sbom_that_disagrees_with_requirements_is_rejected(signed):
    out, key, _ = signed
    sbom = json.loads((out / release.SBOM).read_text())
    sbom["components"] = [c for c in sbom["components"] if c["name"] != "pyyaml"]
    (out / release.SBOM).write_text(json.dumps(sbom))
    resign(out, key)
    assert_rejected(check(out, key), "SBOM Python components differ")


def test_signed_sbom_with_wrong_wheel_hash_is_rejected(signed):
    out, key, _ = signed
    sbom = json.loads((out / release.SBOM).read_text())
    sbom["metadata"]["component"]["hashes"][0]["content"] = "0" * 64
    (out / release.SBOM).write_text(json.dumps(sbom))
    resign(out, key)
    assert_rejected(check(out, key), "SBOM root component")


def test_signed_provenance_for_other_files_is_rejected(signed):
    out, key, _ = signed
    prov = json.loads((out / release.PROVENANCE).read_text())
    prov["subject"][0]["digest"]["sha256"] = "0" * 64
    (out / release.PROVENANCE).write_text(json.dumps(prov))
    resign(out, key)
    assert_rejected(check(out, key), "provenance subjects differ")


def test_signed_provenance_binding_other_subset_is_rejected(signed):
    out, key, _ = signed
    prov = json.loads((out / release.PROVENANCE).read_text())
    prov["predicate"]["buildDefinition"]["externalParameters"]["accepted_subset_sha256"] = "0" * 64
    (out / release.PROVENANCE).write_text(json.dumps(prov))
    resign(out, key)
    assert_rejected(check(out, key), "different accepted subset")


def test_signed_subset_with_injected_feature_shape_is_rejected(signed):
    out, key, _ = signed
    subset = json.loads((out / release.SUBSET).read_text())
    subset["features"].append({"id": "x"})
    (out / release.SUBSET).write_text(json.dumps(subset))
    resign(out, key)
    assert not check(out, key).ok


def test_dirty_source_fails_unless_explicitly_allowed(tmp_path, source_tree):
    key = new_key()
    out, _ = make_release(tmp_path, source_tree, key=key, dirty=True)
    assert_rejected(check(out, key), "dirty or unknown source")
    allowed = check(out, key, allow_dirty=True)
    assert allowed.ok and any("dirty" in w for w in allowed.warnings)


def test_missing_release_is_rejected(tmp_path):
    assert_rejected(check(tmp_path / "nope", new_key()), "no such release")


# ---- archive -------------------------------------------------------------------------


def test_archive_roundtrip_is_deterministic_and_verifies(signed, tmp_path):
    out, key, _ = signed
    first = tmp_path / "a.tar.gz"
    second = tmp_path / "b.tar.gz"
    assert release.pack_release(out, first) == release.pack_release(out, second)
    assert check(first, key).ok


def rewrite_archive(src, dst, edit):
    with tarfile.open(src) as tar:
        members = [(m, tar.extractfile(m).read() if m.isfile() else None) for m in tar.getmembers()]
    with tarfile.open(dst, "w:gz") as tar:
        for member, data in edit(members):
            tar.addfile(member, io.BytesIO(data) if data is not None else None)


@pytest.mark.parametrize("body_fails", [False, True])
def test_staged_release_keeps_private_snapshot(signed, tmp_path, body_fails):
    out, key, manifest = signed
    original = tmp_path / "original.tar.gz"
    archive = tmp_path / "renamed.tar.gz"
    release.pack_release(out, original)

    def rename_top(members):
        for member, data in members:
            _, _, relative = member.name.partition("/")
            member.name = "{{ archive_name }}/" + relative
            yield member, data

    rewrite_archive(original, archive, rename_top)
    failure = OSError("deployment failed")
    stage = None

    outcome = pytest.raises(OSError) if body_fails else nullcontext()
    with outcome as caught, release.staged_verified_release(archive, key.public_key()) as payload:
        stage = Path(payload["dir"])
        assert stage.is_absolute() and stage.name == "release"
        assert stage.parent.stat().st_mode & 0o777 == 0o700
        assert payload == {
            "version": manifest["version"],
            "wheel": manifest["wheel"],
            "files": manifest["files"],
            "dir": str(stage),
        }
        archive.write_bytes(b"replaced")
        assert all(
            release.sha256_file(stage / name) == sha for name, sha in payload["files"].items()
        )
        if body_fails:
            raise failure
    if body_fails:
        assert caught.value is failure
    assert stage is not None and not stage.parent.exists()


@pytest.mark.parametrize(
    ("problem", "message"),
    [
        ("empty", "unlisted directory"),
        ("unsafe", "invalid deployment release artifact"),
        ("extra", "invalid deployment release artifact"),
        ("shallow", "invalid deployment release artifact"),
        ("version", "incomplete deployment release"),
        ("no-bundles", "incomplete deployment release"),
        ("vault", "contains an Ansible Vault file"),
    ],
)
def test_staging_rejects_general_release_shapes(tmp_path, source_tree, problem, message):
    key = new_key()
    version = "0.1.0_example" if problem == "version" else "0.1.0.dev0"
    out, manifest = make_release(tmp_path, source_tree, version=version)
    if problem == "empty":
        (out / "bundles/app/nested/empty").mkdir(parents=True)
    elif problem == "no-bundles":
        shutil.rmtree(out / "bundles")
    elif problem == "vault":
        (out / "bundles/app/main.py").write_bytes(b"$ANSIBLE_VAULT;1.1;AES256\n00\n")
    elif problem in {"unsafe", "extra", "shallow"}:
        name = {"unsafe": "bundles/app/file name", "extra": "extra.txt", "shallow": "bundles/top"}[
            problem
        ]
        (out / name).write_text("signed")
    release.finalize_release(
        out,
        version=version,
        files={
            p.relative_to(out).as_posix(): release.sha256_file(p)
            for p in out.rglob("*")
            if p.is_file() and p.name not in {release.MANIFEST, *release.ATTESTATIONS.values()}
        },
        wheel=manifest["wheel"],
        root=source_tree,
        subset_path=source_tree / "subset.yml",
        signing_key=key,
        source={"commit": COMMIT, "dirty": False},
    )
    archive = tmp_path / "release.tar.gz"
    release.pack_release(out, archive)
    assert check(archive, key).ok
    with (
        pytest.raises(release.ReleaseError, match=message),
        release.staged_verified_release(archive, key.public_key()),
    ):
        pytest.fail("invalid payload reached deployment")


@pytest.mark.parametrize(
    ("problem", "message"),
    [
        ("wrong-key", "trusted key"),
        ("tampered", "does not match the manifest"),
        ("unlisted", "not listed in the manifest"),
        ("trailer", "archive cannot be read safely"),
    ],
)
def test_staged_release_setup_failure_cleans_snapshot(
    signed, tmp_path, monkeypatch, problem, message
):
    out, key, manifest = signed
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(release.tempfile, "tempdir", str(scratch))
    if problem == "tampered":
        (out / manifest["wheel"]).write_bytes(b"changed")
    if problem == "unlisted":
        (out / "bundles/app/unlisted").write_bytes(b"unlisted")
    archive = tmp_path / "release.tar.gz"
    release.pack_release(out, archive)
    if problem == "trailer":
        data = bytearray(archive.read_bytes())
        data[-8] ^= 0xFF
        archive.write_bytes(data)
    trusted = new_key().public_key() if problem == "wrong-key" else key.public_key()
    with (
        pytest.raises(release.ReleaseError, match=message),
        release.staged_verified_release(archive, trusted),
    ):
        pytest.fail("invalid archive reached deployment")
    assert list(scratch.iterdir()) == []


def test_tampered_archive_content_is_rejected(signed, tmp_path):
    out, key, _ = signed
    archive = tmp_path / "r.tar.gz"
    release.pack_release(out, archive)

    def edit(members):
        for member, data in members:
            if member.name.endswith("bundles/app/main.py"):
                data = b"evil\n"
                member.size = len(data)
            yield member, data

    bad = tmp_path / "bad.tar.gz"
    rewrite_archive(archive, bad, edit)
    assert_rejected(check(bad, key), "does not match the manifest")


@pytest.mark.parametrize("kind", ["traversal", "absolute", "symlink", "second_top", "device"])
def test_hostile_archive_members_are_rejected(signed, tmp_path, kind):
    out, key, _ = signed
    archive = tmp_path / "r.tar.gz"
    release.pack_release(out, archive)
    top = "opstend-release-0.1.0.dev0"

    def edit(members):
        yield from members
        info = tarfile.TarInfo(
            {
                "traversal": f"{top}/../../escape",
                "absolute": "/tmp/escape",
                "symlink": f"{top}/link",
                "second_top": "other/file",
                "device": f"{top}/dev",
            }[kind]
        )
        data = b"x"
        if kind == "symlink":
            info.type, info.linkname, data = tarfile.SYMTYPE, "/etc/passwd", None
        elif kind == "device":
            info.type, data = tarfile.CHRTYPE, None
        else:
            info.size = 1
        yield info, data

    bad = tmp_path / "bad.tar.gz"
    rewrite_archive(archive, bad, edit)
    assert_rejected(check(bad, key), "archive cannot be read safely")
    assert not (tmp_path / "escape").exists()


def test_truncated_and_corrupt_archives_are_rejected(signed, tmp_path):
    out, key, _ = signed
    archive = tmp_path / "r.tar.gz"
    release.pack_release(out, archive)
    data = archive.read_bytes()
    truncated = tmp_path / "t.tar.gz"
    truncated.write_bytes(data[:200])
    corrupt = tmp_path / "c.tar.gz"
    corrupt.write_bytes(data[:30] + bytes(b ^ 0xFF for b in data[30:130]) + data[130:])
    for bad in (truncated, corrupt):
        assert_rejected(check(bad, key), "archive cannot be read safely")


def test_garbage_archive_is_rejected(tmp_path):
    junk = tmp_path / "junk.tar.gz"
    junk.write_bytes(b"not an archive")
    assert_rejected(check(junk, new_key()), "archive cannot be read safely")


# ---- keys by reference ---------------------------------------------------------------


def test_signing_key_by_file_reference_outside_repository(tmp_path):
    key = new_key()
    path = tmp_path / "key.pem"
    path.write_bytes(pem_private(key))
    path.chmod(0o600)
    loaded = release.load_private_key(f"file:{path}", forbidden_root=tmp_path / "repo")
    assert release.key_id(loaded.public_key()) == release.key_id(key.public_key())


def test_signing_key_inside_repository_is_refused(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    path = repo / "key.pem"
    path.write_bytes(pem_private(new_key()))
    path.chmod(0o600)
    with pytest.raises(release.ReleaseError, match="outside the repository"):
        release.load_private_key(f"file:{path}", forbidden_root=repo)


def test_file_key_is_opened_from_the_checked_path(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.pem"
    inside = repo / "inside.pem"
    outside_key = new_key()
    for path, key in [(outside, outside_key), (inside, new_key())]:
        path.write_bytes(pem_private(key))
        path.chmod(0o600)
    alias = tmp_path / "alias.pem"
    alias.symlink_to(outside)
    open_file = release._open_without_following

    def swap_alias(path, flags):
        alias.unlink()
        alias.symlink_to(inside)
        return open_file(path, flags)

    monkeypatch.setattr(release, "_open_without_following", swap_alias)
    loaded = release.load_private_key(f"file:{alias}", forbidden_root=repo)
    assert release.key_id(loaded.public_key()) == release.key_id(outside_key.public_key())


def test_signing_key_by_environment_reference(monkeypatch):
    key = new_key()
    monkeypatch.setenv("TEST_RELEASE_KEY", pem_private(key).decode())
    loaded = release.load_private_key("env:TEST_RELEASE_KEY")
    assert release.key_id(loaded.public_key()) == release.key_id(key.public_key())


def test_signing_key_loose_permissions_missing_or_wrong_type(tmp_path, monkeypatch):
    path = tmp_path / "key.pem"
    path.write_bytes(pem_private(new_key()))
    path.chmod(0o644)
    with pytest.raises(release.ReleaseError, match="permissions too open"):
        release.load_private_key(f"file:{path}")
    with pytest.raises(release.ReleaseError):
        release.load_private_key(f"file:{tmp_path}/absent")
    rsa = generate_private_key(65537, 2048).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    monkeypatch.setenv("TEST_RSA_KEY", rsa.decode())
    with pytest.raises(release.ReleaseError, match="Ed25519"):
        release.load_private_key("env:TEST_RSA_KEY")
    monkeypatch.setenv("TEST_BAD_KEY", "-----not a key-----")
    with pytest.raises(release.ReleaseError) as exc:
        release.load_private_key("env:TEST_BAD_KEY")
    assert "not a key" not in str(exc.value)


def test_keygen_writes_private_key_0600_and_never_overwrites(tmp_path):
    private, public = tmp_path / "k.pem", tmp_path / "k.pub"
    fingerprint = release.generate_keypair(private, public)
    assert (private.stat().st_mode & 0o777) == 0o600
    assert release.key_id(release.load_public_key(public)) == fingerprint
    with pytest.raises(FileExistsError):
        release.generate_keypair(private, tmp_path / "other.pub")


def test_untrusted_public_key_file_must_be_valid_ed25519(tmp_path):
    bad = tmp_path / "bad.pub"
    bad.write_text("nope")
    with pytest.raises(release.ReleaseError):
        release.load_public_key(bad)


def test_repository_tracks_no_private_key_material():
    root = Path(__file__).resolve().parents[1]
    try:
        listed = subprocess.run(
            ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True
        ).stdout.split("\n")
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    marker = "BEGIN " + "PRIVATE KEY"
    for name in filter(None, listed):
        path = root / name
        if path.is_file() and path.stat().st_size < 2_000_000:
            assert marker not in path.read_bytes().decode("utf-8", "ignore"), name


# ---- CLI -----------------------------------------------------------------------------


def run_cli(*argv):
    with pytest.raises(SystemExit) as exc:
        cli.main(list(argv))
    return exc.value.code


def test_cli_verify_accepts_signed_and_rejects_tampered(signed, tmp_path, capsys):
    out, key, _ = signed
    public = write_public(key, tmp_path / "pub.pem")
    assert run_cli("release", "verify", str(out), "--public-key", str(public)) == 0
    assert "verified" in capsys.readouterr().out
    (out / "requirements.txt").write_text(
        REQUIREMENTS + "evil==1 \\\n    --hash=sha256:" + "5" * 64
    )
    assert run_cli("release", "verify", str(out), "--public-key", str(public)) == cli.EXIT_FAILED
    captured = capsys.readouterr()
    assert "NOT verified" in captured.out and "does not match" in captured.err
    assert "verified:" not in captured.out


def test_cli_verify_bad_public_key_is_invalid_usage(signed, tmp_path, capsys):
    out, _, _ = signed
    bad = tmp_path / "bad.pub"
    bad.write_text("x")
    assert run_cli("release", "verify", str(out), "--public-key", str(bad)) == cli.EXIT_INVALID


def test_cli_keygen_refuses_paths_inside_repository(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "ROOT", tmp_path / "repo")
    (tmp_path / "repo").mkdir()
    code = run_cli(
        "release",
        "keygen",
        "--private-out",
        str(tmp_path / "repo" / "k.pem"),
        "--public-out",
        str(tmp_path / "k.pub"),
    )
    assert code == cli.EXIT_INVALID
    assert not (tmp_path / "repo" / "k.pem").exists()


@pytest.fixture
def build_env(tmp_path, source_tree, monkeypatch):
    """Run the real `release build` flow with uv/npm replaced by file-writing fakes."""
    root = source_tree
    (root / "webapp" / "dist").mkdir()
    (root / "webapp" / "dist" / "index.html").write_text("<html></html>")
    (root / "sample-app").mkdir()
    (root / "sample-app" / "app.py").write_text("x = 1\n")
    (root / "release").mkdir()
    shutil.copy(root / "subset.yml", root / "release" / "accepted-subset.yml")
    monkeypatch.setattr(cli, "ROOT", root)
    monkeypatch.setattr(cli, "RELEASE_DIR", root / "dist" / "release")
    monkeypatch.setattr(cli.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(release, "source_state", lambda _root: {"commit": COMMIT, "dirty": False})

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["uv", "build"]:
            out = Path(cmd[cmd.index("--out-dir") + 1])
            (out / f"steward-{cli.__version__}-py3-none-any.whl").write_bytes(b"wheel")
        elif cmd[:2] == ["uv", "export"]:
            Path(cmd[cmd.index("--output-file") + 1]).write_text(REQUIREMENTS)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    return root


def test_cli_build_sign_pack_verify_end_to_end(build_env, tmp_path, capsys):
    key = new_key()
    keyfile = tmp_path / "outside" / "key.pem"
    keyfile.parent.mkdir()
    keyfile.write_bytes(pem_private(key))
    keyfile.chmod(0o600)
    public = write_public(key, tmp_path / "pub.pem")
    assert run_cli("release", "build", "--signing-key-ref", f"file:{keyfile}") == 0
    assert "signed with key" in capsys.readouterr().out
    assert run_cli("release", "pack", "--output", str(tmp_path / "r.tar.gz")) == 0
    assert (
        run_cli("release", "verify", str(tmp_path / "r.tar.gz"), "--public-key", str(public)) == 0
    )
    # the build still satisfies the deploy-time loader
    assert cli.load_release()["wheel"].endswith(".whl")


def test_cli_build_without_key_is_unsigned_and_does_not_verify(build_env, tmp_path, capsys):
    key = new_key()
    public = write_public(key, tmp_path / "pub.pem")
    assert run_cli("release", "build") == 0
    assert "UNSIGNED" in capsys.readouterr().out
    code = run_cli(
        "release", "verify", str(build_env / "dist" / "release"), "--public-key", str(public)
    )
    assert code == cli.EXIT_FAILED


def test_cli_build_fails_closed_on_bad_subset_or_key_inside_repository(build_env, tmp_path):
    (build_env / "release" / "accepted-subset.yml").write_text("schema: 1\nfeatures: []\n")
    assert run_cli("release", "build") == cli.EXIT_INVALID
    assert not (build_env / "dist").exists()
    inside = build_env / "k.pem"
    inside.write_bytes(pem_private(new_key()))
    inside.chmod(0o600)
    shutil.copy(build_env / "subset.yml", build_env / "release" / "accepted-subset.yml")
    assert run_cli("release", "build", "--signing-key-ref", f"file:{inside}") == cli.EXIT_INVALID
    assert not os.path.exists(build_env / "dist")


# ---- offline signing -----------------------------------------------------------------


@pytest.fixture
def offline_key(tmp_path):
    key = new_key()
    private = tmp_path / "offline.pem"
    private.write_bytes(pem_private(key))
    private.chmod(0o600)
    return key, f"file:{private}"


@pytest.fixture
def unsigned_archive(tmp_path, source_tree):
    out, manifest = make_release(tmp_path, source_tree)
    # Use valid but noncanonical JSON to catch a signer that rewrites the manifest.
    (out / release.MANIFEST).write_bytes(b" \n" + json.dumps(manifest).encode() + b"\n")
    archive = tmp_path / "unsigned.tar.gz"
    release.pack_release(out, archive)
    return archive


def archive_contents(path):
    with tarfile.open(path, "r:gz") as tar:
        return {m.name: tar.extractfile(m).read() if m.isfile() else None for m in tar}


def test_offline_sign_preserves_members_and_is_deterministic(
    unsigned_archive, offline_key, tmp_path
):
    key, ref = offline_key
    original = unsigned_archive.read_bytes()
    members = archive_contents(unsigned_archive)
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"

    report, digest = release.sign_release_archive(unsigned_archive, first, signing_key_ref=ref)
    other_report, other_digest = release.sign_release_archive(
        unsigned_archive, second, signing_key_ref=ref
    )

    assert report.ok and other_report.ok
    assert report.key_id == release.key_id(key.public_key())
    assert digest == other_digest == hashlib.sha256(first.read_bytes()).hexdigest()
    assert first.read_bytes() == second.read_bytes()
    assert unsigned_archive.read_bytes() == original
    signed_members = archive_contents(first)
    manifest = next(name for name in members if name.endswith(f"/{release.MANIFEST}"))
    signature = str(Path(manifest).with_name(release.SIGNATURE))
    assert signed_members.pop(signature)
    assert signed_members == members
    public = write_public(key, tmp_path / "trusted.pub")
    assert release.verify_release(first, release.load_public_key(public)).ok
    assert_rejected(check(first, new_key()), "trusted key")


@pytest.mark.parametrize(
    "problem",
    [
        "tampered-artifact",
        "missing-artifact",
        "malformed-requirements",
        "tampered-attestation",
        "malformed-attestation",
        "wrong-sbom-hash-algorithm",
        "dirty",
        "unknown",
        "invalid-commit",
    ],
)
def test_offline_sign_validates_payload_before_resolving_key(
    tmp_path, source_tree, offline_key, monkeypatch, problem
):
    out, manifest = make_release(tmp_path, source_tree, dirty=problem == "dirty")
    if problem == "tampered-artifact":
        (out / manifest["wheel"]).write_bytes(b"changed wheel")
    elif problem == "missing-artifact":
        (out / manifest["wheel"]).unlink()
    elif problem == "malformed-requirements":
        path = out / "requirements.txt"
        path.write_bytes(b"unpinned\n")
        digest = release.sha256_file(path)
        manifest["files"][path.name] = digest
        path = out / release.PROVENANCE
        provenance = json.loads(path.read_bytes())
        for subject in provenance["subject"]:
            if subject["name"] == "requirements.txt":
                subject["digest"]["sha256"] = digest
        path.write_text(json.dumps(provenance))
        manifest["attestations"]["provenance"]["sha256"] = release.sha256_file(path)
        (out / release.MANIFEST).write_text(json.dumps(manifest))
    elif problem == "tampered-attestation":
        (out / release.SBOM).write_bytes(b"changed SBOM")
    elif problem == "wrong-sbom-hash-algorithm":
        path = out / release.SBOM
        sbom = json.loads(path.read_bytes())
        sbom["metadata"]["component"]["hashes"][0]["alg"] = "MD5"
        path.write_text(json.dumps(sbom))
        manifest["attestations"]["sbom"]["sha256"] = release.sha256_file(path)
        (out / release.MANIFEST).write_text(json.dumps(manifest))
    elif problem in {"malformed-attestation", "unknown", "invalid-commit"}:
        path = out / release.PROVENANCE
        if problem == "malformed-attestation":
            path.write_bytes(b"{")
        else:
            provenance = json.loads(path.read_bytes())
            meta = provenance["predicate"]["runDetails"]["metadata"]
            meta["source_commit"] = "" if problem == "unknown" else COMMIT + "a"
            path.write_text(json.dumps(provenance))
        # Rebind the digest so the attestation itself must be checked.
        manifest["attestations"]["provenance"]["sha256"] = release.sha256_file(path)
        (out / release.MANIFEST).write_text(json.dumps(manifest))

    archive = tmp_path / "invalid.tar.gz"
    release.pack_release(out, archive)
    output = tmp_path / "signed.tar.gz"

    def unexpected_key_resolution(*args, **kwargs):
        pytest.fail("invalid unsigned payload reached private-key resolution")

    monkeypatch.setattr(release, "load_private_key", unexpected_key_resolution)
    with pytest.raises(release.ReleaseError):
        release.sign_release_archive(archive, output, signing_key_ref=offline_key[1])
    assert not output.exists()


@pytest.mark.parametrize("kind", ["duplicate", "traversal", "symlink"])
def test_offline_sign_rejects_hostile_archive_members(
    unsigned_archive, offline_key, tmp_path, kind
):
    def edit(members):
        yield from members
        member, data = next((m, data) for m, data in members if m.isfile())
        if kind == "duplicate":
            yield member, data
        elif kind == "traversal":
            top = member.name.split("/")[0]
            info = tarfile.TarInfo(f"{top}/../../escape")
            info.size = 1
            yield info, b"x"
        else:
            top = member.name.split("/")[0]
            info = tarfile.TarInfo(f"{top}/link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../escape"
            yield info, None

    hostile = tmp_path / "hostile.tar.gz"
    rewrite_archive(unsigned_archive, hostile, edit)
    output = tmp_path / "signed.tar.gz"
    with pytest.raises(release.ReleaseError):
        release.sign_release_archive(hostile, output, signing_key_ref=offline_key[1])
    assert not output.exists()


def test_offline_sign_rejects_already_signed_archive(signed, offline_key, tmp_path):
    out, _, _ = signed
    archive = tmp_path / "already-signed.tar.gz"
    release.pack_release(out, archive)
    original = archive.read_bytes()
    output = tmp_path / "signed-again.tar.gz"
    with pytest.raises(release.ReleaseError):
        release.sign_release_archive(archive, output, signing_key_ref=offline_key[1])
    assert archive.read_bytes() == original
    assert not output.exists()


def test_offline_sign_rejects_corrupt_gzip_trailer(unsigned_archive, offline_key, tmp_path):
    archive = tmp_path / "corrupt.tar.gz"
    data = bytearray(unsigned_archive.read_bytes())
    data[-8] ^= 0xFF
    archive.write_bytes(data)
    output = tmp_path / "signed.tar.gz"

    with pytest.raises(release.ReleaseError):
        release.sign_release_archive(archive, output, signing_key_ref=offline_key[1])
    assert not output.exists()


@pytest.mark.parametrize("kind", ["file", "dangling-symlink", "input"])
def test_offline_sign_never_replaces_output(unsigned_archive, offline_key, tmp_path, kind):
    original = unsigned_archive.read_bytes()
    output = tmp_path / "signed.tar.gz"
    missing = tmp_path / "missing.tar.gz"
    if kind == "file":
        output.write_bytes(b"keep")
    elif kind == "dangling-symlink":
        output.symlink_to(missing)
    else:
        output = unsigned_archive

    with pytest.raises((release.ReleaseError, FileExistsError)):
        release.sign_release_archive(unsigned_archive, output, signing_key_ref=offline_key[1])

    assert unsigned_archive.read_bytes() == original
    if kind == "file":
        assert output.read_bytes() == b"keep"
    elif kind == "dangling-symlink":
        assert output.readlink() == missing
        assert not missing.exists()


def test_offline_sign_cleans_up_after_partial_pack(
    unsigned_archive, offline_key, tmp_path, monkeypatch
):
    output = tmp_path / "signed.tar.gz"
    before = set(tmp_path.iterdir())
    original = unsigned_archive.read_bytes()

    def partial_pack(_release_dir, destination):
        with destination.open("xb") as handle:
            handle.write(b"partial archive")
        raise OSError(errno.EIO, "injected pack failure")

    monkeypatch.setattr(release, "pack_release", partial_pack)
    with pytest.raises((release.ReleaseError, OSError), match="injected pack failure"):
        release.sign_release_archive(unsigned_archive, output, signing_key_ref=offline_key[1])
    assert set(tmp_path.iterdir()) == before
    assert unsigned_archive.read_bytes() == original


def test_cli_offline_sign_and_verify(unsigned_archive, offline_key, tmp_path):
    key, ref = offline_key
    public = write_public(key, tmp_path / "trusted.pub")
    output = tmp_path / "signed.tar.gz"
    assert (
        run_cli(
            "release",
            "sign",
            str(unsigned_archive),
            "--signing-key-ref",
            ref,
            "--output",
            str(output),
        )
        == 0
    )
    assert run_cli("release", "verify", str(output), "--public-key", str(public)) == 0


@pytest.mark.parametrize("problem", ["missing-key", "missing-output", "allow-dirty"])
def test_cli_offline_sign_requires_explicit_arguments(
    unsigned_archive, offline_key, tmp_path, monkeypatch, problem
):
    _, ref = offline_key
    output = tmp_path / "signed.tar.gz"
    monkeypatch.setenv("STEWARD_RELEASE_SIGNING_KEY_REF", ref)
    options = []
    if problem != "missing-key":
        options += ["--signing-key-ref", ref]
    if problem != "missing-output":
        options += ["--output", str(output)]
    if problem == "allow-dirty":
        options += ["--allow-dirty"]
    assert run_cli("release", "sign", str(unsigned_archive), *options) == 2
    assert not output.exists()


def test_cli_offline_sign_redacts_invalid_key_reference(
    unsigned_archive, offline_key, tmp_path, capsys
):
    output = tmp_path / "signed.tar.gz"
    invalid_reference = pem_private(offline_key[0]).decode()
    assert (
        run_cli(
            "release",
            "sign",
            str(unsigned_archive),
            "--signing-key-ref",
            invalid_reference,
            "--output",
            str(output),
        )
        == cli.EXIT_FAILED
    )
    error = capsys.readouterr().err
    assert "signing key reference must use" in error
    assert invalid_reference.splitlines()[1] not in error
    assert not output.exists()
