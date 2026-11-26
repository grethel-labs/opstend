"""Local contract checks for the protected unsigned release build."""

import importlib.util
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from steward import __version__, release
from test_release import COMMIT, make_release
from test_release import source_tree as source_tree

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "grethel-labs/server-deploy-toolkit"
DEFAULT_BRANCH = "trunk"


@pytest.fixture(scope="module")
def workflow():
    # PyYAML's YAML 1.1 boolean resolution interprets the key "on" as True.
    source = (ROOT / ".github/workflows/release-build.yml").read_text()
    return yaml.safe_load(re.sub(r"^on:", "'on':", source, flags=re.MULTILINE))


def test_release_job_structure(workflow):
    assert workflow["on"] in ("workflow_dispatch", {"workflow_dispatch": None})
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"build"}
    job = workflow["jobs"]["build"]
    assert job["if"] == (
        f"github.repository == '{REPOSITORY}' && "
        "github.event_name == 'workflow_dispatch' && "
        "github.ref_type == 'branch' && github.ref_protected == true && "
        "github.ref == format('refs/heads/{0}', github.event.repository.default_branch) && "
        "github.workflow_sha == github.sha"
    )
    assert job["environment"] == {"name": "steward-release-build", "deployment": False}
    assert "permissions" not in job
    assert job["defaults"]["run"]["shell"] == "bash"
    assert job["steps"][0]["name"] == "Check release ref"
    actions = {}
    for step in job["steps"]:
        assert "continue-on-error" not in step
        assert "if" not in step
        if "uses" in step:
            action, revision = step["uses"].split("@")
            assert re.fullmatch("[0-9a-f]{40}", revision)
            assert action not in actions
            actions[action] = step
    checkout = actions["actions/checkout"]
    assert checkout is job["steps"][1]
    assert job["steps"][2]["name"] == "Check clean source checkout"
    assert checkout["with"]["ref"] == "${{ github.sha }}"
    assert checkout["with"]["persist-credentials"] is False
    upload = actions["actions/upload-artifact"]
    build = job["steps"][job["steps"].index(upload) - 1]
    assert build["name"] == "Build, pack and verify unsigned candidate"
    assert "unset STEWARD_RELEASE_SIGNING_KEY_REF" in build["run"]
    assert ".venv/bin/python .github/release/verify_candidate.py" in build["run"]
    assert upload["with"]["if-no-files-found"] == "error"
    assert upload["with"]["overwrite"] is False
    assert upload["with"]["name"] == (
        "steward-release-unsigned-${{ github.run_id }}-${{ github.run_attempt }}"
    )
    assert upload["with"]["path"].splitlines() == [
        "dist/candidate/steward-release-unsigned.tar.gz",
        "dist/candidate/steward-release-unsigned.tar.gz.sha256",
        "dist/candidate/receipt.json",
    ]


@pytest.mark.parametrize(
    ("overrides", "default_branch", "allowed"),
    [
        pytest.param({}, DEFAULT_BRANCH, True, id="protected-default"),
        pytest.param(
            {"GITHUB_REF": "refs/heads/other"}, DEFAULT_BRANCH, False, id="protected-nondefault"
        ),
        pytest.param(
            {"GITHUB_REF_PROTECTED": "false"}, DEFAULT_BRANCH, False, id="unprotected-default"
        ),
        pytest.param(
            {"GITHUB_REF_TYPE": "tag", "GITHUB_REF": "refs/tags/trunk"},
            DEFAULT_BRANCH,
            False,
            id="tag",
        ),
        pytest.param(
            {"GITHUB_REF": "refs/heads/Trunk"}, DEFAULT_BRANCH, False, id="case-only-mismatch"
        ),
        pytest.param(
            {"GITHUB_EVENT_NAME": "pull_request"}, DEFAULT_BRANCH, False, id="pull-request"
        ),
        pytest.param(
            {"GITHUB_REPOSITORY": "fork/server-deploy-toolkit"}, DEFAULT_BRANCH, False, id="fork"
        ),
        pytest.param({}, None, False, id="missing-default-branch"),
        pytest.param(
            {"GITHUB_REF_PROTECTED": None}, DEFAULT_BRANCH, False, id="missing-protection"
        ),
        pytest.param(
            {"GITHUB_WORKFLOW_SHA": "b" * 40}, DEFAULT_BRANCH, False, id="workflow-sha-mismatch"
        ),
    ],
)
def test_release_ref_step(workflow, tmp_path, overrides, default_branch, allowed):
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("executing the runner step requires bash")
    event_path = tmp_path / "event.json"
    repository = {"full_name": overrides.get("GITHUB_REPOSITORY", REPOSITORY)}
    if default_branch is not None:
        repository["default_branch"] = default_branch
    event_path.write_text(json.dumps({"repository": repository}))
    env = {
        "PATH": os.environ["PATH"],
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF_TYPE": "branch",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_REF": f"refs/heads/{DEFAULT_BRANCH}",
        "GITHUB_EVENT_PATH": str(event_path),
        "GITHUB_SHA": COMMIT,
        "GITHUB_WORKFLOW_SHA": COMMIT,
    }
    env.update(overrides)
    step = workflow["jobs"]["build"]["steps"][0]
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
        env={name: value for name, value in env.items() if value is not None},
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert (result.returncode == 0) is allowed, result.stdout + result.stderr


@pytest.fixture(scope="module")
def verify_candidate():
    path = ROOT / ".github/release/verify_candidate.py"
    spec = importlib.util.spec_from_file_location("verify_candidate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify_candidate


@pytest.mark.parametrize(
    ("problem", "error"),
    [
        (None, None),
        ("wrong-checkout", "checkout is dirty or does not match"),
        ("dirty-checkout", "checkout is dirty or does not match"),
        ("wrong-source", "provenance source commit differs"),
        ("dirty-source", "dirty"),
        ("stale-export", "requirements differ from the frozen host export"),
        ("wrong-lock", "provenance lock hashes differ"),
        ("tampered", "does not match the manifest"),
    ],
)
def test_verify_candidate(verify_candidate, tmp_path, source_tree, monkeypatch, problem, error):
    out, manifest = make_release(
        tmp_path, source_tree, version=__version__, dirty=problem == "dirty-source"
    )
    monkeypatch.setattr(
        release,
        "source_state",
        lambda _: {
            "commit": "b" * 40 if problem == "wrong-checkout" else COMMIT,
            "dirty": problem == "dirty-checkout",
        },
    )
    host_export = tmp_path / "host.txt"
    shutil.copyfile(out / "requirements.txt", host_export)
    if problem == "stale-export":
        host_export.write_text(host_export.read_text().replace("0.8.0", "0.8.1"))
    elif problem in {"wrong-source", "wrong-lock"}:
        path = out / release.PROVENANCE
        provenance = json.loads(path.read_text())
        predicate = provenance["predicate"]
        if problem == "wrong-source":
            predicate["runDetails"]["metadata"]["source_commit"] = "b" * 40
        else:
            deps = predicate["buildDefinition"]["resolvedDependencies"]
            next(dep for dep in deps if dep["name"] == "uv.lock")["digest"]["sha256"] = "b" * 64
        path.write_text(json.dumps(provenance))
        manifest["attestations"]["provenance"]["sha256"] = release.sha256_file(path)
        (out / release.MANIFEST).write_text(json.dumps(manifest))
    elif problem == "tampered":
        (out / manifest["wheel"]).write_bytes(b"changed wheel")

    archive = tmp_path / "candidate.tar.gz"
    digest = release.pack_release(out, archive)
    if error is None:
        receipt = verify_candidate(archive, source_tree, COMMIT, host_export)
        assert receipt["version"] == __version__
        assert receipt["host_requirements_sha256"] == release.sha256_file(host_export)
        assert receipt["archive"] == archive.name
        assert receipt["archive_sha256"] == digest
    else:
        with pytest.raises(release.ReleaseError, match=error):
            verify_candidate(archive, source_tree, COMMIT, host_export)
