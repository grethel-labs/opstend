"""R04: validated repository artifacts deploy only through the executor update path.

Real fetch, builder runner (fake backend), independent validator (fake registry/probe/scanner)
and the real executor with the fake host of the L05/L06 tests. Proves control flow and
refusals, not Podman, a registry or HTTP/data readback on a host (see
tests/integration/gates/m7_r04.md).
"""

from __future__ import annotations

import dataclasses
import json

import pytest

import test_remediation as tr
from artifact_testkit import APPROVER_SIGNER, FakeProbe, build_candidate, make_validator
from repo_testkit import Upstream
from steward.core import artifact_validation as av
from steward.core import repository_deploy as rd
from steward.core.canonical import revision_id
from steward.core.config import Application
from steward.core.update_evidence import sign_statement, validate_update
from steward.executor import image_update
from steward.executor.protocol import ExecutorError
from test_application_graph import graph
from update_support import NOW, SIGNER


@pytest.fixture
def upstream(tmp_path):
    return Upstream(tmp_path)


@pytest.fixture
def pipeline(tmp_path, raw_config, monkeypatch, upstream):
    for name in ("fetch", "build"):
        (tmp_path / name).mkdir(mode=0o700)
    w = tr.build_world(tmp_path, raw_config, monkeypatch, "observe")
    tr.write_capture(w, completed_at=NOW - 120)
    request, record = build_candidate(upstream, tmp_path / "fetch", tmp_path / "build")
    w.calls = []

    def call(action, params):
        w.calls.append(action)
        response = tr.call(w, action, params)
        if not response["ok"]:
            raise ExecutorError(response["error_class"], response["message"])
        return response["result"]

    w.call = call
    w.request, w.record = request, record
    w.validate = lambda **parts: validate(w, tmp_path, **parts)
    return w


def validate(w, tmp_path, **parts):
    validator, _ = make_validator(tmp_path / "validate", tmp_path / "build", **parts)
    report = validator.validate(
        w.request, w.record, project="shop", version="1.4.0", policy=w.contract, now=NOW
    )
    return report


def approve(w, report):
    return av.issue_approval(
        report,
        APPROVER_SIGNER,
        policy=w.contract,
        server="my-server",
        config_revision=tr.registry_of(w)["config_revision"],
        now=NOW,
    )


def desired(w) -> str:
    return json.loads(w.paths.desired.read_text())["projects"][0]["image"]


def restarts(w) -> int:
    return [c[0] for c in w.host.calls].count("restart")


def readback(w):
    def read(project, digest):
        return {
            "image": desired(w),
            "healthy": w.host.current_tag == tr.NEW_TAG and w.host.health_ok,
            "data_ok": True,
        }

    return read


def deployment(w, report):
    return rd.ServiceDeployment("backend", "shop", report, approve(w, report))


# --- single service ----------------------------------------------------------------------


def test_fetch_build_validate_deploy_then_an_unchanged_repeat_changes_nothing(pipeline):
    w = pipeline
    report = w.validate()
    assert report.accepted and desired(w) == tr.OLD_IMAGE
    outcome = rd.deploy_service(w.call, deployment(w, report), readback=readback(w))
    assert (outcome.state, outcome.changed) == ("deployed", 1)
    assert outcome.readback["healthy"] and outcome.image == tr.NEW_IMAGE
    assert desired(w) == tr.NEW_IMAGE  # the accepted digest is the desired state
    assert w.host.current_tag == tr.NEW_TAG and restarts(w) == 1
    assert w.calls == ["update_validate", "apply_verified_image"]  # only the executor path

    # the same accepted inputs and digest, validated and approved again: nothing restarts
    again = w.validate()
    assert again.accepted and again.digest == report.digest
    repeat = rd.deploy_service(w.call, deployment(w, again), readback=readback(w))
    assert (repeat.state, repeat.changed) == ("unchanged", 0)
    assert restarts(w) == 1 and w.calls.count("apply_verified_image") == 1


def test_the_old_approval_cannot_be_replayed(pipeline):
    w = pipeline
    first = deployment(w, w.validate())
    assert rd.deploy_service(w.call, first).state == "deployed"
    assert rd.deploy_service(w.call, first).changed == 0
    assert restarts(w) == 1


def test_a_rejected_validation_never_reaches_the_executor(pipeline):
    w = pipeline
    report = w.validate(probe=FakeProbe(uid=0))
    assert not report.accepted
    forged = rd.ServiceDeployment("backend", "shop", report, {"statement": {}})
    outcome = rd.deploy_service(w.call, forged)
    assert (outcome.state, outcome.changed) == ("rejected", 0)
    assert w.calls == [] and desired(w) == tr.OLD_IMAGE


def test_an_artifact_replaced_after_validation_is_refused(pipeline):
    w = pipeline
    report = w.validate()
    deployed = deployment(w, report)
    replaced = dataclasses.replace(report, digest="sha256:" + "c" * 64)
    outcome = rd.deploy_service(w.call, dataclasses.replace(deployed, report=replaced))
    assert outcome.state == "rejected" and "digest_mismatch" in outcome.detail
    assert w.calls == ["update_validate"] and desired(w) == tr.OLD_IMAGE
    assert restarts(w) == 0


@pytest.mark.parametrize("code", ["migration_unobserved", "scan_mismatch"])
def test_invalid_repository_evidence_is_denied_at_validation_and_apply(pipeline, code):
    w = pipeline
    report = w.validate()
    approved = approve(w, report)
    config_revision = tr.registry_of(w)["config_revision"]
    validated = validate_update(
        w.contract,
        server="my-server",
        project="shop",
        config_revision=config_revision,
        current_image=tr.OLD_IMAGE,
        candidate_digest=report.digest,
        attestation=report.attestation,
        approval=approved,
        now=NOW,
    )

    attestation = report.attestation
    approval_statement = approved["statement"].copy()
    if code == "migration_unobserved":
        statement = json.loads(json.dumps(attestation["statement"]))
        del statement["repository_validation"]["compatibility"]
        attestation = sign_statement(SIGNER, attestation["key_id"], statement)
        approval_statement["attestation_digest"] = revision_id(statement)
    else:
        approval_statement["scan"] = {**approval_statement["scan"], "checked_at": NOW}
    approval = sign_statement(APPROVER_SIGNER.key, APPROVER_SIGNER.key_id, approval_statement)
    historical_report = dataclasses.replace(report, attestation=attestation)
    historical_deployment = rd.ServiceDeployment("backend", "shop", historical_report, approval)
    before = w.paths.desired.read_bytes()
    host_calls = list(w.host.calls)

    outcome = rd.deploy_service(w.call, historical_deployment)
    assert (outcome.state, outcome.changed) == ("rejected", 0)
    assert code in outcome.detail
    assert w.calls == ["update_validate"]
    assert w.ex.update_ledger.get(validated.approval_id) is None

    # Seed the row an older executor could have admitted, then exercise the apply recheck.
    historical = dataclasses.replace(
        validated,
        attestation_digest=approval_statement["attestation_digest"],
        scan_checked_at=approval_statement["scan"]["checked_at"],
    )
    assert w.ex.update_ledger.record(historical, attestation, approval) == "new"
    response = tr.apply(w, approval_id=historical.approval_id, digest=report.digest)
    assert response["error_class"] == "policy_denied" and code in response["message"]
    assert w.ex.update_ledger.get(historical.approval_id)["state"] == "validated"
    assert w.paths.desired.read_bytes() == before
    assert w.host.current_tag == tr.OLD_TAG
    assert w.host.calls == host_calls


def test_an_approval_for_another_project_or_forged_signature_is_refused(pipeline):
    w = pipeline
    report = w.validate()
    good = deployment(w, report)
    forged = json.loads(json.dumps(good.approval))
    forged["statement"]["expires_at"] += 1000
    outcome = rd.deploy_service(w.call, dataclasses.replace(good, approval=forged))
    assert outcome.state == "rejected" and "bad_signature" in outcome.detail
    assert desired(w) == tr.OLD_IMAGE


def test_an_incompatible_or_unpermitted_migration_is_rejected_before_any_change(pipeline):
    w = pipeline
    probe = FakeProbe()
    probe.previous = {"data_migrated": True}  # observed format change: restore_required
    report = w.validate(probe=probe)
    assert report.accepted and report.migration == "restore_required"
    outcome = rd.deploy_service(w.call, deployment(w, report))
    assert outcome.state == "rejected" and "migration_not_allowed" in outcome.detail
    assert restarts(w) == 0 and desired(w) == tr.OLD_IMAGE
    unreadable = FakeProbe()
    unreadable.previous = {"data_readable": False}
    assert not w.validate(probe=unreadable).accepted


def test_a_failed_rollout_is_recovered_and_reported(pipeline):
    w = pipeline
    w.host.unhealthy_tags.add(tr.NEW_TAG)
    outcome = rd.deploy_service(w.call, deployment(w, w.validate()), readback=readback(w))
    assert outcome.state == "failed" and outcome.changed == 0
    assert w.host.current_tag == tr.OLD_TAG and desired(w) == tr.OLD_IMAGE


def test_an_interrupted_rollout_is_completed_and_a_repeat_is_unchanged(pipeline, monkeypatch):
    w = pipeline
    first = deployment(w, w.validate())
    monkeypatch.setenv("CRASH_ON", tr.NEW_TAG)
    with pytest.raises(tr.Crash):
        rd.deploy_service(w.call, first)
    monkeypatch.delenv("CRASH_ON")
    approval_id = first.approval["statement"]["approval_id"]
    assert image_update.recover_updates(w.ex, automatic=False) == [f"{approval_id}:applied"]
    assert desired(w) == tr.NEW_IMAGE
    count = restarts(w)
    again = w.validate()
    outcome = rd.deploy_service(w.call, deployment(w, again))
    assert (outcome.state, outcome.changed) == ("unchanged", 0) and restarts(w) == count


def test_a_readback_that_disagrees_with_the_digest_is_reported(pipeline):
    w = pipeline
    outcome = rd.deploy_service(
        w.call,
        deployment(w, w.validate()),
        readback=lambda project, digest: {"image": tr.OLD_IMAGE, "healthy": True},
    )
    assert outcome.state == "readback_failed" and outcome.changed == 1


def test_an_unreadable_readback_is_not_a_success(pipeline):
    w = pipeline

    def broken(project, digest):
        raise OSError("connection refused")

    outcome = rd.deploy_service(w.call, deployment(w, w.validate()), readback=broken)
    assert outcome.state == "readback_failed" and outcome.readback == {"error": "OSError"}


# --- two services --------------------------------------------------------------------------


class FakeExecutor:
    """Records calls; fails an apply for chosen projects (the executor itself is tested above)."""

    def __init__(self, fail=(), unchanged=()):
        self.fail, self.unchanged = set(fail), set(unchanged)
        self.calls: list[tuple[str, str]] = []

    def __call__(self, action, params):
        project = params["project_id"]
        self.calls.append((action, project))
        if action == "update_validate" and project in self.unchanged:
            raise ExecutorError("policy_denied", "update evidence rejected: already_current")
        if action == "apply_verified_image" and project in self.fail:
            raise ExecutorError("execution_failed", "unit failed")
        return {}


@pytest.fixture
def services(pipeline, raw_config):
    w = pipeline
    report = w.validate()
    approval = approve(w, report)
    app = Application.model_validate(graph(raw_config))
    deployments = {
        name: rd.ServiceDeployment(
            name, f"{name}-prj", dataclasses.replace(report, project=f"{name}-prj"), approval
        )
        for name in ("frontend", "worker", "backend", "database")
    }
    return app, deployments


def applied(executor):
    return [p for a, p in executor.calls if a == "apply_verified_image"]


def test_services_deploy_in_dependency_order(services):
    app, deployments = services
    executor = FakeExecutor()
    outcomes = rd.deploy_application(executor, app, deployments)
    assert [o.service for o in outcomes] == ["database", "backend", "frontend", "worker"]
    assert {o.state for o in outcomes} == {"deployed"}
    assert applied(executor) == ["database-prj", "backend-prj", "frontend-prj", "worker-prj"]


def test_a_failed_service_stops_its_dependents_but_not_independent_services(services):
    app, deployments = services
    executor = FakeExecutor(fail={"backend-prj"})
    outcomes = {o.service: o for o in rd.deploy_application(executor, app, deployments)}
    assert outcomes["database"].state == "deployed"
    assert outcomes["backend"].state == "failed"
    assert outcomes["frontend"].state == "skipped"  # depends on backend
    assert outcomes["worker"].state == "deployed"  # depends only on database
    assert "frontend-prj" not in applied(executor)


def test_an_unchanged_service_does_not_block_or_restart_and_a_service_without_artifact_is_left(
    services,
):
    app, deployments = services
    del deployments["worker"]
    executor = FakeExecutor(unchanged={"database-prj"})
    outcomes = {o.service: o for o in rd.deploy_application(executor, app, deployments)}
    assert outcomes["database"].state == "unchanged" and outcomes["database"].changed == 0
    assert "database-prj" not in applied(executor)
    assert outcomes["backend"].state == "deployed" and "worker" not in outcomes


def test_a_service_with_a_rejected_validation_blocks_its_dependents(services):
    app, deployments = services
    bad = dataclasses.replace(deployments["database"].report, accepted=False)
    deployments["database"] = dataclasses.replace(deployments["database"], report=bad)
    executor = FakeExecutor()
    outcomes = {o.service: o.state for o in rd.deploy_application(executor, app, deployments)}
    assert outcomes == {
        "database": "rejected",
        "backend": "skipped",
        "frontend": "skipped",
        "worker": "skipped",
    }
    assert executor.calls == []
