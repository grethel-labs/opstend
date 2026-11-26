"""R04: independent validation of a build artifact (fake registry, probe and scanner)."""

from __future__ import annotations

import copy
import json
from dataclasses import replace

import pytest
import yaml

from artifact_testkit import (
    APPROVER_SIGNER,
    BUILD_REF,
    FakeProbe,
    FakeRegistry,
    FakeScanner,
    build_candidate,
    make_validator,
)
from builder_testkit import OUT, FakeBackend, prepare, request_for
from builder_testkit import policy as build_policy
from repo_testkit import Upstream
from steward.core import artifact_validation as av
from steward.core import builder as bd
from steward.core.canonical import revision_id
from steward.core.config import effective, parse_config
from steward.core.ids import graph_identifier
from steward.core.repository_contract import CONTRACT_FILE
from steward.core.update_evidence import UpdateRejected, sign_statement, validate_update
from test_repositories import with_repository
from update_support import CONFIG_REVISION, NOW, OLD_IMAGE, REPOSITORY, SIGNER, contract

POLICY = contract()


@pytest.fixture
def dirs(tmp_path):
    for name in ("fetch", "build"):
        (tmp_path / name).mkdir(mode=0o700)
    return tmp_path / "fetch", tmp_path / "build", tmp_path / "validate"


@pytest.fixture
def upstream(tmp_path):
    return Upstream(tmp_path)


@pytest.fixture
def candidate(upstream, dirs):
    fetch, build, _ = dirs
    return build_candidate(upstream, fetch, build)


def validate(candidate, dirs, version="1.4.0", **parts):
    request, record = candidate
    validator, used = make_validator(dirs[2], dirs[1], **parts)
    report = validator.validate(
        request, record, project="shop", version=version, policy=POLICY, now=NOW
    )
    return report, validator, used


def failed(report):
    return report.failed


# --- acceptance -----------------------------------------------------------------------


def test_a_clean_artifact_is_accepted_and_attested_by_the_validator(candidate, dirs):
    request, record = candidate
    report, validator, used = validate(candidate, dirs)
    assert report.accepted and report.failed == []
    assert report.authorizes == [] and report.trust == "validated_candidate"
    assert report.digest == OUT and report.image == f"{REPOSITORY}@{OUT}"
    assert report.isolation_level == "ephemeral_vm"
    # inspected through its own access, by the builder's digest-pinned reference
    assert used["registry"].inspected == [BUILD_REF]
    assert used["registry"].copies == [(BUILD_REF, report.image)]
    # the evidence is exactly what the executor path validates
    approval = av.issue_approval(
        report, APPROVER_SIGNER, policy=POLICY, server="my-server",
        config_revision=CONFIG_REVISION, now=NOW,
    )  # fmt: skip
    update = validate_update(
        POLICY, server="my-server", project="shop", config_revision=CONFIG_REVISION,
        current_image=OLD_IMAGE, candidate_digest=OUT,
        attestation=report.attestation, approval=approval, now=NOW,
    )  # fmt: skip
    assert update.image == report.image and update.test_revision == report.test_revision
    assert update.source_revision == f"git:{request.record.commit}"
    assert update.migration == "none"
    assert (
        report.attestation["statement"]["repository_validation"]["compatibility"]
        == "data_format_unchanged"
    )
    # persisted privately; reuse of the accepted digest is possible, a tag never
    assert validator.accepted_digests(request.input_digest) == {OUT}
    runner = bd.BuildRunner(dirs[1], __import__("builder_testkit").policy(), [], minimum=None)
    assert runner.find_reusable(request, accepted={OUT})["output"]["digest"] == OUT
    assert runner.find_reusable(request, accepted=set()) is None
    (path,) = (dirs[2] / "reports" / request.input_digest).glob("*.json")
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text())["accepted"] is True


def test_a_builder_cannot_attest_to_its_own_acceptance(candidate, dirs):
    request, record = candidate
    forged = copy.deepcopy(record)
    forged["authorizes"] = ["deploy"]
    report, _, used = validate((request, forged), dirs)
    assert not report.accepted and report.attestation is None
    assert report.failed == ["record_binding:record_claims_authority"]
    assert used["registry"].inspected == []  # nothing was inspected for an unbound record


@pytest.mark.parametrize(
    ("edit", "code"),
    [
        (lambda r: r.update(status="failed"), "build_not_succeeded"),
        (lambda r: r.update(trust="trusted"), "record_claims_authority"),
        (lambda r: r.update(commit="0" * 40), "inputs_changed"),
        (lambda r: r.update(source_digest="1" * 64), "inputs_changed"),
        (lambda r: r.update(contract_digest="2" * 64), "inputs_changed"),
        (lambda r: r.update(input_digest="3" * 64), "inputs_changed"),
        (lambda r: r["recipe"].update(target="evil"), "inputs_changed"),
        (lambda r: r["isolation"].update(level="bare_metal"), "unknown_isolation_level"),
        (lambda r: r["output"].update(ref="reg.invalid/app:latest"), "unpinned_output_ref"),
        (lambda r: r["output"].update(digest="sha256:nothex"), "build_not_succeeded"),
    ],
)
def test_a_record_that_does_not_match_independent_inputs_is_rejected(candidate, dirs, edit, code):
    request, record = candidate
    forged = copy.deepcopy(record)
    edit(forged)
    report, _, _ = validate((request, forged), dirs)
    assert not report.accepted and report.failed[0].endswith(code)


def test_a_changed_commit_or_recipe_needs_a_new_build_and_validation(
    upstream, dirs, candidate, tmp_path
):
    request, record = candidate
    # same repository, new commit: the old record no longer binds
    new_request, _ = build_candidate(
        upstream, dirs[0], dirs[1], files={"app.py": "print('changed')\n"}
    )
    assert new_request.input_digest != request.input_digest
    report, _, _ = validate((new_request, record), dirs)
    assert report.failed == ["record_binding:inputs_changed"]


def test_the_artifact_digest_comes_from_the_validators_own_registry_access(candidate, dirs):
    other = "sha256:" + "9" * 64
    report, _, used = validate(candidate, dirs, registry=FakeRegistry(digest=other))
    assert report.failed == ["artifact_identity:digest_mismatch"]
    assert used["registry"].copies == [] and report.attestation is None


def test_a_registry_or_probe_failure_is_a_rejection_not_an_acceptance(candidate, dirs):
    registry = FakeRegistry()
    registry.error = OSError("registry down")
    report, _, _ = validate(candidate, dirs, registry=registry)
    assert not report.accepted and report.failed == ["validator:validator_error"]


def test_the_minimum_isolation_level_is_enforced(candidate, dirs):
    request, record = candidate
    validator, _ = make_validator(
        dirs[2],
        dirs[1],
    )
    validator.minimum_level = "ephemeral_vm"
    weak = copy.deepcopy(record)
    weak["isolation"]["level"] = "container_rootless"
    report = validator.validate(
        request, weak, project="shop", version="1.4.0", policy=POLICY, now=NOW
    )
    assert "isolation_level:below_minimum_isolation" in report.failed


@pytest.mark.parametrize(
    ("configured", "override", "allow_container", "code"),
    [
        ("external_ci", "container_rootless", True, "below_minimum_isolation"),
        ("container_rootless", "external_ci", True, "below_minimum_isolation"),
        (None, None, False, "isolation_not_allowed"),
    ],
)
def test_validator_applies_current_policy_to_records_and_cached_reports(
    upstream, dirs, raw_config, configured, override, allow_container, code
):
    request, weak_record = build_candidate(upstream, dirs[0], dirs[1], level="container_rootless")
    report, legacy, _ = validate((request, weak_record), dirs)
    assert report.accepted and report.isolation_level == "container_rootless"
    assert legacy.accepted_digests(request.input_digest) == {OUT}
    opted_in, _ = make_validator(
        dirs[2], dirs[1], build_policy=build_policy(allow_container_isolation=True)
    )
    assert opted_in.accepted_digests(request.input_digest) == {OUT}

    raw_config["build"] = {
        "allow_container_isolation": allow_container,
        "minimum_isolation": configured,
    }
    canonical = effective(parse_config(raw_config, allow_unavailable=True))
    cfg = parse_config(canonical, allow_unavailable=True)
    report, validator, used = validate(
        (request, weak_record), dirs, build_policy=cfg.build, minimum_level=override
    )
    assert report.failed == [f"isolation_level:{code}"]
    assert not report.accepted and report.attestation is None
    assert used["registry"].inspected == []
    assert used["registry"].copies == []
    assert used["probe"].calls == []
    assert used["scanner"].subjects == []
    assert validator.accepted_digests(request.input_digest) == set()

    strong_record = bd.BuildRunner(dirs[1], cfg.build, [FakeBackend()]).run(request)
    assert strong_record["output"]["digest"] == OUT
    report = validator.validate(
        request, strong_record, project="shop", version="1.4.0", policy=POLICY, now=NOW
    )
    assert report.accepted and report.isolation_level == "ephemeral_vm"
    assert validator.accepted_digests(request.input_digest) == {OUT}


# --- origin, inventory ---------------------------------------------------------------------


def test_signature_policy(candidate, dirs):
    required = av.OriginPolicy(require_signature=True, trusted_signers=frozenset({"ci"}))
    for facts, code in (
        ({}, "signature_missing_or_invalid"),
        ({"signature": {"signer": "ci", "valid": False}}, "signature_missing_or_invalid"),
        ({"signature": {"signer": "other", "valid": True}}, "untrusted_signer"),
    ):
        report, _, _ = validate(candidate, dirs, registry=FakeRegistry(**facts), origin=required)
        assert f"origin_policy:{code}" in report.failed
    ok, _, _ = validate(
        candidate, dirs,
        registry=FakeRegistry(signature={"signer": "ci", "valid": True}), origin=required,
    )  # fmt: skip
    assert ok.accepted
    # even without a requirement, a present but invalid signature is never accepted
    bad, _, _ = validate(
        candidate, dirs, registry=FakeRegistry(signature={"signer": "ci", "valid": False})
    )
    assert "origin_policy:signature_invalid" in bad.failed


def test_a_missing_sbom_is_a_rejection(candidate, dirs):
    registry = FakeRegistry(sbom=None)
    report, _, _ = validate(candidate, dirs, registry=registry)
    assert report.failed == ["inventory:no_sbom"]


def test_unresolved_dependencies_stay_visible_and_block_unless_allowed(upstream, dirs):
    candidate = build_candidate(
        upstream, dirs[0], dirs[1], files={"Dockerfile": "FROM python:3\nCOPY . /app\n"}
    )
    report, _, _ = validate(candidate, dirs)
    assert not report.accepted and report.failed == ["inventory:unresolved_dependencies"]
    assert report.unresolved and report.unresolved[0]["code"] == "base_image_not_pinned"
    allowed, _, _ = validate(
        candidate, dirs, origin=av.OriginPolicy(allow_unresolved_inventory=True)
    )
    assert allowed.accepted and allowed.unresolved  # still reported


def test_dependencies_join_the_vulnerability_inventory(upstream, dirs):
    candidate = build_candidate(
        upstream, dirs[0], dirs[1], files={"requirements.txt": "flask==3.0.0\n"}
    )
    scanner = FakeScanner()
    registry = FakeRegistry(
        sbom=[{"ecosystem": "pip", "name": "werkzeug", "version": "3.0.1"},
              {"ecosystem": "pip", "name": "flask", "version": "3.0.0"}]
    )  # fmt: skip
    report, _, _ = validate(candidate, dirs, registry=registry, scanner=scanner)
    assert report.accepted
    names = [(c.kind, c.name, c.version) for c in scanner.subjects]
    assert names[0][0] == "image" and names[0][2] == OUT
    assert ("dependency", "flask", "3.0.0") in names  # lockfile and SBOM, once
    assert ("dependency", "werkzeug", "3.0.1") in names
    assert names.count(("dependency", "flask", "3.0.0")) == 1
    assert all(c.scope == "shop" for c in scanner.subjects)
    assert report.components == len(scanner.subjects) == 3


# --- isolation tests, data -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("over", "check", "code"),
    [
        ({"started": False}, "isolation_tests", "not_started"),
        ({"uid": 0}, "isolation_tests", "wrong_user"),
        ({"uid": 10002}, "isolation_tests", "wrong_user"),
        ({"read_only_rootfs": False}, "isolation_tests", "writable_rootfs"),
        ({"privileged": True}, "isolation_tests", "privileged"),
        ({"capabilities": ["CAP_NET_RAW"]}, "isolation_tests", "capabilities"),
        ({"host_network": True}, "isolation_tests", "host_network"),
        ({"engine_socket": True}, "isolation_tests", "engine_socket"),
        ({"egress_reachable": ["169.254.169.254"]}, "isolation_tests", "egress_reachable"),
        ({"listening_ports": [9999]}, "health_and_data", "port_not_listening"),
        ({"health_status": 500}, "health_and_data", "unhealthy"),
        ({"health_status": None}, "health_and_data", "unhealthy"),
        ({"data_writable": False}, "health_and_data", "data_not_writable"),
    ],
)
def test_the_artifact_is_judged_by_its_observed_isolation_and_health(
    candidate, dirs, over, check, code
):
    report, _, used = validate(candidate, dirs, probe=FakeProbe(**over))
    assert not report.accepted and report.attestation is None
    assert f"{check}:{code}" in report.failed
    assert used["registry"].copies == []  # a rejected artifact is never promoted


def test_an_incompatible_migration_is_rejected(candidate, dirs):
    probe = FakeProbe()
    probe.previous = {"data_readable": False}
    report, _, _ = validate(candidate, dirs, probe=probe)
    assert report.failed == ["data_compatibility:incompatible_migration"]
    assert probe.calls == [False, True]  # the second run opens a copy of previous data


def test_missing_migration_observation_blocks_acceptance(candidate, dirs):
    request, _ = candidate
    probe = FakeProbe()
    del probe.base["data_migrated"]

    report, validator, used = validate(candidate, dirs, probe=probe)

    assert report.failed == ["data_compatibility:migration_unobserved"]
    assert not report.accepted and report.migration is None and report.attestation is None
    assert used["registry"].copies == []
    assert validator.accepted_digests(request.input_digest) == set()


def test_a_cached_report_with_an_ambiguous_migration_requires_revalidation(candidate, dirs):
    request, _ = candidate
    report, validator, _ = validate(candidate, dirs)
    assert report.accepted
    assert validator.accepted_digests(request.input_digest) == {OUT}

    (path,) = (dirs[2] / "reports" / request.input_digest).glob("*.json")
    cached = json.loads(path.read_text())
    compatibility = next(
        check for check in cached["checks"] if check["name"] == "data_compatibility"
    )
    compatibility["detail"] = "none"  # Older reports used this for either False or None.
    path.write_text(json.dumps(cached))
    assert validator.accepted_digests(request.input_digest) == set()

    report, _, _ = validate(candidate, dirs)
    assert report.accepted
    assert validator.accepted_digests(request.input_digest) == {OUT}


def test_compatibility_probe_timeout_blocks_acceptance(candidate, dirs, monkeypatch):
    request, _ = candidate
    probe = FakeProbe()
    run = probe.run

    def run_with_timeout(image_ref, contract, *, with_previous_data):
        if with_previous_data:
            raise TimeoutError
        return run(image_ref, contract, with_previous_data=with_previous_data)

    monkeypatch.setattr(probe, "run", run_with_timeout)
    report, validator, used = validate(candidate, dirs, probe=probe)

    assert report.failed == ["validator:validator_error"]
    assert not report.accepted and report.migration is None and report.attestation is None
    assert used["registry"].copies == []
    assert validator.accepted_digests(request.input_digest) == set()


def test_a_contract_without_a_data_path_needs_no_migration_observation(upstream, dirs):
    candidate = build_candidate(
        upstream, dirs[0], dirs[1], files={CONTRACT_FILE: "container_port: 8080\n"}
    )
    probe = FakeProbe(data_writable=None, data_readable=None, data_migrated=None)

    report, validator, _ = validate(candidate, dirs, probe=probe)

    assert report.accepted and report.migration == "none"
    assert report.attestation["statement"]["migration"] == "none"
    assert (
        report.attestation["statement"]["repository_validation"]["compatibility"] == "no_data_path"
    )
    assert validator.accepted_digests(report.input_digest) == {OUT}


def test_an_observed_data_format_change_is_attested_as_restore_required(candidate, dirs):
    probe = FakeProbe()
    probe.previous = {"data_migrated": True}
    report, validator, _ = validate(candidate, dirs, probe=probe)
    assert report.accepted and report.migration == "restore_required"
    assert report.attestation["statement"]["migration"] == "restore_required"
    assert (
        report.attestation["statement"]["repository_validation"]["compatibility"]
        == "restore_required"
    )
    assert validator.accepted_digests(report.input_digest) == {OUT}


# --- scan ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scanner", "code"),
    [
        (FakeScanner("confirmed"), "scan_not_clean"),
        (FakeScanner("confirmed", only="image"), "scan_not_clean"),
        (FakeScanner("unknown"), "scan_incomplete"),
        (FakeScanner("scan_failed"), "scan_incomplete"),
        (FakeScanner(checked_at=NOW - 10 * 86400), "stale_scan"),
    ],
)
def test_only_complete_fresh_clean_scans_pass(candidate, dirs, scanner, code):
    report, _, _ = validate(candidate, dirs, scanner=scanner)
    assert report.failed == [f"vulnerability_scan:{code}"]


def test_a_vulnerable_dependency_rejects_even_when_the_image_is_clean(upstream, dirs):
    candidate = build_candidate(
        upstream, dirs[0], dirs[1], files={"requirements.txt": "flask==3.0.0\n"}
    )
    report, _, _ = validate(candidate, dirs, scanner=FakeScanner("confirmed", only="dependency"))
    assert report.failed == ["vulnerability_scan:scan_not_clean"]


def test_missing_scan_results_fail_closed(candidate, dirs):
    scanner = FakeScanner()
    scanner.drop = True
    report, _, _ = validate(candidate, dirs, scanner=scanner)
    assert report.failed == ["vulnerability_scan:scan_incomplete"]


def test_promotion_failure_or_digest_change_rejects(candidate, dirs):
    registry = FakeRegistry()
    registry.copy_result = OSError("denied")
    report, _, _ = validate(candidate, dirs, registry=registry)
    assert report.failed == ["promotion:promotion_failed"] and report.attestation is None
    registry = FakeRegistry()
    registry.copy_result = "sha256:" + "8" * 64
    report, _, _ = validate(candidate, dirs, registry=registry)
    assert report.failed == ["promotion:promotion_digest_mismatch"]


# --- independence --------------------------------------------------------------------------


def test_the_validator_refuses_to_share_identity_or_state_with_the_builder(tmp_path):
    build = tmp_path / "build"
    build.mkdir()
    base = {"builder_root": build, "validator_identity": "v", "builder_identity": "b"}
    av.ensure_independent(validator_root=tmp_path / "validate", **base)
    for over, root in (
        ({"validator_identity": "b"}, tmp_path / "validate"),
        ({}, build),
        ({}, build / "records"),
        ({}, tmp_path),  # contains the builder root
        ({"validator_uid": 5, "builder_uid": 5}, tmp_path / "validate"),
        ({"key_paths": (build / "key",)}, tmp_path / "validate"),
    ):
        with pytest.raises(av.ValidationFailure) as caught:
            av.ensure_independent(validator_root=root, **{**base, **over})
        assert caught.value.code == "not_independent"


def test_constructing_a_validator_inside_the_builder_root_fails(dirs):
    with pytest.raises(av.ValidationFailure):
        make_validator(dirs[1] / "validate", dirs[1])


# --- approval ------------------------------------------------------------------------------


def approve(report, signer=APPROVER_SIGNER, **over):
    args = {"policy": POLICY, "server": "my-server", "config_revision": CONFIG_REVISION, "now": NOW}
    return av.issue_approval(report, signer, **{**args, **over})


def test_approval_binds_application_revisions_tests_digest_and_expiry(candidate, dirs):
    report, _, _ = validate(candidate, dirs)
    approval = approve(report, ttl_s=1800)
    statement = approval["statement"]
    assert statement["project"] == "shop" and statement["server"] == "my-server"
    assert statement["config_revision"] == CONFIG_REVISION
    assert statement["image"] == report.image and statement["test_revision"] == report.test_revision
    assert statement["expires_at"] == NOW + 1800
    assert statement["scan"]["state"] == "not_affected"
    assert approve(report) == approve(report)  # idempotent id: a repeat reuses the approval
    # any changed binding invalidates it at the L04 gate
    with pytest.raises(UpdateRejected) as caught:
        validate_update(
            POLICY, server="my-server", project="shop", config_revision="e" * 64,
            current_image=OLD_IMAGE, candidate_digest=OUT,
            attestation=report.attestation, approval=approval, now=NOW,
        )  # fmt: skip
    assert caught.value.code == "revision_mismatch"


def test_approval_is_refused_for_rejected_reports_and_wrong_identities(candidate, dirs):
    rejected, _, _ = validate(candidate, dirs, probe=FakeProbe(uid=0))
    with pytest.raises(av.ValidationFailure) as caught:
        approve(rejected)
    assert caught.value.code == "not_accepted"
    report, _, _ = validate(candidate, dirs)
    for signer, code in (
        (av.Signer("ci-signer", SIGNER), "not_independent"),  # the validator approves itself
        (av.Signer("ops-approver", SIGNER), "not_independent"),  # validator key under approver id
        (av.Signer("stranger", APPROVER_SIGNER.key), "unknown_approver"),
    ):
        with pytest.raises(av.ValidationFailure) as caught:
            av.issue_approval(
                report, signer, policy=POLICY, server="my-server",
                config_revision=CONFIG_REVISION, now=NOW,
            )  # fmt: skip
        assert caught.value.code == code


def test_approval_limits_ttl_freshness_and_widened_egress(upstream, dirs):
    report, _, _ = validate(
        build_candidate(upstream, dirs[0], dirs[1]),
        dirs,
        scanner=FakeScanner(checked_at=NOW - 80000),
    )
    for kwargs, code in (
        ({"ttl_s": 10}, "bad_ttl"),
        ({"ttl_s": 10**6}, "bad_ttl"),
        ({"now": NOW + 30000}, "stale_scan"),
    ):
        with pytest.raises(av.ValidationFailure) as caught:
            approve(report, **kwargs)
        assert caught.value.code == code
    widened = copy.deepcopy(report)
    widened.egress_mode = "public-web"
    with pytest.raises(av.ValidationFailure) as caught:
        approve(widened)
    assert caught.value.code == "egress_unconfirmed"
    assert approve(widened, operator_confirmed_egress=True)["statement"]["image"] == report.image


def egress_rule(cidr, *ports, proto="tcp"):
    return {"proto": proto, "cidr": cidr, "ports": list(ports)}


def rule_egress(*rules):
    return {"mode": "rules", "rules": list(rules)}


@pytest.fixture
def signed_egress_candidate(raw_config, upstream, dirs):
    raw = with_repository(raw_config)
    app = raw["applications"][0]
    service = next(s for s in app["services"] if s["id"] == "backend")
    service.update(container_port=8080, update=POLICY.model_dump(mode="json"))

    def validate_egress(egress, *, pinned=False, requested_revision=None):
        files = {CONTRACT_FILE: yaml.safe_dump({"container_port": 8080, "egress": egress})}
        source, proposal = prepare(upstream, dirs[0], files=files)
        repo = raw["repositories"][0]
        # Fetch locally, then bind the production-shaped identity before building and signing.
        pin = requested_revision or (source.commit if pinned else None)
        source = replace(source, url=repo["url"], requested_revision=pin)
        if pin is not None:
            repo["revision"] = pin
        request = request_for(source, proposal, dirs[0])
        runner = bd.BuildRunner(
            dirs[1], build_policy(allow_container_isolation=True), [FakeBackend()]
        )
        validator, _ = make_validator(dirs[2], dirs[1])
        report = validator.validate(
            request, runner.run(request),
            project=graph_identifier("s", app["id"], service["id"]),
            version="1.4.0", policy=POLICY, now=NOW,
        )  # fmt: skip
        assert report.accepted, report.failed
        return report, request.contract

    return raw, service, validate_egress


def approval_context(raw, workload_contract):
    cfg = parse_config(raw, allow_unavailable=True)
    return {
        "current_config": cfg,
        "workload_contract": workload_contract,
        "config_revision": revision_id(effective(cfg)),
        "server": cfg.server.name,
    }


@pytest.mark.parametrize(
    ("requested", "patterns", "allowed"),
    [
        pytest.param(
            [egress_rule("192.0.2.0/25", 443)],
            [egress_rule("192.0.2.0/24", 80, 443)],
            True,
            id="narrower-ipv4",
        ),
        pytest.param(
            [egress_rule("192.0.2.0/25", 443), egress_rule("192.0.2.128/25", 443)],
            [egress_rule("192.0.2.0/24", 443)],
            True,
            id="split-request-ipv4",
        ),
        pytest.param(
            [egress_rule("192.0.2.0/24", 443)],
            [egress_rule("192.0.2.0/25", 443), egress_rule("192.0.2.128/25", 443)],
            True,
            id="split-pattern-ipv4",
        ),
        pytest.param(
            [egress_rule("192.0.2.0/24", 443)],
            [egress_rule("192.0.2.0/25", 443)],
            False,
            id="wider-ipv4",
        ),
        pytest.param(
            [egress_rule("2001:db8:1::/48", 53, proto="udp")],
            [egress_rule("2001:db8::/32", 53, proto="udp")],
            True,
            id="narrower-ipv6-udp",
        ),
        pytest.param(
            [egress_rule("2001:db8:1::/48", 53, proto="udp")],
            [egress_rule("2001:db8::/32", 53)],
            False,
            id="wrong-protocol",
        ),
        pytest.param(
            [egress_rule("2001:db8:1::/48", 53, 443, proto="udp")],
            [egress_rule("2001:db8::/32", 53, proto="udp")],
            False,
            id="missing-port",
        ),
        pytest.param(
            [egress_rule("2001:db8:1::/48", 443)],
            [egress_rule("192.0.2.0/24", 443)],
            False,
            id="wrong-family",
        ),
    ],  # fmt: skip
)
def test_repository_egress_patterns_bound_each_requested_rule(
    signed_egress_candidate, requested, patterns, allowed
):
    raw, _, validate_egress = signed_egress_candidate
    raw["repositories"][0]["egress_rule_patterns"] = patterns
    report, candidate_contract = validate_egress(rule_egress(*requested), pinned=True)
    context = approval_context(raw, candidate_contract)
    if allowed:
        statement = approve(report, **context)["statement"]
        assert statement["config_revision"] == context["config_revision"]
        assert statement["project"] == graph_identifier("s", "shop", "backend")
    else:
        with pytest.raises(av.ValidationFailure) as caught:
            approve(report, **context)
        assert caught.value.code == "egress_unconfirmed"


@pytest.mark.parametrize(
    "baseline", ["same", "other-service", "stopped", "unmanaged", "shared", "firewall-off"]
)
def test_public_web_requires_an_active_enforced_baseline_or_one_off_confirmation(
    signed_egress_candidate, baseline
):
    raw, service, validate_egress = signed_egress_candidate
    public_web = {"mode": "public-web"}
    raw["repositories"][0]["egress_rule_patterns"] = [
        egress_rule("0.0.0.0/1", 80, 443),
        egress_rule("128.0.0.0/1", 80, 443),
        egress_rule("::/1", 80, 443),
        egress_rule("8000::/1", 80, 443),
    ]
    if baseline == "other-service":
        raw["applications"][0]["services"][0]["egress"] = public_web
    else:
        service["egress"] = public_web
    if baseline == "stopped":
        service["deploy"] = False
    elif baseline == "unmanaged":
        service["manage"] = False
    elif baseline == "shared":
        raw["applications"][0]["isolation"] = "shared"
    elif baseline == "firewall-off":
        raw["hardening"]["firewall"]["manage"] = False
    report, candidate_contract = validate_egress(public_web)
    context = approval_context(raw, candidate_contract)
    if baseline == "same":
        assert approve(report, **context)["statement"]["project"] == report.project
    else:
        with pytest.raises(av.ValidationFailure) as caught:
            approve(report, **context)
        assert caught.value.code == "egress_unconfirmed"
        assert (
            approve(report, **context, operator_confirmed_egress=True)["statement"]["image"]
            == report.image
        )


@pytest.mark.parametrize(
    "change",
    [
        "config-revision",
        "server",
        "signature",
        "test-revision",
        "contract",
        "operator-contract",
        "policy",
        "repository-id",
        "service",
        "url",
        "ref",
        "pin",
        "wrong-commit",
        "missing-config",
        "missing-contract",
    ],  # fmt: skip
)
def test_repository_egress_confirmation_requires_intact_context(signed_egress_candidate, change):
    raw, service, validate_egress = signed_egress_candidate
    rule = egress_rule("192.0.2.0/25", 443)
    repo = raw["repositories"][0]
    repo["egress_rule_patterns"] = [rule]
    report, candidate_contract = validate_egress(
        rule_egress(rule), requested_revision="e" * 40 if change == "wrong-commit" else None
    )
    if change == "operator-contract":
        repo["contract"] = {**candidate_contract, "egress": {"mode": "none"}}
    elif change == "policy":
        service["update"]["approval_max_ttl_s"] = POLICY.approval_max_ttl_s + 1
    elif change == "repository-id":
        repo["id"] = "another-repo"
    elif change == "service":
        repo["service"] = "frontend"
        next(s for s in raw["applications"][0]["services"] if s["id"] == "frontend")["update"] = (
            service["update"]
        )
    elif change == "url":
        repo["url"] = "https://git.example.org/shop/another.git"
    elif change == "ref":
        repo["ref"] = "refs/heads/release"
    elif change == "pin":
        repo["revision"] = "e" * 40
    elif change == "contract":
        candidate_contract = {**candidate_contract, "egress": {"mode": "none"}}
    elif change == "signature":
        signature = report.attestation["signature"]
        report.attestation["signature"] = ("B" if signature[0] == "A" else "A") + signature[1:]
    elif change == "test-revision":
        report.test_revision = "f" * 64

    context = approval_context(raw, candidate_contract)
    if change == "config-revision":
        context["config_revision"] = CONFIG_REVISION
    elif change == "server":
        context["server"] = "other-server"
    elif change == "missing-config":
        del context["current_config"]
    elif change == "missing-contract":
        del context["workload_contract"]
    with pytest.raises(av.ValidationFailure):
        approve(report, **context, operator_confirmed_egress=True)


def test_unsigned_report_egress_mode_cannot_hide_widening(signed_egress_candidate):
    raw, _, validate_egress = signed_egress_candidate
    report, candidate_contract = validate_egress({"mode": "public-web"})
    report.egress_mode = "none"
    with pytest.raises(av.ValidationFailure, match="egress_binding_mismatch"):
        approve(report, **approval_context(raw, candidate_contract))
    with pytest.raises(av.ValidationFailure, match="egress_binding_mismatch"):
        approve(report)


def test_unset_repository_egress_patterns_still_require_confirmation(signed_egress_candidate):
    raw, _, validate_egress = signed_egress_candidate
    report, candidate_contract = validate_egress(rule_egress(egress_rule("192.0.2.0/25", 443)))
    context = approval_context(raw, candidate_contract)
    with pytest.raises(av.ValidationFailure, match="egress_unconfirmed"):
        approve(report, **context)
    assert (
        approve(report, **context, operator_confirmed_egress=True)["statement"]["image"]
        == report.image
    )


def test_mapped_candidate_without_egress_still_requires_current_context(signed_egress_candidate):
    raw, _, validate_egress = signed_egress_candidate
    report, candidate_contract = validate_egress({"mode": "none"})
    with pytest.raises(av.ValidationFailure, match="egress_binding_mismatch"):
        approve(report, operator_confirmed_egress=True)
    assert (
        approve(report, **approval_context(raw, candidate_contract))["statement"]["image"]
        == report.image
    )


@pytest.mark.parametrize(
    ("request_rule", "patterns", "allowed"),
    [
        (egress_rule("192.0.2.5/32", 443), [], True),
        (egress_rule("2001:db8::1/128", 80), [], True),
        (egress_rule("192.0.2.5/32", 443, proto="udp"), [], False),
        (egress_rule("192.0.2.5/32", 8443), [], False),
        (egress_rule("10.254.253.20/32", 443), [], False),
        (egress_rule("fc00::5/128", 80), [], False),
        (egress_rule("192.0.0.0/23", 443), [egress_rule("192.0.0.0/24", 443)], True),
    ],
)
def test_explicit_rules_use_active_public_web_with_its_exclusions(
    signed_egress_candidate, request_rule, patterns, allowed
):
    raw, service, validate_egress = signed_egress_candidate
    service["egress"] = {"mode": "public-web"}
    raw["repositories"][0]["egress_rule_patterns"] = patterns
    report, candidate_contract = validate_egress(rule_egress(request_rule))
    context = approval_context(raw, candidate_contract)
    if allowed:
        assert approve(report, **context)["statement"]["image"] == report.image
    else:
        with pytest.raises(av.ValidationFailure, match="egress_unconfirmed"):
            approve(report, **context)


def test_active_rules_and_patterns_cover_one_range_and_approval_binds_revision(
    signed_egress_candidate,
):
    raw, service, validate_egress = signed_egress_candidate
    service["egress"] = rule_egress(egress_rule("192.0.2.0/25", 443))
    repo = raw["repositories"][0]
    repo["egress_rule_patterns"] = [egress_rule("192.0.2.128/25", 443)]
    report, candidate_contract = validate_egress(rule_egress(egress_rule("192.0.2.0/24", 443)))
    context = approval_context(raw, candidate_contract)
    approval = approve(report, **context)

    del repo["egress_rule_patterns"]
    current = approval_context(raw, candidate_contract)
    with pytest.raises(av.ValidationFailure, match="egress_binding_mismatch"):
        approve(report, **{**current, "config_revision": context["config_revision"]})
    with pytest.raises(av.ValidationFailure, match="egress_unconfirmed"):
        approve(report, **current)
    with pytest.raises(UpdateRejected, match="revision_mismatch"):
        validate_update(
            POLICY,
            server=current["server"],
            project=report.project,
            config_revision=current["config_revision"],
            current_image=OLD_IMAGE,
            candidate_digest=OUT,
            attestation=report.attestation,
            approval=approval,
            now=NOW,
        )


@pytest.mark.parametrize("compatibility", ["missing_extension", None, "restore_required"])
@pytest.mark.parametrize("confirmed", [False, True])
def test_approval_requires_consistent_signed_repository_compatibility(
    candidate, dirs, compatibility, confirmed
):
    report, _, _ = validate(candidate, dirs)
    statement = copy.deepcopy(report.attestation["statement"])
    if compatibility == "missing_extension":
        del statement["repository_validation"]
    elif compatibility is None:
        del statement["repository_validation"]["compatibility"]
    else:
        statement["repository_validation"]["compatibility"] = compatibility
    report.attestation = sign_statement(SIGNER, "ci-signer", statement)

    with pytest.raises(av.ValidationFailure) as caught:
        approve(report, operator_confirmed_egress=confirmed)
    assert caught.value.code == "migration_unobserved"


@pytest.mark.parametrize(
    ("scan_change", "code"),
    [
        ({"state": "confirmed"}, "scan_not_clean"),
        ({"checked_at": NOW + 61}, "stale_scan"),
    ],
)
def test_approval_requires_clean_fresh_signed_repository_scan(candidate, dirs, scan_change, code):
    report, _, _ = validate(candidate, dirs)
    statement = copy.deepcopy(report.attestation["statement"])
    report.scan = {**report.scan, **scan_change}
    statement["repository_validation"]["scan"] = report.scan
    report.attestation = sign_statement(SIGNER, "ci-signer", statement)

    with pytest.raises(av.ValidationFailure) as caught:
        approve(report, operator_confirmed_egress=True)
    assert caught.value.code == code


def test_report_cannot_refresh_signed_scan_time(candidate, dirs):
    report, _, _ = validate(candidate, dirs)
    now = NOW + POLICY.scan_max_age_s
    with pytest.raises(av.ValidationFailure, match="stale_scan"):
        approve(report, now=now)

    report.scan["checked_at"] = NOW
    with pytest.raises(av.ValidationFailure, match="scan_mismatch"):
        approve(report, now=now, operator_confirmed_egress=True)


def test_validator_does_not_attest_to_a_mutated_build_request_contract(candidate, dirs):
    request, _ = candidate
    request.contract["egress"] = {"mode": "public-web"}
    report, _, _ = validate(candidate, dirs)
    assert report.failed == ["record_binding:contract_digest_mismatch"]
    assert report.attestation is None
