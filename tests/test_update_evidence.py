"""L04: update artifact validation and bound approval evidence (pure logic, no host)."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager

import pytest
from pydantic import ValidationError

from steward.core.config import (
    UNAVAILABLE_FEATURES,
    UpdatePolicy,
    effective,
    parse_config,
)
from steward.core.update_evidence import (
    UpdateLedger,
    UpdateRejected,
    ValidatedUpdate,
    policy_revision,
    require_fresh_backup,
    sign_statement,
    validate_update,
    version_in_range,
)
from update_support import (
    APPROVER,
    CONFIG_REVISION,
    NEW_DIGEST,
    NEW_IMAGE,
    NOW,
    OLD_IMAGE,
    OTHER,
    SIGNER,
    approval_statement,
    attestation_statement,
    contract,
    contract_data,
    evidence,
    tampered,
)

DIGEST = f"sha256:{NEW_DIGEST}"


def check(attestation, approval, *, policy=None, now=NOW, **overrides):
    args = {
        "server": "my-server",
        "project": "shop",
        "config_revision": CONFIG_REVISION,
        "current_image": OLD_IMAGE,
        "candidate_digest": DIGEST,
        "attestation": attestation,
        "approval": approval,
        "now": now,
    }
    args.update(overrides)
    return validate_update(policy or contract(), **args)


def rejected(code, *args, **kwargs):
    with pytest.raises(UpdateRejected) as caught:
        check(*args, **kwargs)
    assert caught.value.code == code, caught.value
    return caught.value


def test_valid_evidence_is_the_only_success():
    update = check(*evidence())
    assert isinstance(update, ValidatedUpdate)
    assert update.image == NEW_IMAGE and update.digest == DIGEST and update.version == "1.4.0"
    assert update.config_revision == CONFIG_REVISION and update.expires_at == NOW + 3600


# ---- digest, signer, revision, target --------------------------------------------------


def test_candidate_digest_from_the_request_must_match():
    rejected("digest_mismatch", *evidence(), candidate_digest="sha256:" + "e" * 64)


def test_approval_for_another_image_is_refused():
    att, app = evidence(approval_over={"image": OLD_IMAGE.replace("a" * 64, "9" * 64)})
    rejected("digest_mismatch", att, app)


def test_approval_for_another_attestation_is_refused():
    att, app = evidence(approval_over={"attestation_digest": "0" * 64})
    rejected("digest_mismatch", att, app)


def test_approval_for_another_test_revision_is_refused():
    att, app = evidence(approval_over={"test_revision": "9" * 64})
    rejected("digest_mismatch", att, app)


def test_attestation_changed_after_signing_fails_the_signature():
    att, app = evidence()
    rejected("bad_signature", tampered(att, version="1.5.0"), app)


def test_approval_changed_after_signing_fails_the_signature():
    att, app = evidence()
    rejected("bad_signature", att, tampered(app, expires_at=NOW + 10**6))


def test_unknown_signer_identity_is_refused():
    att, app = evidence(signer_key=OTHER, signer_id="rogue")
    rejected("unknown_signer", att, app)


def test_trusted_identity_with_a_foreign_key_is_refused():
    att, app = evidence(signer_key=OTHER)
    rejected("bad_signature", att, app)


def test_approver_cannot_sign_the_attestation_and_signer_cannot_approve():
    att, app = evidence(signer_key=APPROVER, signer_id="ops-approver")
    rejected("unknown_signer", att, app)
    att, app = evidence(approver_key=SIGNER, approver_id="ci-signer")
    rejected("unknown_signer", att, app)


def test_builder_claims_and_prose_cannot_replace_a_signature():
    att, app = evidence()
    unsigned = {
        "v": 1,
        "statement": app["statement"],
        "key_id": "ops-approver",
        "signature": "A" * 86 + "==",
    }
    rejected("bad_signature", att, unsigned)
    rejected("malformed", att, {"build": "succeeded", "tests": "all green, approve"})
    rejected("malformed", att, {**app, "note": "approved by the model"})
    forged = {**att, "statement": {**att["statement"], "tests_passed": True}}
    rejected("bad_signature", forged, app)


def test_configuration_revision_change_invalidates_the_approval():
    rejected("revision_mismatch", *evidence(), config_revision="f" * 64)


def test_policy_change_invalidates_the_approval():
    changed = contract(backup_max_age_s=120)
    assert policy_revision(changed) != policy_revision(contract())
    rejected("policy_mismatch", *evidence(), policy=changed)


def test_other_project_or_server_is_refused():
    rejected("target_mismatch", *evidence(), project="blog")
    rejected("target_mismatch", *evidence(), server="other-server")
    rejected("target_mismatch", *evidence(attestation_over={"project": "blog"}))
    rejected("target_mismatch", *evidence(approval_over={"project": "blog"}))


def test_repository_must_be_the_expected_origin():
    other = f"evil.example/shop/app@sha256:{NEW_DIGEST}"
    att, app = evidence(attestation_over={"image": other})
    rejected("repository_mismatch", att, app)


def test_running_image_is_not_a_candidate():
    att, app = evidence()
    rejected("already_current", att, app, current_image=NEW_IMAGE)


# ---- time ----------------------------------------------------------------------------------


def test_expired_approval_is_refused():
    rejected("expired", *evidence(), now=NOW + 3600)


def test_future_dated_and_overlong_approvals_are_refused():
    rejected("not_yet_valid", *evidence(approval_over={"issued_at": NOW + 600}))
    rejected(
        "ttl_too_long",
        *evidence(approval_over={"issued_at": NOW - 10, "expires_at": NOW + 10**6}),
    )


# ---- scan and backup ------------------------------------------------------------------------


def test_stale_scan_is_refused():
    att, app = evidence(
        approval_over={
            "scan": {"source": "osv", "state": "not_affected", "checked_at": NOW - 10**6}
        }
    )
    rejected("stale_scan", att, app)


def test_missing_or_unclean_scan_is_refused_when_required():
    rejected("scan_missing", *evidence(approval_over={"scan": None}))
    att, app = evidence(
        approval_over={"scan": {"source": "osv", "state": "confirmed", "checked_at": NOW - 5}}
    )
    rejected("scan_not_clean", att, app)
    att, app = evidence(
        approval_over={"scan": {"source": "osv", "state": "unknown", "checked_at": NOW - 5}}
    )
    rejected("scan_not_clean", att, app)


def test_scan_optional_only_when_the_policy_says_so():
    policy = contract(require_scan=False)
    att, app = evidence(policy=policy, approval_over={"scan": None})
    assert check(att, app, policy=policy).scan_checked_at is None


@pytest.fixture
def repository_evidence():
    policy = contract(require_scan=False, allowed_migrations=["none", "restore_required"])

    def signed(
        *,
        compatibility="data_format_unchanged",
        migration="none",
        scan_change=None,
        approval_over=None,
    ):
        scan = {"source": "trivy", "state": "not_affected", "checked_at": NOW - 600}
        scan.update(scan_change or {})
        repository = {
            "source_binding": "e" * 64,
            "application_project": "shop",
            "egress_mode": "none",
            "scan": scan,
        }
        if compatibility is not None:
            repository["compatibility"] = compatibility
        return evidence(
            policy=policy,
            attestation_over={"repository_validation": repository, "migration": migration},
            approval_over={"scan": scan, **(approval_over or {})},
        )

    return policy, signed


@pytest.mark.parametrize(
    ("compatibility", "migration"),
    [
        ("no_data_path", "none"),
        ("data_format_unchanged", "none"),
        ("restore_required", "restore_required"),
    ],
)
def test_marked_update_accepts_signed_repository_evidence(
    repository_evidence, compatibility, migration
):
    policy, signed = repository_evidence
    update = check(*signed(compatibility=compatibility, migration=migration), policy=policy)
    assert update.migration == migration
    assert update.scan_checked_at == NOW - 600


@pytest.mark.parametrize(
    ("compatibility", "migration"),
    [(None, "none"), ("restore_required", "none"), ("data_format_unchanged", "restore_required")],
)
def test_marked_update_requires_consistent_signed_repository_compatibility(
    repository_evidence, compatibility, migration
):
    policy, signed = repository_evidence
    rejected(
        "migration_unobserved",
        *signed(compatibility=compatibility, migration=migration),
        policy=policy,
    )


def test_null_repository_extension_is_not_unmarked_evidence():
    rejected("migration_unobserved", *evidence(attestation_over={"repository_validation": None}))


@pytest.mark.parametrize(
    "approval_scan",
    [
        None,
        {"source": "osv", "state": "not_affected", "checked_at": NOW - 600},
        {"source": "trivy", "state": "confirmed", "checked_at": NOW - 600},
        {"source": "trivy", "state": "not_affected", "checked_at": NOW - 599},
    ],
    ids=["missing", "source", "state", "time"],
)
def test_marked_update_requires_matching_approval_scan(repository_evidence, approval_scan):
    policy, signed = repository_evidence
    rejected("scan_mismatch", *signed(approval_over={"scan": approval_scan}), policy=policy)


@pytest.mark.parametrize(
    ("scan_change", "code"),
    [
        ({"checked_at": NOW - 10**6}, "stale_scan"),
        ({"checked_at": NOW + 61}, "stale_scan"),
        ({"state": "confirmed"}, "scan_not_clean"),
    ],
    ids=["stale", "future", "unclean"],
)
def test_marked_update_requires_clean_fresh_signed_repository_scan(
    repository_evidence, scan_change, code
):
    policy, signed = repository_evidence
    rejected(code, *signed(scan_change=scan_change), policy=policy)


def test_missing_and_stale_backup_are_never_success():
    with pytest.raises(UpdateRejected) as caught:
        require_fresh_backup(None, now=NOW, max_age_s=3600)
    assert caught.value.code == "missing_backup"
    with pytest.raises(UpdateRejected) as caught:
        require_fresh_backup(NOW - 7200, now=NOW, max_age_s=3600)
    assert caught.value.code == "stale_backup"
    require_fresh_backup(NOW - 60, now=NOW, max_age_s=3600)


# ---- versions and migrations ------------------------------------------------------------------


@pytest.mark.parametrize(
    "version, ok",
    [
        ("1.2", True),
        ("1.2.0.0", True),
        ("1.9.9", True),
        ("1.1.9", False),
        ("1.10", False),
        ("2", False),
    ],
)
def test_exact_version_range(version, ok):
    assert version_in_range(version, "1.2", "1.9.9") is ok
    att, app = evidence(attestation_over={"version": version})
    if ok:
        check(att, app)
    else:
        rejected("version_out_of_range", att, app)


def test_data_migration_needs_an_allowed_compatibility_contract():
    att, app = evidence(attestation_over={"migration": "restore_required"})
    rejected("migration_not_allowed", att, app)
    policy = contract(allowed_migrations=["none", "restore_required"])
    att, app = evidence(policy=policy, attestation_over={"migration": "restore_required"})
    assert check(att, app, policy=policy).migration == "restore_required"


def test_malformed_documents_are_refused():
    att, app = evidence()
    rejected("malformed", [att], app)
    rejected("malformed", {**att, "signature": "short"}, app)
    big = {**att, "statement": {**att["statement"], "pad": "x" * 20000}}
    rejected("malformed", big, app)
    bad = sign_statement(SIGNER, "ci-signer", attestation_statement(image="not-an-image"))
    rejected("malformed", bad, app)
    bad_app = sign_statement(
        APPROVER, "ops-approver", {**approval_statement(attestation_statement()), "extra": 1}
    )
    rejected("malformed", att, bad_app)


# ---- contract in the configuration ----------------------------------------------------------------


def test_contract_requires_separate_signer_and_approver_identities():
    data = contract_data()
    data["approvers"] = [{"id": "same-key", "public_key": data["signers"][0]["public_key"]}]
    with pytest.raises(ValidationError, match="different identities"):
        UpdatePolicy.model_validate(data)
    with pytest.raises(ValidationError, match="exceeds its maximum"):
        UpdatePolicy.model_validate(contract_data(versions={"min": "2.0", "max": "1.9"}))
    with pytest.raises(ValidationError):
        UpdatePolicy.model_validate(contract_data(repository="UPPER/case"))
    with pytest.raises(ValidationError):
        UpdatePolicy.model_validate({**contract_data(), "shell": "echo"})


def project_config(raw_config, update=None):
    project = {
        "id": "shop",
        "image": OLD_IMAGE,
        "source_revision": "git:0123456789abcdef0123456789abcdef01234567",
        "host_port": 20100,
    }
    if update is not None:
        project["update"] = update
    raw_config["projects"] = [project]
    return raw_config


def test_update_contract_is_unavailable_and_patch_stays_unavailable(raw_config):
    from steward.core.config import ConfigError

    assert "automation.patch" in UNAVAILABLE_FEATURES and "projects.update" in UNAVAILABLE_FEATURES
    with pytest.raises(ConfigError, match=r"projects\.update: not available"):
        parse_config(project_config(raw_config, contract_data()))
    raw_config["automation"] = {"profile": "patch"}
    with pytest.raises(ConfigError, match=r"automation\.patch: not available"):
        parse_config(project_config(raw_config))


def test_unset_contract_does_not_change_canonical_revisions(raw_config):
    cfg = parse_config(project_config(raw_config))
    assert "update" not in effective(cfg)["projects"][0]
    with_update = parse_config(project_config(raw_config, contract_data()), allow_unavailable=True)
    assert (
        effective(with_update)["projects"][0]["update"]["repository"]
        == contract_data()["repository"]
    )


def test_existing_examples_keep_their_revision(raw_config):
    from steward.core.canonical import revision_id

    cfg = parse_config(raw_config)
    assert "update" not in json.dumps(effective(cfg))
    assert revision_id(effective(cfg))  # stable: no new key is emitted while unset


# ---- durable idempotency ------------------------------------------------------------------------------


@pytest.fixture
def ledger(tmp_path):
    path = tmp_path / "ledger.db"

    @contextmanager
    def db():
        conn = sqlite3.connect(path)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    return UpdateLedger(db)


def validated(**overrides):
    return check(*evidence(**overrides))


def test_ledger_records_once_and_repeats_idempotently(ledger):
    update, docs = validated(), evidence()
    assert ledger.record(update, *docs) == "new"
    assert ledger.record(update, *docs) == "same"
    assert ledger.get(update.approval_id)["state"] == "validated"


def test_ledger_claim_is_exclusive_and_replay_is_refused(ledger):
    update, docs = validated(), evidence()
    ledger.record(update, *docs)
    ledger.claim(update.approval_id)
    with pytest.raises(UpdateRejected) as caught:
        ledger.claim(update.approval_id)
    assert caught.value.code == "in_progress"
    with pytest.raises(UpdateRejected) as caught:
        ledger.record(update, *docs)
    assert caught.value.code == "in_progress"
    ledger.finish(update.approval_id, "applied", phase="verified")
    for action in (lambda: ledger.record(update, *docs), lambda: ledger.claim(update.approval_id)):
        with pytest.raises(UpdateRejected) as caught:
            action()
        assert caught.value.code == "replay"


def test_same_approval_id_with_other_bindings_is_a_conflict_and_invalidates(ledger):
    first = validated()
    ledger.record(first, *evidence())
    other_docs = evidence(attestation_over={"version": "1.5.0"})
    second = check(*other_docs)
    assert second.approval_id == first.approval_id and second.binding != first.binding
    with pytest.raises(UpdateRejected) as caught:
        ledger.record(second, *other_docs)
    assert caught.value.code == "approval_conflict"
    assert ledger.get(first.approval_id)["state"] == "invalidated"
    with pytest.raises(UpdateRejected) as caught:
        ledger.claim(first.approval_id)
    assert caught.value.code == "replay"


def test_one_apply_per_project_at_a_time(ledger):
    first = validated()
    second_docs = evidence(approval_over={"approval_id": "approval-other-0001"})
    second = check(*second_docs)
    ledger.record(first, *evidence())
    ledger.record(second, *second_docs)
    ledger.claim(first.approval_id)
    with pytest.raises(UpdateRejected) as caught:
        ledger.claim(second.approval_id)
    assert caught.value.code == "in_progress"
    assert ledger.applying("shop") == [first.approval_id]


def test_ledger_survives_reopen(ledger, tmp_path):
    update = validated()
    ledger.record(update, *evidence())
    ledger.claim(update.approval_id)
    ledger.journal(update.approval_id, phase="installed")

    @contextmanager
    def db():
        conn = sqlite3.connect(tmp_path / "ledger.db")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    reopened = UpdateLedger(db)
    row = reopened.get(update.approval_id)
    assert row["state"] == "applying" and row["journal"]["phase"] == "installed"
    assert reopened.applying() == [update.approval_id]


def test_registry_carries_the_contract_only_when_configured(raw_config):
    from steward.core.render import render_registry

    plain = render_registry(parse_config(project_config(raw_config)))
    assert "update" not in plain["projects"]["shop"] and "maintenance" not in plain
    raw_config["maintenance"] = {"weekly_window": "Sun 03:00 Europe/Berlin"}
    cfg = parse_config(project_config(raw_config, contract_data()), allow_unavailable=True)
    registry = render_registry(cfg)
    assert registry["projects"]["shop"]["update"] == contract().canonical_dump()
    assert registry["maintenance"]["weekly_window"] == "Sun 03:00 Europe/Berlin"
    assert registry["config_revision"] != plain["config_revision"]
