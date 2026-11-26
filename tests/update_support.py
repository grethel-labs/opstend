"""Shared builders for update evidence tests: keys, contracts, signed statements."""

from __future__ import annotations

import copy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from steward.core.canonical import revision_id
from steward.core.config import UpdatePolicy
from steward.core.update_evidence import policy_revision, public_key_b64, sign_statement

REPOSITORY = "registry.example/shop/app"
OLD_DIGEST = "a" * 64
NEW_DIGEST = "b" * 64
OLD_IMAGE = f"{REPOSITORY}@sha256:{OLD_DIGEST}"
NEW_IMAGE = f"{REPOSITORY}@sha256:{NEW_DIGEST}"
CONFIG_REVISION = "c" * 64
TEST_REVISION = "d" * 64
NOW = 1_800_000_000.0

SIGNER = Ed25519PrivateKey.generate()
APPROVER = Ed25519PrivateKey.generate()
OTHER = Ed25519PrivateKey.generate()


def contract_data(**overrides) -> dict:
    data = {
        "repository": REPOSITORY,
        "versions": {"min": "1.2", "max": "1.9.9"},
        "signers": [{"id": "ci-signer", "public_key": public_key_b64(SIGNER)}],
        "approvers": [{"id": "ops-approver", "public_key": public_key_b64(APPROVER)}],
    }
    data.update(overrides)
    return data


def contract(**overrides) -> UpdatePolicy:
    return UpdatePolicy.model_validate(contract_data(**overrides))


def attestation_statement(**overrides) -> dict:
    statement = {
        "type": "steward.image-attestation.v1",
        "project": "shop",
        "image": NEW_IMAGE,
        "version": "1.4.0",
        "source_revision": "git:0123456789abcdef0123456789abcdef01234567",
        "test_revision": TEST_REVISION,
        "migration": "none",
        "created_at": NOW - 600,
    }
    statement.update(overrides)
    return statement


def approval_statement(attestation: dict, policy: UpdatePolicy | None = None, **overrides) -> dict:
    statement = {
        "type": "steward.update-approval.v1",
        "approval_id": "approval-0123456789",
        "server": "my-server",
        "project": "shop",
        "config_revision": CONFIG_REVISION,
        "policy_revision": policy_revision(policy or contract()),
        "image": attestation["image"],
        "attestation_digest": revision_id(attestation),
        "test_revision": attestation["test_revision"],
        "scan": {"source": "trivy", "state": "not_affected", "checked_at": NOW - 600},
        "issued_at": NOW - 300,
        "expires_at": NOW + 3600,
    }
    statement.update(overrides)
    return statement


def evidence(
    *,
    attestation_over: dict | None = None,
    approval_over: dict | None = None,
    policy: UpdatePolicy | None = None,
    signer_key=SIGNER,
    signer_id="ci-signer",
    approver_key=APPROVER,
    approver_id="ops-approver",
) -> tuple[dict, dict]:
    att = attestation_statement(**(attestation_over or {}))
    app = approval_statement(att, policy, **(approval_over or {}))
    return (
        sign_statement(signer_key, signer_id, att),
        sign_statement(approver_key, approver_id, app),
    )


def tampered(document: dict, **statement_changes) -> dict:
    out = copy.deepcopy(document)
    out["statement"].update(statement_changes)
    return out
