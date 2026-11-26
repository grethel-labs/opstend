#!/usr/bin/env python3
"""Throwaway-key evidence tool for the M3 L05 gate (test keys only, never production).

  gate_evidence.py keygen KEYDIR
  gate_evidence.py evidence KEYDIR REGISTRY_JSON IMAGE VERSION VARIANT APPROVAL_ID

`keygen` writes signer.key and approver.key (base64 raw private keys, mode 0600)
and prints the two public-key blocks for the `update:` contract.
`evidence` prints the JSON parameters of `update_validate` for the deployed
registry. VARIANT selects a deliberate defect so each refusal can be observed.
"""

import base64
import json
import pathlib
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from steward.core.canonical import revision_id
from steward.core.config import UpdatePolicy
from steward.core.update_evidence import policy_revision, public_key_b64, sign_statement

TEST_REVISION = "d" * 64


def load(path):
    raw = base64.b64decode(pathlib.Path(path).read_text())
    return Ed25519PrivateKey.from_private_bytes(raw)


def keygen(keydir):
    keydir = pathlib.Path(keydir)
    keydir.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ("signer", "approver"):
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        path = keydir / f"{name}.key"
        path.write_text(base64.b64encode(raw).decode())
        path.chmod(0o600)
        print(f"{name}: id={name}-1 public_key={public_key_b64(key)}")


def evidence(keydir, registry_file, image, version, variant, approval_id):
    registry = json.loads(pathlib.Path(registry_file).read_text())
    spec = registry["projects"]["shop"]
    contract = UpdatePolicy.model_validate(spec["update"])
    now = time.time()
    signer, approver = load(f"{keydir}/signer.key"), load(f"{keydir}/approver.key")
    signer_id, approver_id = "signer-1", "approver-1"
    attestation = {
        "type": "steward.image-attestation.v1",
        "project": "shop",
        "image": image,
        "version": version,
        "source_revision": "gate:l05-fixture",
        "test_revision": TEST_REVISION,
        "migration": "none",
        "created_at": now - 600,
    }
    if variant == "repository":
        attestation["image"] = image.replace("/shop/app@", "/other/app@")
    if variant == "version":
        attestation["version"] = "9.0"
    if variant == "target":
        attestation["project"] = "other"
    approval = {
        "type": "steward.update-approval.v1",
        "approval_id": approval_id,
        "server": registry["server_name"],
        "project": "other" if variant == "target" else "shop",
        "config_revision": "e" * 64 if variant == "revision" else registry["config_revision"],
        "policy_revision": policy_revision(contract),
        "image": attestation["image"],
        "attestation_digest": revision_id(attestation),
        "test_revision": TEST_REVISION,
        "scan": {
            "source": "trivy",
            "state": "confirmed" if variant == "scan-unclean" else "not_affected",
            "checked_at": now - (172800 if variant == "stale-scan" else 60),
        },
        "issued_at": now - (3600 if variant == "expired" else 30),
        "expires_at": now - 10 if variant == "expired" else now + 1800,
    }
    if variant == "digest-mismatch":
        approval["image"] = image.replace(image.rsplit("@", 1)[1][7:15], "0" * 8)
    if variant == "unknown-signer":
        signer_id = "rogue"
    if variant == "wrong-approver-key":
        approver = Ed25519PrivateKey.generate()
    print(
        json.dumps(
            {
                "project_id": "shop",
                "digest": image.rsplit("@", 1)[1],
                "attestation": sign_statement(signer, signer_id, attestation),
                "approval": sign_statement(approver, approver_id, approval),
            }
        )
    )


if __name__ == "__main__":
    if sys.argv[1] == "keygen":
        keygen(sys.argv[2])
    else:
        evidence(*sys.argv[2:8])
