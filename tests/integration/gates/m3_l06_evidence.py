#!/usr/bin/env python3
"""Throwaway-key evidence tool for the M3 L06 gate (test keys only, never production).

  m3_l06_evidence.py keygen KEYDIR                       (same keys as the L05 gate)
  m3_l06_evidence.py evidence KEYDIR REGISTRY_JSON PROJECT IMAGE VERSION MIGRATION APPROVAL_ID [good|expired]

Prints the JSON parameters of `update_validate` for the deployed registry. MIGRATION is
`none`, `reversible` or `restore_required`; it is signed into the attestation, exactly as
an independent signer would declare it. Signer and approver ids default to the ones
`keygen` printed (`signer-1`, `approver-1`).
"""

import json
import pathlib
import sys
import time

from m3_l05_evidence import TEST_REVISION, keygen, load

from steward.core.canonical import revision_id
from steward.core.config import UpdatePolicy
from steward.core.update_evidence import policy_revision, sign_statement


def evidence(
    keydir, registry_file, project, image, version, migration, approval_id, variant="good"
):
    registry = json.loads(pathlib.Path(registry_file).read_text())
    contract = UpdatePolicy.model_validate(registry["projects"][project]["update"])
    now = time.time()
    attestation = {
        "type": "steward.image-attestation.v1",
        "project": project,
        "image": image,
        "version": version,
        "source_revision": "gate:l06-fixture",
        "test_revision": TEST_REVISION,
        "migration": migration,
        "created_at": now - 600,
    }
    expired = variant == "expired"
    approval = {
        "type": "steward.update-approval.v1",
        "approval_id": approval_id,
        "server": registry["server_name"],
        "project": project,
        "config_revision": registry["config_revision"],
        "policy_revision": policy_revision(contract),
        "image": image,
        "attestation_digest": revision_id(attestation),
        "test_revision": TEST_REVISION,
        "scan": {"source": "trivy", "state": "not_affected", "checked_at": now - 60},
        "issued_at": now - (3600 if expired else 30),
        "expires_at": now - 10 if expired else now + 1800,
    }
    return {
        "project_id": project,
        "digest": image.rsplit("@", 1)[1],
        "attestation": sign_statement(load(f"{keydir}/signer.key"), "signer-1", attestation),
        "approval": sign_statement(load(f"{keydir}/approver.key"), "approver-1", approval),
    }


if __name__ == "__main__":
    if sys.argv[1] == "keygen":
        keygen(sys.argv[2])
    else:
        print(json.dumps(evidence(*sys.argv[2:])))
