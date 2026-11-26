"""The M3 L06 gate evidence tool must produce evidence the real validator accepts."""

from __future__ import annotations

import importlib.util
import json
import re
import time
from pathlib import Path

import pytest

from steward.core.config import UpdatePolicy
from steward.core.update_evidence import UpdateRejected, validate_update
from update_support import NEW_IMAGE, OLD_IMAGE, contract_data

GATES = Path(__file__).parent / "integration" / "gates"


@pytest.fixture
def tool(monkeypatch):
    monkeypatch.syspath_prepend(str(GATES))
    spec = importlib.util.spec_from_file_location("m3_l06_evidence", GATES / "m3_l06_evidence.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def contract_from_keygen(tool, keydir, capsys) -> dict:
    tool.keygen(str(keydir))
    printed = capsys.readouterr().out
    signer = re.search(r"signer: id=(\S+) public_key=(\S+)", printed)
    approver = re.search(r"approver: id=(\S+) public_key=(\S+)", printed)
    return contract_data(
        signers=[{"id": signer[1], "public_key": signer[2]}],
        approvers=[{"id": approver[1], "public_key": approver[2]}],
        allowed_migrations=["none", "reversible", "restore_required"],
    )


def validate(contract, params):
    return validate_update(
        contract,
        server="my-server",
        project="shop",
        config_revision="c" * 64,
        current_image=OLD_IMAGE,
        candidate_digest=params["digest"],
        attestation=params["attestation"],
        approval=params["approval"],
        now=time.time(),
    )


@pytest.mark.parametrize("migration", ["none", "reversible", "restore_required"])
def test_tool_output_is_accepted_by_the_validator(tool, tmp_path, capsys, migration):
    data = contract_from_keygen(tool, tmp_path / "keys", capsys)
    contract = UpdatePolicy.model_validate(data)
    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps(
            {
                "server_name": "my-server",
                "config_revision": "c" * 64,
                "projects": {"shop": {"update": data}},
            }
        )
    )
    keys = str(tmp_path / "keys")
    good = tool.evidence(keys, registry, "shop", NEW_IMAGE, "1.4", migration, "approval-gate-0001")
    update = validate(contract, good)
    assert update.migration == migration and update.image == NEW_IMAGE
    late = tool.evidence(
        keys, registry, "shop", NEW_IMAGE, "1.4", migration, "approval-gate-0002", "expired"
    )
    with pytest.raises(UpdateRejected) as caught:
        validate(contract, late)
    assert caught.value.code == "expired"
