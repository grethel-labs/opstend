import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from steward.core.fleet_identity import FleetIdentityRegistry
from steward.core.fleet_policy import (
    FleetPolicy,
    FleetPolicyStore,
    FleetPolicyValues,
    FleetTarget,
    FleetTargetPolicy,
)
from steward.core.fleet_policy_target import FleetPolicyTargetConfig, FleetPolicyTargetStore


@pytest.fixture
def target_files(tmp_path):
    registry = FleetIdentityRegistry(tmp_path / "coordinator.db")
    site = registry.register_site("lab")
    host = registry.register_host(site.id, "local-target")
    target = FleetTarget(kind="host", id=host.id)
    config = FleetPolicyTargetConfig(target=target, limits=FleetPolicyValues())
    return registry, tmp_path / "local.db", config


def test_target_provisioning_pins_identity_and_preserves_local_metadata(target_files):
    registry, target_path, config = target_files
    target = FleetPolicyTargetStore.configure(target_path, config)
    store = FleetPolicyStore(registry)
    record = store.commit(
        FleetPolicy(targets=(FleetTargetPolicy(target=config.target),)), parent=None
    )
    approval_id = uuid4().hex
    with target.transaction(registry) as db:
        state = target.read(db, datetime.now(UTC))
        assert state.applied_revision is None
        plan = store.effective(
            record.id,
            config.target,
            local=state.local,
            expected_local_revision=state.local.revision,
        )
        assert plan is not None and plan.status == "ready"
        target.apply(db, plan, approval_id)

    new_limits = FleetPolicyValues(backup_profile_refs=("daily",))
    reprovisioned = FleetPolicyTargetStore.configure(
        target_path, config.model_copy(update={"limits": new_limits})
    ).state()
    assert reprovisioned.local.revision != state.local.revision
    assert reprovisioned.local.limits == new_limits
    assert reprovisioned.applied_revision == record.id
    assert reprovisioned.approval_id == approval_id
    assert reprovisioned.effective == plan
    with pytest.raises(ValueError, match="already pinned"):
        FleetPolicyTargetStore.configure(
            target_path,
            config.model_copy(update={"target": FleetTarget(kind="host", id=uuid4().hex)}),
        )
    assert target.state().local.target == config.target


def test_separate_policy_databases_commit_together_and_reject_aliases(target_files):
    registry, target_path, config = target_files
    target = FleetPolicyTargetStore.configure(target_path, config)
    with (
        pytest.raises(ValueError, match="distinct databases"),
        FleetPolicyTargetStore(registry._path).transaction(registry),
    ):
        pytest.fail("identical databases were admitted")
    with pytest.raises(ValueError, match="unrelated schema"):
        FleetPolicyTargetStore.configure(registry._path, config)

    store = FleetPolicyStore(registry)
    record = store.commit(
        FleetPolicy(targets=(FleetTargetPolicy(target=config.target),)), parent=None
    )
    state = target.state()
    plan = store.effective(
        record.id, config.target, local=state.local, expected_local_revision=state.local.revision
    )
    assert plan is not None
    with pytest.raises(RuntimeError, match="receipt failure"), target.transaction(registry) as db:
        db.execute("CREATE TABLE test_policy_receipt (revision TEXT)")
        db.execute("INSERT INTO test_policy_receipt VALUES (?)", (record.id,))
        target.apply(db, plan, uuid4().hex)
        raise RuntimeError("receipt failure")
    assert target.state().applied_revision is None
    with registry._connection() as db:
        assert not db.execute(
            "SELECT name FROM sqlite_schema WHERE name IN ('test_policy_receipt', 'fleet_local_policy')"
        ).fetchall()


@pytest.mark.parametrize("wal", ["coordinator", "target"])
def test_attached_adoption_refuses_wal_before_writing(target_files, wal):
    registry, target_path, config = target_files
    target = FleetPolicyTargetStore.configure(target_path, config)
    path = registry._path if wal == "coordinator" else target_path
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("PRAGMA journal_mode = WAL").fetchone()[0] == "wal"

    with pytest.raises(ValueError, match="DELETE journal"), target.transaction(registry):
        pytest.fail("unsafe journal mode was admitted")
    assert target.state().applied_revision is None
