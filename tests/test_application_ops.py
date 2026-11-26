"""Root-registry graph planning is bounded and remains non-mutating."""

from copy import deepcopy

import pytest

from steward.core.application_ops import derive_group_plan
from steward.core.config import parse_config
from steward.core.render import prepare_application_registry
from steward.executor.protocol import ExecutorError
from test_application_graph import graph


def registry_for(raw):
    graph(raw)
    raw["applications"][0]["services"][2]["deploy"] = False
    return prepare_application_registry(parse_config(raw, allow_unavailable=True))


def test_impact_orders_dependents_and_uses_registry_derived_locks(raw_config, executor):
    registry = registry_for(raw_config)
    rev = registry["config_revision"]
    plan = derive_group_plan(registry, "shop", "database", expected_revision=rev)
    assert plan["start_order"] == ["database", "backend", "frontend", "worker"]
    assert plan["stop_order"] == ["worker", "frontend", "backend", "database"]
    assert plan["desired_running"]["frontend"] is False
    assert plan["external_dependencies"] == []
    assert len(plan["lock_targets"]) == 5 and plan["lock_targets"] == sorted(plan["lock_targets"])
    with executor.target_locks(plan["lock_targets"]):
        with (
            pytest.raises(ExecutorError) as error,
            executor.target_lock(registry["applications"]["shop"]["services"]["backend"]["lock"]),
        ):
            pytest.fail("derived group must exclude individual service operations")
        assert error.value.error_class == "target_busy"
    narrower = derive_group_plan(registry, "shop", "backend", expected_revision=rev)
    assert narrower["start_order"] == ["backend", "frontend"]
    assert narrower["stop_order"] == ["frontend", "backend"]
    assert narrower["external_dependencies"] == ["database"]
    assert narrower["external_desired_running"] == {"database": True}
    assert len(narrower["lock_targets"]) == 4
    assert (
        registry["applications"]["shop"]["services"]["database"]["lock"] in narrower["lock_targets"]
    )
    leaf = derive_group_plan(registry, "shop", "frontend", expected_revision=rev)
    assert leaf["start_order"] == ["frontend"]
    assert leaf["external_dependencies"] == ["backend", "database"]
    assert len(leaf["lock_targets"]) == 4
    with executor.target_lock(registry["applications"]["shop"]["services"]["database"]["lock"]):
        with pytest.raises(ExecutorError) as error, executor.target_locks(narrower["lock_targets"]):
            pytest.fail("a dependency mutation must exclude the dependent group")
        assert error.value.error_class == "target_busy"


def test_unmanaged_dependent_prevents_group_impact(raw_config):
    registry = registry_for(raw_config)
    registry["applications"]["shop"]["services"]["worker"]["manage"] = False
    with pytest.raises(ValueError, match="unmanaged"):
        derive_group_plan(
            registry, "shop", "database", expected_revision=registry["config_revision"]
        )
    assert derive_group_plan(
        registry, "shop", "backend", expected_revision=registry["config_revision"]
    )["start_order"] == ["backend", "frontend"]
    registry["applications"]["shop"]["services"]["database"]["manage"] = False
    with pytest.raises(ValueError, match="external dependency is unmanaged"):
        derive_group_plan(
            registry, "shop", "backend", expected_revision=registry["config_revision"]
        )


def test_shared_group_checks_pod_identity(raw_config):
    graph(raw_config)["isolation"] = "shared"
    registry = prepare_application_registry(parse_config(raw_config, allow_unavailable=True))
    revision = registry["config_revision"]
    assert derive_group_plan(registry, "shop", "backend", expected_revision=revision)[
        "start_order"
    ] == ["backend", "frontend"]
    registry["applications"]["shop"]["pod_unit"] = "ssh.service"
    with pytest.raises(ValueError, match="application identity mismatch"):
        derive_group_plan(registry, "shop", "backend", expected_revision=revision)


@pytest.mark.parametrize(
    "fault", ["stale", "target", "unit", "user", "lock", "dependency", "cycle", "bool"]
)
def test_untrusted_or_inconsistent_registrations_never_produce_a_plan(raw_config, fault):
    registry = registry_for(raw_config)
    rev = registry["config_revision"]
    services = registry["applications"]["shop"]["services"]
    target = "database"
    if fault == "stale":
        rev = "a" * 64
    elif fault == "target":
        target = "../../etc"
    elif fault == "unit":
        services["backend"]["unit"] = "ssh.service"
    elif fault == "user":
        services["backend"]["user"] = "root"
    elif fault == "lock":
        services["backend"]["lock"] = "project-../../etc"
    elif fault == "dependency":
        services["backend"]["depends_on"] = ["missing"]
    elif fault == "cycle":
        services["database"]["depends_on"] = ["frontend"]
    else:
        services["backend"]["manage"] = 1
    with pytest.raises(ValueError):
        derive_group_plan(registry, "shop", target, expected_revision=rev)


def test_registry_service_order_does_not_change_derived_impact(raw_config):
    registry = registry_for(raw_config)
    reordered = deepcopy(registry)
    services = reordered["applications"]["shop"]["services"]
    reordered["applications"]["shop"]["services"] = dict(reversed(list(services.items())))
    rev = registry["config_revision"]
    assert derive_group_plan(
        registry, "shop", "database", expected_revision=rev
    ) == derive_group_plan(reordered, "shop", "database", expected_revision=rev)


def test_group_plan_rejects_derived_service_identity_collisions(raw_config, monkeypatch):
    from steward.core import application_ops

    registry = registry_for(raw_config)
    original = application_ops.graph_identifier
    collision = "s" + "0" * 20
    for spec in registry["applications"]["shop"]["services"].values():
        spec.update(
            user="stw-" + collision,
            unit=collision + ".service",
            container=collision,
            lock="project-" + collision,
        )
    monkeypatch.setattr(
        application_ops,
        "graph_identifier",
        lambda kind, *parts: collision if kind == "s" else original(kind, *parts),
    )
    with pytest.raises(ValueError, match="service identity collision"):
        derive_group_plan(
            registry, "shop", "database", expected_revision=registry["config_revision"]
        )


def test_application_scope_includes_independent_services_and_all_locks(raw_config):
    group_registry = registry_for(raw_config)
    revision = group_registry["config_revision"]
    plan = derive_group_plan(
        group_registry, "shop", "frontend", expected_revision=revision, scope="application"
    )
    assert plan["scope"] == "application"
    assert plan["start_order"] == ["database", "backend", "frontend", "worker"]
    assert plan["stop_order"] == list(reversed(plan["start_order"]))
    assert plan["external_dependencies"] == [] and len(plan["lock_targets"]) == 5
    assert plan["desired_running"]["frontend"] is False
    from steward.core.group_checkpoint import GroupPlan

    dependent = derive_group_plan(group_registry, "shop", "frontend", expected_revision=revision)
    with pytest.raises(ValueError, match="inconsistent group plan"):
        GroupPlan.model_validate({**dependent, "scope": "application"})
    with pytest.raises(ValueError):
        derive_group_plan(
            group_registry, "shop", "frontend", expected_revision=revision, scope="unknown"
        )
    group_registry["applications"]["shop"]["services"]["worker"]["manage"] = False
    with pytest.raises(ValueError, match="unmanaged"):
        derive_group_plan(
            group_registry, "shop", "frontend", expected_revision=revision, scope="application"
        )
    assert derive_group_plan(group_registry, "shop", "frontend", expected_revision=revision)[
        "start_order"
    ] == ["frontend"]
