"""L09 step 1: removal is decided from two complete registries, never inferred."""

import copy

import pytest

from steward.core.config import effective, parse_config
from steward.core.render import prepare_application_registry
from steward.core.retirement import (
    RetirementPlanError,
    classify,
    plan_retirements,
    retirement_lines,
)
from test_application_graph import graph


def configs(raw_config, *, deploy=False, isolation="separate", manage=True):
    with_app = copy.deepcopy(raw_config)
    app = graph(with_app)
    app["isolation"] = isolation
    for service in app["services"]:
        service["deploy"] = deploy
        service["manage"] = manage
    if isolation == "shared":
        for index, service in enumerate(app["services"]):
            service["container_port"] = 9000 + index
    return with_app, copy.deepcopy(raw_config)


def registry(raw, *, projects=True):
    cfg = parse_config(raw, allow_unavailable=True)
    result = prepare_application_registry(cfg)
    if projects:
        result["projects"] = {project.id: {} for project in cfg.projects}
    return result


def test_removed_application_is_a_candidate_with_its_stage(raw_config):
    applied_raw, desired_raw = configs(raw_config, deploy=False)
    plan = plan_retirements(registry(applied_raw), registry(desired_raw))
    [candidate] = plan.candidates
    assert (candidate.application, candidate.isolation, candidate.stage) == (
        "shop",
        "separate",
        "ready",
    )
    assert candidate.services == ["backend", "database", "frontend", "worker"]
    assert candidate.data_services == candidate.services and candidate.retirable
    assert plan.applied_revision != plan.desired_revision


@pytest.mark.parametrize(
    ("kwargs", "stage"),
    [
        ({"deploy": True}, "needs_disable"),
        ({"manage": False}, "unmanaged_services"),
        ({"isolation": "shared"}, "shared_isolation_unavailable"),
    ],
)
def test_non_ready_stages_are_reported_not_retirable(raw_config, kwargs, stage):
    applied_raw, desired_raw = configs(raw_config, **kwargs)
    [candidate] = plan_retirements(registry(applied_raw), registry(desired_raw)).candidates
    assert candidate.stage == stage and not candidate.retirable


def test_manage_false_or_disabled_services_never_make_a_candidate(raw_config):
    applied_raw, _ = configs(raw_config, deploy=True)
    unmanaged = copy.deepcopy(applied_raw)
    for service in unmanaged["applications"][0]["services"]:
        service["manage"] = False
    assert plan_retirements(registry(applied_raw), registry(unmanaged)).candidates == []
    emptied = copy.deepcopy(applied_raw)
    emptied["applications"][0]["services"][0]["deploy"] = False
    assert plan_retirements(registry(applied_raw), registry(emptied)).candidates == []
    applied = effective(parse_config(applied_raw, allow_unavailable=True))
    for declared in (unmanaged, emptied):
        assert retirement_lines(applied, parse_config(declared, allow_unavailable=True)) == []


def test_legacy_projects_are_reported_but_never_retired(raw_config):
    applied_raw, desired_raw = configs(raw_config)
    desired_raw["projects"] = []
    plan = plan_retirements(registry(applied_raw), registry(desired_raw))
    assert [candidate.application for candidate in plan.candidates] == ["shop"]
    assert plan.legacy_projects_left_running == ["notes"]
    only_projects = plan_retirements(registry(desired_raw), registry(raw_config))
    assert only_projects.candidates == []


def test_application_free_registries_have_no_candidates(raw_config):
    plan = plan_retirements(registry(raw_config), registry(raw_config))
    assert plan.candidates == [] and plan.applied_revision == plan.desired_revision


@pytest.mark.parametrize(
    "mutate",
    [
        lambda applied, desired: (None, desired),
        lambda applied, desired: (applied, None),
        lambda applied, desired: (applied, {**desired, "config_revision": "A" * 64}),
        lambda applied, desired: ({**applied, "config_revision": None}, desired),
        lambda applied, desired: (applied, {"config_revision": desired["config_revision"]}),
        lambda applied, desired: (applied, {**desired, "applications": []}),
        lambda applied, desired: (applied, {**desired, "applications": {"Bad_Id": {}}}),
        lambda applied, desired: (
            applied,
            {**desired, "config_revision": applied["config_revision"]},
        ),
        lambda applied, desired: (
            {**applied, "server_name": "one"},
            {**desired, "server_name": "two"},
        ),
        lambda applied, desired: (
            {**applied, "applications": {"shop": {"isolation": "other", "services": {}}}},
            desired,
        ),
        lambda applied, desired: (
            {
                **applied,
                "applications": {
                    "shop": {
                        "isolation": "separate",
                        "services": {"a-b": {"manage": 1, "deploy": False}},
                    }
                },
            },
            desired,
        ),
    ],
)
def test_incomplete_or_inconsistent_input_retires_nothing(raw_config, mutate):
    applied_raw, desired_raw = configs(raw_config)
    applied, desired = mutate(registry(applied_raw), registry(desired_raw))
    with pytest.raises(RetirementPlanError):
        plan_retirements(applied, desired)


def test_classify_requires_exact_registration_shape():
    with pytest.raises(RetirementPlanError):
        classify("shop", {"isolation": "separate", "services": {}})
    with pytest.raises(RetirementPlanError):
        classify("shop", [])


def test_operator_lines_explain_each_outcome_and_fail_closed(raw_config):
    applied_raw, desired_raw = configs(raw_config, deploy=True)
    desired_raw["projects"] = []
    desired = parse_config(desired_raw, allow_unavailable=True)
    text = "\n".join(
        retirement_lines(effective(parse_config(applied_raw, allow_unavailable=True)), desired)
    )
    assert "application shop: absent from this file" in text
    assert "the private schema 2 guarded deploy stops it, disables autostart" in text
    assert "manual fallback: deploy every service with deploy: false first" in text
    assert "project notes: absent from this file -> stays running" in text
    assert retirement_lines(None, desired) == []
    assert retirement_lines(effective(desired), desired) == []
    broken = effective(parse_config(applied_raw, allow_unavailable=True))
    broken["applications"][0]["isolation"] = "bogus"
    [line] = retirement_lines(broken, desired)
    assert "nothing is retired" in line


@pytest.mark.parametrize(
    ("kwargs", "expected", "manual_available"),
    [
        ({}, "guarded deploy archives and releases it", True),
        ({"manage": False}, "removal refused because it has manage: false services", False),
        ({"isolation": "shared"}, "removal refused for isolation: shared", False),
    ],
)
def test_operator_lines_show_only_applicable_removal_paths(
    raw_config, kwargs, expected, manual_available
):
    applied_raw, desired_raw = configs(raw_config, **kwargs)
    applied = parse_config(applied_raw, allow_unavailable=True)
    desired = parse_config(desired_raw, allow_unavailable=True)
    [line] = retirement_lines(effective(applied), desired)
    assert expected in line
    assert ("steward-host application-retire" in line) is manual_available
