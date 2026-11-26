"""Decide which applications a deployment would remove (L09 step 1).

Pure comparison of two application registries. It performs no host effect and
grants no authority: the executor re-derives the same decision from its own
root-owned registry before it retires anything.

Removal is never inferred from ``manage: false``, ``deploy: false``, an
unreadable or partial configuration, or a pending UI revision. Only an
application that is registered in the applied registry and absent from the
desired registry of an explicit, complete deployment candidate is a candidate.
Legacy ``projects`` keep the version 0.1 behavior (removal leaves them running
and unmanaged) and are only reported, never retired.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .config import Slug
from .inventory import Digest

MAX_APPLICATIONS = 16
MAX_SERVICES = 64
_REVISION = re.compile(r"[a-f0-9]{64}")
_SLUG = re.compile(r"[a-z][a-z0-9-]{1,30}[a-z0-9]")

Stage = Literal[
    "ready",
    "needs_disable",
    "unmanaged_services",
    "shared_isolation_unavailable",
]


class RetirementPlanError(ValueError):
    """The comparison input is incomplete or inconsistent; nothing may be retired."""


class Candidate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    application: Slug
    isolation: Literal["shared", "separate"]
    services: list[Slug] = Field(min_length=1, max_length=MAX_SERVICES)
    data_services: list[Slug] = Field(max_length=MAX_SERVICES)
    stage: Stage

    @property
    def retirable(self) -> bool:
        return self.stage == "ready"


class RetirementPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    applied_revision: Digest
    desired_revision: Digest
    candidates: list[Candidate] = Field(max_length=MAX_APPLICATIONS)
    # Legacy projects removed from the desired file: left running, never retired.
    legacy_projects_left_running: list[Slug] = Field(max_length=64)


_STAGE_TEXT = {
    "ready": (
        "the private schema 2 guarded deploy archives and releases it before removal; "
        "manual fallback: steward-host application-retire"
    ),
    "needs_disable": (
        "the private schema 2 guarded deploy stops it, disables autostart, and archives "
        "and releases it before removal; manual fallback: deploy every service with "
        "deploy: false first, then run steward-host application-retire"
    ),
    "unmanaged_services": "removal refused because it has manage: false services",
    "shared_isolation_unavailable": "removal refused for isolation: shared (ADR 0006)",
}


def _applications(registry: Any, label: str, *, required: bool) -> dict[str, Any]:
    if not isinstance(registry, Mapping):
        raise RetirementPlanError(f"{label} registry is unavailable")
    revision = registry.get("config_revision")
    if not isinstance(revision, str) or _REVISION.fullmatch(revision) is None:
        raise RetirementPlanError(f"{label} registry has no valid revision")
    applications = registry.get("applications", None if required else {})
    if not isinstance(applications, Mapping) or len(applications) > MAX_APPLICATIONS:
        raise RetirementPlanError(f"{label} registry has no valid application map")
    if any(not isinstance(name, str) or _SLUG.fullmatch(name) is None for name in applications):
        raise RetirementPlanError(f"{label} registry has an invalid application ID")
    return dict(applications)


def _legacy(registry: Mapping[str, Any]) -> set[str]:
    projects = registry.get("projects", {})
    if not isinstance(projects, Mapping) or len(projects) > 64:
        raise RetirementPlanError("registry has an invalid project map")
    if any(not isinstance(name, str) or _SLUG.fullmatch(name) is None for name in projects):
        raise RetirementPlanError("registry has an invalid project ID")
    return set(projects)


def classify(application: str, entry: Any) -> Candidate:
    """Validate one applied registration and decide whether it may be retired."""
    if not isinstance(entry, Mapping) or entry.get("isolation") not in ("shared", "separate"):
        raise RetirementPlanError("applied application registration is invalid")
    services = entry.get("services")
    if not isinstance(services, Mapping) or not 1 <= len(services) <= MAX_SERVICES:
        raise RetirementPlanError("applied application has no valid service map")
    names = sorted(services)
    for name, spec in services.items():
        if (
            not isinstance(name, str)
            or _SLUG.fullmatch(name) is None
            or not isinstance(spec, Mapping)
            or type(spec.get("manage")) is not bool
            or type(spec.get("deploy")) is not bool
        ):
            raise RetirementPlanError("applied application service registration is invalid")
    if entry["isolation"] == "shared":
        stage: Stage = "shared_isolation_unavailable"
    elif any(not services[name]["manage"] for name in names):
        stage = "unmanaged_services"
    elif any(services[name]["deploy"] for name in names):
        stage = "needs_disable"
    else:
        stage = "ready"
    return Candidate(
        application=application,
        isolation=entry["isolation"],
        services=names,
        data_services=[name for name in names if services[name].get("data_source") is not None],
        stage=stage,
    )


def plan_retirements(applied: Any, desired: Any) -> RetirementPlan:
    """Compare registries; every error means nothing is retired.

    ``desired`` is the registry rendered from the complete configuration that is
    about to be deployed. Only its application keys are read, so a caller may
    pass ``{"config_revision": ..., "applications": {id: {}, ...}}``.
    """
    before = _applications(applied, "applied", required=False)
    after = _applications(desired, "desired", required=True)
    applied_revision, desired_revision = applied["config_revision"], desired["config_revision"]
    if applied_revision == desired_revision and before.keys() != after.keys():
        raise RetirementPlanError("registries with one revision list different applications")
    if (
        applied.get("server_name") is not None
        and desired.get("server_name") is not None
        and applied["server_name"] != desired["server_name"]
    ):
        raise RetirementPlanError("registries belong to different servers")
    candidates = [classify(name, before[name]) for name in sorted(before.keys() - after.keys())]
    legacy = sorted(_legacy(applied) - _legacy(desired)) if "projects" in desired else []
    return RetirementPlan(
        applied_revision=applied_revision,
        desired_revision=desired_revision,
        candidates=candidates,
        legacy_projects_left_running=legacy,
    )


def retire_params(application: str, applied_revision: str, desired_cfg: Any) -> dict[str, Any]:
    """Executor parameters from the exact desired configuration the operator will deploy."""
    from .canonical import revision_id
    from .config import effective

    return {
        "application": application,
        "expected_revision": applied_revision,
        "desired_revision": revision_id(effective(desired_cfg)),
        "desired_applications": sorted(item.id for item in desired_cfg.applications),
    }


def retirement_lines(applied_config: Any, desired_cfg: Any) -> list[str]:
    """Operator-facing plan text for `steward plan`; failures are reported, never hidden."""
    from .config import ConfigError, parse_config
    from .render import prepare_application_registry

    if not applied_config:
        return []
    try:
        previous = parse_config(applied_config, allow_unavailable=True)
        applied = prepare_application_registry(previous)
        applied["projects"] = {project.id: {} for project in previous.projects}
        desired = prepare_application_registry(desired_cfg)
        desired["projects"] = {project.id: {} for project in desired_cfg.projects}
        plan = plan_retirements(applied, desired)
    except (ConfigError, ValueError, KeyError, TypeError) as error:
        return [
            f"    application retirement: cannot compare the applied registry ({error}); "
            "nothing is retired"
        ]
    lines = []
    for candidate in plan.candidates:
        lines.append(
            f"    application {candidate.application}: absent from this file -> "
            + _STAGE_TEXT[candidate.stage]
        )
    for project in plan.legacy_projects_left_running:
        lines.append(
            f"    project {project}: absent from this file -> stays running, unmanaged "
            "(version 0.1 behavior, not retired)"
        )
    return lines
