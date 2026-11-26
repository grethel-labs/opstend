"""Validate registered application graphs and derive bounded group impact.

This module does not execute operations. The caller must obtain the registry
from the root-controlled executor path, fence configuration changes, snapshot
actual running intent and apply the remaining authorization policy.
"""

from __future__ import annotations

import heapq
import re
from typing import Any

from .canonical import revision_id
from .ids import graph_identifier

_SLUG = re.compile(r"[a-z][a-z0-9-]{1,30}[a-z0-9]")
_REVISION = re.compile(r"[a-f0-9]{64}")


def _slug(value: object) -> bool:
    return isinstance(value, str) and _SLUG.fullmatch(value) is not None


def derive_group_plan(
    registry: dict[str, Any],
    application_id: str,
    service_id: str,
    *,
    expected_revision: str,
    scope: str = "dependents",
) -> dict[str, Any]:
    """Derive a restart/pause impact set from a root-owned registry candidate.

    The plan does not authorize a mutation or assume a service is currently
    running. A future executor action must snapshot and preserve actual intent.
    """
    if (
        not isinstance(registry, dict)
        or not _slug(application_id)
        or not _slug(service_id)
        or not isinstance(expected_revision, str)
        or _REVISION.fullmatch(expected_revision) is None
        or registry.get("config_revision") != expected_revision
        or scope not in ("dependents", "application")
    ):
        raise ValueError("invalid or stale application registry")
    applications = registry.get("applications")
    if not isinstance(applications, dict) or len(applications) > 16:
        raise ValueError("invalid application registry")
    app = applications.get(application_id)
    if not isinstance(app, dict) or app.get("isolation") not in ("shared", "separate"):
        raise ValueError("unknown or invalid application")
    app_stem = graph_identifier("a", application_id)
    if app.get("lock") != "application-" + app_stem:
        raise ValueError("application identity mismatch")
    services = app.get("services")
    if not isinstance(services, dict) or not 1 <= len(services) <= 64 or service_id not in services:
        raise ValueError("unknown or invalid service")
    dependencies: dict[str, set[str]] = {}
    stems: set[str] = set()
    for name, spec in services.items():
        if not _slug(name) or not isinstance(spec, dict):
            raise ValueError("invalid service registration")
        stem = graph_identifier("s", application_id, name)
        if stem in stems:
            raise ValueError("service identity collision")
        stems.add(stem)
        user = "stw-" + (app_stem if app["isolation"] == "shared" else stem)
        refs = spec.get("depends_on")
        if (
            type(spec.get("manage")) is not bool
            or type(spec.get("deploy")) is not bool
            or spec.get("user") != user
            or spec.get("unit") != stem + ".service"
            or spec.get("container") != stem
            or spec.get("lock") != "project-" + stem
            or not isinstance(refs, list)
            or len(refs) > 64
            or any(not _slug(item) for item in refs)
            or len(refs) != len(set(refs))
            or name in refs
            or not set(refs) <= services.keys()
        ):
            raise ValueError("invalid service registration")
        dependencies[name] = set(refs)
    expected_pod = (
        app_stem + "-pod.service"
        if app["isolation"] == "shared" and any(spec["manage"] for spec in services.values())
        else None
    )
    if app.get("pod_unit") != expected_pod:
        raise ValueError("application identity mismatch")
    pending = {name: set(refs) for name, refs in dependencies.items()}
    ready = [name for name, refs in pending.items() if not refs]
    heapq.heapify(ready)
    order = []
    while ready:
        name = heapq.heappop(ready)
        order.append(name)
        for other in sorted(pending):
            if name in pending[other]:
                pending[other].remove(name)
                if not pending[other]:
                    heapq.heappush(ready, other)
    if len(order) != len(services):
        raise ValueError("application dependency cycle")
    affected = set(order) if scope == "application" else {service_id}
    if scope == "dependents":
        for name in order:
            if dependencies[name] & affected:
                affected.add(name)
    if any(not services[name]["manage"] for name in affected):
        raise ValueError("affected service is unmanaged")
    start_order = [name for name in order if name in affected]
    # Fence every prerequisite as well: a concurrent single-service operation
    # must not change a dependency while this group is paused or resumed.
    lock_scope = set(affected)
    for name in reversed(order):
        if name in lock_scope:
            lock_scope.update(dependencies[name])
    external = sorted(lock_scope - affected)
    if any(not services[name]["manage"] for name in external):
        raise ValueError("external dependency is unmanaged")
    return {
        "config_revision": expected_revision,
        "application": application_id,
        "target": service_id,
        "scope": scope,
        "data_contract_revision": revision_id(
            {
                "server_name": registry.get("server_name"),
                "services": {
                    name: {
                        key: services[name].get(key)
                        for key in (
                            "data_source",
                            "data_target",
                            "image",
                            "source_revision",
                            "allow_backup_pause",
                        )
                    }
                    for name in sorted(services)
                },
            }
        )
        if scope == "application"
        else None,
        "lock_targets": sorted([app["lock"], *(services[name]["lock"] for name in lock_scope)]),
        "stop_order": list(reversed(start_order)),
        "start_order": start_order,
        "external_dependencies": external,
        "external_desired_running": {name: services[name]["deploy"] for name in external},
        "desired_running": {name: services[name]["deploy"] for name in start_order},
    }


def rederive_checkpoint_plan(registry: dict[str, Any], plan: Any) -> dict[str, Any]:
    """Revalidate a checkpoint, preserving pre-data-binding legacy intents.

    Legacy application-scope checkpoints remain operable, but callers must not
    treat them as authorizing a capture without the original data binding.
    """
    current = derive_group_plan(
        registry,
        plan.application,
        plan.target,
        expected_revision=plan.config_revision,
        scope=plan.scope,
    )
    if plan.data_contract_revision is None:
        current["data_contract_revision"] = None
    return current
