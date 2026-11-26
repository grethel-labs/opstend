"""Plan for applying a pending web UI revision locally (L10 step 1).

Pure functions: the API uses them to show the plan, the executor uses them as the
authority before it writes anything. Nothing here touches the host.

What can be applied without a controller deployment is exactly what the executor
can install by itself: the applied configuration (`desired.json`) and the executor
registry. A revision qualifies only when every Ansible input generated from it is
identical to the applied one (units, firewall, proxy, secrets, users, scanning, bot,
channels, backups) and only the areas in `SUPPORTED_AREAS` changed. Everything
else needs `./steward deploy`; the plan then says so instead of guessing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canonical import diff, revision_id
from .config import ConfigError, effective, parse_config
from .render import render_vars

# Top-level configuration areas a local apply may change.
SUPPORTED_AREAS = frozenset({"maintenance", "projects"})
# Generated inputs that legitimately differ between two revisions: the files the
# executor itself rewrites.
REWRITTEN_INPUTS = frozenset(
    {"steward_desired_config", "steward_config_revision", "steward_registry"}
)
OPERATIONS = ("desired_config", "executor_registry")


@dataclass(frozen=True)
class ApplyPlan:
    supported: bool
    reason: str | None
    applied: str
    head: str
    areas: tuple[str, ...] = ()
    operations: tuple[str, ...] = ()
    diff: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "supported": self.supported,
            "reason": self.reason,
            "applied": self.applied,
            "head": self.head,
            "areas": list(self.areas),
            "operations": list(self.operations),
            "diff": self.diff,
        }


def _generated(body: dict[str, Any], cfg, release_version: str) -> dict[str, Any]:
    out = render_vars(cfg, release={"version": release_version}, ssh_port=22)
    out = {k: v for k, v in out.items() if k not in REWRITTEN_INPUTS}
    # Backups are disabled here (checked by the caller); the revision they embed is moot.
    out["steward_backup"] = {
        k: v for k, v in out["steward_backup"].items() if k != "config_revision"
    }
    return out


def plan_apply(
    applied_body: dict[str, Any], head_body: dict[str, Any], *, release_version: str
) -> ApplyPlan:
    """Decide whether `head_body` can replace `applied_body` through the executor."""
    applied, head = revision_id(applied_body), revision_id(head_body)

    def refuse(reason: str, areas: tuple[str, ...] = ()) -> ApplyPlan:
        return ApplyPlan(False, reason, applied, head, areas, (), diff(applied_body, head_body))

    if applied == head:
        return refuse("no_change")
    try:
        old = parse_config(applied_body, allow_unavailable=True)
        new = parse_config(head_body)  # a revision with an unavailable feature never applies
    except ConfigError:
        return refuse("invalid_configuration")
    if effective(old) != applied_body or effective(new) != head_body:
        return refuse("not_canonical")
    if old.server != new.server:
        return refuse("server_changed")
    areas = tuple(
        sorted(
            k
            for k in head_body.keys() | applied_body.keys()
            if head_body.get(k) != applied_body.get(k)
        )
    )
    blocked = [a for a in areas if a not in SUPPORTED_AREAS]
    if blocked:
        return refuse("area_needs_deployment:" + ",".join(blocked), areas)
    if old.backup.enabled or new.backup.enabled or old.applications or new.applications:
        return refuse("backup_or_applications_need_deployment", areas)
    try:
        before = _generated(applied_body, old, release_version)
        after = _generated(head_body, new, release_version)
    except (ValueError, KeyError, TypeError):
        return refuse("not_renderable", areas)
    changed = sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))
    if changed:
        return refuse("generated_inputs_need_deployment:" + ",".join(changed), areas)
    return ApplyPlan(True, None, applied, head, areas, OPERATIONS, diff(applied_body, head_body))
