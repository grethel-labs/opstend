"""Read-only listing of update captures and preserved data trees (decision 16).

`update_retention_status` reports, per registered project, the captures an update took
(`recovery_capture` in the update journal), the `data.preserved-*` trees next to `data/`,
their age, which are cleanup candidates (older than 30 days) and whether a limit is near.
It changes nothing and offers no deletion; removal stays the operator's explicit,
existing path (`backup-export`, `backup-retention-purge`, manual removal of a preserved
tree after export). Names are identifiers, never paths.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from ..core.update_retention import project_report
from . import image_update as iu
from .data_restore import preserved_trees

if TYPE_CHECKING:
    from .server import Executor

SCAN_MAX = 64


class RetentionParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str | None = Field(None, pattern=iu.PROJECT_ID)


def _spool_items(ex: Executor, project: str) -> list[dict[str, Any]]:
    """Every artifact in the project's capture spool: `{name, created_at}` (ctime, no paths)."""
    spool = Path(ex._db_path).parent / "captures" / project
    out: list[dict[str, Any]] = []
    try:
        with os.scandir(spool) as entries:
            for _, entry in zip(range(SCAN_MAX), entries, strict=False):
                out.append({"name": entry.name, "created_at": _tree_age_source(spool, entry.name)})
    except OSError:
        return []
    return out


def _tree_age_source(root: Path, name: str) -> float | None:
    try:
        return os.lstat(root / name).st_ctime  # a rename (the preservation) sets ctime
    except OSError:
        return None


def report(ex: Executor, registry: dict[str, Any], only: str | None, now: float) -> dict[str, Any]:
    from . import server

    ledger = iu._ledger(ex)
    projects: dict[str, Any] = {}
    for project, spec in sorted(registry["projects"].items()):
        if only is not None and project != only:
            continue
        if not spec.get("update") and not spec.get("has_data"):
            continue
        records = ledger.capture_records(project)
        captures = [
            {
                "name": r["artifact"],
                "approval_id": r["approval_id"],
                "created_at": r["completed_at"],
            }
            for r in records
        ]
        root = server.PROJECT_DATA_ROOT / project
        by_name = {r["preserved"]: r for r in records if r.get("preserved")}
        trees = []
        for name in preserved_trees(root):
            known = by_name.get(name)
            at = known.get("preserved_at") if known else None
            trees.append(
                {
                    "name": name,
                    "approval_id": known["approval_id"] if known else None,
                    "created_at": at if at is not None else _tree_age_source(root, name),
                }
            )
        projects[project] = project_report(captures, trees, _spool_items(ex, project), now)
    return {
        "generated_at": now,
        "cleanup_after_days": 30,
        "projects": projects,
        "cleanup_candidates": sum(p["cleanup_candidates"] for p in projects.values()),
        "note": "Nothing is deleted automatically; export, then remove by hand "
        "(docs/operations.md, 'Retention of update captures and preserved trees').",
    }


def update_retention_status(ex: Executor, params: RetentionParams, _role: str, registry: dict):
    if params.project_id is not None and params.project_id not in registry["projects"]:
        from .protocol import ExecutorError

        raise ExecutorError("policy_denied", "project is not registered")
    return report(ex, registry, params.project_id, iu._now())


def register(actions: dict, action_cls) -> None:
    actions["update_retention_status"] = action_cls(
        RetentionParams,
        frozenset({"operator", "controller", "api"}),
        False,
        update_retention_status,
    )
