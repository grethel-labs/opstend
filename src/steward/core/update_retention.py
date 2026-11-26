"""Retention report for update captures and preserved data trees (decision 16).

Nothing here deletes anything. Update-time captures and `data.preserved-<token>` trees are
kept at least `CLEANUP_AFTER_S` (30 days). Older ones are reported as *cleanup candidates*
for the operator to export and remove by hand, and a hint is raised before the fixed
limits (8 preserved trees per project, 10 captures in a project's executor spool) turn a
later update or restore into a refusal.

Pure functions over already-collected facts; the executor action collects them.
"""

from __future__ import annotations

from typing import Any

from .update_recovery import MAX_PRESERVED_TREES

CLEANUP_AFTER_S = 30 * 86400
MAX_SPOOL_CAPTURES = 10
HINT_MARGIN = 2  # raise the hint when this few slots remain


def classify(
    items: list[dict[str, Any]], now: float, *, cleanup_after_s: int = CLEANUP_AFTER_S
) -> list[dict[str, Any]]:
    """Mark each `{kind, name, created_at}` item; unknown age is never a candidate."""
    out = []
    for item in items:
        created = item.get("created_at")
        known = type(created) in (int, float) and 0 <= created <= now + 86400
        age = max(0.0, now - created) if known else None
        out.append(
            {
                **item,
                "age_days": None if age is None else int(age // 86400),
                "cleanup_candidate": age is not None and age >= cleanup_after_s,
            }
        )
    return sorted(out, key=lambda i: (i["kind"], i.get("created_at") or 0, i["name"]))


def limit_hint(count: int, limit: int) -> bool:
    """True once at most `HINT_MARGIN` slots remain (or the limit is reached)."""
    return count >= limit - HINT_MARGIN


def project_report(
    captures: list[dict[str, Any]],
    trees: list[dict[str, Any]],
    spool: list[dict[str, Any]],
    now: float,
) -> dict[str, Any]:
    """`captures` are the update-bound ones (journal `recovery_capture`); `spool` is every
    artifact in the project's capture spool. Spool artifacts without a journal binding are
    listed too, with `bound_to_update: false` (for example plain `backup-capture`)."""
    bound = {c["name"] for c in captures}
    plain = [s for s in spool if s["name"] not in bound]
    spool_count = max(len(spool), len(bound))
    items = classify(
        [
            *({"kind": "capture", "bound_to_update": True, **c} for c in captures),
            *({"kind": "capture", "bound_to_update": False, **s} for s in plain),
            *({"kind": "preserved_tree", **t} for t in trees),
        ],
        now,
    )
    return {
        "spool_captures": {
            "count": spool_count,
            "limit": MAX_SPOOL_CAPTURES,
            "hint": limit_hint(spool_count, MAX_SPOOL_CAPTURES),
        },
        "preserved_trees": {
            "count": len(trees),
            "limit": MAX_PRESERVED_TREES,
            "hint": limit_hint(len(trees), MAX_PRESERVED_TREES),
        },
        "items": items,
        "cleanup_candidates": sum(1 for i in items if i["cleanup_candidate"]),
    }
