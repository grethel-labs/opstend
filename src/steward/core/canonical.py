"""Canonical serialisation, revision ids and structural diffs."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def revision_id(data: Any) -> str:
    """Content address of a configuration: sha256 over its canonical JSON."""
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def flatten(data: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested data to dotted paths. Lists of objects with an `id` key by id."""
    out: dict[str, Any] = {}
    if isinstance(data, dict):
        if not data and prefix:
            out[prefix] = {}
        for key, value in data.items():
            out.update(flatten(value, f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(data, list):
        if not data:
            out[prefix] = []
        for index, value in enumerate(data):
            key = value["id"] if isinstance(value, dict) and "id" in value else index
            out.update(flatten(value, f"{prefix}[{key}]"))
    else:
        out[prefix] = data
    return out


def diff(old: Any, new: Any) -> list[dict[str, Any]]:
    """Path-level differences between two configurations."""
    a, b = flatten(old), flatten(new)
    changes = []
    for path in sorted(a.keys() | b.keys()):
        if path not in b:
            changes.append({"path": path, "change": "removed", "old": a[path]})
        elif path not in a:
            changes.append({"path": path, "change": "added", "new": b[path]})
        elif a[path] != b[path]:
            changes.append({"path": path, "change": "changed", "old": a[path], "new": b[path]})
    return changes
