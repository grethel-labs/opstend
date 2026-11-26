"""Redacted, bounded, authorized snapshots for inference.

A snapshot is assembled only from items the caller already authorized (identity and
project grants are enforced before this point); this module re-checks scope per
item, applies the data-class sharing policy, redacts, bounds size and states
source, evidence times and coverage so an answer cannot hide missing data.
Unauthorized items are dropped silently: nothing about them reaches the payload.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Any

from .canonical import canonical_json
from .secrets import redact

SNAPSHOT_VERSION = 1
LABEL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
OTHER_PROJECT = "[other-project]"


@dataclass(frozen=True)
class Scope:
    """What the requesting identity may see: granted projects, optionally host data."""

    projects: frozenset[str]
    host: bool
    since: float
    until: float

    def __post_init__(self):
        if not (
            math.isfinite(self.since) and math.isfinite(self.until) and self.since < self.until
        ):
            raise ValueError("invalid snapshot time range")


@dataclass(frozen=True)
class Item:
    source: str  # e.g. "controller", "collector"
    kind: str  # e.g. "status", "vulnerability.finding"
    data_class: str  # sharing class, matches ai.share
    observed_at: float
    text: str
    project: str | None = None  # None = host-level observation


@dataclass(frozen=True)
class Snapshot:
    payload: dict[str, Any]
    digest: str
    projects: tuple[str, ...]
    data_classes: frozenset[str]
    # Local-only diagnostics, never part of the payload or digest.
    denied: int = field(default=0, compare=False)

    def item_count(self) -> int:
        return len(self.payload["items"])


def _clean(text: str, secrets: tuple[str, ...], hidden: re.Pattern | None, limit: int) -> str:
    text = _CONTROL.sub("", str(text))
    text = redact(text, secrets)
    if hidden is not None:
        text = hidden.sub(OTHER_PROJECT, text)
    if len(text) > limit:
        text = text[:limit] + "...[truncated]"
    return text


def project_mask(all_projects: tuple[str, ...], scope: Scope) -> re.Pattern | None:
    others = sorted(set(all_projects) - scope.projects, key=len, reverse=True)
    if not others:
        return None
    return re.compile(
        r"(?<![A-Za-z0-9-])(?:" + "|".join(map(re.escape, others)) + r")(?![A-Za-z0-9-])"
    )


def mask_item_text(text: str, hidden: re.Pattern) -> str:
    return hidden.sub(OTHER_PROJECT, _CONTROL.sub("", text))


def build_snapshot(
    items: list[Item],
    scope: Scope,
    *,
    now: float,
    expected_sources: tuple[str, ...] = (),
    allowed_classes: frozenset[str] | None = None,
    all_projects: tuple[str, ...] = (),
    secrets: tuple[str, ...] = (),
    max_bytes: int = 24000,
    max_item_chars: int = 1500,
) -> Snapshot:
    """Return the payload a provider may see. `allowed_classes=None` means no class filter."""
    if not math.isfinite(now) or max_bytes < 512 or max_item_chars < 16:
        raise ValueError("invalid snapshot parameters")
    hidden = project_mask(all_projects, scope)
    denied = outside_window = 0
    withheld_classes: set[str] = set()
    eligible: list[Item] = []
    for item in items:
        if not LABEL.fullmatch(item.source) or not LABEL.fullmatch(item.kind):
            raise ValueError("invalid item label")
        authorized = scope.host if item.project is None else item.project in scope.projects
        if not authorized:
            denied += 1
            continue
        if allowed_classes is not None and item.data_class not in allowed_classes:
            withheld_classes.add(item.data_class)
            continue
        if (
            not math.isfinite(item.observed_at)
            or not scope.since <= item.observed_at <= scope.until
        ):
            outside_window += 1
            continue
        eligible.append(item)
    eligible.sort(key=lambda i: (-i.observed_at, i.source, i.kind, i.project or ""))

    present = {i.source for i in eligible}
    coverage: dict[str, Any] = {
        "expected_sources": sorted(set(expected_sources)),
        "missing_sources": sorted(set(expected_sources) - present),
        "withheld_classes": sorted(withheld_classes),
        "omitted_outside_window": outside_window,
        "omitted_size": 0,
        "truncated": False,
        "items": 0,
        "oldest": None,
        "newest": None,
    }
    payload: dict[str, Any] = {
        "v": SNAPSHOT_VERSION,
        "generated_at": now,
        "window": {"since": scope.since, "until": scope.until},
        "scope": {"projects": sorted(scope.projects), "host": scope.host},
        "coverage": coverage,
        "items": [],
    }
    used = len(canonical_json(payload).encode()) + 64  # headroom for the final coverage numbers
    included: list[Item] = []
    for item in eligible:
        row = {
            "source": item.source,
            "kind": item.kind,
            "project": item.project,
            "observed_at": item.observed_at,
            "text": _clean(item.text, secrets, hidden, max_item_chars),
        }
        size = len(canonical_json(row).encode()) + 1
        if used + size > max_bytes:
            coverage["omitted_size"] += 1
            coverage["truncated"] = True
            continue
        used += size
        payload["items"].append(row)
        included.append(item)
    stamps = [i.observed_at for i in included]
    coverage["items"] = len(included)
    if stamps:
        coverage["oldest"], coverage["newest"] = min(stamps), max(stamps)
    digest = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
    return Snapshot(
        payload=payload,
        digest=digest,
        projects=tuple(sorted({i.project for i in included if i.project})),
        data_classes=frozenset(i.data_class for i in included),
        denied=denied,
    )
