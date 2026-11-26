import json
import os
import stat

import pytest

from steward.core.scan_observations import PAGE_BYTES, Observations
from steward.core.vulnerabilities import Advisory, Component, ScanResult

REV = "a" * 64
CONFIG = "b" * 64
NOW = 1800000000


def result(name="openssl", *, now=NOW, state="confirmed", summary="Provider finding"):
    return ScanResult(
        source="osv",
        inventory_revision=REV,
        subject=Component(kind="os_package", scope="host", name=name, version="1.0"),
        checked_at=now,
        state=state,
        complete=state in ("confirmed", "not_affected"),
        error_class="timeout" if state == "scan_failed" else None,
        findings=[Advisory(id="CVE-2026-1234", summary=summary, severity="high")]
        if state == "confirmed"
        else [],
    ).model_dump(mode="json") | {"last_success": None}


def report(records=None, *, now=NOW):
    records = [result(now=now)] if records is None else records
    counts = {}
    for record in records:
        counts[record["state"]] = counts.get(record["state"], 0) + 1
    complete = bool(records) and all(r["complete"] for r in records)
    return {
        "v": 1,
        "generated_at": now,
        "enabled": True,
        "config_revision": CONFIG,
        "inventory_revision": REV,
        "running_kernel": "test-kernel",
        "complete": complete,
        "source_queries_complete": complete,
        "runtime_images_verified": True,
        "kernel": {
            "release": "test-kernel",
            "state": "not_affected",
            "complete": True,
            "reboot_required": False,
            "basis": "fixture",
            "matched_sources": [["openssl", "1.0"]],
        },
        "counts": counts,
        "results": records,
    }


def options(**patch):
    return {"now": NOW, "enabled": True, "config_revision": CONFIG, "max_age_s": 60} | patch


def test_atomic_snapshot_transitions_deduplication_and_persistent_feed(tmp_path):
    path = tmp_path / "observations.db"
    store = Observations(path)
    assert store.publish(report())
    first = store.changes()
    assert [r["kind"] for r in first["changes"]] == [
        "vulnerability.confirmed",
        "vulnerability.scan_completed",
    ]
    assert not store.publish(report())
    assert store.publish(report(now=NOW + 1))
    later = Observations(path).changes(first["next_id"])
    assert [r["kind"] for r in later["changes"]] == ["vulnerability.scan_completed"]
    assert later["coverage"]["stream_id"] == first["coverage"]["stream_id"]
    assert not store.publish(report(now=NOW - 1))


def test_summary_and_queries_derive_freshness_and_configuration_coverage(tmp_path):
    store = Observations(tmp_path / "observations.db")
    assert not store.summary(**options())["complete"]
    store.publish(report())
    assert store.summary(**options())["complete"]
    assert store.query(**options(now=NOW + 61))["records"][0]["state"] == "stale"
    assert not store.summary(**options(now=NOW + 61))["complete"]
    for patch in ({"enabled": False}, {"config_revision": "c" * 64}):
        assert store.query(**options(**patch))["records"][0]["state"] == "unknown"
        assert not store.summary(**options(**patch))["complete"]


@pytest.mark.parametrize("mutation", ["counts", "mixed", "duplicate", "history"])
def test_invalid_snapshot_cannot_replace_prior_evidence(tmp_path, mutation):
    store = Observations(tmp_path / "observations.db")
    store.publish(report())
    before = store.changes()
    body = report(now=NOW + 1)
    if mutation == "counts":
        body["counts"] = {}
    elif mutation == "mixed":
        body["results"][0]["inventory_revision"] = "d" * 64
    elif mutation == "duplicate":
        body["results"] *= 2
        body["counts"]["confirmed"] = 2
    else:
        historical = result(name="different")
        historical.pop("last_success")
        body["results"][0]["last_success"] = historical
    with pytest.raises(ValueError):
        store.publish(body)
    assert store.changes() == before
    assert store.summary(**options())["generated_at"] == NOW


def test_query_pages_bound_unicode_and_keep_all_subjects(tmp_path):
    store = Observations(tmp_path / "observations.db")
    records = [result(name=f"package-{i}", summary="😀" * 500) for i in range(200)]
    store.publish(report(records))
    offset, seen = 0, []
    while offset is not None:
        page = store.query(**options(), offset=offset, limit=200)
        assert len(json.dumps(page, ensure_ascii=False).encode()) < PAGE_BYTES + 1024
        assert page["records"]
        seen.extend(r["subject_key"] for r in page["records"])
        offset = page["next_offset"]
    assert len(set(seen)) == len(records)
    assert store.query(**options(), project="no-project")["total"] == 0


def test_failure_keeps_explicit_history_without_claiming_current_success(tmp_path):
    store = Observations(tmp_path / "observations.db")
    record = result(state="scan_failed", now=NOW + 1)
    historical = result()
    historical.pop("last_success")
    record["last_success"] = historical
    store.publish(report([record], now=NOW + 1))
    view = store.query(**options(now=NOW + 1))["records"][0]
    assert view["state"] == "scan_failed" and not view["complete"]
    assert view["last_success"]["checked_at"] == NOW
    assert not store.summary(**options(now=NOW + 1))["complete"]


def test_retention_exposes_stream_bounds_and_removed_subjects_can_reappear(tmp_path):
    store = Observations(tmp_path / "observations.db")
    store.publish(report())
    initial = store.changes()
    empty = report([], now=NOW + 31 * 86400)
    empty["enabled"] = False
    store.publish(empty)
    retained = store.changes()
    assert retained["coverage"]["oldest_id"] > initial["next_id"]
    assert retained["changes"][0]["kind"] == "vulnerability.disabled"
    store.publish(report(now=NOW + 31 * 86400 + 1))
    assert store.changes(retained["next_id"])["changes"][0]["kind"] == "vulnerability.confirmed"


def test_database_file_is_private_and_rejects_nonregular_files(tmp_path):
    path = tmp_path / "observations.db"
    store = Observations(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    symlink = tmp_path / "link"
    symlink.symlink_to(path)
    with pytest.raises(OSError):
        Observations(symlink)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):
        Observations(fifo)
    assert not store.changes()["changes"]


def test_inventory_invalidation_is_durable_and_cannot_override_newer_snapshot(tmp_path):
    path = tmp_path / "observations.db"
    store = Observations(path)
    assert store.publish(report())
    original = store.snapshot_id()
    assert store.invalidate_inventory(original, now=NOW + 1)
    assert not store.invalidate_inventory(original, now=NOW + 2)
    restored = Observations(path)
    summary = restored.summary(**options(now=NOW + 2))
    assert summary["stale"] and not summary["complete"]
    assert restored.query(**options(now=NOW + 2))["records"][0]["state"] == "stale"
    assert restored.publish(report(now=NOW + 3))
    assert not restored.invalidate_inventory(original, now=NOW + 4)
    assert restored.summary(**options(now=NOW + 4))["complete"]


def test_inventory_unknown_and_stale_transitions_preserve_evidence_and_fence_old_tokens(tmp_path):
    store = Observations(tmp_path / "observations.db")
    store.publish(report())
    first = store.snapshot_id()
    assert store.invalidate_unavailable(first, now=NOW + 1)
    unknown_id = store.snapshot_id()
    assert not store.invalidate_unavailable(unknown_id, now=NOW + 2)
    assert not store.invalidate_inventory(first, now=NOW + 2)
    assert store.invalidate_inventory(unknown_id, now=NOW + 3)
    stale_id = store.snapshot_id()
    assert not store.invalidate_unavailable(stale_id, now=NOW + 4)
    summary = store.summary(**options(now=NOW + 4))
    assert summary["stale"] and not summary["complete"]
    assert [x["kind"] for x in store.changes()["changes"]][-2:] == [
        "vulnerability.unknown",
        "vulnerability.stale",
    ]
