"""Unprivileged vulnerability scans of exported, revision-bound inventory.

Providers receive package names/versions or image references, never secrets or
production mounts. No result grants mutation authority. Failures preserve the
last successful evidence in the private local state database.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from .adapters.scanners import OSV, Trivy, failed
from .core.images import configured_content_id, runtime_identity_verified
from .core.inventory import Inventory
from .core.scan_observations import Observations
from .core.vulnerabilities import Component, ScanResult, packages


class ScanStore:
    def __init__(self, path: Path):
        self.path = path
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise ValueError(
                    "scan database must be a private regular file owned by the scanner"
                )
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        db = sqlite3.connect(path)
        try:
            with db:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS results (source TEXT, subject TEXT, "
                    "latest TEXT NOT NULL, success TEXT, updated REAL NOT NULL, "
                    "PRIMARY KEY(source,subject))"
                )
                db.execute(
                    "CREATE TABLE IF NOT EXISTS cooldowns (source TEXT PRIMARY KEY,until REAL)"
                )
        finally:
            db.close()

    def save(self, results: list[ScanResult]) -> None:
        db = sqlite3.connect(self.path)
        try:
            with db:
                for result in results:
                    if result.retry_after_s is not None:
                        db.execute(
                            "INSERT INTO cooldowns VALUES (?,?) ON CONFLICT(source) "
                            "DO UPDATE SET until=MAX(cooldowns.until,excluded.until)",
                            (result.source, result.checked_at + result.retry_after_s),
                        )
                    success = (
                        result.model_dump_json()
                        if result.complete and result.state in ("confirmed", "not_affected")
                        else None
                    )
                    db.execute(
                        "INSERT INTO results VALUES (?,?,?,?,?) ON CONFLICT(source,subject) "
                        "DO UPDATE SET latest=CASE WHEN excluded.updated>=results.updated "
                        "THEN excluded.latest ELSE results.latest END, "
                        "success=CASE WHEN excluded.success IS NOT NULL AND "
                        "(results.success IS NULL OR json_extract(excluded.success,'$.checked_at') "
                        ">=json_extract(results.success,'$.checked_at')) "
                        "THEN excluded.success ELSE results.success END, "
                        "updated=MAX(results.updated,excluded.updated)",
                        (
                            result.source,
                            result.subject.key,
                            result.model_dump_json(),
                            success,
                            result.checked_at,
                        ),
                    )
                # Cached subjects no longer observed are retained for thirty days.
                if results:
                    db.execute(
                        "DELETE FROM results WHERE updated < ?",
                        (max(r.checked_at for r in results) - 30 * 86400,),
                    )
                    db.execute(
                        "DELETE FROM results WHERE rowid IN "
                        "(SELECT rowid FROM results ORDER BY updated DESC,rowid DESC "
                        "LIMIT -1 OFFSET 50000)"
                    )
        finally:
            db.close()

    def ready_at(self, source: str) -> float:
        db = sqlite3.connect(self.path)
        try:
            row = db.execute("SELECT until FROM cooldowns WHERE source=?", (source,)).fetchone()
            return row[0] if row else 0
        finally:
            db.close()

    def evidence(self, result: ScanResult) -> dict | None:
        db = sqlite3.connect(self.path)
        try:
            row = db.execute(
                "SELECT success FROM results WHERE source=? AND subject=?",
                (result.source, result.subject.key),
            ).fetchone()
            return json.loads(row[0]) if row and row[0] else None
        finally:
            db.close()


def load_bundle(path: Path) -> tuple[Inventory, list[Component]]:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("inventory must be a regular file")
        raw = handle.read(32 * 1024 * 1024 + 1)
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError("inventory too large")
    document = json.loads(raw)
    return parse_bundle(document)


def parse_bundle(document: dict) -> tuple[Inventory, list[Component]]:
    inventory = Inventory.model_validate(
        {k: v for k, v in document.items() if k not in ("revision", "images")}
    )
    if document.get("revision") != inventory.revision:
        raise ValueError("inventory revision mismatch")
    projects = set(inventory.projects)
    services = set(inventory.application_services or ())
    images = []
    seen_projects, seen_services = set(), set()
    observations = document.get("images", [])
    if not isinstance(observations, list):
        raise ValueError("invalid image observations")
    for image in observations:
        if not isinstance(image, dict):
            raise ValueError("invalid image observation")
        if image.get("config_revision") != inventory.config_revision:
            raise ValueError("image configuration revision mismatch")
        if "project" in image:
            scope = image["project"]
            if (
                "application" in image
                or "service" in image
                or not isinstance(scope, str)
                or "/" in scope
                or scope not in projects
            ):
                raise ValueError("invalid legacy image identity")
            seen = seen_projects
        else:
            application, service = image.get("application"), image.get("service")
            if not all(
                isinstance(part, str) and "/" not in part for part in (application, service)
            ):
                raise ValueError("invalid application service image identity")
            scope = f"{application}/{service}"
            if scope not in services:
                raise ValueError("unregistered application service image")
            seen = seen_services
        if scope in seen:
            raise ValueError("unregistered or duplicate image")
        seen.add(scope)
        ref = image.get("configured_image")
        if not isinstance(ref, str):
            raise ValueError("invalid configured image")
        expected = ref.rsplit("@", 1)[-1]
        images.append(
            Component(
                kind="image",
                scope=scope,
                name=ref.split("@", 1)[0],
                version=expected,
                image=ref,
                runtime_verified=runtime_identity_verified(image),
                expected_image_id=configured_content_id(image),
            )
        )
    if seen_projects != projects or seen_services != services:
        raise ValueError("missing registered image observations")
    return inventory, images


def assess_kernel(inventory: Inventory, results: list[ScanResult], *, now: float) -> dict:
    names = {
        "linux-image-" + inventory.running_kernel,
        "linux-image-unsigned-" + inventory.running_kernel,
        "linux-modules-" + inventory.running_kernel,
    }
    sources = {(p.source_name, p.source_version) for p in inventory.packages if p.name in names}
    matching = [
        r
        for r in results
        if r.subject.kind == "os_package" and (r.subject.name, r.subject.version) in sources
    ]
    state, complete = "unknown", False
    if inventory.reboot_required is False and sources and len(matching) == len(sources):
        states = [r.state_at(now, inventory_revision=inventory.revision) for r in matching]
        if all(r.complete for r in matching) and all(
            s in ("confirmed", "not_affected") for s in states
        ):
            state = "confirmed" if "confirmed" in states else "not_affected"
            complete = True
        elif "scan_failed" in states:
            state = "scan_failed"
        elif "stale" in states:
            state = "stale"
    return {
        "release": inventory.running_kernel,
        "state": state,
        "complete": complete,
        "reboot_required": inventory.reboot_required,
        "basis": (
            "matching installed kernel packages and reboot indicator; no in-memory attestation"
        ),
        "matched_sources": sorted([list(s) for s in sources]),
    }


def scan(
    inventory: Inventory,
    images: list[Component],
    store: ScanStore,
    providers: dict,
    *,
    now: float,
    before_save: Callable | None = None,
    enricher=None,
) -> dict:
    if len(packages(inventory)) + len(images) > 5000:
        raise ValueError("scan subject limit exceeded")
    results = []
    for source, subjects in (("osv", packages(inventory)), ("trivy", images)):
        ready_at = store.ready_at(source)
        if source in providers and ready_at > now:
            observed = [
                failed(source, s, inventory.revision, now, "quota_exhausted") for s in subjects
            ]
            for result in observed:
                result.retry_after_s = max(1, ready_at - now)
            results.extend(observed)
        elif source in providers:
            observed = providers[source].scan(
                subjects, inventory_revision=inventory.revision, now=now
            )
            expected = {s.key: s for s in subjects}
            if (
                len(observed) != len(subjects)
                or len({r.subject.key for r in observed}) != len(subjects)
                or any(
                    r.source != source
                    or r.inventory_revision != inventory.revision
                    or r.subject != expected.get(r.subject.key)
                    for r in observed
                )
            ):
                raise ValueError("scanner result does not bind every requested subject/inventory")
            results.extend(observed)
        else:
            results.extend(
                failed(source, s, inventory.revision, now, "unsupported") for s in subjects
            )
    if sum(len(r.model_dump_json().encode()) for r in results) > 32 * 1024 * 1024:
        raise ValueError("scan report limit exceeded")
    if enricher is not None:
        results = enricher.enrich(results)
        now = max(now, enricher.clock())
    records = []
    counts = {}
    report_bytes = 0
    for result in results:
        state = result.state_at(now, inventory_revision=inventory.revision)
        counts[state] = counts.get(state, 0) + 1
        records.append(
            {
                **result.model_dump(mode="json"),
                "state": state,
                "complete": result.complete and state in ("confirmed", "not_affected"),
                "last_success": store.evidence(result) if not result.complete else None,
            }
        )
        report_bytes += len(json.dumps(records[-1], ensure_ascii=False).encode())
        if report_bytes > 32 * 1024 * 1024:
            raise ValueError("scan report with historical evidence exceeds limit")
    kernel = assess_kernel(inventory, results, now=now)
    queries_complete = all(
        r.complete
        and r.state_at(now, inventory_revision=inventory.revision) in ("confirmed", "not_affected")
        for r in results
    ) and bool(results)
    report = {
        "v": 1,
        "generated_at": now,
        "enabled": True,
        "config_revision": inventory.config_revision,
        "inventory_revision": inventory.revision,
        "running_kernel": inventory.running_kernel,
        "complete": queries_complete
        and kernel["complete"]
        and all(s.runtime_verified and s.expected_image_id for s in images),
        "runtime_images_verified": all(s.runtime_verified and s.expected_image_id for s in images),
        "source_queries_complete": queries_complete,
        "kernel": kernel,
        "counts": counts,
        "context_enabled": {
            "kev": bool(enricher and enricher.kev),
            "epss": bool(enricher and enricher.epss),
        },
        "results": records,
    }
    if len(json.dumps(report, ensure_ascii=False).encode()) > 32 * 1024 * 1024:
        raise ValueError("scan report limit exceeded")
    if before_save:
        before_save()
    store.save(results)
    return report


def write_private(path: Path, body: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, mode="w", encoding="utf-8", delete=False
        ) as handle:
            temporary = Path(handle.name)
            json.dump(body, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--inventory",
        type=Path,
        required=True,
        help="JSON exported by steward-host inventory; no secret values",
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--state-dir", type=Path, default=Path.home() / ".local/state/steward-scanner"
    )
    parser.add_argument(
        "--provider",
        action="append",
        choices=["osv", "trivy"],
        help="defaults to OSV; enables network transfer of package/image identifiers",
    )
    parser.add_argument("--max-requests", type=int, default=1000)
    parser.add_argument(
        "--kev", action="store_true", help="fetch optional CISA exploitation context"
    )
    parser.add_argument(
        "--epss", action="store_true", help="query FIRST with public CVE identifiers"
    )
    parser.add_argument("--context-max-requests", type=int, default=100)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("run scans as an unprivileged user; export inventory separately as root")
    if not 1 <= args.max_requests <= 10000:
        parser.error("--max-requests must be 1..10000")
    if not 1 <= args.context_max_requests <= 1000:
        parser.error("--context-max-requests must be 1..1000")
    os.umask(0o077)
    try:
        inventory, images = load_bundle(args.inventory)
        args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        providers = {}
        for source in args.provider or ["osv"]:
            providers[source] = (
                OSV(max_requests=args.max_requests)
                if source == "osv"
                else Trivy(cache=args.state_dir / "trivy-cache")
            )
        from .adapters.intelligence import Cache, Intelligence

        enricher = (
            Intelligence(
                Cache(args.state_dir / "intelligence.db"),
                kev=args.kev,
                epss=args.epss,
                max_requests=args.context_max_requests,
            )
            if args.kev or args.epss
            else None
        )
        report = scan(
            inventory,
            images,
            ScanStore(args.state_dir / "scans.db"),
            providers,
            now=time.time(),
            enricher=enricher,
        )
        Observations(args.state_dir / "observations.db").publish(report)
        write_private(args.out, report)
        print(
            json.dumps(
                {
                    "complete": report["complete"],
                    "counts": report["counts"],
                    "source_queries_complete": report["source_queries_complete"],
                    "kernel_state": report["kernel"]["state"],
                    "runtime_images_verified": report["runtime_images_verified"],
                    "inventory_revision": report["inventory_revision"],
                }
            )
        )
        sys.exit(0 if report["complete"] else 3)
    except (
        ValueError,
        OSError,
        ValidationError,
        KeyError,
        TypeError,
        AttributeError,
        sqlite3.Error,
    ):
        sys.exit("scan input/state error; report not replaced")


if __name__ == "__main__":
    main()
