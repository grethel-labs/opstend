"""Scheduled, unprivileged scans and peer-authenticated read-only observations."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import signal
import threading
import time
import uuid
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .adapters.intelligence import Cache, Intelligence
from .adapters.scanners import OSV, Trivy
from .collector import resolve_readers
from .core import ipc
from .core.config import Scanning, Slug
from .core.inventory import ApplicationServiceScope, Digest, collect
from .core.scan_observations import Observations
from .core.store import Store
from .core.tools import TRIVY_BINARY
from .executor.protocol import DEFAULT_SOCKET, PROTOCOL_VERSION, ExecutorError, call
from .scanner import ScanStore, parse_bundle, scan

QUERY_SOCKET = "/run/steward-scanner/query.sock"


class RuntimeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    config_revision: Digest
    scanning: Scanning


class Page(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project: Literal["host"] | Slug | None = None
    source: Literal["osv", "trivy"] | None = None
    subject: Digest | None = None
    offset: int = Field(0, ge=0, le=5000)
    limit: int = Field(50, ge=1, le=200)
    finding_offset: int = Field(0, ge=0, le=1000)
    snapshot_id: Digest | None = None


class Changes(BaseModel):
    model_config = ConfigDict(extra="forbid")
    after_id: int = Field(0, ge=0)
    limit: int = Field(200, ge=1, le=200)


class ControllerPage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project: ApplicationServiceScope
    expected_revision: Digest
    finding_offset: int = Field(0, ge=0, le=1000)
    snapshot_id: Digest | None = None


class QueryService:
    def __init__(self, observations, jobs, config, readers, *, clock=time.time):
        self.observations, self.jobs, self.config = observations, jobs, config
        self.readers, self.clock = readers, clock

    def options(self):
        return {
            "now": self.clock(),
            "enabled": self.config.scanning.enabled,
            "config_revision": self.config.config_revision,
            "max_age_s": self.config.scanning.max_age_s,
        }

    def handle(self, raw: bytes, peer_uid: int) -> dict:
        try:
            role = "operator" if peer_uid == 0 else self.readers.get(peer_uid)
            if role not in ("operator", "api", "collector", "controller"):
                raise ExecutorError("unauthorized_peer", "peer is not a registered scanner reader")
            request = json.loads(raw)
            if not isinstance(request, dict) or request.get("v") != PROTOCOL_VERSION:
                raise ValueError("invalid request")
            action, params = request.get("action"), request.get("params", {})
            if action == "scans_summary" and role in ("operator", "api", "collector"):
                if params:
                    raise ValueError("unexpected parameters")
                result = self.observations.summary(**self.options())
            elif action == "scans_query" and role in ("operator", "api", "controller"):
                options = self.options()
                if role == "controller":
                    values = ControllerPage.model_validate(params).model_dump()
                    if values.pop("expected_revision") != options["config_revision"]:
                        raise ExecutorError("conflict", "scanner configuration revision changed")
                    values.update(source="trivy", offset=0, limit=1)
                else:
                    values = Page.model_validate(params).model_dump()
                expected = values.pop("snapshot_id")
                result = self.observations.query(**options, **values)
                if expected is not None and result["snapshot_id"] != expected:
                    raise ExecutorError("conflict", "scan snapshot changed")
            elif action == "scans_changes" and role in ("operator", "collector"):
                page = Changes.model_validate(params)
                result = self.observations.changes(**page.model_dump())
                result["coverage"]["enabled"] = self.config.scanning.enabled
                result["coverage"]["config_revision"] = self.config.config_revision
            elif action == "scans_jobs" and role in ("operator", "api"):
                if params:
                    raise ValueError("unexpected parameters")
                result = {"jobs": self.jobs.list_jobs(limit=20)}
            else:
                raise ExecutorError(
                    "policy_denied", "read-only action is not allowed for this peer"
                )
            return {"ok": True, "result": result}
        except ExecutorError as exc:
            return {"ok": False, "error_class": exc.error_class, "message": exc.message}
        except (ValueError, TypeError, ValidationError):
            return {"ok": False, "error_class": "bad_request", "message": "invalid scanner query"}
        except Exception as exc:  # noqa: BLE001 - no paths/provider exceptions cross trust domains
            return {"ok": False, "error_class": "internal", "message": type(exc).__name__}
        finally:
            self.jobs.close()


class Runner:
    def __init__(
        self,
        state_dir,
        config,
        *,
        executor=call,
        socket_path=DEFAULT_SOCKET,
        clock=time.time,
        providers=None,
    ):
        self.state = Path(state_dir)
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.config, self.executor, self.socket_path = config, executor, socket_path
        self.clock, self.providers = clock, providers
        self.jobs = Store(self.state / "jobs.db")
        self.cache = ScanStore(self.state / "scans.db")
        self.observations = Observations(self.state / "observations.db")
        self.worker = uuid.uuid4().hex
        self.stop = threading.Event()

    def inventory(self):
        inventory = collect(self.executor, socket_path=self.socket_path)
        images = [
            self.executor("image_inventory", {"project_id": project}, socket_path=self.socket_path)
            for project in inventory.projects
        ]
        for scope in inventory.application_services or ():
            application, service = scope.split("/")
            image = self.executor(
                "image_inventory",
                {
                    "application": application,
                    "service": service,
                    "expected_revision": inventory.config_revision,
                },
                socket_path=self.socket_path,
            )
            if (
                not isinstance(image, dict)
                or image.get("application") != application
                or image.get("service") != service
            ):
                raise ExecutorError("unavailable", "application service image identity differs")
            images.append(image)
        return parse_bundle(
            {
                **inventory.model_dump(mode="json", exclude_none=True),
                "revision": inventory.revision,
                "images": images,
            }
        )

    def run_once(self):
        now, settings = self.clock(), self.config.scanning
        self.jobs.reconcile(now=now)
        self.jobs.prune_jobs("vulnerability_scan", now=now)
        if not settings.enabled:
            self.observations.disable(now=now, config_revision=self.config.config_revision)
            return None
        slot = int(now // settings.interval_s)
        self.jobs.enqueue(
            "vulnerability_scan",
            "inventory",
            {"config_revision": self.config.config_revision},
            idempotency_key=f"scan:{self.config.config_revision}:{settings.interval_s}:{slot}",
            created_by="scanner",
            max_attempts=3,
            now=now,
        )
        job = self.jobs.claim(self.worker, lease_s=60, now=now)
        if not job:
            return None
        finished, lost = threading.Event(), threading.Event()

        def guard():
            if (
                self.stop.is_set()
                or lost.is_set()
                or not self.jobs.heartbeat(job["id"], self.worker, lease_s=60, now=self.clock())
            ):
                lost.set()
                raise ExecutorError("unavailable", "scan lease lost")

        def heartbeat():
            while not finished.wait(10):
                try:
                    guard()
                except Exception:  # noqa: BLE001 - uncertainty must stop publication
                    lost.set()
                    return

        thread = threading.Thread(target=heartbeat, daemon=True, name="scan-lease")
        thread.start()
        try:
            if job["payload"]["config_revision"] != self.config.config_revision:
                raise ValueError("obsolete scan configuration")
            binding = self.observations.snapshot_binding()
            snapshot_id = binding[0] if binding else None
            try:
                inventory, images = self.inventory()
                if inventory.config_revision != self.config.config_revision:
                    raise ExecutorError("unavailable", "executor configuration differs")
            except (ExecutorError, OSError, ValueError):
                guard()
                self.observations.invalidate_unavailable(snapshot_id, now=self.clock())
                raise
            guard()
            if (
                binding
                and binding[1] == inventory.config_revision
                and (
                    binding[2] != inventory.revision
                    or binding[3] != sorted(images, key=lambda image: image.key)
                )
            ):
                self.observations.invalidate_inventory(snapshot_id, now=self.clock())

            def revalidate():
                guard()
                try:
                    current, current_images = self.inventory()
                except (ExecutorError, OSError, ValueError):
                    guard()
                    self.observations.invalidate_unavailable(snapshot_id, now=self.clock())
                    raise
                guard()
                if current.revision != inventory.revision or current_images != images:
                    self.observations.invalidate_inventory(snapshot_id, now=self.clock())
                    raise ExecutorError("unavailable", "inventory changed during scan")

            providers = self.providers
            if providers is None:
                providers = {}
                if settings.osv:
                    providers["osv"] = OSV(max_requests=settings.max_requests)
                if settings.trivy:
                    providers["trivy"] = Trivy(
                        binary=TRIVY_BINARY, cache=self.state / "trivy-cache"
                    )
            report = scan(
                inventory,
                images,
                self.cache,
                providers,
                now=self.clock(),
                before_save=revalidate,
                enricher=Intelligence(
                    Cache(self.state / "intelligence.db"),
                    kev=settings.kev,
                    epss=settings.epss,
                    max_requests=settings.context_max_requests,
                    clock=self.clock,
                )
                if settings.kev or settings.epss
                else None,
            )
            guard()
            self.observations.publish(report)
            self.jobs.finish(
                job["id"],
                self.worker,
                ok=True,
                result={"complete": report["complete"], "counts": report["counts"]},
                now=self.clock(),
            )
            return report
        except Exception as exc:  # noqa: BLE001 - persist bounded failure, let later attempts recover
            error = exc.error_class if isinstance(exc, ExecutorError) else type(exc).__name__
            self.jobs.finish(
                job["id"],
                self.worker,
                ok=False,
                error=error,
                retryable=isinstance(exc, (ExecutorError, OSError)),
                now=self.clock(),
            )
            return None
        finally:
            finished.set()
            thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/steward/scanner.json"))
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/steward-scanner"))
    parser.add_argument("--executor-socket", default=DEFAULT_SOCKET)
    parser.add_argument("--query-socket", default=QUERY_SOCKET)
    parser.add_argument("--query-group", default="steward-obs")
    parser.add_argument(
        "--reader",
        action="append",
        default=["api=steward-api", "collector=steward-col", "controller=steward-ctl"],
    )
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("scanner daemon must run as an unprivileged user")
    os.umask(0o077)
    config = RuntimeConfig.model_validate_json(args.config.read_bytes())
    args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    # One process owns scheduling/publication. The kernel releases this on death.
    with (args.state_dir / "worker.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        runner = Runner(args.state_dir, config, socket_path=args.executor_socket)
        service = QueryService(
            runner.observations,
            runner.jobs,
            config,
            resolve_readers(args.reader),
        )
        server = ipc.bind(args.query_socket, service.handle, args.query_group)
        threading.Thread(target=server.serve_forever, daemon=True, name="scan-query").start()
        signal.signal(signal.SIGTERM, lambda *_: runner.stop.set())
        signal.signal(signal.SIGINT, lambda *_: runner.stop.set())
        try:
            while not runner.stop.is_set():
                runner.run_once()
                runner.stop.wait(5)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
