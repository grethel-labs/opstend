"""Durable record of maintenance runs (L03 step 2).

One run per work item and window, kept as a job in a dedicated store: the
idempotency key binds it to the exact window start, so a restart, a repeated
controller cycle or a retry inside the same window cannot start it twice. A run
is never retried automatically (one attempt): an interrupted run ends as failed
with an explicit cause, because maintenance work is not assumed idempotent.

This module only records and admits. It never performs host actions, and the
controller's ordinary health restarts do not go through it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .maintenance import Admission, EmergencyWindow, WorkKind, admit
from .store import Store

KIND = "maintenance"
WORK_ID = re.compile(r"^[a-z][a-z0-9_-]{1,40}$")
MIN_LEASE_S = 30.0
LEASE_SLACK_S = 60.0


@dataclass(frozen=True)
class RunDecision:
    admission: Admission
    job: dict[str, Any] | None
    created: bool


class MaintenanceRuns:
    def __init__(self, store: Store):
        self.store = store

    def request(
        self,
        spec: str,
        now: float,
        *,
        work: str,
        work_seconds: int,
        kind: WorkKind = "routine",
        allow_reboot: bool = False,
        emergency: EmergencyWindow | None = None,
        created_by: str = "controller",
    ) -> RunDecision:
        """Admit and record one run. A second request in the same window is refused."""
        if not WORK_ID.fullmatch(work):
            raise ValueError("invalid maintenance work id")
        moment = datetime.fromtimestamp(now, UTC)
        admission = admit(
            spec,
            moment,
            work_seconds=work_seconds,
            kind=kind,
            allow_reboot=allow_reboot,
            emergency=emergency,
        )
        if not admission.allowed or admission.window is None:
            return RunDecision(admission, None, False)
        window = admission.window
        job, created = self.store.enqueue(
            KIND,
            f"maintenance:{work}",
            {
                "work": work,
                "kind": kind,
                "work_seconds": work_seconds,
                "window_start": window.start.isoformat(),
                "window_end": window.end.isoformat(),
                "window": admission.reason,
            },
            idempotency_key=f"maintenance:{work}:{window.start.isoformat()}",
            created_by=created_by,
            max_attempts=1,
            now=now,
        )
        if not created:
            return RunDecision(Admission(False, "already_recorded_in_window", window), job, False)
        return RunDecision(admission, job, True)

    def begin(self, worker: str, now: float, *, job_id: str | None = None) -> dict[str, Any] | None:
        """Lease the next recorded run, or only the given run, if it fits its window.

        A run whose window ended (or no longer has room) before it was claimed is
        closed as failed without starting.
        """
        if job_id is not None:
            # A job's kind is fixed at enqueue. Claim checks its runnable state atomically.
            job = self.store.get_job(job_id)
            if job is None or job["kind"] != KIND:
                return None
        while True:
            lease = LEASE_SLACK_S + MIN_LEASE_S
            job = self.store.claim(worker, lease_s=lease, now=now, job_id=job_id)
            if job is None:
                return None
            if job["kind"] != KIND:
                self.store.finish(job["id"], worker, ok=False, error="unexpected job kind", now=now)
                continue
            payload = job["payload"]
            end = datetime.fromisoformat(payload["window_end"]).timestamp()
            if now + payload["work_seconds"] > end:
                self.store.finish(
                    job["id"], worker, ok=False, error="window expired before start", now=now
                )
                if job_id is not None:
                    return None
                continue
            seconds = max(MIN_LEASE_S, payload["work_seconds"] + LEASE_SLACK_S)
            self.store.heartbeat(job["id"], worker, lease_s=seconds, now=now)
            return self.store.get_job(job["id"])

    def heartbeat(self, job_id: str, worker: str, now: float) -> bool:
        return self.store.heartbeat(job_id, worker, lease_s=LEASE_SLACK_S + MIN_LEASE_S, now=now)

    def complete(
        self,
        job_id: str,
        worker: str,
        *,
        ok: bool,
        now: float,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> str | None:
        return self.store.finish(
            job_id, worker, ok=ok, result=result, error=error, retryable=False, now=now
        )

    def recover(self, now: float) -> list[str]:
        """After a restart: close expired leases as failed (single attempt)."""
        return self.store.reconcile(now=now)

    def history(self, limit: int = 50) -> list[dict[str, Any]]:
        return [j for j in self.store.list_jobs(limit) if j["kind"] == KIND]
