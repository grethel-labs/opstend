"""Unprivileged notification worker: collector socket -> private outbox -> HTTPS.

This process receives neither an executor socket nor permission to mutate host
state. Transport outages only delay messages, never controller security work.
"""

from __future__ import annotations

import argparse
import os
import signal
import threading
import time
from pathlib import Path

from .adapters.notifications import NotificationAdapter, Result
from .collector import QUERY_SOCKET
from .core.outbox import Outbox
from .executor.protocol import ExecutorError, call


class Worker:
    def __init__(
        self,
        outbox: Outbox,
        adapters: dict[tuple[str, str], NotificationAdapter],
        collector_socket: str = QUERY_SOCKET,
        heartbeat_intervals: dict[tuple[str, str], int] | None = None,
        audit_destinations: set[tuple[str, str]] | None = None,
    ):
        self.outbox, self.adapters = outbox, adapters
        self.collector_socket = collector_socket
        self.heartbeat_intervals = heartbeat_intervals or {}
        self.audit_destinations = audit_destinations or set()

    def collect(self, *, now: float) -> None:
        for adapter, destination in self.adapters:
            cursor = self.outbox.cursor(adapter, destination)
            try:
                result = call(
                    "events_query",
                    {"after_id": cursor, "limit": 500},
                    socket_path=self.collector_socket,
                    timeout=10,
                )
            except ExecutorError:
                result = None
            interval = self.heartbeat_intervals.get((adapter, destination))
            if interval:
                coverage = result.get("coverage", {}) if result else {}
                lag = coverage.get("lag_s")
                fresh = (
                    isinstance(lag, (int, float))
                    and 0 <= lag <= 120
                    and not coverage.get("open_gaps")
                )
                summary = (
                    "Heartbeat: notifier running; collector current."
                    if fresh
                    else "Heartbeat: notifier running; collector observation gap."
                )
                bucket = int(now // interval)
                self.outbox.heartbeat(
                    adapter,
                    destination,
                    bucket,
                    {
                        "summary": summary,
                        "observed_at": now,
                        "collector_current": fresh,
                        "collector_last_cycle": coverage.get("last_cycle"),
                    },
                    now=now,
                )
            if result is not None:
                self.outbox.ingest(
                    adapter,
                    destination,
                    result["events"],
                    now=now,
                    coverage=result.get("coverage"),
                    audit_export=(adapter, destination) in self.audit_destinations,
                )
        self.outbox.flush_digests(now=now)
        self.outbox.prune(finished_before=now - 30 * 86400)

    def deliver(self, *, now: float | None = None) -> bool:
        fixed_time = now is not None
        now = time.time() if now is None else now
        delivery = self.outbox.claim(now=now, lease_s=30)
        if delivery is None:
            return False
        adapter = self.adapters.get((delivery.adapter, delivery.destination))
        try:
            result = (
                adapter.send(f"{self.outbox.identity}:{delivery.key}", delivery.payload)
                if adapter
                else Result(error_class="destination_removed", permanent=True)
            )
        except Exception:  # noqa: BLE001 - transport bugs must not terminate the worker
            result = Result(error_class="internal")
        finished = now if fixed_time else time.time()
        if result.confirmed:
            self.outbox.acknowledge(delivery, now=finished)
        else:
            self.outbox.retry(
                delivery,
                now=finished,
                retry_after_s=result.retry_after_s,
                permanent=result.permanent,
            )
        return True


def main() -> None:
    import json

    from .adapters.notifications import DiscordWebhook, SignedWebhook
    from .core.config import Channel
    from .core.secrets import resolve

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--config", required=True, help="private JSON list of channel settings")
    parser.add_argument("--state-dir", default="/var/lib/steward-notifier")
    parser.add_argument("--collector-socket", default=QUERY_SOCKET)
    args = parser.parse_args()
    os.umask(0o077)
    channels = [Channel.model_validate(c) for c in json.loads(Path(args.config).read_text())]
    adapters = {}
    for c in channels:
        credentials = os.environ.get("CREDENTIALS_DIRECTORY")
        url = (
            Path(credentials, f"{c.id}-url").read_text().strip()
            if credentials
            else resolve(c.url_ref)
        )
        signing_key = (
            Path(credentials, f"{c.id}-key").read_text().strip()
            if credentials and c.adapter == "webhook"
            else resolve(c.signing_key_ref)
            if c.signing_key_ref
            else None
        )
        adapters[c.adapter, c.id] = (
            DiscordWebhook(url) if c.adapter == "discord" else SignedWebhook(url, signing_key)
        )
    state = Path(args.state_dir)
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    worker = Worker(
        Outbox(state / "outbox.db"),
        adapters,
        args.collector_socket,
        {(c.adapter, c.id): c.heartbeat_interval_s for c in channels if c.heartbeat_interval_s},
        {(c.adapter, c.id) for c in channels if c.audit_export},
    )
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    while not stop.is_set():
        try:
            worker.collect(now=time.time())
        except Exception as exc:  # noqa: BLE001 - do not print credential-bearing messages
            print(f"notification collection failed: {type(exc).__name__}", flush=True)
        for _ in range(20):
            if stop.is_set() or not worker.deliver():
                break
        stop.wait(5)


if __name__ == "__main__":
    main()
