"""Health probes: HTTP, TCP and container state, with response-time thresholds."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import StrEnum

import httpx


class ProbeResult(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"  # answered, but slower than the threshold
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"  # the probe could not decide; never treated as healthy


@dataclass
class Probe:
    kind: str  # http | tcp | container
    target: str
    timeout_s: float = 5.0
    slow_ms: int = 2000
    expect_status: tuple[int, ...] = (200, 204, 301, 302, 401)
    verify_tls: bool = True  # set False only for services with self-signed certificates


@dataclass
class Observation:
    result: ProbeResult
    latency_ms: int | None
    detail: str


async def run_probe(
    probe: Probe, client: httpx.AsyncClient | None = None, container_state: str | None = None
) -> Observation:
    start = time.monotonic()
    try:
        if probe.kind == "http":
            own = client is None
            c = client or httpx.AsyncClient(timeout=probe.timeout_s, verify=probe.verify_tls)
            try:
                resp = await c.get(probe.target)
            finally:
                if own:
                    await c.aclose()
            ms = int((time.monotonic() - start) * 1000)
            if resp.status_code not in probe.expect_status:
                return Observation(ProbeResult.UNHEALTHY, ms, f"HTTP {resp.status_code}")
            return Observation(
                ProbeResult.DEGRADED if ms > probe.slow_ms else ProbeResult.HEALTHY,
                ms,
                f"HTTP {resp.status_code}",
            )
        if probe.kind == "tcp":
            host, _, port = probe.target.rpartition(":")
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, int(port)), probe.timeout_s
            )
            writer.close()
            ms = int((time.monotonic() - start) * 1000)
            return Observation(
                ProbeResult.DEGRADED if ms > probe.slow_ms else ProbeResult.HEALTHY, ms, "port open"
            )
        if probe.kind == "container":
            if container_state is None:
                return Observation(ProbeResult.UNKNOWN, None, "container state not available")
            if container_state == "running":
                return Observation(ProbeResult.HEALTHY, None, "running")
            return Observation(ProbeResult.UNHEALTHY, None, container_state)
    except (TimeoutError, OSError, httpx.HTTPError) as exc:
        return Observation(ProbeResult.UNHEALTHY, None, type(exc).__name__)
    return Observation(ProbeResult.UNKNOWN, None, f"unknown probe kind {probe.kind}")
