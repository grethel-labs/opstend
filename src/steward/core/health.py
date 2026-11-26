"""Classification of workload health probe results (L03 step 3).

A probe returns a mapping; this module normalizes it into one of five states so
that "could not tell" is never reported as healthy and never triggers a restart:

- healthy    verified success within the response-time threshold
- slow       verified success, but slower than ``max_response_ms`` (treated as a hang)
- unhealthy  the workload answered with a failure
- timeout    no answer within the probe timeout
- unknown    the probe could not be evaluated (for example no container healthcheck)

``ok`` stays true only for ``healthy``. Probes are fixed kinds addressed by
registered IDs; no operator- or model-supplied command is ever executed.
"""

from __future__ import annotations

from typing import Any, Literal

HealthState = Literal["healthy", "slow", "unhealthy", "timeout", "unknown"]
PROBES = ("http", "tcp", "container")


def classify(result: dict[str, Any], max_response_ms: int | None = None) -> dict[str, Any]:
    out = dict(result)
    state = out.get("state")
    if state not in ("healthy", "slow", "unhealthy", "timeout", "unknown"):
        if out.get("error") == "TimeoutError":
            state = "timeout"
        else:
            state = "healthy" if out.get("ok") else "unhealthy"
    elapsed = out.get("elapsed_ms")
    if (
        state == "healthy"
        and max_response_ms is not None
        and isinstance(elapsed, int | float)
        and elapsed > max_response_ms
    ):
        state = "slow"
        out["error"] = f"response {int(elapsed)} ms exceeds {max_response_ms} ms"
    out["state"] = state
    out["ok"] = state == "healthy"
    return out
