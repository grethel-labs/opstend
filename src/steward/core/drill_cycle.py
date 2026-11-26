"""Controller driver for announced maintenance drills (L11).

Decides only *when to ask*; the executor re-checks everything (kill switch, window,
announcement, suspension, resources, locks). One drill request per cycle keeps the
self-healing loop responsive; each target is asked at most once per window.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from ..executor.protocol import ExecutorError

ORDER = ("resources", "restart", "restore")
CALL_TIMEOUT_S = 1200


class DrillCycle:
    def __init__(self, executor, socket_path: str):
        self.executor, self.socket_path = executor, socket_path
        self.asked: set[tuple[str, str, str]] = set()
        self.announced: set[str] = set()

    def _call(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        return self.executor(
            action,
            params,
            socket_path=self.socket_path,
            request_id=f"drill-{uuid.uuid4().hex[:16]}",
            timeout=CALL_TIMEOUT_S,
        )

    def run(self, status: dict[str, Any], now: float) -> dict[str, Any]:
        policy = status.get("maintenance") or {}
        drills = [d for d in ORDER if d in (policy.get("drills") or [])]
        if not drills:
            return {"state": "off"}
        if status.get("kill_switch") or status.get("deployment_recovery") != "clear":
            return {"state": "blocked", "reason": "kill switch or deployment recovery"}
        try:
            if policy.get("state") == "outside_window":
                start = (policy.get("next_window") or {}).get("start")
                if (
                    not start
                    or start in self.announced
                    or datetime.fromisoformat(start).timestamp() - now > 24 * 3600
                ):
                    return {"state": "waiting"}
                result = self._call("drill_announce", {})
                if result.get("announced"):
                    self.announced.add(start)
                return {
                    "state": "announce",
                    "announced": bool(result.get("announced")),
                    "reason": result.get("reason"),
                }
            if policy.get("state") != "in_window":
                return {"state": "unknown"}
            window = (policy.get("current_window") or {}).get("start", "")
            projects = sorted(
                p
                for p, entry in status.get("projects", {}).items()
                if entry.get("deploy")
                and (entry.get("health") or {}).get("state") == "healthy"
                and entry.get("allow_restart")
            )
            for drill in drills:
                for project in [None] if drill == "resources" else projects:
                    key = (drill, project or "", window)
                    if key in self.asked:
                        continue
                    self.asked.add(key)
                    params = {"drill": drill, **({"project_id": project} if project else {})}
                    result = self._call("drill_run", params)
                    return {
                        "state": "asked",
                        "drill": drill,
                        "project": project,
                        "outcome": result.get("state"),
                        "reason": result.get("reason"),
                    }
            return {"state": "done"}
        except ExecutorError as exc:
            return {"state": "error", "class": exc.error_class}
