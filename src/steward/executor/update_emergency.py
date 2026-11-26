"""Operator emergency confirmation for an update outside the maintenance window.

Decision 5 (2026-11-23): an operator may apply a verified update outside the window with an
explicit confirmation and a reason. Everything else stays: evidence, kill switch semantics,
backup age, approval, target lock, recovery admission and journal are the unchanged
`apply_verified_image` path. Only the *window* check is waived, only for the role
`operator`, never for the controller or any automatic caller, and only when a window is
configured at all (no window is a configuration gap, not an emergency).

Every use is audited as `update_emergency` (collector event `update.emergency`, immediate
delivery class) when the bypass is granted, and a refused attempt by another role is audited
too.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..core.config import UpdatePolicy
from .protocol import ExecutorError

if TYPE_CHECKING:
    from .server import Executor

REASON_PATTERN = r"^[\x20-\x7e]{10,200}$"


def refuse_automatic(ex: Executor, role: str, project: str, approval_id: str) -> None:
    """Emergency confirmation is an operator act; any other caller is refused and audited."""
    if role == "operator":
        return
    ex.audit.append(
        "update_emergency",
        project_id=project,
        approval_id=approval_id,
        outcome="denied",
        role=role,
    )
    raise ExecutorError("policy_denied", "emergency confirmation is operator-only")


def window_allows_or_emergency(
    registry: dict[str, Any],
    contract: UpdatePolicy,
    now: float,
    *,
    emergency: bool,
    check_window: Any,
) -> bool:
    """True when the update proceeds only because of the emergency confirmation.

    `check_window(registry, contract, now)` is the ordinary admission and raises when the
    time is not allowed. Without a configured window nothing is waived."""
    try:
        check_window(registry, contract, now)
    except ExecutorError as exc:
        if not emergency or not registry.get("maintenance"):
            raise
        if exc.error_class != "policy_denied":
            raise
        return True
    return False


def announce(ex: Executor, project: str, approval_id: str, reason: str) -> None:
    ex.audit.append(
        "update_emergency",
        project_id=project,
        approval_id=approval_id,
        outcome="confirmed",
        reason=reason[:200],
        role="operator",
    )
