"""Deploy validated repository artifacts only through the executor's update path (R04).

Neither the builder nor the fetcher deploys. This module takes a *validated report*
(:mod:`artifact_validation`) plus an approval signed by a second identity and hands
both to the executor's existing authorization path: ``update_validate`` (L04
evidence, approval bound to digest/revisions/expiry) then ``apply_verified_image``
(L05/L06 maintenance window, backup, journal, verification and recovery). It adds
no host effect of its own.

- A repeat deployment of the accepted digest is ``unchanged`` with ``changed=0``: the
  executor reports ``already_current`` and nothing is restarted.
- After a verified apply the caller's readback (running image, HTTP health, data) is
  compared with the accepted digest; a mismatch is reported, never hidden.
- An application is rolled out in ``depends_on`` order; a service that is rejected or
  fails stops every service that depends on it (it is skipped, not attempted).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..executor.protocol import ExecutorError
from .artifact_validation import ValidationReport
from .config import Application

States = ("deployed", "unchanged", "rejected", "failed", "readback_failed", "skipped")


class ExecutorCall(Protocol):
    def __call__(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Raises ExecutorError on a refusal."""


Readback = Callable[[str, str], dict[str, Any]]
"""``readback(project, digest) -> {"image": ref, "healthy": bool, "data_ok": bool | None}``."""


@dataclass(frozen=True)
class ServiceDeployment:
    service: str
    project: str
    report: ValidationReport
    approval: dict


@dataclass
class DeployOutcome:
    service: str
    project: str
    state: str
    changed: int = 0
    image: str | None = None
    approval_id: str | None = None
    detail: str = ""
    readback: dict = field(default_factory=dict)


def _approval_id(approval: dict) -> str | None:
    statement = approval.get("statement") if isinstance(approval, dict) else None
    value = statement.get("approval_id") if isinstance(statement, dict) else None
    return value if isinstance(value, str) else None


def deploy_service(
    call: ExecutorCall, deployment: ServiceDeployment, *, readback: Readback | None = None
) -> DeployOutcome:
    report = deployment.report
    out = DeployOutcome(
        deployment.service, deployment.project, "rejected", image=report.image,
        approval_id=_approval_id(deployment.approval),
    )  # fmt: skip
    if (
        not report.accepted
        or report.attestation is None
        or report.digest is None
        or report.project != deployment.project
        or out.approval_id is None
    ):
        out.detail = "no accepted validation for this project"
        return out
    try:
        call(
            "update_validate",
            {
                "project_id": deployment.project,
                "digest": report.digest,
                "attestation": report.attestation,
                "approval": deployment.approval,
            },
        )
    except ExecutorError as exc:
        if "already_current" in exc.message:
            out.state, out.detail = "unchanged", "accepted digest is already running"
        else:
            out.detail = f"{exc.error_class}: {exc.message}"[:200]
        return out
    try:
        call(
            "apply_verified_image",
            {
                "project_id": deployment.project,
                "approval_id": out.approval_id,
                "digest": report.digest,
            },
        )
    except ExecutorError as exc:
        out.state = "failed"
        out.detail = f"{exc.error_class}: {exc.message}"[:200]
        return out
    out.state, out.changed = "deployed", 1
    if readback is not None:
        try:
            seen = readback(deployment.project, report.digest)
        except Exception as exc:  # noqa: BLE001 - an unreadable result is not a success
            seen = {"error": type(exc).__name__}
        out.readback = seen
        if (
            seen.get("image") != report.image
            or seen.get("healthy") is not True
            or seen.get("data_ok") is False
        ):
            out.state, out.detail = "readback_failed", "running state does not match the digest"
    return out


def deploy_application(
    call: ExecutorCall,
    application: Application,
    deployments: dict[str, ServiceDeployment],
    *,
    readback: Readback | None = None,
) -> list[DeployOutcome]:
    """Roll out in dependency order; dependents of a failed service are skipped."""
    blocked: set[str] = set()
    outcomes: list[DeployOutcome] = []
    for name in application.start_order():
        deployment = deployments.get(name)
        if deployment is None:
            continue  # nothing new for this service: it neither deploys nor blocks
        service = next(s for s in application.services if s.id == name)
        if blocked.intersection(service.depends_on):
            outcomes.append(
                DeployOutcome(name, deployment.project, "skipped", detail="a dependency failed")
            )
            blocked.add(name)
            continue
        outcome = deploy_service(call, deployment, readback=readback)
        outcomes.append(outcome)
        if outcome.state not in ("deployed", "unchanged"):
            blocked.add(name)
    return outcomes
