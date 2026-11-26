"""Registered action `config_apply` (L10): apply the pending web UI revision locally.

The caller names the exact validated head revision, the exact applied revision it
reviewed and the installed release; nothing else. The executor

1. refuses unless the installed release, the registry and `desired.json` all still
   match what the caller named (version binding, second browser edit, CLI
   deployment, an executor-applied update in between),
2. reads the head body from the API's export and trusts only its content address,
   then re-validates it and recomputes the plan itself (`core/config_apply.py`):
   only a revision whose generated Ansible inputs are unchanged and whose changed
   areas are supported is applied; there is no uploaded playbook, command or path,
3. writes the executor registry first and `desired.json` last. `desired.json` is
   what the API and the CLI read as "applied", so it is the commit point; every
   crash point leaves files that are each old or new and a repeat of the same call
   finishes the job,
4. re-reads both files and reports success only if both carry the new revision.

Services need no restart: the executor reads the registry on every request, and
the areas that can change here are consumed only through it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from .. import __version__
from ..adapters.remediation import (
    Paths,
    RemediationError,
    _read_regular,
    _registry_for,
    _write_atomic,
)
from ..core.canonical import revision_id
from ..core.config_apply import plan_apply
from .protocol import ExecutorError

if TYPE_CHECKING:
    from .server import Executor

HEAD_EXPORT = Path("/var/lib/steward-api/export/head.json")
DIGEST = r"^[a-f0-9]{64}$"
RELEASE = r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$"
# Written by the unguarded site deployment for its whole run (first play to last), next to
# `desired.json`. Guarded deployments are covered by the fence and the held lock instead.
RUN_MARKER = "deploy-run.json"
MOVED = "STEWARD_CONFIG_MOVED"


class ConfigApplyParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    head_revision: str = Field(pattern=DIGEST)
    applied_revision: str = Field(pattern=DIGEST)
    release: str = Field(pattern=RELEASE)


def _paths(ex: Executor) -> tuple[Paths, Path]:
    paths = getattr(ex, "config_apply_paths", None) or Paths(registry=Path(ex.registry_path))
    return paths, getattr(ex, "config_apply_export", None) or HEAD_EXPORT


def _read_head(export: Path, head: str) -> dict[str, Any]:
    try:
        document = json.loads(_read_regular(export)[0])
        body = document["config"]
        named = document["head"]
    except (OSError, ValueError, KeyError, TypeError, RemediationError):
        raise ExecutorError("unavailable", "the exported head revision is not readable") from None
    if named != head or not isinstance(body, dict) or revision_id(body) != head:
        raise ExecutorError("conflict", "the head revision changed or its export is inconsistent")
    return body


def _out(value: dict[str, Any], *, indent: bool) -> str:
    if indent:
        return json.dumps(value, indent=4, sort_keys=True, separators=(",", ": ")) + "\n"
    return json.dumps(value, sort_keys=True) + "\n"


def config_apply(ex: Executor, params: ConfigApplyParams, role: str, registry: dict[str, Any]):
    from ..core.inference_deployment import revoke_for_desired
    from .server import load_registry

    paths, export = _paths(ex)
    with ex.target_lock("deployment-execution"):
        if ex.deployment_fence() is not None:
            raise ExecutorError("target_busy", "deployment recovery is pending")
        if os.path.lexists(paths.desired.parent / RUN_MARKER):
            raise ExecutorError(
                "target_busy",
                "a site deployment is running or was interrupted; "
                "finish or repeat `./steward deploy` first",
            )
        try:
            registry = load_registry(ex.registry_path)
            desired_text, desired_info = _read_regular(paths.desired)
            current = json.loads(desired_text)
            registry_text, registry_info = _read_regular(paths.registry)
            on_disk = json.loads(registry_text)
        except (OSError, ValueError, RemediationError):
            raise ExecutorError("unavailable", "applied configuration is not readable") from None
        if params.release != __version__ or registry.get("release") != params.release:
            raise ExecutorError("conflict", "the installed release differs from the request")
        applied_now = revision_id(current)
        if applied_now == params.head_revision and on_disk.get("config_revision") == applied_now:
            return _result("already_applied", params, ())  # repeat after completion
        if applied_now != params.applied_revision:
            raise ExecutorError("conflict", "the applied configuration changed")
        head_body = _read_head(export, params.head_revision)
        plan = plan_apply(current, head_body, release_version=params.release)
        if not plan.supported:
            raise ExecutorError("policy_denied", f"revision needs a deployment: {plan.reason}")
        peers = on_disk.get("peers")
        try:
            old_registry = _registry_for(current, peers)
            new_registry = _registry_for(head_body, peers)
        except RemediationError:
            raise ExecutorError("conflict", "applied configuration is not canonical") from None
        if on_disk not in (old_registry, new_registry):
            raise ExecutorError("conflict", "registry does not match the applied configuration")
        try:
            revoke_for_desired(paths.desired)
            if on_disk != new_registry:
                _write_atomic(
                    paths.registry,
                    _out(new_registry, indent=True),
                    mode=registry_info.st_mode & 0o7777,
                    uid=registry_info.st_uid,
                    gid=registry_info.st_gid,
                )
            _write_atomic(  # the commit point: this is what readers call "applied"
                paths.desired,
                _out(head_body, indent=False),
                mode=desired_info.st_mode & 0o7777,
                uid=desired_info.st_uid,
                gid=desired_info.st_gid,
            )
            seen_desired = json.loads(_read_regular(paths.desired)[0])
            seen_registry = json.loads(_read_regular(paths.registry)[0])
        except (OSError, ValueError, RemediationError):
            raise ExecutorError("unavailable", "writing the configuration failed") from None
        if (
            revision_id(seen_desired) != params.head_revision
            or seen_registry != new_registry
            or seen_registry.get("config_revision") != params.head_revision
        ):
            raise ExecutorError("execution_failed", "configuration was not applied as planned")
        ex.audit.append(
            "config_apply",
            role=role,
            head=params.head_revision,
            previous=params.applied_revision,
            areas=list(plan.areas),
            outcome="applied",
        )
        return _result("applied", params, plan.operations, plan.areas)


def _result(state: str, params: ConfigApplyParams, operations, areas=()) -> dict[str, Any]:
    return {
        "state": state,
        "config_revision": params.head_revision,
        "previous_revision": params.applied_revision,
        "release": params.release,
        "operations": list(operations),
        "areas": list(areas),
        "verified": True,
    }


def register(actions: dict, action_cls) -> None:
    actions["config_apply"] = action_cls(
        ConfigApplyParams, frozenset({"operator", "api"}), True, config_apply
    )


def check_base(expected: str, *, desired: Path, registry: Path, timeout: float = 30) -> None:
    """Compare-and-set guard for the unguarded deployment's writes.

    Runs under the deployment-execution lock, so a concurrent `config_apply` has either
    finished (and the revision moved: refuse) or is refused by the run marker. Refuses
    unless `desired.json` and the registry both still carry the revision the deployment
    started from.
    """
    from ..application_boot import BootError, deployment_lock

    try:
        with deployment_lock(timeout=timeout):
            seen = revision_id(json.loads(_read_regular(desired)[0]))
            on_disk = json.loads(_read_regular(registry)[0]).get("config_revision")
    except (BootError, OSError, ValueError, RemediationError, AttributeError) as error:
        raise SystemExit(f"cannot verify the applied configuration: {error}") from None
    if seen != expected or on_disk not in (None, expected):
        print(f"{MOVED} applied={seen} registry={on_disk}", file=sys.stderr)
        raise SystemExit(3)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="steward.executor.config_apply")
    parser.add_argument("command", choices=["check-base"])
    parser.add_argument("--expected", required=True)
    parser.add_argument("--desired", default="/etc/steward/config/desired.json")
    parser.add_argument("--registry", default="/etc/steward/executor.json")
    args = parser.parse_args(argv)
    check_base(args.expected, desired=Path(args.desired), registry=Path(args.registry))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
