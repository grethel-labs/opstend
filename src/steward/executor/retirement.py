"""Executor actions that retire and archive a removed application (L09 step 2).

Retirement applies to a registered, separately isolated application with only
managed services that is absent from the exact desired registry. Manual retirement
requires an already disabled deployment. Guarded site deployment holds boot and
route custody while it stops enabled services and archives their working area.
The registry, identities, paths, units and image tags come from root-owned state.

Sequence, journaled in the archive directory so every crash point resumes:
verify stopped -> archive data and images -> verify the archive by re-reading it
-> re-verify and compare the working data signature -> release images, then
data -> stop the dedicated managers. Nothing in this module deletes an archive.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import application_boot as boot
from ..core import app_archive as archive
from ..core.application_ops import derive_group_plan
from ..core.backups import BackupError
from ..core.config import Backup
from ..core.ids import graph_identifier
from ..core.incidents import TERMINAL as TERMINAL_INCIDENTS
from ..core.incidents import IncidentError, IncidentStore
from ..core.render import image_tag
from ..core.retirement import Candidate, RetirementPlanError, classify, plan_retirements
from .protocol import ExecutorError

PERMANENT = {"state_conflict", "evidence_mismatch", "binding_changed", "source_changed"}
CAPTURE_DEADLINE_S = 300


def _failure(error: BackupError) -> ExecutorError:
    error_class = error.error_class
    if error_class == "target_busy":
        return ExecutorError("target_busy", "another archive operation is running")
    if error_class in PERMANENT:
        return ExecutorError("conflict", f"application archive conflict ({error_class})")
    if error_class == "shared_unavailable":
        return ExecutorError("policy_denied", "isolation: shared retirement is not available")
    return ExecutorError("unavailable", f"application archive is unavailable ({error_class})")


def read_identity(user: str) -> dict:
    return boot.inspect_identity(user)


@dataclass
class Context:
    ex: Any
    application: str
    registry: dict[str, Any]
    specs: dict[str, dict[str, Any]]
    root: Path
    data_root: Path
    cache: Path
    server: str
    max_data_bytes: int
    read_identity: Callable[[str], dict]
    expected_revision: str
    desired_revision: str
    identities: dict[str, dict] | None = None
    require_custody: Callable[[], None] | None = None

    @property
    def host(self):
        return self.ex.host


def _audit(ctx: Context, state, outcome: str, **fields) -> None:
    ctx.ex.audit.append(
        "application_retirement",
        application=ctx.application,
        operation_id=state.operation_id,
        phase=state.phase,
        outcome=outcome,
        **fields,
    )


def _observe_identities(ctx: Context) -> dict[str, dict]:
    identities = {}
    for name, spec in sorted(ctx.specs.items()):
        try:
            identity = ctx.read_identity(spec["user"])
            archive.Identity.model_validate(identity)
        except (boot.BootError, OSError, ValueError, KeyError, TypeError):
            raise ExecutorError("unavailable", "application identity is unavailable") from None
        if ctx.host.service_user_uid(spec["user"]) != identity["uid"]:
            raise ExecutorError("policy_denied", "application identity changed")
        identities[name] = identity
    ctx.identities = identities
    return identities


def _stopped(ctx: Context, name: str) -> bool:
    spec, identity = ctx.specs[name], ctx.identities[name]
    host = ctx.host
    if host.application_manager_quiescent(identity["uid"], identity["subuid"]):
        return True
    return bool(
        host.group_service_quiescent(spec["user"], spec["unit"], spec["container"])
        and host.workload_quiescent(spec["user"], spec["unit"])
    )


def _require_stopped(ctx: Context) -> None:
    for name, spec in sorted(ctx.specs.items()):
        if ctx.host.group_service_running(spec["user"], spec["unit"], spec["container"]) is True:
            raise ExecutorError(
                "policy_denied", "a service is running; deploy it with deploy: false first"
            )
        if not _stopped(ctx, name):
            raise ExecutorError("unavailable", "application writers are not quiescent")
    live = sorted(
        {
            spec["user"]
            for name, spec in ctx.specs.items()
            if not ctx.host.application_manager_quiescent(
                ctx.identities[name]["uid"], ctx.identities[name]["subuid"]
            )
        }
    )
    if live and not ctx.host.group_users_within_systemd_slices(live):
        raise ExecutorError("unavailable", "application user process scope is unknown")


def _data_source(spec, expected: Path) -> Path | None:
    source, target = spec.get("data_source"), spec.get("data_target")
    if (source is None) != (target is None):
        raise ExecutorError("policy_denied", "application data contract is incomplete")
    if source is None:
        return None
    if source != str(expected) or spec.get("allow_backup_pause") is not True:
        raise ExecutorError("policy_denied", "application data archive is not authorized")
    return expected


def _require_archive_revisions(state, applied_revision: str, desired_revision: str) -> None:
    if state is not None and (state.applied_revision, state.desired_revision) != (
        applied_revision,
        desired_revision,
    ):
        raise ExecutorError("conflict", "an unfinished retirement is bound to other revisions")


def require_guarded_eligibility(ex, registry, application: str, desired_revision: str) -> None:
    """Refuse fixed policy conflicts before a guarded removal can reserve custody."""
    from .server import APPLICATION_DATA_ROOT

    data = APPLICATION_DATA_ROOT / application / "data"
    for name, spec in registry["applications"][application]["services"].items():
        _data_source(spec, data / name)
    try:
        incident = IncidentStore(Path(ex._db_path).parent / "incidents").get(application)
    except (IncidentError, OSError):
        raise ExecutorError("unavailable", "application incident state is inconsistent") from None
    if incident is not None and incident.phase not in TERMINAL_INCIDENTS:
        raise ExecutorError("target_busy", "an application incident is unfinished")
    try:
        (archive.ARCHIVE_ROOT / application).lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise ExecutorError("unavailable", "application archive is unavailable") from None
    try:
        state = archive.active_operation(archive.ARCHIVE_ROOT, application)
    except BackupError as error:
        raise _failure(error) from None
    _require_archive_revisions(state, registry["config_revision"], desired_revision)


def _service_inputs(ctx: Context) -> list[archive.ServiceInput]:
    result = []
    for name, spec in sorted(ctx.specs.items()):
        data = _data_source(spec, ctx.data_root / ctx.application / "data" / name)
        result.append(
            archive.ServiceInput(
                service=name,
                user=spec["user"],
                unit=spec["unit"],
                identity=ctx.identities[name],
                image=spec["image"],
                image_tag=image_tag(spec["container"], spec["image"]),
                source_revision=spec["source_revision"],
                data_source=data,
            )
        )
    return result


def _build(ctx: Context, state):
    operation = ctx.root / ctx.application / state.operation_id
    deadline = time.monotonic() + CAPTURE_DEADLINE_S

    def quiescent() -> bool:
        if time.monotonic() >= deadline or ctx.host.kill_switch():
            return False
        return all(_stopped(ctx, name) for name in ctx.specs)

    try:
        manifest = archive.write_archive(
            operation,
            state,
            server=ctx.server,
            services=_service_inputs(ctx),
            image_cache=ctx.cache,
            is_quiescent=quiescent,
            max_data_bytes=ctx.max_data_bytes,
            timeout_s=CAPTURE_DEADLINE_S,
        )
        archive.verify_archive(operation, expected_id=manifest.id)
    except (BackupError, OSError) as error:
        # Never verified: only now may partial output be discarded. Working data is untouched.
        error_class = error.error_class if isinstance(error, BackupError) else "capture_failed"
        state = archive.discard_unverified(ctx.root, state, error_class)
        _audit(ctx, state, "failed", error_class=error_class)
        raise _failure(BackupError(error_class)) from None
    return manifest


def _verified_manifest(ctx: Context, state):
    operation = ctx.root / ctx.application / state.operation_id
    try:
        return archive.verify_archive(operation, expected_id=state.manifest_id or "")
    except BackupError as error:
        raise _failure(error) from None


def _stop_manager(ctx: Context, name: str) -> None:
    identity = ctx.identities[name]
    host = ctx.host
    if host.application_manager_quiescent(identity["uid"], identity["subuid"]):
        return
    if not host.stop_application_manager(identity["uid"]) or not host.application_manager_quiescent(
        identity["uid"], identity["subuid"]
    ):
        raise ExecutorError("unavailable", "application user manager did not stop")


def _release_images(ctx: Context, manifest) -> list[str]:
    kept = []
    for name, item in sorted(manifest.services.items()):
        if item.image_copy is None:
            kept.append(name)  # no archived copy to restore from: keep the loaded image
            continue
        identity = ctx.identities[name]
        if ctx.host.application_manager_quiescent(
            identity["uid"], identity["subuid"]
        ) and not ctx.host.start_application_manager(identity["uid"]):
            raise ExecutorError("unavailable", "application user manager did not start")
        if not ctx.host.remove_user_image(item.user, item.image_tag):
            raise ExecutorError("unavailable", "loaded application image was not removed")
        try:
            archive.release_image_cache(ctx.cache, item.image_copy)
        except BackupError as error:
            raise _failure(error) from None
    return kept


def _stop_managers(ctx: Context) -> None:
    for name in sorted(ctx.specs):
        _stop_manager(ctx, name)


def _release(ctx: Context, state, manifest):
    if state.phase == "verified":
        state = archive.advance(
            ctx.root, state, "releasing", released={name: "pending" for name in ctx.specs}
        )
        _audit(ctx, state, "ok")
    kept = _release_images(ctx, manifest)
    if ctx.require_custody:
        # Image cleanup can start a rootless manager. Prove there are no
        # account processes before releasing any writable data.
        _observe_identities(ctx)
        _require_manifest_binding(ctx, state, manifest)
        _require_stopped(ctx)
        _stop_managers(ctx)
        _require_working_data(ctx, state, manifest)
        if not all(
            ctx.host.application_manager_quiescent(identity["uid"], identity["subuid"])
            for identity in ctx.identities.values()
        ):
            raise ExecutorError("unavailable", "application user managers are not quiescent")
    for name in sorted(manifest.services):
        item = manifest.services[name]
        if item.data is None or state.released.get(name) == "deleted":
            continue
        if ctx.require_custody:
            if ctx.host.kill_switch():
                raise ExecutorError("kill_switch", "application retirement is stopped")
            ctx.require_custody()
        if state.released.get(name) != "moved":
            state = archive.advance(ctx.root, state, released={**state.released, name: "moved"})
        try:
            archive.release_data(ctx.data_root / ctx.application / "data", state.operation_id, name)
        except BackupError as error:
            raise _failure(error) from None
        state = archive.advance(ctx.root, state, released={**state.released, name: "deleted"})
    if not ctx.require_custody:
        _stop_managers(ctx)
    state = archive.advance(ctx.root, state, "released")
    _audit(ctx, state, "ok", images_kept=kept)
    return state, kept


def _require_manifest_binding(ctx: Context, state, manifest) -> None:
    if (
        manifest.application != ctx.application
        or manifest.operation_id != state.operation_id
        or manifest.applied_revision != ctx.expected_revision
        or manifest.desired_revision != ctx.desired_revision
        or manifest.server != ctx.server
        or manifest.services.keys() != ctx.specs.keys()
    ):
        raise _failure(BackupError("binding_changed"))
    for service in _service_inputs(ctx):
        item = manifest.services[service.service]
        cache_name = archive.image_cache_name(service.image, service.image_tag)
        if (
            item.user != service.user
            or item.unit != service.unit
            or item.image != service.image
            or item.image_tag != service.image_tag
            or item.data_source != (str(service.data_source) if service.data_source else None)
            or (item.image_copy is not None and item.image_copy.cache_name != cache_name)
            or item.data is not None
            and (
                item.data.binding.image != service.image
                or item.data.binding.source_revision != service.source_revision
            )
        ):
            raise _failure(BackupError("binding_changed"))
        if item.identity.model_dump(mode="json") != service.identity:
            raise ExecutorError("policy_denied", "application identity changed")


def _result(ctx: Context, state, images_kept: list[str]) -> dict[str, Any]:
    return {
        "state": state.phase,
        "operation_id": state.operation_id,
        "archive_id": state.manifest_id,
        "archive": str(ctx.root / ctx.application / state.operation_id),
        "released": dict(state.released),
        "images_kept": images_kept,
    }


def _require_working_data(ctx: Context, state, manifest) -> None:
    for name, item in sorted(manifest.services.items()):
        if item.data is None or state.released.get(name) == "deleted":
            continue
        source = ctx.data_root / ctx.application / "data" / name
        if state.released.get(name) == "moved":
            try:
                source.lstat()
            except FileNotFoundError:
                # An earlier attempt already renamed the tree after verifying it.
                continue
            except OSError:
                raise ExecutorError("unavailable", "working data is unavailable") from None
        if archive.source_intact(item, source, max_bytes=ctx.max_data_bytes):
            continue
        if state.phase == "verified":
            state = archive.advance(ctx.root, state, "cancelled", error_class="source_changed")
            _audit(ctx, state, "failed", error_class="source_changed")
        raise ExecutorError("conflict", "working data changed after it was archived")


def _drive(ctx: Context, state) -> dict[str, Any]:
    images_kept: list[str] = []
    if state.phase == "archiving":
        _observe_identities(ctx)
        _require_stopped(ctx)
        manifest = _build(ctx, state)
        state = archive.advance(ctx.root, state, "archived", manifest_id=manifest.id)
        _audit(ctx, state, "ok")
    if state.phase == "archived":
        manifest = _verified_manifest(ctx, state)
        if ctx.require_custody:
            _require_manifest_binding(ctx, state, manifest)
        state = archive.advance(ctx.root, state, "verified")
        _audit(ctx, state, "ok")
    if state.phase in ("verified", "releasing"):
        _observe_identities(ctx)
        _require_stopped(ctx)
        manifest = _verified_manifest(ctx, state)
        if ctx.require_custody:
            _require_manifest_binding(ctx, state, manifest)
        else:
            for name, item in manifest.services.items():
                if item.identity.model_dump(mode="json") != ctx.identities[name]:
                    raise ExecutorError("policy_denied", "application identity changed")
        if state.phase == "verified" or ctx.require_custody:
            _require_working_data(ctx, state, manifest)
        if ctx.host.kill_switch():
            raise ExecutorError("kill_switch", "application retirement is stopped")
        if ctx.require_custody:
            _observe_identities(ctx)
            _require_manifest_binding(ctx, state, manifest)
            ctx.require_custody()
        state, images_kept = _release(ctx, state, manifest)
    return _result(ctx, state, images_kept)


def _boot_settled(ex, registry) -> bool:
    """The boot unit finished, or it is absent because no application service starts at boot.

    The accepted all-disabled deployment removes `steward-applications.service`; that is not
    an unfinished boot. A missing unit counts only when every registered service is disabled.
    """
    if ex._operator_group_boot_ready():
        return True
    if ex.host.system_unit(boot.BOOT_UNIT).get("load") != "not-found":
        return False
    try:
        applications = registry["applications"]
        return not any(
            spec.get("deploy")
            for application in applications.values()
            for spec in application["services"].values()
        )
    except (KeyError, TypeError, AttributeError):
        return False


def _guarded_quiesce(ctx: Context, group, *, may_stop: bool) -> None:
    bindings = {
        name: boot.Binding(ctx.application, name, "separate", ctx.identities[name])
        for name in group["stop_order"]
    }
    try:
        running = boot._retirement_observations(ctx.host, bindings, group["desired_running"])
        for name, binding in bindings.items():
            if not running[name]:
                continue
            if not may_stop:
                raise ExecutorError("conflict", "an archived application service is running")
            if ctx.host.kill_switch():
                raise ExecutorError("kill_switch", "application retirement is stopped")
            boot.verify_stop_identity(binding)
            boot.assert_authority(ctx.host, binding)
            boot.require(
                ctx.host.set_user_unit(binding.user, binding.unit, running=False)
                and not boot.observe_projected_target(ctx.host, binding, require_quiescent=True),
                "application unit failed to stop",
            )
    except ExecutorError:
        raise
    except boot.EVIDENCE_ERRORS as error:
        raise ExecutorError("policy_denied", "invalid retirement boot authority") from error
    _require_stopped(ctx)
    _stop_managers(ctx)


def _guarded_drive(ctx: Context, group, *, boot_ready: bool) -> dict[str, Any]:
    with archive.archive_lock(ctx.root, ctx.application, create=True):
        state = archive.active_operation(ctx.root, ctx.application)
        _require_archive_revisions(state, ctx.expected_revision, ctx.desired_revision)
        _observe_identities(ctx)
        _service_inputs(ctx)
        if state is not None and state.phase == "released":
            manifest = _verified_manifest(ctx, state)
            _require_manifest_binding(ctx, state, manifest)
            _require_stopped(ctx)
            return {
                **_result(
                    ctx,
                    state,
                    sorted(
                        name for name, item in manifest.services.items() if item.image_copy is None
                    ),
                ),
                "changed": False,
            }
        _guarded_quiesce(
            ctx, group, may_stop=boot_ready and (state is None or state.phase == "archiving")
        )
        if state is not None and state.phase == "archiving":
            archive.discard_unverified(ctx.root, state, "interrupted")
            state = None
        if state is None:
            state = archive.start_operation(
                ctx.root,
                ctx.application,
                uuid.uuid4().hex,
                applied_revision=ctx.expected_revision,
                desired_revision=ctx.desired_revision,
            )
            _audit(ctx, state, "started")
        return {**_drive(ctx, state), "changed": True}


def retire_guarded_application(
    ex,
    registry: dict[str, Any],
    candidate: Candidate,
    desired_revision: str,
    require_custody: Callable[[], None],
) -> dict[str, Any]:
    """Retire an exact site removal under the caller's deployment and runtime locks."""
    from . import server as srv

    if ex.host.kill_switch():
        raise ExecutorError("kill_switch", "application retirement is stopped")
    application = candidate.application
    if not callable(require_custody):
        raise ExecutorError("policy_denied", "retirement requires deployment custody")
    try:
        expected_revision = registry["config_revision"]
        entry = registry["applications"][application]
        current = classify(application, entry)
        if (
            current != candidate
            or current.isolation != "separate"
            or not all(spec["manage"] for spec in entry["services"].values())
            or not boot.is_digest(desired_revision)
            or expected_revision == desired_revision
        ):
            raise ValueError
        group = derive_group_plan(
            registry,
            application,
            current.services[0],
            expected_revision=expected_revision,
            scope="application",
        )
        backup = Backup.model_validate(registry.get("backup", {}))
        server = registry["server_name"]
    except (ValueError, KeyError, TypeError):
        raise ExecutorError("policy_denied", "invalid guarded application retirement") from None

    with ex.target_locks(group["lock_targets"]):
        try:
            if srv.load_registry(ex.registry_path) != registry:
                raise ExecutorError("conflict", "registry changed while locking")
            checkpoint = ex.group_checkpoint(application)
            workflow = ex.group_capture_workflow(application)
        except (OSError, ValueError):
            raise ExecutorError("unavailable", "application group state is inconsistent") from None
        if (
            checkpoint is not None and checkpoint.phase not in ("complete", "recovered")
        ) or workflow:
            raise ExecutorError("target_busy", "an application group operation is unfinished")
        require_guarded_eligibility(ex, registry, application, desired_revision)
        boot_ready = _boot_settled(ex, registry)
        if not boot_ready:
            # A deployment fence also inhibits ordinary startup after a reboot.
            # Exact custody can resume once boot is idle and every unit is down.
            unit = ex.host.system_unit(boot.BOOT_UNIT)
            if (unit.get("load"), unit.get("active"), unit.get("sub")) not in (
                ("loaded", "failed", "failed"),
                ("loaded", "inactive", "dead"),
                ("not-found", "inactive", "dead"),
            ):
                raise ExecutorError("unavailable", "application boot has not completed")
            require_custody()
        ctx = Context(
            ex=ex,
            application=application,
            registry=registry,
            specs=entry["services"],
            root=archive.ARCHIVE_ROOT,
            data_root=srv.APPLICATION_DATA_ROOT,
            cache=archive.IMAGE_CACHE,
            server=server,
            max_data_bytes=backup.max_mib * 1024 * 1024,
            read_identity=read_identity,
            expected_revision=expected_revision,
            desired_revision=desired_revision,
            require_custody=require_custody,
        )
        try:
            return _guarded_drive(ctx, group, boot_ready=boot_ready)
        except BackupError as error:
            raise _failure(error) from None


def retire_application(ex, params, *, identity_reader=None) -> dict[str, Any]:
    """Archive and release one removed application; safe to repeat after any interruption."""
    from . import server as srv

    if ex.host.kill_switch():
        raise ExecutorError("kill_switch", "application retirement is stopped")
    application = params.application
    root = archive.ARCHIVE_ROOT
    with ex.target_lock("deployment-execution"):
        try:
            registry = srv.load_registry(ex.registry_path)
        except (OSError, ValueError):
            raise ExecutorError("unavailable", "application registry is unavailable") from None
        if registry.get("config_revision") != params.expected_revision:
            raise ExecutorError("conflict", "active configuration changed")
        if ex.deployment_fence() is not None:
            raise ExecutorError("target_busy", "deployment fence is active")
        if not _boot_settled(ex, registry):
            raise ExecutorError("unavailable", "application boot has not completed")
        try:
            plan = plan_retirements(
                registry,
                {
                    "config_revision": params.desired_revision,
                    "applications": {name: {} for name in params.desired_applications},
                },
            )
        except RetirementPlanError:
            raise ExecutorError("policy_denied", "registries cannot be compared") from None
        candidate = next((c for c in plan.candidates if c.application == application), None)
        if candidate is None:
            raise ExecutorError(
                "policy_denied", "application is still declared or is not registered"
            )
        if not candidate.retirable:
            raise ExecutorError("policy_denied", f"retirement is blocked: {candidate.stage}")
        specs = registry["applications"][application]["services"]
        try:
            group = derive_group_plan(
                registry,
                application,
                sorted(specs)[0],
                expected_revision=params.expected_revision,
                scope="application",
            )
            policy = Backup.model_validate(registry.get("backup", {}))
            server = registry["server_name"]
        except (ValueError, KeyError, TypeError):
            raise ExecutorError("policy_denied", "application registration is invalid") from None
        try:
            checkpoint = ex.group_checkpoint(application)
            workflow = ex.group_capture_workflow(application)
        except ValueError:
            raise ExecutorError("unavailable", "application group state is inconsistent") from None
        if (
            checkpoint is not None and checkpoint.phase not in ("complete", "recovered")
        ) or workflow:
            raise ExecutorError("target_busy", "an application group operation is unfinished")
        with ex.target_locks(group["lock_targets"]):
            if srv.load_registry(ex.registry_path) != registry:
                raise ExecutorError("conflict", "registry changed while locking")
            ctx = Context(
                ex=ex,
                application=application,
                registry=registry,
                specs=specs,
                root=root,
                data_root=srv.APPLICATION_DATA_ROOT,
                cache=archive.IMAGE_CACHE,
                server=server,
                max_data_bytes=policy.max_mib * 1024 * 1024,
                read_identity=identity_reader or read_identity,
                expected_revision=params.expected_revision,
                desired_revision=params.desired_revision,
            )
            try:
                with archive.archive_lock(root, application, create=True):
                    state = archive.active_operation(root, application)
                    if state is not None and state.phase == "archiving":
                        # An interrupted build never verified: its partial output is not an archive.
                        archive.discard_unverified(root, state, "interrupted")
                        state = None
                    if state is None:
                        # Refuse before any journal entry exists when the host is not ready.
                        _observe_identities(ctx)
                        _require_stopped(ctx)
                        state = archive.start_operation(
                            root,
                            application,
                            uuid.uuid4().hex,
                            applied_revision=params.expected_revision,
                            desired_revision=params.desired_revision,
                        )
                        _audit(ctx, state, "started")
                    elif (state.applied_revision, state.desired_revision) != (
                        params.expected_revision,
                        params.desired_revision,
                    ):
                        raise ExecutorError(
                            "conflict", "an unfinished retirement is bound to other revisions"
                        )
                    if state.phase == "released":
                        return {
                            "state": "released",
                            "operation_id": state.operation_id,
                            "archive_id": state.manifest_id,
                            "archive": str(root / application / state.operation_id),
                            "released": dict(state.released),
                            "images_kept": [],
                        }
                    return _drive(ctx, state)
            except BackupError as error:
                raise _failure(error) from None


def retirement_status(ex, application: str) -> dict[str, Any]:
    """Read-only journal summary; unknown or unsafe archive state is an error."""
    if not (archive.ARCHIVE_ROOT / application).exists():
        return {"application": application, "operations": [], "active": None}
    try:
        states = archive.operations(archive.ARCHIVE_ROOT, application)
    except BackupError as error:
        raise _failure(error) from None
    summaries = [
        {
            "operation_id": item.operation_id,
            "phase": item.phase,
            "archive_id": item.manifest_id,
            "created_at": item.created_at,
            "updated_at": item.updated_at,
            "error_class": item.error_class,
            "released": dict(item.released),
        }
        for item in states
    ]
    active = next((item for item in summaries if item["phase"] not in archive.TERMINAL), None)
    return {
        "application": application,
        "stem": graph_identifier("a", application),
        "operations": summaries,
        "active": active,
    }
