"""RemediationAdapter v1: apply one already-verified image to one registered project.

The adapter performs the host effects of an update; it never decides whether an
update is allowed. The executor validates evidence (core/update_evidence.py),
locks the target and journals each phase before calling it. Authority never
comes from here: parameters are bound identifiers derived from the root-owned
registry and a verified digest, there is no shell string and no caller path.

Desired state: the applied configuration (`desired.json`), the executor registry
and the Quadlet unit move together to the new image, so the next deployment
(after `config pull`) keeps it and a repeat run changes nothing. Every file must
equal either its previous or its new content before it is written; anything else
is a conflict and nothing is changed. `install` is idempotent in both directions
so an interrupted apply can be completed or reverted after a process death.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from ..core.canonical import revision_id
from ..core.config import effective, parse_config
from ..core.images import image_id
from ..core.render import image_tag, render_project_quadlet, render_registry

Target = Literal["new", "old"]


class RemediationError(Exception):
    """`error_class` is one of: conflict, policy_denied, execution_failed, unavailable."""

    def __init__(self, error_class: str, message: str):
        super().__init__(message)
        self.error_class = error_class
        self.message = message[:300]


@dataclass(frozen=True)
class Paths:
    registry: Path = Path("/etc/steward/executor.json")
    desired: Path = Path("/etc/steward/config/desired.json")
    quadlet_root: Path = Path("/etc/containers/systemd/users")
    archive_dir: Path = Path("/var/lib/steward/images")


@dataclass(frozen=True)
class ApplyPlan:
    project: str
    user: str
    unit: str
    container: str
    old_image: str
    new_image: str
    old_source_revision: str
    new_source_revision: str
    old_config_revision: str
    new_config_revision: str

    @property
    def tag(self) -> str:
        return image_tag(self.project, self.new_image)

    @property
    def digest(self) -> str:
        return self.new_image.rsplit("@", 1)[1]

    def reversed(self) -> ApplyPlan:
        """The plan that returns from the new state to the old one (rollback)."""
        return ApplyPlan(
            project=self.project,
            user=self.user,
            unit=self.unit,
            container=self.container,
            old_image=self.new_image,
            new_image=self.old_image,
            old_source_revision=self.new_source_revision,
            new_source_revision=self.old_source_revision,
            old_config_revision=self.new_config_revision,
            new_config_revision=self.old_config_revision,
        )

    def journal(self) -> dict[str, str]:
        return {
            "old_image": self.old_image,
            "new_image": self.new_image,
            "old_source_revision": self.old_source_revision,
            "new_source_revision": self.new_source_revision,
            "old_config_revision": self.old_config_revision,
            "new_config_revision": self.new_config_revision,
        }


@dataclass(frozen=True)
class Observation:
    running: bool
    image_id: str | None
    container: dict[str, Any] | None


@runtime_checkable
class RemediationAdapter(Protocol):
    version: int
    capabilities: tuple[str, ...]

    def health(self) -> bool: ...

    def plan(
        self, registry: dict[str, Any], project: str, image: str, source_revision: str
    ) -> ApplyPlan: ...

    def resume_plan(self, project: str, journal: dict[str, Any]) -> ApplyPlan: ...

    def prepare(self, plan: ApplyPlan) -> str:
        """Fetch by digest, verify the identity and load it for the service user.

        Returns the local image ID the running container must report."""
        ...

    def present(self, plan: ApplyPlan) -> str | None:
        """The verified local image ID if the plan's image is already loaded for the
        service user (a rollback needs no registry then), otherwise None."""
        ...

    def install(self, plan: ApplyPlan, target: Target) -> None: ...

    def restart(self, plan: ApplyPlan) -> None: ...

    def observe(self, plan: ApplyPlan) -> Observation: ...


def _bodies(current: dict[str, Any], plan_fields: dict[str, str], project: str):
    """Old and new desired bodies: only this project's image and source differ."""

    def with_image(image: str, source: str) -> dict[str, Any]:
        body = json.loads(json.dumps(current))
        for entry in body["projects"]:
            if entry["id"] == project:
                entry["image"], entry["source_revision"] = image, source
                return body
        raise RemediationError("policy_denied", "project is not in the applied configuration")

    return (
        with_image(plan_fields["old_image"], plan_fields["old_source_revision"]),
        with_image(plan_fields["new_image"], plan_fields["new_source_revision"]),
    )


def _registry_for(body: dict[str, Any], peers: Any) -> dict[str, Any]:
    cfg = parse_config(body, allow_unavailable=True)
    if effective(cfg) != body:
        raise RemediationError("conflict", "applied configuration is not in canonical form")
    return {**render_registry(cfg), "peers": peers}


def _write_atomic(path: Path, text: str, *, mode: int, uid: int, gid: int) -> None:
    parent = path.parent
    fd, name = tempfile.mkstemp(dir=parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, mode)
        if (os.stat(name).st_uid, os.stat(name).st_gid) != (uid, gid):
            os.chown(name, uid, gid)
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _read_regular(path: Path, limit: int = 4 * 1024 * 1024) -> tuple[str, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_size > limit:
            raise RemediationError("conflict", f"{path.name} is unexpectedly large")
        with os.fdopen(os.dup(fd), encoding="utf-8") as handle:
            return handle.read(), info
    finally:
        os.close(fd)


class HostImageRemediation:
    """Applies a verified image with the fixed host operations of `executor/host.py`."""

    version = 1
    capabilities = ("image.apply",)
    REQUIRED = (
        "image_fetch",
        "image_tag",
        "image_archive",
        "image_exists",
        "image_load",
        "user_image_id",
        "reload_user_manager",
        "configured_image_identity",
        "restart_user_unit",
        "container",
        "service_user_uid",
    )

    def __init__(self, host: Any, paths: Paths | None = None):
        self.host = host
        self.paths = paths or Paths()

    def health(self) -> bool:
        return all(callable(getattr(self.host, name, None)) for name in self.REQUIRED)

    # ---- planning ----------------------------------------------------------------

    def plan(
        self, registry: dict[str, Any], project: str, image: str, source_revision: str
    ) -> ApplyPlan:
        spec = registry["projects"].get(project)
        if spec is None:
            raise RemediationError("policy_denied", "project is not registered")
        text, _ = _read_regular(self.paths.desired)
        current = json.loads(text)
        if revision_id(current) != registry["config_revision"]:
            raise RemediationError("conflict", "applied configuration differs from the registry")
        entry = next((p for p in current.get("projects", []) if p.get("id") == project), None)
        if entry is None or entry.get("image") != spec["image"]:
            raise RemediationError("conflict", "applied configuration does not match the registry")
        if entry.get("bundle"):
            raise RemediationError("policy_denied", "bundled workloads ship with the release")
        fields = {
            "old_image": spec["image"],
            "new_image": image,
            "old_source_revision": spec["source_revision"],
            "new_source_revision": source_revision,
        }
        _, new_body = _bodies(current, fields, project)
        on_disk = json.loads(_read_regular(self.paths.registry)[0])
        peers = on_disk.get("peers")
        if _registry_for(current, peers) != on_disk:
            raise RemediationError("conflict", "registry does not match the applied configuration")
        _registry_for(new_body, peers)  # the new state must be valid and canonical
        return ApplyPlan(
            project=project,
            user=spec["user"],
            unit=spec["unit"],
            container=spec["container"],
            old_config_revision=registry["config_revision"],
            new_config_revision=revision_id(new_body),
            **fields,
        )

    def resume_plan(self, project: str, journal: dict[str, Any]) -> ApplyPlan:
        registry = json.loads(_read_regular(self.paths.registry)[0])
        spec = registry["projects"].get(project)
        if spec is None:
            raise RemediationError("policy_denied", "project is not registered")
        return ApplyPlan(
            project=project,
            user=spec["user"],
            unit=spec["unit"],
            container=spec["container"],
            **{
                key: journal[key]
                for key in (
                    "old_image",
                    "new_image",
                    "old_source_revision",
                    "new_source_revision",
                    "old_config_revision",
                    "new_config_revision",
                )
            },
        )

    # ---- fetch and load ------------------------------------------------------------

    def archive_path(self, plan: ApplyPlan) -> Path:
        # Same naming as the deployment role: sha256 of the full image reference.
        name = hashlib.sha256(plan.new_image.encode()).hexdigest()
        return self.paths.archive_dir / f"{name}.tar"

    def prepare(self, plan: ApplyPlan) -> str:
        ok, detail = self.host.image_fetch(plan.new_image)
        if not ok:
            raise RemediationError("execution_failed", f"image fetch failed: {detail}")
        identity = self.host.configured_image_identity(plan.new_image)
        expected = image_id((identity or {}).get("id"))
        if not expected or (identity or {}).get("manifest_digest") != plan.digest:
            raise RemediationError("execution_failed", "fetched image does not match its digest")
        ok, detail = self.host.image_tag(plan.new_image, plan.tag)
        if not ok:
            raise RemediationError("execution_failed", f"image tag failed: {detail}")
        archive = self.archive_path(plan)
        ok, detail = self.host.image_archive(plan.tag, archive)
        if not ok:
            raise RemediationError("execution_failed", f"image archive failed: {detail}")
        present = self.host.image_exists(plan.user, plan.tag)
        if present is None:
            raise RemediationError("unavailable", "service image store state is not known")
        if not present:
            ok, detail = self.host.image_load(plan.user, archive)
            if not ok:
                raise RemediationError("execution_failed", f"image load failed: {detail}")
        if image_id(self.host.user_image_id(plan.user, plan.tag)) != expected:
            raise RemediationError("execution_failed", "service image does not match the digest")
        return expected

    def present(self, plan: ApplyPlan) -> str | None:
        identity = self.host.configured_image_identity(plan.new_image)
        expected = image_id((identity or {}).get("id"))
        if not expected or (identity or {}).get("manifest_digest") != plan.digest:
            return None
        if image_id(self.host.user_image_id(plan.user, plan.tag)) != expected:
            return None
        return expected

    # ---- desired state -------------------------------------------------------------

    def install(self, plan: ApplyPlan, target: Target) -> None:
        from ..core.inference_deployment import revoke_for_desired

        desired_text, desired_info = _read_regular(self.paths.desired)
        current = json.loads(desired_text)
        old_body, new_body = _bodies(current, plan.journal(), plan.project)
        if revision_id(current) not in (plan.old_config_revision, plan.new_config_revision):
            raise RemediationError("conflict", "applied configuration changed during the update")
        registry_text, registry_info = _read_regular(self.paths.registry)
        registry = json.loads(registry_text)
        peers = registry.get("peers")
        states = {
            "old": (old_body, _registry_for(old_body, peers)),
            "new": (new_body, _registry_for(new_body, peers)),
        }
        if registry not in (states["old"][1], states["new"][1]):
            raise RemediationError("conflict", "registry changed during the update")
        want_body, want_registry = states[target]

        uid = self.host.service_user_uid(plan.user)
        if uid is None:
            raise RemediationError("unavailable", "service user is not known")
        quadlet = self.paths.quadlet_root / str(uid) / f"{plan.project}.container"
        release_dir = f"/opt/steward/releases/{registry['release']}"

        def unit_text(body: dict[str, Any]) -> str:
            cfg = parse_config(body, allow_unavailable=True)
            project = next(p for p in cfg.projects if p.id == plan.project)
            return render_project_quadlet(project, release_dir)

        quadlet_text, quadlet_info = _read_regular(quadlet)
        if quadlet_text not in (unit_text(old_body), unit_text(new_body)):
            raise RemediationError("conflict", "unit file changed during the update")

        # Desired state first, unit last: a crash leaves files that are each old or
        # new, and the journal decides whether to finish or to revert.
        desired_out = json.dumps(want_body, sort_keys=True) + "\n"
        if desired_text != desired_out or registry != want_registry:
            try:
                revoke_for_desired(self.paths.desired)
            except (OSError, ValueError) as error:
                raise RemediationError(
                    "unavailable", "inference policy withdrawal failed"
                ) from error
        if desired_text != desired_out:
            _write_atomic(
                self.paths.desired,
                desired_out,
                mode=desired_info.st_mode & 0o7777,
                uid=desired_info.st_uid,
                gid=desired_info.st_gid,
            )
        registry_out = (
            json.dumps(want_registry, indent=4, sort_keys=True, separators=(",", ": ")) + "\n"
        )
        if registry != want_registry:
            _write_atomic(
                self.paths.registry,
                registry_out,
                mode=registry_info.st_mode & 0o7777,
                uid=registry_info.st_uid,
                gid=registry_info.st_gid,
            )
        unit_out = unit_text(want_body)
        if quadlet_text != unit_out:
            _write_atomic(
                quadlet,
                unit_out,
                mode=quadlet_info.st_mode & 0o7777,
                uid=quadlet_info.st_uid,
                gid=quadlet_info.st_gid,
            )

    def restart(self, plan: ApplyPlan) -> None:
        if not self.host.reload_user_manager(plan.user):
            raise RemediationError("execution_failed", "unit definitions could not be reloaded")
        ok, detail = self.host.restart_user_unit(plan.user, plan.unit)
        if not ok:
            raise RemediationError("execution_failed", detail or "restart failed")

    def observe(self, plan: ApplyPlan) -> Observation:
        info = self.host.container(plan.user, plan.container)
        if info is None:
            return Observation(False, None, None)
        return Observation(
            (info.get("State") or {}).get("Running") is True, image_id(info.get("Image")), info
        )
