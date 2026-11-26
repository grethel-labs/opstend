"""L05: RemediationAdapter contract and apply_verified_image through the executor.

Everything here uses a fake host and local temporary files: it proves the control
flow and the refusal cases, not the behavior of Podman, systemd or a registry on a
real host (see tests/integration/gates/m3_l05.md for that gate).
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from conftest import FakeHost
from steward.adapters.remediation import (
    HostImageRemediation,
    Paths,
    RemediationAdapter,
    RemediationError,
)
from steward.core import render
from steward.core.backups import Binding, FilesystemCapture
from steward.core.canonical import revision_id
from steward.core.config import UpdatePolicy, effective, parse_config
from steward.core.maintenance import DAYS
from steward.core.store import Store
from steward.core.update_evidence import policy_revision, sign_statement
from steward.executor import image_update
from steward.executor import server as executor_server
from update_support import (
    APPROVER,
    NEW_DIGEST,
    NEW_IMAGE,
    NOW,
    OLD_IMAGE,
    SIGNER,
    approval_statement,
    attestation_statement,
    contract_data,
)

ME = os.getuid()
OPERATOR = 0
OLD_ID = "sha256:" + "1" * 64
NEW_ID = "sha256:" + "2" * 64
OLD_TAG = render.image_tag("shop", OLD_IMAGE)
NEW_TAG = render.image_tag("shop", NEW_IMAGE)
APPROVAL_ID = "approval-0123456789"


class Crash(BaseException):
    """Simulates the executor process dying mid-apply (not caught by handle())."""


class FakeImageHost(FakeHost):
    """In-memory registry, root image store, service image store and one container."""

    def __init__(self, quadlet: Path, memory_mb: int, pids: int):
        super().__init__()
        self.quadlet = quadlet
        self.available = {OLD_IMAGE: OLD_ID, NEW_IMAGE: NEW_ID}
        self.local: dict[str, str] = {OLD_IMAGE: OLD_ID}
        self.tags: dict[str, str] = {OLD_TAG: OLD_ID}
        self.user_store: dict[str, str] = {OLD_TAG: OLD_ID}
        self.archives: dict[Path, str] = {}
        self.fail: set[str] = set()  # fetch load restart start unhealthy
        self.mismatch_identity = False
        self.container_info["HostConfig"]["Memory"] = memory_mb * 2**20
        self.container_info["HostConfig"]["PidsLimit"] = pids
        self.container_info["Image"] = OLD_ID
        self.container_info["State"] = {"Running": True}
        self.unhealthy_tags: set[str] = set()
        self.current_tag = OLD_TAG

    # image operations -----------------------------------------------------------------
    def image_fetch(self, ref):
        self.calls.append(("fetch", ref))
        if "fetch" in self.fail or ref not in self.available:
            return False, "registry unreachable"
        self.local[ref] = self.available[ref]
        return True, ""

    def configured_image_identity(self, image):
        identity = self.local.get(image)
        if identity is None:
            return None
        digest = image.rsplit("@", 1)[1]
        if self.mismatch_identity:
            digest = "sha256:" + "f" * 64
        return {"id": identity, "manifest_digest": digest}

    def image_tag(self, ref, tag):
        self.tags[tag] = self.local[ref]
        return True, ""

    def image_archive(self, tag, archive):
        archive.write_bytes(b"archive")
        self.archives[archive] = tag
        return True, ""

    def image_exists(self, user, tag):
        return tag in self.user_store

    def image_load(self, user, archive):
        self.calls.append(("load", user))
        if "load" in self.fail:
            return False, "load failed"
        tag = self.archives[archive]
        self.user_store[tag] = self.tags[tag]
        return True, ""

    def user_image_id(self, user, tag):
        return self.user_store.get(tag)

    def reload_user_manager(self, user):
        self.calls.append(("reload", user))
        return True

    # runtime --------------------------------------------------------------------------
    def restart_user_unit(self, user, unit):
        text = self.quadlet.read_text()
        tag = re.search(r"^Image=(.+)$", text, re.M).group(1)
        self.calls.append(("restart", tag))
        if os.environ.get("CRASH_ON") == tag:
            raise Crash
        if "restart" in self.fail and tag == NEW_TAG:
            return False, "unit failed"
        self.current_tag = tag
        self.container_info["Image"] = self.user_store[tag]
        self.container_info["State"] = {"Running": not ("start" in self.fail and tag == NEW_TAG)}
        self.health_ok = tag not in self.unhealthy_tags
        return True, ""


def build_world(tmp_path, raw_config, monkeypatch, profile="observe"):
    raw = yaml.safe_load(yaml.safe_dump(raw_config))
    raw["projects"] = [
        {
            "id": "shop",
            "image": OLD_IMAGE,
            "source_revision": "git:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "host_port": 20100,
            "update": contract_data(),
            "maintenance": {"allow_backup_pause": True},
        }
    ]
    raw["automation"] = {"profile": profile}
    # The weekly window starts a few minutes before the fake "now".
    opened = datetime.fromtimestamp(NOW - 300, UTC)
    raw["maintenance"] = {"weekly_window": f"{DAYS[opened.weekday()]} {opened:%H:%M} UTC"}
    cfg = parse_config(raw, allow_unavailable=True)
    registry = render.render_registry(cfg)
    registry["peers"] = {"controller": ME, "api": 4242}

    root = tmp_path / "host"
    for name in ("config", "images", "state"):
        (root / name).mkdir(parents=True)
    paths = Paths(
        registry=root / "executor.json",
        desired=root / "config" / "desired.json",
        quadlet_root=root / "quadlet",
        archive_dir=root / "images",
    )
    paths.registry.write_text(
        json.dumps(registry, indent=4, sort_keys=True, separators=(",", ": ")) + "\n"
    )
    paths.registry.chmod(0o600)
    paths.desired.write_text(json.dumps(effective(cfg), sort_keys=True) + "\n")
    paths.desired.chmod(0o640)
    quadlet = paths.quadlet_root / str(ME) / "shop.container"
    quadlet.parent.mkdir(parents=True)
    quadlet.write_text(render.render_project_quadlet(cfg.projects[0], "/opt/steward/releases/x"))
    quadlet.chmod(0o644)

    host = FakeImageHost(
        quadlet, cfg.projects[0].resources.memory_mb, cfg.projects[0].resources.pids
    )
    ex = executor_server.Executor(
        registry_path=str(paths.registry),
        state_dir=str(root / "state"),
        audit_path=str(root / "audit.jsonl"),
        lock_dir=str(root / "locks"),
        host=host,
    )
    ex.remediation = HostImageRemediation(host, paths)
    clock = {"t": 0.0}
    monkeypatch.setattr(image_update, "_now", lambda: NOW)
    monkeypatch.setattr(image_update, "_monotonic", lambda: clock["t"])
    monkeypatch.setattr(image_update, "_sleep", lambda s: clock.__setitem__("t", clock["t"] + s))

    class World:
        pass

    w = World()
    w.ex, w.host, w.paths, w.cfg, w.quadlet, w.clock, w.root = (
        ex,
        host,
        paths,
        cfg,
        quadlet,
        clock,
        root,
    )
    w.contract = UpdatePolicy.model_validate(contract_data())
    return w


@pytest.fixture
def world(tmp_path, raw_config, monkeypatch):
    return build_world(tmp_path, raw_config, monkeypatch)


@pytest.fixture
def patch_world(tmp_path, raw_config, monkeypatch):
    """Registry rendered with the patch profile: only reachable in tests."""
    w = build_world(tmp_path, raw_config, monkeypatch, "patch")
    write_capture(w, completed_at=NOW - 120)
    assert validate(w)["ok"]
    return w


def registry_of(w) -> dict:
    return json.loads(w.paths.registry.read_text())


def evidence(w, *, attestation_over=None, approval_over=None):
    att = attestation_statement(**(attestation_over or {}))
    bound = {
        "approval_id": APPROVAL_ID,
        "server": "my-server",
        "config_revision": registry_of(w)["config_revision"],
        **(approval_over or {}),
    }
    app = approval_statement(att, w.contract, **bound)
    return (
        sign_statement(SIGNER, "ci-signer", att),
        sign_statement(APPROVER, "ops-approver", app),
    )


def req(action, params, **overrides):
    body = {
        "v": 1,
        "action": action,
        "params": params,
        "request_id": uuid.uuid4().hex,
        "expires_at": time.time() + 60,
    }
    body.update(overrides)
    return json.dumps(body).encode()


def call(w, action, params, uid=OPERATOR):
    return w.ex.handle(req(action, params), uid)


def validate(w, uid=OPERATOR, **kwargs):
    att, app = evidence(w, **kwargs)
    return call(
        w,
        "update_validate",
        {
            "project_id": "shop",
            "digest": "sha256:" + NEW_DIGEST,
            "attestation": att,
            "approval": app,
        },
        uid,
    )


def apply(w, uid=OPERATOR, approval_id=APPROVAL_ID, digest="sha256:" + NEW_DIGEST):
    return call(
        w,
        "apply_verified_image",
        {"project_id": "shop", "approval_id": approval_id, "digest": digest},
        uid,
    )


def write_capture(w, *, completed_at, registry=None):
    registry = registry or registry_of(w)
    spec = registry["projects"]["shop"]
    capture = FilesystemCapture(
        binding=Binding(
            server=registry["server_name"],
            project="shop",
            config_revision=registry["config_revision"],
            image=spec["image"],
            source_revision=spec["source_revision"],
        ),
        created_at=completed_at - 5,
        completed_at=completed_at,
        size=1,
        sha256="0" * 64,
        entries=0,
        data_bytes=0,
    )
    spool = Path(w.ex._db_path).parent / "captures" / "shop" / uuid.uuid4().hex
    spool.mkdir(parents=True)
    (spool / "manifest.json").write_text(capture.model_dump_json())


@pytest.fixture
def ready(world):
    """Validated approval and a fresh bound backup: only the apply is left."""
    write_capture(world, completed_at=NOW - 120)
    assert validate(world)["ok"]
    return world


def state_of(w):
    return w.ex.update_ledger.get(APPROVAL_ID)["state"]


# ---- adapter contract ---------------------------------------------------------------------


def test_adapter_implements_the_contract(world):
    adapter = world.ex.remediation
    assert isinstance(adapter, RemediationAdapter)
    assert adapter.version == 1 and adapter.capabilities == ("image.apply",)
    assert adapter.health() is True


def test_adapter_without_host_operations_is_unhealthy(world):
    class Bare:
        pass

    assert HostImageRemediation(Bare(), world.paths).health() is False
    assert not isinstance(object(), RemediationAdapter)


def plan_for(w):
    return w.ex.remediation.plan(
        registry_of(w), "shop", NEW_IMAGE, "git:0123456789abcdef0123456789abcdef01234567"
    )


def test_adapter_prepare_loads_the_exact_digest_for_the_service_user(world):
    plan = plan_for(world)
    assert world.ex.remediation.prepare(plan) == NEW_ID
    assert world.host.user_store[NEW_TAG] == NEW_ID
    archive = world.ex.remediation.archive_path(plan)
    assert archive.parent == world.paths.archive_dir and archive.suffix == ".tar"
    assert ("fetch", NEW_IMAGE) in world.host.calls


def test_adapter_refuses_an_image_that_does_not_match_its_digest(world):
    world.host.mismatch_identity = True
    with pytest.raises(RemediationError, match="does not match its digest"):
        world.ex.remediation.prepare(plan_for(world))
    assert NEW_TAG not in world.host.user_store


def test_adapter_refuses_failed_fetch_and_failed_load(world):
    world.host.fail.add("fetch")
    with pytest.raises(RemediationError, match="fetch failed"):
        world.ex.remediation.prepare(plan_for(world))
    world.host.fail = {"load"}
    with pytest.raises(RemediationError, match="load failed"):
        world.ex.remediation.prepare(plan_for(world))


def test_adapter_install_is_idempotent_in_both_directions(world):
    adapter, plan = world.ex.remediation, plan_for(world)
    before = world.paths.desired.read_text()
    adapter.install(plan, "new")
    adapter.install(plan, "new")
    assert json.loads(world.paths.desired.read_text())["projects"][0]["image"] == NEW_IMAGE
    assert revision_id(json.loads(world.paths.desired.read_text())) == plan.new_config_revision
    assert registry_of(world)["config_revision"] == plan.new_config_revision
    assert NEW_TAG in world.quadlet.read_text()
    adapter.install(plan, "old")
    assert world.paths.desired.read_text() == before
    assert registry_of(world)["config_revision"] == plan.old_config_revision
    assert OLD_TAG in world.quadlet.read_text()


def test_adapter_install_preserves_registry_peers_and_modes(world):
    adapter, plan = world.ex.remediation, plan_for(world)
    adapter.install(plan, "new")
    assert registry_of(world)["peers"] == {"controller": ME, "api": 4242}
    assert world.paths.registry.stat().st_mode & 0o777 == 0o600
    assert world.paths.desired.stat().st_mode & 0o777 == 0o640
    # Re-rendering from the new applied configuration reproduces the same bytes,
    # so a later deployment of that configuration changes nothing.
    body = json.loads(world.paths.desired.read_text())
    assert (
        world.paths.desired.read_text()
        == json.dumps(effective(parse_config(body, allow_unavailable=True)), sort_keys=True) + "\n"
    )
    again = {
        **render.render_registry(parse_config(body, allow_unavailable=True)),
        "peers": registry_of(world)["peers"],
    }
    assert registry_of(world) == again


@pytest.mark.parametrize("drift", ["desired", "registry", "quadlet"])
def test_adapter_refuses_drifted_files(world, drift):
    adapter, plan = world.ex.remediation, plan_for(world)
    if drift == "desired":
        body = json.loads(world.paths.desired.read_text())
        body["projects"][0]["host_port"] = 20101
        world.paths.desired.write_text(json.dumps(body, sort_keys=True) + "\n")
    elif drift == "registry":
        registry = registry_of(world)
        registry["reserved_memory_mb"] += 1
        world.paths.registry.write_text(json.dumps(registry))
    else:
        world.quadlet.write_text(world.quadlet.read_text() + "# local edit\n")
    with pytest.raises(RemediationError) as caught:
        adapter.install(plan, "new")
    assert caught.value.error_class == "conflict"
    assert NEW_TAG not in world.quadlet.read_text()


def test_adapter_plan_refuses_registry_desired_mismatch_and_bundles(world):
    registry = registry_of(world)
    registry["config_revision"] = "9" * 64
    with pytest.raises(RemediationError, match="differs from the registry"):
        world.ex.remediation.plan(registry, "shop", NEW_IMAGE, "git:abc")
    with pytest.raises(RemediationError, match="not registered"):
        world.ex.remediation.plan(registry_of(world), "other", NEW_IMAGE, "git:abc")
    body = json.loads(world.paths.desired.read_text())
    body["projects"][0]["bundle"] = "sample-notes"
    world.paths.desired.write_text(json.dumps(body, sort_keys=True) + "\n")
    registry = registry_of(world)
    registry["config_revision"] = revision_id(body)
    with pytest.raises(RemediationError, match="bundled"):
        world.ex.remediation.plan(registry, "shop", NEW_IMAGE, "git:abc")


# ---- evidence submission ----------------------------------------------------------------------


def test_validate_records_evidence_and_is_idempotent(world):
    first = validate(world)
    assert first["ok"] and first["result"]["state"] == "validated" and not first["result"]["repeat"]
    assert validate(world)["result"]["repeat"] is True
    status = call(world, "update_status", {"project_id": "shop"})
    assert status["result"]["approvals"][0]["state"] == "validated"


def test_validate_refusals_are_policy_denials(world):
    for over, code in [
        ({"approval_over": {"expires_at": NOW - 1}}, "expired"),
        ({"approval_over": {"config_revision": "e" * 64}}, "policy_denied"),
        ({"attestation_over": {"version": "9.0"}}, "policy_denied"),
    ]:
        result = validate(world, **over)
        assert not result["ok"] and "update evidence rejected" in result["message"]
        assert result["error_class"] == code


def test_validate_and_apply_are_closed_to_other_roles(world):
    for uid in (4242, 4343, 31337):  # api, unregistered collector, unknown peer
        assert validate(world, uid)["error_class"] in ("forbidden_role", "unauthorized_peer")
        assert apply(world, uid)["error_class"] in ("forbidden_role", "unauthorized_peer")
    assert world.host.calls == []


@pytest.mark.parametrize(
    "params",
    [
        {"project_id": "shop", "approval_id": "short", "digest": "sha256:" + NEW_DIGEST},
        {"project_id": "../shop", "approval_id": APPROVAL_ID, "digest": "sha256:" + NEW_DIGEST},
        {"project_id": "shop", "approval_id": APPROVAL_ID, "digest": NEW_DIGEST},
        {
            "project_id": "shop",
            "approval_id": APPROVAL_ID,
            "digest": "sha256:" + NEW_DIGEST,
            "path": "/x",
        },
        {
            "project_id": "shop",
            "approval_id": APPROVAL_ID,
            "digest": "sha256:" + NEW_DIGEST,
            "image": "evil",
        },
        {
            "project_id": "shop; reboot",
            "approval_id": APPROVAL_ID,
            "digest": "sha256:" + NEW_DIGEST,
        },
    ],
)
def test_apply_parameters_are_bound_identifiers_only(world, params):
    assert call(world, "apply_verified_image", params)["error_class"] == "bad_request"
    assert world.host.calls == []


# ---- successful apply ---------------------------------------------------------------------------


def test_apply_installs_verifies_and_records_the_new_state(ready):
    w = ready
    result = apply(w)
    assert result["ok"], result
    out = result["result"]
    assert out["state"] == "applied" and out["image"] == NEW_IMAGE
    assert out["verified"]["image_verified"] and out["verified"]["running_image_id"] == NEW_ID
    body = json.loads(w.paths.desired.read_text())
    assert body["projects"][0]["image"] == NEW_IMAGE
    assert revision_id(body) == out["config_revision"] == registry_of(w)["config_revision"]
    assert state_of(w) == "applied"
    assert w.host.current_tag == NEW_TAG
    events = [r for r in w.ex.audit.read() if r["event"] == "update_apply"]
    assert [e["outcome"] for e in events] == ["started", "applied"]
    assert w.ex.audit.verify()[0]


def test_apply_by_controller_needs_patch_profile_which_stays_unavailable(ready):
    w = ready
    result = apply(w, ME)  # controller
    assert result["error_class"] == "policy_denied" and "patch profile" in result["message"]
    assert w.host.calls == [] and state_of(w) == "validated"
    from steward.core.config import UNAVAILABLE_FEATURES

    assert "automation.patch" in UNAVAILABLE_FEATURES


def test_automatic_apply_runs_only_when_the_profile_gate_is_open(patch_world):
    result = apply(patch_world, ME)
    assert result["ok"], result
    assert state_of(patch_world) == "applied"


def test_kill_switch_stops_automatic_apply_but_not_the_operator(patch_world):
    w = patch_world
    w.host.killed = True
    assert apply(w, ME)["error_class"] == "kill_switch"
    assert w.host.calls == [] and state_of(w) == "validated"
    assert apply(w, OPERATOR)["ok"]


def test_kill_switch_engaged_during_the_fetch_stops_before_install(patch_world):
    w = patch_world
    original = w.host.image_fetch

    def fetch(ref):
        result = original(ref)
        w.host.killed = True  # the operator stops automation while the image downloads
        return result

    w.host.image_fetch = fetch
    assert apply(w, ME)["error_class"] == "kill_switch"
    assert NEW_TAG not in w.quadlet.read_text() and state_of(w) == "failed"
    assert ("restart", NEW_TAG) not in w.host.calls


def test_automatic_apply_spends_the_hourly_budget(patch_world):
    w = patch_world
    for _ in range(image_update.UPDATE_BUDGET_PER_HOUR):
        w.ex.spend_budget("shop", "apply_verified_image", image_update.UPDATE_BUDGET_PER_HOUR)
    result = apply(w, ME)
    assert result["error_class"] == "budget_exhausted" and w.host.calls == []
    assert state_of(w) == "validated"


def test_target_lock_held_refuses_without_side_effects(ready):
    w = ready
    with w.ex.target_lock("project-shop"):
        result = apply(w)
    assert result["error_class"] == "target_busy" and w.host.calls == []
    with w.ex.target_lock("deployment-execution"):
        assert apply(w)["error_class"] == "target_busy"
    assert state_of(w) == "validated" and apply(w)["ok"]


# ---- refusals at execution time -----------------------------------------------------------------------


def test_replay_is_refused_after_success_and_after_failure(ready):
    w = ready
    assert apply(w)["ok"]
    again = apply(w)
    assert again["error_class"] == "replay"
    assert w.host.calls.count(("fetch", NEW_IMAGE)) == 1


def test_expired_approval_is_refused_at_execution_time(ready, monkeypatch):
    monkeypatch.setattr(image_update, "_now", lambda: NOW + 3601)
    # keep the window open so expiry is the reason
    result = apply(ready)
    assert result["error_class"] == "expired" and ready.host.calls == []


def test_unvalidated_unknown_and_mismatching_requests_are_refused(ready):
    w = ready
    assert apply(w, approval_id="approval-unknown-00001")["error_class"] == "policy_denied"
    assert apply(w, digest="sha256:" + "e" * 64)["error_class"] == "policy_denied"
    assert w.host.calls == []


def test_changed_configuration_revision_invalidates_the_approval(ready):
    w = ready
    registry = registry_of(w)
    registry["config_revision"] = "9" * 64
    w.paths.registry.write_text(json.dumps(registry))
    result = apply(w)
    assert result["error_class"] == "policy_denied" and "revision_mismatch" in result["message"]
    assert state_of(w) == "invalidated" and w.host.calls == []


def test_changed_applied_configuration_conflicts_before_any_change(ready):
    w = ready
    body = json.loads(w.paths.desired.read_text())
    body["projects"][0]["host_port"] = 20111
    w.paths.desired.write_text(json.dumps(body, sort_keys=True) + "\n")
    result = apply(w)
    assert result["error_class"] == "conflict" and w.host.calls == []
    assert NEW_TAG not in w.quadlet.read_text() and state_of(w) == "validated"


def test_missing_and_stale_backup_block_the_update(world):
    assert validate(world)["ok"]
    missing = apply(world)
    assert missing["error_class"] == "policy_denied" and "missing_backup" in missing["message"]
    write_capture(world, completed_at=NOW - 7200)
    stale = apply(world)
    assert "stale_backup" in stale["message"]
    write_capture(
        world, completed_at=NOW - 60, registry={**registry_of(world), "config_revision": "8" * 64}
    )
    # a capture bound to another revision is not evidence: the old one still decides
    assert "stale_backup" in apply(world)["message"]
    assert world.host.calls == []


def test_backup_is_not_required_without_workload_data(world):
    registry = registry_of(world)
    registry["projects"]["shop"]["has_data"] = False
    # keep the adapter consistent with the registry: render from a data-less config
    body = json.loads(world.paths.desired.read_text())
    body["projects"][0]["data_path"] = None
    world.paths.desired.write_text(json.dumps(body, sort_keys=True) + "\n")
    cfg = parse_config(body, allow_unavailable=True)
    registry = {**render.render_registry(cfg), "peers": registry["peers"]}
    world.paths.registry.write_text(
        json.dumps(registry, indent=4, sort_keys=True, separators=(",", ": ")) + "\n"
    )
    world.quadlet.write_text(
        render.render_project_quadlet(cfg.projects[0], "/opt/steward/releases/x")
    )
    assert validate(world)["ok"]
    assert apply(world)["ok"]


def test_window_is_checked_independently_of_evidence(ready, monkeypatch):
    w = ready
    # Approval and backup still fresh, but only minutes remain in the window.
    start = (NOW // 60) * 60 - 300
    monkeypatch.setattr(image_update, "_now", lambda: start + 3600 - 30)
    result = apply(w)
    assert result["error_class"] == "policy_denied" and "maintenance window" in result["message"]
    assert w.host.calls == []


def test_apply_without_a_configured_window_is_refused(ready):
    w = ready
    registry = registry_of(w)
    del registry["maintenance"]
    w.paths.registry.write_text(json.dumps(registry))
    result = apply(w)
    assert result["error_class"] == "policy_denied" and "window" in result["message"]


def test_unregistered_project_stopped_project_and_pending_backup_pause(ready):
    w = ready
    assert (
        call(
            w,
            "apply_verified_image",
            {"project_id": "ghost", "approval_id": APPROVAL_ID, "digest": "sha256:" + NEW_DIGEST},
        )["error_class"]
        == "policy_denied"
    )
    registry = registry_of(w)
    registry["projects"]["shop"]["deploy"] = False
    w.paths.registry.write_text(json.dumps(registry))
    assert apply(w)["error_class"] == "policy_denied"


# ---- failure and recovery ------------------------------------------------------------------------------------


def test_failed_prepare_changes_nothing_and_consumes_the_approval(ready):
    w = ready
    w.host.fail.add("fetch")
    result = apply(w)
    assert result["error_class"] == "execution_failed"
    assert state_of(w) == "failed"
    assert NEW_TAG not in w.quadlet.read_text()
    assert json.loads(w.paths.desired.read_text())["projects"][0]["image"] == OLD_IMAGE
    assert apply(w)["error_class"] == "replay"


def test_failed_start_restores_the_previous_image_and_reports_failure(ready):
    w = ready
    w.host.fail.add("start")
    result = apply(w)
    assert result["error_class"] == "execution_failed"
    assert "previous image restored" in result["message"]
    assert state_of(w) == "failed"
    row = w.ex.update_ledger.get(APPROVAL_ID)
    assert row["journal"]["reverted"] is True
    assert json.loads(w.paths.desired.read_text())["projects"][0]["image"] == OLD_IMAGE
    assert OLD_TAG in w.quadlet.read_text() and w.host.current_tag == OLD_TAG
    assert registry_of(w)["projects"]["shop"]["image"] == OLD_IMAGE
    assert not [e for e in w.ex.audit.read() if e.get("outcome") == "applied"]


def test_unhealthy_new_image_is_not_success(ready):
    w = ready
    w.host.unhealthy_tags.add(NEW_TAG)
    result = apply(w)
    assert result["error_class"] == "execution_failed" and "health" in result["message"]
    assert w.host.current_tag == OLD_TAG and state_of(w) == "failed"


def test_isolation_violation_after_restart_is_not_success(ready):
    w = ready
    original = w.host.restart_user_unit

    def restart(user, unit):
        ok = original(user, unit)
        if w.host.current_tag == NEW_TAG:
            w.host.container_info["HostConfig"]["Privileged"] = True
        else:
            w.host.container_info["HostConfig"]["Privileged"] = False
        return ok

    w.host.restart_user_unit = restart
    result = apply(w)
    assert "previous image restored" in result["message"]
    assert w.host.current_tag == OLD_TAG


def test_wrong_running_image_is_not_success(ready):
    w = ready
    original = w.host.restart_user_unit

    def restart(user, unit):
        ok = original(user, unit)
        if w.host.current_tag == NEW_TAG:
            w.host.container_info["Image"] = OLD_ID  # unit started something else
        return ok

    w.host.restart_user_unit = restart
    result = apply(w)
    assert (
        "does not match the approved digest"
        in w.ex.update_ledger.get(APPROVAL_ID)["journal"]["reason"]
    )
    assert result["error_class"] == "execution_failed"


def test_failed_revert_is_reported_as_unrecovered(ready):
    w = ready
    w.host.fail.add("start")
    w.host.unhealthy_tags.add(OLD_TAG)
    result = apply(w)
    assert result["error_class"] == "execution_failed"
    assert "could not be restored" in result["message"]
    assert state_of(w) == "revert_failed"
    status = call(w, "update_status", {"project_id": "shop"})["result"]["approvals"][0]
    assert status["state"] == "revert_failed"


def test_interrupted_apply_is_completed_after_restart(ready, monkeypatch):
    w = ready
    monkeypatch.setenv("CRASH_ON", NEW_TAG)
    with pytest.raises(Crash):
        apply(w)
    monkeypatch.delenv("CRASH_ON")
    assert state_of(w) == "applying"
    assert w.ex.update_ledger.get(APPROVAL_ID)["journal"]["phase"] == "installed"
    # a new executor process on the same state; the first one is gone
    ex2 = executor_server.Executor(
        registry_path=str(w.paths.registry),
        state_dir=str(w.root / "state"),
        audit_path=str(w.root / "audit.jsonl"),
        lock_dir=str(w.root / "locks"),
        host=w.host,
    )
    ex2.remediation = w.ex.remediation
    assert image_update.recover_updates(ex2, automatic=False) == [f"{APPROVAL_ID}:applied"]
    assert w.host.current_tag == NEW_TAG
    assert json.loads(w.paths.desired.read_text())["projects"][0]["image"] == NEW_IMAGE
    assert ex2.update_ledger.get(APPROVAL_ID)["state"] == "applied"


def test_interrupted_apply_that_cannot_verify_is_reverted(ready, monkeypatch):
    w = ready
    monkeypatch.setenv("CRASH_ON", NEW_TAG)
    with pytest.raises(Crash):
        apply(w)
    monkeypatch.delenv("CRASH_ON")
    w.host.unhealthy_tags.add(NEW_TAG)
    assert image_update.recover_updates(w.ex, automatic=False) == [f"{APPROVAL_ID}:failed"]
    assert w.host.current_tag == OLD_TAG
    assert json.loads(w.paths.desired.read_text())["projects"][0]["image"] == OLD_IMAGE


def test_interrupted_before_installation_is_abandoned_not_repeated(ready, monkeypatch):
    w = ready
    original = w.host.image_load
    w.host.user_store.pop(NEW_TAG, None)

    def dying_load(user, archive):
        raise Crash

    w.host.image_load = dying_load
    with pytest.raises(Crash):
        apply(w)
    w.host.image_load = original
    assert image_update.recover_updates(w.ex, automatic=False) == [f"{APPROVAL_ID}:abandoned"]
    assert state_of(w) == "failed"
    assert NEW_TAG not in w.quadlet.read_text()
    assert apply(w)["error_class"] == "replay"


def test_automatic_recovery_respects_the_kill_switch(ready, monkeypatch):
    w = ready
    monkeypatch.setenv("CRASH_ON", NEW_TAG)
    with pytest.raises(Crash):
        apply(w)
    monkeypatch.delenv("CRASH_ON")
    w.host.killed = True
    assert image_update.recover_updates(w.ex, automatic=True) == []
    assert state_of(w) == "applying"


def test_stale_worker_is_recovered_before_the_next_update_starts(ready, monkeypatch):
    w = ready
    monkeypatch.setenv("CRASH_ON", NEW_TAG)
    with pytest.raises(Crash):
        apply(w)
    monkeypatch.delenv("CRASH_ON")
    # Dead worker holds no lock any more; its journal says applying. A second,
    # unrelated approval request must not run on top of that half-state.
    newer = "sha256:" + "c" * 64
    other = NEW_IMAGE.replace(NEW_DIGEST, "c" * 64)
    w.host.available[other] = "sha256:" + "3" * 64
    result = call(
        w,
        "apply_verified_image",
        {"project_id": "shop", "approval_id": "approval-other-0002", "digest": newer},
    )
    assert not result["ok"]
    assert state_of(w) == "applied"  # the interrupted update was completed first
    assert w.host.current_tag == NEW_TAG


def test_pending_ui_revision_survives_an_applied_image_change(ready, tmp_path):
    w = ready
    store = Store(tmp_path / "api.db")
    old_body = json.loads(w.paths.desired.read_text())
    applied = store.record_applied(old_body)
    ui_edit = json.loads(json.dumps(old_body))
    ui_edit["projects"][0]["resources"]["memory_mb"] = 512
    head = store.commit_revision(ui_edit, parent=applied, author="ui", source="ui")
    assert apply(w)["ok"]
    new_applied = store.record_applied(json.loads(w.paths.desired.read_text()))
    assert store.head() == head != new_applied  # the pending edit is neither lost nor applied
    assert store.applied() == new_applied
    # The pending edit still carries the old image: adopting it needs `config pull`
    # and a deliberate merge, never a silent downgrade.
    assert store.get_revision(head)["body"]["projects"][0]["image"] == OLD_IMAGE


def test_update_status_is_read_only_and_bounded(ready):
    result = call(ready, "update_status", {"project_id": "shop"}, ME)
    assert result["ok"] and result["result"]["approvals"][0]["approval_id"] == APPROVAL_ID
    assert call(ready, "update_status", {"project_id": "ghost"})["error_class"] == "policy_denied"
    assert call(ready, "update_status", {"project_id": "shop"}, 4343)["error_class"] in (
        "forbidden_role",
        "unauthorized_peer",
    )
    assert policy_revision(ready.contract)


def test_real_host_operations_use_fixed_argv_only(tmp_path):
    from steward.executor.host import Host

    seen = []

    class Recording(Host):
        def _run(self, argv, timeout=30):
            seen.append(("root", argv))
            return 0, ""

        def _as_user(self, user, argv, timeout=30):
            seen.append((user, argv))
            return 0, "sha256:" + "2" * 64

    host = Recording()
    archive = tmp_path / "x.tar"
    ref = OLD_IMAGE
    assert host.image_fetch(ref)[0] and host.image_tag(ref, "localhost/steward/shop:t")[0]
    assert host.image_exists("stw-shop", "localhost/steward/shop:t") is True
    assert host.image_load("stw-shop", archive)[0]
    assert host.user_image_id("stw-shop", "localhost/steward/shop:t").startswith("sha256:")
    assert host.reload_user_manager("stw-shop")
    # the fake runner does not write the archive: that is a failure, never success
    assert host.image_archive("localhost/steward/shop:t", archive) == (
        False,
        "archive was not written",
    )
    for _who, argv in seen:
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        assert argv[0] in {"podman", "systemctl"} and "sh" not in argv and "-c" not in argv
    assert ["podman", "pull", "--quiet", ref] in [argv for _, argv in seen]


def test_interrupted_rollback_revokes_fixture_projection(ready, monkeypatch):
    from steward import application_boot as boot
    from steward.core import inference_deployment as inference

    w = ready
    monkeypatch.setenv("CRASH_ON", NEW_TAG)
    with pytest.raises(Crash):
        apply(w)
    monkeypatch.delenv("CRASH_ON")
    projection = w.paths.desired.parent.parent / "inference" / "selection.json"
    projection.parent.mkdir()
    projection.write_text("{}")
    monkeypatch.setattr(inference, "_projection_group", lambda directory: 1234)
    monkeypatch.setattr(boot, "protected", lambda path, mode, gid: path.open("rb"))
    w.host.unhealthy_tags.add(NEW_TAG)
    assert image_update.recover_updates(w.ex, automatic=False) == [f"{APPROVAL_ID}:failed"]
    assert not projection.exists()
