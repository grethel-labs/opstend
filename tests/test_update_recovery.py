"""L06: recovery of a failed update, exact data restore and the operator `rollback`.

A fake host drives the real executor, the real ledger/journal and the real capture and
restore code on temporary directories. The fake "application" migrates its data file to
schema 2 when the new image starts and its old version cannot read schema 2 (it reports
unhealthy), so a rollback that returns only the image is visibly not a recovery.

This proves control flow, bindings and refusals; it does not prove Podman, systemd, UID
mapping or a real application readback (see tests/integration/gates/m3_l06.md).
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
from pathlib import Path

import pytest

import test_remediation as tr
from steward.core.backups import BackupError, Binding, FilesystemCapture, load_capture
from steward.core.config import Backup
from steward.core.store import Store
from steward.core.update_evidence import UpdateRejected
from steward.core.update_recovery import CaptureRef, capture_ref, recovery_mode
from steward.executor import data_restore, image_update, update_recovery
from steward.executor import server as executor_server
from update_support import NEW_DIGEST, NEW_IMAGE, OLD_IMAGE, contract_data

ORIGINAL = {
    "db.txt": b"schema=1\nrows=3\n",
    "files/a.bin": bytes(range(200)),
    "files/sub/b.txt": b"beta",
}
RESTORE = "restore_required"


class Crash(BaseException):
    """The executor process dies at this point."""


def snapshot(root: Path) -> dict[str, bytes]:
    out = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        out[relative] = path.read_bytes() if path.is_file() else b"<dir>"
    return out


def expected_tree() -> dict[str, bytes]:
    out = {}
    for name, content in ORIGINAL.items():
        parts = name.split("/")
        for index in range(1, len(parts)):
            out["/".join(parts[:index])] = b"<dir>"
        out[name] = content
    out["empty"] = b"<dir>"
    return dict(sorted(out.items()))


class RecoveryHost(tr.FakeImageHost):
    """Adds unit control and a tiny application with a data migration."""

    def __init__(self, quadlet, memory_mb, pids, data: Path):
        super().__init__(quadlet, memory_mb, pids)
        self.data = data
        self.units["shop.service"] = "active"
        self.migrates = True
        self.stop_fails = False
        self.not_quiescent = False
        self.fail_old_start = False

    def set_user_unit(self, user, unit, *, running):
        self.calls.append(("set", unit, running))
        if not running and self.stop_fails:
            return False
        self.units[unit] = "active" if running else "inactive"
        self.container_info["State"] = {"Running": running}
        return True

    def workload_quiescent(self, user, unit):
        return not self.not_quiescent and self.units.get(unit) != "active"

    def restart_user_unit(self, user, unit):
        ok, detail = super().restart_user_unit(user, unit)
        if not ok:
            return ok, detail
        self.units[unit] = "active"
        text = (self.data / "db.txt").read_text()
        if self.current_tag == tr.NEW_TAG and self.migrates:
            (self.data / "db.txt").write_text("schema=2\nrows=3\nmigrated-by=new\n")
        elif self.current_tag == tr.OLD_TAG and ("schema=2" in text or self.fail_old_start):
            self.health_ok = False  # the previous version cannot read migrated data
        return ok, detail


def build(
    tmp_path, raw_config, monkeypatch, migration, *, profile="observe", approve=True, contract=None
):
    data = tmp_path / "srv" / "shop" / "data"
    for name, content in ORIGINAL.items():
        path = data / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o600)
    (data / "empty").mkdir()
    data.chmod(0o700)
    monkeypatch.setattr(executor_server, "PROJECT_DATA_ROOT", tmp_path / "srv")
    monkeypatch.setattr(
        tr,
        "contract_data",
        lambda **o: contract_data(
            allowed_migrations=["none", "reversible", RESTORE], **(contract or {}), **o
        ),
    )
    monkeypatch.setattr(
        tr, "FakeImageHost", lambda quadlet, mem, pids: RecoveryHost(quadlet, mem, pids, data)
    )
    w = tr.build_world(tmp_path, raw_config, monkeypatch, profile)
    w.data = data
    w.migration = migration
    tr.write_capture(w, completed_at=tr.NOW - 120)
    if approve:
        assert tr.validate(w, attestation_over={"migration": migration})["ok"]
    return w


@pytest.fixture
def restore_world(tmp_path, raw_config, monkeypatch):
    return build(tmp_path, raw_config, monkeypatch, RESTORE)


@pytest.fixture
def plain_world(tmp_path, raw_config, monkeypatch):
    w = build(tmp_path, raw_config, monkeypatch, "none")
    w.host.migrates = False  # the new version keeps the data format
    return w


@pytest.fixture
def reversible_world(tmp_path, raw_config, monkeypatch):
    return build(tmp_path, raw_config, monkeypatch, "reversible")


def ledger(w):
    return w.ex.update_ledger


def journal(w):
    return ledger(w).get(tr.APPROVAL_ID)["journal"]


def state(w):
    return ledger(w).get(tr.APPROVAL_ID)["state"]


def spool(w) -> Path:
    return Path(w.ex._db_path).parent / "captures" / "shop"


def preserved(w) -> list[Path]:
    return sorted(w.data.parent.glob("data.preserved-*"))


def desired_image(w) -> str:
    return json.loads(w.paths.desired.read_text())["projects"][0]["image"]


def rollback(
    w, uid=tr.OPERATOR, *, ack=False, approval=tr.APPROVAL_ID, digest=None, project="shop"
):
    return tr.call(
        w,
        "rollback",
        {
            "project_id": project,
            "approval_id": approval,
            "digest": digest or "sha256:" + NEW_DIGEST,
            "acknowledge_data_restore": ack,
        },
        uid,
    )


@contextlib.contextmanager
def crash_before(w, phase):
    """The process dies right before this journal phase becomes durable."""
    original = ledger(w).journal

    def journal_(approval_id, **fields):
        if fields.get("phase") == phase:
            raise Crash
        return original(approval_id, **fields)

    ledger(w).journal = journal_
    try:
        yield
    finally:
        ledger(w).__dict__.pop("journal", None)


def recover(w):
    return image_update.recover_updates(w.ex, automatic=False)


def assert_original_state(w):
    """Previous image, previous desired revision, previous data, workload running."""
    assert desired_image(w) == OLD_IMAGE
    assert w.host.current_tag == tr.OLD_TAG
    assert tr.registry_of(w)["projects"]["shop"]["image"] == OLD_IMAGE
    assert snapshot(w.data) == expected_tree()
    assert w.host.units["shop.service"] == "active"


# ---- contract (pure) ----------------------------------------------------------------------


def test_recovery_modes_follow_the_declared_migration():
    assert recovery_mode("none", has_data=False, allow_backup_pause=False) == "image_only"
    assert recovery_mode("none", has_data=True, allow_backup_pause=True) == "image_only"
    assert (
        recovery_mode("reversible", has_data=True, allow_backup_pause=True) == "reversible_capture"
    )
    assert recovery_mode(RESTORE, has_data=True, allow_backup_pause=True) == RESTORE


@pytest.mark.parametrize(
    "kind,data,pause",
    [
        ("reversible", False, True),  # nothing registered that could be backed up
        ("reversible", True, False),  # the update-time capture needs the pause contract
        (RESTORE, False, True),
        (RESTORE, True, False),  # exact restore needs the backup pause contract
        ("unknown-kind", True, True),
    ],
)
def test_migrations_without_a_recovery_contract_are_refused(kind, data, pause):
    with pytest.raises(UpdateRejected) as caught:
        recovery_mode(kind, has_data=data, allow_backup_pause=pause)
    assert caught.value.code == "recovery_unavailable"


def test_capture_ref_binds_exact_identity_and_rejects_foreign_fields():
    binding = Binding(
        server="my-server",
        project="shop",
        config_revision="a" * 64,
        image=OLD_IMAGE,
        source_revision="git:x",
    )
    manifest = FilesystemCapture(
        binding=binding,
        created_at=1,
        completed_at=2,
        size=10,
        sha256="b" * 64,
        entries=1,
        data_bytes=1,
    )
    ref = capture_ref(manifest, "c" * 32)
    assert ref.capture_id == manifest.id
    with pytest.raises(ValueError):
        CaptureRef.model_validate({**ref.model_dump(), "path": "/etc"})


# ---- admission ------------------------------------------------------------------------------


def test_unrecoverable_migration_is_refused_before_any_change(tmp_path, raw_config, monkeypatch):
    w = build(tmp_path, raw_config, monkeypatch, RESTORE, approve=False)
    registry = tr.registry_of(w)
    # a project without registered data cannot declare a data migration
    body = json.loads(w.paths.desired.read_text())
    body["projects"][0]["data_path"] = None
    w.paths.desired.write_text(json.dumps(body, sort_keys=True) + "\n")
    from steward.core import render
    from steward.core.config import parse_config

    cfg = parse_config(body, allow_unavailable=True)
    w.paths.registry.write_text(
        json.dumps(
            {**render.render_registry(cfg), "peers": registry["peers"]},
            indent=4,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    )
    w.quadlet.write_text(render.render_project_quadlet(cfg.projects[0], "/opt/steward/releases/x"))
    assert tr.validate(w, attestation_over={"migration": RESTORE})["ok"]
    result = tr.apply(w)
    assert result["error_class"] == "policy_denied" and "recovery_unavailable" in result["message"]
    assert state(w) == "validated"  # nothing was claimed, the approval is not consumed
    assert w.host.calls == [] and desired_image(w) == OLD_IMAGE


def test_restore_capacity_is_checked_before_the_update_starts(restore_world, monkeypatch):
    w = restore_world
    for index in range(update_recovery.MAX_PRESERVED_TREES - 1):
        (w.data.parent / f"data.preserved-old{index}").mkdir()
    result = tr.apply(w)
    assert result["error_class"] == "unavailable" and "preserved" in result["message"]
    assert state(w) == "validated" and w.host.calls == []
    assert_original_state_files_only(w)


def assert_original_state_files_only(w):
    assert desired_image(w) == OLD_IMAGE and snapshot(w.data) == expected_tree()


def test_full_capture_spool_and_missing_space_refuse_the_update(restore_world, monkeypatch):
    w = restore_world
    for index in range(10):
        (spool(w) / f"{index:032x}").mkdir(exist_ok=True)
    assert tr.apply(w)["error_class"] == "unavailable"
    assert state(w) == "validated"
    for path in spool(w).iterdir():
        if not (path / "manifest.json").exists():
            shutil.rmtree(path)
    real = shutil.disk_usage
    monkeypatch.setattr(shutil, "disk_usage", lambda p: real(p)._replace(free=1024))
    result = tr.apply(w)
    assert result["error_class"] == "unavailable" and "free space" in result["message"]
    assert w.host.calls == []


def test_missing_backup_still_blocks_a_migrating_update(tmp_path, raw_config, monkeypatch):
    w = build(tmp_path, raw_config, monkeypatch, RESTORE, approve=False)
    for entry in spool(w).iterdir():
        shutil.rmtree(entry)
    assert tr.validate(w, attestation_over={"migration": RESTORE})["ok"]
    result = tr.apply(w)
    assert result["error_class"] == "policy_denied" and "missing_backup" in result["message"]
    assert w.host.calls == []


def test_wrong_and_expired_approval_are_denied_for_a_migrating_update(restore_world, monkeypatch):
    w = restore_world
    assert tr.apply(w, approval_id="approval-unknown-0001")["error_class"] == "policy_denied"
    assert tr.apply(w, digest="sha256:" + "e" * 64)["error_class"] == "policy_denied"
    monkeypatch.setattr(image_update, "_now", lambda: tr.NOW + 7200)
    assert tr.apply(w)["error_class"] == "expired"
    assert w.host.calls == [] and snapshot(w.data) == expected_tree()


# ---- exact capture and a successful migrating update ------------------------------------------


def test_restore_required_update_captures_the_stopped_workload_then_applies(restore_world):
    w = restore_world
    result = tr.apply(w)
    assert result["ok"], result
    calls = w.host.calls
    stop = calls.index(("set", "shop.service", False))
    assert stop < calls.index(("restart", tr.NEW_TAG))  # captured while stopped, then new image
    assert state(w) == "applied" and w.host.current_tag == tr.NEW_TAG
    assert (w.data / "db.txt").read_text().startswith("schema=2")
    row = journal(w)
    assert row["recovery_mode"] == RESTORE and row["migration"] == RESTORE
    ref = CaptureRef.model_validate(row["recovery_capture"])
    manifest = load_capture(spool(w) / ref.artifact)  # exact artifact, verified end to end
    assert manifest.id == ref.capture_id == row["capture_id"]
    assert manifest.binding.image == OLD_IMAGE
    assert manifest.binding.config_revision == row["old_config_revision"]
    assert manifest.entries == len(expected_tree())  # rehearsed restore left no workspace behind
    assert not list(w.data.parent.glob(".rehearse-*")) and not preserved(w)
    status = tr.call(w, "update_status", {"project_id": "shop"})["result"]["approvals"][0]
    assert status["recovery_mode"] == RESTORE and status["capture_id"] == ref.capture_id


def test_capture_failure_resumes_the_old_workload_and_changes_nothing(restore_world):
    w = restore_world
    w.host.not_quiescent = True
    result = tr.apply(w)
    assert result["error_class"] == "execution_failed" and "workload resumed" in result["message"]
    assert state(w) == "failed" and journal(w)["phase"] == "capture_failed"
    assert_original_state(w)
    assert not list(spool(w).glob("*/data.tar"))  # an incomplete capture is never kept
    assert tr.apply(w)["error_class"] == "replay"


def test_failed_restore_rehearsal_stops_before_the_image_changes(restore_world, monkeypatch):
    w = restore_world

    def rehearsal_fails(root, directory, manifest):
        raise BackupError("evidence_mismatch")

    monkeypatch.setattr(update_recovery, "_rehearse", rehearsal_fails)
    result = tr.apply(w)
    assert result["error_class"] == "execution_failed"
    assert state(w) == "failed" and ("restart", tr.NEW_TAG) not in w.host.calls
    assert_original_state(w)


def test_workload_that_cannot_be_stopped_is_not_captured(restore_world):
    w = restore_world
    w.host.stop_fails = True
    assert tr.apply(w)["error_class"] == "execution_failed"
    assert state(w) == "failed" and ("restart", tr.NEW_TAG) not in w.host.calls
    assert_original_state(w)


# ---- failed update recovers with the exact data -----------------------------------------------


def test_failed_health_restores_exact_data_and_keeps_the_migrated_tree(restore_world):
    w = restore_world
    w.host.unhealthy_tags.add(tr.NEW_TAG)
    result = tr.apply(w)
    assert (
        result["error_class"] == "execution_failed"
        and "previous image restored" in (result["message"])
    )
    assert state(w) == "failed" and journal(w)["reverted"] is True
    assert_original_state(w)  # readback: schema=1 data and the old image healthy again
    assert w.host.health_ok is True
    (kept,) = preserved(w)
    assert (kept / "db.txt").read_text().startswith("schema=2")  # nothing was lost
    assert journal(w)["preserved_data"] == kept.name and journal(w)["data_restore"] == "restored"
    assert tr.apply(w)["error_class"] == "replay"


def test_failed_start_restores_exact_data(restore_world):
    w = restore_world
    w.host.fail.add("restart")
    assert tr.apply(w)["error_class"] == "execution_failed"
    assert state(w) == "failed" and journal(w)["reverted"] is True
    assert_original_state(w)


def test_fake_application_cannot_read_migrated_data_with_the_old_image(restore_world):
    """Guard for the fixture: an image-only return after the migration is unhealthy."""
    w = restore_world
    assert tr.apply(w)["ok"]
    plan = w.ex.remediation.resume_plan("shop", journal(w)).reversed()
    w.ex.remediation.install(plan, "new")
    w.ex.remediation.restart(plan)
    assert w.host.current_tag == tr.OLD_TAG and w.host.health_ok is False


def test_damaged_capture_makes_the_failure_visible_and_does_not_touch_live_data(
    restore_world,
):
    w = restore_world
    w.host.unhealthy_tags.add(tr.NEW_TAG)
    original = w.host.restart_user_unit

    def corrupt_then_restart(user, unit):
        for tar in spool(w).glob("*/data.tar"):
            tar.write_bytes(b"damaged")
        return original(user, unit)

    w.host.restart_user_unit = corrupt_then_restart
    result = tr.apply(w)
    assert result["error_class"] == "execution_failed"
    assert "could not be restored" in result["message"]
    assert state(w) == "revert_failed"
    assert not preserved(w)  # the swap never started
    assert (w.data / "db.txt").read_text().startswith("schema=2")  # live tree untouched


def test_reversible_migration_takes_a_capture_but_reverts_the_image_only(
    reversible_world, monkeypatch
):
    w = reversible_world
    w.host.migrates = False  # old and new versions share the data format
    w.host.unhealthy_tags.add(tr.NEW_TAG)

    def no_rehearsal(*_args):
        raise AssertionError("a reversible update needs no restore rehearsal")

    monkeypatch.setattr(update_recovery, "_rehearse", no_rehearsal)
    assert tr.apply(w)["error_class"] == "execution_failed"
    assert state(w) == "failed"
    assert journal(w)["recovery_mode"] == "reversible_capture"
    assert (spool(w) / journal(w)["recovery_capture"]["artifact"] / "data.tar").exists()
    assert ("set", "shop.service", False) in w.host.calls  # stopped for the capture
    assert not preserved(w) and "data_restore" not in journal(w)  # no restore was needed
    assert_original_state(w)


def test_reversible_revert_falls_back_to_the_exact_capture(reversible_world):
    w = reversible_world  # the new image migrates; the old one cannot read the result
    w.host.unhealthy_tags.add(tr.NEW_TAG)
    assert tr.apply(w)["error_class"] == "execution_failed"
    assert state(w) == "failed" and journal(w)["data_restore"] == "restored"
    assert len(preserved(w)) == 1  # the migrated tree is kept, never deleted
    assert_original_state(w)


def test_reversible_rollback_is_image_only_unless_the_exact_fallback_is_acknowledged(
    tmp_path, raw_config, monkeypatch
):
    w = build(tmp_path, raw_config, monkeypatch, "reversible")
    w.host.migrates = False
    assert tr.apply(w)["ok"] and state(w) == "applied"
    assert journal(w)["recovery_mode"] == "reversible_capture"
    (w.data / "later.txt").write_text("written by the new version")
    assert rollback(w)["ok"] and state(w) == "rolled_back"
    assert (w.data / "later.txt").exists() and not preserved(w)  # image only: data stays live
    assert journal(w).get("rollback_exact") is None


def test_reversible_rollback_can_restore_the_exact_capture(tmp_path, raw_config, monkeypatch):
    w = build(tmp_path, raw_config, monkeypatch, "reversible")
    w.host.migrates = False
    assert tr.apply(w)["ok"]
    (w.data / "later.txt").write_text("written by the new version")
    assert rollback(w, ack=True)["ok"] and state(w) == "rolled_back"
    assert journal(w)["rollback_exact"] is True and journal(w)["data_restore"] == "restored"
    assert not (w.data / "later.txt").exists() and len(preserved(w)) == 1
    assert (w.data.parent / preserved(w)[0].name / "later.txt").exists()


# ---- interruption at every phase ---------------------------------------------------------------


@pytest.mark.parametrize(
    "phase,durable,outcome",
    [
        ("capturing", "prepared", "abandoned"),  # nothing happened yet
        ("captured", "capturing", "failed"),  # stopped, complete capture not journaled
        ("installing", "captured", "failed"),  # stopped, captured, nothing installed
        ("installed", "installing", "failed"),  # files written, nothing started
        ("restarted", "installed", "failed"),  # new image started and migrated
    ],
)
def test_process_death_in_every_phase_recovers_without_repeating_the_migration(
    restore_world, phase, durable, outcome
):
    w = restore_world
    with crash_before(w, phase), pytest.raises(Crash):
        tr.apply(w)
    assert state(w) == "applying" and journal(w)["phase"] == durable
    assert recover(w) == [f"{tr.APPROVAL_ID}:{outcome}"]
    assert_original_state(w)
    assert state(w) == "failed"
    assert tr.apply(w)["error_class"] == "replay"  # never run twice
    restarts = [c for c in w.host.calls if c == ("restart", tr.NEW_TAG)]
    assert len(restarts) <= 1  # the migrating image was started at most once


def test_process_death_during_verification_reverts_with_the_capture(restore_world, monkeypatch):
    w = restore_world

    def dies(*_args, **_kwargs):
        raise Crash

    original = image_update._verify
    monkeypatch.setattr(image_update, "_verify", dies)
    with pytest.raises(Crash):
        tr.apply(w)
    monkeypatch.setattr(image_update, "_verify", original)
    assert journal(w)["phase"] == "restarted"
    assert (w.data / "db.txt").read_text().startswith("schema=2")
    assert recover(w) == [f"{tr.APPROVAL_ID}:failed"]
    assert_original_state(w)
    assert len(preserved(w)) == 1


def test_process_death_during_the_revert_is_finished_without_a_second_restore(
    restore_world, monkeypatch
):
    w = restore_world
    w.host.unhealthy_tags.add(tr.NEW_TAG)
    adapter = w.ex.remediation
    original = adapter.install

    def install(plan, target):
        if target == "old":
            raise Crash
        return original(plan, target)

    adapter.install = install
    with pytest.raises(Crash):
        tr.apply(w)
    adapter.__dict__.pop("install", None)
    assert state(w) == "applying" and journal(w)["phase"] == "reverting"
    # data was already restored when the process died; new writes must survive recovery
    assert (w.data / "db.txt").read_bytes() == ORIGINAL["db.txt"]
    (w.data / "later.txt").write_text("written after the restore")
    assert recover(w) == [f"{tr.APPROVAL_ID}:failed"]
    assert (w.data / "later.txt").read_text() == "written after the restore"
    assert len(preserved(w)) == 1 and w.host.current_tag == tr.OLD_TAG


@pytest.mark.parametrize(
    "phase,outcome",
    [("installing", "failed"), ("installed", "failed"), ("restarted", "failed")],
)
def test_interrupted_reversible_migration_is_reverted_not_completed(
    reversible_world, phase, outcome
):
    w = reversible_world
    w.host.migrates = False
    with crash_before(w, phase), pytest.raises(Crash):
        tr.apply(w)
    assert recover(w) == [f"{tr.APPROVAL_ID}:{outcome}"]
    assert w.host.current_tag == tr.OLD_TAG and desired_image(w) == OLD_IMAGE
    assert not preserved(w) and snapshot(w.data) == expected_tree()


def test_interrupted_update_without_migration_still_completes_forward(plain_world):
    w = plain_world
    with crash_before(w, "restarted"), pytest.raises(Crash):
        tr.apply(w)
    assert recover(w) == [f"{tr.APPROVAL_ID}:applied"]
    assert desired_image(w) == NEW_IMAGE and w.host.current_tag == tr.NEW_TAG


# ---- restore primitive ---------------------------------------------------------------------------


def make_capture(w, tmp_path):
    from steward.core.filebackups import capture_files

    binding = Binding(
        server="my-server",
        project="shop",
        config_revision="a" * 64,
        image=OLD_IMAGE,
        source_revision="git:x",
    )
    destination = tmp_path / "cap"
    manifest = capture_files(w.data, destination, binding, is_quiescent=lambda: True)
    return destination, manifest


def test_restore_primitive_swaps_atomically_and_never_deletes(plain_world, tmp_path):
    w = plain_world
    destination, manifest = make_capture(w, tmp_path)
    (w.data / "db.txt").write_text("schema=2\n")
    (w.data / "extra.txt").write_text("newer")
    result = data_restore.restore_tree(
        w.data.parent, destination, manifest, token="tok1", service_uid=os.getuid()
    )
    assert result.state == "restored" and result.preserved == "data.preserved-tok1"
    assert snapshot(w.data) == expected_tree()
    assert (w.data.parent / "data.preserved-tok1" / "extra.txt").read_text() == "newer"
    assert not list(w.data.parent.glob(".restore-*"))
    assert w.data.stat().st_mode & 0o777 == 0o700 and w.data.stat().st_uid == os.getuid()
    # repeating it keeps what the restored application wrote since
    (w.data / "later.txt").write_text("kept")
    again = data_restore.restore_tree(
        w.data.parent, destination, manifest, token="tok1", service_uid=os.getuid()
    )
    assert again.state == "already_restored" and (w.data / "later.txt").exists()


def test_restore_primitive_finishes_a_swap_interrupted_between_the_renames(
    plain_world, tmp_path, monkeypatch
):
    w = plain_world
    destination, manifest = make_capture(w, tmp_path)
    (w.data / "db.txt").write_text("schema=2\n")
    real_rename, calls = os.rename, []

    def dying_rename(src, dst):
        calls.append(dst)
        if len(calls) == 2:  # live tree is already moved away, staging not yet in place
            raise Crash
        return real_rename(src, dst)

    monkeypatch.setattr(data_restore.os, "rename", dying_rename)
    with pytest.raises(Crash):
        data_restore.restore_tree(
            w.data.parent, destination, manifest, token="tok2", service_uid=os.getuid()
        )
    monkeypatch.setattr(data_restore.os, "rename", real_rename)
    assert not w.data.exists()
    result = data_restore.restore_tree(
        w.data.parent, destination, manifest, token="tok2", service_uid=os.getuid()
    )
    assert result.state == "finished" and snapshot(w.data) == expected_tree()
    assert (w.data.parent / "data.preserved-tok2" / "db.txt").read_text() == "schema=2\n"


def test_restore_primitive_refuses_foreign_owner_limit_and_damaged_archives(plain_world, tmp_path):
    w = plain_world
    destination, manifest = make_capture(w, tmp_path)
    root = w.data.parent
    with pytest.raises(BackupError) as caught:
        data_restore.restore_tree(
            root, destination, manifest, token="t3", service_uid=os.getuid() + 1
        )
    assert caught.value.error_class == "unsafe_owner"
    (destination / "data.tar").write_bytes(b"damaged")
    with pytest.raises(BackupError):
        data_restore.restore_tree(root, destination, manifest, token="t4", service_uid=os.getuid())
    assert snapshot(w.data) == expected_tree() and not list(root.glob(".restore-*"))
    assert not preserved(w)
    with pytest.raises(BackupError):
        data_restore.restore_tree(
            root, destination, manifest, token="../x", service_uid=os.getuid()
        )


# ---- rollback ----------------------------------------------------------------------------------


def test_rollback_returns_an_applied_update_to_the_previous_image(plain_world):
    w = plain_world
    assert tr.apply(w)["ok"]
    result = rollback(w)
    assert result["ok"], result
    body = result["result"]
    assert body["state"] == "rolled_back" and body["image"] == OLD_IMAGE
    assert body["verified"]["image_verified"] is True and body["verified"]["health"] == "healthy"
    assert state(w) == "rolled_back"
    assert w.host.current_tag == tr.OLD_TAG and desired_image(w) == OLD_IMAGE
    assert tr.registry_of(w)["config_revision"] == journal(w)["old_config_revision"]
    assert tr.OLD_TAG in w.quadlet.read_text()
    assert ("fetch", OLD_IMAGE) not in w.host.calls  # still loaded: no registry needed
    assert ("set", "shop.service", False) not in w.host.calls  # image only: data untouched
    assert snapshot(w.data) == expected_tree()
    assert [e for e in w.ex.audit.read() if e.get("outcome") == "rolled_back"]
    assert rollback(w)["error_class"] == "replay"
    assert tr.apply(w)["error_class"] == "replay"  # a rolled-back approval is not reusable


def test_rollback_fetches_the_previous_image_by_digest_when_it_is_gone(plain_world):
    w = plain_world
    assert tr.apply(w)["ok"]
    w.host.local.pop(OLD_IMAGE)
    w.host.user_store.pop(tr.OLD_TAG)
    assert rollback(w)["ok"]
    assert ("fetch", OLD_IMAGE) in w.host.calls and w.host.current_tag == tr.OLD_TAG


def test_rollback_needs_the_bound_approval_and_digest(plain_world):
    w = plain_world
    assert tr.apply(w)["ok"]
    before = (w.paths.desired.read_text(), w.quadlet.read_text(), len(w.host.calls))
    for kwargs in (
        {"approval": "approval-unknown-0001"},
        {"digest": "sha256:" + "e" * 64},
        {"digest": "sha256:" + tr.OLD_ID[-64:]},
    ):
        result = rollback(w, **kwargs)
        assert result["error_class"] == "policy_denied", kwargs
    assert rollback(w, project="ghost")["error_class"] == "policy_denied"
    for uid in (4242, 4343, 31337):  # api, unregistered, unknown peer
        assert rollback(w, uid)["error_class"] in ("forbidden_role", "unauthorized_peer")
    # the controller may only ask for the automatic rollback and says so explicitly
    assert rollback(w, tr.ME)["error_class"] == "policy_denied"
    assert (w.paths.desired.read_text(), w.quadlet.read_text(), len(w.host.calls)) == before
    assert state(w) == "applied"


@pytest.mark.parametrize("final", ["validated", "failed", "invalidated"])
def test_rollback_refuses_an_approval_that_was_never_applied(
    tmp_path, raw_config, monkeypatch, final
):
    w = build(tmp_path, raw_config, monkeypatch, "none")
    w.host.migrates = False
    if final == "failed":
        w.host.unhealthy_tags.add(tr.NEW_TAG)
        assert tr.apply(w)["error_class"] == "execution_failed"
    elif final == "invalidated":
        ledger(w).invalidate(tr.APPROVAL_ID)
    result = rollback(w)
    assert result["error_class"] == "replay"
    assert desired_image(w) == OLD_IMAGE


def test_rollback_is_refused_when_a_later_change_superseded_the_update(plain_world):
    w = plain_world
    assert tr.apply(w)["ok"]
    body = json.loads(w.paths.desired.read_text())
    body["projects"][0]["host_port"] = 20101  # someone deployed another revision since
    w.paths.desired.write_text(json.dumps(body, sort_keys=True) + "\n")
    result = rollback(w)
    assert result["error_class"] == "conflict"
    assert state(w) == "applied" and desired_image(w) == NEW_IMAGE
    assert w.host.current_tag == tr.NEW_TAG


def test_rollback_by_the_registry_head_is_checked_against_a_deploy_in_between(plain_world):
    w = plain_world
    assert tr.apply(w)["ok"]
    registry = tr.registry_of(w)
    registry["config_revision"] = "9" * 64
    w.paths.registry.write_text(json.dumps(registry))
    assert rollback(w)["error_class"] == "conflict"


def test_rollback_with_a_busy_target_changes_nothing(plain_world):
    w = plain_world
    assert tr.apply(w)["ok"]
    before = len(w.host.calls)
    with w.ex.target_lock("project-shop"):
        assert rollback(w)["error_class"] == "target_busy"
    with w.ex.target_lock("deployment-execution"):
        assert rollback(w)["error_class"] == "target_busy"
    assert len(w.host.calls) == before and state(w) == "applied"
    assert rollback(w)["ok"]


def test_rollback_keeps_a_pending_ui_revision_and_never_advances_it(plain_world, tmp_path):
    w = plain_world
    store = Store(tmp_path / "api.db")
    old_body = json.loads(w.paths.desired.read_text())
    applied = store.record_applied(old_body)
    edit = json.loads(json.dumps(old_body))
    edit["projects"][0]["resources"]["memory_mb"] = 512
    head = store.commit_revision(edit, parent=applied, author="ui", source="ui")
    assert tr.apply(w)["ok"] and rollback(w)["ok"]
    assert store.head() == head != applied  # the pending edit is neither lost nor applied
    assert json.loads(w.paths.desired.read_text()) == old_body  # back to the applied revision
    assert store.get_revision(head)["body"]["projects"][0]["resources"]["memory_mb"] == 512


def test_failed_rollback_is_visible_and_can_be_retried(plain_world):
    w = plain_world
    assert tr.apply(w)["ok"]
    w.host.unhealthy_tags.add(tr.OLD_TAG)
    result = rollback(w)
    assert result["error_class"] == "execution_failed" and "rollback failed" in result["message"]
    assert state(w) == "rollback_failed" and journal(w)["phase"] == "rollback_failed"
    status = tr.call(w, "update_status", {"project_id": "shop"})["result"]["approvals"][0]
    assert status["state"] == "rollback_failed"
    w.host.unhealthy_tags.clear()
    assert rollback(w)["ok"] and state(w) == "rolled_back"


# ---- rollback with an exact data restore ------------------------------------------------------


def applied_with_new_writes(w):
    assert tr.apply(w)["ok"]
    (w.data / "post-update.txt").write_text("written by the new version")


def test_rollback_with_migration_restores_the_exact_capture_and_preserves_newer_data(
    restore_world,
):
    w = restore_world
    applied_with_new_writes(w)
    refused = rollback(w)  # no acknowledgement: nothing changes
    assert refused["error_class"] == "policy_denied" and "acknowledge" in refused["message"]
    assert state(w) == "applied" and w.host.current_tag == tr.NEW_TAG and not preserved(w)
    result = rollback(w, ack=True)
    assert result["ok"], result
    body = result["result"]
    assert body["data_restore"] == "restored" and body["state"] == "rolled_back"
    assert_original_state(w)  # real readback: old version healthy on the original data
    assert w.host.health_ok is True
    (kept,) = preserved(w)
    assert body["preserved_data"] == kept.name
    assert (kept / "post-update.txt").read_text() == "written by the new version"
    assert (kept / "db.txt").read_text().startswith("schema=2")


def test_rollback_without_a_matching_capture_changes_nothing(restore_world):
    w = restore_world
    applied_with_new_writes(w)
    ref = CaptureRef.model_validate(journal(w)["recovery_capture"])
    (spool(w) / ref.artifact / "data.tar").write_bytes(b"damaged")
    result = rollback(w, ack=True)
    assert result["error_class"] == "unavailable" and "capture" in result["message"]
    assert state(w) == "applied" and w.host.current_tag == tr.NEW_TAG
    assert (w.data / "post-update.txt").exists() and not preserved(w)


def test_rollback_with_a_removed_capture_is_refused(restore_world):
    w = restore_world
    applied_with_new_writes(w)
    shutil.rmtree(spool(w) / journal(w)["recovery_capture"]["artifact"])
    assert rollback(w, ack=True)["error_class"] == "unavailable"
    assert state(w) == "applied" and (w.data / "post-update.txt").exists()


def test_rollback_is_bound_to_the_capture_of_this_update(restore_world):
    w = restore_world
    applied_with_new_writes(w)
    row = ledger(w).get(tr.APPROVAL_ID)
    other = dict(row["journal"]["recovery_capture"], capture_id="f" * 64)
    ledger(w).journal(tr.APPROVAL_ID, recovery_capture=other)
    assert rollback(w, ack=True)["error_class"] == "unavailable"
    assert state(w) == "applied" and not preserved(w)


def test_rollback_that_fails_health_keeps_data_and_retry_does_not_restore_twice(restore_world):
    w = restore_world
    applied_with_new_writes(w)
    w.host.unhealthy_tags.add(tr.OLD_TAG)
    assert rollback(w, ack=True)["error_class"] == "execution_failed"
    assert state(w) == "rollback_failed" and len(preserved(w)) == 1
    (w.data / "after-restore.txt").write_text("written by the old version")
    w.host.unhealthy_tags.clear()
    w.host.fail_old_start = False
    result = rollback(w, ack=True)
    assert result["ok"] and result["result"]["data_restore"] == "already_restored"
    assert (w.data / "after-restore.txt").exists() and len(preserved(w)) == 1
    assert state(w) == "rolled_back"


@pytest.mark.parametrize(
    "phase,durable",
    [
        ("rollback_preparing", "rollback_started"),
        ("rollback_restoring", "rollback_preparing"),
        ("rollback_installing", "rollback_restoring"),
        ("rollback_installed", "rollback_installing"),
        ("rollback_restarted", "rollback_installed"),
    ],
)
def test_process_death_during_a_rollback_is_finished_after_restart(restore_world, phase, durable):
    w = restore_world
    applied_with_new_writes(w)
    with crash_before(w, phase), pytest.raises(Crash):
        rollback(w, ack=True)
    assert state(w) == "rolling_back" and journal(w)["phase"] == durable
    assert recover(w) == [f"{tr.APPROVAL_ID}:rolled_back"]
    assert_original_state(w)
    assert len(preserved(w)) == 1  # restored exactly once
    assert rollback(w, ack=True)["error_class"] == "replay"


def test_automatic_recovery_respects_the_kill_switch_but_the_operator_can_finish(restore_world):
    w = restore_world
    applied_with_new_writes(w)
    with crash_before(w, "rollback_installing"), pytest.raises(Crash):
        rollback(w, ack=True)
    w.host.killed = True
    assert image_update.recover_updates(w.ex, automatic=True) == []
    assert state(w) == "rolling_back"
    result = rollback(w, ack=True)  # settles the interrupted rollback first, then reports it
    assert result["error_class"] == "replay" and state(w) == "rolled_back"
    assert_original_state(w)


def test_a_second_update_cannot_start_while_a_rollback_is_in_flight(restore_world):
    w = restore_world
    applied_with_new_writes(w)
    with crash_before(w, "rollback_installed"), pytest.raises(Crash):
        rollback(w, ack=True)
    other = "approval-other-0003"
    assert ledger(w).get(other) is None
    with pytest.raises(UpdateRejected) as caught:
        ledger(w).begin_rollback(tr.APPROVAL_ID)
    assert caught.value.code == "in_progress"


def test_preserved_tree_limit_blocks_a_rollback_before_any_change(restore_world):
    w = restore_world
    applied_with_new_writes(w)
    for index in range(update_recovery.MAX_PRESERVED_TREES):
        (w.data.parent / f"data.preserved-full{index}").mkdir()
    result = rollback(w, ack=True)
    assert result["error_class"] == "unavailable"
    assert state(w) == "applied" and w.host.current_tag == tr.NEW_TAG


def test_capture_limit_never_exceeds_what_a_restore_can_verify():
    big = {"backup": {"max_mib": 1024}}
    assert update_recovery._capture_limit(big) == 1024 * 1024 * 1024
    assert Backup.model_validate({}).max_mib * 1024 * 1024 <= 1024 * 1024 * 1024


def test_a_stale_rollback_is_settled_before_the_next_update_starts(restore_world):
    w = restore_world
    applied_with_new_writes(w)
    with crash_before(w, "rollback_installed"), pytest.raises(Crash):
        rollback(w, ack=True)
    result = tr.call(
        w,
        "apply_verified_image",
        {
            "project_id": "shop",
            "approval_id": "approval-other-0002",
            "digest": "sha256:" + "c" * 64,
        },
    )
    assert not result["ok"]  # unknown approval, but the half-finished rollback is completed first
    assert state(w) == "rolled_back"
    assert_original_state(w)


def test_rollback_that_cannot_fetch_the_previous_image_changes_no_data(restore_world):
    w = restore_world
    applied_with_new_writes(w)
    w.host.local.pop(OLD_IMAGE)
    w.host.user_store.pop(tr.OLD_TAG)
    w.host.fail.add("fetch")
    result = rollback(w, ack=True)
    assert result["error_class"] == "execution_failed" and "fetch" in result["message"]
    assert state(w) == "rollback_failed"
    assert not preserved(w) and (w.data / "post-update.txt").exists()  # data untouched
    assert ("set", "shop.service", False) not in w.host.calls[
        w.host.calls.index(("restart", tr.NEW_TAG)) :
    ]
    w.host.fail.clear()
    assert rollback(w, ack=True)["ok"] and len(preserved(w)) == 1
    assert_original_state(w)


def test_a_rollback_that_cannot_be_resumed_is_failed_visibly(restore_world):
    w = restore_world
    applied_with_new_writes(w)
    with crash_before(w, "rollback_installing"), pytest.raises(Crash):
        rollback(w, ack=True)
    registry = tr.registry_of(w)
    del registry["projects"]["shop"]["update"]  # the contract was removed meanwhile
    w.paths.registry.write_text(json.dumps(registry))
    assert recover(w) == [f"{tr.APPROVAL_ID}:rollback_failed"]
    assert state(w) == "rollback_failed"


def test_restore_primitive_finishes_when_only_the_empty_staging_directory_is_left(
    plain_world, tmp_path, monkeypatch
):
    w = plain_world
    destination, manifest = make_capture(w, tmp_path)
    (w.data / "db.txt").write_text("schema=2\n")
    real_rmdir = os.rmdir

    def dying_rmdir(path, *args, **kwargs):
        if str(path).endswith(".restore-tok5"):
            raise Crash
        return real_rmdir(path, *args, **kwargs)

    monkeypatch.setattr(data_restore.os, "rmdir", dying_rmdir)
    with pytest.raises(Crash):
        data_restore.restore_tree(
            w.data.parent, destination, manifest, token="tok5", service_uid=os.getuid()
        )
    monkeypatch.setattr(data_restore.os, "rmdir", real_rmdir)
    assert snapshot(w.data) == expected_tree()  # both renames were done
    result = data_restore.restore_tree(
        w.data.parent, destination, manifest, token="tok5", service_uid=os.getuid()
    )
    assert result.state == "finished" and not list(w.data.parent.glob(".restore-*"))
    assert snapshot(w.data) == expected_tree()


@pytest.mark.parametrize("value", ["yes", "true", 1, "1", None])
def test_data_restore_acknowledgement_must_be_a_real_boolean(plain_world, value):
    w = plain_world
    assert tr.apply(w)["ok"]
    result = tr.call(
        w,
        "rollback",
        {
            "project_id": "shop",
            "approval_id": tr.APPROVAL_ID,
            "digest": "sha256:" + NEW_DIGEST,
            "acknowledge_data_restore": value,
        },
    )
    assert result["error_class"] == "bad_request" and state(w) == "applied"


def test_update_status_shows_the_data_restore_of_a_failed_update(restore_world):
    w = restore_world
    w.host.unhealthy_tags.add(tr.NEW_TAG)
    assert tr.apply(w)["error_class"] == "execution_failed"
    body = tr.call(w, "update_status", {"project_id": "shop"})["result"]
    entry = body["approvals"][0]
    assert entry["state"] == "failed" and entry["data_restore"] == "restored"
    assert entry["preserved_data"].startswith("data.preserved-")
    assert body["verify_timeout_s"] == 120


def test_a_full_capture_spool_gives_actionable_guidance(restore_world):
    w = restore_world
    for index in range(10):
        (spool(w) / f"{index:032x}").mkdir(exist_ok=True)
    message = tr.apply(w)["message"]
    assert "10 artifacts" in message and "backup-retention-purge" in message
