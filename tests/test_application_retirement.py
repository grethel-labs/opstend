"""L09 executor actions: retire, archive and release a removed application."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from steward import application_boot as boot
from steward.core import app_archive as archive
from steward.core.config import parse_config
from steward.core.ids import graph_identifier
from steward.core.render import image_tag, prepare_application_registry
from steward.core.retirement import classify
from steward.executor import retirement, server
from steward.executor.host import Host
from steward.executor.protocol import ExecutorError
from test_application_graph import graph
from test_executor import request

DESIRED = "b" * 64


class Crash(BaseException):
    """Simulated process death: nothing in the executor may catch it."""


def boom(*_args, **_kwargs):
    raise Crash


@pytest.fixture
def world(executor, raw_config, tmp_path, monkeypatch):
    app = graph(raw_config)
    for service in app["services"]:
        service["deploy"] = False
    registry = prepare_application_registry(parse_config(raw_config, allow_unavailable=True))
    registry.update(server_name="test-server", backup={"max_mib": 1})
    data_root = tmp_path / "applications"
    cache = tmp_path / "images"
    cache.mkdir(mode=0o755)
    root = tmp_path / "archive"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(server, "APPLICATION_DATA_ROOT", data_root)
    monkeypatch.setattr(archive, "ARCHIVE_ROOT", root)
    monkeypatch.setattr(archive, "IMAGE_CACHE", cache)
    specs = registry["applications"]["shop"]["services"]
    identities = {}
    for number, (name, spec) in enumerate(sorted(specs.items())):
        identities[spec["user"]] = {
            "uid": 31000 + number,
            "gid": 31000 + number,
            "subuid": [400000 + number * 65536, 65536],
            "subgid": [400000 + number * 65536, 65536],
        }
        if name == "database":
            path = data_root / "shop" / "data" / name
            path.mkdir(parents=True, mode=0o755)
            for parent in (data_root, data_root / "shop", data_root / "shop" / "data"):
                parent.chmod(0o755)
            path.chmod(0o700)
            (path / "value.txt").write_text("precious")
            (path / "value.txt").chmod(0o644)
            spec.update(data_source=str(path), data_target="/data", allow_backup_pause=True)
        else:
            spec.update(data_source=None, data_target=None)
        tag = image_tag(spec["container"], spec["image"])
        cached = cache / archive.image_cache_name(spec["image"], tag)
        cached.write_bytes(b"image-" + name.encode())
        cached.chmod(0o644)
    write(executor, registry)
    managers = {item["uid"]: True for item in identities.values()}  # True: manager is up
    calls = []
    by_uid = {item["uid"]: user for user, item in identities.items()}
    host = executor.host
    host.service_user_uid = lambda user: identities[user]["uid"]
    host.group_service_running = lambda *_: False
    host.group_service_quiescent = lambda *_: True
    host.workload_quiescent = lambda *_: True
    host.group_users_within_systemd_slices = lambda users: True
    host.application_manager_quiescent = lambda uid, _sub: not managers.get(uid, True)
    host.system_unit = lambda unit: {"load": "loaded", "active": "active", "sub": "exited"}

    def start(uid):
        calls.append(("start_manager", by_uid[uid]))
        managers[uid] = True
        return True

    def stop(uid):
        calls.append(("stop_manager", by_uid[uid]))
        managers[uid] = False
        return True

    def remove(user, tag):
        calls.append(("remove_image", user, tag))
        return True

    host.start_application_manager = start
    host.stop_application_manager = stop
    host.remove_user_image = remove
    monkeypatch.setattr(retirement, "read_identity", lambda user: dict(identities[user]))
    return SimpleNamespace(
        registry=registry,
        specs=specs,
        data=data_root / "shop" / "data",
        data_root=data_root,
        cache=cache,
        root=root,
        identities=identities,
        managers=managers,
        calls=calls,
    )


def write(executor, registry):
    path = Path(executor.registry_path)
    path.write_text(json.dumps(registry))
    path.chmod(0o600)


def params(world, **changes):
    body = {
        "application": "shop",
        "expected_revision": world.registry["config_revision"],
        "desired_revision": DESIRED,
        "desired_applications": [],
    }
    body.update(changes)
    return body


def retire(executor, world, **changes):
    return executor.handle(request("application_retire", params(world, **changes)), 0)


def states(world):
    return archive.operations(world.root, "shop")


def intact(world):
    return (world.data / "database" / "value.txt").read_text() == "precious"


def test_retirement_archives_verifies_then_releases(executor, world):
    response = retire(executor, world)
    assert response["ok"], response
    result = response["result"]
    assert result["state"] == "released" and result["released"]["database"] == "deleted"
    [state] = states(world)
    assert state.phase == "released" and state.manifest_id == result["archive_id"]
    path = world.root / "shop" / state.operation_id
    manifest = archive.verify_archive(path, expected_id=state.manifest_id)
    assert manifest.services["database"].data.entries == 1
    assert set(manifest.services) == {"backend", "database", "frontend", "worker"}
    assert manifest.applied_revision == world.registry["config_revision"]
    # Working data and loaded/cached images are released only after verification.
    assert not (world.data / "database").exists()
    assert not any(world.cache.iterdir())
    assert len([call for call in world.calls if call[0] == "remove_image"]) == 4
    assert not any(world.managers.values())
    phases = [
        event["phase"]
        for event in executor.audit.read()
        if event["event"] == "application_retirement"
    ]
    assert phases == ["archiving", "archived", "verified", "releasing", "released"]
    assert executor.audit.verify()[0]
    # A repeated request is idempotent and creates no second archive.
    again = retire(executor, world)
    assert again["ok"] and again["result"]["operation_id"] == state.operation_id
    assert len(states(world)) == 1


def test_status_reads_the_journal_and_actions_are_operator_only(executor, world):
    empty = executor.handle(request("application_retirement_status", {"application": "shop"}), 0)
    assert empty["result"]["operations"] == []
    retire(executor, world)
    status = executor.handle(request("application_retirement_status", {"application": "shop"}), 0)
    [summary] = status["result"]["operations"]
    assert summary["phase"] == "released" and status["result"]["active"] == summary
    world.registry["peers"] = {"api": os.getuid()}
    write(executor, world.registry)
    for action, body in (
        ("application_retire", params(world)),
        ("application_retirement_status", {"application": "shop"}),
    ):
        denied = executor.handle(request(action, body), os.getuid())
        assert denied["error_class"] == "forbidden_role"


@pytest.mark.parametrize(
    "body",
    [
        {"application": "../shop"},
        {"desired_applications": ["shop"]},
        {"desired_applications": ["a-b", "a-b"]},
        {"desired_revision": "z" * 64},
        {"desired_revision": "a" * 64, "expected_revision": "a" * 64},
        {"path": "/srv/steward"},
        {"data_source": "/etc"},
        {"unit": "x.service"},
        {"operation_id": "1" * 32},
    ],
)
def test_requests_cannot_carry_paths_or_identities(executor, world, body):
    response = executor.handle(request("application_retire", {**params(world), **body}), 0)
    assert response["error_class"] == "bad_request"
    assert not world.calls and intact(world)


def refuse(executor, world, error_class, **changes):
    response = retire(executor, world, **changes)
    assert response["error_class"] == error_class, response
    assert intact(world)
    assert not (world.root / "shop").exists() or not states(world)
    assert not world.calls
    return response


def test_unregistered_or_unmanaged_applications_are_never_retired(executor, world):
    refuse(executor, world, "policy_denied", application="other-app")
    world.registry["projects"] = {"notes": {"user": "stw-notes"}}
    write(executor, world.registry)
    refuse(executor, world, "policy_denied", application="notes")
    world.registry["applications"]["shop"]["services"]["worker"]["manage"] = False
    write(executor, world.registry)
    assert "unmanaged" in refuse(executor, world, "policy_denied")["message"]


def test_enabled_shared_or_running_applications_are_refused(executor, world):
    service = world.registry["applications"]["shop"]["services"]["worker"]
    service["deploy"] = True
    write(executor, world.registry)
    assert "needs_disable" in refuse(executor, world, "policy_denied")["message"]
    service["deploy"] = False
    write(executor, world.registry)
    executor.host.group_service_running = lambda user, *_: True
    refuse(executor, world, "policy_denied")
    executor.host.group_service_running = lambda *_: None
    executor.host.group_service_quiescent = lambda *_: False
    refuse(executor, world, "unavailable")
    world.registry["applications"]["shop"]["isolation"] = "shared"
    write(executor, world.registry)
    assert "shared_isolation" in refuse(executor, world, "policy_denied")["message"]


def test_stale_fenced_busy_or_stopped_states_refuse_before_any_effect(executor, world):
    refuse(executor, world, "conflict", expected_revision="d" * 64)
    executor.host.killed = True
    refuse(executor, world, "kill_switch")
    executor.host.killed = False
    executor.host.system_unit = lambda unit: {"load": "loaded", "active": "activating", "sub": "x"}
    refuse(executor, world, "unavailable")
    executor.host.system_unit = lambda unit: {"load": "loaded", "active": "active", "sub": "exited"}
    with executor.target_lock("deployment-execution"):
        refuse(executor, world, "target_busy")
    with executor.target_lock(world.registry["applications"]["shop"]["lock"]):
        refuse(executor, world, "target_busy")
    executor.begin_deployment_fence(
        base_revision=world.registry["config_revision"], desired_revision=DESIRED
    )
    refuse(executor, world, "target_busy")


def test_unfinished_group_operation_blocks_retirement(executor, world):
    with executor.observed_group_execution(
        "shop", "database", expected_revision=world.registry["config_revision"], scope="application"
    ):
        pass
    assert retire(executor, world)["error_class"] == "target_busy"
    assert intact(world) and not world.calls


def test_full_disk_fails_closed_and_a_retry_starts_a_clean_archive(executor, world, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(
            archive.shutil, "disk_usage", lambda _p: SimpleNamespace(total=1, used=1, free=1024)
        )
        response = retire(executor, world)
    assert response["error_class"] == "unavailable" and "insufficient_space" in response["message"]
    [failed] = states(world)
    assert failed.phase == "failed" and failed.error_class == "insufficient_space"
    leftovers = {item.name for item in (world.root / "shop" / failed.operation_id).iterdir()}
    assert leftovers == {"state.json"}
    assert intact(world) and len(list(world.cache.iterdir())) == 4 and not world.calls
    assert retire(executor, world)["ok"]
    assert [item.phase for item in states(world)] == ["failed", "released"]


def test_corrupt_archive_never_reaches_release(executor, world, monkeypatch):
    real = archive.write_archive

    def corrupting(operation, *args, **kwargs):
        manifest = real(operation, *args, **kwargs)
        (operation / "data" / "database" / "data.tar").write_bytes(b"corrupt")
        return manifest

    monkeypatch.setattr(archive, "write_archive", corrupting)
    response = retire(executor, world)
    assert response["error_class"] in ("conflict", "unavailable")
    [failed] = states(world)
    assert failed.phase == "failed"
    assert intact(world) and len(list(world.cache.iterdir())) == 4 and not world.calls


def test_archive_corrupted_after_verification_blocks_the_release(executor, world, monkeypatch):
    real = retirement._verified_manifest
    seen = []

    def tampering(ctx, state):
        if state.phase == "verified" and not seen:
            seen.append(True)
            path = ctx.root / ctx.application / state.operation_id
            (path / "images" / "backend.tar").write_bytes(b"tampered")
        return real(ctx, state)

    monkeypatch.setattr(retirement, "_verified_manifest", tampering)
    response = retire(executor, world)
    assert response["error_class"] == "conflict"
    assert intact(world) and len(list(world.cache.iterdir())) == 4 and not world.calls
    assert states(world)[0].phase == "verified"


def test_crash_before_release_resumes_from_the_journal(executor, world, monkeypatch):
    real = retirement._release
    monkeypatch.setattr(retirement, "_release", boom)
    with pytest.raises(Crash):
        retire(executor, world)
    [state] = states(world)
    assert state.phase == "verified"
    assert intact(world) and len(list(world.cache.iterdir())) == 4
    monkeypatch.setattr(retirement, "_release", real)
    result = retire(executor, world)["result"]
    assert result["state"] == "released" and result["operation_id"] == state.operation_id
    assert len(states(world)) == 1


@pytest.mark.parametrize("point", ["image", "data", "manager"])
def test_crash_during_release_resumes_without_a_second_archive(executor, world, monkeypatch, point):
    host = executor.host
    fired = []

    def once(original):
        def wrapper(*args, **kwargs):
            if not fired:
                fired.append(True)
                raise Crash
            return original(*args, **kwargs)

        return wrapper

    if point == "image":
        host.remove_user_image = once(host.remove_user_image)
    elif point == "data":
        monkeypatch.setattr(archive, "release_data", once(archive.release_data))
    else:
        host.stop_application_manager = once(host.stop_application_manager)
    with pytest.raises(Crash):
        retire(executor, world)
    [state] = states(world)
    assert state.phase == "releasing"
    result = retire(executor, world)["result"]
    assert result["state"] == "released" and result["operation_id"] == state.operation_id
    assert len(states(world)) == 1 and not (world.data / "database").exists()
    assert not any(world.managers.values())
    archive.verify_archive(world.root / "shop" / state.operation_id, expected_id=state.manifest_id)


def test_changed_uid_after_archive_blocks_release_until_restored(executor, world, monkeypatch):
    real = retirement._release
    monkeypatch.setattr(retirement, "_release", boom)
    with pytest.raises(Crash):
        retire(executor, world)
    monkeypatch.setattr(retirement, "_release", real)
    user = world.specs["database"]["user"]
    original = dict(world.identities[user])
    world.identities[user]["uid"] += 500
    assert retire(executor, world)["error_class"] == "policy_denied"
    world.identities[user].update(original)
    executor.host.service_user_uid = lambda name: world.identities[name]["uid"] + 7
    assert retire(executor, world)["error_class"] == "policy_denied"
    assert intact(world) and not world.calls
    executor.host.service_user_uid = lambda name: world.identities[name]["uid"]
    assert retire(executor, world)["ok"]


def test_working_data_changed_after_archiving_cancels_instead_of_releasing(
    executor, world, monkeypatch
):
    real = retirement._release
    monkeypatch.setattr(retirement, "_release", boom)
    with pytest.raises(Crash):
        retire(executor, world)
    monkeypatch.setattr(retirement, "_release", real)
    (world.data / "database" / "late.txt").write_text("written after the archive")
    (world.data / "database" / "late.txt").chmod(0o644)
    response = retire(executor, world)
    assert response["error_class"] == "conflict"
    assert states(world)[0].phase == "cancelled"
    assert (world.data / "database" / "late.txt").exists() and not world.calls
    again = retire(executor, world)
    assert again["ok"]  # the next request archives the data as it is now
    assert [item.phase for item in states(world)] == ["cancelled", "released"]


def test_interrupted_archive_build_is_discarded_and_rebuilt(executor, world, monkeypatch):
    real = archive.write_archive
    monkeypatch.setattr(archive, "write_archive", boom)
    with pytest.raises(Crash):
        retire(executor, world)
    assert states(world)[0].phase == "archiving"
    monkeypatch.setattr(archive, "write_archive", real)
    assert retire(executor, world)["ok"]
    assert [item.phase for item in states(world)] == ["failed", "released"]


def test_unfinished_retirement_is_bound_to_its_revisions(executor, world, monkeypatch):
    monkeypatch.setattr(retirement, "_release", boom)
    with pytest.raises(Crash):
        retire(executor, world)
    assert retire(executor, world, desired_revision="c" * 64)["error_class"] == "conflict"


def test_end_to_end_remove_and_readd_preserves_data(executor, world):
    assert retire(executor, world)["ok"]
    assert not (world.data / "database").exists()
    (world.data / "database").mkdir(mode=0o700)  # the layout step prepares an empty directory
    services = {
        name: archive.ReactivationService(
            user=spec["user"],
            identity=world.identities[spec["user"]],
            data_source=Path(spec["data_source"]) if spec["data_source"] else None,
            image=spec["image"],
            image_tag=image_tag(spec["container"], spec["image"]),
        )
        for name, spec in world.specs.items()
    }
    result = archive.reactivate(
        world.root,
        "shop",
        services=services,
        isolation="separate",
        image_cache=world.cache,
        check_identity=lambda *_: None,
        owner_of=lambda _identity: (os.geteuid(), os.getegid()),
    )
    assert result["state"] == "reactivated" and result["restored"] == ["database"]
    assert intact(world) and len(list(world.cache.iterdir())) == 4
    # A later retirement of the returned application starts a new archive; the old one stays.
    assert retire(executor, world)["ok"]
    assert [item.phase for item in states(world)] == ["reactivated", "released"]


def test_no_action_deletes_an_archive():
    names = [name for name in server.ACTIONS if name.startswith("application_")]
    assert sorted(names) == [
        "application_group_resume",
        "application_group_status",
        "application_group_stop",
        "application_retire",
        "application_retirement_status",
    ]
    assert server.ACTIONS["application_retire"].roles == frozenset({"operator"})
    assert not server.ACTIONS["application_retirement_status"].mutating


def test_host_methods_use_fixed_argv_and_registered_names(monkeypatch):
    host = Host()
    ran = []
    monkeypatch.setattr(host, "_run", lambda argv, timeout=0: ran.append(argv) or (0, ""))
    assert host.stop_application_manager(31000)
    assert ran == [["systemctl", "stop", "user@31000.service"]]
    for bad in (1000, 40000, "31000", None):
        assert not host.stop_application_manager(bad)
    stem = graph_identifier("s", "shop", "database")
    user, tag = "stw-" + stem, f"localhost/steward/{stem}:sha256-" + "a" * 32
    monkeypatch.setattr("steward.executor.host.pwd.getpwnam", lambda _user: SimpleNamespace())
    answers = iter([(0, ""), (0, ""), (1, "")])
    commands = []

    def as_user(_user, argv, timeout=0):
        commands.append(argv)
        return next(answers)

    monkeypatch.setattr(host, "_as_user", as_user)
    assert host.remove_user_image(user, tag)
    assert [c[:3] for c in commands] == [
        ["podman", "image", "exists"],
        ["podman", "image", "rm"],
        ["podman", "image", "exists"],
    ]
    commands.clear()
    for who, name in (("root", tag), (user, "docker.io/library/x:1"), (user, tag + ";id")):
        assert not host.remove_user_image(who, name)
    assert not commands
    monkeypatch.setattr(host, "_as_user", lambda _user, argv, timeout=0: (2, "unknown"))
    assert not host.remove_user_image(user, tag)


def test_absent_boot_unit_counts_only_when_every_service_is_disabled(executor, world):
    """The all-disabled deployment removes the boot unit; that must not block retirement."""
    absent = {"load": "not-found", "active": "inactive", "sub": "dead"}
    executor.host.system_unit = lambda unit: absent
    services = world.registry["applications"]["shop"]["services"]
    for spec in services.values():
        spec["deploy"] = True
    write(executor, world.registry)
    refuse(executor, world, "unavailable")  # an enabled service: the unit must exist and be done
    for spec in services.values():
        spec["deploy"] = False
    write(executor, world.registry)
    response = retire(executor, world)
    assert response.get("error_class") != "unavailable", response


@pytest.fixture
def guarded(executor, world, monkeypatch):
    statuses = {spec["user"]: name != "worker" for name, spec in world.specs.items()}
    for spec in world.specs.values():
        spec["deploy"] = statuses[spec["user"]]
    write(executor, world.registry)
    owned = [
        boot.Binding("shop", name, "separate", dict(world.identities[spec["user"]]))
        for name, spec in world.specs.items()
        if spec["deploy"]
    ]
    monkeypatch.setattr(boot, "read_active", lambda: boot.Active("a" * 64, owned, []))
    monkeypatch.setattr(boot, "verify_stop_identity", lambda _binding: None)

    host = executor.host
    host.group_service_running = lambda user, *_: (
        statuses[user] if world.managers[world.identities[user]["uid"]] else None
    )
    host.application_unit_authority = lambda user, unit, source: (
        unit == user.removeprefix("stw-") + ".service"
        and source
        == boot.QUADLETS
        / str(world.identities[user]["uid"])
        / unit.replace(".service", ".container")
    )
    host.application_unit_transitioning = lambda *_: False

    def stop(user, unit, *, running=False):
        assert not running
        world.calls.append(("stop_unit", user, unit))
        statuses[user] = False
        return True

    host.set_user_unit = stop

    def run(desired_revision=DESIRED, require_custody=lambda: None):
        candidate = classify("shop", world.registry["applications"]["shop"])
        return retirement.retire_guarded_application(
            executor, world.registry, candidate, desired_revision, require_custody
        )

    return SimpleNamespace(run=run, running=statuses, owned=owned)


def test_guarded_stops_only_enabled_units_in_reverse_order(executor, world, guarded, monkeypatch):
    real = archive.release_data

    def custody():
        [state] = states(world)
        world.calls.append(("custody", state.phase))

    def release(*args):
        assert not any(world.managers.values())
        assert world.calls[-1] == ("custody", "releasing")
        return real(*args)

    monkeypatch.setattr(archive, "release_data", release)
    result = guarded.run(require_custody=custody)
    assert result["changed"] is True
    assert result["state"] == "released" and result["released"]["database"] == "deleted"
    assert [call[1:] for call in world.calls if call[0] == "stop_unit"] == [
        (world.specs[name]["user"], world.specs[name]["unit"])
        for name in ("frontend", "backend", "database")
    ]
    assert [call[1] for call in world.calls if call[0] == "custody"] == ["verified", "releasing"]
    calls = world.calls.copy()
    assert guarded.run() == {**result, "changed": False}
    assert world.calls == calls


@pytest.mark.parametrize("reason", ["disabled", "unowned", "unit_source", "data_contract", "job"])
def test_guarded_refuses_unproven_ownership_before_stopping(executor, world, guarded, reason):
    if reason == "disabled":
        guarded.running[world.specs["worker"]["user"]] = True
    elif reason == "unowned":
        guarded.owned.pop()
    elif reason == "unit_source":
        executor.host.application_unit_authority = lambda *_: False
    elif reason == "data_contract":
        world.specs["database"]["allow_backup_pause"] = False
        write(executor, world.registry)
    else:
        executor.host.application_unit_transitioning = lambda *_: True
    with pytest.raises(ExecutorError, match="policy_denied"):
        guarded.run()
    assert intact(world) and not world.calls
    if reason == "data_contract":
        assert not (world.root / "shop").exists()
    else:
        assert not states(world)


def test_guarded_respects_group_and_archive_locks(executor, world, guarded):
    with (
        executor.target_lock(world.specs["database"]["lock"]),
        pytest.raises(ExecutorError, match="target_busy"),
    ):
        guarded.run()
    with (
        archive.archive_lock(world.root, "shop", create=True),
        pytest.raises(ExecutorError, match="target_busy"),
    ):
        guarded.run()
    assert intact(world) and not world.calls and not states(world)


def test_guarded_partial_archive_checks_revision_before_discard(world, guarded, monkeypatch):
    write_archive = archive.write_archive
    monkeypatch.setattr(archive, "write_archive", boom)
    with pytest.raises(Crash):
        guarded.run()
    [state] = states(world)
    assert state.phase == "archiving"
    with pytest.raises(ExecutorError, match="other revisions"):
        guarded.run(desired_revision="c" * 64)
    assert states(world) == [state]
    monkeypatch.setattr(archive, "write_archive", write_archive)
    assert guarded.run()["state"] == "released"
    assert [state.phase for state in states(world)] == ["failed", "released"]


def test_guarded_rechecks_verified_archive_and_uid_after_crash(
    executor, world, guarded, monkeypatch
):
    with pytest.raises(Crash):
        guarded.run(require_custody=boom)
    [state] = states(world)
    assert state.phase == "verified" and intact(world)
    user = world.specs["database"]["user"]
    identity = world.identities[user]
    uid = identity["uid"]
    identity["uid"] += 500
    world.managers[identity["uid"]] = False
    with pytest.raises(ExecutorError, match="application identity changed"):
        guarded.run()
    identity["uid"] = uid
    executor.host.system_unit = lambda _unit: {
        "load": "loaded",
        "active": "failed",
        "sub": "failed",
    }
    guarded.owned.clear()
    assert guarded.run()["state"] == "released"
    path = world.root / "shop" / state.operation_id / "data" / "database" / "data.tar"
    path.write_bytes(b"corrupt")
    with pytest.raises(ExecutorError, match="archive conflict"):
        guarded.run()


def test_guarded_after_rename_intent_refuses_changed_live_data(world, guarded, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(archive, "release_data", boom)
        with pytest.raises(Crash):
            guarded.run()
    [state] = states(world)
    assert state.phase == "releasing" and state.released["database"] == "moved"
    path = world.data / "database" / "value.txt"
    path.write_text("new writes")
    with pytest.raises(ExecutorError, match="working data changed"):
        guarded.run()
    assert path.read_text() == "new writes" and states(world) == [state]


def test_guarded_rechecks_live_data_after_rootless_image_cleanup(executor, world, guarded):
    remove_image = executor.host.remove_user_image
    path = world.data / "database" / "value.txt"

    def remove_and_write(user, tag):
        path.write_text("new writes")
        return remove_image(user, tag)

    executor.host.remove_user_image = remove_and_write
    with pytest.raises(ExecutorError, match="working data changed"):
        guarded.run()
    [state] = states(world)
    assert state.phase == "releasing" and state.released["database"] == "pending"
    assert path.read_text() == "new writes"


@pytest.mark.parametrize("failure", ["insufficient_space", "corrupt"])
def test_guarded_bad_archives_never_release_working_area(world, guarded, monkeypatch, failure):
    if failure == "insufficient_space":
        monkeypatch.setattr(
            archive.shutil, "disk_usage", lambda _p: SimpleNamespace(total=1, used=1, free=1024)
        )
    else:
        write_archive = archive.write_archive

        def corrupt(operation, *args, **kwargs):
            manifest = write_archive(operation, *args, **kwargs)
            (operation / "images" / "backend.tar").write_bytes(b"corrupt")
            return manifest

        monkeypatch.setattr(archive, "write_archive", corrupt)
    with pytest.raises(ExecutorError, match="application archive"):
        guarded.run(require_custody=lambda: pytest.fail("unexpected release"))
    [state] = states(world)
    assert state.phase == "failed"
    assert intact(world) and len(list(world.cache.iterdir())) == 4
    assert not any(call[0] == "remove_image" for call in world.calls)
