"""Destructive reset guards must fail before touching a VM or its disks."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location(
    "proxmox_harness", Path(__file__).with_name("harness.py")
)
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


@pytest.fixture
def owned(tmp_path, monkeypatch):
    base = tmp_path / "base.img"
    base.write_bytes(b"verified Ubuntu base fixture")
    disks = {"scsi0": "test:vm-123-disk-0,size=24G", "ide2": "local:iso/test.iso,media=cdrom"}
    state = {
        "ssh_config": "/private/ssh/config",
        "alias": "test-node",
        "node": "test-node",
        "vmid": 123,
        "name": "test-owned",
        "tag": "steward-test",
        "smbios1": "uuid=b824f4ce-d276-44d1-9334-e5a1d7c33a78",
        "disks": disks,
        "local_port": 2224,
        "remote_port": 22223,
        "base": str(base),
        "base_sha256": harness.digest(base),
        "remote_dir": "/private-owned-cache",
    }
    (tmp_path / "ownership.json").write_text(json.dumps(state))
    driver = harness.Harness(tmp_path)
    config = {"name": "test-owned", "tags": "steward-test", "smbios1": state["smbios1"], **disks}
    monkeypatch.setattr(driver, "config", lambda: config)
    calls = []
    monkeypatch.setattr(driver, "remote", lambda *args, **kwargs: calls.append(args))
    return driver, config, calls


@pytest.mark.parametrize("tamper", ["uuid", "name", "tag", "extra_disk", "different_disk"])
def test_reset_refuses_changed_identity_or_disk_before_any_mutation(owned, tamper):
    driver, config, calls = owned
    if tamper == "uuid":
        config["smbios1"] = "uuid=someone-else"
    elif tamper == "name":
        config["name"] = "foreign"
    elif tamper == "tag":
        config["tags"] = "unrelated"
    elif tamper == "extra_disk":
        config["unused0"] = "test:vm-999-disk-0"
    else:
        config["scsi0"] = "test:vm-999-disk-0,size=24G"
    with pytest.raises(RuntimeError, match="refusing reset"):
        driver.provision(reset=True)
    assert calls == []


def test_provision_refuses_occupied_vmid_without_mutation(owned):
    driver, _, calls = owned
    with pytest.raises(RuntimeError, match="VMID occupied"):
        driver.provision()
    assert calls == []


def test_reset_refuses_missing_vm_without_mutation(owned, monkeypatch):
    driver, _, calls = owned
    monkeypatch.setattr(driver, "config", lambda: None)
    with pytest.raises(RuntimeError, match="Owned VM missing"):
        driver.provision(reset=True)
    assert calls == []


def test_reset_rejects_corrupt_local_base_before_any_remote_call(owned):
    driver, _, calls = owned
    Path(driver.state["base"]).write_bytes(b"corrupted")
    with pytest.raises(RuntimeError, match="Local base checksum changed"):
        driver.provision(reset=True)
    assert calls == []


def test_reset_rejects_corrupt_remote_base_before_shutdown(owned, monkeypatch):
    driver, _, calls = owned

    def remote(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout="0" * 64 + "  base.img\n")

    monkeypatch.setattr(driver, "remote", remote)
    with pytest.raises(RuntimeError, match="Remote base checksum differs"):
        driver.provision(reset=True)
    assert [args[0] for args in calls] == ["test", "sha256sum"]


def test_tunnel_options_are_before_destination_and_only_bind_loopback(owned, monkeypatch):
    driver, _, _ = owned
    commands = []
    monkeypatch.setattr(harness.subprocess, "call", lambda argv: commands.append(argv) or 0)
    assert driver.tunnel() == 0
    argv = commands[0]
    assert argv[-1] == "test-node"
    assert argv[argv.index("-L") + 1] == "127.0.0.1:2224:127.0.0.1:22223"
    assert "StrictHostKeyChecking=yes" in argv


def test_owned_pair_checks_both_recorded_guests_without_mutating(owned, tmp_path, monkeypatch):
    source, config, calls = owned
    target_state = dict(source.state)
    target_state.update(
        vmid=124, name="target-owned", smbios1="uuid=3b35da2d-cff1-4412-9b26-6b28440b1f18"
    )
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    (target_dir / "ownership.json").write_text(json.dumps(target_state))
    target = harness.Harness(target_dir)
    target_config = {**config, "name": "target-owned", "smbios1": target_state["smbios1"]}
    monkeypatch.setattr(target, "config", lambda: target_config)
    monkeypatch.setattr(target, "remote", lambda *args, **kwargs: calls.append(args))
    assert harness.owned_pair(source, target) == (config, target_config)
    assert calls == []
    target_config["unused0"] = "test:unrecorded-disk"
    with pytest.raises(RuntimeError, match="VM disks differ"):
        harness.owned_pair(source, target)
    assert calls == []


@pytest.mark.parametrize("duplicate", ["vmid", "uuid"])
def test_owned_pair_refuses_duplicate_identity_before_remote_access(owned, monkeypatch, duplicate):
    source, _, calls = owned
    target = harness.Harness(source.work)
    target.state = dict(source.state)
    if duplicate == "vmid":
        target.state["smbios1"] = "uuid=3b35da2d-cff1-4412-9b26-6b28440b1f18"
    else:
        target.state["vmid"] = 124
        target.state["smbios1"] = (
            source.state["smbios1"].upper().replace("UUID=", "uuid=") + ",manufacturer=test"
        )
    monkeypatch.setattr(source, "config", lambda: pytest.fail("must reject before contact"))
    monkeypatch.setattr(target, "config", lambda: pytest.fail("must reject before contact"))
    with pytest.raises(RuntimeError, match="distinct"):
        harness.owned_pair(source, target)
    assert calls == []


def test_guest_identity_checks_node_and_boot_over_fresh_pinned_ssh(owned, monkeypatch):
    driver, config, _ = owned
    vm_uuid = "3b35da2d-cff1-4412-9b26-6b28440b1f18"
    boot = "e03b068f-8076-48be-a90f-987724d10623"
    driver.state.update(smbios1="uuid=" + vm_uuid, identity="/private/test-key")
    config["smbios1"] = driver.state["smbios1"]
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(stdout=json.dumps({"uuid": vm_uuid, "boot_id": boot}))

    monkeypatch.setattr(harness, "run", run)
    assert driver.guest_identity(boot) == {"uuid": vm_uuid, "boot_id": boot}
    argv, kwargs = calls[0]
    assert argv[argv.index("-F") + 1] == "/dev/null"
    assert argv[argv.index("-S") + 1] == "none"
    assert "StrictHostKeyChecking=yes" in argv
    assert "GlobalKnownHostsFile=/dev/null" in argv
    assert "UserKnownHostsFile=" + str(driver.work / "known_hosts") in argv
    assert "BatchMode=yes" in argv and "IdentitiesOnly=yes" in argv
    assert kwargs["input"] == harness.GUEST_IDENTITY


@pytest.mark.parametrize("bad", ["boot", "uuid", "bad_json", "node"])
def test_guest_identity_refuses_mismatch_or_changed_node(owned, monkeypatch, bad):
    driver, config, _ = owned
    vm_uuid = "3b35da2d-cff1-4412-9b26-6b28440b1f18"
    boot = "e03b068f-8076-48be-a90f-987724d10623"
    driver.state.update(smbios1="uuid=" + vm_uuid, identity="/private/test-key")
    config["smbios1"] = driver.state["smbios1"]
    if bad == "node":
        config["unused0"] = "foreign:disk"
    result = {"uuid": vm_uuid, "boot_id": boot}
    if bad == "uuid":
        result["uuid"] = "137724e2-31ff-4c9b-9700-fbb5cb40a713"
    if bad == "boot":
        result["boot_id"] = "137724e2-31ff-4c9b-9700-fbb5cb40a713"
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(stdout="invalid" if bad == "bad_json" else json.dumps(result))

    monkeypatch.setattr(harness, "run", run)
    with pytest.raises(RuntimeError):
        driver.guest_identity(boot)
    assert bool(calls) is (bad != "node")


@pytest.mark.parametrize("value", [None, "", "uuid=not-a-uuid", "uuid=1,uuid=2"])
def test_owned_pair_rejects_invalid_uuid_before_remote_access(owned, monkeypatch, value):
    source, _, _ = owned
    target = harness.Harness(source.work)
    target.state = {**source.state, "vmid": 124, "smbios1": value}
    monkeypatch.setattr(source, "config", lambda: pytest.fail("must reject before contact"))
    monkeypatch.setattr(target, "config", lambda: pytest.fail("must reject before contact"))
    with pytest.raises(RuntimeError, match="invalid recorded VM UUID"):
        harness.owned_pair(source, target)


@pytest.fixture
def restore_preflight(owned, monkeypatch):
    driver, _, _ = owned
    driver.state["identity"] = "/private/test-key"
    identity = {
        "uuid": "3b35da2d-cff1-4412-9b26-6b28440b1f18",
        "boot_id": "e03b068f-8076-48be-a90f-987724d10623",
    }
    facts = {
        **identity,
        "uid": 1000,
        "platform_paths_absent": True,
        "platform_accounts_absent": True,
        "platform_units_absent": True,
        "container_count": 0,
        "rootless": True,
        "image_present": True,
    }
    monkeypatch.setattr(driver, "guest_identity", lambda boot: identity)
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(stdout=json.dumps(facts))

    monkeypatch.setattr(harness, "run", run)
    image = "docker.io/library/python@sha256:" + "a" * 64
    return driver, identity, facts, calls, image


def test_restore_preflight_accepts_only_matching_empty_rootless_guest(restore_preflight):
    driver, identity, facts, calls, image = restore_preflight
    assert driver.guest_restore_preflight(identity["boot_id"], image) == facts
    assert "StrictHostKeyChecking=yes" in calls[0]
    assert "GlobalKnownHostsFile=/dev/null" in calls[0]
    assert image in calls[0][-1]


@pytest.mark.parametrize(
    "field,value",
    [
        ("uuid", "137724e2-31ff-4c9b-9700-fbb5cb40a713"),
        ("boot_id", "137724e2-31ff-4c9b-9700-fbb5cb40a713"),
        ("uid", 0),
        ("uid", True),
        ("platform_paths_absent", False),
        ("platform_accounts_absent", False),
        ("platform_units_absent", False),
        ("container_count", 1),
        ("container_count", False),
        ("rootless", False),
        ("image_present", False),
    ],
)
def test_restore_preflight_refuses_unprepared_or_changed_guest(restore_preflight, field, value):
    driver, identity, facts, _, image = restore_preflight
    facts[field] = value
    with pytest.raises(RuntimeError, match="preflight failed"):
        driver.guest_restore_preflight(identity["boot_id"], image)


@pytest.mark.parametrize("image", ["python:latest", "-option@sha256:" + "a" * 64, "x;id"])
def test_restore_preflight_rejects_unpinned_or_unsafe_image_before_ssh(restore_preflight, image):
    driver, identity, _, calls, _ = restore_preflight
    with pytest.raises(RuntimeError, match="invalid pinned restore image"):
        driver.guest_restore_preflight(identity["boot_id"], image)
    assert calls == []


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "empty_units",
        "container_object",
        "installed_unit",
        "active_unit",
        "installed_account",
        "installed_path",
        "existing_container",
        "missing_image",
        "rootful",
    ],
)
def test_restore_guest_inspection_interprets_actual_command_results(monkeypatch, capsys, bad):
    import os
    import pwd
    import subprocess
    import sys

    image = "docker.io/library/python@sha256:" + "a" * 64
    boot = "e03b068f-8076-48be-a90f-987724d10623"
    vm_uuid = "3b35da2d-cff1-4412-9b26-6b28440b1f18"
    original_read = Path.read_text

    def read_text(path, *args, **kwargs):
        if str(path) == "/proc/sys/kernel/random/boot_id":
            return boot
        return original_read(path, *args, **kwargs)

    def output(argv, **kwargs):
        if argv[0] == "/usr/bin/systemctl":
            return (
                ""
                if bad == "empty_units"
                else (
                    "steward-api.service enabled\n"
                    if bad == "installed_unit" or (bad == "active_unit" and argv[1] == "list-units")
                    else "ssh.service enabled\n"
                )
            )
        if argv[:3] == ("/usr/bin/podman", "ps", "--all"):
            return (
                "{}"
                if bad == "container_object"
                else json.dumps([{}] if bad == "existing_container" else [])
            )
        if argv[:3] == ("/usr/bin/podman", "image", "inspect"):
            return json.dumps([] if bad == "missing_image" else [image])
        if argv[:2] == ("/usr/bin/podman", "info"):
            return "false" if bad == "rootful" else "true"
        if argv[0] == "/usr/bin/sudo":
            return vm_uuid
        raise AssertionError("unexpected guest command")

    monkeypatch.setattr(sys, "argv", ["inspect", image])
    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(subprocess, "check_output", output)
    monkeypatch.setattr(
        pwd,
        "getpwall",
        lambda: [SimpleNamespace(pw_name="stw-other")] if bad == "installed_account" else [],
    )
    monkeypatch.setattr(
        os.path, "lexists", lambda path: bad == "installed_path" and path == "/etc/steward"
    )
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    if bad in ("empty_units", "container_object"):
        with pytest.raises(ValueError):
            exec(harness.GUEST_RESTORE_INSPECT, {})  # noqa: S102 - fixed in-repository probe
    else:
        exec(harness.GUEST_RESTORE_INSPECT, {})  # noqa: S102 - fixed in-repository probe
        result = json.loads(capsys.readouterr().out)
        assert result["platform_units_absent"] is (bad not in ("installed_unit", "active_unit"))
        assert result["platform_accounts_absent"] is (bad != "installed_account")
        assert result["platform_paths_absent"] is (bad != "installed_path")
        assert result["container_count"] == (1 if bad == "existing_container" else 0)
        assert result["image_present"] is (bad != "missing_image")
        assert result["rootless"] is (bad != "rootful")


def test_restore_preflight_cli_uses_recorded_workdir_and_explicit_binding(
    tmp_path, monkeypatch, capsys
):
    import sys

    image = "docker.io/library/python@sha256:" + "a" * 64
    boot = "e03b068f-8076-48be-a90f-987724d10623"
    calls = []

    class FakeHarness:
        def __init__(self, work):
            calls.append(("work", work))

        def guest_restore_preflight(self, actual_boot, actual_image):
            calls.append(("preflight", actual_boot, actual_image))
            return {"rootless": True}

    monkeypatch.setattr(harness, "Harness", FakeHarness)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "harness",
            "--workdir",
            str(tmp_path),
            "restore-preflight",
            "--boot-id",
            boot,
            "--image",
            image,
        ],
    )
    assert harness.main() == 0
    assert calls == [("work", tmp_path.resolve()), ("preflight", boot, image)]
    assert json.loads(capsys.readouterr().out) == {"rootless": True}
