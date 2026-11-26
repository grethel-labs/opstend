import copy
import json
import os

import pytest

from steward import application_layout as layout
from steward.core.ids import graph_identifier
from steward.executor import host as host_module

UID = 31000
GID = 31001
IDENTITY = {"uid": UID, "gid": GID, "subuid": [100000, 65536], "subgid": [300000, 65536]}
UID_MAP = f"0 100000 10001\n10001 {UID} 1\n10002 110001 55535\n"
GID_MAP = f"0 300000 10001\n10001 {GID} 1\n10002 310001 55535\n"
APP = "mixed-example"
POD_STEM = graph_identifier("a", APP)
USER = "stw-" + POD_STEM
POD_UNIT = POD_STEM + "-pod.service"
POD_NAME = "steward-" + POD_STEM


def configuration(*services):
    items = []
    for service, uid, deploy in services:
        stem = graph_identifier("s", APP, service)
        items.append(
            {
                "id": service,
                "user": USER,
                "unit": stem + ".service",
                "filename": stem + ".container",
                "deploy": deploy,
                "data_source": str(layout.DATA_ROOT / "applications" / APP / "data" / service),
                "data_owner_container_uid": uid,
                "data_needs_mapped_owner": uid != 10001,
            }
        )
    return {
        "application": {
            "id": APP,
            "isolation": "shared",
            "pod": {"user": USER, "unit": POD_UNIT, "filename": POD_STEM + ".pod"},
            "services": items,
        },
        "ids": {USER: {**IDENTITY, "changed": False}},
    }


def test_exact_directory_preserves_existing_mode_owner_and_data(tmp_path, monkeypatch):
    uid, gid = os.geteuid(), os.getegid()
    data = tmp_path / "data"
    assert layout.exact_directory(data, uid, gid, 0o700, create=True)
    (data / "content").write_text("keep")
    monkeypatch.setattr(os, "fchown", lambda *args: pytest.fail("unexpected ownership mutation"))
    assert not layout.exact_directory(data, uid, gid, 0o700, create=True)
    for owner, group, mode in [(uid + 1, gid, 0o700), (uid, gid + 1, 0o700), (uid, gid, 0o750)]:
        with pytest.raises(ValueError, match="unexpected type, ownership or mode"):
            layout.exact_directory(data, owner, group, mode, create=True)
    link = tmp_path / "link"
    link.symlink_to(data)
    with pytest.raises(ValueError, match="unexpected type, ownership or mode"):
        layout.exact_directory(link, uid, gid, 0o700, create=True)
    assert (data / "content").read_text() == "keep"
    assert data.stat().st_mode & 0o777 == 0o700
    assert link.is_symlink()


@pytest.mark.parametrize("existing_mode", [0o700, 0o750])
@pytest.mark.parametrize("contains_data", [False, True])
def test_publish_preserves_existing_leaf_after_collision(
    tmp_path, monkeypatch, existing_mode, contains_data
):
    path = tmp_path / "service"
    rename = layout.rename_noreplace

    def collide(*args):
        path.mkdir(mode=existing_mode)
        if contains_data:
            (path / "content").write_text("preserve")
        original = path.stat()
        try:
            rename(*args)
        finally:
            assert path.stat() == original

    monkeypatch.setattr(layout, "rename_noreplace", collide)
    if existing_mode == 0o700:
        assert not layout.publish_mapped_directory(path, os.geteuid(), os.getegid())
    else:
        with pytest.raises(ValueError, match="unexpected type, ownership or mode"):
            layout.publish_mapped_directory(path, os.geteuid(), os.getegid())
    assert [entry.name for entry in tmp_path.iterdir()] == ["service"]
    assert [entry.name for entry in path.iterdir()] == (["content"] if contains_data else [])
    if contains_data:
        assert (path / "content").read_text() == "preserve"


@pytest.mark.parametrize("operation", ["fchown", "fsync"])
def test_publish_leaves_final_path_available_after_failed_staging(tmp_path, monkeypatch, operation):
    path = tmp_path / "service"

    def fail(*args):
        raise OSError("cannot prepare staging")

    with monkeypatch.context() as patch:
        patch.setattr(os, operation, fail)
        with pytest.raises(OSError, match="cannot prepare staging"):
            layout.publish_mapped_directory(path, os.geteuid(), os.getegid())
    assert list(tmp_path.iterdir()) == []
    assert layout.publish_mapped_directory(path, os.geteuid(), os.getegid())
    assert path.stat().st_mode & 0o777 == 0o700


def test_directory_phase_preserves_default_layout_and_defers_mapped_leaves(monkeypatch):
    checked = {}
    monkeypatch.setattr(layout, "protected_ancestors", lambda path: None)

    def record(path, uid, gid, mode, *, create=False):
        if create:
            checked[path.name] = (uid, gid, mode)
        return create

    monkeypatch.setattr(layout, "exact_directory", record)
    assert layout.ensure_layout(configuration(("default", 10001, True), ("mapped", 10002, True)))
    assert checked["default"] == (UID, GID, 0o700)
    assert checked["data"] == (0, 0, 0o755)
    assert checked[str(UID)] == (0, 0, 0o755)
    assert "mapped" not in checked


@pytest.fixture
def mapped_layout(monkeypatch):
    monkeypatch.setattr(layout, "protected_ancestors", lambda path: None)
    monkeypatch.setattr(layout, "pinned_account", lambda user, pin: None)
    host = host_module.Host()

    def maps(user, unit, uid):
        assert (user, unit, uid) == (USER, POD_UNIT, UID)
        return UID_MAP, GID_MAP

    monkeypatch.setattr(host, "application_infra_maps", maps)
    return host


def test_mapped_phase_distinguishes_uid_gid_and_is_idempotent(monkeypatch, mapped_layout):
    recorded = {}

    def directory(path, uid, gid, mode, *, create=False):
        if mode != 0o700:
            assert not create
            return False
        expected = (uid, gid, mode)
        if path not in recorded:
            if not create:
                raise FileNotFoundError
            recorded[path] = expected
            return True
        assert recorded[path] == expected
        return False

    monkeypatch.setattr(layout, "exact_directory", directory)
    monkeypatch.setattr(
        layout,
        "publish_mapped_directory",
        lambda path, uid, gid: directory(path, uid, gid, 0o700, create=True),
    )
    config = configuration(
        ("default", 10001, True), ("mapped", 10002, True), ("disabled", 2_000, False)
    )
    with pytest.raises(FileNotFoundError):
        layout.verify_mapped_layout(mapped_layout, config)
    assert not recorded
    assert layout.verify_mapped_layout(mapped_layout, config, create=True)
    assert {path.name: owner for path, owner in recorded.items()} == {
        "mapped": (110001, 310001, 0o700)
    }
    assert not layout.verify_mapped_layout(mapped_layout, config, create=True)
    assert not layout.verify_mapped_layout(mapped_layout, config)


def test_mapped_phase_checks_every_existing_leaf_before_creation(monkeypatch, mapped_layout):
    def directory(path, uid, gid, mode, *, create=False):
        assert not create
        if path.name == "absent":
            raise FileNotFoundError
        if path.name == "wrong":
            raise ValueError("wrong owner")
        return False

    monkeypatch.setattr(layout, "exact_directory", directory)
    monkeypatch.setattr(
        layout, "publish_mapped_directory", lambda *args: pytest.fail("unexpected publication")
    )
    with pytest.raises(ValueError, match="wrong owner"):
        layout.verify_mapped_layout(
            mapped_layout,
            configuration(("absent", 10002, True), ("wrong", 10003, True)),
            create=True,
        )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("id", "../outside"),
        ("unit", "foreign.service"),
        ("user", "root"),
        ("data_source", "/tmp/unrelated"),
        ("data_needs_mapped_owner", False),
    ],
)
def test_mapped_phase_rejects_inconsistent_binding(mapped_layout, key, value):
    config = configuration(("mapped", 10002, True))
    config["application"]["services"][0][key] = value
    with pytest.raises(ValueError, match="invalid application service"):
        layout.verify_mapped_layout(mapped_layout, config, create=True)


def test_mapped_phase_skips_disabled_even_without_pod_observation(monkeypatch, mapped_layout):
    monkeypatch.setattr(
        layout, "pinned_account", lambda *args: pytest.fail("unexpected identity read")
    )
    assert not layout.verify_mapped_layout(
        mapped_layout, configuration(("disabled", 10002, False)), create=True
    )


@pytest.mark.parametrize(
    "rows",
    [
        "",
        UID_MAP.replace(f"10001 {UID} 1", f"10001 {UID + 1} 1"),
        UID_MAP.replace("110001", "90000"),
        UID_MAP.replace("10002 110001", "10000 110001"),
        UID_MAP.replace("110001", "110000"),
        UID_MAP.replace("55535", "0"),
        UID_MAP.replace("55535", "4294967295"),
        UID_MAP + "10 160000 -1",
        UID_MAP + "10 160000 1 unexpected",
    ],
)
def test_namespace_map_refuses_invalid_or_unconfined_ranges(rows):
    with pytest.raises(ValueError):
        layout.parse_id_map(rows, UID, IDENTITY["subuid"])


def test_namespace_map_refuses_unmapped_configured_target():
    spans = layout.parse_id_map(f"10001 {UID} 1\n", UID, IDENTITY["subuid"])
    with pytest.raises(ValueError, match="unmapped"):
        layout.translated_id(spans, 10002)


@pytest.fixture
def running_infra(tmp_path, monkeypatch):
    host = host_module.Host()
    pod_id, infra_id = "a" * 64, "b" * 64
    cgroup = (
        f"/user.slice/user-{UID}.slice/user@{UID}.service/user.slice/"
        f"user-libpod_pod_{pod_id}.slice/libpod-{infra_id}.scope"
    )
    pid = 10000
    process = tmp_path / str(pid)
    (process / "ns").mkdir(parents=True)
    (process / "ns" / "user").touch()
    (process / "stat").write_text(f"{pid} (podman pause) S" + (" 0" * 18) + " 1234\n")
    (process / "uid_map").write_text(UID_MAP)
    (process / "gid_map").write_text(GID_MAP)
    (process / "cgroup").write_text(f"0::{cgroup}/container\n")
    pod = {
        "id": pod_id,
        "infra": infra_id,
        "name": POD_NAME,
        "unit": POD_UNIT,
        "members": [{"Id": infra_id, "Name": POD_NAME + "-infra", "State": "running"}],
    }
    infra = {
        "id": infra_id,
        "name": POD_NAME + "-infra",
        "pod": pod_id,
        "infra": True,
        "unit": POD_UNIT,
        "userns": "private",
        "state": {
            "Pid": pid,
            "Status": "running",
            "Running": True,
            "Paused": False,
            "Restarting": False,
            "Dead": False,
            "CgroupPath": cgroup,
            "StartedAt": "now",
        },
    }
    calls = []

    def inspect(user, argv):
        assert user == USER
        kind = argv[1]
        assert argv == (
            ["podman", "pod", "inspect", "--format", host_module.POD_INSPECT, POD_NAME]
            if kind == "pod"
            else ["podman", "container", "inspect", "--format", host_module.INFRA_INSPECT, infra_id]
        )
        record = copy.deepcopy(pod if kind == "pod" else infra)
        if len(calls) == 3 and "change" in infra:
            record["state"]["Pid"] += 1
        calls.append(argv)
        return 0, json.dumps(record)

    monkeypatch.setattr(host_module, "PROC_ROOT", tmp_path)
    monkeypatch.setattr(host, "_as_user", inspect)
    return host, pod, infra, process


def test_stable_running_infra_provides_kernel_maps(running_infra):
    host, _, _, _ = running_infra
    assert host.application_infra_maps(USER, POD_UNIT, UID) == (UID_MAP, GID_MAP)


@pytest.mark.parametrize(
    ("source", "key", "value"),
    [
        ("pod", "name", "foreign"),
        ("pod", "members", []),
        ("infra", "unit", "foreign.service"),
        ("infra", "infra", False),
        ("infra", "pod", "c" * 64),
        ("infra", "userns", "host"),
        ("infra", "change", True),
        ("state", "Pid", True),
        ("state", "Status", "exited"),
        ("state", "Paused", True),
    ],
)
def test_infra_observation_rejects_unexpected_or_unstable_identity(
    running_infra, source, key, value
):
    host, pod, infra, _ = running_infra
    {"pod": pod, "infra": infra, "state": infra["state"]}[source][key] = value
    with pytest.raises(ValueError):
        host.application_infra_maps(USER, POD_UNIT, UID)


@pytest.mark.parametrize(("name", "data"), [("cgroup", "0::/foreign\n"), ("stat", "bogus")])
def test_infra_observation_rejects_unrelated_proc_entries(running_infra, name, data):
    host, _, _, process = running_infra
    (process / name).write_text(data)
    with pytest.raises(ValueError):
        host.application_infra_maps(USER, POD_UNIT, UID)


def test_infra_observation_rejects_changed_namespace(running_infra, monkeypatch):
    host, _, _, _ = running_infra
    observations = iter(((1234, 5, 30), (1234, 5, 31)))
    monkeypatch.setattr(host_module, "process_namespace", lambda path: next(observations))
    with pytest.raises(ValueError, match="changed during inspection"):
        host.application_infra_maps(USER, POD_UNIT, UID)
