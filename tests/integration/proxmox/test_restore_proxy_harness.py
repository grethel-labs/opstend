"""Ownership and transport guards for the disposable read-only proxy."""

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

SPEC = importlib.util.spec_from_file_location(
    "restore_proxy_harness", Path(__file__).with_name("restore_proxy_harness.py")
)
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)
GUARD_SPEC = importlib.util.spec_from_file_location(
    "restore_proxy_guard", Path(__file__).with_name("proxy_guard.py")
)
guard_module = importlib.util.module_from_spec(GUARD_SPEC)
GUARD_SPEC.loader.exec_module(guard_module)


@pytest.fixture(autouse=True)
def restore_umask():
    previous = os.umask(0o077)
    os.umask(previous)
    try:
        yield
    finally:
        os.umask(previous)


@pytest.mark.parametrize(
    "field,value",
    [
        ("namespace", "foreign"),
        ("namespace", "stw-read-test-../../etc"),
        ("token", "bad"),
        ("port", 22),
        ("upstream_port", 22),
    ],
)
def test_node_guard_rejects_bad_scope_before_commands(tmp_path, field, value):
    payload = {
        "namespace": "stw-read-test-" + "a" * 24,
        "token": "b" * 64,
        "port": 28474,
        "upstream_port": 28473,
        "action": "cleanup",
    }
    payload[field] = value
    commands = Mock(side_effect=AssertionError("no remote commands allowed"))
    with pytest.raises(ValueError):
        guard_module.Guard(
            payload, opt=tmp_path, units=tmp_path, uid=os.geteuid(), command=commands
        )
    commands.assert_not_called()


def test_start_sends_credentials_only_over_stdin_and_keeps_reader_separate(
    tmp_path, monkeypatch, capsys
):
    upstream = tmp_path / "upstream"
    upstream.mkdir(mode=0o700)
    state = {
        "namespace": "stw-rest-test-" + "a" * 24,
        "token": "b" * 64,
        "port": 28473,
        "ssh_config": "/private/ssh-config",
        "alias": "fixture-node",
    }
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    writer = b"writer-secret-" + b"x" * 40
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    for name, data in (
        ("ownership.json", json.dumps(state).encode()),
        ("username", b"fixture"),
        ("auth-password", writer),
        ("cert.pem", cert),
    ):
        path = upstream / name
        path.write_bytes(data)
        path.chmod(0o600)
    work = tmp_path / "proxy"
    calls = []

    def remote(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"active": "active"}))

    monkeypatch.setattr(harness.subprocess, "run", remote)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "restore-proxy",
            "--workdir",
            str(work),
            "start",
            "--upstream-workdir",
            str(upstream),
            "--port",
            "28474",
        ],
    )
    harness.main()
    assert json.loads(capsys.readouterr().out)["active"] == "active"
    argv, kwargs = calls[0]
    assert argv[:3] == ["ssh", "-F", "/private/ssh-config"] and "StrictHostKeyChecking=yes" in argv
    assert writer.decode() not in repr(argv)
    payload = json.loads(kwargs["input"])
    assert payload["action"] == "start" and payload["upstream_namespace"] == state["namespace"]
    assert payload["guard_sha256"] == guard_module.digest(harness.REMOTE.encode())
    assert (work / "auth-password").read_bytes() != writer
    assert b"writer-secret" not in (work / "repository").read_bytes()
    assert (work / "ownership.json").stat().st_mode & 0o777 == 0o600
    assert (work / "auth-password").stat().st_mode & 0o777 == 0o600


def test_start_refuses_unsafe_upstream_before_ssh(tmp_path, monkeypatch):
    upstream = tmp_path / "upstream"
    upstream.mkdir(mode=0o755)
    upstream.chmod(0o755)
    remote = Mock(side_effect=AssertionError("SSH must not run"))
    monkeypatch.setattr(harness.subprocess, "run", remote)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "restore-proxy",
            "--workdir",
            str(tmp_path / "work"),
            "start",
            "--upstream-workdir",
            str(upstream),
            "--port",
            "28474",
        ],
    )
    with pytest.raises(SystemExit):
        harness.main()
    remote.assert_not_called()


def test_status_refuses_option_like_ssh_alias_without_contact(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    record = work / "ownership.json"
    record.write_text(
        json.dumps(
            {
                "alias": "-oProxyCommand=bad",
                "ssh_config": "/unused",
                "guard_sha256": guard_module.digest(harness.REMOTE.encode()),
            }
        )
    )
    record.chmod(0o600)
    remote = Mock(side_effect=AssertionError("SSH must not run"))
    monkeypatch.setattr(harness.subprocess, "run", remote)
    monkeypatch.setattr(sys, "argv", ["restore-proxy", "--workdir", str(work), "status"])
    with pytest.raises(SystemExit):
        harness.main()
    remote.assert_not_called()


@pytest.fixture
def guarded_node(tmp_path):
    opt, units, cgroups = tmp_path / "opt", tmp_path / "units", tmp_path / "cgroups"
    for directory in (opt, units, cgroups):
        directory.mkdir(mode=0o700)
    payload = {
        "namespace": "stw-read-test-" + "a" * 24,
        "token": "b" * 64,
        "port": 28474,
        "upstream_port": 28473,
        "action": "cleanup",
        "file_sha256": {name: guard_module.digest(name.encode()) for name in guard_module.FILES},
    }
    calls = []
    state = {
        "Id": payload["namespace"] + ".service",
        "LoadState": "not-found",
        "ActiveState": "inactive",
        "SubState": "dead",
        "MainPID": "0",
        "ControlGroup": "",
        "KillMode": "control-group",
        "FragmentPath": "",
        "NeedDaemonReload": "no",
    }

    def command(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["systemctl", "show"]:
            return SimpleNamespace(
                stdout="\n".join(f"{key}={value}" for key, value in state.items()), returncode=0
            )
        return SimpleNamespace(stdout="", returncode=0)

    guard = guard_module.Guard(
        payload, opt=opt, units=units, cgroups=cgroups, uid=os.geteuid(), command=command
    )
    return guard, state, calls


def write_owned(path, body, mode=0o600):
    path.write_bytes(body)
    path.chmod(mode)


def populate_guard(guard, *, started=False, unit=False):
    guard.root.mkdir(mode=0o700)
    values = {name: name.encode() for name in guard_module.FILES}
    content = guard_module.unit_content(guard.root, guard.port, guard.upstream_port)
    state = {
        "namespace": guard.name,
        "token": guard.token,
        "port": guard.port,
        "upstream_port": guard.upstream_port,
        "unit_sha256": guard_module.digest(content),
        "files": {name: guard_module.digest(body) for name, body in values.items()},
    }
    write_owned(guard.root / "ownership.json", json.dumps(state).encode())
    for name, body in values.items():
        write_owned(guard.root / name, body, 0o755 if name == "proxy.py" else 0o600)
    if started:
        write_owned(guard.root / "started", ("started:" + guard.token).encode())
    if unit:
        write_owned(guard.unit, content, 0o644)
    return state


def test_partial_staging_is_removed_only_after_quiescence(guarded_node):
    guard, _state, calls = guarded_node
    guard.stage.mkdir(mode=0o700)
    expected = json.dumps(guard._expected_state()).encode()
    write_owned(guard.stage / "ownership.json", expected[:20])
    assert guard.cleanup()["staged_files_removed"]
    assert not guard.stage.exists()
    assert len(calls) == 1 and calls[0][:2] == ["systemctl", "show"]


def test_foreign_staging_symlink_refuses_cleanup_before_systemctl(guarded_node, tmp_path):
    guard, _state, calls = guarded_node
    guard.stage.mkdir(mode=0o700)
    foreign = tmp_path / "foreign"
    foreign.write_text("keep")
    (guard.stage / "reader").symlink_to(foreign)
    with pytest.raises((OSError, ValueError)):
        guard.cleanup()
    assert foreign.read_text() == "keep" and (guard.stage / "reader").is_symlink()
    assert all(call[:2] != ["systemctl", "stop"] for call in calls)


def test_cleanup_refuses_active_or_populated_cgroup_without_deleting_secrets(guarded_node):
    guard, state, calls = guarded_node
    populate_guard(guard, started=True, unit=True)
    state.update(
        LoadState="loaded",
        FragmentPath=str(guard.unit),
        ActiveState="active",
        SubState="running",
        MainPID="123",
    )
    with pytest.raises(ValueError, match="quiescence"):
        guard.cleanup()
    assert guard.unit.exists() and (guard.root / "writer").exists()
    assert any(call[:2] == ["systemctl", "stop"] for call in calls)
    state.update(ActiveState="failed", SubState="failed", MainPID="0", ControlGroup="/fixture")
    group = guard.cgroups / "fixture"
    group.mkdir()
    (group / "cgroup.events").write_text("populated 1\n")
    with pytest.raises(ValueError, match="cgroup"):
        guard.cleanup()
    assert guard.unit.exists() and (guard.root / "writer").exists()


def test_cleanup_of_started_fixture_requires_owned_inactive_service(guarded_node):
    guard, state, _calls = guarded_node
    populate_guard(guard, started=True, unit=True)
    state.update(LoadState="loaded", FragmentPath=str(guard.unit))
    result = guard.cleanup()
    assert result["credentials_removed"] and not guard.unit.exists()
    assert not (guard.root / "writer").exists() and not (guard.root / "reader").exists()
    assert (guard.root / "stopped").read_text() == "stopped:" + guard.token


def test_incomplete_lifecycle_staging_is_recovered_without_weakening_hash_checks(guarded_node):
    guard, state, _calls = guarded_node
    populate_guard(guard, started=True, unit=True)
    state.update(LoadState="loaded", FragmentPath=str(guard.unit))
    write_owned(guard.root / ".stopped-staging", b"stopped:partial")
    assert guard.cleanup()["credentials_removed"]
    assert not (guard.root / ".stopped-staging").exists()
    assert (guard.root / "stopped").read_text() == "stopped:" + guard.token


def test_nonregular_proxy_file_is_rejected_without_blocking(guarded_node):
    guard, _state, calls = guarded_node
    populate_guard(guard)
    (guard.root / "writer").unlink()
    os.mkfifo(guard.root / "writer", 0o600)
    with pytest.raises(ValueError, match="unsafe fixture file"):
        guard.cleanup()
    assert not calls and (guard.root / "writer").exists()


def test_atomic_publish_never_overwrites_existing_target(tmp_path):
    source, target = tmp_path / "source", tmp_path / "target"
    write_owned(source, b"own")
    write_owned(target, b"foreign")
    with pytest.raises(FileExistsError):
        guard_module.rename_no_replace(source, target)
    assert source.read_bytes() == b"own" and target.read_bytes() == b"foreign"


def test_cleanup_refuses_to_stop_unverified_loaded_service(guarded_node):
    guard, state, calls = guarded_node
    populate_guard(guard, started=True, unit=True)
    state.update(
        LoadState="loaded",
        FragmentPath="/unrelated/service",
        ActiveState="active",
        SubState="running",
        MainPID="123",
    )
    with pytest.raises(ValueError, match="identity mismatch"):
        guard.cleanup()
    assert not any(call[:2] == ["systemctl", "stop"] for call in calls)
    assert guard.unit.exists() and (guard.root / "writer").exists()


def test_incomplete_unit_and_start_markers_can_be_cleaned_before_start(guarded_node):
    guard, _state, _calls = guarded_node
    populate_guard(guard)
    write_owned(guard.unit_stage, b"partial unit")
    write_owned(guard.root / ".started-staging", b"partial marker")
    assert guard.cleanup()["credentials_removed"]
    assert not guard.unit_stage.exists() and not (guard.root / ".started-staging").exists()
    assert not (guard.root / "writer").exists()


def test_cleanup_requires_explicit_cgroup_property(guarded_node):
    guard, state, _calls = guarded_node
    populate_guard(guard)
    del state["ControlGroup"]
    with pytest.raises(ValueError, match="cgroup identity"):
        guard.cleanup()
    assert (guard.root / "writer").exists()


def test_status_requires_exact_live_unit_identity_and_process(guarded_node, monkeypatch):
    guard, state, _calls = guarded_node
    populate_guard(guard, started=True, unit=True)
    state.update(
        LoadState="loaded",
        FragmentPath=str(guard.unit),
        ActiveState="active",
        SubState="running",
        MainPID="123",
        ControlGroup="/system.slice/fixture.service",
    )
    monkeypatch.setattr(guard, "probe", lambda: {"write_refused": 405})
    assert guard.status()["probe"]["write_refused"] == 405
    state["FragmentPath"] = "/unrelated/unit"
    with pytest.raises(ValueError, match="identity"):
        guard.status()
    state["FragmentPath"] = str(guard.unit)
    state["MainPID"] = "0"
    with pytest.raises(ValueError, match="identity"):
        guard.status()


def test_start_refuses_stale_upstream_unit_before_creating_namespace(guarded_node):
    guard, state, calls = guarded_node
    upstream_name = "stw-rest-test-" + "d" * 24
    upstream = guard.opt / upstream_name
    upstream.mkdir(mode=0o711)
    upstream.chmod(0o711)
    binary, unit = b"rest-server-fixture", b"unit-fixture"
    write_owned(upstream / "rest-server", binary, 0o755)
    upstream_unit = guard.units / (upstream_name + ".service")
    write_owned(upstream_unit, unit, 0o644)
    marker = {
        "namespace": upstream_name,
        "token": "e" * 64,
        "port": guard.upstream_port,
        "binary_sha256": guard_module.digest(binary),
        "unit_sha256": guard_module.digest(unit),
    }
    write_owned(upstream / "ownership.json", json.dumps(marker).encode())
    guard.p.update(upstream_namespace=upstream_name, upstream_token="e" * 64)
    state.update(
        Id=upstream_name + ".service",
        LoadState="loaded",
        ActiveState="active",
        SubState="running",
        MainPID="123",
        FragmentPath="/foreign/unit",
        NeedDaemonReload="no",
    )
    with pytest.raises(ValueError, match="upstream service identity"):
        guard.start()
    assert not guard.root.exists() and not guard.stage.exists() and not guard.unit.exists()
    assert len(calls) == 1 and calls[0][:2] == ["systemctl", "show"]


def test_status_refuses_changed_guard_before_contact(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    write_owned(
        work / "ownership.json",
        json.dumps(
            {"alias": "fixture-node", "ssh_config": "/unused", "guard_sha256": "0" * 64}
        ).encode(),
    )
    remote = Mock(side_effect=AssertionError("SSH must not run"))
    monkeypatch.setattr(harness.subprocess, "run", remote)
    monkeypatch.setattr(sys, "argv", ["restore-proxy", "--workdir", str(work), "status"])
    with pytest.raises(SystemExit):
        harness.main()
    remote.assert_not_called()


def test_cleanup_recovers_interruption_after_unit_unlink(guarded_node):
    guard, state, calls = guarded_node
    populate_guard(guard, started=True)
    write_owned(guard.root / "stopped", ("stopped:" + guard.token).encode())
    state.update(LoadState="loaded", FragmentPath=str(guard.unit), NeedDaemonReload="yes")
    original = guard.command

    def reload_then_forget(argv, **kwargs):
        result = original(argv, **kwargs)
        if argv == ["systemctl", "daemon-reload"]:
            state.update(LoadState="not-found", FragmentPath="", NeedDaemonReload="no")
        return result

    guard.command = reload_then_forget
    assert guard.cleanup()["credentials_removed"]
    assert not (guard.root / "writer").exists()
    assert ["systemctl", "daemon-reload"] in calls
    assert not any(call[:2] == ["systemctl", "stop"] for call in calls)


def test_staging_is_bound_to_namespace_as_well_as_token(guarded_node):
    guard, _state, calls = guarded_node
    guard.stage.mkdir(mode=0o700)
    write_owned(guard.stage / "writer", b"partial")
    other = guard_module.Guard(
        {**guard.p, "namespace": "stw-read-test-" + "c" * 24},
        opt=guard.opt,
        units=guard.units,
        cgroups=guard.cgroups,
        uid=os.geteuid(),
        command=guard.command,
    )
    assert other.stage != guard.stage and other.unit_stage != guard.unit_stage
    with pytest.raises(FileNotFoundError):
        other.cleanup()
    assert (guard.stage / "writer").read_bytes() == b"partial" and not calls


@pytest.mark.parametrize(
    "marker",
    [None, {"namespace": "foreign", "token": "b" * 64, "port": 28474, "upstream_port": 28473}],
)
def test_complete_staging_marker_with_wrong_scope_is_not_removed(guarded_node, marker):
    guard, _state, _calls = guarded_node
    guard.stage.mkdir(mode=0o700)
    write_owned(guard.stage / "ownership.json", json.dumps(marker).encode())
    with pytest.raises(ValueError, match="staged ownership mismatch"):
        guard.cleanup()
    assert (guard.stage / "ownership.json").exists()


def test_node_refuses_equal_reader_writer_passwords_before_staging(guarded_node, monkeypatch):
    import base64
    import socket

    guard, _state, _calls = guarded_node
    monkeypatch.setattr(guard, "_upstream", lambda: None)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        guard.port = sock.getsockname()[1]
    if guard.port == guard.upstream_port:
        guard.upstream_port = guard.port - 1
    files = {name: name.encode() for name in guard_module.FILES}
    files["reader"] = b"reader:" + b"x" * 48
    files["writer"] = b"writer:" + b"x" * 48
    guard.p["files"] = {name: base64.b64encode(body).decode() for name, body in files.items()}
    guard.p["file_sha256"] = {name: guard_module.digest(body) for name, body in files.items()}
    guard.p["proxy_sha256"] = guard_module.digest(files["proxy.py"])
    with pytest.raises(ValueError, match="separate fixture credentials"):
        guard.start()
    assert not guard.stage.exists() and not guard.root.exists() and not guard.unit.exists()


@pytest.mark.parametrize("body", [b"\xff", b"garbage", b'{"namespace":"foreign"}garbage'])
def test_corrupt_staging_marker_is_not_treated_as_interruption(guarded_node, body):
    guard, _state, _calls = guarded_node
    guard.stage.mkdir(mode=0o700)
    write_owned(guard.stage / "ownership.json", body)
    with pytest.raises(ValueError, match="staged ownership mismatch"):
        guard.cleanup()
    assert (guard.stage / "ownership.json").read_bytes() == body


def test_only_exact_marker_prefix_may_be_cleaned_after_interrupted_write(guarded_node):
    guard, _state, _calls = guarded_node
    guard.stage.mkdir(mode=0o700)
    expected = json.dumps(guard._expected_state()).encode()
    write_owned(guard.stage / "ownership.json", expected[:-1])
    assert guard.cleanup()["staged_files_removed"]
    assert not guard.stage.exists()


def test_complete_fixture_lifecycle_publishes_and_removes_credentials(guarded_node, monkeypatch):
    import base64
    import socket

    guard, state, calls = guarded_node
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        guard.port = sock.getsockname()[1]
    guard.p["port"] = guard.port
    files = {name: name.encode() for name in guard_module.FILES}
    files["reader"] = b"reader:" + b"r" * 48
    files["writer"] = b"writer:" + b"w" * 48
    guard.p["files"] = {name: base64.b64encode(body).decode() for name, body in files.items()}
    guard.p["file_sha256"] = {name: guard_module.digest(body) for name, body in files.items()}
    guard.p["proxy_sha256"] = guard_module.digest(files["proxy.py"])
    monkeypatch.setattr(guard, "_upstream", lambda: None)
    monkeypatch.setattr(guard, "probe", lambda: {"write_refused": 405})

    def command(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["systemctl", "daemon-reload"]:
            state.update(
                LoadState="loaded" if guard.unit.exists() else "not-found",
                FragmentPath=str(guard.unit) if guard.unit.exists() else "",
            )
        elif argv[:2] == ["systemctl", "start"]:
            state.update(
                ActiveState="active", SubState="running", MainPID="123", ControlGroup="/fixture"
            )
        elif argv[:2] == ["systemctl", "stop"]:
            state.update(ActiveState="inactive", SubState="dead", MainPID="0", ControlGroup="")
        return SimpleNamespace(
            stdout="\n".join(f"{key}={value}" for key, value in state.items()), returncode=0
        )

    guard.command = command
    assert guard.start()["active"] == "active"
    assert guard.status()["probe"]["write_refused"] == 405
    assert not guard.stage.exists()
    assert guard.cleanup()["credentials_removed"] is True
    assert not guard.unit.exists()
    assert all(not (guard.root / name).exists() for name in ("key.pem", "reader", "writer"))


@pytest.mark.parametrize("interruption", range(1, len(guard_module.FILES) + 2))
def test_interrupted_staging_cleanup_can_be_retried(guarded_node, monkeypatch, interruption):
    guard, _, _ = guarded_node
    guard.stage.mkdir(mode=0o700)
    write_owned(guard.stage / "ownership.json", json.dumps(guard._expected_state()).encode())
    for name in guard_module.FILES:
        write_owned(guard.stage / name, name.encode())
    original = Path.unlink
    count = 0

    def interrupted_unlink(path, *args, **kwargs):
        nonlocal count
        original(path, *args, **kwargs)
        if path.parent == guard.stage:
            count += 1
            if count == interruption:
                raise OSError("simulated interruption")

    monkeypatch.setattr(Path, "unlink", interrupted_unlink)
    with pytest.raises(OSError, match="simulated interruption"):
        guard.cleanup()
    monkeypatch.setattr(Path, "unlink", original)
    assert guard.cleanup()["staged_files_removed"] is True
    assert not guard.stage.exists()
