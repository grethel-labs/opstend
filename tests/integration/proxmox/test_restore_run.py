"""Controller binding and credential boundaries for the owned-VM restore fixture."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from steward.core.backups import Binding, FilesystemCapture, Receipt
from steward.restore_drill import DrillSpec

spec = importlib.util.spec_from_file_location(
    "restore_run", Path(__file__).with_name("restore_run.py")
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def put(path, body, mode=0o600):
    path.write_bytes(body)
    path.chmod(mode)


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    source = tmp_path / "source"
    target = tmp_path / "target"
    proxy = tmp_path / "proxy"
    for directory in (source, target, proxy):
        directory.mkdir(mode=0o700)
    vm_uuid = "3b35da2d-cff1-4412-9b26-6b28440b1f18"
    boot = "e03b068f-8076-48be-a90f-987724d10623"
    states = {
        str(source): {
            "node": "node",
            "vmid": 100,
            "smbios1": "uuid=b824f4ce-d276-44d1-9334-e5a1d7c33a78",
            "alias": "node",
            "ssh_config": "/ssh/config",
        },
        str(target): {
            "node": "node",
            "vmid": 101,
            "smbios1": "uuid=" + vm_uuid,
            "alias": "node",
            "ssh_config": "/ssh/config",
        },
    }
    for folder in (source, target):
        put(folder / "ownership.json", json.dumps(states[str(folder)]).encode())
    binding = Binding(
        server="fixture",
        project="notes",
        config_revision="a" * 64,
        image="docker.io/library/python@sha256:" + "b" * 64,
        source_revision="bundled:sample-notes@0.1.1",
    )
    capture = FilesystemCapture(
        binding=binding,
        created_at=1,
        completed_at=2,
        size=1,
        sha256="c" * 64,
        entries=1,
        data_bytes=1,
    )
    receipt = Receipt(
        capture=capture,
        repository_id="d" * 64,
        snapshot_id="e" * 64,
        snapshot_path="/fixture",
        snapshot_created_at=3,
        recorded_at=4,
        integrity_checked_at=5,
    )
    app_sha = runner.SOURCE_SHA256
    drill = DrillSpec(
        repository_id=receipt.repository_id,
        snapshot_id=receipt.snapshot_id,
        capture_id=capture.id,
        binding=binding,
        app_sha256=app_sha,
        note_sha256="1" * 64,
        attachment_sha256="2" * 64,
    )
    receipt_path, spec_path = tmp_path / "receipt", tmp_path / "spec"
    put(receipt_path, receipt.model_dump_json().encode())
    put(spec_path, drill.model_dump_json().encode())
    proof = {
        "passed": True,
        "vmid": 101,
        "old_uuid": "137724e2-31ff-4c9b-9700-fbb5cb40a713",
        "new_uuid": vm_uuid,
        "cloud_init_done": True,
        "fresh_strict_ssh": True,
        "node_identity_resource_guard": True,
        "no_application_or_restore_installed": True,
        "guest": {
            "uuid": vm_uuid,
            "boot_id": boot,
            "platform_paths_absent": {
                name: True
                for name in (
                    "/etc/steward",
                    "/opt/steward",
                    "/srv/steward",
                    "/var/lib/steward-executor",
                    "/var/lib/steward-backup",
                    "/var/lib/steward-backup-import",
                )
            },
            "platform_users_present": {
                name: False for name in ("steward-backup", "steward-api", "stw-notes")
            },
        },
    }
    proof_path = tmp_path / "proof"
    put(proof_path, json.dumps(proof).encode())
    binary = tmp_path / "restic"
    put(binary, b"binary", 0o700)
    password = tmp_path / "password"
    put(password, b"p" * 48)
    report = {
        "repository_id": receipt.repository_id,
        "snapshot_id": receipt.snapshot_id,
        "capture_id": capture.id,
        "binding": binding.model_dump(mode="json"),
        "app_sha256": app_sha,
        "health": "ok",
        "note_readback": True,
        "attachment_readback": True,
        "fresh_vm_proven": False,
        "production_restore_authorized": False,
        "bytes_verified_at": 10.0,
        "application_verified_at": 11.0,
    }
    sent = []

    class FakeHarness:
        def __init__(self, path):
            self.path = str(path)
            self.state = states[self.path]

        def guest_identity(self, actual_boot):
            return {"uuid": self.state["smbios1"].removeprefix("uuid="), "boot_id": actual_boot}

        def guest_restore_preflight(self, actual_boot, image):
            assert actual_boot == boot and image == binding.image
            return {"uuid": vm_uuid, "boot_id": boot, "uid": os.geteuid()}

    monkeypatch.setattr(runner.harness, "Harness", FakeHarness)
    monkeypatch.setattr(runner.harness, "owned_pair", lambda source, target: (None, None))
    monkeypatch.setattr(runner, "archive_commit", lambda repo, commit: b"archive")
    monkeypatch.setattr(runner, "archive_app_sha", lambda archive: app_sha)
    monkeypatch.setattr(
        runner,
        "proxy_inputs",
        lambda path, target: (
            {"namespace": "stw-read-test-example"},
            {
                "repository": b"reader-repo",
                "username": b"reader",
                "auth-password": b"r" * 48,
                "ca.pem": b"ca",
            },
        ),
    )

    def send(target, state, action, files=None):
        sent.append((state, action, files))
        return {"report": report, "workspace_removed": True}

    monkeypatch.setattr(runner, "send", send)
    args = SimpleNamespace(
        source_workdir=source,
        target_workdir=target,
        proxy_workdir=proxy,
        source_boot_id=boot,
        fresh_proof=proof_path,
        receipt=receipt_path,
        spec=spec_path,
        repo=tmp_path,
        commit="3" * 40,
        restic_binary=binary,
        restic_sha256=hashlib.sha256(b"binary").hexdigest(),
        password_file=password,
        workdir=tmp_path / "run",
    )
    return args, receipt, drill, report, proof, sent


def test_complete_controller_flow_transfers_reader_only_and_writes_bound_evidence(scenario, capsys):
    args, receipt, drill, _, _, sent = scenario
    runner.start(args)
    state, action, files = sent[0]
    assert action == "run" and set(files) == runner.guest.FILES
    assert files["username"] == b"reader" and files["auth-password"] == b"r" * 48
    assert b"writer" not in b" ".join(files.values())
    assert state["files"] == {name: runner.digest(value) for name, value in files.items()}
    evidence = json.loads((args.workdir / "evidence.json").read_text())
    assert evidence["report"]["snapshot_id"] == receipt.snapshot_id
    assert evidence["report"]["capture_id"] == drill.capture_id
    assert evidence["production_restore_authorized"] is False
    assert (args.workdir / "ownership.json").stat().st_mode & 0o077 == 0
    assert json.loads(capsys.readouterr().out)["passed"] is True


@pytest.mark.parametrize("field", ["repository_id", "snapshot_id", "capture_id", "app_sha256"])
def test_controller_rejects_wrong_binding_before_guest_transfer(scenario, field):
    args, _, drill, _, _, sent = scenario
    changed = drill.model_copy(update={field: "9" * 64})
    put(args.spec, changed.model_dump_json().encode())
    with pytest.raises(ValueError, match="mismatch"):
        runner.start(args)
    assert not sent and not args.workdir.exists()


@pytest.mark.parametrize(
    "damage", ["not_fresh", "missing_path", "missing_user", "wrong_uuid", "same_uuid"]
)
def test_controller_rejects_incomplete_or_wrong_fresh_proof(scenario, damage):
    args, _, _, _, proof, sent = scenario
    if damage == "not_fresh":
        proof["no_application_or_restore_installed"] = False
    elif damage == "missing_path":
        proof["guest"]["platform_paths_absent"].pop("/etc/steward")
    elif damage == "missing_user":
        proof["guest"]["platform_users_present"].pop("stw-notes")
    elif damage == "wrong_uuid":
        proof["new_uuid"] = "137724e2-31ff-4c9b-9700-fbb5cb40a713"
    else:
        proof["old_uuid"] = proof["new_uuid"]
    put(args.fresh_proof, json.dumps(proof).encode())
    with pytest.raises(ValueError, match="fresh guest proof"):
        runner.start(args)
    assert not sent and not args.workdir.exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("health", "bad"),
        ("workspace_removed", False),
        ("fresh_vm_proven", True),
        ("bytes_verified_at", float("nan")),
        ("snapshot_id", "9" * 64),
    ],
)
def test_controller_refuses_invalid_guest_report(scenario, monkeypatch, field, value):
    args, _, _, report, _, _ = scenario
    if field != "workspace_removed":
        report[field] = value
    monkeypatch.setattr(
        runner,
        "send",
        lambda *a, **k: {
            "report": report,
            "workspace_removed": value if field == "workspace_removed" else True,
        },
    )
    with pytest.raises(RuntimeError, match="does not match"):
        runner.start(args)
    assert (args.workdir / "ownership.json").exists()
    assert not (args.workdir / "evidence.json").exists()


def test_private_reader_rejects_symlinks_and_insecure_files(tmp_path):
    original = tmp_path / "secret"
    put(original, b"fixture")
    alias = tmp_path / "alias"
    alias.symlink_to(original)
    with pytest.raises(OSError):
        runner.read_file(alias, maximum=100)
    original.chmod(0o644)
    with pytest.raises(ValueError, match="unsafe fixture input"):
        runner.read_file(original, maximum=100)


def test_proxy_reader_status_and_files_are_bound_without_writer_transfer(tmp_path, monkeypatch):
    proxy = tmp_path / "proxy"
    proxy.mkdir(mode=0o700)
    reader = b"reader"
    password = b"r" * 48
    certificate = b"certificate"
    port = 28474
    record = {
        "namespace": "stw-read-test-" + "a" * 24,
        "alias": "node",
        "ssh_config": "/ssh/config",
        "port": port,
        "file_sha256": {
            "reader": runner.digest(reader + b":" + password),
            "certificate.pem": runner.digest(certificate),
        },
    }
    put(proxy / "ownership.json", json.dumps(record).encode())
    for name, body in (
        ("username", reader),
        ("auth-password", password),
        ("ca.pem", certificate),
        ("repository", f"rest:https://10.0.2.2:{port}/fixture/fixture/".encode()),
    ):
        put(proxy / name, body)
    status = {
        "namespace": record["namespace"],
        "active": "active",
        "probe": {"unauthenticated": 401, "authenticated_read": 200, "write_refused": 405},
    }
    calls = []
    monkeypatch.setattr(
        runner.subprocess,
        "check_output",
        lambda argv, **kw: calls.append(argv) or json.dumps(status),
    )
    target = SimpleNamespace(state={"alias": "node", "ssh_config": "/ssh/config"})
    got, credentials = runner.proxy_inputs(proxy, target)
    assert got == record and credentials["auth-password"] == password
    assert set(credentials) == {"repository", "username", "auth-password", "ca.pem"}
    assert calls and "status" in calls[0]
    status["probe"]["write_refused"] = 200
    with pytest.raises(ValueError, match="not verified"):
        runner.proxy_inputs(proxy, target)
    put(proxy / "auth-password", b"other-secret")
    calls.clear()
    with pytest.raises(ValueError, match="binding mismatch"):
        runner.proxy_inputs(proxy, target)
    assert not calls


def test_rejects_invalid_repository_password_before_transfer(scenario):
    args, _, _, _, _, sent = scenario
    put(args.password_file, b"short")
    with pytest.raises(ValueError, match="repository password"):
        runner.start(args)
    assert not sent and not args.workdir.exists()


def test_repository_password_must_differ_from_proxy_reader_password(scenario, monkeypatch):
    args, _, _, _, _, sent = scenario
    put(args.password_file, b"r" * 48 + b"\n")
    monkeypatch.setattr(
        runner,
        "proxy_inputs",
        lambda path, target: (
            {"namespace": "stw-read-test-example"},
            {
                "repository": b"reader-repo",
                "username": b"reader",
                "auth-password": b"r" * 48,
                "ca.pem": b"ca",
            },
        ),
    )
    with pytest.raises(ValueError, match="passwords must differ"):
        runner.start(args)
    assert not sent and not args.workdir.exists()


def test_reusable_runner_rejects_forged_bundle_even_when_commit_and_spec_match(
    scenario, monkeypatch
):
    args, _, drill, _, _, sent = scenario
    forged = "9" * 64
    put(args.spec, drill.model_copy(update={"app_sha256": forged}).model_dump_json().encode())
    monkeypatch.setattr(runner, "archive_app_sha", lambda archive: forged)
    with pytest.raises(ValueError, match="mismatch"):
        runner.start(args)
    assert not sent and not args.workdir.exists()
