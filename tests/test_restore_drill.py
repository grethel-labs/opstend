import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path

import pytest

from steward.core.backups import BackupError, Binding, Receipt
from steward.core.filebackups import capture_files, materialize_tree
from steward.restore_drill import DrillSpec, PodmanSample, run_drill


@pytest.fixture
def setup_drill(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    note, attachment = "saved test note", b"saved test attachment"
    attachment_id = hashlib.sha256(attachment).hexdigest()
    (data / "attachments").mkdir()
    (data / "attachments" / attachment_id).write_bytes(attachment)
    with sqlite3.connect(data / "notes.db") as db:
        db.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, created_at REAL, text TEXT)")
        db.execute("INSERT INTO notes VALUES (1, 1, ?)", (note,))
    binding = Binding(
        server="fixture-server",
        project="notes",
        config_revision="a" * 64,
        image="docker.io/library/python@sha256:" + "b" * 64,
        source_revision="bundled:sample-notes@0.1.1",
    )
    capture = tmp_path / "capture"
    manifest = capture_files(data, capture, binding, is_quiescent=lambda: True)
    receipt = Receipt(
        capture=manifest,
        repository_id="c" * 64,
        snapshot_id="d" * 64,
        snapshot_path="/fixture/capture",
        snapshot_created_at=1,
        recorded_at=1,
    )
    app = Path(__file__).resolve().parents[1] / "sample-app/sample-notes/app.py"
    app_hash = hashlib.sha256(app.read_bytes()).hexdigest()
    spec = DrillSpec(
        repository_id=receipt.repository_id,
        snapshot_id=receipt.snapshot_id,
        capture_id=manifest.id,
        binding=binding,
        app_sha256=app_hash,
        note_sha256=hashlib.sha256(note.encode()).hexdigest(),
        attachment_sha256=attachment_id,
    )

    class Adapter:
        def __init__(self):
            self.state = tmp_path / "adapter-state"
            self.state.mkdir(mode=0o700)
            self.paths = []

        @contextmanager
        def restored_tree(self, selected):
            assert selected == receipt
            with tempfile.TemporaryDirectory(dir=self.state) as directory:
                self.paths.append(Path(directory))
                yield materialize_tree(capture / "data.tar", manifest, Path(directory)), manifest

    return Adapter(), receipt, spec, app


def test_drill_records_distinct_evidence_and_cleans_private_tree(setup_drill):
    adapter, receipt, spec, app = setup_drill

    class Runner:
        def readback(self, data, app_copy, given):
            assert given == spec and app_copy != app
            assert app_copy.read_bytes() == app.read_bytes()
            assert (data / "attachments" / spec.attachment_sha256).is_file()
            return {"health": "ok", "note_readback": True, "attachment_readback": True}

    result = run_drill(adapter, receipt, spec, app, Runner())
    assert (
        result["capture_id"] == receipt.capture.id and result["snapshot_id"] == receipt.snapshot_id
    )
    assert result["bytes_verified_at"] <= result["application_verified_at"]
    assert result["note_readback"] and result["attachment_readback"]
    assert result["fresh_vm_proven"] is result["production_restore_authorized"] is False
    assert receipt.application_verified is False and all(not p.exists() for p in adapter.paths)
    assert not list(adapter.state.iterdir())


@pytest.mark.parametrize("field", ["repository_id", "snapshot_id", "capture_id", "app_sha256"])
def test_drill_rejects_wrong_binding_before_application(setup_drill, field):
    adapter, receipt, spec, app = setup_drill

    class Runner:
        def readback(self, *_):
            pytest.fail("mismatched input reached application")

    wrong = spec.model_copy(update={field: "f" * 64})
    with pytest.raises(BackupError, match="evidence_mismatch"):
        run_drill(adapter, receipt, wrong, app, Runner())
    assert not adapter.paths


def test_drill_fails_closed_when_application_readback_fails(setup_drill):
    adapter, receipt, spec, app = setup_drill

    class Runner:
        def readback(self, *_):
            return {"health": "ok", "note_readback": True, "attachment_readback": False}

    with pytest.raises(BackupError, match="application_mismatch"):
        run_drill(adapter, receipt, spec, app, Runner())
    assert all(not p.exists() for p in adapter.paths) and not list(adapter.state.iterdir())


def test_podman_runner_uses_pinned_image_isolated_network_and_owned_cleanup(setup_drill, tmp_path):
    _adapter, _receipt, spec, app = setup_drill
    runner = PodmanSample.__new__(PodmanSample)
    calls, token = [], []

    def execute(args, *, timeout=30):
        calls.append(args)
        if args[0] == "info":
            return "true"
        if args[:2] == ["image", "inspect"]:
            return json.dumps([spec.binding.image])
        if args[0] == "run":
            token.append(args[args.index("--label") + 1].split("=")[1])
            return "e" * 64
        if args[0] == "exec":
            return json.dumps(
                {"health": "ok", "notes": [spec.note_sha256], "attachment": spec.attachment_sha256}
            )
        if args[0] == "inspect":
            return token[0]
        if args[0] == "rm":
            return ""
        pytest.fail(f"unexpected call {args[0]}")

    runner._run = execute
    assert runner.readback(tmp_path, app, spec)["attachment_readback"]
    command = next(args for args in calls if args[0] == "run")
    assert "--network=none" in command and "--pull=never" in command and "--cap-drop=all" in command
    assert spec.binding.image in command and calls[-1][0] == "rm"


def test_podman_runner_refuses_unverified_image_and_unowned_cleanup(setup_drill, tmp_path):
    _adapter, _receipt, spec, app = setup_drill
    runner = PodmanSample.__new__(PodmanSample)
    runner._run = lambda args, **kwargs: "true" if args[0] == "info" else "[]"
    with pytest.raises(BackupError, match="image_unavailable"):
        runner.readback(tmp_path, app, spec)


def test_podman_runner_never_removes_an_unowned_container(setup_drill, tmp_path):
    _adapter, _receipt, spec, app = setup_drill
    runner = PodmanSample.__new__(PodmanSample)
    calls = []

    def execute(args, *, timeout=30):
        calls.append(args)
        if args[0] == "info":
            return "true"
        if args[:2] == ["image", "inspect"]:
            return json.dumps([spec.binding.image])
        if args[0] == "run":
            return "e" * 64
        if args[0] == "exec":
            return json.dumps(
                {"health": "ok", "notes": [spec.note_sha256], "attachment": spec.attachment_sha256}
            )
        if args[0] == "inspect":
            return "not-our-token"
        pytest.fail("must not remove a container without the ownership label")

    runner._run = execute
    with pytest.raises(BackupError, match="cleanup_unconfirmed"):
        runner.readback(tmp_path, app, spec)
    assert not any(args[0] == "rm" for args in calls)


def test_drill_refuses_changed_private_app_and_keeps_no_evidence(setup_drill):
    adapter, receipt, spec, app = setup_drill

    class Runner:
        def readback(self, data, app_copy, given):
            app_copy.chmod(0o600)
            app_copy.write_text("changed")
            return {"health": "ok", "note_readback": True, "attachment_readback": True}

    with pytest.raises(BackupError, match="source_changed"):
        run_drill(adapter, receipt, spec, app, Runner())
    assert not list(adapter.state.iterdir())


@pytest.mark.parametrize("command", ["application-drill", "restore-test"])
def test_application_drill_cli_writes_private_evidence_only_after_success(
    setup_drill, tmp_path, monkeypatch, capsys, command
):
    import sys

    from steward import backup, restore_drill

    adapter, receipt, spec, app = setup_drill
    receipt_file, spec_file = tmp_path / "receipt.json", tmp_path / "spec.json"
    receipt_file.write_text(receipt.model_dump_json())
    spec_file.write_text(spec.model_dump_json())
    repository, password = tmp_path / "repo", tmp_path / "password"
    repository.write_text("placeholder")
    password.write_text("placeholder")
    output = tmp_path / "evidence.json"

    class Runner:
        def readback(self, *_):
            return {"health": "ok", "note_readback": True, "attachment_readback": True}

    def read_only_adapter(**kwargs):
        assert kwargs["read_only"] is True
        return adapter

    monkeypatch.setattr(backup, "Restic", read_only_adapter)
    monkeypatch.setattr(restore_drill, "PodmanSample", Runner)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "steward-backup",
            command,
            "--receipt",
            str(receipt_file),
            "--spec",
            str(spec_file),
            "--app",
            str(app),
            "--repository-file",
            str(repository),
            "--password-file",
            str(password),
            "--state-dir",
            str(adapter.state),
            "--out",
            str(output),
        ],
    )
    prior_umask = os.umask(0o077)
    try:
        backup.main()
    finally:
        os.umask(prior_umask)
    result = json.loads(output.read_text())
    assert result["capture_id"] == receipt.capture.id and result["attachment_readback"]
    assert result["fresh_vm_proven"] is False and output.stat().st_mode & 0o077 == 0
    assert "saved test note" not in output.read_text()
    assert json.loads(capsys.readouterr().out)["note_readback"]


def test_application_drill_cli_wont_overwrite_inputs(setup_drill, tmp_path, monkeypatch):
    import sys

    from steward import backup

    adapter, receipt, spec, app = setup_drill
    receipt_file, spec_file = tmp_path / "receipt.json", tmp_path / "spec.json"
    receipt_file.write_text(receipt.model_dump_json())
    spec_file.write_text(spec.model_dump_json())
    repository, password = tmp_path / "repo", tmp_path / "password"
    monkeypatch.setattr(backup, "Restic", lambda **kwargs: adapter)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "steward-backup",
            "application-drill",
            "--receipt",
            str(receipt_file),
            "--spec",
            str(spec_file),
            "--app",
            str(app),
            "--repository-file",
            str(repository),
            "--password-file",
            str(password),
            "--state-dir",
            str(adapter.state),
            "--out",
            str(receipt_file),
        ],
    )
    before = receipt_file.read_bytes()
    prior_umask = os.umask(0o077)
    try:
        with pytest.raises(SystemExit, match="invalid_input"):
            backup.main()
    finally:
        os.umask(prior_umask)
    assert receipt_file.read_bytes() == before


@pytest.mark.parametrize("provided", [None, "--spec", "--app"])
def test_restore_test_rejects_incomplete_application_binding_before_adapter(
    tmp_path, monkeypatch, provided
):
    import sys

    from steward import backup

    monkeypatch.setattr(
        backup, "Restic", lambda **kwargs: pytest.fail("adapter must not be created")
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "steward-backup",
            "restore-test",
            "--receipt",
            str(tmp_path / "receipt"),
            "--repository-file",
            str(tmp_path / "repository"),
            "--password-file",
            str(tmp_path / "password"),
            "--state-dir",
            str(tmp_path),
            "--out",
            str(tmp_path / "out"),
        ]
        + ([provided, str(tmp_path / "one-binding")] if provided else []),
    )
    with pytest.raises(SystemExit) as error:
        backup.main()
    assert error.value.code == 2


def test_verify_bytes_retains_byte_only_behavior_with_read_only_access(
    setup_drill, tmp_path, monkeypatch, capsys
):
    import sys

    from steward import backup

    adapter, receipt, _, _ = setup_drill
    receipt_file = tmp_path / "receipt.json"
    receipt_file.write_text(receipt.model_dump_json())

    class ByteCheck:
        def restore_test(self, received):
            assert received == receipt
            return received

    def byte_adapter(**kwargs):
        assert kwargs["read_only"] is True
        return ByteCheck()

    monkeypatch.setattr(backup, "Restic", byte_adapter)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "steward-backup",
            "verify-bytes",
            "--receipt",
            str(receipt_file),
            "--repository-file",
            str(tmp_path / "repository"),
            "--password-file",
            str(tmp_path / "password"),
            "--state-dir",
            str(adapter.state),
            "--out",
            str(tmp_path / "out.json"),
        ],
    )
    old_umask = os.umask(0o077)
    try:
        backup.main()
    finally:
        os.umask(old_umask)
    assert json.loads(capsys.readouterr().out)["application_verified"] is False


@pytest.mark.parametrize(
    "command", ["init", "backup", "check", "verify-bytes", "restore-test", "application-drill"]
)
@pytest.mark.parametrize(
    "protected_flag",
    [
        "--repository-file",
        "--password-file",
        "--username-file",
        "--auth-password-file",
        "--ca-file",
        "--restic-binary",
    ],
)
def test_backup_output_never_overwrites_repository_inputs_before_connecting(
    command, protected_flag, tmp_path, monkeypatch
):
    import sys

    from steward import backup

    protected = tmp_path / "protected"
    protected.write_text("original")
    output = tmp_path / "output-link"
    output.symlink_to(protected)
    inputs = {
        "--repository-file": str(tmp_path / "repository"),
        "--password-file": str(tmp_path / "password"),
        "--username-file": str(tmp_path / "username"),
        "--auth-password-file": str(tmp_path / "auth-password"),
        "--ca-file": str(tmp_path / "ca"),
        "--restic-binary": str(tmp_path / "restic"),
    }
    inputs[protected_flag] = str(protected)
    argv = ["steward-backup", command]
    for flag, value in inputs.items():
        argv.extend((flag, value))
    argv.extend(("--state-dir", str(tmp_path / "state"), "--out", str(output)))
    if command == "backup":
        argv.extend(("--capture", str(tmp_path / "capture")))
    if command in ("check", "verify-bytes", "restore-test", "application-drill"):
        argv.extend(("--receipt", str(tmp_path / "receipt")))
    if command in ("restore-test", "application-drill"):
        argv.extend(("--spec", str(tmp_path / "spec"), "--app", str(tmp_path / "app")))
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(backup, "Restic", lambda **kwargs: pytest.fail("adapter created"))
    old_umask = os.umask(0o077)
    try:
        with pytest.raises(SystemExit, match="invalid_input"):
            backup.main()
    finally:
        os.umask(old_umask)
    assert protected.read_text() == "original"


def test_bundled_revision_is_bound_to_the_actual_sample_source():
    from steward.restore_drill import SOURCE_SHA256

    app = Path(__file__).resolve().parents[1] / "sample-app/sample-notes/app.py"
    assert hashlib.sha256(app.read_bytes()).hexdigest() == SOURCE_SHA256


def test_forged_application_and_matching_spec_cannot_impersonate_bundle(setup_drill, tmp_path):
    adapter, receipt, spec, _ = setup_drill
    forged = tmp_path / "forged-app.py"
    forged.write_text("print('not the registered application')\n")
    forged_spec = spec.model_copy(
        update={"app_sha256": hashlib.sha256(forged.read_bytes()).hexdigest()}
    )

    class NeverRun:
        def readback(self, *_):
            pytest.fail("forged source reached the container")

    with pytest.raises(BackupError, match="evidence_mismatch"):
        run_drill(adapter, receipt, forged_spec, forged, NeverRun())
    assert adapter.paths == []


def test_controller_restore_executes_real_tree_and_application_workflow(
    setup_drill, cfg, tmp_path, monkeypatch
):
    from contextlib import contextmanager

    import steward.adapters.backups as backups
    from steward import restore_drill
    from steward.cli import main as cli
    from steward.core.config import BackupEndpoint

    original_adapter, original_receipt, spec, app = setup_drill
    receipt = original_receipt.model_copy(
        update={"integrity_checked_at": 5.0, "restore_verified_at": 6.0}
    )
    cfg.server.name = receipt.capture.binding.server
    cfg.backup.enabled = True
    cfg.backup.endpoint = BackupEndpoint(
        host="backup.example", port=443, addresses=["203.0.113.12"]
    )
    cfg.managed_projects[0].bundle = "sample-notes"
    receipt_path, spec_path = tmp_path / "receipt.json", tmp_path / "spec.json"
    receipt_path.write_text(receipt.model_dump_json())
    receipt_path.chmod(0o600)
    spec_path.write_text(spec.model_dump_json())
    spec_path.chmod(0o600)
    password, reader = tmp_path / "password", tmp_path / "reader-password"
    password.write_bytes(b"p" * 48)
    password.chmod(0o600)
    reader.write_bytes(b"r" * 48)
    reader.chmod(0o600)
    repository = tmp_path / "repository"
    repository.write_bytes(b"rest:https://backup.example/fixture")
    repository.chmod(0o600)
    out = tmp_path / "evidence.json"
    args = cli.build_parser().parse_args(
        [
            "restore-test",
            "--config",
            "fixture.yml",
            "--limit",
            cfg.server.name,
            "--project",
            receipt.capture.binding.project,
            "--config-revision",
            receipt.capture.binding.config_revision,
            "--repository-id",
            receipt.repository_id,
            "--capture-id",
            receipt.capture.id,
            "--snapshot-id",
            receipt.snapshot_id,
            "--receipt",
            str(receipt_path),
            "--spec",
            str(spec_path),
            "--app",
            str(app),
            "--repository-file",
            str(tmp_path / "repository"),
            "--password-file",
            str(password),
            "--reader-username-file",
            str(tmp_path / "username"),
            "--reader-password-file",
            str(reader),
            "--state-dir",
            str(original_adapter.state),
            "--out",
            str(out),
        ]
    )

    class BoundAdapter:
        state = original_adapter.state

        @contextmanager
        def restored_tree(self, selected):
            assert selected == receipt
            with original_adapter.restored_tree(original_receipt) as tree:
                yield tree

    class Runner:
        def readback(self, data, app_copy, selected):
            assert (data / "notes.db").is_file() and (
                data / "attachments" / selected.attachment_sha256
            ).is_file()
            assert app_copy.read_bytes() == app.read_bytes()
            return {"health": "ok", "note_readback": True, "attachment_readback": True}

    def adapter(**kwargs):
        assert kwargs["read_only"] is True
        return BoundAdapter()

    monkeypatch.setattr(cli, "load", lambda _: cfg)
    monkeypatch.setattr(backups, "Restic", adapter)
    monkeypatch.setattr(restore_drill, "PodmanSample", Runner)
    assert args.func(args) == 0
    report = json.loads(out.read_text())
    assert report["note_readback"] and report["attachment_readback"]
    assert report["fresh_vm_proven"] is report["production_restore_authorized"] is False
    assert not list(original_adapter.state.iterdir())
