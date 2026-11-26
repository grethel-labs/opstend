import json
import os
import shlex
import stat
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from steward import release as release_tools
from steward.cli import main as cli
from steward.core.canonical import revision_id
from steward.core.config import effective, load_config_file, parse_config


@pytest.fixture
def rc_deploy(cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "__version__", "0.1.0rc1")
    monkeypatch.setattr(cli, "WORK", tmp_path / "work")
    monkeypatch.setattr(cli, "RELEASE_DIR", tmp_path / "dist" / "release")
    monkeypatch.setattr(cli, "load", lambda _: cfg)
    monkeypatch.setattr(cli, "check_secrets", lambda _: None)
    return ["deploy", "--config", "server.yml", "--limit", cfg.server.name, "--yes"]


def make_cli_release(tmp_path, variant, *, directory=None):
    key = Ed25519PrivateKey.generate()
    trusted = Ed25519PrivateKey.generate() if variant == "wrong_key" else key
    public_key = tmp_path / "release.pub"
    public_key.write_bytes(
        trusted.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    version = "0.1.0.dev0" if variant in ("pre_rc", "version") else "0.1.0rc1"
    directory = directory or tmp_path / "release"
    directory.mkdir(parents=True)
    wheel = f"steward-{version}-py3-none-any.whl"
    (directory / wheel).write_bytes(b"verified wheel")
    (directory / "requirements.txt").write_text("")
    bundle = directory / "bundles" / "app" / "main.py"
    bundle.parent.mkdir(parents=True)
    bundle.write_bytes(
        b"$ANSIBLE_VAULT;1.1;AES256\n00\n" if variant == "vault" else b"print('hello')\n"
    )
    subset = tmp_path / "subset.yml"
    subset.write_text(
        "schema: 1\nfeatures:\n"
        "  - {id: core, description: Core, evidence: Local test}\n"
        "unsupported: [arm64]\n"
    )
    manifest = release_tools.finalize_release(
        directory,
        version=version,
        files={
            p.relative_to(directory).as_posix(): release_tools.sha256_file(p)
            for p in (directory / wheel, directory / "requirements.txt", bundle)
        },
        wheel=wheel,
        root=tmp_path,
        subset_path=subset,
        signing_key=None if variant == "unsigned" else key,
        source={"commit": "a" * 40, "dirty": False},
    )
    if variant == "tamper":
        (directory / wheel).write_bytes(b"tampered wheel")
    archive = tmp_path / "release.tar.gz"
    release_tools.pack_release(directory, archive)
    return (
        archive,
        ["--release-archive", str(archive), "--release-public-key", str(public_key)],
        {name: manifest[name] for name in ("version", "files", "wheel")},
    )


@pytest.mark.parametrize(
    ("variant", "error"),
    [
        ("missing", "requires --release-archive"),
        ("archive_only", "must be supplied together"),
        ("key_only", "must be supplied together"),
        ("dev_archive", "cannot be combined"),
        ("dev_key", "cannot be combined"),
        ("dev_missing", "no release found"),
        ("wrong_key", "not the trusted key"),
        ("unsigned", "release is unsigned"),
        ("tamper", "does not match the manifest"),
        ("vault", "contains an Ansible Vault file"),
        ("version", "does not match this CLI"),
    ],
)
def test_rc_deploy_refuses_unverified_inputs_before_preflight(
    tmp_path, monkeypatch, capsys, rc_deploy, variant, error
):
    _, verified_options, _ = make_cli_release(tmp_path, variant)
    development = ["--allow-unsigned-development-release"]
    options = {
        "missing": [],
        "archive_only": verified_options[:2],
        "key_only": verified_options[2:],
        "dev_archive": development + verified_options[:2],
        "dev_key": development + verified_options[2:],
        "dev_missing": development,
    }.get(variant, verified_options)

    def unexpected(*args, **kwargs):
        pytest.fail("invalid release inputs reached the deployment path")

    for name in ("load", "deployment_lock", "generate", "ansible"):
        monkeypatch.setattr(cli, name, unexpected)
    for resume in ([], ["--resume-deployment", "a" * 32]):
        with pytest.raises(SystemExit) as exc:
            cli.main([*rc_deploy, *resume, *options])
        expected = (
            cli.EXIT_INVALID
            if variant in {"missing", "archive_only", "key_only", "dev_archive", "dev_key"}
            else cli.EXIT_FAILED
        )
        assert exc.value.code == expected
        assert error in capsys.readouterr().err
    assert not cli.WORK.exists()


@pytest.mark.parametrize(
    "variant",
    ["regular", "pre_rc", "declined", "pending", "binding", "complete", "body_error", "unsigned"],
)
def test_rc_deploy_uses_staged_payload_through_apply(
    cfg, tmp_path, monkeypatch, capsys, rc_deploy, variant
):
    development = variant == "unsigned"
    archive, options, binding = make_cli_release(
        tmp_path, variant, directory=cli.RELEASE_DIR if development else None
    )
    if variant == "pre_rc":
        monkeypatch.setattr(cli, "__version__", binding["version"])
    if variant == "declined":

        def decline(*_):
            assert stages[0].is_dir()
            raise cli.CliError("not confirmed")

        monkeypatch.setattr(cli, "confirm", decline)
    operation = "a" * 32
    current = effective(cfg)
    revision = revision_id(current)
    complete = variant == "complete"
    state = {
        "deployment": {
            "operation_id": operation,
            "run_id": "b" * 32,
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "state": "complete" if complete else "pending",
            "base_revision": None if complete else revision,
            "release_hash": None
            if complete
            else ("0" * 64 if variant == "binding" else revision_id(binding)),
            "desired_revision": "0" * 64 if complete else revision,
        },
        "applied": current,
        "head": {"head": revision, "applied": revision, "config": current},
        "ssh_port": 22,
        "architecture": "x86_64",
        "kernel": "6",
        "memtotal_mb": 4096,
        "installed": True,
    }
    stages = []
    calls = []

    def fake_ansible(playbook, _, out, **kwargs):
        calls.append(playbook)
        payload = json.loads((out / "vars.json").read_text())["steward_release"]
        stage = Path(payload["dir"])
        stages.append(stage)
        assert stage.is_absolute()
        assert (stage / binding["wheel"]).read_bytes() == b"verified wheel"
        assert (stage / "bundles/app/main.py").read_text() == "print('hello')\n"
        assert {key: payload[key] for key in binding} == binding
        if not development:
            assert stage != cli.RELEASE_DIR
            assert payload.keys() == {*binding, "dir"}
        if playbook == "preflight.yml":
            (out / "remote-state.json").write_text(json.dumps(state))
            if not development:
                replacement = tmp_path / "replacement.tar.gz"
                replacement.write_bytes(b"replacement archive")
                replacement.replace(archive)
        elif variant == "body_error":
            raise release_tools.ReleaseError("apply body failure")
        return {"changed": 0}

    monkeypatch.setattr(cli, "ansible", fake_ansible)
    saved = cli.local_state_path(cfg)
    saved.parent.mkdir(parents=True)
    saved.write_text("{}")
    if development:
        options = ["--allow-unsigned-development-release"]
    resume = (
        [] if variant in ("regular", "pre_rc", "declined") else ["--resume-deployment", operation]
    )
    argv = [*rc_deploy, *resume, *options]
    if variant == "body_error":
        with pytest.raises(release_tools.ReleaseError, match="apply body failure"):
            cli.main(argv)
    else:
        with pytest.raises(SystemExit) as exc:
            cli.main(argv)
        expected = {"declined": cli.EXIT_FAILED, "binding": cli.EXIT_CONFLICT}.get(variant, 0)
        assert exc.value.code == expected

    output = capsys.readouterr()
    if variant in ("complete", "binding", "declined"):
        assert calls == ["preflight.yml"]
    else:
        assert calls == ["preflight.yml", "site.yml"]
    if complete:
        assert "verified completion receipt" in output.out
    if variant in ("complete", "binding", "body_error", "declined"):
        assert saved.read_text() == "{}"
    else:
        fingerprint = revision_id({key: binding[key] for key in ("version", "files")})
        assert json.loads(saved.read_text())["manifest_fingerprint"] == fingerprint
    assert len(set(stages)) == 1
    if development:
        assert stages[0] == cli.RELEASE_DIR
        assert "warning: allowing an unsigned local development release" in output.err
    else:
        assert not stages[0].exists()


@pytest.mark.parametrize(
    "variant", ["known_stale_api", "ui_edit", "bad_body", "unknown_controller", "other_desired"]
)
def test_interrupted_apply_only_resumes_a_consistent_known_unchanged_api_head(
    cfg, tmp_path, monkeypatch, variant
):
    monkeypatch.setattr(cli, "WORK", tmp_path)
    old = effective(cfg)
    old["events"]["max_events"] += 1
    known = revision_id(old)
    path = cli.local_state_path(cfg)
    path.parent.mkdir()
    path.write_text(json.dumps({"applied": known if variant != "unknown_controller" else "0" * 64}))
    exported = {"head": known, "applied": known, "config": old}
    if variant == "ui_edit":
        exported["applied"] = "0" * 64
    elif variant == "bad_body":
        exported["config"] = effective(cfg)
    state = {"applied": effective(cfg) if variant != "other_desired" else old, "head": exported}
    if variant == "other_desired":
        state["applied"]["events"]["max_events"] += 1
    args = Namespace(config="server.yml", limit=cfg.server.name, yes=True, discard_pending=False)
    if variant == "known_stale_api":
        assert cli.check_conflicts(cfg, state, args) == []
    else:
        with pytest.raises(cli.CliError) as exc:
            cli.check_conflicts(cfg, state, args)
        assert exc.value.code == cli.EXIT_CONFLICT


@pytest.mark.parametrize("succeeds", [True, False])
@pytest.mark.parametrize("existing_install", [True, False])
def test_deploy_checkpoints_exact_release_manifest_only_after_success(
    cfg, tmp_path, monkeypatch, succeeds, existing_install
):
    monkeypatch.setattr(cli, "WORK", tmp_path / "work")
    out = tmp_path / "invocation"
    out.mkdir()
    release = {"version": "0.1.0.dev0", "files": {"dist/steward.whl": "a" * 64}}
    (out / "vars.json").write_text(json.dumps({"steward_release": release}))
    reviewed_base = effective(cfg)
    reviewed_base["events"]["max_events"] += 1
    remote = {"applied": reviewed_base} if existing_install else {}
    monkeypatch.setattr(cli, "prepare", lambda *_args, **_kwargs: (cfg, out, remote))
    monkeypatch.setattr(cli, "confirm", lambda *_args: None)
    state = cli.local_state_path(cfg)
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps({"applied": "old", "manifest_fingerprint": "old"}))

    def apply(playbook, *_args, **_kwargs):
        assert playbook == "site.yml"
        generated = json.loads((out / "vars.json").read_text())
        assert generated.get("steward_base_revision") == (
            revision_id(reviewed_base) if existing_install else None
        )
        if not succeeds:
            raise cli.CliError("interrupted")
        return {"changed": 0}

    monkeypatch.setattr(cli, "ansible", apply)
    args = Namespace()
    if succeeds:
        assert cli._deploy(args, cfg) == 0
        saved = json.loads(state.read_text())
        assert saved["applied"] == revision_id(effective(cfg))
        assert saved["manifest_fingerprint"] == revision_id(release)
    else:
        with pytest.raises(cli.CliError, match="interrupted"):
            cli._deploy(args, cfg)
        assert json.loads(state.read_text()) == {"applied": "old", "manifest_fingerprint": "old"}


@pytest.mark.parametrize(
    "variant",
    ["reviewed_partial", "already_synced_api", "wrong_hash", "ui_edit", "inconsistent_body"],
)
def test_explicit_resume_binds_reviewed_partial_revision_without_discarding_ui_edits(
    cfg, tmp_path, monkeypatch, variant
):
    monkeypatch.setattr(cli, "WORK", tmp_path)
    previous = effective(cfg)
    previous["events"]["max_events"] += 1
    partial = effective(cfg)
    partial["events"]["max_events"] += 2
    known, partial_rev = revision_id(previous), revision_id(partial)
    path = cli.local_state_path(cfg)
    path.parent.mkdir()
    path.write_text(json.dumps({"applied": known}))
    exported = {"head": known, "applied": known, "config": previous}
    if variant == "already_synced_api":
        exported = {"head": partial_rev, "applied": partial_rev, "config": partial}
    elif variant == "ui_edit":
        exported["applied"] = "0" * 64
    elif variant == "inconsistent_body":
        exported["config"] = partial
    state = {"applied": partial, "head": exported}
    args = Namespace(
        config="server.yml",
        limit=cfg.server.name,
        yes=True,
        discard_pending=False,
        resume_from=partial_rev if variant != "wrong_hash" else "0" * 64,
    )
    if variant in ("reviewed_partial", "already_synced_api"):
        assert cli.check_conflicts(cfg, state, args)
    else:
        with pytest.raises(cli.CliError) as exc:
            cli.check_conflicts(cfg, state, args)
        assert exc.value.code == cli.EXIT_CONFLICT


@pytest.mark.parametrize(
    "option", ["A" * 32, "a" * 31, "a" * 32 + "\n", "--discard-pending", "--resume-from", "--plan"]
)
def test_exact_resume_parser_rejects_invalid_token_and_conflicting_modes(option):
    common = ["--config", "server.yml", "--limit", "my-server", "--resume-deployment"]
    if option == "--plan":
        argv = ["plan", *common, "a" * 32]
    elif option == "--resume-from":
        argv = ["deploy", *common, "a" * 32, option, "0" * 64]
    elif option == "--discard-pending":
        argv = ["deploy", *common, "a" * 32, option]
    else:
        argv = ["deploy", *common, option]
    with pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(argv)
    assert exc.value.code == cli.EXIT_INVALID


@pytest.mark.parametrize(
    "variant",
    [
        "base",
        "desired",
        "complete",
        "active",
        "closing",
        "manifest",
        "operation",
        "target",
        "root",
        "ui_edit_base",
        "ui_edit_desired",
        "missing_head",
        "malformed_head",
        "bad_status",
        "apply_failed",
    ],
)
def test_exact_deployment_recovery(cfg, tmp_path, monkeypatch, capsys, variant):
    operation = "a" * 32
    base_config = effective(cfg)
    base_config["events"]["max_events"] += 1
    desired = effective(cfg)
    base_revision, desired_revision = revision_id(base_config), revision_id(desired)
    observed = desired if variant in ("desired", "ui_edit_desired") else base_config
    binding = {
        "version": "0.1.0.dev0",
        "files": {"dist/steward.whl": "a" * 64},
        "wheel": "dist/steward.whl",
    }
    release = {**binding, "dir": "/controller"}
    receipt = {
        "operation_id": "0" * 32 if variant == "operation" else operation,
        "run_id": "b" * 32,
        "boot_id": "12345678-1234-1234-1234-123456789abc",
        "state": variant if variant in ("complete", "active", "closing") else "pending",
        "base_revision": None if variant == "complete" else base_revision,
        "release_hash": None if variant == "complete" else revision_id(binding),
        "desired_revision": "0" * 64 if variant in ("target", "complete") else desired_revision,
    }
    exported = {"head": base_revision, "applied": base_revision, "config": base_config}
    state = {
        "deployment": receipt,
        "applied": observed,
        "head": exported,
        "ssh_port": 22,
        "architecture": "x86_64",
        "kernel": "6",
        "memtotal_mb": 4096,
        "installed": True,
    }
    if variant == "manifest":
        release["wheel"] = "another.whl"
    elif variant == "root":
        state["applied"] = {}
    elif variant.startswith("ui_edit"):
        exported.update(head=desired_revision, config=desired)
    elif variant == "missing_head":
        state["head"] = None
    elif variant == "malformed_head":
        exported["config"] = desired
    elif variant == "bad_status":
        receipt["run_id"] = 12

    # Exercise recovery with the pre-RC path that loads the local release.
    monkeypatch.setattr(cli, "__version__", binding["version"])
    monkeypatch.setattr(cli, "WORK", tmp_path)
    monkeypatch.setattr(cli, "load", lambda _: cfg)
    calls = []
    monkeypatch.setattr(cli, "check_secrets", lambda _: calls.append("secrets"))
    monkeypatch.setattr(cli, "load_release", lambda: release)
    monkeypatch.setattr(cli, "confirm", lambda *_: calls.append("confirm"))

    def ansible(playbook, _, out, *, extra, **kwargs):
        calls.append(playbook)
        if playbook == "preflight.yml":
            assert extra[-2:] == ["-e", json.dumps({"steward_resume_deployment": operation})]
            (out / "remote-state.json").write_text(json.dumps(state))
        else:
            variables = json.loads((out / "vars.json").read_text())
            assert variables["steward_resume_deployment"] == operation
            assert variables["steward_base_revision"] == base_revision
            assert variables["steward_observed_revision"] == revision_id(observed)
            if variant == "apply_failed":
                raise cli.CliError("interrupted")
        return {"changed": 0}

    monkeypatch.setattr(cli, "ansible", ansible)
    args = cli.build_parser().parse_args(
        [
            "deploy",
            "--config",
            "server.yml",
            "--limit",
            cfg.server.name,
            "--resume-deployment",
            operation,
            "--yes",
            "-K",
        ]
    )
    saved = cli.local_state_path(cfg)
    saved.parent.mkdir()
    saved.write_text("{}")
    if variant == "complete":
        assert args.func(args) == 0
        assert calls == ["preflight.yml"]
        assert "verified completion receipt" in capsys.readouterr().out
        assert saved.read_text() == "{}"
    elif variant in ("base", "desired"):
        assert args.func(args) == 0
        assert calls == ["preflight.yml", "secrets", "confirm", "site.yml"]
        assert json.loads(saved.read_text())["applied"] == desired_revision
    else:
        with pytest.raises(cli.CliError) as exc:
            args.func(args)
        if variant == "apply_failed":
            assert calls == ["preflight.yml", "secrets", "confirm", "site.yml"]
            assert f"retry deployment {operation}" in str(exc.value)
            assert "(pending)" in capsys.readouterr().out
        else:
            assert exc.value.code == cli.EXIT_CONFLICT
            assert "confirm" not in calls
            assert "site.yml" not in calls
            if variant in ("active", "closing"):
                assert calls == ["preflight.yml"]
                assert f"deployment {operation} is {variant}" in str(exc.value)
                assert "only if the original deployment has been abandoned" in str(exc.value)
        assert saved.read_text() == "{}"


def fake_server(monkeypatch, tmp_path, cfg, **overrides):
    monkeypatch.setattr(cli, "WORK", tmp_path / "work")
    body = effective(cfg)
    head = {"head": revision_id(body), "config": body, **overrides}
    calls = []

    def ansible(playbook, connection, out, **kw):
        calls.append((playbook, connection))
        (out / "remote-state.json").write_text(json.dumps({"head": head}))

    monkeypatch.setattr(cli, "ansible", ansible)
    return calls


def test_config_pull_from_fresh_checkout(tmp_path, monkeypatch, cfg):
    calls = fake_server(monkeypatch, tmp_path, cfg)
    ancestor = tmp_path / "existing"
    ancestor.mkdir()
    ancestor.chmod(0o751)
    config_dir = ancestor / "config"
    target = config_dir / "nested" / "server.yml"
    args = cli.build_parser().parse_args(
        [
            "config",
            "pull",
            "--host",
            "server.example.org",
            "--user",
            "deploy",
            "--port",
            "2222",
            "--limit",
            "my-server",
            "--out",
            str(target),
        ]
    )
    previous_umask = os.umask(0o002)
    try:
        assert args.func(args) == 0
    finally:
        os.umask(previous_umask)
    restored = parse_config(yaml.safe_load(target.read_text()))
    assert restored.server.host == "server.example.org" and restored.server.port == 2222
    assert restored.projects == cfg.projects
    assert restored.admin.token_ref == cfg.admin.token_ref
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(config_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(ancestor.stat().st_mode) == 0o751
    assert calls[0][0] == "config-pull.yml"


def test_config_pull_preserves_existing_local_connection_and_token(tmp_path, monkeypatch, cfg):
    fake_server(monkeypatch, tmp_path, cfg)
    local = effective(cfg)
    local["admin"]["token_ref"] = "file:/local/token"
    local["server"]["host"] = "local.example.org"
    path = tmp_path / "server.yml"
    path.write_text(yaml.safe_dump(local))
    args = cli.build_parser().parse_args(
        ["config", "pull", "--config", str(path), "--limit", "my-server"]
    )
    assert args.func(args) == 0
    restored = yaml.safe_load(path.read_text())
    assert restored["admin"]["token_ref"] == "file:/local/token"
    assert restored["server"]["host"] == "local.example.org"


@pytest.mark.parametrize("overrides", [{"head": "bad"}, {"config": None}])
def test_invalid_remote_revision_leaves_output_unchanged(tmp_path, monkeypatch, cfg, overrides):
    fake_server(monkeypatch, tmp_path, cfg, **overrides)
    path = tmp_path / "out.yml"
    args = cli.build_parser().parse_args(
        [
            "config",
            "pull",
            "--host",
            "server.example.org",
            "--user",
            "deploy",
            "--limit",
            "my-server",
            "--out",
            str(path),
        ]
    )
    with pytest.raises(cli.CliError):
        args.func(args)
    assert not path.exists()


def test_config_pull_refuses_existing_explicit_output_without_network(tmp_path, monkeypatch, cfg):
    calls = fake_server(monkeypatch, tmp_path, cfg)
    target = tmp_path / "out.yml"
    target.write_text("preserve")
    args = cli.build_parser().parse_args(
        [
            "config",
            "pull",
            "--host",
            "server.example.org",
            "--user",
            "deploy",
            "--limit",
            "my-server",
            "--out",
            str(target),
        ]
    )
    with pytest.raises(cli.CliError, match="output already exists"):
        args.func(args)
    assert target.read_text() == "preserve"
    assert not calls


def test_config_pull_refuses_output_created_during_publication(tmp_path, monkeypatch, cfg):
    fake_server(monkeypatch, tmp_path, cfg)
    target = tmp_path / "out.yml"
    args = cli.build_parser().parse_args(
        [
            "config",
            "pull",
            "--host",
            "server.example.org",
            "--user",
            "deploy",
            "--limit",
            "my-server",
            "--out",
            str(target),
        ]
    )
    original = os.link

    def race(source, destination):
        target.write_text("concurrent data")
        original(source, destination)

    monkeypatch.setattr(os, "link", race)
    with pytest.raises(cli.CliError, match="output already exists"):
        args.func(args)
    assert target.read_text() == "concurrent data"


def test_invalid_pull_does_not_overwrite_existing_local_config(tmp_path, monkeypatch, cfg):
    fake_server(monkeypatch, tmp_path, cfg, head="bad")
    path = tmp_path / "server.yml"
    original = yaml.safe_dump(effective(cfg))
    path.write_text(original)
    args = cli.build_parser().parse_args(
        ["config", "pull", "--config", str(path), "--limit", "my-server"]
    )
    with pytest.raises(cli.CliError, match="revision does not match"):
        args.func(args)
    assert path.read_text() == original


def test_bootstrap_requires_explicit_connection_and_output():
    args = cli.build_parser().parse_args(["config", "pull", "--limit", "my-server"])
    with pytest.raises(cli.CliError, match="required"):
        args.func(args)


def test_simultaneous_commands_never_overwrite_another_invocations_vars(tmp_path, monkeypatch, cfg):
    monkeypatch.setattr(cli, "WORK", tmp_path)
    original = cli.generate(cfg, None)
    before = (original / "vars.json").read_bytes()
    changed = cfg.model_copy(deep=True)
    changed.projects[0].resources.memory_mb += 100
    other = cli.generate(changed, None)
    assert original != other
    assert (original / "vars.json").read_bytes() == before
    assert (other / "vars.json").read_bytes() != before


def test_ansible_uses_private_control_paths_and_strict_host_keys(tmp_path, monkeypatch, cfg):
    monkeypatch.setattr(cli, "WORK", tmp_path / "work")
    known_hosts = tmp_path / "custom known_hosts"
    known_hosts.touch()
    cfg.server.known_hosts_file = str(known_hosts)
    out = cli.generate(cfg, None)
    control_dirs = []

    def popen(argv, *, env, **kwargs):
        early_args = shlex.split(env["ANSIBLE_SSH_ARGS"])
        control_paths = [
            Path(option.removeprefix("ControlPath="))
            for flag, option in zip(early_args, early_args[1:], strict=False)
            if flag == "-o" and option.startswith("ControlPath=")
        ]
        (control_path,) = control_paths
        assert control_path.is_absolute()
        control_dir = control_path.parent
        assert stat.S_IMODE(control_dir.stat().st_mode) == 0o700
        control_dirs.append(control_dir)

        inventory_path = Path(argv[argv.index("-i") + 1])
        inventory = yaml.safe_load(inventory_path.read_text())
        host = inventory["all"]["hosts"][cfg.server.name]
        common_args = shlex.split(host["ansible_ssh_common_args"])
        options = [
            option
            for flag, option in zip(common_args, common_args[1:], strict=False)
            if flag == "-o"
        ]
        assert "StrictHostKeyChecking=yes" in options
        assert f'UserKnownHostsFile="{known_hosts}"' in options

        def wait():
            assert control_dir.is_dir()

        return SimpleNamespace(stdout=[], wait=wait, returncode=len(control_dirs) - 1)

    monkeypatch.setattr(cli.subprocess, "Popen", popen)
    cli.ansible("preflight.yml", cfg, out)
    assert not control_dirs[0].exists()
    with pytest.raises(cli.CliError, match=r"preflight.yml failed \(exit 1\)"):
        cli.ansible("preflight.yml", cfg, out)
    assert not control_dirs[1].exists()
    assert len(set(control_dirs)) == 2


def test_prepare_rerenders_the_same_invocation_with_learned_ssh_port(tmp_path, monkeypatch, cfg):
    from argparse import Namespace

    monkeypatch.setattr(cli, "WORK", tmp_path)
    cfg.server.port = 2222  # Forwarded connection; sshd really listens on 22.
    monkeypatch.setattr(cli, "check_secrets", lambda cfg: None)
    monkeypatch.setattr(cli, "load_release", lambda: {"version": "test"})
    monkeypatch.setattr(cli, "check_conflicts", lambda *a: [])
    monkeypatch.setattr(cli, "show_plan", lambda *a: None)
    seen = []

    def preflight(cfg, out, args):
        seen.append(out)
        return {"ssh_port": 22, "installed": False}

    monkeypatch.setattr(cli, "preflight", preflight)
    _, out, _ = cli.prepare(Namespace(), cfg=cfg)
    assert out == seen[0]
    variables = json.loads((out / "vars.json").read_text())
    assert variables["steward_ssh_port"] == 22
    assert (
        yaml.safe_load((out / "inventory.yml").read_text())["all"]["hosts"][cfg.server.name][
            "ansible_port"
        ]
        == 2222
    )


LAN_CANDIDATE = {"interface": "ens18", "bind": "192.168.10.7/24"}
OTHER_LAN_CANDIDATE = {"interface": "ens19", "bind": "10.10.20.7/24"}
INVALID_LAN_CANDIDATE = {"interface": "ens20", "bind": "169.254.5.3/24"}


@pytest.mark.parametrize(
    "mode",
    [
        "legacy",
        "omitted",
        "auto",
        "ambiguous",
        "missing",
        "explicit",
        "pinned",
        "pin_missing",
        "unreadable_applied",
        "resume",
        "complete",
    ],
)
def test_prepare_private_admin_lan(tmp_path, monkeypatch, capsys, mode):
    legacy = mode in ("legacy", "omitted")
    example = cli.ROOT / "examples" / ("server.api.yml" if legacy else "server.lan.yml")
    if mode == "omitted":
        raw = yaml.safe_load(example.read_text())
        del raw["admin"]["access"]
        cfg = parse_config(raw)
    else:
        cfg = load_config_file(example)
    assert effective(cfg)["admin"].get("lan") is None
    cfg.server.port = 2222
    if mode == "explicit":
        raw = effective(cfg)
        raw["admin"]["lan"] = {**OTHER_LAN_CANDIDATE, "advertise_ipv4": "172.16.0.7"}
        cfg = parse_config(raw)

    monkeypatch.setattr(cli, "WORK", tmp_path)
    monkeypatch.setattr(cli, "check_secrets", lambda _: None)
    binding = {"version": "test", "files": {}, "wheel": ""}
    release = {**binding, "dir": ""}
    state = {"ssh_port": 22, "installed": False, "admin_lan_candidates": []}
    candidates = state["admin_lan_candidates"]
    if mode in ("auto", "ambiguous", "explicit", "pinned", "resume", "unreadable_applied"):
        candidates.append(LAN_CANDIDATE)
    if legacy or mode in ("ambiguous", "explicit", "pinned", "pin_missing"):
        candidates.append(OTHER_LAN_CANDIDATE)
    if mode in ("auto", "missing"):
        candidates.append(INVALID_LAN_CANDIDATE)
    if mode in ("pinned", "pin_missing"):
        raw = effective(cfg)
        raw["admin"]["lan"] = {**LAN_CANDIDATE, "allowed_sources": ["192.168.10.0/28"]}
        state.update(installed=True, applied=effective(parse_config(raw)))
    if mode == "unreadable_applied":
        state.update(installed=True, applied=None)
    args = Namespace()
    if mode in ("resume", "complete"):
        args.resume_deployment = "a" * 32
        base = effective(load_config_file(cli.ROOT / "examples" / "server.api.yml"))
        base["server"]["port"] = cfg.server.port
        desired = effective(cfg)
        desired["admin"]["lan"] = LAN_CANDIDATE
        desired_revision = revision_id(effective(parse_config(desired)))
        base_revision = revision_id(base)
        state.update(
            installed=True,
            applied=base,
            head={"head": base_revision, "applied": base_revision, "config": base},
        )
        state["deployment"] = {
            "operation_id": args.resume_deployment,
            "run_id": "b" * 32,
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "state": "complete" if mode == "complete" else "pending",
            "base_revision": base_revision,
            "release_hash": revision_id(binding),
            "desired_revision": desired_revision,
        }

    def preflight(original, out, _args):
        assert original is cfg
        variables = json.loads((out / "vars.json").read_text())
        assert variables["steward_config_revision"] == revision_id(effective(cfg))
        if mode != "explicit":
            assert variables["steward_admin"]["allowed_origins"] == [
                "https://localhost:9443",
                "https://127.0.0.1:9443",
            ]
        return state

    monkeypatch.setattr(cli, "preflight", preflight)
    errors = {
        "ambiguous": "multiple usable",
        "missing": "no usable",
        "pin_missing": "installed admin LAN scope",
        "unreadable_applied": "could not read the applied admin scope",
    }
    if mode in errors:
        with pytest.raises(cli.CliError, match=errors[mode]) as err:
            cli.prepare(args, cfg, release)
        assert err.value.code == cli.EXIT_INVALID
        assert "admin.lan.interface and admin.lan.bind" in str(err.value)
        assert "SSH tunnel" in str(err.value)
        return
    resolved, out, _ = cli.prepare(args, cfg, release)
    variables = json.loads((out / "vars.json").read_text())
    assert variables["steward_config_revision"] == revision_id(effective(resolved))
    if legacy or mode == "complete":
        assert resolved is cfg
        assert variables["steward_admin"]["lan"] is None
    else:
        expected = OTHER_LAN_CANDIDATE if mode == "explicit" else LAN_CANDIDATE
        assert variables["steward_admin"]["lan"]["bind"] == expected["bind"]
        assert variables["steward_admin"]["lan"]["interface"] == expected["interface"]
        address = expected["bind"].split("/")[0]
        output = capsys.readouterr().out
        assert f"https://{address}:9443" in output
        if mode == "explicit":
            assert "https://172.16.0.7:9443" in output
        if mode == "pinned":
            assert effective(resolved) == state["applied"]
        if mode == "auto":
            prospective_revision = revision_id(effective(resolved))
            assert prospective_revision != revision_id(effective(cfg))
            assert variables["steward_admin"]["allowed_origins"] == [
                "https://localhost:9443",
                "https://127.0.0.1:9443",
                "https://192.168.10.7:9443",
            ]

            def ansible(playbook, config, out, **_kwargs):
                assert playbook == "site.yml"
                assert revision_id(effective(config)) == prospective_revision
                assert (
                    json.loads((out / "vars.json").read_text())["steward_config_revision"]
                    == prospective_revision
                )
                return {"changed": 1}

            monkeypatch.setattr(cli, "ansible", ansible)
            assert cli._deploy(Namespace(yes=True), cfg, release) == 0
            assert (
                json.loads(cli.local_state_path(cfg).read_text())["applied"] == prospective_revision
            )
            assert "ssh -N -p 2222" in capsys.readouterr().out
        if mode == "resume":
            assert variables["steward_config_revision"] == desired_revision


def test_deployment_lock_is_nonblocking_per_target_and_releases_on_failure(
    tmp_path, monkeypatch, cfg
):
    monkeypatch.setattr(cli, "WORK", tmp_path)
    other = cfg.model_copy(deep=True)
    other.server.host = "other.example.org"
    with cli.deployment_lock(cfg):
        with pytest.raises(cli.CliError, match="another deployment"), cli.deployment_lock(cfg):
            pytest.fail("concurrent deployment acquired the target lock")
        with cli.deployment_lock(other):
            pass
    with cli.deployment_lock(cfg):
        pass
    with pytest.raises(RuntimeError), cli.deployment_lock(cfg):
        raise RuntimeError("simulated deployment failure")
    with cli.deployment_lock(cfg):
        pass


def test_backup_command_requires_project_and_keeps_disabled_gate(cfg, monkeypatch):
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["backup", "--config", "server.yml", "--limit", cfg.server.name])
    args = parser.parse_args(
        ["backup", "--config", "server.yml", "--limit", cfg.server.name, "--project", "notes"]
    )
    monkeypatch.setattr(cli, "load", lambda _: cfg)
    monkeypatch.setattr(cli, "generate", lambda *_: pytest.fail("disabled backup reached network"))
    with pytest.raises(cli.CliError, match="disabled") as error:
        args.func(args)
    assert error.value.code == cli.EXIT_UNAVAILABLE


def test_backup_command_binds_project_revision_and_never_claims_upload(
    cfg, tmp_path, monkeypatch, capsys
):
    cfg.backup.enabled = True  # isolated candidate; production config availability guard stays on
    cfg.managed_projects[0].maintenance.allow_backup_pause = True
    args = cli.build_parser().parse_args(
        [
            "backup",
            "--config",
            "server.yml",
            "--limit",
            cfg.server.name,
            "--project",
            cfg.managed_projects[0].id,
        ]
    )
    monkeypatch.setattr(cli, "load", lambda _: cfg)
    (tmp_path / "vars.json").write_text("{}")
    monkeypatch.setattr(cli, "generate", lambda *_: tmp_path)
    expected = revision_id(effective(cfg))
    calls = []

    def ansible(playbook, connection, out, **kwargs):
        variables = json.loads((out / "vars.json").read_text())
        assert variables["steward_backup_project"] == args.project
        assert variables["steward_backup_expected_revision"] == expected
        calls.append(playbook)
        (out / "backup-result.json").write_text(
            json.dumps(
                {
                    "project_id": args.project,
                    "config_revision": expected,
                    "capture_id": "b" * 64,
                    "uploaded": False,
                    "reused": False,
                }
            )
        )

    monkeypatch.setattr(cli, "ansible", ansible)
    assert args.func(args) == 0
    assert calls == ["backup.yml"]
    assert "Upload and restore verification are not established" in capsys.readouterr().out
    assert (tmp_path / "vars.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "variant", ["wrong_project", "wrong_revision", "uploaded", "bad_id", "missing"]
)
def test_backup_command_rejects_unbound_or_incomplete_result(cfg, tmp_path, monkeypatch, variant):
    cfg.backup.enabled = True
    project = cfg.managed_projects[0]
    project.maintenance.allow_backup_pause = True
    args = cli.build_parser().parse_args(
        ["backup", "--config", "x", "--limit", cfg.server.name, "--project", project.id]
    )
    monkeypatch.setattr(cli, "load", lambda _: cfg)
    monkeypatch.setattr(cli, "generate", lambda *_: tmp_path)
    (tmp_path / "vars.json").write_text("{}")
    result = {
        "project_id": project.id,
        "config_revision": revision_id(effective(cfg)),
        "capture_id": "b" * 64,
        "uploaded": False,
        "reused": False,
    }
    if variant == "wrong_project":
        result["project_id"] = "different"
    elif variant == "wrong_revision":
        result["config_revision"] = "c" * 64
    elif variant == "uploaded":
        result["uploaded"] = True
    elif variant == "bad_id":
        result["capture_id"] = "../../escape"
    else:
        result.pop("reused")
    monkeypatch.setattr(
        cli,
        "ansible",
        lambda *args, **kwargs: (tmp_path / "backup-result.json").write_text(json.dumps(result)),
    )
    with pytest.raises(cli.CliError, match="does not match"):
        args.func(args)


def test_backup_playbook_preserves_exact_argv_and_writes_result(tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path

    binary = Path(sys.executable).parent / "ansible-playbook"
    if not binary.exists():
        pytest.skip("Ansible is unavailable")
    root = Path(__file__).resolve().parents[1]
    stub = tmp_path / "steward-host-fixture"
    captured = tmp_path / "argv.json"
    stub.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys\n"
        f"pathlib.Path({str(captured)!r}).write_text(json.dumps(sys.argv[1:]))\n"
        "print(json.dumps({'project_id':sys.argv[2], 'config_revision':sys.argv[4], "
        "'capture_id':'b'*64, 'uploaded':False, 'reused':False}))\n"
    )
    stub.chmod(0o700)
    source = (root / "ansible/playbooks/backup.yml").read_text()
    play = tmp_path / "backup.yml"
    play.write_text(
        source.replace("become: true", "become: false").replace(
            "/opt/steward/current/venv/bin/steward-host", str(stub)
        )
    )
    variables = tmp_path / "vars.json"
    variables.write_text(
        json.dumps(
            {
                "steward_backup_project": "notes",
                "steward_backup_expected_revision": "a" * 64,
                "steward_local_dir": str(tmp_path),
            }
        )
    )
    env = {
        **os.environ,
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-local"),
        "ANSIBLE_NOCOLOR": "1",
    }
    result = subprocess.run(
        [str(binary), "-i", "localhost,", "-c", "local", "-e", f"@{variables}", str(play)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(captured.read_text()) == [
        "backup-schedule",
        "notes",
        "--expected-revision",
        "a" * 64,
    ]
    assert json.loads((tmp_path / "backup-result.json").read_text())["uploaded"] is False


@pytest.mark.parametrize("variant", ["unknown", "no_data", "no_consent"])
def test_backup_command_rejects_unregistered_project_before_network(cfg, monkeypatch, variant):
    cfg.backup.enabled = True
    project = cfg.managed_projects[0]
    project.maintenance.allow_backup_pause = variant != "no_consent"
    if variant == "no_data":
        project.data_path = None
    selected = "unknown" if variant == "unknown" else project.id
    args = cli.build_parser().parse_args(
        ["backup", "--config", "server.yml", "--limit", cfg.server.name, "--project", selected]
    )
    monkeypatch.setattr(cli, "load", lambda _: cfg)
    monkeypatch.setattr(
        cli, "generate", lambda *_: pytest.fail("ineligible project reached network")
    )
    with pytest.raises(cli.CliError, match="not registered") as error:
        args.func(args)
    assert error.value.code == cli.EXIT_INVALID


def test_backup_command_does_not_bypass_unavailable_configuration_guard(
    raw_config, tmp_path, monkeypatch
):
    raw_config["backup"] = {
        "enabled": True,
        "endpoint": {"host": "backup.example", "addresses": ["192.0.2.1"]},
        "repository_ref": "env:BACKUP_REPOSITORY",
        "password_ref": "env:BACKUP_PASSWORD",
    }
    path = tmp_path / "server.yml"
    path.write_text(yaml.safe_dump(raw_config))
    args = cli.build_parser().parse_args(
        [
            "backup",
            "--config",
            str(path),
            "--limit",
            raw_config["server"]["name"],
            "--project",
            "notes",
        ]
    )
    monkeypatch.setattr(
        cli, "generate", lambda *_: pytest.fail("unavailable feature reached network")
    )
    with pytest.raises(cli.CliError, match="backup.enabled.*not available"):
        args.func(args)


@pytest.fixture
def receipt_export(cfg, tmp_path, monkeypatch):
    from steward.core.backups import Binding, FilesystemCapture, Receipt

    cfg.backup.enabled = True
    project = cfg.managed_projects[0]
    binding = Binding(
        server=cfg.server.name,
        project=project.id,
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
        snapshot_path="/private/fixture",
        snapshot_created_at=3,
        recorded_at=4,
        integrity_checked_at=5,
        restore_verified_at=6,
    )
    out = tmp_path / "run"
    out.mkdir(mode=0o700)
    (out / "vars.json").write_text("{}")
    target = tmp_path / "receipt.json"
    argv = [
        "backup-receipt",
        "--config",
        "server.yml",
        "--limit",
        cfg.server.name,
        "--project",
        project.id,
        "--config-revision",
        "a" * 64,
        "--repository-id",
        "d" * 64,
        "--capture-id",
        capture.id,
        "--snapshot-id",
        "e" * 64,
        "--out",
        str(target),
    ]
    args = cli.build_parser().parse_args(argv)
    monkeypatch.setattr(cli, "load", lambda _: cfg)
    monkeypatch.setattr(cli, "generate", lambda *_: out)
    payload = {
        "receipt": receipt.model_dump(mode="json"),
        "provenance": "worker_reported",
        "production_restore_authorized": False,
    }
    calls = []

    def ansible(name, actual_cfg, actual_out, **kwargs):
        calls.append((name, actual_cfg, actual_out, kwargs))
        path = out / "backup-receipt-result.json"
        path.write_text(json.dumps(payload))
        path.chmod(0o600)

    monkeypatch.setattr(cli, "ansible", ansible)
    return args, cfg, out, target, receipt, payload, calls


def test_controller_exports_exact_receipt_to_new_private_file(receipt_export, capsys):
    args, cfg, out, target, receipt, _, calls = receipt_export
    assert args.func(args) == 0
    assert json.loads(target.read_text()) == receipt.model_dump(mode="json")
    assert target.stat().st_mode & 0o777 == 0o600
    assert not (out / "backup-receipt-result.json").exists()
    assert calls[0][0] == "backup-receipt.yml" and calls[0][1] is cfg
    variables = json.loads((out / "vars.json").read_text())
    assert variables["steward_backup_capture_id"] == receipt.capture.id
    assert variables["steward_backup_snapshot_id"] == receipt.snapshot_id
    assert "/private/fixture" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "damage",
    [
        "server",
        "project",
        "revision",
        "repository",
        "capture",
        "snapshot",
        "unchecked",
        "unrestored",
        "provenance",
        "authorized",
        "extra",
    ],
)
def test_controller_refuses_unbound_or_incomplete_receipt(receipt_export, damage):
    args, _, out, target, _, payload, _ = receipt_export
    receipt = payload["receipt"]
    if damage in ("server", "project"):
        receipt["capture"]["binding"][damage] = "different"
    elif damage == "revision":
        receipt["capture"]["binding"]["config_revision"] = "f" * 64
    elif damage == "repository":
        receipt["repository_id"] = "f" * 64
    elif damage == "capture":
        receipt["capture"]["sha256"] = "f" * 64
    elif damage == "snapshot":
        receipt["snapshot_id"] = "f" * 64
    elif damage == "unchecked":
        receipt["integrity_checked_at"] = None
    elif damage == "unrestored":
        receipt["restore_verified_at"] = None
    elif damage == "provenance":
        payload["provenance"] = "root_attested"
    elif damage == "authorized":
        payload["production_restore_authorized"] = True
    else:
        payload["unexpected"] = "value"
    with pytest.raises(cli.CliError, match="does not match"):
        args.func(args)
    assert not target.exists() and not (out / "backup-receipt-result.json").exists()


def test_controller_receipt_refuses_existing_output_before_network(receipt_export):
    args, _, _, target, _, _, calls = receipt_export
    target.write_text("preserve")
    with pytest.raises(cli.CliError, match="already exists"):
        args.func(args)
    assert target.read_text() == "preserve" and not calls


def test_controller_receipt_refuses_disabled_backup_and_invalid_identifier(receipt_export):
    args, cfg, _, _, _, _, calls = receipt_export
    cfg.backup.enabled = False
    with pytest.raises(cli.CliError, match="disabled"):
        args.func(args)
    cfg.backup.enabled = True
    args.capture_id = "../../foreign"
    with pytest.raises(cli.CliError, match="SHA256"):
        args.func(args)
    assert not calls


def test_controller_receipt_does_not_replace_output_created_during_request(
    receipt_export, monkeypatch
):
    args, _, out, target, _, payload, _ = receipt_export

    def raced(*args, **kwargs):
        target.write_text("concurrent file")
        response = out / "backup-receipt-result.json"
        response.write_text(json.dumps(payload))
        response.chmod(0o600)

    monkeypatch.setattr(cli, "ansible", raced)
    with pytest.raises(cli.CliError, match="already exists"):
        args.func(args)
    assert target.read_text() == "concurrent file"
    assert not (out / "backup-receipt-result.json").exists()


@pytest.mark.parametrize("kind", ["symlink", "public", "hardlink", "oversized"])
def test_controller_receipt_refuses_unsafe_worker_response(receipt_export, monkeypatch, kind):
    args, _, out, target, _, payload, _ = receipt_export
    foreign = out / "foreign"

    def unsafe(*args, **kwargs):
        response = out / "backup-receipt-result.json"
        foreign.write_text(json.dumps(payload))
        foreign.chmod(0o600)
        if kind == "symlink":
            response.symlink_to(foreign)
        elif kind == "hardlink":
            os.link(foreign, response)
        else:
            response.write_text("x" * 65537 if kind == "oversized" else json.dumps(payload))
            response.chmod(0o644 if kind == "public" else 0o600)

    monkeypatch.setattr(cli, "ansible", unsafe)
    with pytest.raises(cli.CliError, match="unavailable or does not match"):
        args.func(args)
    assert not target.exists() and not (out / "backup-receipt-result.json").exists()
    assert foreign.exists()


def test_receipt_playbook_preserves_argv_and_hides_private_response(tmp_path):
    import subprocess
    import sys

    binary = Path(sys.executable).parent / "ansible-playbook"
    if not binary.exists():
        pytest.skip("Ansible is unavailable")
    root = Path(__file__).resolve().parents[1]
    stub = tmp_path / "steward-host-fixture"
    captured = tmp_path / "argv.json"
    stub.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys\n"
        f"pathlib.Path({str(captured)!r}).write_text(json.dumps(sys.argv[1:]))\n"
        "print(json.dumps({'receipt': {'snapshot_path': '/private/fixture-secret'}, "
        "'provenance': 'worker_reported', 'production_restore_authorized': False}))\n"
    )
    stub.chmod(0o700)
    source = (root / "ansible/playbooks/backup-receipt.yml").read_text()
    play = tmp_path / "backup-receipt.yml"
    play.write_text(
        source.replace("become: true", "become: false").replace(
            "/opt/steward/current/venv/bin/steward-host", str(stub)
        )
    )
    variables = tmp_path / "vars.json"
    variables.write_text(
        json.dumps(
            {
                "steward_backup_project": "notes",
                "steward_backup_config_revision": "a" * 64,
                "steward_backup_repository_id": "b" * 64,
                "steward_backup_capture_id": "c" * 64,
                "steward_backup_snapshot_id": "d" * 64,
                "steward_local_dir": str(tmp_path),
            }
        )
    )
    env = {
        **os.environ,
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-local"),
        "ANSIBLE_NOCOLOR": "1",
    }
    result = subprocess.run(
        [str(binary), "-vvv", "-i", "localhost,", "-c", "local", "-e", f"@{variables}", str(play)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(captured.read_text()) == [
        "backup-receipt",
        "notes",
        "--config-revision",
        "a" * 64,
        "--repository-id",
        "b" * 64,
        "--capture-id",
        "c" * 64,
        "--snapshot-id",
        "d" * 64,
    ]
    response = tmp_path / "backup-receipt-result.json"
    assert response.stat().st_mode & 0o777 == 0o600
    assert json.loads(response.read_text())["receipt"]["snapshot_path"] == "/private/fixture-secret"
    assert "/private/fixture-secret" not in result.stdout + result.stderr


def test_controller_receipt_does_not_bypass_unavailable_backup_gate(
    raw_config, tmp_path, monkeypatch
):
    raw_config["backup"] = {
        "enabled": True,
        "endpoint": {"host": "backup.example", "addresses": ["192.0.2.1"]},
        "repository_ref": "env:BACKUP_REPOSITORY",
        "password_ref": "env:BACKUP_PASSWORD",
    }
    config = tmp_path / "server.yml"
    config.write_text(yaml.safe_dump(raw_config))
    args = cli.build_parser().parse_args(
        [
            "backup-receipt",
            "--config",
            str(config),
            "--limit",
            raw_config["server"]["name"],
            "--project",
            "notes",
            "--config-revision",
            "a" * 64,
            "--repository-id",
            "b" * 64,
            "--capture-id",
            "c" * 64,
            "--snapshot-id",
            "d" * 64,
            "--out",
            str(tmp_path / "receipt"),
        ]
    )
    monkeypatch.setattr(
        cli, "generate", lambda *_: pytest.fail("unavailable feature reached network")
    )
    with pytest.raises(cli.CliError, match="backup.enabled.*not available"):
        args.func(args)


def test_controller_receipt_refuses_output_symlink_before_network(receipt_export):
    args, _, _, target, _, _, calls = receipt_export
    foreign = target.parent / "foreign"
    foreign.write_text("preserve")
    target.symlink_to(foreign)
    with pytest.raises(cli.CliError, match="already exists"):
        args.func(args)
    assert foreign.read_text() == "preserve" and not calls


@pytest.fixture
def controller_restore(receipt_export, tmp_path, monkeypatch):
    import hashlib

    from steward import restore_drill

    _, cfg, _, _, receipt, _, _ = receipt_export
    from steward.core.config import BackupEndpoint

    cfg.backup.endpoint = BackupEndpoint(
        host="backup.example", port=443, addresses=["203.0.113.12"]
    )
    cfg.managed_projects[0].bundle = "sample-notes"
    receipt_path = tmp_path / "restore-receipt.json"
    receipt_path.write_text(receipt.model_dump_json())
    receipt_path.chmod(0o600)
    app = tmp_path / "app.py"
    app.write_bytes(
        (Path(__file__).resolve().parents[1] / "sample-app/sample-notes/app.py").read_bytes()
    )
    spec = restore_drill.DrillSpec(
        repository_id=receipt.repository_id,
        snapshot_id=receipt.snapshot_id,
        capture_id=receipt.capture.id,
        binding=receipt.capture.binding,
        app_sha256=hashlib.sha256(app.read_bytes()).hexdigest(),
        note_sha256="1" * 64,
        attachment_sha256="2" * 64,
    )
    spec_path = tmp_path / "restore-spec.json"
    spec_path.write_text(spec.model_dump_json())
    spec_path.chmod(0o600)
    paths = {
        name: tmp_path / name
        for name in ("repository", "password", "reader-user", "reader-password", "ca")
    }
    for name, path in paths.items():
        path.write_bytes(
            {
                "repository": b"rest:https://backup.example/fixture",
                "password": b"p" * 48,
                "reader-user": b"reader",
                "reader-password": b"r" * 48,
                "ca": b"ca",
            }[name]
        )
        path.chmod(0o600)
    out = tmp_path / "drill-evidence.json"
    args = cli.build_parser().parse_args(
        [
            "restore-test",
            "--config",
            "server.yml",
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
            str(paths["repository"]),
            "--password-file",
            str(paths["password"]),
            "--reader-username-file",
            str(paths["reader-user"]),
            "--reader-password-file",
            str(paths["reader-password"]),
            "--ca-file",
            str(paths["ca"]),
            "--state-dir",
            str(tmp_path / "state"),
            "--out",
            str(out),
        ]
    )
    calls = []
    import steward.adapters.backups as backups

    monkeypatch.setattr(
        backups, "Restic", lambda **kwargs: calls.append(("adapter", kwargs)) or object()
    )
    monkeypatch.setattr(restore_drill, "PodmanSample", lambda: object())
    report = {
        "v": 1,
        "repository_id": receipt.repository_id,
        "snapshot_id": receipt.snapshot_id,
        "capture_id": receipt.capture.id,
        "binding": receipt.capture.binding.model_dump(mode="json"),
        "app_sha256": spec.app_sha256,
        "bytes_verified_at": 10.0,
        "application_verified_at": 11.0,
        "health": "ok",
        "note_readback": True,
        "attachment_readback": True,
        "fresh_vm_proven": False,
        "production_restore_authorized": False,
    }
    monkeypatch.setattr(
        restore_drill, "run_drill", lambda *values: calls.append(("drill", values)) or report
    )
    return args, cfg, receipt, spec, report, paths, out, calls


def test_controller_restore_runs_bound_read_only_application_drill(controller_restore, capsys):
    args, _, receipt, spec, report, _, out, calls = controller_restore
    assert args.func(args) == 0
    assert calls[0][0] == "adapter" and calls[0][1]["read_only"] is True
    assert calls[0][1]["username_file"] == args.reader_username_file
    assert calls[0][1]["auth_password_file"] == args.reader_password_file
    assert calls[1][0] == "drill" and calls[1][1][1:3] == (receipt, spec)
    assert json.loads(out.read_text()) == report and out.stat().st_mode & 0o777 == 0o600
    assert "fresh VM and production recovery are not proven" in capsys.readouterr().out


@pytest.mark.parametrize(
    "field", ["project", "config_revision", "repository_id", "capture_id", "snapshot_id"]
)
def test_controller_restore_rejects_wrong_selection_before_adapter(controller_restore, field):
    args, _, _, _, _, _, out, calls = controller_restore
    setattr(args, field, "other" if field == "project" else "f" * 64)
    with pytest.raises(cli.CliError):
        args.func(args)
    assert not calls and not out.exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("health", "failed"),
        ("note_readback", False),
        ("attachment_readback", False),
        ("fresh_vm_proven", True),
        ("production_restore_authorized", True),
        ("bytes_verified_at", float("nan")),
        ("application_verified_at", 9.0),
        ("snapshot_id", "f" * 64),
        ("v", True),
    ],
)
def test_controller_restore_rejects_untrusted_or_incomplete_result(
    controller_restore, field, value
):
    args, _, _, _, report, _, out, _ = controller_restore
    report[field] = value
    with pytest.raises(cli.CliError, match="evidence_mismatch"):
        args.func(args)
    assert not out.exists()


def test_controller_restore_rejects_reused_reader_secret_before_adapter(controller_restore):
    args, _, _, _, _, paths, out, calls = controller_restore
    paths["reader-password"].write_bytes(paths["password"].read_bytes() + b"\n")
    with pytest.raises(cli.CliError, match="invalid_credentials"):
        args.func(args)
    assert not calls and not out.exists()


def test_controller_restore_refuses_existing_output_and_disabled_gate(controller_restore):
    args, cfg, _, _, _, _, out, calls = controller_restore
    out.write_text("preserve")
    with pytest.raises(cli.CliError, match="already exists"):
        args.func(args)
    assert out.read_text() == "preserve" and not calls
    out.unlink()
    cfg.backup.enabled = False
    with pytest.raises(cli.CliError, match="disabled"):
        args.func(args)
    assert not calls and not out.exists()


def test_controller_restore_does_not_bypass_unavailable_backup_config(
    raw_config, tmp_path, monkeypatch
):
    raw_config["backup"] = {
        "enabled": True,
        "endpoint": {"host": "backup.example", "addresses": ["192.0.2.1"]},
        "repository_ref": "env:BACKUP_REPOSITORY",
        "password_ref": "env:BACKUP_PASSWORD",
    }
    config = tmp_path / "server.yml"
    config.write_text(yaml.safe_dump(raw_config))
    args = cli.build_parser().parse_args(
        [
            "restore-test",
            "--config",
            str(config),
            "--limit",
            raw_config["server"]["name"],
            "--project",
            "notes",
            "--config-revision",
            "a" * 64,
            "--repository-id",
            "b" * 64,
            "--capture-id",
            "c" * 64,
            "--snapshot-id",
            "d" * 64,
            "--receipt",
            "receipt",
            "--spec",
            "spec",
            "--app",
            "app",
            "--repository-file",
            "repository",
            "--password-file",
            "password",
            "--reader-username-file",
            "user",
            "--reader-password-file",
            "reader",
            "--state-dir",
            "state",
            "--out",
            "output",
        ]
    )
    monkeypatch.setattr(
        cli, "generate", lambda *_: pytest.fail("unavailable feature reached network")
    )
    with pytest.raises(cli.CliError, match="backup.enabled.*not available"):
        args.func(args)


@pytest.mark.parametrize(
    "which,kind",
    [
        ("receipt", "public"),
        ("spec", "public"),
        ("receipt", "symlink"),
        ("spec", "symlink"),
        ("receipt", "hardlink"),
        ("spec", "hardlink"),
    ],
)
def test_controller_restore_refuses_nonprivate_or_linked_documents(
    controller_restore, tmp_path, which, kind
):
    args, _, _, _, _, _, out, calls = controller_restore
    path = getattr(args, which)
    if kind == "public":
        path.chmod(0o644)
    elif kind == "hardlink":
        os.link(path, tmp_path / (which + "-hardlink"))
    else:
        original = tmp_path / (which + "-original")
        path.rename(original)
        path.symlink_to(original)
    with pytest.raises(cli.CliError, match="input or local state"):
        args.func(args)
    assert not calls and not out.exists()


def test_controller_restore_rejects_changed_app_before_adapter(controller_restore):
    args, _, _, _, _, _, out, calls = controller_restore
    args.app.write_text("changed application")
    with pytest.raises(cli.CliError, match="evidence_mismatch"):
        args.func(args)
    assert not calls and not out.exists()


def test_controller_restore_requires_integrity_checked_receipt(controller_restore):
    args, _, receipt, _, _, _, out, calls = controller_restore
    args.receipt.write_text(
        receipt.model_copy(update={"integrity_checked_at": None}).model_dump_json()
    )
    with pytest.raises(cli.CliError, match="evidence_mismatch"):
        args.func(args)
    assert not calls and not out.exists()


def test_controller_restore_can_be_first_restore_for_checked_snapshot(controller_restore):
    args, _, receipt, _, _, _, out, calls = controller_restore
    args.receipt.write_text(
        receipt.model_copy(update={"restore_verified_at": None}).model_dump_json()
    )
    assert args.func(args) == 0
    assert calls[1][0] == "drill" and json.loads(out.read_text())["note_readback"] is True


def test_controller_restore_refuses_output_created_during_drill(controller_restore, monkeypatch):
    from steward import restore_drill

    args, _, _, _, report, _, out, _ = controller_restore

    def raced(*values):
        out.write_text("concurrent file")
        return report

    monkeypatch.setattr(restore_drill, "run_drill", raced)
    with pytest.raises(cli.CliError, match="already exists"):
        args.func(args)
    assert out.read_text() == "concurrent file"


def test_controller_restore_refuses_root_and_become(controller_restore, monkeypatch):
    args, _, _, _, _, _, out, calls = controller_restore
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    with pytest.raises(cli.CliError, match="unprivileged"):
        args.func(args)
    monkeypatch.undo()
    # Reapply the fixture's loader after undoing the root override.
    cfg = controller_restore[1]
    monkeypatch.setattr(cli, "load", lambda _: cfg)
    args.ask_become_pass = True
    with pytest.raises(cli.CliError, match="without privilege"):
        args.func(args)
    assert not calls and not out.exists()


def test_controller_restore_refuses_forged_source_even_with_matching_hash(controller_restore):
    import hashlib

    args, _, _, spec, _, _, out, calls = controller_restore
    args.app.write_text("print('forged')\n")
    forged = spec.model_copy(
        update={"app_sha256": hashlib.sha256(args.app.read_bytes()).hexdigest()}
    )
    args.spec.write_text(forged.model_dump_json())
    with pytest.raises(cli.CliError, match="evidence_mismatch"):
        args.func(args)
    assert not calls and not out.exists()


def test_controller_restore_requires_configured_repository_target(controller_restore):
    args, cfg, _, _, _, paths, out, calls = controller_restore
    paths["repository"].write_bytes(b"rest:https://different.example/fixture")
    with pytest.raises(cli.CliError, match="repository_target_mismatch"):
        args.func(args)
    assert not calls and not out.exists()
    cfg.backup.endpoint = None
    with pytest.raises(cli.CliError, match="endpoint is not configured"):
        args.func(args)
    assert not calls and not out.exists()


def test_controller_restore_accepts_separate_short_server_reader_credential(controller_restore):
    args, _, _, _, _, paths, out, calls = controller_restore
    paths["reader-password"].write_bytes(b"readonly-token")
    assert args.func(args) == 0
    assert calls[0][1]["read_only"] is True and out.exists()
