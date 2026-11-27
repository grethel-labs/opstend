import json
import os
import shutil
import stat
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from steward import __version__, release
from steward.core import pve_native as native
from steward.core import pve_native_install as installer
from test_pve_native import API_NAME, API_TOKEN
from test_pve_native_runtime import ADMIN_TOKEN, ui_certificate
from test_release import COMMIT, new_key, write_public
from test_release import source_tree as source_tree


@pytest.fixture
def inputs(tmp_path, source_tree):
    ca = tmp_path / "pve-ca.pem"
    ca.write_text("synthetic CA; transport is substituted by the host fixture")
    ca.chmod(0o644)
    token = tmp_path / "pve-token"
    token.write_text(API_TOKEN)
    token.chmod(0o600)
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    dependency = wheelhouse / "fixture_pkg-1.2-py3-none-any.whl"
    dependency.write_bytes(b"pinned synthetic dependency")
    key = new_key()
    public = write_public(key, tmp_path / "release.pub")
    public.chmod(0o644)

    def build(*, defect=None, version=__version__, variant="", different_signer=False):
        if defect == "version":
            version = "9.9.9"
        out = tmp_path / f"release-{version}-{defect}-{variant}"
        out.mkdir()
        wheel = out / f"steward-{version}-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("steward/core/pve_native_install.py", f"# fixture {variant}")
            prefix = "lookalike/" if defect == "membership" else ""
            archive.writestr(f"{prefix}steward/pve_native_runtime.py", "# fixture")
        requirements = out / "requirements.txt"
        requirements.write_text(
            f"fixture-pkg==1.2 --hash=sha256:{release.sha256_file(dependency)}\n"
        )
        bundle = out / "bundles" / "fixture" / "main.py"
        bundle.parent.mkdir(parents=True)
        bundle.write_text("# synthetic S01 bundle")
        signer = new_key() if different_signer else key
        release.finalize_release(
            out,
            version=version,
            files={
                path.relative_to(out).as_posix(): release.sha256_file(path)
                for path in (wheel, requirements, bundle)
            },
            wheel=wheel.name,
            root=source_tree,
            subset_path=source_tree / "subset.yml",
            signing_key=None if defect == "unsigned" else signer,
            source={"commit": COMMIT, "dirty": False},
            license_lookup=lambda _: "MIT",
        )
        if defect == "tampered":
            wheel.write_bytes(wheel.read_bytes() + b"unexpected bytes")
        archive = tmp_path / f"{out.name}.tar.gz"
        release.pack_release(out, archive)
        if defect == "key":
            public_key = write_public(new_key(), tmp_path / "wrong.pub")
            public_key.chmod(0o644)
        elif different_signer:
            public_key = write_public(signer, tmp_path / "different.pub")
            public_key.chmod(0o644)
        else:
            public_key = public
        return {
            "mode": "agent",
            "api_name": API_NAME,
            "ca_file": ca,
            "token_file": token,
            "release_archive": archive,
            "release_public_key": public_key,
            "wheelhouse": wheelhouse,
        }

    return SimpleNamespace(build=build, dependency=dependency)


@pytest.fixture
def host(tmp_path, monkeypatch):
    paths = {name: tmp_path / name for name in ("install", "config", "state")}
    unit_dir = tmp_path / "units"
    unit_dir.mkdir(mode=0o755)
    home = tmp_path / "root"
    home.mkdir(mode=0o700)
    uid, gid = os.geteuid(), os.getegid()
    monkeypatch.setattr(installer, "_ROOT_UID", uid)
    monkeypatch.setattr(installer, "_ROOT_GID", gid)
    monkeypatch.setattr(installer, "_ROOT_HOME", home)
    monkeypatch.setattr(native, "_PATHS", {name: str(path) for name, path in paths.items()})
    monkeypatch.setattr(native, "_UNIT_DIR", unit_dir)
    monkeypatch.setattr(native, "_LEGACY_PATHS", ())

    secure_directory = installer._secure_directory
    monkeypatch.setattr(
        installer,
        "_secure_directory",
        lambda path: secure_directory(path) if path.is_relative_to(tmp_path) else None,
    )
    # Keep real file modes and inode checks while modeling the service UID mapping.
    directory = installer._directory
    monkeypatch.setattr(installer.os, "chown", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        installer,
        "_directory",
        lambda path, mode, _user, _group: directory(path, mode, uid, gid),
    )

    def ok():
        return {"ok": True, "detail": "fixture"}

    for probe in ("_host", "_package", "_resources"):
        monkeypatch.setattr(native, probe, ok)
    monkeypatch.setattr(native, "_listener_inodes", set)
    monkeypatch.setattr(
        native,
        "_probe_api",
        lambda *_: {name: ok() for name in ("tls", "permissions", "api_version")},
    )

    accounts = {}
    comments = {}
    active = set()
    loaded = set()
    commands = []
    inspected = []
    fixture = SimpleNamespace(
        paths=paths,
        unit_dir=unit_dir,
        accounts=accounts,
        active=active,
        commands=commands,
        inspected=inspected,
        fail_pip=False,
        fail_start=False,
        fail_start_versions=set(),
        package_conflict=False,
    )

    def read_host(argv):
        inspected.append(argv)
        command, *args = argv
        if command == "/usr/bin/dpkg-query":
            package = "opstend-other" if fixture.package_conflict else "pve-manager"
            return SimpleNamespace(returncode=0, stdout=f"installed\t{package}\t9.3.1\tamd64\n")
        if command == "/usr/bin/systemctl":
            assert args[4] in {"list-units", "list-unit-files"}, argv
            names = (
                active if args[4] == "list-units" else [p.name for p in unit_dir.glob("*.service")]
            )
            return SimpleNamespace(returncode=0, stdout="\n".join(names))
        if command == "/usr/bin/getent":
            database, key = args
            for account, account_uid in accounts.items():
                if key in {account, str(account_uid)}:
                    row = {
                        "passwd": f"{account}:x:{account_uid}:{account_uid}:{comments[account]}:/nonexistent:/usr/sbin/nologin",
                        "group": f"{account}:x:{account_uid}:",
                        "shadow": f"{account}:!:",
                    }[database]
                    return SimpleNamespace(returncode=0, stdout=row)
            return SimpleNamespace(returncode=2, stdout="")
        assert command == "/usr/bin/id" and args[0] == "-G", argv
        return SimpleNamespace(returncode=0, stdout=str(accounts[args[1]]))

    def execute(argv, *, timeout):
        commands.append(argv)
        output = ""
        status = 0
        if argv[:3] == ["/usr/bin/systemctl", "--system", "--no-pager"]:
            operation, *args = argv[3:]
            if operation == "show":
                name = args[-1]
                if name in loaded:
                    path = unit_dir / name
                    output = (
                        f"LoadState=loaded\nFragmentPath={path}\nDropInPaths=\nType=notify\n"
                        f"ActiveState={'active' if name in active else 'inactive'}\n"
                        f"MainPID={'12345' if name in active else '0'}\n"
                        f"UnitFileState={'enabled' if installer._want(path).exists() else 'disabled'}\n"
                        f"NeedDaemonReload={'no' if path.exists() else 'yes'}\n"
                    )
                else:
                    status = 1
                    output = (
                        "LoadState=not-found\nFragmentPath=\nDropInPaths=\n"
                        "ActiveState=inactive\nMainPID=0\nUnitFileState=\nNeedDaemonReload=no\n"
                    )
            elif operation == "enable":
                path = unit_dir / args[0]
                want = installer._want(path)
                want.parent.mkdir(mode=0o755, exist_ok=True)
                want.symlink_to(path)
            elif operation == "start":
                release_path = (paths["install"] / "current").readlink()
                if fixture.fail_start or release_path.name in fixture.fail_start_versions:
                    status = 1
                else:
                    active.add(args[-1])
            elif operation == "stop":
                assert args[0] == "--job-mode=ignore-dependencies"
                active.discard(args[-1])
            else:
                assert argv[3:] == ["daemon-reload"]
                loaded.clear()
                loaded.update(path.name for path in unit_dir.glob("*.service"))
        elif argv[0] == "/usr/sbin/useradd":
            accounts[argv[-1]] = int(argv[argv.index("--uid") + 1])
            comments[argv[-1]] = argv[argv.index("--comment") + 1]
        elif argv[:4] == ["/usr/bin/python3", "-I", "-m", "venv"]:
            fake_python = Path(argv[-1]) / "bin/python"
            Path(argv[-1]).mkdir(mode=0o755)
            fake_python.parent.mkdir(mode=0o755)
            fake_python.write_text("test-only placeholder")
            fake_python.chmod(0o755)
        elif argv[:3] == ["/usr/bin/python3", "-I", "-c"]:
            assert "import ensurepip" in argv[-1]
        else:
            assert argv[1:7] == [
                "-I",
                "-B",
                "-m",
                "pip",
                "--isolated",
                "--disable-pip-version-check",
            ]
            assert argv[7] in {"install", "check"}
            if argv[7] == "install":
                assert Path(argv[-2]).read_bytes() == b"pinned synthetic dependency"
                assert zipfile.is_zipfile(argv[-1])
                status = int(fixture.fail_pip)
        return SimpleNamespace(returncode=status, stdout=output)

    monkeypatch.setattr(native, "_run", read_host)
    monkeypatch.setattr(installer, "_run", execute)
    return fixture


@pytest.mark.parametrize(
    "defect, error",
    [
        ("version", "match the installer version"),
        ("key", "verify the signed"),
        ("unsigned", "verify the signed"),
        ("tampered", "verify the signed"),
        ("membership", "lacks the native"),
    ],
)
def test_refuses_invalid_release_before_host_activity(inputs, host, defect, error):
    with pytest.raises(installer.InstallError, match=error):
        installer.install(**inputs.build(defect=defect))
    assert not host.commands and not host.inspected
    assert not any(path.exists() for path in host.paths.values())


@pytest.mark.parametrize(
    "problem, error",
    [
        ("extra", "only pinned wheel"),
        ("changed", "signed dependency hash"),
        ("missing", "missing a signed dependency"),
        ("symlink", "safely stage"),
    ],
)
def test_refuses_invalid_wheelhouse_before_host_activity(inputs, host, problem, error):
    args = inputs.build()
    wheel = inputs.dependency
    if problem == "extra":
        wheel.with_suffix(".txt").touch()
    elif problem == "changed":
        wheel.write_bytes(b"bad hash")
    elif problem == "missing":
        wheel.unlink()
    else:
        source = wheel.rename(wheel.parent.parent / "copy")
        wheel.symlink_to(source)
    with pytest.raises(installer.InstallError, match=error):
        installer.install(**args)
    assert not host.commands and not host.inspected
    assert not any(path.exists() for path in host.paths.values())


def systemd_mutations(commands):
    return [argv[3:] for argv in commands if argv[0] == "/usr/bin/systemctl" and argv[3] != "show"]


@pytest.mark.parametrize("mode", ["agent", "standalone"])
def test_install_uses_offline_wheels_and_exact_repeat_is_unchanged(tmp_path, inputs, host, mode):
    args = inputs.build()
    args["mode"] = mode
    agent = "opstend-pve-agent"
    ui = "opstend-pve-ui"
    names = [agent]
    if mode == "standalone":
        names.append(ui)
        cert, key = ui_certificate(tmp_path)
        admin = tmp_path / "admin"
        admin.write_text(ADMIN_TOKEN)
        admin.chmod(0o600)
        args.update(admin_token_file=admin, ui_cert_file=cert, ui_key_file=key)

    assert installer.install(**args) == {
        "profile": native.PROFILE,
        "version": __version__,
        "mode": mode,
        "changed": 1,
    }
    version = host.paths["install"] / "releases" / __version__
    assert (host.paths["install"] / "current").readlink() == version
    assert stat.S_IMODE(version.stat().st_mode) == 0o555
    assert stat.S_IMODE((host.paths["state"] / "agent").stat().st_mode) == 0o750
    assert set(host.accounts) == set(names)
    assert len(set(host.accounts.values())) == len(names)
    assert set(path.name for path in host.unit_dir.glob("*.service")) == {
        f"{name}.service" for name in names
    }
    assert systemd_mutations(host.commands) == [
        ["daemon-reload"],
        *[["enable", f"{name}.service"] for name in names],
        *[["start", f"{name}.service"] for name in names],
    ]
    pip = next(argv for argv in host.commands if "install" in argv)
    assert pip[7:-2] == [
        "install",
        "--no-deps",
        "--no-index",
        "--no-cache-dir",
        "--no-compile",
        "--only-binary=:all:",
    ]
    assert Path(pip[-2]).name == inputs.dependency.name
    assert Path(pip[-2]) != inputs.dependency
    assert Path(pip[-1]).name == f"steward-{__version__}-py3-none-any.whl"
    assert [*pip[:7], "check"] in host.commands
    assert not any(
        API_TOKEN in value or ADMIN_TOKEN in value for argv in host.commands for value in argv
    )

    agent_unit = (host.unit_dir / f"{agent}.service").read_text()
    assert f"User={agent}\nGroup={agent}\n" in agent_unit
    assert f"LoadCredential=pve-ca:{args['ca_file']}\n" in agent_unit
    assert f"LoadCredential=pve-token:{args['token_file']}\n" in agent_unit
    assert "ReadWritePaths=/var/lib/opstend-pve/agent\n" in agent_unit
    assert "SocketBindDeny=any\n" in agent_unit and "SocketBindAllow=" not in agent_unit
    assert "IPAddressDeny=any\nIPAddressAllow=127.0.0.1/32\n" in agent_unit
    assert "LoadCredential=admin-token:" not in agent_unit
    assert "LoadCredential=ui-" not in agent_unit
    if mode == "standalone":
        ui_unit = (host.unit_dir / f"{ui}.service").read_text()
        assert f"User={ui}\nGroup={ui}\n" in ui_unit
        assert f"SupplementaryGroups={agent}\n" in ui_unit
        assert f"LoadCredential=admin-token:{admin}\n" in ui_unit
        assert f"LoadCredential=ui-cert:{cert}\nLoadCredential=ui-key:{key}\n" in ui_unit
        assert "LoadCredential=pve-" not in ui_unit and "ReadWritePaths=" not in ui_unit
        assert "SocketBindDeny=any\n" in ui_unit
        assert "SocketBindAllow=ipv4:tcp:8447\n" in ui_unit
        assert "IPAddressDeny=any\nIPAddressAllow=127.0.0.1/32\n" in ui_unit

    command_count = len(host.commands)
    assert installer.install(**args)["changed"] == 0
    assert all(argv[3] == "show" for argv in host.commands[command_count:])


def test_exact_retry_after_offline_pip_failure(inputs, host):
    args = inputs.build()
    host.fail_pip = True
    with pytest.raises(installer.InstallError, match="pinned offline"):
        installer.install(**args)
    journal = host.paths["config"] / installer._JOURNAL
    pending = journal.read_bytes()
    assert json.loads(pending)["complete"] is False
    assert not (host.paths["install"] / "current").exists()
    assert not host.accounts and not systemd_mutations(host.commands)

    command_count = len(host.commands)
    with pytest.raises(installer.InstallError, match="exact intent"):
        installer.install(**{**args, "api_name": "different.invalid"})
    assert len(host.commands) == command_count
    assert journal.read_bytes() == pending

    host.fail_pip = False
    assert installer.install(**args)["changed"] == 1
    assert json.loads(journal.read_text())["complete"] is True
    assert installer.install(**args)["changed"] == 0


def test_exact_retry_after_service_activation_interruption(inputs, host):
    args = inputs.build()
    host.fail_start = True
    with pytest.raises(installer.InstallError, match="did not become ready"):
        installer.install(**args)
    journal = host.paths["config"] / installer._JOURNAL
    pending = json.loads(journal.read_bytes())
    assert pending["complete"] is False and pending["tree"]
    assert (host.paths["install"] / "current").is_symlink()
    assert set(host.accounts) == {native._AGENT}

    command_count = len(host.commands)
    host.fail_start = False
    assert installer.install(**args)["changed"] == 1
    commands = host.commands[command_count:]
    assert all(argv[0] == "/usr/bin/systemctl" for argv in commands)
    assert systemd_mutations(commands) == [
        ["daemon-reload"],
        ["start", f"{native._AGENT}.service"],
    ]
    assert json.loads(journal.read_bytes()) == {**pending, "complete": True}
    assert installer.install(**args)["changed"] == 0


def test_partial_os_account_cannot_be_adopted(inputs, host, monkeypatch):
    args = inputs.build()
    host.fail_pip = True
    with pytest.raises(installer.InstallError, match="pinned offline"):
        installer.install(**args)
    journal = host.paths["config"] / installer._JOURNAL
    pending = journal.read_bytes()
    uid = json.loads(pending)["uids"][native._AGENT]
    read_host = native._run

    def read_partial_group(argv):
        if argv == ["/usr/bin/getent", "group", native._AGENT]:
            return SimpleNamespace(returncode=0, stdout=f"{native._AGENT}:x:{uid}:\n")
        return read_host(argv)

    monkeypatch.setattr(native, "_run", read_partial_group)
    host.fail_pip = False
    command_count = len(host.commands)
    with pytest.raises(installer.InstallError, match="does not match its reserved identity"):
        installer.install(**args)
    assert len(host.commands) == command_count
    assert journal.read_bytes() == pending
    assert not (host.paths["install"] / "current").exists()


def test_package_conflict_blocks_before_installation(inputs, host):
    args = inputs.build()
    host.package_conflict = True
    with pytest.raises(installer.InstallError, match="preflight failed .*conflicts"):
        installer.install(**args)
    assert not host.commands
    assert not any(path.exists() for path in host.paths.values())


def test_changed_owned_unit_is_not_overwritten(inputs, host):
    args = inputs.build()
    installer.install(**args)
    unit = host.unit_dir / "opstend-pve-agent.service"
    with unit.open("a") as handle:
        handle.write("# external change\n")
    contents = unit.read_bytes()
    command_count = len(host.commands)
    with pytest.raises(installer.InstallError, match="unit does not match"):
        installer.install(**args)
    assert len(host.commands) == command_count
    assert unit.read_bytes() == contents


NEXT_RELEASE = "99.0.0rc1"
AGENT_UNIT = f"{native._AGENT}.service"
UI_UNIT = f"{native._UI}.service"


def release_args(args):
    return {name: args[name] for name in ("release_archive", "release_public_key", "wheelhouse")}


def operation_commands(host, start):
    return systemd_mutations(host.commands[start:])


def active_release(host):
    return (host.paths["install"] / "current").readlink().name


def test_signed_native_upgrade_and_rollback_preserve_data_and_unit_identity(tmp_path, inputs, host):
    from steward.core.pve_native_lifecycle import rollback, upgrade

    args = inputs.build()
    cert, key = ui_certificate(tmp_path)
    admin = tmp_path / "admin"
    admin.write_text(ADMIN_TOKEN)
    admin.chmod(0o600)
    args.update(mode="standalone", admin_token_file=admin, ui_cert_file=cert, ui_key_file=key)
    installer.install(**args)
    journal = host.paths["config"] / installer._JOURNAL
    assert json.loads(journal.read_bytes())["intent"]["schema"] == 1
    units = {path: path.read_bytes() for path in host.unit_dir.glob("*.service")}
    data = host.paths["state"] / "agent" / "keep"
    data.write_text("keep this data")
    credentials = {
        path: (path.stat().st_ino, path.read_bytes()) for path in (admin, key, args["token_file"])
    }

    candidate = release_args(inputs.build(version=NEXT_RELEASE))
    start = len(host.commands)
    assert upgrade(**candidate)["changed"] == 1
    assert active_release(host) == NEXT_RELEASE
    assert operation_commands(host, start) == [
        ["stop", "--job-mode=ignore-dependencies", UI_UNIT],
        ["stop", "--job-mode=ignore-dependencies", AGENT_UNIT],
        ["start", "--job-mode=ignore-dependencies", AGENT_UNIT],
        ["start", "--job-mode=ignore-dependencies", UI_UNIT],
    ]
    start = len(host.commands)
    assert upgrade(**candidate)["changed"] == 0
    assert not operation_commands(host, start)

    assert rollback(target=__version__)["changed"] == 1
    assert active_release(host) == __version__
    start = len(host.commands)
    assert rollback(target=__version__)["changed"] == 0
    assert not operation_commands(host, start)
    assert {path: path.read_bytes() for path in units} == units
    assert data.read_text() == "keep this data"
    assert {path: (path.stat().st_ino, path.read_bytes()) for path in credentials} == credentials
    assert host.active == {AGENT_UNIT, UI_UNIT}
    assert len(host.accounts) == 2


@pytest.mark.parametrize("defect", ["other-signer", "invalid", "same-version", "owned-unit-drift"])
def test_upgrade_refuses_bad_artifact_or_drift_before_mutating(inputs, host, defect):
    from steward.core.pve_native_lifecycle import upgrade

    installer.install(**inputs.build())
    journal = host.paths["config"] / installer._JOURNAL
    previous_bytes = journal.read_bytes()
    version = __version__ if defect == "same-version" else NEXT_RELEASE
    candidate = release_args(
        inputs.build(
            version=version,
            variant=defect,
            different_signer=defect == "other-signer",
            defect="tampered" if defect == "invalid" else None,
        )
    )
    if defect == "owned-unit-drift":
        with (host.unit_dir / AGENT_UNIT).open("a") as handle:
            handle.write("# drift\n")
    start = len(host.commands)
    with pytest.raises(installer.InstallError):
        upgrade(**candidate)
    assert not operation_commands(host, start)
    assert journal.read_bytes() == previous_bytes
    assert active_release(host) == __version__
    assert {path.name for path in (host.paths["install"] / "releases").iterdir()} == {__version__}


@pytest.mark.parametrize("source_can_restart", [True, False])
def test_failed_upgrade_restore_verifies_running_source_or_remains_recoverable(
    inputs, host, source_can_restart
):
    from steward.core.pve_native_lifecycle import rollback, upgrade

    installer.install(**inputs.build())
    host.fail_start_versions.add(NEXT_RELEASE)
    if not source_can_restart:
        host.fail_start_versions.add(__version__)
    with pytest.raises(installer.InstallError):
        upgrade(**release_args(inputs.build(version=NEXT_RELEASE)))
    assert active_release(host) == __version__
    if not source_can_restart:
        assert not host.active
        host.fail_start_versions.remove(__version__)
        assert rollback(target=__version__)["changed"] == 1
    assert host.active == {AGENT_UNIT}
    assert active_release(host) == __version__


@pytest.mark.parametrize("source_can_restart", [True, False])
def test_failed_explicit_rollback_restores_the_last_active_release(
    inputs, host, source_can_restart
):
    from steward.core.pve_native_lifecycle import rollback, upgrade

    installer.install(**inputs.build())
    upgrade(**release_args(inputs.build(version=NEXT_RELEASE)))
    host.fail_start_versions.add(__version__)
    if not source_can_restart:
        host.fail_start_versions.add(NEXT_RELEASE)
    with pytest.raises(installer.InstallError, match="Native rollback failed"):
        rollback(target=__version__)
    assert active_release(host) == NEXT_RELEASE
    if not source_can_restart:
        assert not host.active
        host.fail_start_versions.remove(NEXT_RELEASE)
        assert rollback(target=NEXT_RELEASE)["changed"] == 1
    assert host.active == {AGENT_UNIT}
    assert active_release(host) == NEXT_RELEASE


@pytest.mark.parametrize("recovery", ["upgrade", "rollback"])
def test_interrupted_activation_resumes_exact_signed_release(inputs, host, monkeypatch, recovery):
    from steward.core.pve_native_lifecycle import rollback, upgrade

    installer.install(**inputs.build())
    candidate = release_args(inputs.build(version=NEXT_RELEASE))
    execute = installer._run

    def interrupted(argv, *, timeout):
        if argv[3:] == ["start", "--job-mode=ignore-dependencies", AGENT_UNIT]:
            raise KeyboardInterrupt
        return execute(argv, timeout=timeout)

    monkeypatch.setattr(installer, "_run", interrupted)
    with pytest.raises(KeyboardInterrupt):
        upgrade(**candidate)
    assert active_release(host) == NEXT_RELEASE
    assert not host.active
    monkeypatch.setattr(installer, "_run", execute)
    start = len(host.commands)
    if recovery == "upgrade":
        assert upgrade(**candidate)["changed"] == 1
        assert active_release(host) == NEXT_RELEASE
    else:
        assert rollback(target=__version__)["changed"] == 1
        assert active_release(host) == __version__
    assert host.active == {AGENT_UNIT}
    assert all(argv[0] == "/usr/bin/systemctl" for argv in host.commands[start:])


def test_staged_upgrade_retry_preserves_active_source_until_candidate_is_sealed(inputs, host):
    from steward.core.pve_native_lifecycle import upgrade

    installer.install(**inputs.build())
    candidate = release_args(inputs.build(version=NEXT_RELEASE))
    start = len(host.commands)
    host.fail_pip = True
    with pytest.raises(installer.InstallError, match="pinned offline"):
        upgrade(**candidate)
    assert not operation_commands(host, start)
    assert active_release(host) == __version__
    assert host.active == {AGENT_UNIT}
    host.fail_pip = False
    assert upgrade(**candidate)["changed"] == 1
    assert active_release(host) == NEXT_RELEASE


def test_staged_upgrade_refuses_to_rebuild_over_nested_mount(tmp_path, inputs, host, monkeypatch):
    from steward.core.pve_native_lifecycle import upgrade

    installer.install(**inputs.build())
    candidate = release_args(inputs.build(version=NEXT_RELEASE))
    host.fail_pip = True
    with pytest.raises(installer.InstallError, match="pinned offline"):
        upgrade(**candidate)
    host.fail_pip = False

    pending = host.paths["install"] / "releases" / NEXT_RELEASE / "venv"
    sentinel = pending / "keep"
    sentinel.write_bytes(b"retain mounted data")
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(f"17 14 8:1 / {sentinel} rw - ext4 /dev/test rw\n")
    monkeypatch.setattr(installer, "_MOUNTINFO", mountinfo)
    start = len(host.commands)
    with pytest.raises(installer.InstallError, match="mounted filesystem"):
        upgrade(**candidate)
    assert sentinel.read_bytes() == b"retain mounted data"
    assert not operation_commands(host, start)
    assert active_release(host) == __version__


@pytest.fixture
def removable_test_tree(monkeypatch, host):
    original = shutil.rmtree
    install = host.paths["install"]

    def remove_owned_test_tree(path, *args, **kwargs):
        # The fixture models UID 0 but runs as an ordinary test user. Make only
        # this test's quarantine writable before using the real recursive deletion.
        target = Path(path)
        if target.parent == install.parent and target.name.startswith(f".{install.name}-remove-"):
            for directory, _, _ in os.walk(target):
                Path(directory).chmod(0o700)
        return original(path, *args, **kwargs)

    remove_owned_test_tree.avoids_symlink_attacks = original.avoids_symlink_attacks
    monkeypatch.setattr(shutil, "rmtree", remove_owned_test_tree)


def test_removal_plan_and_apply_keep_operator_material_even_without_pve(
    tmp_path, inputs, host, monkeypatch, removable_test_tree
):
    from steward.core.pve_native_remove import remove

    args = inputs.build()
    installer.install(**args)
    data = host.paths["state"] / "agent" / "retained.sqlite"
    data.write_bytes(b"keep database")
    data_inode = data.stat().st_ino
    unit = host.unit_dir / AGENT_UNIT
    enablement = installer._want(unit)
    unrelated = host.unit_dir / "foreign.service"
    unrelated.write_text("unrelated unit")
    other_link = enablement.parent / unrelated.name
    other_link.symlink_to(unrelated)
    credential = args["ca_file"]
    credential_state = (credential.stat().st_ino, credential.read_bytes())
    args["token_file"].unlink()
    identities = host.accounts.copy()
    journal = host.paths["config"] / installer._JOURNAL

    def unavailable(*_args, **_kwargs):
        pytest.fail("removal needs no Proxmox API")

    monkeypatch.setattr(native, "_probe_api", unavailable)
    journal_bytes = journal.read_bytes()
    start = len(host.commands)
    preview = remove(plan=True)
    encoded_plan = json.dumps(preview)
    for path in (unit, enablement, host.paths["state"], credential, args["token_file"]):
        assert str(path) in encoded_plan
    assert API_TOKEN not in encoded_plan
    assert journal.read_bytes() == journal_bytes
    assert not operation_commands(host, start)

    export = tmp_path / "config-export.json"
    export.write_text("operator owned")
    with pytest.raises((installer.InstallError, native.PreflightError)):
        remove(export_config=export)
    assert export.read_text() == "operator owned"
    assert journal.read_bytes() == journal_bytes
    assert not operation_commands(host, start)
    export.unlink()

    assert remove(export_config=export)["changed"] == 1
    assert operation_commands(host, start) == [
        ["stop", "--job-mode=ignore-dependencies", AGENT_UNIT],
        ["daemon-reload"],
    ]
    assert stat.S_IMODE(export.stat().st_mode) == 0o600
    exported = export.read_text()
    assert API_TOKEN not in exported and str(args["token_file"]) in exported
    assert json.loads(exported)
    assert not native._exists(unit) and not native._exists(enablement)
    assert not native._exists(host.paths["install"])
    assert not host.active
    assert (credential.stat().st_ino, credential.read_bytes()) == credential_state
    assert not args["token_file"].exists()
    assert (data.stat().st_ino, data.read_bytes()) == (data_inode, b"keep database")
    assert host.accounts == identities
    assert unrelated.read_text() == "unrelated unit" and other_link.readlink() == unrelated
    start = len(host.commands)
    assert remove(export_config=export)["changed"] == 0
    assert not operation_commands(host, start)


def test_remove_resumes_after_units_unlinked_before_systemd_readback(
    inputs, host, monkeypatch, removable_test_tree
):
    from steward.core.pve_native_remove import remove

    installer.install(**inputs.build())
    execute = installer._run

    def interrupted(argv, *, timeout):
        if argv[3:] == ["daemon-reload"]:
            raise KeyboardInterrupt
        return execute(argv, timeout=timeout)

    monkeypatch.setattr(installer, "_run", interrupted)
    with pytest.raises(KeyboardInterrupt):
        remove()
    assert not host.active
    assert not native._exists(host.unit_dir / AGENT_UNIT)
    assert host.paths["install"].exists()
    monkeypatch.setattr(installer, "_run", execute)
    assert remove()["changed"] == 1
    assert not host.paths["install"].exists()


def test_remove_resumes_partial_deletion_of_owned_quarantine(
    inputs, host, monkeypatch, removable_test_tree
):
    from steward.core.pve_native_remove import remove

    installer.install(**inputs.build())
    root = host.paths["install"]
    delete = shutil.rmtree

    def interrupted(path, *args, **kwargs):
        candidate = Path(path)
        if candidate.parent == root.parent and candidate.name.startswith(f".{root.name}-remove-"):
            (candidate / installer._MARKER).unlink()
            raise KeyboardInterrupt
        return delete(path, *args, **kwargs)

    interrupted.avoids_symlink_attacks = delete.avoids_symlink_attacks
    monkeypatch.setattr(shutil, "rmtree", interrupted)
    with pytest.raises(KeyboardInterrupt):
        remove()
    assert not root.exists()
    assert not host.active
    assert len(tuple(root.parent.glob(f".{root.name}-remove-*"))) == 1
    monkeypatch.setattr(shutil, "rmtree", delete)
    assert remove()["changed"] == 1
    assert not tuple(root.parent.glob(f".{root.name}-remove-*"))
    assert host.paths["state"].exists()


def test_remove_refuses_a_mount_under_the_package_before_stopping_units(
    tmp_path, inputs, host, monkeypatch
):
    from steward.core import pve_native_remove as removal

    installer.install(**inputs.build())
    mountinfo = tmp_path / "mountinfo"
    nested_mount = host.paths["install"] / "releases" / __version__ / "venv"
    mountinfo.write_text(f"17 14 8:1 / {nested_mount} rw - ext4 /dev/test rw\n")
    monkeypatch.setattr(installer, "_MOUNTINFO", mountinfo)
    journal = host.paths["config"] / installer._JOURNAL
    before = journal.read_bytes()
    start = len(host.commands)
    with pytest.raises(installer.InstallError, match="mounted filesystem"):
        removal.remove()
    assert not operation_commands(host, start)
    assert journal.read_bytes() == before
    assert host.active == {AGENT_UNIT}


def test_remove_can_withdraw_from_failed_upgrade_staging_without_pve(
    inputs, host, monkeypatch, removable_test_tree
):
    from steward.core.pve_native_lifecycle import upgrade
    from steward.core.pve_native_remove import remove

    args = inputs.build()
    installer.install(**args)
    candidate = release_args(inputs.build(version=NEXT_RELEASE))
    host.fail_pip = True
    with pytest.raises(installer.InstallError, match="pinned offline"):
        upgrade(**candidate)
    args["token_file"].unlink()
    candidate["release_archive"].unlink()
    monkeypatch.setattr(native, "_probe_api", lambda *_: pytest.fail("expected local removal"))
    journal = host.paths["config"] / installer._JOURNAL
    before = journal.read_bytes()
    assert remove(plan=True)["changed"] == 0
    assert before == journal.read_bytes()
    assert remove()["changed"] == 1
    assert remove()["changed"] == 0
    assert not host.paths["install"].exists()
    assert host.paths["state"].exists()
    assert not host.active


@pytest.mark.parametrize("drift", ["foreign-entry", "foreign-enable-link", "unit-content"])
def test_remove_refuses_drift_before_stopping_units(inputs, host, drift):
    from steward.core.pve_native_remove import remove

    installer.install(**inputs.build())
    marker = host.paths["config"] / installer._JOURNAL
    before = marker.read_bytes()
    unit = host.unit_dir / AGENT_UNIT
    if drift == "foreign-entry":
        (host.paths["install"] / "keep-me").write_text("operator material")
    elif drift == "foreign-enable-link":
        link = installer._want(unit)
        link.unlink()
        link.symlink_to(host.unit_dir / "foreign.service")
    else:
        with unit.open("a") as handle:
            handle.write("# external change\n")
    start = len(host.commands)
    with pytest.raises(installer.InstallError):
        remove()
    assert not operation_commands(host, start)
    assert marker.read_bytes() == before
    assert host.active == {AGENT_UNIT}


@pytest.fixture
def inventory_credential(tmp_path):
    path = tmp_path / "optional-inventory"
    path.write_text(API_TOKEN.replace("!preflight=", "!inventory="))
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("existing", [False, True])
def test_inventory_binding_keeps_signed_release_and_survives_upgrade_and_removal(
    tmp_path, inputs, host, inventory_credential, existing, removable_test_tree
):
    from steward.core.pve_native_lifecycle import rollback, upgrade
    from steward.core.pve_native_remove import remove

    args = inputs.build()
    unit = host.unit_dir / AGENT_UNIT
    if existing:
        assert installer.install(**args)["changed"] == 1
        assert b"pve-inventory-token" not in unit.read_bytes()

    bound_args = {**args, "inventory_token_file": inventory_credential}
    result = installer.install(**bound_args)
    assert result["changed"] == 1
    assert str(inventory_credential) not in json.dumps(result)
    assert active_release(host) == __version__
    assert host.active == {AGENT_UNIT}
    content = unit.read_bytes()
    assert b"SetCredential=pve-inventory-token:unavailable\n" in content
    assert f"LoadCredential=pve-inventory-token:{inventory_credential}".encode() in content
    assert inventory_credential.read_bytes() not in content

    assert installer.install(**bound_args)["changed"] == 0
    assert installer.install(**args)["changed"] == 0
    alternative = inventory_credential.with_name("different-ref")
    alternative.write_bytes(inventory_credential.read_bytes())
    alternative.chmod(0o600)
    with pytest.raises(installer.InstallError, match="exact intent"):
        installer.install(**{**bound_args, "inventory_token_file": alternative})
    with pytest.raises(installer.InstallError, match="exact intent"):
        installer.install(**{**bound_args, **release_args(inputs.build(variant="different"))})

    # A missing source disables inventory availability, but the optional binding
    # should neither change unit ownership nor impede signed release operations.
    hidden = inventory_credential.rename(inventory_credential.with_name("temporarily-missing"))
    candidate = release_args(inputs.build(version=NEXT_RELEASE))
    assert upgrade(**candidate)["changed"] == 1
    assert rollback(target=__version__)["changed"] == 1
    assert installer.install(**args)["changed"] == 0
    assert unit.read_bytes() == content
    hidden.rename(inventory_credential)
    inode = inventory_credential.stat().st_ino

    plan = remove(plan=True)
    assert str(inventory_credential) not in json.dumps(plan)
    export = tmp_path / "protected-export.json"
    removed = remove(export_config=export)
    assert removed["changed"] == 1
    assert str(inventory_credential) not in json.dumps(removed)
    assert remove()["changed"] == 0
    assert inventory_credential.stat().st_ino == inode
    assert stat.S_IMODE(export.stat().st_mode) == 0o600
    assert json.loads(export.read_bytes())["credential_refs"]["inventory_token_file"] == str(
        inventory_credential
    )


@pytest.mark.parametrize(
    "problem",
    [
        "relative",
        "public",
        "group-readable",
        "symlink",
        "directory",
        "oversized",
        "same-identity",
        "same-ref",
    ],
)
def test_inventory_binding_rejects_unsafe_credentials(inputs, host, inventory_credential, problem):
    args = inputs.build()
    path = inventory_credential
    if problem == "relative":
        path = Path(path.name)
    elif problem == "public":
        path.chmod(0o644)
    elif problem == "group-readable":
        path.chmod(0o440)
    elif problem == "symlink":
        target = path.rename(path.with_name("inventory-source"))
        path.symlink_to(target)
    elif problem == "directory":
        path.unlink()
        path.mkdir(mode=0o700)
    elif problem == "oversized":
        path.write_bytes(b"x" * 1025)
    elif problem == "same-identity":
        path.write_text(API_TOKEN)
    else:
        path = args["token_file"]
    with pytest.raises(native.PreflightError, match="PVE|credential"):
        installer.install(**args, inventory_token_file=path)
    assert not host.commands
    assert not host.paths["config"].exists()


@pytest.mark.parametrize("failure", ["reload", "start", "interruption"])
def test_inventory_binding_rolls_back_or_resumes_exact_op(
    inputs, host, inventory_credential, monkeypatch, failure
):
    from steward.core.pve_native_lifecycle import load_journal

    args = inputs.build()
    installer.install(**args)
    unit = host.unit_dir / AGENT_UNIT
    prior = unit.read_bytes()
    bound_args = {**args, "inventory_token_file": inventory_credential}
    original = installer._checked
    call = "start" if failure == "start" else "daemon-reload"

    def fail_binding(argv, error, **kwargs):
        if argv[3] == call and unit.read_bytes() != prior:
            if failure == "interruption":
                raise KeyboardInterrupt
            raise installer.InstallError(error)
        return original(argv, error, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(installer, "_checked", fail_binding)
        if failure == "interruption":
            with pytest.raises(KeyboardInterrupt):
                installer.install(**bound_args)
            assert load_journal(host.paths["config"])["operation"]["phase"] == "activate"
            with pytest.raises(installer.InstallError, match="exact intent"):
                installer.install(**args)
        else:
            with pytest.raises(installer.InstallError, match="former agent unit was restored"):
                installer.install(**bound_args)
            assert unit.read_bytes() == prior
            assert host.active == {AGENT_UNIT}
            assert load_journal(host.paths["config"])["operation"] is None

    assert installer.install(**bound_args)["changed"] == 1
    assert b"pve-inventory-token" in unit.read_bytes()
    assert load_journal(host.paths["config"])["operation"] is None


def test_inventory_binding_can_restore_after_interruption_and_missing_source(
    inputs, host, inventory_credential, monkeypatch
):
    from steward.core.pve_native_lifecycle import load_journal, upgrade
    from steward.core.pve_native_remove import remove

    args = inputs.build()
    installer.install(**args)
    unit = host.unit_dir / AGENT_UNIT
    prior = unit.read_bytes()
    bound_args = {**args, "inventory_token_file": inventory_credential}
    original = installer._checked

    def fail_binding_and_restore(argv, error, **kwargs):
        if argv[3] == "daemon-reload":
            raise installer.InstallError(error)
        return original(argv, error, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(installer, "_checked", fail_binding_and_restore)
        with pytest.raises(installer.InstallError, match="restoration is pending"):
            installer.install(**bound_args)

    assert load_journal(host.paths["config"])["operation"]["phase"] == "restore"
    with pytest.raises(installer.InstallError, match="Resume the exact operation"):
        upgrade(**release_args(inputs.build(version=NEXT_RELEASE)))
    with pytest.raises(installer.InstallError, match="Resume the exact operation"):
        remove(plan=True)
    inventory_credential.unlink()
    monkeypatch.setattr(native, "_probe_api", lambda *_: pytest.fail("restoration is local"))
    with pytest.raises(installer.InstallError, match="former agent unit was restored"):
        installer.install(**bound_args)
    assert unit.read_bytes() == prior
    assert host.active == {AGENT_UNIT}
    assert load_journal(host.paths["config"])["operation"] is None
