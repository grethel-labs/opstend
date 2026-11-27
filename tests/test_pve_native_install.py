import json
import os
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

    def build(*, defect=None):
        version = "9.9.9" if defect == "version" else __version__
        out = tmp_path / f"release-{defect}"
        out.mkdir()
        wheel = out / f"steward-{version}-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("steward/core/pve_native_install.py", "# fixture")
            prefix = "lookalike/" if defect == "membership" else ""
            archive.writestr(f"{prefix}steward/pve_native_runtime.py", "# fixture")
        requirements = out / "requirements.txt"
        requirements.write_text(
            f"fixture-pkg==1.2 --hash=sha256:{release.sha256_file(dependency)}\n"
        )
        bundle = out / "bundles" / "fixture" / "main.py"
        bundle.parent.mkdir(parents=True)
        bundle.write_text("# synthetic S01 bundle")
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
            signing_key=None if defect == "unsigned" else key,
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
    enabled = set()
    commands = []
    inspected = []
    fixture = SimpleNamespace(
        paths=paths,
        unit_dir=unit_dir,
        accounts=accounts,
        commands=commands,
        inspected=inspected,
        fail_pip=False,
        fail_start=False,
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
                output = (
                    f"LoadState=loaded\nFragmentPath={unit_dir / name}\nDropInPaths=\nType=notify\n"
                    f"ActiveState={'active' if name in active else 'inactive'}\n"
                    f"UnitFileState={'enabled' if name in enabled else 'disabled'}\n"
                    "NeedDaemonReload=no\n"
                )
            elif operation == "enable":
                path = unit_dir / args[0]
                want = installer._want(path)
                want.parent.mkdir(mode=0o755, exist_ok=True)
                want.symlink_to(path)
                enabled.add(path.name)
            elif operation == "start":
                if fixture.fail_start:
                    status = 1
                else:
                    active.add(args[0])
            else:
                assert argv[3:] == ["daemon-reload"]
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
