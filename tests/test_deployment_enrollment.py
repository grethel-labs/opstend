import hashlib
import json
import os
import stat
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from steward import __version__, application_boot
from steward.executor import deployment_enrollment as enrollment
from steward.executor import deployment_gate, deployment_launcher


@pytest.fixture
def host(tmp_path, monkeypatch):
    uid = os.geteuid()
    gid = os.getegid()
    lstat = Path.lstat
    fstat = os.fstat

    def file_stat(path, *args, **kwargs):
        info = lstat(path, *args, **kwargs)
        if not path.is_relative_to(tmp_path):
            return info
        return RootStat(info)

    class RootStat:
        def __init__(self, info):
            self.info = info
            self.st_uid = 0 if info.st_uid == uid else info.st_uid
            self.st_gid = 0 if info.st_gid == gid else info.st_gid

        def __getattr__(self, name):
            return getattr(self.info, name)

    class ProtectedOS:
        def fstat(self, fd):
            return RootStat(fstat(fd))

        def __getattr__(self, name):
            return getattr(os, name)

    def safe_directory(path):
        assert path.is_relative_to(tmp_path)
        for item in (path, *path.parents):
            if not item.is_relative_to(tmp_path):
                break
            info = item.lstat()
            application_boot.require(
                stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "unsafe test directory",
            )

    monkeypatch.setattr(Path, "lstat", file_stat)
    monkeypatch.setattr(application_boot, "safe_directory", safe_directory)
    monkeypatch.setattr(enrollment, "safe_directory", safe_directory)
    monkeypatch.setattr(application_boot, "os", ProtectedOS())
    monkeypatch.setattr(deployment_gate, "os", ProtectedOS())
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda *args: None)
    monkeypatch.setattr(os, "fchown", lambda *args: None)
    monkeypatch.setattr(application_boot, "read_deployment_fence", lambda: None)

    install = tmp_path / "etc/steward/install.json"
    releases = tmp_path / "opt/steward/releases"
    libexec = tmp_path / "usr/local/libexec"
    state = tmp_path / "var/lib/steward"
    runtime = tmp_path / "run/steward-deployment"
    release = releases / __version__
    dist = release / "dist"
    current = releases.parent / "current"
    for directory in (install.parent, dist, libexec.parent, state.parent, runtime):
        directory.mkdir(parents=True)
        for item in (directory, *directory.parents):
            if item == tmp_path:
                break
            item.chmod(0o755)
    install.write_text('{"schema_version":1,"state":"installed","server_name":"fixture-server"}')
    install.chmod(0o644)
    current.symlink_to(release)
    monkeypatch.setattr(enrollment, "INSTALL", install)
    monkeypatch.setattr(enrollment, "RELEASES", releases)
    monkeypatch.setattr(enrollment, "LIBEXEC", libexec)
    monkeypatch.setattr(enrollment, "STATE", state)
    monkeypatch.setattr(deployment_gate, "RUNTIME", runtime)

    wheel = dist / f"steward-{__version__}-py3-none-any.whl"
    launcher_source = Path(deployment_launcher.__file__).read_bytes()

    def write_wheel(entries=None):
        if entries is None:
            entries = [(enrollment.MEMBER, launcher_source)]
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, data in entries:
                archive.writestr(name, data)
        wheel.chmod(0o644)
        return hashlib.sha256(wheel.read_bytes()).hexdigest()

    return SimpleNamespace(
        approval=write_wheel(),
        current=current,
        install=install,
        launcher=libexec / "steward/deployment-v1/launch.py",
        record=state / "deployment-enrollment-v1.json",
        runtime=runtime,
        source=launcher_source,
        wheel=wheel,
        write_wheel=write_wheel,
    )


def test_prepare_then_replay_and_refuse_replacement(host):
    record = {
        "v": 1,
        "server_name": "fixture-server",
        "wheel_sha256": host.approval,
        "launcher_sha256": hashlib.sha256(host.source).hexdigest(),
    }
    assert enrollment.prepare(host.approval) == {**record, "changed": True}
    assert host.launcher.read_bytes() == host.source
    assert stat.S_IMODE(host.launcher.stat().st_mode) == 0o644
    assert json.loads(host.record.read_bytes()) == record
    assert stat.S_IMODE(host.record.stat().st_mode) == 0o600
    inode = host.record.stat().st_ino
    assert enrollment.prepare(host.approval) == {**record, "changed": False}
    changed_wheel = host.write_wheel([(enrollment.MEMBER, host.source), ("other", b"wheel")])
    with pytest.raises(application_boot.BootError, match="evidence does not match"):
        enrollment.prepare(changed_wheel)
    assert host.record.stat().st_ino == inode
    assert json.loads(host.record.read_bytes()) == record
    assert host.launcher.read_bytes() == host.source


def test_verified_launcher_survives_interrupted_record_publish(host, monkeypatch):
    publish = enrollment.publish

    def fail_record(path, *args):
        if path == host.record:
            raise OSError("simulated interruption")
        publish(path, *args)

    monkeypatch.setattr(enrollment, "publish", fail_record)
    with pytest.raises(OSError, match="interruption"):
        enrollment.prepare(host.approval)
    assert host.launcher.read_bytes() == host.source
    assert not host.record.exists()
    inode = host.launcher.stat().st_ino
    monkeypatch.setattr(enrollment, "publish", publish)
    assert enrollment.prepare(host.approval)["changed"] is True
    assert host.launcher.stat().st_ino == inode


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("drift", ["content", "mode", "symlink", "hardlink"])
def test_refuse_launcher_drift(host, existing, drift):
    enrollment.prepare(host.approval)
    if not existing:
        host.record.unlink()
    if drift == "content":
        host.launcher.write_bytes(b"altered")
    elif drift == "mode":
        host.launcher.chmod(0o744)
    elif drift == "symlink":
        host.launcher.unlink()
        host.launcher.symlink_to("missing")
    else:
        os.link(host.launcher, host.launcher.with_name("other"))
    with pytest.raises((application_boot.BootError, OSError)):
        enrollment.prepare(host.approval)
    assert host.record.exists() is existing
    if drift == "symlink":
        assert os.readlink(host.launcher) == "missing"
    elif drift == "content":
        assert host.launcher.read_bytes() == b"altered"


@pytest.mark.parametrize("replacement", ["symlink", "hardlink", "other-wheel", "wrong-mode"])
def test_refuse_unsafe_wheel(host, replacement):
    original = host.wheel.with_name("original")
    if replacement == "other-wheel":
        host.wheel.with_name("steward-elsewhere-py3-none-any.whl").touch()
    elif replacement == "wrong-mode":
        host.wheel.chmod(0o664)
    else:
        host.wheel.rename(original)
        if replacement == "symlink":
            host.wheel.symlink_to(original)
        else:
            os.link(original, host.wheel)
    with pytest.raises((application_boot.BootError, OSError)):
        enrollment.prepare(host.approval)
    assert not host.launcher.exists() and not host.record.exists()


def test_wrong_sha_never_opens_zip(host, monkeypatch):
    def reject_read(*args):
        pytest.fail("wheel was opened before digest approval")

    monkeypatch.setattr(zipfile, "ZipFile", reject_read)
    with pytest.raises(application_boot.BootError, match="approved SHA-256"):
        enrollment.prepare("0" * 64)
    assert not host.launcher.exists() and not host.record.exists()


@pytest.mark.parametrize("invalid", ["missing", "duplicate", "oversized"])
def test_refuse_invalid_member(host, invalid):
    entries = {
        "missing": [("elsewhere/" + enrollment.MEMBER, host.source)],
        "duplicate": [(enrollment.MEMBER, host.source)] * 2,
        "oversized": [(enrollment.MEMBER, b" " * (enrollment.LAUNCHER_LIMIT + 1))],
    }
    if invalid == "duplicate":
        with pytest.warns(UserWarning, match="Duplicate name"):
            approved = host.write_wheel(entries[invalid])
    else:
        approved = host.write_wheel(entries[invalid])
    with pytest.raises(application_boot.BootError, match="launcher"):
        enrollment.prepare(approved)
    assert not host.launcher.exists() and not host.record.exists()


@pytest.mark.parametrize("reason", ["marker", "socket", "fence", "unknown-fence"])
def test_refuse_unresolved_deployment(host, monkeypatch, reason):
    def unavailable():
        raise application_boot.BootError("unavailable deployment fence evidence")

    if reason == "marker":
        (host.runtime / "active.json").touch()
    elif reason == "socket":
        (host.runtime / "gate.sock").symlink_to("missing")
    elif reason == "fence":
        monkeypatch.setattr(application_boot, "read_deployment_fence", object)
    else:
        monkeypatch.setattr(application_boot, "read_deployment_fence", unavailable)
    with pytest.raises(application_boot.BootError, match="deployment"):
        enrollment.prepare(host.approval)
    assert not host.launcher.exists() and not host.record.exists()


def test_refuse_noncanonical_current(host):
    target = host.current.readlink()
    host.current.unlink()
    host.current.symlink_to(target.relative_to(host.current.parent))
    with pytest.raises(application_boot.BootError, match="active Steward release"):
        enrollment.prepare(host.approval)


@pytest.mark.parametrize(
    "change", [{"state": "claimed"}, {"schema_version": True}, {"server_name": "../fixture-server"}]
)
def test_refuse_invalid_install_marker(host, change):
    marker = json.loads(host.install.read_bytes())
    host.install.write_text(json.dumps({**marker, **change}))
    with pytest.raises(application_boot.BootError, match="installed Steward marker"):
        enrollment.prepare(host.approval)


def test_refuse_existing_enrollment_record_drift(host):
    enrollment.prepare(host.approval)
    record = json.loads(host.record.read_bytes())
    host.record.write_text(json.dumps({**record, "v": True}))
    with pytest.raises(application_boot.BootError, match="enrollment evidence does not match"):
        enrollment.prepare(host.approval)
    assert json.loads(host.record.read_bytes())["v"] is True
    assert host.launcher.read_bytes() == host.source


@pytest.mark.parametrize("existing", [False, True])
def test_refuse_inaccessible_launcher_directory(host, existing):
    if existing:
        enrollment.prepare(host.approval)
    else:
        host.launcher.parent.mkdir(parents=True)
        for directory in (enrollment.LIBEXEC, host.launcher.parent.parent):
            directory.chmod(0o755)
    host.launcher.parent.chmod(0o700)
    with pytest.raises(application_boot.BootError, match="deployment launcher is inaccessible"):
        enrollment.prepare(host.approval)
    assert host.launcher.exists() is existing
    assert host.record.exists() is existing


def test_refuse_enrollment_while_gate_holds_control_lock(host):
    with deployment_gate.control_lock(), pytest.raises(BlockingIOError):
        enrollment.prepare(host.approval)
    assert not host.launcher.exists() and not host.record.exists()


def test_cli_reports_changed_and_refuses_nonroot(host, capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["deployment_enrollment", "--sha256", host.approval])
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert enrollment.main() == 1
    assert "requires root" in capsys.readouterr().err
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert enrollment.main() == 0
    assert json.loads(capsys.readouterr().out)["changed"] is True
