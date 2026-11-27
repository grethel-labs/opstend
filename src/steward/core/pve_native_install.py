"""Root-only installation of the signed native PVE profile."""

import ctypes
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import zipfile
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from .. import __version__, pve_native_runtime, release
from . import pve_native as native

_ROOT_UID = 0
_ROOT_GID = 0
_ROOT_HOME = Path("/root")
_PYTHON = Path("/usr/bin/python3")
_SYSTEMCTL = ("/usr/bin/systemctl", "--system", "--no-pager")
_REQUIRED_MODULES = (
    "steward/core/pve_native_install.py",
    "steward/pve_native_runtime.py",
)
_WHEEL = re.compile(
    r"([A-Za-z0-9_]+)-([A-Za-z0-9_.!+]+)(?:-[0-9][A-Za-z0-9_.]*)?"
    r"-([A-Za-z0-9_.]+)-([A-Za-z0-9_.]+)-([A-Za-z0-9_.]+)\.whl"
)
_SAFE_REF = re.compile(r"/[A-Za-z0-9_./-]+")
_JOURNAL = "install.json"
_JOURNAL_LIMIT = 64 * 1024
_MARKER = ".install-intent"
_MOUNTINFO = Path("/proc/self/mountinfo")
_CHILD_LOCK = ContextVar("native_install_child_lock", default=())


class InstallError(RuntimeError):
    """The native installation is unavailable or conflicts with existing state."""


def _run(argv: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        encoding="utf-8",
        timeout=timeout,
        pass_fds=_CHILD_LOCK.get(),
        umask=0o022,
        env={
            "LANG": "C.UTF-8",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(_ROOT_HOME),
            "PIP_CONFIG_FILE": os.devnull,
        },
        check=False,
    )


def _checked(argv: list[str], error: str, *, timeout: int = 120) -> str:
    result = _run(argv, timeout=timeout)
    if result.returncode != 0:
        raise InstallError(error)
    return result.stdout


def _secure_directory(path: Path) -> None:
    entry = path.lstat()
    if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != _ROOT_UID or entry.st_mode & 0o022:
        raise InstallError("Expected a root-owned directory without unsafe write permissions.")


def _verify_unmounted(*roots: Path) -> None:
    lines = _MOUNTINFO.read_bytes().splitlines()
    if not lines:
        raise InstallError("Could not verify native package mount boundaries.")
    for line in lines:
        fields = line.split(b" ")
        if len(fields) < 10 or b" - " not in line:
            raise InstallError("Could not verify native package mount boundaries.")
        mount = Path(
            os.fsdecode(re.sub(rb"\\([0-7]{3})", lambda m: bytes([int(m[1], 8)]), fields[4]))
        )
        if any(mount.is_relative_to(root) for root in roots):
            raise InstallError(f"A mounted filesystem intersects a native package path ({mount}).")


def _credential(path: Path, roots: tuple[Path, ...], *, private: bool) -> None:
    if (
        path.anchor != "/"
        or not _SAFE_REF.fullmatch(str(path))
        or ".." in path.parts
        or any(path.is_relative_to(root) for root in roots)
    ):
        raise native.PreflightError("Use absolute, safe credential paths outside native roots.")
    try:
        for parent in reversed(path.parents):
            _secure_directory(parent)
        entry = path.lstat()
        mode = stat.S_IMODE(entry.st_mode)
        if (
            not stat.S_ISREG(entry.st_mode)
            or entry.st_uid != _ROOT_UID
            or entry.st_nlink != 1
            or mode not in ((0o400, 0o600) if private else (0o400, 0o444, 0o600, 0o644))
        ):
            raise ValueError
    except (OSError, ValueError, InstallError):
        raise native.PreflightError("Use secure root-owned regular credential files.") from None


def _wheel_snapshot(payload: dict, wheelhouse: Path, scratch: Path) -> tuple[list[Path], dict]:
    """Install only private copies of the signed dependency artifacts."""
    root = Path(payload["dir"])
    pins = {
        pin.name: pin
        for pin in release.parse_requirements((root / "requirements.txt").read_text("utf-8"))
    }
    selected = {}
    digests = {}
    target = scratch / "wheels"
    target.mkdir(mode=0o700)
    directory = os.open(wheelhouse, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY)
    try:
        for name in sorted(os.listdir(directory)):
            match = _WHEEL.fullmatch(name)
            if not match:
                raise InstallError("The wheelhouse may contain only pinned wheel files.")
            package = release.normalize_name(match[1])
            pin = pins.get(package)
            if not pin or pin.version != match[2] or package in selected:
                raise InstallError("Expected exactly one wheel per signed dependency pin.")
            dest = target / name
            fd = os.open(name, os.O_NOFOLLOW | os.O_NONBLOCK | os.O_RDONLY, dir_fd=directory)
            with os.fdopen(fd, "rb") as source:
                metadata = os.fstat(source.fileno())
                if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 512 * 1024**2:
                    raise InstallError("The wheelhouse contains an invalid wheel file.")
                with dest.open("xb") as out:
                    # Bound the amount copied even if the source changes.
                    remaining = metadata.st_size
                    while remaining:
                        block = source.read(min(1024**2, remaining))
                        if not block:
                            raise InstallError("A wheel changed while being staged.")
                        out.write(block)
                        remaining -= len(block)
                    if source.read(1):
                        raise InstallError("A wheel changed while being staged.")
            digest = release.sha256_file(dest)
            if digest not in pin.hashes:
                raise InstallError("A wheel does not match its signed dependency hash.")
            selected[package] = dest
            digests[name] = digest
    finally:
        os.close(directory)
    if selected.keys() != pins.keys():
        raise InstallError("The wheelhouse is missing a signed dependency pin.")
    return list(selected.values()), digests


def _require_native_release(payload: dict, *, match_installer: bool = True) -> str:
    if match_installer and payload["version"] != __version__:
        raise InstallError("The signed native release must match the installer version exactly.")
    root = Path(payload["dir"])
    with zipfile.ZipFile(root / payload["wheel"]) as archive:
        for module in _REQUIRED_MODULES:
            entries = [item for item in archive.infolist() if item.filename == module]
            if len(entries) != 1 or entries[0].is_dir() or not entries[0].file_size:
                raise InstallError("The signed wheel lacks the native PVE installer and runtime.")
            if stat.S_IFMT(entries[0].external_attr >> 16) not in (0, stat.S_IFREG):
                raise InstallError("The signed native module is not a regular wheel member.")
    return release.sha256_file(root / release.MANIFEST)


def _check_python() -> None:
    _checked(
        [
            str(_PYTHON),
            "-I",
            "-c",
            "import ensurepip, sys, venv; "
            "sys.exit(sys.implementation.name != 'cpython' or sys.version_info < (3, 12))",
        ],
        "The installed Debian CPython with venv and ensurepip is required.",
    )


def _build_venv(payload: dict, dependencies: list[Path], env: Path) -> None:
    _checked(
        [str(_PYTHON), "-I", "-m", "venv", str(env)],
        "Could not prepare a native environment with the installed Debian Python.",
    )
    python = str(env / "bin/python")
    pip = [python, "-I", "-B", "-m", "pip", "--isolated", "--disable-pip-version-check"]
    _checked(
        [
            *pip,
            "install",
            "--no-deps",
            "--no-index",
            "--no-cache-dir",
            "--no-compile",
            "--only-binary=:all:",
            *(str(path) for path in dependencies),
            str(Path(payload["dir"]) / payload["wheel"]),
        ],
        "Could not install the signed wheel and its pinned offline dependencies.",
    )
    _checked([*pip, "check"], "The signed native environment failed its dependency check.")


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_NOFOLLOW | os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def _locked():
    _secure_directory(_ROOT_HOME)
    fd = os.open(_ROOT_HOME, os.O_NOFOLLOW | os.O_DIRECTORY | os.O_RDONLY)
    try:
        mode = stat.S_IMODE(os.fstat(fd).st_mode)
        if mode != 0o700:
            raise InstallError("The native install lock requires a private root home directory.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError("Another native PVE installation holds the lock.") from None
        # Mutating children retain the lock if the installer is interrupted
        # while they are still working on the reserved installation.
        context = _CHILD_LOCK.set((fd,))
        try:
            yield
        finally:
            _CHILD_LOCK.reset(context)
    finally:
        os.close(fd)


def _object(path: Path, kind: int, mode: int, uid: int, gid: int) -> None:
    entry = path.lstat()
    if (
        stat.S_IFMT(entry.st_mode) != kind
        or stat.S_IMODE(entry.st_mode) != mode
        or (entry.st_uid, entry.st_gid) != (uid, gid)
        or (kind == stat.S_IFREG and entry.st_nlink != 1)
    ):
        raise InstallError(f"An existing native object has unexpected type or ownership ({path}).")


def _directory(path: Path, mode: int, uid: int, gid: int) -> None:
    _object(path, stat.S_IFDIR, mode, uid, gid)


def _children(path: Path, expected: set[str]) -> None:
    if {item.name for item in path.iterdir()} - expected:
        raise InstallError(f"An existing native directory contains unexpected entries ({path}).")


def _write_file(path: Path, contents: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as handle:
        os.fchown(handle.fileno(), _ROOT_UID, _ROOT_GID)
        os.fchmod(handle.fileno(), mode)
        handle.write(contents)
        handle.flush()
        os.fsync(handle.fileno())


def _rename_new(source: Path, target: Path) -> None:
    # Debian Linux renameat2 supports publishing directories without replacing
    # a pre-existing empty directory. AT_FDCWD=-100 and RENAME_NOREPLACE=1.
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(target), 1) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), target)


def _publish_directory(path: Path, mode: int, uid: int, gid: int, populate=None) -> None:
    if native._exists(path):
        raise InstallError(f"A native installation path has appeared ({path}).")
    with tempfile.TemporaryDirectory(dir=path.parent, prefix=".opstend-pve-stage-") as name:
        temporary = Path(name) / "directory"
        temporary.mkdir(mode=0o700)
        if populate is not None:
            populate(temporary)
        # After publication an agent-owned slot can create entries through its
        # parent. Sync the administrative metadata while it is still private.
        os.chown(temporary, uid, gid)
        temporary.chmod(mode)
        _fsync_directory(temporary)
        _rename_new(temporary, path)
        _fsync_directory(path.parent)


def _publish_unit(path: Path, unit: bytes) -> None:
    with tempfile.TemporaryDirectory(dir=path.parent, prefix=".opstend-pve-stage-") as name:
        source = Path(name) / "unit"
        _write_file(source, unit, 0o644)
        # Never replace a unit which appeared after the collision checks.
        _rename_new(source, path)
        _fsync_directory(path.parent)


def _journal_bytes(journal: dict | list) -> bytes:
    return (json.dumps(journal, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _update_journal(config: Path, journal: dict) -> None:
    contents = _journal_bytes(journal)
    if len(contents) > _JOURNAL_LIMIT:
        raise InstallError("The native installation journal exceeds its size limit.")
    with tempfile.TemporaryDirectory(dir=config.parent, prefix=".opstend-pve-stage-") as name:
        source = Path(name) / _JOURNAL
        _write_file(source, contents, 0o600)
        source.replace(config / _JOURNAL)
        _fsync_directory(config)


def _read_journal(config: Path) -> dict | None:
    if not native._exists(config):
        return None
    _directory(config, 0o700, _ROOT_UID, _ROOT_GID)
    _children(config, {_JOURNAL})
    path = config / _JOURNAL
    if not native._exists(path):
        raise InstallError("The native config directory lacks an installation journal.")
    _object(path, stat.S_IFREG, 0o600, _ROOT_UID, _ROOT_GID)
    try:
        journal = json.loads(
            native._read_file(path, _JOURNAL_LIMIT, private=True),
            object_pairs_hook=native._unique_object,
        )
        if not isinstance(journal, dict):
            raise ValueError
        return journal
    except (ValueError, TypeError):
        raise InstallError("Invalid native installation journal.") from None


def _validate_install_journal(journal: dict, intent: dict, accounts: set[str]) -> None:
    try:
        if (
            set(journal) != {"intent", "uids", "tree", "complete", "reservation"}
            or journal["intent"] != intent
            or not re.fullmatch(r"[0-9a-f]{48}", journal["reservation"])
            or type(journal["complete"]) is not bool
            or set(journal["uids"]) != accounts
            or any(
                type(uid) is not int or not 100 <= uid <= 999 for uid in journal["uids"].values()
            )
            or len(set(journal["uids"].values())) != len(accounts)
            or (journal["tree"] is not None and not re.fullmatch(r"[0-9a-f]{64}", journal["tree"]))
            or (journal["complete"] and not journal["tree"])
        ):
            raise ValueError
    except (TypeError, ValueError, KeyError, AttributeError):
        raise InstallError(
            "The native installation journal does not match this exact intent."
        ) from None


def _lookup(database: str, key: str) -> str | None:
    result = native._run(["/usr/bin/getent", database, key])
    if result.returncode == 2 and not result.stdout:
        return None
    if result.returncode != 0 or not result.stdout or len(result.stdout.splitlines()) != 1:
        raise InstallError("Could not inspect a native service account.")
    return result.stdout.strip()


def _available_uids(accounts: dict[str, bytes]) -> dict[str, int]:
    available = {}
    for uid in range(999, 99, -1):
        key = str(uid)
        if _lookup("passwd", key) is None and _lookup("group", key) is None:
            name = next(name for name in accounts if name not in available)
            available[name] = uid
            if len(available) == len(accounts):
                return available
    raise InstallError("Could not reserve free system account identities.")


def _identity(name: str, uid: int, reservation: str) -> bool:
    passwd = _lookup("passwd", name)
    group = _lookup("group", name)
    if passwd is None and group is None:
        if _lookup("passwd", str(uid)) is not None or _lookup("group", str(uid)) is not None:
            raise InstallError("A reserved numeric service identity is already occupied.")
        return False
    expected_user = f"{name}:x:{uid}:{uid}:OpsTend PVE {reservation}:/nonexistent:/usr/sbin/nologin"
    shadow = _lookup("shadow", name)
    if (
        passwd != expected_user
        or group != f"{name}:x:{uid}:"
        or _lookup("passwd", str(uid)) != passwd
        or _lookup("group", str(uid)) != group
        or shadow is None
        or shadow.split(":")[1:2] != ["!"]
    ):
        raise InstallError("A native service account does not match its reserved identity.")
    groups = native._run(["/usr/bin/id", "-G", name])
    if groups.returncode != 0 or groups.stdout.split() != [str(uid)]:
        raise InstallError("A native service account has unexpected group memberships.")
    return True


def _create_identity(name: str, uid: int, reservation: str) -> None:
    _checked(
        [
            "/usr/sbin/useradd",
            "--system",
            "--uid",
            str(uid),
            "--user-group",
            "--no-create-home",
            "--no-log-init",
            "--home-dir",
            "/nonexistent",
            "--shell",
            "/usr/sbin/nologin",
            "--comment",
            f"OpsTend PVE {reservation}",
            "--password",
            "!",
            name,
        ],
        "Could not create the reserved native service account.",
    )
    if not _identity(name, uid, reservation):
        raise InstallError("The native service account was not created.")


def _marker(journal: dict) -> bytes:
    return (journal["reservation"] + "\n").encode("ascii")


def _verify_marker(path: Path, journal: dict) -> None:
    marker = path / _MARKER
    marker_mode = stat.S_IMODE(marker.lstat().st_mode)
    if marker_mode not in (0o400, 0o444):
        raise InstallError("The native ownership marker has unexpected permissions.")
    _object(marker, stat.S_IFREG, marker_mode, _ROOT_UID, _ROOT_GID)
    if native._read_file(marker, 64) != _marker(journal):
        raise InstallError("The reserved directory does not match the native journal.")


def _write_marker(path: Path, journal: dict) -> None:
    _write_file(path / _MARKER, _marker(journal), 0o400)


def _pending_tree(path: Path, journal: dict) -> None:
    # The no-current-pointer branch is the only one allowed to retry a
    # private, incomplete venv. Its marker was atomically reserved with it.
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if mode not in (0o700, 0o555):
        raise InstallError("The pending release directory has unexpected permissions.")
    _directory(path, mode, _ROOT_UID, _ROOT_GID)
    _children(path, {_MARKER, "venv"})
    _verify_marker(path, journal)
    venv = path / "venv"
    if native._exists(venv):
        _secure_directory(venv)


def _prepare_version(path: Path, journal: dict, payload: dict, wheels: list[Path]) -> str:
    _verify_unmounted(path)
    if not native._exists(path):
        _publish_directory(
            path,
            0o700,
            _ROOT_UID,
            _ROOT_GID,
            lambda directory: _write_marker(directory, journal),
        )
    _pending_tree(path, journal)
    path.chmod(0o700)
    venv = path / "venv"
    if native._exists(venv):
        if not shutil.rmtree.avoids_symlink_attacks:
            raise InstallError("Native package rebuild requires symlink-safe directory removal.")
        shutil.rmtree(venv)
    _build_venv(payload, wheels, venv)
    return _sealed_tree(path, prepare=True)


def _sealed_tree(path: Path, *, prepare: bool = False) -> str:
    digest = hashlib.sha256()

    def visit(item: Path) -> None:
        info = item.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if prepare and info.st_uid == _ROOT_UID and info.st_gid != _ROOT_GID:
            os.chown(item, _ROOT_UID, _ROOT_GID, follow_symlinks=False)
        elif (info.st_uid, info.st_gid) != (_ROOT_UID, _ROOT_GID):
            raise InstallError("The release tree contains a file with unexpected ownership.")
        if stat.S_ISLNK(info.st_mode):
            record = ["link", os.readlink(item)]
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise InstallError("The release tree contains a hard link.")
            expected = 0o555 if mode & 0o100 else 0o444
            if prepare:
                item.chmod(expected)
                with item.open("rb") as handle:
                    os.fsync(handle.fileno())
            elif mode != expected:
                raise InstallError("The installed release contains a writable or altered file.")
            record = ["file", expected, release.sha256_file(item)]
        elif stat.S_ISDIR(info.st_mode):
            if not prepare and mode != 0o555:
                raise InstallError(
                    "The installed release contains a writable or altered directory."
                )
            for child in sorted(item.iterdir()):
                visit(child)
            if prepare:
                item.chmod(0o555)
                _fsync_directory(item)
            record = ["dir", 0o555]
        else:
            raise InstallError("The release tree contains a non-file object.")
        digest.update(_journal_bytes([str(item.relative_to(path)), *record]))

    _directory(path, 0o700 if prepare else 0o555, _ROOT_UID, _ROOT_GID)
    visit(path)
    return digest.hexdigest()


def _unit_state(name: str, path: Path) -> dict:
    stdout = _checked(
        [
            *_SYSTEMCTL,
            "show",
            "--all",
            "--property=LoadState,ActiveState,FragmentPath,DropInPaths,"
            "UnitFileState,Type,MainPID,NeedDaemonReload",
            name,
        ],
        "Could not inspect the effective native service unit.",
        timeout=10,
    )
    properties = dict(line.split("=", 1) for line in stdout.splitlines() if "=" in line)
    if (
        properties.get("LoadState") != "loaded"
        or properties.get("FragmentPath") != str(path)
        or properties.get("DropInPaths") != ""
        or properties.get("Type") != "notify"
        or properties.get("ActiveState") not in {"active", "inactive", "failed", "activating"}
        or properties.get("UnitFileState") not in {"enabled", "disabled"}
    ):
        raise InstallError("The effective native unit does not match the reserved unit.")
    return properties


def _want(path: Path) -> Path:
    return path.parent / "multi-user.target.wants" / path.name


def _link(path: Path, target: Path) -> None:
    _object(path, stat.S_IFLNK, 0o777, _ROOT_UID, _ROOT_GID)
    if os.readlink(path) != str(target):
        raise InstallError(f"An existing native link points to an unexpected target ({path}).")


def _listener(mode: str, assignments: dict[str, Path]) -> dict:
    if mode == "agent" or not (sockets := native._listener_inodes()):
        return native._finding(True, "No unowned standalone listener.")
    ui = f"{native._UI}.service"
    if ui in assignments:
        properties = _unit_state(ui, assignments[ui])
        raw_pid = properties.get("MainPID", "")
        if (
            properties["ActiveState"] in {"active", "activating"}
            and raw_pid.isascii()
            and raw_pid.isdecimal()
        ):
            pid = int(raw_pid)
            if pid > 0:
                descriptors = set()
                for fd in Path(f"/proc/{pid}/fd").iterdir():
                    try:
                        descriptors.add(os.readlink(fd))
                    except FileNotFoundError:
                        continue
                if {f"socket:[{inode}]" for inode in sockets} <= descriptors:
                    return native._finding(True, "The verified native UI owns the listener.")
    return native._finding(False, "The standalone port has an unowned listener.")


def _admitted_objects(
    paths: dict[str, Path], accounts: dict[str, bytes], journal: dict | None, version: Path
) -> tuple[set[Path], dict[str, Path], set[str]]:
    owned_paths = set()
    owned_units = {}
    owned_accounts = set()
    install, config, state = (paths[key] for key in ("install", "config", "state"))
    complete = journal is not None and journal["complete"]
    if journal:
        owned_paths.add(config)
        if native._exists(install):
            _directory(install, 0o755, _ROOT_UID, _ROOT_GID)
            _children(install, {_MARKER, "releases", "current"})
            _verify_marker(install, journal)
            releases = version.parent
            if native._exists(releases):
                _directory(releases, 0o755, _ROOT_UID, _ROOT_GID)
                _children(releases, {version.name})
            if native._exists(version):
                if journal["tree"] is None and not native._exists(install / "current"):
                    _pending_tree(version, journal)
                elif _sealed_tree(version) != journal["tree"]:
                    raise InstallError("The installed release does not match the native journal.")
            elif journal["tree"] is not None or native._exists(install / "current"):
                raise InstallError("The reserved release tree is missing.")
            if native._exists(install / "current"):
                _link(install / "current", version)
            elif complete:
                raise InstallError("The reserved current release pointer is missing.")
            owned_paths.add(install)
        elif journal["tree"] is not None:
            raise InstallError("The reserved install directory is missing.")
        for name, uid in journal["uids"].items():
            if _identity(name, uid, journal["reservation"]):
                owned_accounts.add(name)
        if native._exists(state):
            _directory(state, 0o755, _ROOT_UID, _ROOT_GID)
            _children(state, {_MARKER, "agent"})
            _verify_marker(state, journal)
            if native._exists(state / "agent"):
                if native._AGENT not in owned_accounts:
                    raise InstallError("The state directory has no verified agent identity.")
                uid = journal["uids"][native._AGENT]
                _directory(state / "agent", 0o750, uid, uid)
            elif complete:
                raise InstallError("The reserved agent data directory is missing.")
            owned_paths.add(state)

    # Include the disabled UI slot when checking enablement collisions.
    for name in (native._AGENT, native._UI):
        unit_name = f"{name}.service"
        path = native._UNIT_DIR / unit_name
        want = _want(path)
        if journal and name in accounts and native._exists(path):
            if journal["tree"] is None or not (
                native._exists(install / "current")
                and state in owned_paths
                and native._exists(state / "agent")
                and owned_accounts == accounts.keys()
            ):
                raise InstallError("A reserved unit appeared before the native release was ready.")
            _object(path, stat.S_IFREG, 0o644, _ROOT_UID, _ROOT_GID)
            if path.stat().st_size != len(accounts[name]) or path.read_bytes() != accounts[name]:
                raise InstallError("A reserved unit does not match the rendered unit.")
            if native._exists(want):
                _secure_directory(want.parent)
                _link(want, path)
            owned_paths.add(path)
            owned_units[unit_name] = path
        elif native._exists(want):
            raise InstallError("An unowned native unit enablement link already exists.")

    if complete and (
        {install, state} - owned_paths
        or len(owned_accounts) != len(accounts)
        or len(owned_units) != len(accounts)
    ):
        raise InstallError("The completed native installation is missing reserved objects.")
    return owned_paths, owned_units, owned_accounts


def _active_and_enabled(name: str, path: Path) -> bool:
    state = _unit_state(name, path)
    if state["UnitFileState"] == "enabled":
        _link(_want(path), path)
    return (
        state["ActiveState"] == "active"
        and state["UnitFileState"] == "enabled"
        and state.get("NeedDaemonReload") == "no"
    )


def _activate(units: dict[str, Path]) -> None:
    _checked([*_SYSTEMCTL, "daemon-reload"], "Could not reload native systemd units.")
    states = {name: _unit_state(name, path) for name, path in units.items()}
    for name, path in units.items():
        if states[name]["UnitFileState"] != "enabled":
            _checked([*_SYSTEMCTL, "enable", name], "Could not enable a native systemd unit.")
        _link(_want(path), path)
    for name in units:
        if states[name]["ActiveState"] != "active":
            _checked([*_SYSTEMCTL, "start", name], "A native service did not become ready.")
    if not all(_active_and_enabled(name, path) for name, path in units.items()):
        raise InstallError("The native services did not remain active and enabled.")


def _ensure_directory(
    path: Path, mode: int, uid: int, gid: int, *, journal: dict | None = None
) -> None:
    if not native._exists(path):
        populate = None if journal is None else lambda directory: _write_marker(directory, journal)
        _publish_directory(path, mode, uid, gid, populate)
    _directory(path, mode, uid, gid)
    if journal is not None:
        _verify_marker(path, journal)


def _install_locked(
    *,
    mode: str,
    api_name: str,
    ca_file: Path,
    token_file: Path,
    paths: dict[str, Path],
    accounts: dict[str, bytes],
    prior_agent: bytes,
    intent: dict,
    payload: dict,
    dependencies: list[Path],
) -> dict:
    from . import pve_native_lifecycle as lifecycle

    install, config, state = (paths[key] for key in ("install", "config", "state"))
    version = install / "releases" / payload["version"]
    journal = _read_journal(config)
    if journal and (
        journal.get("schema") == 2
        or (
            journal.get("complete") is True
            and (
                "inventory_token_file" in intent
                or (
                    isinstance(journal.get("intent"), dict)
                    and "inventory_token_file" in journal["intent"]
                )
            )
        )
    ):
        return lifecycle.reconcile_install(
            paths, lifecycle.load_journal(config), intent, prior_agent, accounts[native._AGENT]
        )
    if "inventory_token_file" in intent:
        _inventory_credential(intent, paths)
    if journal is not None:
        _validate_install_journal(journal, intent, set(accounts))
    owned_paths, owned_units, owned_accounts = _admitted_objects(paths, accounts, journal, version)
    result = native.collect_preflight(
        mode=mode,
        api_name=api_name,
        ca_file=ca_file,
        token_file=token_file,
        _conflict_probe=lambda: native._conflicts(
            owned_paths=frozenset(owned_paths),
            owned_identities=frozenset(owned_accounts),
            owned_units=frozenset(owned_units),
        ),
        _listener_probe=lambda: _listener(mode, owned_units),
    )
    if not result["ready"]:
        failed = ", ".join(key for key, value in result["findings"].items() if not value["ok"])
        raise InstallError(f"Native PVE installation preflight failed ({failed}).")
    units = {f"{name}.service": native._UNIT_DIR / f"{name}.service" for name in accounts}
    if (
        journal
        and journal["complete"]
        and all(_active_and_enabled(name, path) for name, path in units.items())
    ):
        return {
            "profile": native.PROFILE,
            "mode": mode,
            "version": payload["version"],
            "changed": 0,
        }

    if journal is None or journal["tree"] is None:
        _check_python()
    if journal is None:
        journal = {
            "intent": intent,
            "uids": _available_uids(accounts),
            "tree": None,
            "complete": False,
            "reservation": secrets.token_hex(24),
        }
        _publish_directory(
            config,
            0o700,
            _ROOT_UID,
            _ROOT_GID,
            lambda directory: _write_file(directory / _JOURNAL, _journal_bytes(journal), 0o600),
        )
    _ensure_directory(install, 0o755, _ROOT_UID, _ROOT_GID, journal=journal)
    _ensure_directory(version.parent, 0o755, _ROOT_UID, _ROOT_GID)
    if journal["tree"] is None:
        journal["tree"] = _prepare_version(version, journal, payload, dependencies)
        _update_journal(config, journal)
    for name, uid in journal["uids"].items():
        if name not in owned_accounts:
            _create_identity(name, uid, journal["reservation"])
    _ensure_directory(state, 0o755, _ROOT_UID, _ROOT_GID, journal=journal)
    agent_uid = journal["uids"][native._AGENT]
    _ensure_directory(state / "agent", 0o750, agent_uid, agent_uid)

    current = install / "current"
    if not native._exists(current):
        # Publish a complete root-owned pointer without replacing an existing link.
        with tempfile.TemporaryDirectory(dir=install.parent, prefix=".opstend-pve-stage-") as name:
            source = Path(name) / "current"
            source.symlink_to(version)
            os.chown(source, _ROOT_UID, _ROOT_GID, follow_symlinks=False)
            _rename_new(source, current)
            _fsync_directory(install)
    _link(current, version)
    for name, contents in accounts.items():
        path = units[f"{name}.service"]
        if not native._exists(path):
            _publish_unit(path, contents)
    _admitted_objects(paths, accounts, journal, version)
    if not _listener(mode, units)["ok"]:
        raise InstallError("The standalone port has an unowned listener.")
    _activate(units)
    if not journal["complete"]:
        journal["complete"] = True
        _update_journal(config, journal)
    return {"profile": native.PROFILE, "mode": mode, "version": payload["version"], "changed": 1}


def _inventory_credential(intent: dict, paths: dict[str, Path]) -> None:
    ref = Path(intent["inventory_token_file"])
    _credential(ref, (*paths.values(), native._UNIT_DIR), private=True)
    health_token = native._load_token(Path(intent["refs"][1]))
    inventory_token = native._load_token(ref)
    if (
        str(ref) in intent["refs"]
        or inventory_token.partition("=")[0] == health_token.partition("=")[0]
    ):
        raise native.PreflightError("Use a separate PVE inventory token identity and file.")


def install(
    *,
    mode: str,
    api_name: str,
    ca_file: Path,
    token_file: Path,
    release_archive: Path,
    release_public_key: Path,
    wheelhouse: Path,
    admin_token_file: Path | None = None,
    ui_cert_file: Path | None = None,
    ui_key_file: Path | None = None,
    inventory_token_file: Path | None = None,
) -> dict:
    """Install or reconcile an exact native deployment on the local PVE node."""
    if os.geteuid() != _ROOT_UID:
        raise native.PreflightError("Native PVE installation requires root.")
    native.install_plan(mode)
    native._validate_api_name(api_name)
    standalone = mode == "standalone"
    optional = (admin_token_file, ui_cert_file, ui_key_file)
    if standalone and any(ref is None for ref in optional):
        raise native.PreflightError("Standalone mode requires the admin token and UI TLS files.")
    if not standalone and any(ref is not None for ref in optional):
        raise native.PreflightError("Agent mode has no admin or UI TLS credentials.")

    paths = {name: Path(value) for name, value in native._PATHS.items()}
    managed = (*paths.values(), native._UNIT_DIR)
    _credential(release_public_key, managed, private=False)
    for ref, private in (
        (ca_file, False),
        (token_file, True),
        (admin_token_file, True),
        (ui_cert_file, False),
        (ui_key_file, True),
    ):
        if ref is not None:
            _credential(ref, managed, private=private)
    native._load_token(token_file)
    if inventory_token_file is not None and (
        inventory_token_file.anchor != "/"
        or not _SAFE_REF.fullmatch(str(inventory_token_file))
        or ".." in inventory_token_file.parts
        or inventory_token_file == release_public_key
    ):
        raise native.PreflightError("Use an absolute, safe and separate PVE inventory token file.")
    if standalone:
        pve_native_runtime.read_admin_token(admin_token_file)
        pve_native_runtime.validate_ui_tls(ui_cert_file, ui_key_file)
    accounts = {
        name: pve_native_runtime.render_unit(
            role,
            api_name=api_name,
            ca_file=ca_file,
            token_file=token_file,
            admin_token_file=admin_token_file,
            ui_cert_file=ui_cert_file,
            ui_key_file=ui_key_file,
        ).encode()
        for role, name in (("agent", native._AGENT), ("ui", native._UI))
        if role == "agent" or standalone
    }
    prior_agent = accounts[native._AGENT]
    if inventory_token_file is not None:
        accounts[native._AGENT] = pve_native_runtime.render_unit(
            "agent",
            api_name=api_name,
            ca_file=ca_file,
            token_file=token_file,
            admin_token_file=admin_token_file,
            inventory_token_file=inventory_token_file,
        ).encode()
    try:
        key = release.load_public_key(release_public_key)
        with release.staged_verified_release(release_archive, key) as payload:
            manifest = _require_native_release(payload)
            with tempfile.TemporaryDirectory(prefix="opstend-pve-install-") as name:
                scratch = Path(name).resolve()
                dependencies, wheel_digests = _wheel_snapshot(payload, wheelhouse, scratch)
                intent = {
                    "schema": 1,
                    "manifest": manifest,
                    "release_key": release.key_id(key),
                    "version": payload["version"],
                    "mode": mode,
                    "api_name": api_name,
                    "refs": [
                        str(ref) if ref is not None else None
                        for ref in (
                            ca_file,
                            token_file,
                            admin_token_file,
                            ui_cert_file,
                            ui_key_file,
                        )
                    ],
                    "wheels": wheel_digests,
                    "units": {
                        name: hashlib.sha256(unit).hexdigest() for name, unit in accounts.items()
                    },
                }
                if inventory_token_file is not None:
                    intent["inventory_token_file"] = str(inventory_token_file)
                with _locked():
                    for directory in (*[path.parent for path in paths.values()], native._UNIT_DIR):
                        for ancestor in (directory, *directory.parents):
                            _secure_directory(ancestor)
                    return _install_locked(
                        mode=mode,
                        api_name=api_name,
                        ca_file=ca_file,
                        token_file=token_file,
                        paths=paths,
                        accounts=accounts,
                        prior_agent=prior_agent,
                        intent=intent,
                        payload=payload,
                        dependencies=dependencies,
                    )
    except release.ReleaseError:
        raise InstallError(
            "Could not verify the signed native PVE release and dependency pins."
        ) from None
    except (OSError, subprocess.SubprocessError, zipfile.BadZipFile, UnicodeError):
        raise InstallError(
            "Could not safely stage or reconcile the native PVE installation."
        ) from None
