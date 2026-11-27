"""Journaled upgrades and rollbacks of the native PVE installation."""

import hashlib
import os
import re
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path

from .. import pve_native_runtime, release
from . import pve_native as native
from . import pve_native_install as host
from .pve_native_install import InstallError

_DIGEST = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,39}")
_ORDERED_VERSION = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:(a|b|rc)(0|[1-9][0-9]*))?"
)
_HOST_ERRORS = (OSError, subprocess.SubprocessError)


def managed_paths() -> dict[str, Path]:
    """Validate the root-owned ancestors of the reserved paths under the host lock."""
    paths = {name: Path(value) for name, value in native._PATHS.items()}
    for directory in (*[path.parent for path in paths.values()], native._UNIT_DIR):
        for ancestor in (directory, *directory.parents):
            host._secure_directory(ancestor)
    return paths


def _version_order(version: str) -> tuple[int, ...]:
    match = _ORDERED_VERSION.fullmatch(version)
    if match is None:
        raise InstallError(
            "Use a three-component release version with an optional a, b or rc suffix."
        )
    major, minor, patch, suffix, number = match.groups()
    stage = ("a", "b", "rc", None).index(suffix)
    return int(major), int(minor), int(patch), stage, int(number or "0")


def _valid_wheels(wheels: dict) -> bool:
    return isinstance(wheels, dict) and all(
        host._WHEEL.fullmatch(name) and _DIGEST.fullmatch(digest) for name, digest in wheels.items()
    )


def _release_entry(intent: dict, tree: str | None = None) -> dict:
    return {"manifest": intent["manifest"], "wheels": intent["wheels"], "tree": tree}


def _normalize_journal(raw: dict) -> dict:
    if set(raw) != {"intent", "uids", "reservation", "tree", "complete"}:
        raise ValueError
    if raw["complete"] is not True or raw["tree"] is None:
        raise InstallError(
            "Complete the original native installation before running lifecycle commands."
        )
    return {
        "schema": 2,
        "intent": raw["intent"],
        "uids": raw["uids"],
        "reservation": raw["reservation"],
        "releases": {raw["intent"]["version"]: _release_entry(raw["intent"], raw["tree"])},
        "active": raw["intent"]["version"],
        "previous": None,
        "operation": None,
    }


def _validate_intent(intent: dict, uids: dict) -> None:
    refs = intent["refs"]
    accounts = {native._AGENT, native._UI} if intent["mode"] == "standalone" else {native._AGENT}
    keys = {
        "schema",
        "version",
        "manifest",
        "release_key",
        "mode",
        "api_name",
        "refs",
        "wheels",
        "units",
    }
    if (
        not keys <= set(intent) <= keys | {"inventory_token_file"}
        or type(intent["schema"]) is not int
        or intent["schema"] != 1
        or intent["mode"] not in ("agent", "standalone")
        or not _VERSION.fullmatch(intent["version"])
        or not _DIGEST.fullmatch(intent["manifest"])
        or not _DIGEST.fullmatch(intent["release_key"])
        or not _valid_wheels(intent["wheels"])
        or not isinstance(refs, list)
        or len(refs) != 5
        or any(
            not host._SAFE_REF.fullmatch(ref) or ".." in Path(ref).parts
            for ref in (refs if intent["mode"] == "standalone" else refs[:2])
        )
        or (intent["mode"] == "agent" and refs[2:] != [None, None, None])
        or set(intent["units"]) != accounts
        or any(not _DIGEST.fullmatch(digest) for digest in intent["units"].values())
        or set(uids) != accounts
        or any(type(uid) is not int or not 100 <= uid <= 999 for uid in uids.values())
        or len(set(uids.values())) != len(accounts)
    ):
        raise ValueError
    if "inventory_token_file" in intent and not _valid_inventory_ref(
        intent["inventory_token_file"], refs
    ):
        raise ValueError
    native._validate_api_name(intent["api_name"])


def _valid_inventory_ref(ref: str, refs: list[str | None]) -> bool:
    return (
        host._SAFE_REF.fullmatch(ref) is not None
        and Path(ref).anchor == "/"
        and ".." not in Path(ref).parts
        and ref not in refs
    )


def _validate_operation(
    operation: dict | None, active: str, previous: str | None, releases: dict, intent: dict
):
    if operation is None or operation["kind"] == "remove":
        # The removal implementation validates its own phase and request fields.
        return
    if operation["kind"] == "inventory":
        if (
            set(operation) != {"kind", "phase", "ref", "before", "after"}
            or operation["phase"] not in ("activate", "restore")
            or "inventory_token_file" in intent
            or not _valid_inventory_ref(operation["ref"], intent["refs"])
            or operation["before"] != intent["units"][native._AGENT]
            or operation["before"] == operation["after"]
            or not _DIGEST.fullmatch(operation["after"])
        ):
            raise ValueError
        return
    if (
        set(operation) != {"kind", "source", "target", "phase"}
        or operation["kind"] not in ("upgrade", "rollback")
        or operation["source"] != active
        or operation["target"] == active
        or operation["target"] not in releases
    ):
        raise ValueError
    if operation["kind"] == "rollback":
        if operation["phase"] not in ("activate", "restore") or operation["target"] != previous:
            raise ValueError
    elif operation["phase"] not in ("stage", "activate", "restore"):
        raise ValueError


def load_journal(config: Path) -> dict:
    """Load a completed v1 installation or an existing v2 lifecycle journal."""
    try:
        raw = host._read_journal(config)
        if raw is None:
            raise InstallError("There is no native PVE installation journal.")
        journal = raw if "schema" in raw else _normalize_journal(raw)
        required = {
            "schema",
            "intent",
            "uids",
            "reservation",
            "releases",
            "active",
            "previous",
            "operation",
        }
        if (
            not required <= set(journal) <= required | {"last_rollback"}
            or type(journal["schema"]) is not int
            or journal["schema"] != 2
            or not re.fullmatch(r"[0-9a-f]{48}", journal["reservation"])
        ):
            raise ValueError
        intent = journal["intent"]
        _validate_intent(intent, journal["uids"])
        releases = journal["releases"]
        active, previous, operation = (journal[key] for key in ("active", "previous", "operation"))
        if (
            active not in releases
            or (previous is not None and (previous not in releases or previous == active))
            or ("last_rollback" in journal and journal["last_rollback"] != active)
        ):
            raise ValueError
        _validate_operation(operation, active, previous, releases, intent)
        pending = None
        if operation and operation["kind"] == "remove":
            pending = operation["staged"]
            current = operation["current"]
            if current not in releases or releases[current]["tree"] is None:
                raise ValueError
        elif operation and operation["kind"] == "upgrade" and operation["phase"] == "stage":
            pending = operation["target"]
        for version, entry in releases.items():
            if (
                not _VERSION.fullmatch(version)
                or set(entry) != {"manifest", "wheels", "tree"}
                or not _DIGEST.fullmatch(entry["manifest"])
                or not _valid_wheels(entry["wheels"])
                or (entry["tree"] is None and (version != pending or version in (active, previous)))
                or (entry["tree"] is not None and not _DIGEST.fullmatch(entry["tree"]))
            ):
                raise ValueError
        original = releases[intent["version"]]
        if original != _release_entry(intent, original["tree"]) or original["tree"] is None:
            raise ValueError
        return journal
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        raise InstallError("Invalid native PVE lifecycle journal.") from None


def verify_retained(paths: dict[str, Path], journal: dict) -> None:
    """Verify the reserved host identities and state directories."""
    for name, uid in journal["uids"].items():
        if not host._identity(name, uid, journal["reservation"]):
            raise InstallError("A reserved native service identity is missing.")
    state = paths["state"]
    host._directory(state, 0o755, host._ROOT_UID, host._ROOT_GID)
    host._children(state, {host._MARKER, "agent"})
    host._verify_marker(state, journal)
    uid = journal["uids"][native._AGENT]
    host._directory(state / "agent", 0o750, uid, uid)


def _release_path(paths: dict[str, Path], version: str) -> Path:
    return paths["install"] / "releases" / version


def current_version(paths: dict[str, Path], journal: dict) -> str:
    current = paths["install"] / "current"
    host._object(current, stat.S_IFLNK, 0o777, host._ROOT_UID, host._ROOT_GID)
    pointer = os.readlink(current)
    versions = [journal["active"]]
    operation = journal["operation"]
    if operation:
        if operation["kind"] == "remove":
            versions = [operation["current"]]
        elif operation["kind"] != "inventory" and operation["phase"] != "stage":
            versions.append(operation["target"])
    for version in versions:
        if pointer == str(_release_path(paths, version)):
            return version
    raise InstallError(
        "The current native release pointer is outside the approved lifecycle intent."
    )


def verify_package(paths: dict[str, Path], journal: dict) -> None:
    """Verify the owned package directory, sealed releases, and current pointer."""
    install = paths["install"]
    host._directory(install, 0o755, host._ROOT_UID, host._ROOT_GID)
    host._children(install, {host._MARKER, "releases", "current"})
    host._verify_marker(install, journal)
    releases = install / "releases"
    host._directory(releases, 0o755, host._ROOT_UID, host._ROOT_GID)
    host._children(releases, set(journal["releases"]))
    for version, entry in journal["releases"].items():
        path = releases / version
        if entry["tree"] is None:
            if native._exists(path):
                host._pending_tree(path, journal)
        elif host._sealed_tree(path) != entry["tree"]:
            raise InstallError("An installed native release does not match its sealed tree.")
        else:
            host._verify_marker(path, journal)
    current_version(paths, journal)


def _admit(
    paths: dict[str, Path], journal: dict, *, inventory_retry: dict | None = None
) -> dict[str, Path]:
    verify_retained(paths, journal)
    verify_package(paths, journal)
    intent = journal["intent"]
    units = {}
    for name in (native._AGENT, native._UI):
        unit = f"{name}.service"
        path = native._UNIT_DIR / unit
        want = host._want(path)
        if name not in intent["units"]:
            if native._exists(want):
                raise InstallError("An unowned native unit enablement link already exists.")
            continue
        host._object(path, stat.S_IFREG, 0o644, host._ROOT_UID, host._ROOT_GID)
        pending_agent = inventory_retry if name == native._AGENT else None
        digests = {intent["units"][name]}
        if pending_agent:
            digests.add(pending_agent["after"])
        if release.sha256_file(path) not in digests:
            raise InstallError("A reserved unit does not match its installation journal.")
        host._secure_directory(want.parent)
        host._link(want, path)
        systemd = host._unit_state(unit, path)
        if systemd["UnitFileState"] != "enabled" or (
            not pending_agent and systemd.get("NeedDaemonReload") != "no"
        ):
            raise InstallError("The reserved native unit is disabled or requires a daemon reload.")
        units[unit] = path

    # Recovery needs the verified local objects even when the API is unavailable.
    if inventory_retry is not None:
        return units
    refs = [Path(ref) if ref is not None else None for ref in intent["refs"]]
    managed = (*paths.values(), native._UNIT_DIR)
    for ref, private in zip(refs, (False, True, True, False, True), strict=True):
        if ref is not None:
            host._credential(ref, managed, private=private)
    ca_file, token_file, admin_token, ui_cert, ui_key = refs
    if intent["mode"] == "standalone":
        pve_native_runtime.read_admin_token(admin_token)
        pve_native_runtime.validate_ui_tls(ui_cert, ui_key)
    report = native.collect_preflight(
        mode=intent["mode"],
        api_name=intent["api_name"],
        ca_file=ca_file,
        token_file=token_file,
        _conflict_probe=lambda: native._conflicts(
            owned_paths=frozenset((*paths.values(), *units.values())),
            owned_identities=frozenset(journal["uids"]),
            owned_units=frozenset(units),
        ),
        _listener_probe=lambda: host._listener(intent["mode"], units),
    )
    if not report["ready"]:
        failed = ", ".join(key for key, value in report["findings"].items() if not value["ok"])
        raise InstallError(f"Native PVE lifecycle preflight failed ({failed}).")
    return units


def _result(journal: dict, changed: int) -> dict:
    return {
        "profile": native.PROFILE,
        "mode": journal["intent"]["mode"],
        "version": journal["active"],
        "changed": changed,
    }


def _require_ready(units: dict[str, Path]) -> None:
    if not all(host._active_and_enabled(name, path) for name, path in units.items()):
        raise InstallError("The native services did not remain active and enabled.")


def reconcile_install(
    paths: dict[str, Path], journal: dict, intent: dict, prior_agent: bytes, agent: bytes
) -> dict:
    """Accept an exact install replay and bind an explicitly supplied inventory token once."""
    active = journal["active"]
    entry = journal["releases"][active]
    expected = {
        **journal["intent"],
        "version": active,
        "manifest": entry["manifest"],
        "wheels": entry["wheels"],
    }
    ref = intent.get("inventory_token_file")
    operation = journal["operation"]
    if operation and operation["kind"] != "inventory":
        _require_idle(journal)
    if not operation and ref is None and "inventory_token_file" in expected:
        bound_ref = expected["inventory_token_file"]
        ca, health, admin, _, _ = intent["refs"]
        with_inventory = pve_native_runtime.render_unit(
            "agent",
            api_name=intent["api_name"],
            ca_file=Path(ca),
            token_file=Path(health),
            admin_token_file=Path(admin) if admin else None,
            inventory_token_file=Path(bound_ref),
        ).encode()
        intent = {
            **intent,
            "inventory_token_file": bound_ref,
            "units": {**intent["units"], native._AGENT: hashlib.sha256(with_inventory).hexdigest()},
        }
    if not operation and intent == expected:
        if ref is not None:
            host._inventory_credential(intent, paths)
        _require_ready(_admit(paths, journal))
        return _result(journal, 0)
    if ref is not None and "inventory_token_file" not in expected:
        before = hashlib.sha256(prior_agent).hexdigest()
        after = hashlib.sha256(agent).hexdigest()
        new_intent = {
            **expected,
            "inventory_token_file": ref,
            "units": {**expected["units"], native._AGENT: after},
        }
        if intent == new_intent and before == expected["units"][native._AGENT] and before != after:
            return _bind_inventory(paths, journal, intent, prior_agent, agent, before, after)
    raise InstallError("The native installation journal does not match this exact intent.")


def _activate_inventory_unit(path: Path, contents: bytes, allowed: set[str]) -> None:
    name = path.name
    host._object(path, stat.S_IFREG, 0o644, host._ROOT_UID, host._ROOT_GID)
    if release.sha256_file(path) not in allowed:
        raise InstallError("The reserved agent unit changed during inventory binding.")
    host._unit_state(name, path)
    with tempfile.TemporaryDirectory(dir=path.parent, prefix=".opstend-pve-stage-") as directory:
        source = Path(directory) / "unit"
        host._write_file(source, contents, 0o644)
        source.replace(path)
        host._fsync_directory(path.parent)
    host._checked([*host._SYSTEMCTL, "daemon-reload"], "Could not reload the native agent unit.")
    host._unit_state(name, path)
    host._checked(
        [*host._SYSTEMCTL, "stop", "--job-mode=ignore-dependencies", name],
        "Could not stop the native agent service.",
    )
    host._checked(
        [*host._SYSTEMCTL, "start", "--job-mode=ignore-dependencies", name],
        "The native agent service did not become ready.",
    )


def _bind_inventory(
    paths: dict[str, Path],
    journal: dict,
    intent: dict,
    prior_agent: bytes,
    agent: bytes,
    before: str,
    after: str,
) -> dict:
    operation = journal["operation"]
    ref = intent["inventory_token_file"]
    expected = {
        "kind": "inventory",
        "phase": "activate",
        "ref": ref,
        "before": before,
        "after": after,
    }
    if operation is None:
        host._inventory_credential(intent, paths)
    elif operation != {**expected, "phase": operation["phase"]}:
        raise InstallError("Resume inventory binding with the exact recorded credential reference.")
    units = _admit(paths, journal, inventory_retry=operation)
    unit = units[f"{native._AGENT}.service"]
    host._verify_unmounted(unit, host._want(unit))
    if operation is None:
        _require_ready(units)
        operation = journal["operation"] = expected
        host._update_journal(paths["config"], journal)

    if operation["phase"] == "activate":
        try:
            host._inventory_credential(intent, paths)
            _activate_inventory_unit(unit, agent, {before, after})
            _require_ready(units)
        except (InstallError, native.PreflightError, *_HOST_ERRORS):
            operation["phase"] = "restore"
            host._update_journal(paths["config"], journal)
        else:
            journal["intent"]["inventory_token_file"] = ref
            journal["intent"]["units"][native._AGENT] = after
            journal["operation"] = None
            host._update_journal(paths["config"], journal)
            return _result(journal, 1)

    try:
        _activate_inventory_unit(unit, prior_agent, {before, after})
        _require_ready(units)
    except (InstallError, *_HOST_ERRORS):
        raise InstallError(
            "Native inventory binding failed and restoration is pending. Resume the exact install."
        ) from None
    journal["operation"] = None
    host._update_journal(paths["config"], journal)
    raise InstallError("Native inventory binding failed. The former agent unit was restored.")


def _require_idle(journal: dict) -> None:
    if journal["operation"] is not None:
        raise InstallError("A native lifecycle operation is pending. Resume the exact operation.")


def _switch(paths: dict[str, Path], journal: dict, units: dict[str, Path], target: str) -> None:
    current = current_version(paths, journal)
    # Start/stop only the verified units, including when other units have
    # added reverse dependencies. The UI has an explicit dependency on the agent.
    for name in reversed(units):
        host._checked(
            [*host._SYSTEMCTL, "stop", "--job-mode=ignore-dependencies", name],
            "Could not stop a native service.",
        )
    if any(
        host._unit_state(name, path)["ActiveState"] not in ("inactive", "failed")
        for name, path in units.items()
    ):
        raise InstallError("A native service did not stop.")
    if current != target:
        install = paths["install"]
        pointer = install / "current"
        with tempfile.TemporaryDirectory(dir=install.parent, prefix=".opstend-pve-stage-") as name:
            source = Path(name) / "current"
            source.symlink_to(_release_path(paths, target))
            os.chown(source, host._ROOT_UID, host._ROOT_GID, follow_symlinks=False)
            host._link(pointer, _release_path(paths, current))
            source.replace(pointer)
            host._fsync_directory(install)
    host._link(paths["install"] / "current", _release_path(paths, target))
    if not host._listener(journal["intent"]["mode"], units)["ok"]:
        raise InstallError("The standalone port has an unowned listener.")
    for name, path in units.items():
        host._checked(
            [*host._SYSTEMCTL, "start", "--job-mode=ignore-dependencies", name],
            "A native service did not become ready.",
        )
        if not host._active_and_enabled(name, path):
            raise InstallError("A native service did not become active and enabled.")
    _require_ready(units)


def _restore(
    paths: dict[str, Path], journal: dict, units: dict[str, Path], *, rollback: bool = False
) -> None:
    try:
        _switch(paths, journal, units, journal["active"])
    except (InstallError, *_HOST_ERRORS):
        kind = journal["operation"]["kind"]
        raise InstallError(
            f"Native {kind} failed and restoration is pending. Resume the exact operation."
        ) from None
    journal["operation"] = None
    if rollback:
        journal["last_rollback"] = journal["active"]
    host._update_journal(paths["config"], journal)


def _switch_or_restore(paths: dict[str, Path], journal: dict, units: dict[str, Path]) -> None:
    operation = journal["operation"]
    try:
        _switch(paths, journal, units, operation["target"])
    except (InstallError, *_HOST_ERRORS):
        operation["phase"] = "restore"
        host._update_journal(paths["config"], journal)
        _restore(paths, journal, units)
        raise InstallError(
            f"Native {operation['kind']} failed. The former active release was restored."
        ) from None


def _finish(paths: dict[str, Path], journal: dict, *, rollback: bool = False) -> dict:
    journal["previous"], journal["active"] = journal["active"], journal["operation"]["target"]
    journal["operation"] = None
    if rollback:
        journal["last_rollback"] = journal["active"]
    else:
        journal.pop("last_rollback", None)
    host._update_journal(paths["config"], journal)
    return _result(journal, 1)


def _upgrade_locked(
    paths: dict[str, Path],
    journal: dict,
    payload: dict,
    wheels: list[Path],
    candidate: dict,
) -> dict:
    target = payload["version"]
    active = journal["active"]
    operation = journal["operation"]
    releases = journal["releases"]
    if operation and (operation["kind"] != "upgrade" or operation["target"] != target):
        _require_idle(journal)
    if (
        target in releases
        and _release_entry(candidate, releases[target]["tree"]) != releases[target]
    ):
        raise InstallError(
            "The native release version is already bound to different signed inputs."
        )
    if target == active:
        _require_ready(_admit(paths, journal))
        return _result(journal, 0)
    if _version_order(target) <= _version_order(active):
        raise InstallError("The candidate native release must be newer than the current release.")

    units = _admit(paths, journal)
    if operation and operation["phase"] == "restore":
        _restore(paths, journal, units)
        raise InstallError("Native upgrade failed. The previous release was restored.")
    if operation is None:
        operation = {"kind": "upgrade", "source": active, "target": target, "phase": "stage"}
        journal["operation"] = operation
        releases.setdefault(target, candidate)
        # Leave capacity to seal the candidate and journal a later rollback or removal.
        if len(host._journal_bytes(journal)) > host._JOURNAL_LIMIT - 8192:
            raise InstallError("The lifecycle journal lacks space for another native release.")
        host._update_journal(paths["config"], journal)
    if operation["phase"] == "stage":
        path = _release_path(paths, target)
        if releases[target]["tree"] is None:
            host._check_python()
            releases[target]["tree"] = host._prepare_version(path, journal, payload, wheels)
        operation["phase"] = "activate"
        host._update_journal(paths["config"], journal)
        units = _admit(paths, journal)
    _switch_or_restore(paths, journal, units)
    return _finish(paths, journal)


def upgrade(*, release_archive: Path, release_public_key: Path, wheelhouse: Path) -> dict:
    """Stage a newer signed native release and activate it with automatic restoration."""
    if os.geteuid() != host._ROOT_UID:
        raise native.PreflightError("Native PVE upgrade requires root.")
    try:
        with host._locked():
            paths = managed_paths()
            journal = load_journal(paths["config"])
            if journal["operation"] and journal["operation"]["kind"] != "upgrade":
                _require_idle(journal)
            host._credential(release_public_key, (*paths.values(), native._UNIT_DIR), private=False)
            key = release.load_public_key(release_public_key)
            if release.key_id(key) != journal["intent"]["release_key"]:
                raise InstallError("The candidate must use the trusted native installation signer.")
            with release.staged_verified_release(release_archive, key) as payload:
                manifest = host._require_native_release(payload, match_installer=False)
                with tempfile.TemporaryDirectory(prefix="opstend-pve-upgrade-") as name:
                    wheels, digests = host._wheel_snapshot(
                        payload, wheelhouse, Path(name).resolve()
                    )
                    candidate = {"manifest": manifest, "wheels": digests, "tree": None}
                    return _upgrade_locked(paths, journal, payload, wheels, candidate)
    except release.ReleaseError:
        raise InstallError(
            "Could not verify the signed native PVE release and dependency pins."
        ) from None
    except (*_HOST_ERRORS, zipfile.BadZipFile, UnicodeError):
        raise InstallError("Could not safely stage or activate the native PVE upgrade.") from None


def rollback(*, target: str) -> dict:
    """Activate the sealed previous release or resume the exact recorded recovery."""
    if os.geteuid() != host._ROOT_UID:
        raise native.PreflightError("Native PVE rollback requires root.")
    if not _VERSION.fullmatch(target):
        raise native.PreflightError("Use a valid native PVE release version.")
    try:
        with host._locked():
            paths = managed_paths()
            journal = load_journal(paths["config"])
            operation = journal["operation"]
            if operation and operation["kind"] == "rollback" and operation["phase"] == "restore":
                if target not in (operation["source"], operation["target"]):
                    raise InstallError("The requested release is outside the pending rollback.")
                restoring_source = target == operation["source"]
                _restore(paths, journal, _admit(paths, journal), rollback=restoring_source)
                if restoring_source:
                    return _result(journal, 1)
                raise InstallError(
                    "Native rollback failed. The former active release was restored."
                )
            if (
                operation
                and operation["kind"] == "upgrade"
                and operation["phase"] in ("activate", "restore")
            ):
                if target != operation["source"]:
                    raise InstallError(
                        "Rollback target must match the pending upgrade restoration."
                    )
                units = _admit(paths, journal)
                if operation["phase"] == "activate":
                    operation["phase"] = "restore"
                    host._update_journal(paths["config"], journal)
                _restore(paths, journal, units, rollback=True)
                return _result(journal, 1)
            if operation and (operation["kind"] != "rollback" or target != operation["target"]):
                _require_idle(journal)
            if operation is None and target == journal.get("last_rollback"):
                _require_ready(_admit(paths, journal))
                return _result(journal, 0)
            if target != journal["previous"]:
                raise InstallError("Rollback target must match the previous sealed native release.")
            units = _admit(paths, journal)
            if operation is None:
                journal["operation"] = {
                    "kind": "rollback",
                    "source": journal["active"],
                    "target": target,
                    "phase": "activate",
                }
                host._update_journal(paths["config"], journal)
            _switch_or_restore(paths, journal, units)
            return _finish(paths, journal, rollback=True)
    except _HOST_ERRORS:
        raise InstallError("Could not safely activate the native PVE rollback.") from None
