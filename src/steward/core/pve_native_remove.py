"""Orderly local removal of the native package and its recorded services."""

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from steward.core import pve_native as native
from steward.core import pve_native_install as installer
from steward.core import pve_native_lifecycle as lifecycle

InstallError = installer.InstallError
_REFS = ("ca_file", "token_file", "admin_token_file", "ui_cert_file", "ui_key_file")
_PHASES = ("prepared", "unlinking", "quarantining", "complete")


def _identity(path: Path) -> list[int]:
    entry = path.lstat()
    return [entry.st_dev, entry.st_ino]


def _valid_identity(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 2
        and all(type(item) is int and item >= 0 for item in value)
        and value[1] > 0
    )


def _staged_release(journal: dict) -> str | None:
    for version, entry in journal["releases"].items():
        if entry["tree"] is None:
            return version
    return None


def _operation(journal: dict) -> dict | None:
    op = journal["operation"]
    if op is None or op["kind"] != "remove":
        return None
    if (
        op.keys()
        != {"kind", "phase", "package_identity", "export", "export_identity", "current", "staged"}
        or op["phase"] not in _PHASES
        or op["staged"] != _staged_release(journal)
        or not _valid_identity(op["package_identity"])
        or (op["export"] is not None and not isinstance(op["export"], str))
        or (op["export_identity"] is not None and not _valid_identity(op["export_identity"]))
        or (op["export"] is None and op["export_identity"] is not None)
        or (
            op["phase"] != "prepared" and op["export"] is not None and op["export_identity"] is None
        )
    ):
        raise InstallError("The native removal journal is invalid.")
    return op


def _refs(journal: dict) -> dict:
    return {
        name: ref
        for name, ref in zip(_REFS, journal["intent"]["refs"], strict=True)
        if ref is not None
    }


def _export_bytes(journal: dict) -> bytes:
    intent = journal["intent"]
    return installer._journal_bytes(
        {
            "profile": native.PROFILE,
            "mode": intent["mode"],
            "api": {"host": native.API_HOST, "port": native.API_PORT, "name": intent["api_name"]},
            "credential_refs": _refs(journal),
        }
    )


def _export_staging(paths: dict[str, Path], journal: dict, quarantine: Path, dest: Path) -> Path:
    staging = dest.parent / f".opstend-pve-export-{journal['reservation']}"
    if (
        dest.anchor != "/"
        or ".." in dest.parts
        or staging == dest
        or any(
            dest.is_relative_to(root) for root in (*paths.values(), native._UNIT_DIR, quarantine)
        )
        or any(str(path) in journal["intent"]["refs"] for path in (dest, staging))
    ):
        raise native.PreflightError(
            "Use an absolute export path outside managed paths and credentials."
        )
    for parent in reversed(dest.parents):
        installer._secure_directory(parent)
    return staging


def _verify_export(path: Path, content: bytes, identity: list[int] | None) -> None:
    installer._object(path, stat.S_IFREG, 0o600, installer._ROOT_UID, installer._ROOT_GID)
    if (identity is not None and _identity(path) != identity) or native._read_file(
        path, len(content), private=True
    ) != content:
        raise InstallError("The native removal export differs from the recorded configuration.")


def _publish_export(config: Path, journal: dict, dest: Path, staging: Path) -> None:
    op = journal["operation"]
    content = _export_bytes(journal)
    if native._exists(dest):
        if op["export_identity"] is None or native._exists(staging):
            raise InstallError("The native removal export destination already exists.")
    else:
        if op["export_identity"] is None:
            if not native._exists(staging):
                with tempfile.TemporaryDirectory(
                    dir=dest.parent, prefix=".opstend-pve-stage-"
                ) as name:
                    source = Path(name) / "export"
                    installer._write_file(source, content, 0o600)
                    installer._rename_new(source, staging)
            installer._fsync_directory(dest.parent)
            _verify_export(staging, content, None)
            op["export_identity"] = _identity(staging)
            installer._update_journal(config, journal)
        _verify_export(staging, content, op["export_identity"])
        installer._rename_new(staging, dest)
    _verify_export(dest, content, op["export_identity"])
    installer._fsync_directory(dest.parent)


def _units(journal: dict) -> list[tuple[Path, str]]:
    digests = journal["intent"]["units"]
    return [
        (native._UNIT_DIR / f"{name}.service", digests[name])
        for name in (native._UI, native._AGENT)
        if name in digests
    ]


def _inspect_unit(unit: Path, digest: str, *, missing_ok: bool = False) -> dict:
    present = native._exists(unit)
    want = installer._want(unit)
    if native._exists(want.parent):
        installer._secure_directory(want.parent)
        if native._exists(want):
            if not present:
                raise InstallError(f"A native enablement link has lost its reserved unit ({want}).")
            installer._link(want, unit)
    if present:
        installer._object(unit, stat.S_IFREG, 0o644, installer._ROOT_UID, installer._ROOT_GID)
        if hashlib.sha256(unit.read_bytes()).hexdigest() != digest:
            raise InstallError(f"The native unit differs from its recorded digest ({unit}).")
        values = installer._unit_state(unit.name, unit)
        if values.get("NeedDaemonReload") != "no":
            raise InstallError(f"The native unit requires a systemd reload ({unit}).")
        return values
    if not missing_ok:
        raise InstallError(f"A verified native unit is missing ({unit}).")
    result = installer._run(
        [
            *installer._SYSTEMCTL,
            "show",
            "--all",
            "--property=LoadState,ActiveState,FragmentPath,DropInPaths,UnitFileState,Type,MainPID,NeedDaemonReload",
            unit.name,
        ],
        timeout=10,
    )
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    absent = {
        "LoadState": "not-found",
        "FragmentPath": "",
        "DropInPaths": "",
        "ActiveState": "inactive",
        "MainPID": "0",
        "UnitFileState": "",
    }
    if result.returncode in (0, 1) and all(
        values.get(key) == value for key, value in absent.items()
    ):
        return values
    if result.returncode == 0 and (
        values.get("LoadState") == "loaded"
        and values.get("FragmentPath") == str(unit)
        and values.get("DropInPaths") == ""
        and values.get("Type") == "notify"
        and values.get("ActiveState") in {"active", "inactive", "failed", "activating"}
    ):
        # An interrupted unlink can leave the verified fragment cached until reload.
        return values
    raise InstallError(f"The effective native unit differs from the recorded service ({unit}).")


def _stopped(values: dict) -> bool:
    return values["ActiveState"] in {"inactive", "failed"} and values.get("MainPID") == "0"


def _stop_units(units: list[tuple[Path, str]], *, missing_ok: bool) -> None:
    for unit, digest in units:
        if not _stopped(_inspect_unit(unit, digest, missing_ok=missing_ok)):
            installer._checked(
                [*installer._SYSTEMCTL, "stop", "--job-mode=ignore-dependencies", unit.name],
                f"Could not stop the native unit ({unit}).",
            )
        values = _inspect_unit(unit, digest, missing_ok=missing_ok)
        if not _stopped(values):
            raise InstallError(f"The native unit did not stop ({unit}).")
        if values["ActiveState"] == "failed":
            # systemd can retain a failed unit after its fragment is unlinked.
            installer._checked(
                [*installer._SYSTEMCTL, "reset-failed", unit.name],
                f"Could not clear native unit failure state ({unit}).",
            )


def _verify_units_absent(units: list[tuple[Path, str]]) -> None:
    for unit, digest in units:
        if (
            native._exists(unit)
            or _inspect_unit(unit, digest, missing_ok=True)["LoadState"] != "not-found"
        ):
            raise InstallError(f"The native systemd unit is still present ({unit}).")


def _unlink_units(units: list[tuple[Path, str]]) -> None:
    for unit, digest in units:
        if not _stopped(_inspect_unit(unit, digest, missing_ok=True)):
            raise InstallError(f"The native unit is no longer stopped ({unit}).")
        want = installer._want(unit)
        if native._exists(want.parent):
            want.unlink(missing_ok=True)
            installer._fsync_directory(want.parent)
        unit.unlink(missing_ok=True)
        installer._fsync_directory(unit.parent)
    installer._checked(
        [*installer._SYSTEMCTL, "daemon-reload"], "Could not reload systemd after removal."
    )
    _verify_units_absent(units)


def _verify_package_location(paths: dict[str, Path], journal: dict, quarantine: Path) -> None:
    root = paths["install"]
    op = _operation(journal)
    if native._exists(root):
        if native._exists(quarantine) or (op and op["phase"] == "complete"):
            raise InstallError("The native package location conflicts with the removal journal.")
        installer._verify_unmounted(root)
        lifecycle.verify_package(paths, journal)
        if op and _identity(root) != op["package_identity"]:
            raise InstallError("The native package root was replaced during removal.")
    elif op is None or op["phase"] in {"prepared", "unlinking"}:
        raise InstallError("The owned package root is missing before quarantine.")
    elif native._exists(quarantine):
        if op["phase"] == "complete":
            raise InstallError("The native quarantine path reappeared after removal.")
        installer._verify_unmounted(quarantine)
        installer._secure_directory(quarantine)
        if _identity(quarantine) != op["package_identity"]:
            raise InstallError("The native quarantine root does not match the removal journal.")


def _delete_package(paths: dict[str, Path], journal: dict, quarantine: Path) -> None:
    _verify_package_location(paths, journal, quarantine)
    root = paths["install"]
    if native._exists(root):
        installer._rename_new(root, quarantine)
        installer._fsync_directory(root.parent)
    if native._exists(quarantine):
        installer._verify_unmounted(quarantine)
        if _identity(quarantine) != journal["operation"]["package_identity"]:
            raise InstallError("The native quarantine root changed before deletion.")
        if not shutil.rmtree.avoids_symlink_attacks:
            raise InstallError("Native package deletion requires symlink-safe directory removal.")
        shutil.rmtree(quarantine)
    installer._fsync_directory(root.parent)
    if native._exists(root) or native._exists(quarantine):
        raise InstallError("The native package is still present after removal.")


def _report(paths: dict[str, Path], journal: dict, *, plan: bool, changed: bool) -> dict:
    op = _operation(journal)
    removed = bool(op and op["phase"] == "complete")
    return {
        "profile": native.PROFILE,
        "mode": journal["intent"]["mode"],
        "changed": int(changed),
        "plan": plan,
        "removed": removed,
        "remove": {
            "package": str(paths["install"]),
            "units": [str(unit) for unit, _ in _units(journal)],
            "enablement": [str(installer._want(unit)) for unit, _ in _units(journal)],
            "releases": [
                str(paths["install"] / "releases" / version)
                for version in sorted(journal["releases"])
            ],
        },
        "preserve": {
            "state": str(paths["state"]),
            "config": str(paths["config"]),
            "accounts": sorted(journal["uids"]),
            "credential_refs": {
                name: {"path": path, "present": native._exists(Path(path))}
                for name, path in _refs(journal).items()
            },
        },
        "export_config": op["export"] if op else None,
        "local_connection": "disconnected" if removed else "disconnect_on_remove",
        "pve_token": "operator_managed",
    }


def _remove_locked(plan: bool, export_config: Path | None) -> dict:
    paths = lifecycle.managed_paths()
    config = paths["config"]
    root = paths["install"]
    journal = lifecycle.load_journal(config)
    op = _operation(journal)
    phase = op["phase"] if op else None
    quarantine = root.parent / f".{root.name}-remove-{journal['reservation']}"
    if phase in {None, "prepared", "unlinking"} and native._exists(quarantine):
        raise InstallError("The native removal quarantine path already exists.")
    units = _units(journal)
    installer._verify_unmounted(
        *(item for unit, _ in units for item in (unit, installer._want(unit)))
    )
    lifecycle.verify_retained(paths, journal)
    _verify_package_location(paths, journal, quarantine)
    if phase in {"quarantining", "complete"}:
        _verify_units_absent(units)
    else:
        for unit, digest in units:
            _inspect_unit(unit, digest, missing_ok=phase == "unlinking")

    requested = str(export_config) if export_config is not None else None
    if op and requested is not None and requested != op["export"]:
        raise native.PreflightError(
            "Repeat removal with the recorded configuration export destination."
        )
    dest = Path(op["export"]) if op and op["export"] is not None else export_config
    if dest is not None and phase != "complete":
        staging = _export_staging(paths, journal, quarantine, dest)
        if phase is None and (native._exists(dest) or native._exists(staging)):
            raise InstallError(
                "The native removal export destination or its staging path already exists."
            )
        if phase in {"unlinking", "quarantining"}:
            _verify_export(dest, _export_bytes(journal), op["export_identity"])
    if plan or phase == "complete":
        return _report(paths, journal, plan=plan, changed=False)

    if op is None:
        op = {
            "kind": "remove",
            "phase": "prepared",
            "package_identity": _identity(root),
            "export": requested,
            "export_identity": None,
            "current": lifecycle.current_version(paths, journal),
            "staged": _staged_release(journal),
        }
        journal["operation"] = op
        installer._update_journal(config, journal)
    if op["phase"] == "prepared":
        if dest is not None:
            _publish_export(config, journal, dest, staging)
        _stop_units(units, missing_ok=False)
        op["phase"] = "unlinking"
        installer._update_journal(config, journal)
    if op["phase"] == "unlinking":
        # A reboot before unlinking could have started the owned units again.
        _stop_units(units, missing_ok=True)
        _unlink_units(units)
        op["phase"] = "quarantining"
        installer._update_journal(config, journal)
    _delete_package(paths, journal, quarantine)
    lifecycle.verify_retained(paths, journal)
    _verify_units_absent(units)
    op["phase"] = "complete"
    installer._update_journal(config, journal)
    return _report(paths, journal, plan=False, changed=True)


def remove(*, plan: bool = False, export_config: Path | None = None) -> dict:
    """Preview or remove only the locally verified native package and service units."""
    if os.geteuid() != installer._ROOT_UID:
        raise native.PreflightError("Native PVE removal requires root.")
    if plan and export_config is not None:
        raise native.PreflightError("Use either removal plan or configuration export.")
    try:
        with installer._locked():
            return _remove_locked(plan, export_config)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise InstallError("Could not safely remove the native PVE installation.") from None
