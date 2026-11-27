"""Read a minimal profile from the local root-owned standalone PVE installation."""

import json
import os
import stat
import subprocess
from datetime import UTC, datetime
from hashlib import sha256

from . import pve_native as native
from . import pve_native_install as host
from . import pve_native_lifecycle as lifecycle
from .fleet_adoption_models import LocalPveProfile
from .fleet_connector import pve_instance_binding

_STATUS_COMMAND = ("/usr/bin/pvesh", "get", "/cluster/status", "--output-format", "json")
_STATUS_LIMIT = 64 * 1024
_MAX_UNIT_SIZE = 64 * 1024


class PveNativeProfileError(ValueError):
    """A trusted standalone native profile could not be exported."""


def _local_binding() -> tuple[str, str]:
    result = subprocess.run(
        _STATUS_COMMAND,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=2,
        check=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if len(result.stdout) > _STATUS_LIMIT:
        raise ValueError
    status = json.loads(result.stdout, object_pairs_hook=native._unique_object)
    if not isinstance(status, list) or len(status) != 1 or not isinstance(status[0], dict):
        raise ValueError
    row = status[0]
    node = row.get("name")
    if (
        not isinstance(node, str)
        or row.get("type") != "node"
        or row.get("id") != f"node/{node}"
        or type(row.get("local")) is not int
        or row["local"] != 1
    ):
        raise ValueError
    return node, pve_instance_binding(row.get("cluster-id"))


def export_pve_profile() -> LocalPveProfile:
    """Project configured roles and release from an idle, verified local installation."""
    if os.geteuid() != host._ROOT_UID:
        raise PveNativeProfileError("Native PVE profile export requires root.")
    try:
        with host._locked():
            paths = lifecycle.managed_paths()
            journal = lifecycle.load_journal(paths["config"])
            lifecycle._require_idle(journal)
            intent = journal["intent"]
            if intent["mode"] != "standalone":
                raise ValueError
            lifecycle.verify_package(paths, journal)
            version = lifecycle.current_version(paths, journal)
            for role in (native._AGENT, native._UI):
                unit = native._UNIT_DIR / f"{role}.service"
                host._object(unit, stat.S_IFREG, 0o644, host._ROOT_UID, host._ROOT_GID)
                contents = native._read_file(unit, _MAX_UNIT_SIZE)
                if sha256(contents).hexdigest() != intent["units"][role]:
                    raise ValueError
            node, binding = _local_binding()
            return LocalPveProfile(
                instance_binding=binding,
                node=node,
                version=version,
                observed_at=datetime.now(UTC),
            )
    except (OSError, ValueError, subprocess.SubprocessError, host.InstallError):
        raise PveNativeProfileError("Could not verify the local standalone PVE profile.") from None
