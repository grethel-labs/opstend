"""Restore a retired application's archive before its services can start (L09 step 3).

Run by the deployment as root, after `steward.application_layout directories` and
before any secret, image or unit is installed:

    python -m steward.application_archive reactivate < {"application": ..., "ids": ...}

The input is the same registered application binding the layout step validates.
With no unfinished archive the command changes nothing. Otherwise it verifies the
archive, checks the reserved numerical identity against the pinned account, and
restores released data into the freshly prepared empty directories, or cancels a
retirement that never released data. Failure exits non-zero with a stable error
class, so the deployment stops before anything starts. Nothing here deletes an
archive.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .application_layout import INPUT_LIMIT, layout_bindings, pinned_account
from .core import app_archive as archive
from .core.backups import BackupError


def _check_identity(user: str, identity: dict) -> None:
    try:
        pinned_account(user, identity)
    except (OSError, ValueError, KeyError) as error:
        raise BackupError("identity_changed") from error


def reactivate(configuration: dict) -> dict:
    _data, _pod, services, accounts = layout_bindings(configuration)
    application = configuration["application"]
    inputs = {}
    for service in services:
        user = service["user"]
        source = service["data_source"]
        inputs[service["id"]] = archive.ReactivationService(
            user=user,
            identity=accounts[user],
            data_source=None if source is None else Path(source),
            image=service.get("image", ""),
            image_tag=service.get("image_tag", ""),
        )
    return archive.reactivate(
        archive.ARCHIVE_ROOT,
        application["id"],
        services=inputs,
        isolation=application["isolation"],
        image_cache=archive.IMAGE_CACHE,
        check_identity=_check_identity,
    )


def main() -> None:
    if os.geteuid() != 0 or sys.argv[1:] != ["reactivate"]:
        sys.exit("usage (root only): python -m steward.application_archive reactivate")
    os.umask(0o077)
    try:
        raw = sys.stdin.buffer.read(INPUT_LIMIT + 1)
        if len(raw) > INPUT_LIMIT:
            sys.exit("application archive input exceeds the size limit")
        print(json.dumps(reactivate(json.loads(raw))))
    except BackupError as error:
        sys.exit(f"application archive: {error.error_class}")
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        sys.exit("application archive: invalid input or host state")


if __name__ == "__main__":
    main()
