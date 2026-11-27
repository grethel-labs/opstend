"""Credential files injected into the native PVE units by systemd."""

import os
import stat
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal

_CREDENTIALS_ROOT = Path("/run/credentials")
_CREDENTIAL_IDS = {
    "agent": frozenset({"pve-token", "pve-ca", "pve-inventory-token"}),
    "ui": frozenset({"admin-token", "ui-cert", "ui-key"}),
}


@dataclass(frozen=True)
class _SystemdCredential:
    role: Literal["agent", "ui"]
    name: str

    def __post_init__(self) -> None:
        if self.name not in _CREDENTIAL_IDS.get(self.role, ()):
            raise ValueError("Unknown native PVE systemd credential.")

    @contextmanager
    def open(self) -> Iterator[BinaryIO]:
        unit = f"opstend-pve-{self.role}.service"
        if os.environ.get("CREDENTIALS_DIRECTORY") != str(_CREDENTIALS_ROOT / unit):
            raise ValueError("Expected the native PVE systemd credentials directory.")

        directory_flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW
        with ExitStack() as stack:
            parent = None
            for part in (_CREDENTIALS_ROOT.parent, _CREDENTIALS_ROOT.name, unit):
                parent = os.open(part, directory_flags, dir_fd=parent)
                stack.callback(os.close, parent)
                metadata = os.fstat(parent)
                if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                    raise ValueError("Expected a protected systemd credentials directory.")
            if metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) not in (0o500, 0o550):
                raise ValueError("Expected a protected systemd unit credentials directory.")

            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            fd = os.open(self.name, flags, dir_fd=parent)
            stack.callback(os.close, fd)
            metadata = os.fstat(fd)
            # systemd grants the service user read access through a named ACL.
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) not in (0o400, 0o440)
                or metadata.st_nlink != 1
            ):
                raise ValueError("Expected a protected systemd credential file.")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                yield handle
