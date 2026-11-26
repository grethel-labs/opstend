"""Host operations for applying one verified image (L05).

Mixed into `Host`. Every command is a fixed argv built from values the executor
derived from its root-owned registry and a verified digest: no shell, no
caller-supplied path or argument. Images are fetched by digest as root and given
to the service user as an archive, exactly as the deployment role does, so the
service never needs registry access (ADR 0001 decision 6).
"""

from __future__ import annotations

import os
from pathlib import Path

PULL_TIMEOUT_S = 600
IMAGE_TIMEOUT_S = 300


class ImageHostMixin:
    """Requires `_run` and `_as_user` of the host it is mixed into."""

    def image_fetch(self, ref: str) -> tuple[bool, str]:
        rc, out = self._run(["podman", "pull", "--quiet", ref], PULL_TIMEOUT_S)
        return rc == 0, out.strip()[:300]

    def image_tag(self, ref: str, tag: str) -> tuple[bool, str]:
        rc, out = self._run(["podman", "tag", ref, tag])
        return rc == 0, out.strip()[:300]

    def image_archive(self, tag: str, archive: Path) -> tuple[bool, str]:
        """Write the archive beside its final name, then rename atomically."""
        temporary = archive.with_name(archive.name + ".tmp")
        temporary.unlink(missing_ok=True)
        rc, out = self._run(
            [
                "podman",
                "save",
                "--quiet",
                "--format",
                "oci-archive",
                "--output",
                str(temporary),
                tag,
            ],
            IMAGE_TIMEOUT_S,
        )
        if rc != 0:
            temporary.unlink(missing_ok=True)
            return False, out.strip()[:300]
        if not temporary.is_file():
            return False, "archive was not written"
        os.replace(temporary, archive)
        return True, ""

    def image_exists(self, user: str, tag: str) -> bool | None:
        rc, _ = self._as_user(user, ["podman", "image", "exists", tag])
        return True if rc == 0 else False if rc == 1 else None

    def image_load(self, user: str, archive: Path) -> tuple[bool, str]:
        rc, out = self._as_user(
            user, ["podman", "load", "--quiet", "--input", str(archive)], IMAGE_TIMEOUT_S
        )
        return rc == 0, out.strip()[:300]

    def user_image_id(self, user: str, tag: str) -> str | None:
        rc, out = self._as_user(user, ["podman", "image", "inspect", "--format", "{{.ID}}", tag])
        return out.strip() if rc == 0 else None

    def reload_user_manager(self, user: str) -> bool:
        """Regenerate Quadlet units after a root-owned `.container` file changed."""
        rc, _ = self._as_user(user, ["systemctl", "--user", "daemon-reload"])
        return rc == 0
