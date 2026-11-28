"""OpsTend updates itself.

The release pipeline publishes the wheel, `SHA256SUMS` and a Sigstore bundle for
`SHA256SUMS`, signed keylessly by the release workflow of grethel-labs/opstend.
`opstend self-update` (run as root through the agent):

1. finds the newest release for the channel,
2. verifies the Sigstore signature of SHA256SUMS against the release workflow
   identity (fails closed), then the wheel's SHA-256,
3. installs the wheel into a fresh environment `releases/<version>`,
4. switches the `current` link atomically and restarts the service,
5. waits for the health check, otherwise switches back and restarts again.

Across the fleet the rollout planner orders the nodes, so voters update one at
a time and the control plane keeps its majority.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

REPO = "grethel-labs/opstend"
IDENTITY = f"https://github.com/{REPO}/.github/workflows/release.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
MAX_WHEEL = 64 * 1024 * 1024


class UpdateError(RuntimeError):
    pass


_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$")


def parse_version(text: str) -> tuple[int, int, int, tuple[Any, ...]]:
    m = _SEMVER.match(text.strip())
    if not m:
        raise ValueError(f"not a version: {text!r}")
    pre = m.group(4)
    # A release sorts after its pre-releases.
    pre_key: tuple[Any, ...] = (
        (1,)
        if pre is None
        else (0, *((0, int(p)) if p.isdigit() else (1, p) for p in pre.split(".")))
    )
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), pre_key


def newer(candidate: str, current: str) -> bool:
    return parse_version(candidate) > parse_version(current)


@dataclass
class Release:
    version: str
    wheel_url: str
    sums_url: str
    sums_bundle_url: str
    prerelease: bool

    @property
    def wheel_name(self) -> str:
        return f"opstend-{self.version}-py3-none-any.whl"


def pick_release(releases: list[dict[str, Any]], channel: str = "stable") -> Release | None:
    best: Release | None = None
    for rel in releases:
        if rel.get("draft") or (rel.get("prerelease") and channel == "stable"):
            continue
        version = str(rel.get("tag_name", "")).lstrip("v")
        try:
            parse_version(version)
        except ValueError:
            continue
        assets = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
        wheel = f"opstend-{version}-py3-none-any.whl"
        if not {wheel, "SHA256SUMS", "SHA256SUMS.sigstore.json"} <= set(assets):
            continue
        cand = Release(
            version,
            assets[wheel],
            assets["SHA256SUMS"],
            assets["SHA256SUMS.sigstore.json"],
            bool(rel.get("prerelease")),
        )
        if best is None or newer(cand.version, best.version):
            best = cand
    return best


def expected_hash(sums: str, name: str) -> str:
    for line in sums.splitlines():
        parts = line.split()
        if (
            len(parts) == 2
            and parts[1].lstrip("*") == name
            and re.fullmatch(r"[0-9a-f]{64}", parts[0])
        ):
            return parts[0]
    raise UpdateError(f"{name} is not listed in SHA256SUMS")


def verify_signature(data: bytes, bundle: bytes) -> None:
    """Verify with Sigstore against the release workflow identity. Fails closed."""
    try:
        from sigstore.models import Bundle
        from sigstore.verify import Verifier, policy
    except ImportError as exc:  # pragma: no cover - depends on installation
        raise UpdateError("sigstore is not installed; refusing an unverified update") from exc
    Verifier.production().verify_artifact(
        data, Bundle.from_json(bundle), policy.Identity(identity=IDENTITY, issuer=ISSUER)
    )


@dataclass
class Layout:
    root: Path = Path("/opt/opstend")

    @property
    def releases(self) -> Path:
        return self.root / "releases"

    @property
    def current(self) -> Path:
        return self.root / "current"

    def active_version(self) -> str | None:
        try:
            return os.readlink(self.current).rstrip("/").rsplit("/", 1)[-1]
        except OSError:
            return None

    def switch(self, version: str) -> str | None:
        """Point `current` at a release atomically. Returns the previous version."""
        target = self.releases / version
        if not target.is_dir():
            raise UpdateError(f"release {version} is not installed")
        previous = self.active_version()
        tmp = self.root / f".current-{version}"
        if tmp.is_symlink():
            tmp.unlink()
        tmp.symlink_to(target)
        os.replace(tmp, self.current)
        return previous

    def prune(self, keep: int = 3) -> None:
        active = self.active_version()
        versions = sorted(
            (p.name for p in self.releases.iterdir() if p.is_dir()), key=parse_version, reverse=True
        )
        for old in versions[keep:]:
            if old != active:
                shutil.rmtree(self.releases / old)


def restart_service() -> None:
    if Path("/run/systemd/system").is_dir():
        subprocess.run(["systemctl", "restart", "opstend.service"], check=True)  # noqa: S607
    else:
        subprocess.run(["rc-service", "opstend", "restart"], check=True)  # noqa: S607


def healthy(url: str, timeout: float = 90.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(url, verify=False, timeout=3).status_code == 200:  # noqa: S501 - local
                return True
        except httpx.HTTPError:
            pass
        time.sleep(2)
    return False


class SelfUpdater:
    def __init__(
        self,
        layout: Layout,
        current: str,
        client: httpx.Client | None = None,
        verify: Any = verify_signature,
    ) -> None:
        self.layout = layout
        self.current = current
        self.client = client or httpx.Client(timeout=60.0, follow_redirects=True)
        self.verify = verify

    def check(self, channel: str = "stable") -> Release | None:
        resp = self.client.get(
            f"https://api.github.com/repos/{REPO}/releases", params={"per_page": 20}
        )
        resp.raise_for_status()
        rel = pick_release(resp.json(), channel)
        return rel if rel and newer(rel.version, self.current) else None

    def _get(self, url: str, limit: int) -> bytes:
        with self.client.stream("GET", url) as resp:
            resp.raise_for_status()
            data = bytearray()
            for chunk in resp.iter_bytes():
                data += chunk
                if len(data) > limit:
                    raise UpdateError("download exceeds the size limit")
        return bytes(data)

    def stage(self, rel: Release) -> Path:
        sums = self._get(rel.sums_url, 64 * 1024)
        self.verify(sums, self._get(rel.sums_bundle_url, 1024 * 1024))
        wheel = self._get(rel.wheel_url, MAX_WHEEL)
        if hashlib.sha256(wheel).hexdigest() != expected_hash(sums.decode(), rel.wheel_name):
            raise UpdateError("checksum mismatch; the download was altered or incomplete")
        work = self.layout.root / "downloads"
        work.mkdir(parents=True, exist_ok=True)
        path = work / rel.wheel_name
        path.write_bytes(wheel)
        dest = self.layout.releases / rel.version
        if dest.exists():
            shutil.rmtree(dest)
        uv = str(self.layout.root / "bin" / "uv")
        env = {**os.environ, "UV_PYTHON_INSTALL_DIR": str(self.layout.root / "python")}
        subprocess.run([uv, "venv", "-q", "--python", "3.13", str(dest)], check=True, env=env)
        subprocess.run(
            [uv, "pip", "install", "-q", f"{path}[signing]"],
            check=True,
            env={**env, "VIRTUAL_ENV": str(dest)},
        )
        return dest

    def apply(self, rel: Release, health_url: str) -> str:
        """Install, switch, restart and confirm. Returns the active version afterwards."""
        self.stage(rel)
        previous = self.layout.switch(rel.version)
        restart_service()
        if healthy(health_url):
            self.layout.prune()
            return rel.version
        if previous:
            self.layout.switch(previous)
            restart_service()
        raise UpdateError(f"{rel.version} did not become healthy; returned to {previous}")
