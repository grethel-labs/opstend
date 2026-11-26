"""`steward ai login|status|check|revoke`: the controller side of guided login (A04).

The controller never sees a credential. It opens an interactive SSH session to the
configured server and starts the same root-owned `steward-host ai ...` entry point the
operator can run locally; the official provider program runs there under the inference
identity. Fixed argv only: the method is chosen from a closed list."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ..core.ai_auth import AUTH_METHODS
from ..core.config import Config

HOST_PROGRAM = "/opt/steward/current/venv/bin/steward-host"
ACTIONS = ("login", "status", "check", "revoke")


def ssh_argv(cfg: Config, action: str, method: str | None, *, relogin: bool = False) -> list[str]:
    if action not in ACTIONS or (action != "status" and method not in AUTH_METHODS):
        raise ValueError("invalid ai action or method")
    argv = ["ssh", "-tt", "-p", str(cfg.server.port), "-o", "StrictHostKeyChecking=yes"]
    if cfg.server.known_hosts_file:
        known = Path(cfg.server.known_hosts_file).expanduser().resolve()
        argv += ["-o", f"UserKnownHostsFile={known}"]
    key = os.environ.get("STEWARD_SSH_PRIVATE_KEY_FILE")
    if key:
        argv += ["-o", "IdentitiesOnly=yes", "-i", key]
    argv += ["--", f"{cfg.server.user}@{cfg.server.host}"]
    argv += ["sudo", "--", HOST_PROGRAM, "ai", action]
    if action != "status":
        argv += ["--method", str(method)]
    if relogin and action == "login":
        argv.append("--relogin")
    return argv


def run(cfg: Config, action: str, method: str | None, *, relogin: bool = False) -> int:
    """Interactive session on the operator's terminal; returns the host exit code."""
    return subprocess.run(  # noqa: S603 - fixed argv built above
        ssh_argv(cfg, action, method, relogin=relogin), check=False
    ).returncode
