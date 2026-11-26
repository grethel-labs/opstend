"""Root-owned host entry point for `steward-host ai login|status|check|revoke` (A04).

The same program serves the operator on the server and the controller's SSH session
(`steward ai login`). It only drops to the inference identity and runs the official
login program; it reads or prints no credential. Every method is refused while it has
no recorded official evidence (see `core/ai_auth.py`)."""

from __future__ import annotations

import json
import os
import pwd
import sys
import time
from collections.abc import Callable
from pathlib import Path

from .core.ai_auth import AUTH_METHODS, AuthError, AuthManager, AuthStore, ProcessRunner
from .core.inference_local import SERVICE_USER, STATE_DIR


def run(
    action: str,
    method: str,
    *,
    relogin: bool = False,
    euid: int | None = None,
    lookup: Callable[[str], pwd.struct_passwd] = pwd.getpwnam,
    base: Path = Path(STATE_DIR),
    manager: AuthManager | None = None,
    out=None,
) -> int:
    """Return an exit code: 0 ok, 2 refused, 1 failed. Messages carry stable codes only."""
    if (os.geteuid() if euid is None else euid) != 0:
        print("error: steward-host ai must run as root", file=sys.stderr)
        return 2
    if manager is None:
        try:
            user = lookup(SERVICE_USER)
        except KeyError:
            print("error: inference identity is not installed", file=sys.stderr)
            return 2
        manager = AuthManager(
            AuthStore(base, user.pw_uid, user.pw_gid),
            ProcessRunner(user.pw_gid),
            clock=time.time,
        )
    try:
        if action == "login":
            doc = manager.login(method, relogin=relogin)
        elif action == "check":
            doc = manager.check(method)
        elif action == "revoke":
            doc = manager.revoke(method)
        else:
            doc = manager.store.read()
    except AuthError as exc:
        print(f"error: {exc.code}", file=sys.stderr)
        if exc.code == "method_unavailable":
            print(f"reason: {manager.methods[method].unavailable_reason}", file=sys.stderr)
        return 2
    print(json.dumps(doc, sort_keys=True), file=out or sys.stdout)
    return 0 if doc["state"] in ("active", "revoked") or action == "status" else 1


METHODS = tuple(AUTH_METHODS)
