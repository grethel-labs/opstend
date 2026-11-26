"""Guided login and credential lifecycle for interactive inference methods (A04).

Only the *state machine and its protections* live here; the login itself is the
official, unmodified program of the provider, run under the inference identity with
its own native state directory. Nothing here reads, copies, forwards or stores a
token: the status document holds a state name, times and a fixed reason, nothing
else. Credentials never appear in arguments, logs, configuration or Git.

Every subscription method stays *unavailable* until G4 confirms permitted
unattended server use, isolated transport and credential custody, and an authorized
actual login and revoke. Documentary references are separate from the activation
evidence in `AUTH_METHODS`. API-key and local methods do not use this module's login.

States: `pending` (no valid credential yet), `active`, `expired`, `revoked`,
`unavailable` (method not supported). Deterministic features never depend on them;
they only become findings.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

STATES = ("pending", "active", "expired", "revoked", "unavailable")
REASONS = frozenset(
    {
        "never_logged_in",
        "login_started",
        "login_failed",
        "login_verified",
        "provider_rejected_credential",
        "check_expired",
        "check_revoked",
        "check_unknown",
        "operator_revoked",
        "method_unsupported",
    }
)
METHOD_ID = re.compile(r"^[a-z][a-z0-9-]{2,31}$")
MAX_STATUS_BYTES = 4096
_SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"


class AuthError(Exception):
    """Stable, secret-free failure; the message is the code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Evidence:
    """Official source for a method whose isolated transport and live lifecycle passed G4."""

    source_url: str
    checked_on: str  # YYYY-MM-DD
    statement: str


@dataclass(frozen=True)
class MethodSpec:
    id: str
    login_argv: tuple[str, ...]  # official program, fixed argv, no credential
    check_argv: tuple[str, ...]  # read-only validity check (exit code only)
    logout_argv: tuple[str, ...] | None
    # exit code of check_argv -> state; anything else is "unknown" (not active)
    check_codes: Mapping[int, str]
    evidence: Evidence | None = None
    note: str = ""

    @property
    def available(self) -> bool:
        return self.evidence is not None

    @property
    def unavailable_reason(self) -> str:
        return f"A04 acceptance evidence is incomplete. {self.note}".rstrip()


def _unavailable(method_id: str, note: str) -> MethodSpec:
    return MethodSpec(
        method_id,
        login_argv=(),
        check_argv=(),
        logout_argv=None,
        check_codes={},
        note=note,
    )


# Official sources checked 2026-11-25. G4 in tests/integration/gates/m6_a04_a06.md
# records the commands, observed source semantics and outstanding acceptance checks.
AUTH_METHODS: dict[str, MethodSpec] = {
    # https://ollama.com/blog/cloud-models#signing-in-and-out documents signin/signout.
    # https://ollama.com/terms requires permission for automated access.
    # https://github.com/ollama/ollama/blob/v0.40.18/api/client.go uses POST /api/me
    # for the native account check. GET /api/tags lists local models only.
    "ollama-cloud": _unavailable(
        "ollama-cloud",
        "Ollama permission for this unattended use is unconfirmed. The method needs a dedicated "
        "cloud-enabled daemon outside the local CPU namespace and an authorized login and "
        "disconnect with native account verification",
    ),
    # https://code.claude.com/docs/en/legal-and-compliance describes third-party usage limits.
    # https://code.claude.com/docs/en/cli-reference documents auth commands and status codes.
    # https://code.claude.com/docs/en/headless documents that bare mode bypasses subscription OAuth.
    "claude-subscription": _unavailable(
        "claude-subscription",
        "Anthropic permission for unattended third-party subscription inference is unconfirmed. "
        "An isolated OAuth invocation and authorized login and provider-side revoke are pending",
    ),
    # https://learn.chatgpt.com/docs/auth documents supervised device authorization.
    # https://learn.chatgpt.com/docs/non-interactive-mode documents trusted private CI use.
    # https://openai.com/policies/sign-in-with-chatgpt-terms/ describes separate plan usage rules.
    "chatgpt-subscription": _unavailable(
        "chatgpt-subscription",
        "ChatGPT plan eligibility for Steward's unattended service is unconfirmed. "
        "Isolated Codex credential custody, remote validity, and authorized login and "
        "provider-side revoke are pending",
    ),
}


# ---- state and protected directories --------------------------------------------------


def _check_private_dir(path: Path, uid: int) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise AuthError("state_missing") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise AuthError("state_not_directory")
    if st.st_uid != uid:
        raise AuthError("wrong_owner")
    if st.st_mode & 0o077:
        raise AuthError("state_permissions")


class AuthStore:
    """`native_dir` (0700, inference UID): the official program's own credentials.
    `status_path`: non-secret JSON state, readable by the controller for findings."""

    def __init__(self, base: Path, uid: int, gid: int | None = None):
        self.base, self.uid, self.gid = Path(base), uid, gid
        self.native_dir = self.base / "auth"
        self.status_path = self.base / "auth-status.json"

    # -- protected native state ------------------------------------------------------

    def prepare(self) -> None:
        """Create the native directory when absent; refuse anything not exactly ours."""
        self.base.mkdir(parents=True, exist_ok=True)
        if not self.native_dir.exists() and not self.native_dir.is_symlink():
            self.native_dir.mkdir(mode=0o700)
            if os.geteuid() == 0:
                os.chown(self.native_dir, self.uid, self.gid if self.gid is not None else -1)
        _check_private_dir(self.native_dir, self.uid)

    def wipe_native(self) -> None:
        """Remove the credentials on revocation. Never follows links out of the directory."""
        _check_private_dir(self.native_dir, self.uid)
        for child in self.native_dir.iterdir():
            if child.is_symlink() or child.is_file():
                child.unlink()
            else:
                shutil.rmtree(child)

    # -- status document ------------------------------------------------------------

    def read(self) -> dict:
        try:
            with self.status_path.open("rb") as handle:
                raw = handle.read(MAX_STATUS_BYTES + 1)
            data = json.loads(raw) if len(raw) <= MAX_STATUS_BYTES else None
        except (OSError, ValueError):
            data = None
        if (
            not isinstance(data, dict)
            or data.get("state") not in STATES
            or data.get("reason") not in REASONS
            or not METHOD_ID.fullmatch(str(data.get("method", "")))
        ):
            return {"state": "pending", "reason": "never_logged_in", "method": "", "since": None}
        return {
            "state": data["state"],
            "reason": data["reason"],
            "method": data["method"],
            "since": data.get("since"),
            "checked_at": data.get("checked_at"),
        }

    def write(self, method: str, state: str, reason: str, now: float, *, changed: bool) -> dict:
        if state not in STATES or reason not in REASONS or not METHOD_ID.fullmatch(method):
            raise ValueError("invalid auth state")
        old = self.read()
        since = now if changed or old["state"] != state or old["method"] != method else old["since"]
        doc = {
            "method": method,
            "state": state,
            "reason": reason,
            "since": since,
            "checked_at": now,
        }
        tmp = self.status_path.with_name(self.status_path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w") as handle:
            json.dump(doc, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.status_path)
        return doc


# ---- running the official program -----------------------------------------------------


class Runner(Protocol):
    def run(self, argv: tuple[str, ...], *, env: dict[str, str], cwd: Path, uid: int) -> int: ...


class ProcessRunner:
    """Runs the program on the operator's terminal under the inference identity.

    Output is not captured (the operator must see the device code / link); the program
    gets a minimal environment and no inherited secrets."""

    def __init__(self, gid: int | None = None, timeout_s: float = 900.0):
        self.gid, self.timeout_s = gid, timeout_s

    def run(self, argv, *, env, cwd, uid) -> int:
        extra: dict = {}
        if uid != os.geteuid():
            extra = {"user": uid, "group": self.gid, "extra_groups": []}
        try:
            return subprocess.run(  # noqa: S603 - fixed argv from the registry
                list(argv), env=env, cwd=cwd, timeout=self.timeout_s, check=False, **extra
            ).returncode
        except subprocess.TimeoutExpired:
            return 124
        except OSError:
            return 127


def program_env(native_dir: Path, term: str = "xterm") -> dict[str, str]:
    """Fixed minimal environment: credentials live under HOME, nothing is inherited."""
    return {"HOME": str(native_dir), "PATH": _SAFE_PATH, "TERM": term, "LANG": "C.UTF-8"}


class AuthManager:
    def __init__(
        self,
        store: AuthStore,
        runner: Runner,
        *,
        methods: Mapping[str, MethodSpec] | None = None,
        clock: Callable[[], float],
    ):
        self.store, self.runner = store, runner
        self.methods = dict(AUTH_METHODS if methods is None else methods)
        self.clock = clock

    def _spec(self, method: str) -> MethodSpec:
        spec = self.methods.get(method)
        if spec is None:
            raise AuthError("unknown_method")
        if not spec.available:
            raise AuthError("method_unavailable")
        return spec

    def _run(self, spec: MethodSpec, argv: tuple[str, ...]) -> int:
        return self.runner.run(
            argv,
            env=program_env(self.store.native_dir),
            cwd=self.store.native_dir,
            uid=self.store.uid,
        )

    def check(self, method: str) -> dict:
        """Read-only validity check by exit code; the result is a state, never a token."""
        spec = self._spec(method)
        self.store.prepare()
        code = self._run(spec, spec.check_argv)
        state = spec.check_codes.get(code)
        now = self.clock()
        if state == "active":
            return self.store.write(method, "active", "login_verified", now, changed=False)
        if state in ("expired", "revoked"):
            return self.store.write(method, state, f"check_{state}", now, changed=False)
        return self.store.write(method, "pending", "check_unknown", now, changed=False)

    def login(self, method: str, *, relogin: bool = False) -> dict:
        """Run the official login interactively, then verify it with the read-only check.

        A valid credential is only replaced on explicit `relogin`; a failed login never
        marks the method active."""
        spec = self._spec(method)
        self.store.prepare()
        current = self.store.read()
        if current["state"] == "active" and current["method"] == method and not relogin:
            raise AuthError("already_active")
        now = self.clock()
        self.store.write(method, "pending", "login_started", now, changed=True)
        if self._run(spec, spec.login_argv) != 0:
            return self.store.write(method, "pending", "login_failed", self.clock(), changed=False)
        if spec.check_codes.get(self._run(spec, spec.check_argv)) != "active":
            return self.store.write(method, "pending", "login_failed", self.clock(), changed=False)
        return self.store.write(method, "active", "login_verified", self.clock(), changed=True)

    def revoke(self, method: str) -> dict:
        """Clean revocation: provider logout when the program has one, then remove the
        native credentials. State ends `revoked` even if the provider logout failed."""
        spec = self._spec(method)
        self.store.prepare()
        if spec.logout_argv is not None:
            self._run(spec, spec.logout_argv)
        self.store.wipe_native()
        return self.store.write(method, "revoked", "operator_revoked", self.clock(), changed=True)

    def observe_provider_error(self, method: str, error_class: str) -> dict | None:
        """An `auth` error from the provider moves an active credential to `expired`."""
        if error_class != "auth":
            return None
        current = self.store.read()
        if current["state"] != "active" or current["method"] != method:
            return None
        return self.store.write(
            method, "expired", "provider_rejected_credential", self.clock(), changed=True
        )


# ---- findings --------------------------------------------------------------------------

_TAIL = " Deterministic features are unaffected."
_MESSAGES = {
    "pending": "AI login is pending: run `steward ai login`." + _TAIL,
    "expired": "AI credential expired: run `steward ai login --relogin`." + _TAIL,
    "revoked": "AI credential was revoked: run `steward ai login` to enable AI again." + _TAIL,
}


def auth_finding(status: Mapping | None) -> dict | None:
    """A non-failing finding for login pending/expired/revoked; None when nothing to show.

    `status` is the document from `AuthStore.read` (or None when no interactive method is
    configured). Never blocks deployment, scans or controller rules."""
    if not status or status.get("state") not in ("pending", "expired", "revoked"):
        return None
    state = status["state"]
    return {
        "id": f"ai_login_{state}",
        "severity": "info",
        "target": "host",
        "summary": _MESSAGES[state],
        "blocked": "operator login required",
    }
