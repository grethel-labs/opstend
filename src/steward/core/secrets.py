"""Secret references and redaction.

Configuration stores references only (`env:NAME`, `file:/path`). Values are
resolved on the controller at deploy time, one reference at a time; the
controller environment is never copied wholesale.
"""

from __future__ import annotations

import os
import re
import secrets as _secrets
import stat
from collections.abc import Mapping
from pathlib import Path

MIN_ADMIN_TOKEN_BYTES = 32
REDACTED = "[redacted]"  # noqa: S105


class SecretError(Exception):
    pass


def resolve(ref: str, env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    kind, _, target = ref.partition(":")
    if kind == "env":
        value = env.get(target)
        if not value:
            raise SecretError(f"secret reference {ref}: environment variable is unset or empty")
        return value
    if kind == "file":
        path = Path(target).expanduser()
        try:
            st = path.stat()
        except OSError as exc:
            raise SecretError(f"secret reference file:{path}: {exc.strerror}") from None
        if not stat.S_ISREG(st.st_mode):
            raise SecretError(f"secret reference file:{path}: not a regular file")
        if st.st_mode & 0o077:
            raise SecretError(
                f"secret reference file:{path}: permissions too open "
                f"({stat.S_IMODE(st.st_mode):04o}), expected 0600"
            )
        value = path.read_text(encoding="utf-8").strip()
        if not value:
            raise SecretError(f"secret reference file:{path}: file is empty")
        return value
    raise SecretError(f"unsupported secret reference scheme: {kind}")


def check_env_value(name: str, value: str) -> None:
    """Values are written to an env file; refuse anything that could inject lines."""
    if "\n" in value or "\r" in value or "\x00" in value:
        raise SecretError(f"secret {name}: value contains a line break or NUL byte")


def generate_admin_token(path: Path, *, force: bool = False) -> None:
    """Create a fresh admin token file (0600) without ever printing the value."""
    path = path.expanduser()
    if path.exists() and not force:
        raise SecretError(f"{path} already exists (use --force to rotate)")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = _secrets.token_urlsafe(MIN_ADMIN_TOKEN_BYTES + 16)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token + "\n")
    os.replace(tmp, path)


def validate_admin_token(token: str) -> None:
    # token_urlsafe encodes 3 bytes in 4 characters; 43 chars carry >= 32 bytes.
    if len(token) < 43:
        raise SecretError(
            f"admin token is too short; it must carry at least {MIN_ADMIN_TOKEN_BYTES} random bytes"
        )


_PATTERNS = [
    re.compile(r"(?i)\b(authorization\s*[:=]\s*)(bearer|basic)\s+\S+"),
    re.compile(
        r"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)"
        r"[A-Za-z0-9_.-]*\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
    ),
    re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]


def redact(text: str, known_values: tuple[str, ...] = ()) -> str:
    """Remove secret-looking material from text before it is stored or shown."""
    for value in known_values:
        if value and len(value) >= 6:
            text = text.replace(value, REDACTED)
    text = _PATTERNS[0].sub(lambda m: f"{m.group(1)}{m.group(2)} {REDACTED}", text)
    text = _PATTERNS[1].sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    text = _PATTERNS[2].sub(REDACTED, text)
    return _PATTERNS[3].sub(REDACTED, text)


def redact_tree(value, known_values: tuple[str, ...] = ()):
    """Redact JSON string values without corrupting structure or numeric fields."""
    if isinstance(value, str):
        return redact(value, known_values)
    if isinstance(value, dict):
        return {key: redact_tree(item, known_values) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_tree(item, known_values) for item in value]
    return value
