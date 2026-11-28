"""Accounts, sessions and CSRF protection.

* Passwords: scrypt with a per-user salt.
* Sessions: random tokens in an HttpOnly, SameSite=Strict cookie; idle timeout.
* CSRF: every state-changing request repeats the session's CSRF token in the
  `X-CSRF-Token` header.
* Roles: viewer (read), operator (approve and run jobs), admin (settings,
  users, cluster membership).
* Login attempts are rate limited per address.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import StrEnum


class Role(StrEnum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


RANK = {Role.VIEWER: 0, Role.OPERATOR: 1, Role.ADMIN: 2}


def hash_password(password: str, salt: bytes | None = None) -> str:
    if len(password) < 12:
        raise ValueError("passwords need at least 12 characters")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024
    )
    return f"scrypt${salt.hex()}${digest.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.scrypt(
            password.encode(),
            salt=bytes.fromhex(salt_hex),
            n=2**15,
            r=8,
            p=1,
            maxmem=64 * 1024 * 1024,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


@dataclass
class Session:
    token: str
    user: str
    name: str
    role: Role
    csrf: str
    expires: float
    lang: str = "de"


@dataclass
class Sessions:
    idle_seconds: int = 30 * 60
    _items: dict[str, Session] = field(default_factory=dict)
    _attempts: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))

    def create(self, user: str, name: str, role: Role, lang: str = "de") -> Session:
        s = Session(
            secrets.token_urlsafe(32),
            user,
            name,
            role,
            secrets.token_urlsafe(24),
            time.monotonic() + self.idle_seconds,
            lang,
        )
        self._items[s.token] = s
        return s

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        s = self._items.get(token)
        if s is None or s.expires < time.monotonic():
            self._items.pop(token or "", None)
            return None
        s.expires = time.monotonic() + self.idle_seconds
        return s

    def drop(self, token: str | None) -> None:
        self._items.pop(token or "", None)

    def allow_login(self, address: str, limit: int = 10, window: float = 300) -> bool:
        now = time.monotonic()
        q = self._attempts[address]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True
