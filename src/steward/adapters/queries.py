"""QueryAdapter v1: authenticate transport identity before any information read."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

COMMANDS = frozenset({"status", "updates", "backups", "help", "ask"})
MAX_QUESTION = 500


class QueryError(Exception):
    def __init__(self, error_class: str, status: int = 401):
        super().__init__(error_class)
        self.error_class, self.status = error_class, status


@dataclass(frozen=True)
class Query:
    id: str
    tenant: str
    user: str
    command: str
    ping: bool = False
    text: str = ""  # only for `ask`: an untrusted free-form question, never a command


class QueryAdapter(Protocol):
    version: int
    capabilities: tuple[str, ...]
    input_schema: dict
    timeout_s: float

    def health(self) -> bool: ...

    def decode(self, body: bytes, headers: dict[str, str], *, now: float) -> Query: ...

    def response(self, text: str) -> dict: ...


def timestamp(headers: dict, name: str, now: float) -> str:
    stamp = headers.get(name, "")
    if not stamp.isascii() or not stamp.isdigit() or len(stamp) > 12 or abs(now - int(stamp)) > 300:
        raise QueryError("expired")
    return stamp


def document(body: bytes) -> dict:
    try:
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError
        return data
    except (ValueError, UnicodeError):
        raise QueryError("invalid_message", 400) from None


def query(id: str, tenant: str, user: str, command: str, text: str = "") -> Query:
    if any(not isinstance(v, str) or not v or len(v) > 100 for v in (id, tenant, user, command)):
        raise QueryError("invalid_message", 400)
    if command not in COMMANDS:
        raise QueryError("unknown_command", 400)
    if not isinstance(text, str) or len(text) > MAX_QUESTION or (text and command != "ask"):
        raise QueryError("invalid_message", 400)
    if command == "ask" and not text.strip():
        raise QueryError("invalid_message", 400)
    return Query(id, tenant, user, command, text=text)


class SignedQuery:
    version = 1
    capabilities = ("query.authenticate", "query.respond")
    timeout_s = 2.0
    input_schema = {
        "type": "object",
        "required": ["v", "id", "tenant", "user", "command"],
        "additionalProperties": False,
        "properties": {
            "v": {"const": 1},
            "id": {"type": "string", "maxLength": 100},
            "tenant": {"type": "string", "maxLength": 100},
            "user": {"type": "string", "maxLength": 100},
            "command": {"enum": sorted(COMMANDS)},
        },
    }

    def health(self) -> bool:
        return len(self.key) >= 32

    def __init__(self, key: str):
        if len(key.encode()) < 32:
            raise ValueError("query signing key must contain at least 32 bytes")
        self.key = key.encode()

    def decode(self, body: bytes, headers: dict[str, str], *, now: float) -> Query:
        if len(body) > 16384:
            raise QueryError("too_large", 413)
        stamp = timestamp(headers, "x-steward-timestamp", now)
        signature = (
            "v1=" + hmac.new(self.key, stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        )
        supplied = headers.get("x-steward-signature", "")
        if not supplied.isascii() or not hmac.compare_digest(signature, supplied):
            raise QueryError("invalid_signature")
        data = document(body)
        if set(data) - {"text"} != {"v", "id", "tenant", "user", "command"} or data["v"] != 1:
            raise QueryError("invalid_message", 400)
        command = data["command"]
        if not isinstance(command, str):
            raise QueryError("invalid_message", 400)
        return query(
            data["id"],
            data["tenant"],
            data["user"],
            command.removeprefix("/"),
            data.get("text", ""),
        )

    def response(self, text: str) -> dict:
        return {"v": 1, "text": text}


class DiscordQuery:
    version = 1
    capabilities = ("query.authenticate", "query.respond", "query.ping")
    timeout_s = 2.0
    input_schema = {
        "type": "object",
        "required": ["type", "application_id"],
        "properties": {"type": {"enum": [1, 2]}, "application_id": {"type": "string"}},
    }

    def health(self) -> bool:
        return bool(self.application_id)

    def __init__(self, public_key: str, application_id: str):
        self.key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
        self.application_id = application_id

    def decode(self, body: bytes, headers: dict[str, str], *, now: float) -> Query:
        if len(body) > 16384:
            raise QueryError("too_large", 413)
        stamp = timestamp(headers, "x-signature-timestamp", now)
        try:
            self.key.verify(
                bytes.fromhex(headers.get("x-signature-ed25519", "")), stamp.encode() + body
            )
        except (InvalidSignature, ValueError):
            raise QueryError("invalid_signature") from None
        data = document(body)
        if data.get("application_id") != self.application_id:
            raise QueryError("wrong_application")
        if data.get("type") == 1:
            return Query("ping", "", "", "", ping=True)
        if data.get("type") != 2 or not isinstance(data.get("data"), dict):
            raise QueryError("invalid_message", 400)
        member = data.get("member") or {}
        if not isinstance(member, dict) or not isinstance(member.get("user"), dict):
            raise QueryError("forbidden", 403)  # DMs are not authorized implicitly.
        options = data["data"].get("options") or []
        text = ""
        if options and isinstance(options[0], dict) and options[0].get("name") == "question":
            text = options[0].get("value")
        return query(
            data.get("id"),
            data.get("guild_id"),
            member["user"].get("id"),
            data["data"].get("name"),
            text,
        )

    def response(self, text: str) -> dict:
        return {
            "type": 4,
            "data": {
                "content": text.encode("utf-16-le")[:3600].decode("utf-16-le", errors="ignore"),
                "flags": 64,
                "allowed_mentions": {"parse": []},
            },
        }
