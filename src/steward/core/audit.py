"""Append-only, hash-chained audit log (JSON lines).

Each record carries the hash of its predecessor, so truncation or edits inside
the file are detectable with `verify`. The file is opened with O_APPEND and
O_NOFOLLOW; each trust domain writes its own log in a directory only it owns.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(prev: str, record: dict[str, Any]) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(f"{prev}\n{body}".encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path | str):
        self.path = Path(path)

    def _last_hash(self, fd: int) -> str:
        size = os.fstat(fd).st_size
        if size == 0:
            return GENESIS
        with open(self.path, "rb") as handle:
            start = size
            chunks = []
            newlines = 0
            while start > 0 and newlines < 2:
                previous = max(0, start - 65536)
                handle.seek(previous)
                chunk = handle.read(start - previous)
                chunks.append(chunk)
                newlines += chunk.count(b"\n")
                start = previous
        return json.loads(b"".join(reversed(chunks)).splitlines()[-1])["hash"]

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            prev = self._last_hash(fd)
            record = {"ts": round(time.time(), 3), "event": event, **fields}
            entry = {**record, "prev": prev, "hash": _digest(prev, record)}
            os.write(fd, (json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        return entry

    def read(self, limit: int = 200) -> list[dict[str, Any]]:
        """The last `limit` complete records, read from the end of the file."""
        if not self.path.exists():
            return []
        with open(self.path, "rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            chunk, block = b"", 65536
            while chunk.count(b"\n") <= limit and len(chunk) < size:
                start = max(0, size - len(chunk) - block)
                handle.seek(start)
                chunk = handle.read(size - start)
        lines = chunk.split(b"\n")
        complete = lines[:-1] if not chunk.endswith(b"\n") else lines
        if len(chunk) < size:  # the first line may be cut off
            complete = complete[1:]
        return [json.loads(line) for line in complete if line][-limit:]

    def read_since(
        self,
        offset: int,
        prev_hash: str,
        limit: int,
        *,
        max_bytes: int | None = None,
        transform: Callable | None = None,
    ) -> dict[str, Any]:
        """Records after a cursor (byte offset + hash of the record ending there).

        A cursor that does not match the file (rotated, truncated, rewritten)
        yields `reset: True` and a fresh cursor at the current end, so a reader
        can record the gap instead of silently re-reading or skipping.
        """
        if not self.path.exists():
            fresh = offset == 0 and prev_hash in ("", GENESIS)
            return {
                "reset": not fresh,
                "entries": [],
                "next_offset": 0,
                "next_hash": GENESIS,
                "more": False,
            }
        size = self.path.stat().st_size
        with open(self.path, "rb") as handle:
            if offset > size or not self._cursor_matches(handle, offset, prev_hash):
                tail = self.read(1)
                return {
                    "reset": True,
                    "entries": [],
                    "next_offset": size,
                    "next_hash": tail[-1]["hash"] if tail else GENESIS,
                    "more": False,
                }
            handle.seek(offset)
            entries, position, byte_count, last_hash, limited = [], offset, 0, prev_hash, False
            for line in handle:
                if not line.endswith(b"\n"):  # a writer is mid-append
                    break
                original = json.loads(line)
                entry = transform(original) if transform else original
                length = len(json.dumps(entry, ensure_ascii=False).encode())
                if max_bytes is not None and byte_count + length > max_bytes:
                    if not entries:
                        raise ValueError(
                            "audit record exceeds response budget; read local original"
                        )
                    limited = True
                    break
                entries.append(entry)
                byte_count += length
                position += len(line)
                last_hash = original["hash"]
                if len(entries) >= limit:
                    limited = True
                    break
            return {
                "reset": False,
                "entries": entries,
                "next_offset": position,
                "next_hash": last_hash,
                "more": position < size and limited,
            }

    @staticmethod
    def _cursor_matches(handle, offset: int, prev_hash: str) -> bool:
        if offset == 0:
            return prev_hash in ("", GENESIS)
        start = max(0, offset - 1024 * 1024)
        handle.seek(start)
        chunk = handle.read(offset - start)
        if not chunk.endswith(b"\n"):
            return False
        try:
            return json.loads(chunk[:-1].rsplit(b"\n", 1)[-1])["hash"] == prev_hash
        except (ValueError, KeyError):
            return False

    def verify(self) -> tuple[bool, int]:
        """Check the whole chain. Returns (ok, number of valid records)."""
        prev, count = GENESIS, 0
        if not self.path.exists():
            return True, 0
        with open(self.path, encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                    record = {k: v for k, v in entry.items() if k not in ("prev", "hash")}
                    if entry["prev"] != prev or entry["hash"] != _digest(prev, record):
                        return False, count
                except (ValueError, KeyError):
                    return False, count
                prev, count = entry["hash"], count + 1
        return True, count
