"""Sample workload: a small notes service with persistent state.

Standard library only, so it runs on a stock, digest-pinned Python image with
this directory mounted read-only. State lives in SQLite under DATA_DIR.

    GET  /healthz        liveness + database check
    GET  /notes          list notes
    GET  /attachments/<sha256>  read one content-addressed attachment
    POST /notes          create a note (text/plain body, max 4 KiB)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import sqlite3
import stat
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATA_DIR = os.environ.get("DATA_DIR", "/data")
PORT = int(os.environ.get("PORT", "8080"))
DB_PATH = os.path.join(DATA_DIR, "notes.db")
MAX_NOTE_BYTES = 4096
MAX_NOTES = 1000
MAX_ATTACHMENT_BYTES = 1024 * 1024


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, created_at REAL, text TEXT)"
    )
    return conn


class Handler(BaseHTTPRequestHandler):
    server_version = "sample-notes"
    sys_version = ""

    def _send(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            try:
                with db() as conn:
                    count = conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
                self._send(200, {"status": "ok", "notes": count})
            except sqlite3.Error as exc:
                self._send(503, {"status": "error", "detail": type(exc).__name__})
        elif self.path.startswith("/attachments/"):
            name = self.path.removeprefix("/attachments/")
            if not re.fullmatch(r"[a-f0-9]{64}", name):
                return self._send(404, {"error": "not found"})
            try:
                directory = os.open(
                    os.path.join(DATA_DIR, "attachments"),
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                )
                try:
                    fd = os.open(
                        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
                    )
                finally:
                    os.close(directory)
                with os.fdopen(fd, "rb") as handle:
                    info = os.fstat(handle.fileno())
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_nlink != 1
                        or info.st_size > MAX_ATTACHMENT_BYTES
                    ):
                        raise ValueError("invalid attachment")
                    body = handle.read(MAX_ATTACHMENT_BYTES + 1)
                if len(body) != info.st_size or hashlib.sha256(body).hexdigest() != name:
                    raise ValueError("attachment mismatch")
            except (OSError, ValueError):
                return self._send(404, {"error": "not found"})
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
        elif self.path in ("/", "/notes"):
            with db() as conn:
                rows = conn.execute(
                    "SELECT id, created_at, text FROM notes ORDER BY id DESC LIMIT 100"
                ).fetchall()
            self._send(200, [{"id": r[0], "created_at": r[1], "text": r[2]} for r in rows])
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/notes":
            return self._send(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send(411, {"error": "length required"})
        if not 0 < length <= MAX_NOTE_BYTES:
            return self._send(413, {"error": "note must be 1..4096 bytes"})
        text = self.rfile.read(length).decode("utf-8", errors="replace")
        with db() as conn:
            if conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0] >= MAX_NOTES:
                return self._send(507, {"error": "note limit reached"})
            cur = conn.execute(
                "INSERT INTO notes (created_at, text) VALUES (?, ?)", (time.time(), text)
            )
        self._send(201, {"id": cur.lastrowid})

    def log_message(self, fmt: str, *args: object) -> None:
        print(
            json.dumps(
                {"ts": round(time.time(), 3), "client": self.client_address[0], "msg": fmt % args}
            ),
            flush=True,
        )


if __name__ == "__main__":
    # PID 1 in a container gets no default signal handlers: stop promptly on SIGTERM.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    db().close()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()  # noqa: S104 - container
