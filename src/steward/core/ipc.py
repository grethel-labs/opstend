"""Unix socket plumbing shared by the executor and the collector.

One JSON request line, one JSON response line. Callers are identified by
kernel-provided peer credentials (SO_PEERCRED), never by request content.
"""

from __future__ import annotations

import grp
import json
import os
import socket
import socketserver
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Any

MAX_MESSAGE_BYTES = 256 * 1024

Handler = Callable[[bytes, int], dict[str, Any]]


def peer_uid(sock: socket.socket) -> int:
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


class _RequestHandler(socketserver.StreamRequestHandler):
    timeout = 10

    def handle(self) -> None:
        try:
            uid = peer_uid(self.request)
            raw = self.rfile.readline(MAX_MESSAGE_BYTES + 1)
            if len(raw) > MAX_MESSAGE_BYTES:
                response = {
                    "ok": False,
                    "error_class": "bad_request",
                    "message": "request too large",
                }
            else:
                response = self.server.handler(raw, uid)  # type: ignore[attr-defined]
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode() + b"\n")
        except OSError:
            pass


class UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    request_queue_size = 32


def bind(socket_path: str, handler: Handler, socket_group: str | None) -> UnixServer:
    """Create a server whose socket is reachable only by the owner (and `socket_group`)."""
    path = Path(socket_path)
    path.unlink(missing_ok=True)
    old_umask = os.umask(0o177)
    try:
        server = UnixServer(str(path), _RequestHandler)
    finally:
        os.umask(old_umask)
    if socket_group:
        os.chown(path, -1, grp.getgrnam(socket_group).gr_gid)
        os.chmod(path, 0o660)
    server.handler = handler  # type: ignore[attr-defined]
    return server
