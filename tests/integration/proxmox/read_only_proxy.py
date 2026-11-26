#!/usr/bin/env python3
"""Loopback-only, read-only TLS proxy for one disposable Restic fixture repository."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hmac
import os
import re
import ssl
import stat
import struct
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

PREFIX = "/fixture/fixture/"
PATH = re.compile(
    r"/fixture/fixture/(?:(?:config|data|index|keys|locks|snapshots)(?:/[a-f0-9]{1,64})?)?/?"
)


def private_line(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        private_user = info.st_uid == os.geteuid() and not info.st_mode & 0o077
        systemd_credential = False
        if info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o440:
            # systemd grants precisely this dynamic user read access through an ACL.
            nobody = 0xFFFFFFFF
            expected = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", *entry)
                for entry in (
                    (1, 4, nobody),
                    (2, 4, os.geteuid()),
                    (4, 0, nobody),
                    (16, 4, nobody),
                    (32, 0, nobody),
                )
            )
            with contextlib.suppress(OSError):
                systemd_credential = os.getxattr(fd, "system.posix_acl_access") == expected
        if (
            not stat.S_ISREG(info.st_mode)
            or not (private_user or systemd_credential)
            or info.st_nlink != 1
            or info.st_size > 8192
        ):
            raise ValueError("unsafe private credential")
        with os.fdopen(os.dup(fd), "rb") as handle:
            value = handle.read(8193)
    finally:
        os.close(fd)
    if not value or value.count(b":") != 1:
        raise ValueError("invalid credential")
    user, password = value.split(b":", 1)
    if (
        not re.fullmatch(rb"[A-Za-z0-9_-]{1,64}", user)
        or not 32 <= len(password) <= 512
        or any(byte < 33 or byte > 126 for byte in password)
    ):
        raise ValueError("invalid credential")
    return b"Basic " + base64.b64encode(value)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, upstream_port: int, ca: Path, reader: bytes, writer: bytes):
        if not 1024 <= port <= 65535 or not 1024 <= upstream_port <= 65535 or port == upstream_port:
            raise ValueError("invalid fixture ports")
        if (
            not reader.startswith(b"Basic ")
            or not writer.startswith(b"Basic ")
            or hmac.compare_digest(reader, writer)
        ):
            raise ValueError("separate credentials required")
        try:
            reader_pair = base64.b64decode(reader[6:], validate=True).split(b":", 1)
            writer_pair = base64.b64decode(writer[6:], validate=True).split(b":", 1)
            if (
                len(reader_pair) != 2
                or len(writer_pair) != 2
                or hmac.compare_digest(reader_pair[1], writer_pair[1])
            ):
                raise ValueError("separate passwords required")
        except (ValueError, TypeError):
            raise ValueError("separate credentials required") from None
        self.reader, self.writer = reader, writer
        self.upstream = f"https://127.0.0.1:{upstream_port}"
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))),
        )
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(("127.0.0.1", port), Handler)

    def process_request(self, request, client_address):
        request.settimeout(15)
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reject(self, code):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def do_POST(self):  # noqa: N802
        self.reject(405)

    def do_PUT(self):  # noqa: N802
        self.reject(405)

    def do_DELETE(self):  # noqa: N802
        self.reject(405)

    def do_PATCH(self):  # noqa: N802
        self.reject(405)

    def do_HEAD(self):  # noqa: N802
        self.read_only("HEAD")

    def do_GET(self):  # noqa: N802
        self.read_only("GET")

    def read_only(self, method):
        supplied = self.headers.get("Authorization", "").encode("utf-8", errors="replace")
        if not hmac.compare_digest(supplied, self.server.reader):
            return self.reject(401)
        parsed = urlsplit(self.path)
        if (
            parsed.scheme
            or parsed.netloc
            or parsed.fragment
            or not PATH.fullmatch(parsed.path)
            or parsed.query
        ):
            return self.reject(400)
        upstream = self.server.upstream + parsed.path
        headers = {"Authorization": self.server.writer.decode("ascii")}
        for name in ("Accept", "Range"):
            if name in self.headers:
                headers[name] = self.headers[name]
        request = urllib.request.Request(upstream, headers=headers, method=method)  # noqa: S310 - fixed HTTPS loopback
        try:
            try:
                response = self.server.opener.open(request, timeout=15)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                if 300 <= response.status < 400:
                    return self.reject(502)
                self.send_response(response.status)
                for name in (
                    "Content-Type",
                    "Content-Length",
                    "Content-Encoding",
                    "Content-Range",
                    "Accept-Ranges",
                    "ETag",
                ):
                    value = response.headers.get(name)
                    if value is not None:
                        self.send_header(name, value)
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                if method == "GET":
                    while chunk := response.read(65536):
                        self.wfile.write(chunk)
        except (OSError, urllib.error.URLError, TimeoutError, ValueError):
            self.close_connection = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    for flag in ("ca", "certificate", "key", "reader-credential", "writer-credential"):
        parser.add_argument("--" + flag, type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("run the fixture proxy as an unprivileged identity")
    os.umask(0o077)
    server = Server(
        args.port,
        args.upstream_port,
        args.ca,
        private_line(args.reader_credential),
        private_line(args.writer_credential),
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.certificate, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
