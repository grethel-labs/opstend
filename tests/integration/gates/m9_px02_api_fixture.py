#!/usr/bin/env python3
"""Serve synthetic PX02 responses on a disposable loopback listener."""

import argparse
import json
import ssl
import time
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_VERSION = "/api2/json/version"
_PERMISSIONS = "/api2/json/access/permissions"
_RESOURCES = "/api2/json/cluster/resources"
_CONFIG = "/api2/json/nodes/px02-gate/qemu/9901/config?current=1"
_GUEST = {
    "type": "qemu",
    "id": "qemu/9901",
    "vmid": 9901,
    "node": "px02-gate",
    "name": "px02-synthetic-guest",
    "status": "running",
}


class FixtureServer(ThreadingHTTPServer):
    def __init__(self, state, port):
        self.state = state
        self.tokens = {
            "PVEAPIToken=" + (state / f"{scope}.token").read_text().strip(): scope
            for scope in ("health", "inventory")
        }
        self.contexts = {}
        for chain in ("a", "b"):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(state / f"{chain}.pem", state / f"{chain}.key")
            self.contexts[chain] = context
        super().__init__(("127.0.0.1", port), FixtureHandler)

    def get_request(self):
        connection, peer = super().get_request()
        try:
            connection.settimeout(2)
            chain = (self.state / "chain").read_text().strip()
            return self.contexts[chain].wrap_socket(connection, server_side=True), peer
        except (OSError, KeyError):
            connection.close()
            raise OSError("Fixture TLS connection could not be accepted.") from None


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _reply(self, code, data=None):
        body = data if isinstance(data, bytes) else json.dumps({"data": data}).encode("ascii")
        with suppress(OSError):
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            if code == 429:
                self.send_header("Retry-After", "45")
            self.end_headers()
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        scope = self.server.tokens.get(self.headers.get("Authorization"), "unexpected")
        path = (
            self.path
            if self.path in (_VERSION, _PERMISSIONS, _RESOURCES, _CONFIG)
            else "unexpected"
        )
        state = self.server.state
        mode = (state / "mode").read_text().strip()
        now = time.time()
        print(json.dumps({"time": now, "scope": scope, "path": path, "mode": mode}), flush=True)
        if scope == "unexpected":
            self._reply(401)
        elif path == _VERSION:
            release, version = "9.3", "9.3.1"
            if scope == "inventory" and mode == "bad-version":
                release, version = "9.4", "9.4.1"
            self._reply(200, {"release": release, "version": version})
        elif path == _PERMISSIONS:
            self._reply(200, {"/vms/9901": {"VM.Audit": 0}} if scope == "inventory" else {})
        elif scope != "inventory":
            self._reply(403)
        elif path == _RESOURCES:
            if mode == "malformed":
                self._reply(200, b'{"data":[],"data":[]}')
            elif mode == "hold":
                (state / "inflight").write_text(str(now))
                time.sleep(3)
            else:
                self._reply(200, [_GUEST])
        elif path == _CONFIG:
            if mode == "rate-limit":
                self._reply(429)
            else:
                self._reply(200, {"net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=42"})
        else:
            self._reply(404)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("state", type=Path)
    parser.add_argument("--port", type=int, default=8006)
    args = parser.parse_args()
    with FixtureServer(args.state, args.port) as server:
        print(json.dumps({"listen": server.server_port}), flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
