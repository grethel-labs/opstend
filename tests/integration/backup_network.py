#!/usr/bin/env python3
"""Real packet probe inside disposable user/network namespaces; no host rules."""

import json
import socket
import subprocess
import sys
import threading
import time


def command(*args):
    subprocess.run(args, check=True, capture_output=True)


def listener(family, address, port):
    server = socket.socket(family)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    server.bind((address, port))
    server.listen()

    def serve():
        while True:
            try:
                client, _ = server.accept()
            except OSError:
                return
            with client:
                client.settimeout(2)
                try:
                    client.recv(16)
                    client.sendall(b"ok")
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()
    return server


def reachable(address, port):
    try:
        with socket.create_connection((address, port), timeout=2) as client:
            client.sendall(b"ping")
            return client.recv(2) == b"ok"
    except OSError:
        return False


def child():
    print("namespace-ready", flush=True)
    deadline = time.monotonic() + 10
    while subprocess.run(["ip", "link", "show", "dev", "peer"], capture_output=True).returncode:
        if time.monotonic() > deadline:
            raise RuntimeError("peer namespace was not attached")
        time.sleep(0.02)
    command("ip", "link", "set", "lo", "up")
    command("ip", "addr", "add", "192.0.2.2/24", "dev", "peer")
    command("ip", "addr", "add", "192.0.2.3/24", "dev", "peer")
    command("ip", "-6", "addr", "add", "fd00:1::2/64", "dev", "peer", "nodad")
    command("ip", "-6", "addr", "add", "fd00:1::3/64", "dev", "peer", "nodad")
    command("ip", "link", "set", "peer", "up")
    servers = [
        listener(family, address, port)
        for family, address in (
            (socket.AF_INET, "0.0.0.0"),
            (socket.AF_INET6, "::"),
        )
        for port in (8443, 8444)
    ]
    print("ready", flush=True)
    while servers:
        time.sleep(1)


def main():
    if sys.argv[1] == "serve":
        child()
        return
    remote = subprocess.Popen(
        ["unshare", "-n", sys.executable, __file__, "serve"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    local = []
    try:
        assert remote.stdout.readline().strip() == "namespace-ready"
        command("ip", "link", "set", "lo", "up")
        command("ip", "link", "add", "origin", "type", "veth", "peer", "name", "peer")
        command("ip", "link", "set", "peer", "netns", str(remote.pid))
        command("ip", "addr", "add", "192.0.2.1/24", "dev", "origin")
        command("ip", "-6", "addr", "add", "fd00:1::1/64", "dev", "origin", "nodad")
        command("ip", "link", "set", "origin", "up")
        assert remote.stdout.readline().strip() == "ready"
        local = [
            listener(socket.AF_INET, "127.0.0.1", 8443),
            listener(socket.AF_INET6, "::1", 8443),
        ]
        peers = [
            (address, port)
            for address in ("192.0.2.2", "192.0.2.3", "fd00:1::2", "fd00:1::3")
            for port in (8443, 8444)
        ]
        assert all(reachable(*peer) for peer in peers), (
            "negative controls must be reachable before rules"
        )
        assert reachable("127.0.0.1", 8443) and reachable("::1", 8443)
        command("nft", "-f", sys.argv[1])
        assert reachable("192.0.2.2", 8443) and reachable("fd00:1::2", 8443)
        assert all(
            not reachable(address, port)
            for address, port in peers
            if (address, port) not in (("192.0.2.2", 8443), ("fd00:1::2", 8443))
        )
        assert not reachable("127.0.0.1", 8443) and not reachable("::1", 8443)
        print(
            json.dumps(
                {
                    "ipv4_allowed": True,
                    "ipv6_allowed": True,
                    "other_ip_denied": True,
                    "other_port_denied": True,
                    "loopback_denied": True,
                    "baseline_controls_reachable": True,
                }
            )
        )
    finally:
        for server in local:
            server.close()
        remote.terminate()
        try:
            remote.wait(5)
        except subprocess.TimeoutExpired:
            remote.kill()
            remote.wait()


if __name__ == "__main__":
    main()
