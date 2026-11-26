#!/usr/bin/env python3
"""Run inside a disposable VM after configuring private messaging test endpoints.

Execute with the installed steward venv as root. Credentials are read from
root-only files, never arguments or logs. No external recipient is contacted.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="vm-bot")
    parser.add_argument("--tenant", default="vm-team")
    parser.add_argument("--user", default="vm-user")
    parser.add_argument("--project", default="notes")
    parser.add_argument(
        "--bot-key-file", type=Path, default=Path("/etc/steward/secrets/bot/vm-bot")
    )
    parser.add_argument("--destination", default="vm-refused")
    parser.add_argument(
        "--url-file", type=Path, default=Path("/etc/steward/secrets/notifications/vm-refused-url")
    )
    parser.add_argument(
        "--signing-key-file",
        type=Path,
        default=Path("/etc/steward/secrets/notifications/vm-refused-key"),
    )
    parser.add_argument("--outbox", type=Path, default=Path("/var/lib/steward-notifier/outbox.db"))
    parser.add_argument("--wait-seconds", type=int, default=180)
    parser.add_argument(
        "--restart-bot",
        action="store_true",
        help="prove replay persistence over an owned VM bot restart",
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("this driver must run as root inside the disposable VM")
    key = args.bot_key_file.read_bytes().strip()
    endpoint = "https://localhost:9443/bot/" + urllib.parse.quote(args.endpoint, safe="")
    context = ssl.create_default_context(cafile="/etc/steward/pki/ca.crt")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
    )

    def request(body: bytes, *, stamp: int | None = None, signed_body: bytes | None = None):
        stamp_text = str(int(time.time()) if stamp is None else stamp)
        signature = hmac.new(
            key, stamp_text.encode() + b"." + (signed_body or body), hashlib.sha256
        ).hexdigest()
        req = urllib.request.Request(
            endpoint,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Steward-Timestamp": stamp_text,
                "X-Steward-Signature": "v1=" + signature,
            },
        )
        try:
            with opener.open(req, timeout=90) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def body(id: str, *, command: str = "status", user: str = args.user):
        return json.dumps(
            {"v": 1, "id": id, "tenant": args.tenant, "user": user, "command": command}
        ).encode()

    def check(condition: bool, name: str):
        if not condition:
            print("FAIL  " + name, flush=True)
            raise AssertionError(name)
        print("PASS  " + name, flush=True)

    original = body(uuid.uuid4().hex)
    first_stamp = int(time.time())
    status, first = request(original, stamp=first_stamp)
    check(
        status == 200 and f"{args.project}:" in first.get("text", ""),
        "signed query traverses TLS proxy and reads the real project snapshot",
    )
    check("Kill switch:" not in first["text"], "project-only grant does not disclose host status")
    check(
        request(original) == (status, first), "exact retry returns its persistent cached response"
    )
    if args.restart_bot:
        subprocess.run(["systemctl", "restart", "steward-bot.service"], check=True, timeout=120)
        until = time.monotonic() + 120
        replay = None
        while time.monotonic() < until:
            try:
                replay = request(original, stamp=max(int(time.time()), first_stamp + 1))
                if replay == (status, first):
                    break
            except (OSError, ValueError):
                pass
            time.sleep(1)
        check(
            replay == (status, first),
            "same request with fresh signature survives bot service restart",
        )
    check(
        request(body(json.loads(original)["id"], command="help"))[0] == 409,
        "changed request with reused id is rejected",
    )
    check(
        request(body(uuid.uuid4().hex, user="vm-unauthorized"))[0] == 403,
        "signed but unauthorized identity is rejected",
    )
    check(
        request(original + b" ", signed_body=original)[0] == 401,
        "tampered body is rejected before data access",
    )
    check(
        request(body(uuid.uuid4().hex), stamp=int(time.time()) - 600)[0] == 401,
        "expired signature is rejected",
    )
    check(request(b"x" * 16385)[0] == 413, "oversized query body is rejected")

    url = args.url_file.read_text().strip()
    parsed = urllib.parse.urlsplit(url)
    check(
        parsed.scheme == "https"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        and parsed.port in (None, 443),
        "notification test target is VM loopback only",
    )
    from steward.adapters.notifications import SignedWebhook

    adapter = SignedWebhook(url, args.signing_key_file.read_text().strip())
    result = adapter.send("vm-ssrf-test:" + uuid.uuid4().hex, {"summary": "VM-local refusal test"})
    check(
        not result.confirmed and result.permanent and result.error_class == "unsafe_target",
        "installed sender refuses private target before connecting",
    )
    until = time.monotonic() + args.wait_seconds
    failed = 0
    while time.monotonic() < until:
        try:
            db = sqlite3.connect(f"file:{args.outbox}?mode=ro", uri=True)
            try:
                failed = db.execute(
                    "SELECT COUNT(*) FROM outbox WHERE destination=? AND state='failed' "
                    "AND finished_at>=?",
                    (args.destination, time.time() - args.wait_seconds),
                ).fetchone()[0]
            finally:
                db.close()
        except sqlite3.Error:
            failed = 0
        if failed:
            break
        time.sleep(5)
    check(failed > 0, "live notifier records failed delivery for refused destination")
    print("ALL MESSAGING CHECKS PASSED", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        # Some transport exception messages contain endpoint data; keep logs generic.
        print("FAIL  messaging driver: " + type(exc).__name__, flush=True)
        raise SystemExit(1) from None
