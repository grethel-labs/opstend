"""Local fixtures for repository tests: bare Git repositories, a loopback smart-HTTP
server (with Basic auth, redirects and delays) and a fake `ssh` that enforces the
pinned host key and key file. Nothing here touches the network or a real SSH server."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from steward.core.config import Repository
from steward.core.repositories import FetchPolicy

GIT = shutil.which("git") or "/usr/bin/git"
HTTP_BACKEND = "/usr/lib/git-core/git-http-backend"
CLEAN_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_AUTHOR_NAME": "Fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "Fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
}
POLICY = FetchPolicy(relaxed_for_tests=True)


def git(*args: str, cwd: Path, env: dict | None = None) -> str:
    result = subprocess.run(  # noqa: S603
        [GIT, *args],
        cwd=cwd,
        env={**CLEAN_ENV, **(env or {})},
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


@dataclass
class Symlink:
    target: str


class Upstream:
    """A work tree plus the bare repository that is served."""

    def __init__(self, base: Path, name: str = "app"):
        self.work = base / f"{name}-work"
        self.root = base / "served"
        self.bare = self.root / f"{name}.git"
        self.root.mkdir(exist_ok=True)
        self.work.mkdir()
        git("init", "-q", "-b", "main", cwd=self.work)
        git("init", "-q", "--bare", str(self.bare), cwd=base)
        git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=self.bare)
        git("config", "http.receivepack", "false", cwd=self.bare)

    def commit(self, files: dict[str, str | bytes | Symlink], message: str = "commit") -> str:
        for name, content in files.items():
            path = self.work / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, Symlink):
                path.unlink(missing_ok=True)
                path.symlink_to(content.target)
            elif isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content)
        git("add", "-A", cwd=self.work)
        git("commit", "-q", "--allow-empty", "-m", message, cwd=self.work)
        git("push", "-q", "--force", str(self.bare), "HEAD:refs/heads/main", cwd=self.work)
        return git("rev-parse", "HEAD", cwd=self.work)

    def tree(self, commit: str) -> str:
        return git("rev-parse", f"{commit}^{{tree}}", cwd=self.work)

    @property
    def file_url(self) -> str:
        return f"file://{self.bare}"


def repository(url: str, **fields) -> Repository:
    """A valid model with its URL replaced afterwards (loopback/file transports exist
    only in relaxed test policy; the configuration model rejects them)."""
    base = {
        "id": "shop-backend",
        "application": "shop",
        "service": "backend",
        "url": "https://git.example.org/shop/backend.git",
    }
    base.update(fields)
    if url.startswith("ssh://"):
        return Repository.model_validate({**base, "url": url})
    return Repository.model_validate(base).model_copy(update={"url": url})


# --- loopback smart HTTP ------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):  # silence
        pass

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = b""
            while True:
                size = int(self.rfile.readline().strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    return body
                body += self.rfile.read(size)
                self.rfile.readline()
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def _serve(self):
        server = self.server
        body = self._read_body()
        auth = self.headers.get("Authorization")
        server.requests.append({"method": self.command, "path": self.path, "auth": auth})
        if server.delay:
            threading.Event().wait(server.delay)
        if server.redirect:
            self.send_response(302)
            self.send_header("Location", server.redirect + self.path)
            self.end_headers()
            return
        if server.token is not None:
            expected = (
                "Basic " + base64.b64encode(f"steward-fetch:{server.token}".encode()).decode()
            )
            if auth != expected:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="git"')
                self.end_headers()
                return
        path, _, query = self.path.partition("?")
        env = {
            "PATH": "/usr/bin:/bin",
            "GIT_PROJECT_ROOT": str(server.root),
            "GIT_HTTP_EXPORT_ALL": "1",
            "REQUEST_METHOD": self.command,
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(len(body)),
            "GIT_PROTOCOL": self.headers.get("Git-Protocol", ""),
            "HTTP_CONTENT_ENCODING": self.headers.get("Content-Encoding", ""),
            "REMOTE_USER": "steward-fetch",
            "REMOTE_ADDR": "127.0.0.1",
        }
        out = subprocess.run(  # noqa: S603
            [HTTP_BACKEND], input=body, env=env, capture_output=True, check=False
        ).stdout
        head, _, payload = out.partition(b"\r\n\r\n")
        status, headers = 200, []
        for line in head.decode().split("\r\n"):
            name, _, value = line.partition(": ")
            if name.lower() == "status":
                status = int(value.split()[0])
            elif name:
                headers.append((name, value))
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = _serve


@dataclass
class HttpUpstream:
    server: ThreadingHTTPServer
    thread: threading.Thread
    requests: list = field(default_factory=list)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/{path}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


class _Quiet(ThreadingHTTPServer):
    def handle_error(self, request, client_address):  # clients are killed on purpose
        pass


def serve_http(root: Path, *, token=None, delay: float = 0, redirect: str | None = None):
    server = _Quiet(("127.0.0.1", 0), _Handler)
    server.root, server.token, server.delay, server.redirect = root, token, delay, redirect
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    handle = HttpUpstream(server, thread, server.requests)
    return handle


# --- fake ssh ------------------------------------------------------------------

_FAKE_SSH = """#!{python}
import os, shlex, sys
SERVER_KEY = {server_key!r}
PRIVATE_KEY = {private_key!r}
ROOT = {root!r}
LOG = {log!r}
args = sys.argv[1:]
opts, i = {{}}, 0
while i < len(args):
    if args[i] == "-o":
        key, _, value = args[i + 1].partition("=")
        opts[key] = value
        i += 2
    elif args[i] in ("-i", "-F", "-p"):
        opts[args[i]] = args[i + 1]
        i += 2
    else:
        break
host, command = args[i], args[i + 1]
with open(LOG, "a") as log:
    log.write(repr({{"opts": opts, "host": host, "command": command}}) + "\\n")
if opts.get("StrictHostKeyChecking") != "yes" or opts.get("BatchMode") != "yes":
    sys.exit("fake ssh: host key checking is not strict")
known = open(opts["UserKnownHostsFile"]).read()
if SERVER_KEY not in known:
    sys.stderr.write("Host key verification failed.\\n")
    sys.exit(255)
if open(opts["-i"]).read().strip() != PRIVATE_KEY:
    sys.stderr.write("Permission denied (publickey).\\n")
    sys.exit(255)
name, path = shlex.split(command)
os.execv({git!r}, ["git", "upload-pack", ROOT + path])
"""


def fake_ssh(
    directory: Path, *, server_key: str, private_key: str, root: Path, log: Path
) -> FetchPolicy:
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / "ssh"
    script.write_text(
        _FAKE_SSH.format(
            python=sys.executable,
            server_key=server_key,
            private_key=private_key,
            root=str(root),
            log=str(log),
            git=GIT,
        )
    )
    script.chmod(0o755)
    return FetchPolicy(relaxed_for_tests=True, ssh_binary=str(script))


def logging_git(directory: Path, log: Path) -> FetchPolicy:
    """A `git` wrapper recording argv and environment of every call, then running Git."""
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / "git"
    script.write_text(f'#!/bin/sh\n{{ echo "ARGV $*"; env; echo; }} >> {log}\nexec {GIT} "$@"\n')
    script.chmod(0o755)
    return FetchPolicy(relaxed_for_tests=True, git_binary=str(script))
