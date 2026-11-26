"""Fetch an exact revision of a configured repository (card R01).

This component is meant to run as its own unprivileged identity. It never
executes repository content: it only downloads Git objects into a bare store and
reads them back with plumbing commands (no checkout, no filters, no hooks, no
submodules). Credentials are resolved by reference for the one repository being
fetched, written to a private per-run directory and removed afterwards; they never
appear in arguments, in the environment, in records or in error text.

Layout under the component's own root (never a production data directory)::

    <root>/<application>/<service>/<commit>.git    bare object store, immutable
    <root>/<application>/<service>/<commit>.json   source record (commit, tree, digest)
    <root>/<application>/<service>/.lock           per-service fetch lock
    <root>/<application>/<service>/.tmp-*          in-progress fetch (swept when stale)

Remaining limits are listed in the R01 handoff: DNS pinning narrows rebinding but
the per-UID egress policy of the host remains the enforcing layer.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path

from . import secrets as secretlib
from .canonical import canonical_json
from .config import ConfigError, Repository, load_config_file

SAFE_PATH = "/usr/bin:/bin"
FETCH_REF = "refs/steward/fetched"
RECORD_SCHEMA = 1
SAFE_ROOT = re.compile(r"^/[A-Za-z0-9._/-]+$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
PRODUCTION_SCHEMES = frozenset({"https", "ssh"})
TEST_SCHEMES = frozenset({"https", "ssh", "http", "file"})
_NON_GLOBAL_V6 = tuple(
    ipaddress.ip_network(net)
    for net in ("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32")
)
_KEY_ALGORITHMS = {
    "ssh-ed25519": "ssh-ed25519",
    "ecdsa-sha2-nistp256": "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384": "ecdsa-sha2-nistp384",
    "ssh-rsa": "rsa-sha2-512,rsa-sha2-256",
}


class FetchError(Exception):
    """Stable machine-readable `code`; `message` never contains credentials."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def default_resolver(host: str, port: int) -> list[str]:
    rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(row[4][0] for row in rows))


@dataclass(frozen=True)
class FetchLimits:
    timeout_s: float = 120.0
    max_bytes: int = 256 * 2**20
    stderr_bytes: int = 2000
    poll_s: float = 0.2


@dataclass(frozen=True)
class FetchPolicy:
    """Fixed transport policy. Only https and ssh exist in production.

    `relaxed_for_tests` additionally allows http and file transports, loopback and
    private addresses and models built without validation; it exists for local
    fixtures and must never be set by configuration.
    """

    git_binary: str = "/usr/bin/git"
    ssh_binary: str = "/usr/bin/ssh"
    resolver: Callable[[str, int], list[str]] = default_resolver
    relaxed_for_tests: bool = False

    @property
    def schemes(self) -> frozenset[str]:
        return TEST_SCHEMES if self.relaxed_for_tests else PRODUCTION_SCHEMES


@dataclass(frozen=True)
class SourceRecord:
    repository: str
    application: str
    service: str
    url: str
    ref: str
    requested_revision: str | None
    commit: str
    tree: str
    source_digest: str
    store: str
    fetched_at: str
    changed: bool = field(default=False, compare=False)
    repair_base_commit: str | None = None

    def persisted(self) -> dict:
        data = asdict(self)
        data.pop("changed")
        if self.repair_base_commit is None:
            data.pop("repair_base_commit")
        return {"schema": RECORD_SCHEMA, **data}


def source_digest(commit: str, tree: str) -> str:
    """Immutable identity of the source bytes a build may consume."""
    return hashlib.sha256(
        canonical_json({"scheme": "steward-source-v1", "commit": commit, "tree": tree}).encode()
    ).hexdigest()


# --- git invocation ---------------------------------------------------------


def hardening_args(policy: FetchPolicy) -> list[str]:
    """`-c` options placed before every Git subcommand: no hooks, no helpers,
    no redirects, no submodules, no protocol other than the allowed ones."""
    args = [
        "core.hooksPath=/dev/null",
        "core.fsmonitor=false",
        "credential.helper=",
        "protocol.allow=never",
        "http.followRedirects=false",
        "http.sslVerify=true",
        "http.proxy=",
        "http.lowSpeedLimit=1000",
        "http.lowSpeedTime=30",
        "fetch.recurseSubmodules=false",
        "submodule.recurse=false",
        "transfer.fsckObjects=true",
        "gc.auto=0",
        "maintenance.auto=false",
        "core.symlinks=false",
    ]
    args += [f"protocol.{scheme}.allow=always" for scheme in sorted(policy.schemes)]
    out: list[str] = []
    for item in args:
        out += ["-c", item]
    return out


def git_env(policy: FetchPolicy, home: Path, *, askpass: Path | None = None, ssh: str = "") -> dict:
    env = {
        "PATH": SAFE_PATH,
        "HOME": str(home),
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": ":".join(sorted(policy.schemes)),
        "GIT_ASKPASS": str(askpass) if askpass else "/bin/false",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    if ssh:
        env["GIT_SSH_COMMAND"] = ssh
    return env


def _tree_size(path: Path) -> int:
    total = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                    else:
                        with contextlib.suppress(OSError):
                            total += entry.stat(follow_symlinks=False).st_size
        except OSError:
            continue
    return total


def _clean_text(data: bytes, limit: int, known: tuple[str, ...] = ()) -> str:
    text = data[:limit].decode("utf-8", "replace")
    text = "".join(c if c in "\n\t" or 32 <= ord(c) < 127 or ord(c) > 159 else "?" for c in text)
    return secretlib.redact(text, known).strip()


def run_git(
    policy: FetchPolicy,
    args: list[str],
    *,
    label: str,
    config: list[str] | tuple[str, ...] = (),
    env: dict,
    spool: Path,
    cwd: Path,
    timeout_s: float,
    watch: Path | None = None,
    max_bytes: int | None = None,
    max_stdout: int = 1 << 20,
    stderr_bytes: int = 2000,
    poll_s: float = 0.2,
    known_secrets: tuple[str, ...] = (),
    stdin_path: Path | None = None,
    stdout_path: Path | None = None,
    address_space: int | None = None,
    on_poll: Callable[[], bool] | None = None,
) -> bytes:
    """Run Git with fixed argv under a time, size and output budget; return stdout.

    `spool` is a private directory for the child's output. The whole process
    group is killed on timeout or when `watch` grows beyond `max_bytes`.
    A private `stdout_path` keeps binary output on disk and returns empty bytes.
    `address_space` caps Git's address space for offline processing of untrusted objects.
    `on_poll` can stop Git when its caller loses the active job lease.
    """
    argv = [policy.git_binary, *hardening_args(policy), *config, *args]
    if address_space is not None:
        limits = [f"--as={address_space}"]
        if stdout_path is not None:
            limits.append(f"--fsize={max_stdout}")
        argv = ["/usr/bin/prlimit", *limits, "--", *argv]
    out_path, err_path = stdout_path or spool / "stdout.spool", spool / "stderr.spool"
    deadline = time.monotonic() + timeout_s
    with (
        (stdin_path or Path(os.devnull)).open("rb") as source,
        out_path.open("xb" if stdout_path is not None else "wb") as out,
        err_path.open("wb") as err,
    ):
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                argv,
                cwd=cwd,
                env=env,
                stdin=source,
                stdout=out,
                stderr=err,
                start_new_session=True,
                close_fds=True,
                umask=0o077,
            )
        except OSError as exc:
            raise FetchError("git_unavailable", f"cannot start git: {exc.strerror}") from None
        try:
            while True:
                try:
                    proc.wait(timeout=poll_s)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() > deadline:
                    raise FetchError("timeout", f"git did not finish within {timeout_s:g}s")
                if on_poll is not None and not on_poll():
                    raise FetchError("lost_lease", "job lease expired while waiting for git")
                if watch is not None and max_bytes is not None and _tree_size(watch) > max_bytes:
                    raise FetchError("too_large", f"fetched data exceeds {max_bytes} bytes")
                if out_path.stat().st_size > max_stdout or err_path.stat().st_size > 1 << 20:
                    raise FetchError("too_large", "git output exceeds its limit")
        finally:
            if proc.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    if watch is not None and max_bytes is not None and _tree_size(watch) > max_bytes:
        raise FetchError("too_large", f"fetched data exceeds {max_bytes} bytes")
    if out_path.stat().st_size > max_stdout or err_path.stat().st_size > 1 << 20:
        raise FetchError("too_large", "git output exceeds its limit")
    if proc.returncode != 0:
        with err_path.open("rb") as errors:
            detail = _clean_text(errors.read(stderr_bytes), stderr_bytes, known_secrets)
        raise FetchError("git_failed", f"git {label} exited {proc.returncode}: {detail}")
    return out_path.read_bytes() if stdout_path is None else b""


# --- host policy ------------------------------------------------------------


def _permitted(value: str, allow_private: bool) -> bool:
    """Public addresses; with `allow_private` also private/loopback ones. Link-local
    (including the metadata address), unspecified, multicast and reserved ranges and
    address-translation prefixes are never permitted."""
    ip = ipaddress.ip_address(value.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif any(ip in net for net in _NON_GLOBAL_V6):
            return False
    if ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return False
    if ip.is_loopback:  # ::1 counts as "reserved" in the ipaddress module
        return allow_private
    if ip.is_reserved:
        return False
    return True if allow_private else ip.is_global


def public_addresses(
    host: str, port: int, policy: FetchPolicy, allow_private: bool = False
) -> list[str]:
    """Resolve once; every address must be permitted. Used to pin the connection."""
    try:
        addresses = policy.resolver(host, port)
    except OSError:
        raise FetchError("resolve_failed", "repository host does not resolve") from None
    if not addresses:
        raise FetchError("resolve_failed", "repository host does not resolve")
    if not policy.relaxed_for_tests and not all(_permitted(a, allow_private) for a in addresses):
        raise FetchError("non_public_address", "repository host resolves to a non-public address")
    return addresses


def _split_url(url: str) -> tuple[str, str, int]:
    scheme, _, rest = url.partition("://")
    authority = rest.split("/", 1)[0].rsplit("@", 1)[-1]
    host, _, port = authority.partition(":")
    default = {"https": 443, "ssh": 22, "http": 80}.get(scheme, 0)
    return scheme, host, int(port) if port else default


def _is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def validate_endpoint(repository: Repository, endpoint: str) -> str:
    """Validate a numeric address pinned by the package controller."""
    _, host, port = _split_url(repository.url)
    if not 1 <= port <= 65535:
        raise FetchError("policy", "repository port is out of range")
    try:
        address = ipaddress.ip_address(endpoint)
    except ValueError:
        raise FetchError("policy", "repository endpoint must be numeric") from None
    if (
        str(address) != endpoint
        or "%" in endpoint
        or getattr(address, "ipv4_mapped", None) is not None
        or not _permitted(endpoint, repository.allow_private_network)
    ):
        raise FetchError("policy", "repository endpoint is outside address policy")
    if _is_literal(host):
        if ipaddress.ip_address(host) != address:
            raise FetchError("policy", "repository literal host differs from its endpoint")
    else:
        # libcurl accepts legacy IPv4 spellings that bypass hostname resolution.
        try:
            socket.inet_aton(host.rstrip("."))
        except OSError:
            pass
        else:
            raise FetchError("policy", "repository literal host must be canonical")
    return str(address)


def pin_args(scheme: str, host: str, port: int, addresses: list[str]) -> list[str]:
    """Git config pinning libcurl to the addresses that passed the public check."""
    if scheme not in {"https", "http"} or _is_literal(host):
        return []
    shown = ",".join(f"[{a}]" if ":" in a else a for a in addresses)
    return ["-c", f"http.curloptResolve={host}:{port}:{shown}"]


def ssh_command(
    policy: FetchPolicy, key: Path, known_hosts: Path, algorithms: str, address: str | None
) -> str:
    argv = [
        policy.ssh_binary,
        "-F",
        os.devnull,
        "-i",
        str(key),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        f"HostKeyAlgorithms={algorithms}",
        "-o",
        "HostKeyAlias=steward-pinned",
        "-o",
        "VerifyHostKeyDNS=no",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ConnectTimeout=20",
    ]
    if address is not None:
        argv += ["-o", f"Hostname={address}"]
    return shlex.join(argv)


# --- namespace --------------------------------------------------------------


def _private_dir(parent: Path, name: str, *, create: bool = True) -> Path:
    path = parent / name
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            raise FetchError("bad_store", f"{name} is missing") from None
        path.mkdir(mode=0o700)
        info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise FetchError("bad_store", f"{name} is not a private directory owned by this user")
    return path


def _namespace(root: Path, application: str, service: str, *, create: bool = True) -> Path:
    if not SAFE_ROOT.fullmatch(str(root)):
        raise FetchError("bad_store", "fetch root contains unsupported characters")
    try:
        info = root.lstat()
    except OSError:
        raise FetchError("bad_store", "fetch root does not exist") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise FetchError("bad_store", "fetch root must be a real directory owned by this user")
    application_dir = _private_dir(root, application, create=create)
    return _private_dir(application_dir, service, create=create)


def _remove_tree(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode):
        shutil.rmtree(path, ignore_errors=True)
    else:
        with contextlib.suppress(OSError):
            path.unlink()


def _write_private(path: Path, data: str, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(data)


def store_path(root: Path, record: SourceRecord) -> Path:
    return root / record.application / record.service / record.store


# --- credentials ------------------------------------------------------------


def _prepare_credentials(
    repository: Repository,
    scheme: str,
    host: str,
    port: int,
    addresses: list[str],
    policy: FetchPolicy,
    creds: Path,
    resolve_secret: Callable[[str], str],
) -> tuple[dict, list[str], tuple[str, ...]]:
    """Return (extra env, extra `-c` args, secret values to redact)."""
    pins = pin_args(scheme, host, port, addresses)
    secret_values: tuple[str, ...] = ()
    askpass: Path | None = None
    ssh = ""
    if repository.credential is not None:
        try:
            value = resolve_secret(repository.credential)
            if scheme == "ssh":
                _check_private_key(value)
            else:
                secretlib.check_env_value("repository credential", value)
        except secretlib.SecretError as exc:
            raise FetchError("credential", str(exc)) from None
        secret_values = (value,)
        if scheme == "ssh":
            _write_private(creds / "id", value + "\n")
        else:
            _write_private(creds / "secret", value + "\n")
            askpass = creds / "askpass"
            body = (
                "#!/bin/sh\n"
                'case "$1" in\n'
                "  Username*) printf '%s\\n' steward-fetch ;;\n"
                f"  *) IFS= read -r line < {shlex.quote(str(creds / 'secret'))}\n"
                "     printf '%s\\n' \"$line\" ;;\n"
                "esac\n"
            )
            _write_private(askpass, body, 0o700)
    if scheme == "ssh":
        key_type = (repository.host_key or "").split(" ", 1)[0]
        if key_type not in _KEY_ALGORITHMS:
            raise FetchError("host_key", "ssh repositories need a pinned host key")
        _write_private(creds / "known_hosts", f"steward-pinned {repository.host_key}\n")
        ssh = ssh_command(
            policy,
            creds / "id",
            creds / "known_hosts",
            _KEY_ALGORITHMS[key_type],
            None if _is_literal(host) else addresses[0],
        )
    return {"askpass": askpass, "ssh": ssh}, pins, secret_values


def _check_private_key(value: str) -> None:
    lines = value.strip().splitlines()
    if (
        len(value) > 16384
        or "\0" in value
        or len(lines) < 3
        or not lines[0].startswith("-----BEGIN ")
        or not lines[-1].startswith("-----END ")
    ):
        raise secretlib.SecretError("repository credential is not a PEM/OpenSSH private key")


# --- fetch ------------------------------------------------------------------


def fetch_repository(
    repository: Repository,
    root: Path,
    *,
    resolve_secret: Callable[[str], str] = secretlib.resolve,
    limits: FetchLimits = FetchLimits(),  # noqa: B008 - frozen value object
    policy: FetchPolicy = FetchPolicy(),  # noqa: B008
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    scratch: Path | None = None,
) -> SourceRecord:
    """Fetch the configured revision into the repository's own namespace.

    An identical fetch reuses its store and receipt. A change in source binding
    updates the receipt. With scratch supplied, Git credentials, home and logs
    live there while the bare repository stages beside its final destination.
    """
    if not policy.relaxed_for_tests:
        try:
            repository = Repository.model_validate(repository.model_dump(mode="json"))
        except ValueError:
            raise FetchError("policy", "repository definition is not valid") from None
    scheme, host, port = _split_url(repository.url)
    if scheme not in policy.schemes:
        raise FetchError("policy", f"transport {scheme} is not allowed")
    if scratch is not None:
        _private_dir(root.parent, root.name, create=False)
        _private_dir(scratch.parent, scratch.name, create=False)
        if not SAFE_ROOT.fullmatch(str(scratch)):
            raise FetchError("bad_store", "scratch path contains unsupported characters")
    namespace = _namespace(root, repository.application, repository.service)
    lock_fd = os.open(namespace / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock_fd)
        if not stat.S_ISREG(info.st_mode) or (
            info.st_uid,
            stat.S_IMODE(info.st_mode),
            info.st_nlink,
        ) != (os.geteuid(), 0o600, 1):
            raise FetchError("bad_store", "unsafe fetch lock")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise FetchError("busy", "another fetch of this service is running") from None
        for entry in namespace.iterdir():
            if entry.name.startswith(".tmp-"):
                _remove_tree(entry)
        addresses = (
            []
            if scheme == "file"
            else public_addresses(host, port, policy, repository.allow_private_network)
        )
        work = Path(tempfile.mkdtemp(prefix=".tmp-", dir=namespace))
        try:
            with contextlib.ExitStack() as stack:
                private = work
                if scratch is not None:
                    private = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=scratch)))
                return _fetch_into(
                    repository, namespace, work, private, scheme, host, port, addresses,
                    resolve_secret, limits, policy, clock,
                )  # fmt: skip
        finally:
            _remove_tree(work)
    finally:
        os.close(lock_fd)


def _fetch_into(
    repository: Repository,
    namespace: Path,
    work: Path,
    private: Path,
    scheme: str,
    host: str,
    port: int,
    addresses: list[str],
    resolve_secret: Callable[[str], str],
    limits: FetchLimits,
    policy: FetchPolicy,
    clock: Callable[[], datetime],
) -> SourceRecord:
    creds, spool, home, bare = (
        private / "cred",
        private / "spool",
        private / "home",
        work / "repo.git",
    )
    for directory in (creds, spool, home):
        directory.mkdir(mode=0o700)
    extra, pins, known = _prepare_credentials(
        repository, scheme, host, port, addresses, policy, creds, resolve_secret
    )
    env = git_env(policy, home, askpass=extra["askpass"], ssh=extra["ssh"])
    common = {
        "env": env,
        "spool": spool,
        "cwd": private,
        "known_secrets": known,
        "stderr_bytes": limits.stderr_bytes,
        "poll_s": limits.poll_s,
    }
    run_git(
        policy,
        ["init", "--bare", "--quiet", "--object-format=sha1", "--template=", str(bare)],
        label="init",
        timeout_s=limits.timeout_s,
        **common,
    )
    bare.chmod(0o700)
    source = repository.revision or repository.ref
    run_git(
        policy,
        [
            "fetch",
            "--quiet",
            "--no-tags",
            "--depth=1",
            "--no-recurse-submodules",
            "--no-auto-gc",
            "--no-write-fetch-head",
            repository.url,
            f"+{source}:{FETCH_REF}",
        ],
        label="fetch",
        config=pins,
        timeout_s=limits.timeout_s,
        watch=work,
        max_bytes=limits.max_bytes,
        **{**common, "cwd": bare},
    )
    if private != work:
        _check_retained_store(bare, limits.max_bytes)
    read = {**common, "cwd": bare, "timeout_s": 30.0}
    commit = _rev(policy, bare, f"{FETCH_REF}^{{commit}}", read)
    tree = _rev(policy, bare, f"{commit}^{{tree}}", read)
    if repository.revision and commit != repository.revision:
        raise FetchError("revision_mismatch", "server delivered a different commit")
    final = namespace / f"{commit}.git"
    changed = True
    if os.path.lexists(final):
        if private != work:
            _private_dir(namespace, final.name, create=False)
            _check_retained_store(final, limits.max_bytes)
        try:
            if _rev(policy, final, f"{commit}^{{tree}}", {**read, "cwd": final}) == tree:
                if private != work:
                    run_git(
                        policy,
                        ["fsck", "--full", "--no-reflogs", "--no-dangling", commit],
                        label="verify retained source",
                        **{
                            **read,
                            "cwd": final,
                            "env": {**git_env(policy, home), "GIT_NO_LAZY_FETCH": "1"},
                        },
                    )
                changed = False
        except FetchError:
            pass
        if changed:
            if private != work:
                raise FetchError("bad_store", "retained repository is corrupt or has changed")
            _remove_tree(final)
    if changed:
        os.rename(bare, final)
    record_path = namespace / f"{commit}.json"
    record = _load_record(record_path)
    expected = SourceRecord(
        repository=repository.id,
        application=repository.application,
        service=repository.service,
        url=repository.url,
        ref=repository.ref,
        requested_revision=repository.revision,
        commit=commit,
        tree=tree,
        source_digest=source_digest(commit, tree),
        store=final.name,
        fetched_at=record.fetched_at if record is not None else "",
    )
    if changed or record != expected:
        record = replace(expected, fetched_at=clock().strftime("%Y-%m-%dT%H:%M:%SZ"))
        _write_record(record_path, record)
    return replace(record, changed=changed)


def _check_retained_store(path: Path, max_bytes: int) -> None:
    stack = [path]
    total = count = 0
    while stack:
        with os.scandir(stack.pop()) as entries:
            for entry in entries:
                count += 1
                info = entry.stat(follow_symlinks=False)
                if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise FetchError("bad_store", "unsafe retained repository entry")
                if stat.S_ISDIR(info.st_mode):
                    stack.append(Path(entry.path))
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    total += info.st_size
                else:
                    raise FetchError("bad_store", "unsafe retained repository entry")
                if total > max_bytes or count > 8192:
                    raise FetchError("bad_store", "retained repository exceeds its size limit")
    if any(
        os.path.lexists(path / f"objects/info/{name}") for name in ("alternates", "http-alternates")
    ):
        raise FetchError("bad_store", "retained repository has external object storage")


def _rev(policy: FetchPolicy, git_dir: Path, expression: str, common: dict) -> str:
    args = {k: v for k, v in common.items() if k != "timeout_s"}
    out = run_git(
        policy,
        ["--git-dir", str(git_dir), "rev-parse", "--verify", "--quiet", expression],
        label="rev-parse",
        timeout_s=common.get("timeout_s", 30.0),
        **args,
    )
    value = out.decode("ascii", "replace").strip()
    if not SHA1.fullmatch(value):
        raise FetchError("unsupported_object_format", "repository is not a SHA-1 repository")
    return value


def _record_text(record: SourceRecord) -> str:
    return json.dumps(record.persisted(), sort_keys=True, indent=2) + "\n"


def _write_record(path: Path, record: SourceRecord) -> None:
    tmp = path.with_name(path.name + ".new")
    with contextlib.suppress(FileNotFoundError):
        tmp.unlink()
    _write_private(tmp, _record_text(record))
    os.replace(tmp, path)


def _load_record(path: Path) -> SourceRecord | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                return None
            body = handle.read(8193)
        if len(body) > 8192:
            return None
        data = json.loads(body)
        if not isinstance(data, dict) or data.pop("schema", None) != RECORD_SCHEMA:
            return None
        return SourceRecord(**data)
    except (OSError, ValueError, TypeError):
        return None


def _repair_receipt(namespace: Path, commit: str) -> Path:
    return namespace / f"{commit}.repair.json"


def persist_repair_record(namespace: Path, scratch: Path, record: SourceRecord) -> SourceRecord:
    """Publish a repair receipt once, returning the same provenance on retries."""
    if (
        not SHA1.fullmatch(record.commit)
        or record.repair_base_commit is None
        or not SHA1.fullmatch(record.repair_base_commit)
    ):
        raise FetchError("bad_store", "invalid repair source identity")
    path = _repair_receipt(namespace, record.commit)
    staged = scratch / "receipt.json"
    _write_private(staged, _record_text(record))
    with contextlib.suppress(FileExistsError):
        os.link(staged, path)
    persisted = _load_record(path)
    if persisted is None or persisted != replace(record, fetched_at=persisted.fetched_at):
        raise FetchError("bad_store", "repair source does not match its stored receipt")
    return replace(persisted, changed=record.changed)


def load_record(
    root: Path, application: str, service: str, commit: str, *, repair: bool = False
) -> SourceRecord:
    """Read a stored source record; the commit must be a full lowercase SHA-1."""
    if not SHA1.fullmatch(commit):
        raise FetchError("bad_store", "commit must be a full SHA-1")
    namespace = _namespace(root, application, service, create=False)
    path = _repair_receipt(namespace, commit) if repair else namespace / f"{commit}.json"
    record = _load_record(path)
    if (
        record is None
        or record.commit != commit
        or (record.repair_base_commit is not None) != repair
    ):
        raise FetchError("bad_store", "no stored source for this commit")
    return record


def checked_store_path(root: Path, record: SourceRecord) -> Path:
    """Verify a source receipt and return the private store for its exact commit."""
    persisted = load_record(
        root, record.application, record.service, record.commit,
        repair=record.repair_base_commit is not None,
    )  # fmt: skip
    name = f"{record.commit}.git"
    if record != persisted or persisted.store != name:
        raise FetchError("bad_store", "source record does not match its stored receipt")
    return _private_dir(root / record.application / record.service, name, create=False)


# --- command line (component entry point, not wired into the steward CLI) ---


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m steward.core.repositories")
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch", help="fetch the configured revision of one repository")
    fetch.add_argument("--config", type=Path, required=True)
    fetch.add_argument("--repository", required=True)
    fetch.add_argument("--root", type=Path, required=True)
    fetch.add_argument("--timeout", type=float, default=FetchLimits.timeout_s)
    args = parser.parse_args(argv)
    try:
        cfg = load_config_file(args.config, allow_unavailable=True)
    except ConfigError as exc:
        print(json.dumps({"ok": False, "code": "config", "message": str(exc)}))
        return 2
    repository = next((r for r in cfg.repositories if r.id == args.repository), None)
    if repository is None:
        print(json.dumps({"ok": False, "code": "unknown_repository", "message": args.repository}))
        return 2
    try:
        record = fetch_repository(repository, args.root, limits=FetchLimits(timeout_s=args.timeout))
    except FetchError as exc:
        print(json.dumps({"ok": False, "code": exc.code, "message": exc.message}))
        return 1
    print(json.dumps({"ok": True, **asdict(record)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
