#!/usr/bin/python3
"""Activate an SSH-verified policy for the fixed inet steward table."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import NamedTuple

POLICY_DIR = Path("/etc/steward/nftables")
RUNTIME_DIR = Path("/run/steward-firewall")
HELPER = "/etc/steward/nftables/firewall-policy.py"
NFT = "/usr/sbin/nft"
SYSTEMCTL = "/usr/bin/systemctl"
ROLLBACK = "steward-firewall-rollback"
SSH_ROLLBACK = "steward-ssh-rollback"
REPLACE = b"table inet steward\ndelete table inet steward\n"
TABLE = b"table inet steward {\n"
POLICY_FILE = "steward.nft"
HEADER_FAMILY = b"# steward verified nftables policy"
HEADER = HEADER_FAMILY + b" v1\n"
MARKER = b'comment "steward attempt '
HEX = re.compile(r"[a-f0-9]{64}")
MARKER_PATTERN = re.compile(re.escape(MARKER) + rb'[a-f0-9]{64}"')
MAX_BATCH = 4 * 1024 * 1024
MAX_METADATA = 1024
ROLLBACK_SECONDS = 180
ROLLBACK_LOCK_WAIT = 240
OWNER = 0


class PolicyError(Exception):
    pass


class Verified(NamedTuple):
    source: str
    runtime: str
    attempt: str


class Pending(NamedTuple):
    attempt: str
    source: str
    deadline: int
    previous: str | None
    runtime: str | None


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_digest(value: object) -> bool:
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def run(argv: list[str], *, data: bytes | None = None) -> bytes:
    result = subprocess.run(
        argv,
        input=data,
        capture_output=True,
        cwd="/",
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
        timeout=15,
        check=False,
    )
    if result.returncode:
        error = result.stderr[:500].decode("utf-8", errors="replace").strip()
        raise PolicyError(f"{Path(argv[0]).name} failed: {error}")
    if len(result.stdout) > MAX_BATCH:
        raise PolicyError(f"{Path(argv[0]).name} output exceeds the policy size limit")
    return result.stdout


def check_mode(path: Path, *, directory: bool = False) -> None:
    info = path.lstat()
    file_type = stat.S_ISDIR if directory else stat.S_ISREG
    expected_mode = 0o700 if directory else 0o600
    if (
        not file_type(info.st_mode)
        or stat.S_IMODE(info.st_mode) != expected_mode
        or info.st_uid != OWNER
    ):
        raise PolicyError(f"unsafe owner, mode or file type: {path}")


def read(path: Path, limit: int) -> bytes | None:
    try:
        check_mode(path)
    except FileNotFoundError:
        return None
    with path.open("rb") as file:
        contents = file.read(limit + 1)
    if len(contents) > limit:
        raise PolicyError(f"policy data exceeds its size limit: {path}")
    return contents


def sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(path: Path, data: bytes, *, durable: bool = False) -> None:
    fd, stage = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            if durable:
                file.flush()
                os.fsync(file.fileno())
        os.replace(stage, path)
        if durable:
            sync_dir(path.parent)
    finally:
        Path(stage).unlink(missing_ok=True)


@contextlib.contextmanager
def policy_lock(wait_seconds: int = 25, *, create: bool = True):
    check_mode(POLICY_DIR, directory=True)
    if create:
        RUNTIME_DIR.mkdir(mode=0o700, exist_ok=True)
    check_mode(RUNTIME_DIR, directory=True)
    lock = RUNTIME_DIR / "lock"
    flags = os.O_RDWR | os.O_CREAT if create else os.O_RDONLY
    fd = os.open(lock, flags | os.O_NOFOLLOW, 0o600)
    try:
        check_mode(lock)
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise PolicyError("another firewall operation holds the policy lock") from None
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)


def nft(data: bytes, *, check: bool = False) -> None:
    run([NFT, *(["-c"] if check else []), "-f", "-"], data=data)


def snapshot() -> bytes | None:
    tables = run([NFT, "list", "tables"])
    if b"table inet steward" not in tables.splitlines():
        return None
    current = run([NFT, "-s", "-n", "list", "table", "inet", "steward"])
    if not current.startswith(TABLE) or not current.endswith(b"}\n"):
        raise PolicyError("unexpected nftables snapshot format")
    return current


def owner_marker(attempt: str) -> bytes:
    return MARKER + attempt.encode() + b'"'


def owned_by(current: bytes | None, attempt: str) -> bool:
    return current is not None and current.split(b"\n", 2)[1].strip() == owner_marker(attempt)


def without_attempt(current: bytes) -> bytes:
    table, first, rest = current.split(b"\n", 2)
    if MARKER_PATTERN.fullmatch(first.strip()):
        return table + b"\n" + rest
    return current


def live_digest(current: bytes | None) -> str | None:
    return digest(without_attempt(current)) if current is not None else None


def verified_file() -> tuple[Verified, bytes] | None:
    data = read(POLICY_DIR / POLICY_FILE, MAX_BATCH + MAX_METADATA)
    if data is None or not data.startswith(HEADER_FAMILY):
        return None
    lines = data.split(b"\n", 4)
    if len(lines) != 5 or lines[0] + b"\n" != HEADER:
        raise PolicyError("invalid verified policy header")
    fields = []
    prefixes = (b"# source ", b"# runtime ", b"# attempt ")
    for line, prefix in zip(lines[1:4], prefixes, strict=True):
        if not line.startswith(prefix):
            raise PolicyError("invalid verified policy metadata")
        fields.append(line[len(prefix) :].decode("ascii"))
    source, runtime, attempt = fields
    batch = lines[4]
    if not (
        (source == "-" and attempt == "-" or is_digest(source) and is_digest(attempt))
        and batch.startswith(REPLACE + TABLE)
        and batch.endswith(b"}\n")
        and digest(batch[len(REPLACE) :]) == runtime
    ):
        raise PolicyError("verified policy contents fail integrity checks")
    return Verified(source, runtime, attempt), data


def write_verified(meta: Verified, batch: bytes) -> None:
    metadata = f"# source {meta.source}\n# runtime {meta.runtime}\n# attempt {meta.attempt}\n"
    publish(POLICY_DIR / POLICY_FILE, HEADER + metadata.encode() + batch, durable=True)


def pending_file() -> Pending | None:
    data = read(RUNTIME_DIR / "pending", MAX_METADATA)
    if data is None:
        return None
    try:
        value = Pending(**json.loads(data))
        if (
            is_digest(value.attempt)
            and is_digest(value.source)
            and type(value.deadline) is int
            and value.deadline > 0
            and (value.previous is None or is_digest(value.previous))
            and (value.runtime is None or is_digest(value.runtime))
        ):
            return value
    except (ValueError, TypeError):
        pass
    raise PolicyError("invalid pending firewall state")


def write_pending(pending: Pending) -> None:
    publish(RUNTIME_DIR / "pending", json.dumps(pending._asdict()).encode())


def rollback_unit(kind: str, prefix: str = ROLLBACK) -> dict[str, str]:
    result = run(
        [
            SYSTEMCTL,
            "show",
            f"{prefix}.{kind}",
            "-p",
            "LoadState,ActiveState,SubState,Job,MainPID,ControlGroup,Description",
        ]
    )
    return dict(line.split("=", 1) for line in result.decode().splitlines() if "=" in line)


def quiescent(props: dict[str, str], *, service: bool = False) -> bool:
    state = (props.get("ActiveState"), props.get("SubState"))
    return (
        props.get("Job") == ""
        and (
            props.get("LoadState") in ("not-found", "loaded")
            and state == ("inactive", "dead")
            or props.get("LoadState") == "loaded"
            and state == ("failed", "failed")
        )
        and (not service or props.get("MainPID") == "0" and props.get("ControlGroup") == "")
    )


def require_quiescent(prefix: str = ROLLBACK) -> None:
    if not quiescent(rollback_unit("timer", prefix)) or not quiescent(
        rollback_unit("service", prefix), service=True
    ):
        raise PolicyError(f"{prefix} units are active or their state is unknown")


def timer_description(attempt: str) -> str:
    return f"Steward firewall rollback {attempt}"


def require_armed(attempt: str) -> None:
    if known_timer(attempt) != "waiting" or not quiescent(rollback_unit("service"), service=True):
        raise PolicyError("firewall rollback timer is unavailable or already firing")


def arm(attempt: str) -> None:
    run(
        [
            "/usr/bin/systemd-run",
            f"--unit={ROLLBACK}",
            f"--on-active={ROLLBACK_SECONDS}s",
            "--timer-property=AccuracySec=1us",
            "--timer-property=RemainAfterElapse=no",
            f"--timer-property=Description={timer_description(attempt)}",
            "--collect",
            "/usr/bin/python3",
            HELPER,
            "rollback",
            attempt,
        ]
    )


def known_timer(attempt: str) -> str:
    timer = rollback_unit("timer")
    if quiescent(timer):
        return "quiescent"
    state = timer.get("SubState", "")
    if (
        timer.get("LoadState") == "loaded"
        and timer.get("ActiveState") == "active"
        and state in ("waiting", "running", "elapsed")
        and timer.get("Job") == ""
        and timer.get("Description") == timer_description(attempt)
    ):
        return state
    raise PolicyError("firewall rollback timer state is unknown or belongs to another attempt")


def disarm(attempt: str) -> None:
    if known_timer(attempt) != "quiescent":
        run([SYSTEMCTL, "stop", f"{ROLLBACK}.timer"])


def finish_pending(attempt: str) -> None:
    disarm(attempt)
    (RUNTIME_DIR / "pending").unlink()


def restore(stable: tuple[Verified, bytes]) -> None:
    meta, batch = stable
    nft(batch)
    if live_digest(snapshot()) != meta.runtime:
        raise PolicyError("restored firewall does not match the verified policy")


def recover(pending: Pending) -> None:
    known_timer(pending.attempt)
    stable = verified_file()
    current = snapshot()
    actual = live_digest(current)
    if stable is not None:
        meta = stable[0]
        if actual != meta.runtime:
            if (
                meta.attempt == pending.attempt
                or owned_by(current, pending.attempt)
                or actual == pending.previous
                or (current is None and pending.runtime is not None)
            ):
                restore(stable)
            else:
                raise PolicyError("active firewall no longer matches the attempt or previous rules")
    elif current is not None:
        if not owned_by(current, pending.attempt):
            raise PolicyError("refusing to delete a table without the pending attempt marker")
        nft(b"delete table inet steward\n")
        if snapshot() is not None:
            raise PolicyError("firewall rollback could not verify removal of the first policy")
    finish_pending(pending.attempt)


def reconcile() -> None:
    pending = pending_file()
    if pending is not None:
        stable = verified_file()
        published = stable is not None and stable[0].attempt == pending.attempt
        if not published and time.monotonic_ns() < pending.deadline:
            raise PolicyError("firewall change is awaiting SSH verification or rollback")
        recover(pending)
    require_quiescent()


def inspect() -> dict:
    check_mode(POLICY_DIR, directory=True)
    with contextlib.suppress(FileNotFoundError):
        check_mode(RUNTIME_DIR, directory=True)
    stable = verified_file()
    pending = pending_file()
    if pending is None:
        require_quiescent()
    elif (
        stable is None or stable[0].attempt != pending.attempt
    ) and time.monotonic_ns() < pending.deadline:
        raise PolicyError("firewall change is awaiting SSH verification or rollback")
    current = snapshot()
    if stable is not None:
        state = "verified"
    else:
        try:
            check_mode(POLICY_DIR / POLICY_FILE)
        except FileNotFoundError:
            if current is not None and (pending is None or not owned_by(current, pending.attempt)):
                raise PolicyError("active steward table has no owned policy") from None
            state = "fresh"
        else:
            if current is None:
                raise PolicyError("legacy firewall file exists without an active table to verify")
            state = "legacy"
    return {
        "state": state,
        "runtime": live_digest(current),
        "source": stable[0].source if stable is not None and stable[0].source != "-" else None,
        "verified_runtime": stable[0].runtime if stable is not None else None,
    }


def bootstrap(expected: str) -> None:
    require_quiescent(SSH_ROLLBACK)
    if pending_file() is not None:
        raise PolicyError("legacy firewall cannot be verified during a pending change")
    info = inspect()
    if info["state"] != "legacy" or info["runtime"] != expected:
        raise PolicyError("legacy rules changed or disappeared before SSH verification finished")
    current = snapshot()
    if current is None or live_digest(current) != expected:
        raise PolicyError("legacy snapshot no longer matches the verified runtime")
    batch = REPLACE + without_attempt(current)
    nft(batch, check=True)
    if snapshot() != current:
        raise PolicyError("legacy snapshot changed during validation")
    write_verified(Verified("-", expected, "-"), batch)


def apply(source: bytes) -> dict:
    require_quiescent(SSH_ROLLBACK)
    reconcile()
    info = inspect()
    if info["state"] == "legacy":
        raise PolicyError("verify the active legacy firewall before applying new rules")
    stable = verified_file()
    source_id = digest(source)
    if stable is not None and stable[0][:2] == (source_id, info["runtime"]):
        return {"changed": False, "attempt": None}
    anchor = REPLACE + b"\n" + TABLE
    prefix, separator, suffix = source.partition(anchor)
    if (
        not separator
        or not suffix.endswith(b"}\n")
        or any(line and not line.startswith(b"#") for line in prefix.splitlines())
    ):
        raise PolicyError("unexpected rendered firewall format")
    attempt = secrets.token_hex(32)
    batch = prefix + anchor + b"\t" + owner_marker(attempt) + b"\n" + suffix
    nft(batch, check=True)
    pending = Pending(
        attempt,
        source_id,
        time.monotonic_ns() + ROLLBACK_SECONDS * 1_000_000_000,
        info["runtime"],
        None,
    )
    write_pending(pending)
    try:
        arm(attempt)
        require_armed(attempt)
        if live_digest(snapshot()) != pending.previous:
            raise PolicyError("active firewall changed before candidate activation")
        nft(batch)
        current = snapshot()
        if current is None or not owned_by(current, attempt):
            raise PolicyError("candidate nftables rules were not installed")
        write_pending(pending._replace(runtime=live_digest(current)))
    except (OSError, PolicyError, subprocess.TimeoutExpired):
        recover(pending)
        raise
    return {"changed": True, "attempt": attempt}


def commit(attempt: str) -> None:
    pending = pending_file()
    if pending is None or pending.attempt != attempt:
        raise PolicyError("firewall attempt does not match the pending change")
    if pending.runtime is None or time.monotonic_ns() >= pending.deadline:
        raise PolicyError("firewall attempt is incomplete or expired")
    require_quiescent(SSH_ROLLBACK)
    require_armed(attempt)
    current = snapshot()
    if current is None or live_digest(current) != pending.runtime or not owned_by(current, attempt):
        raise PolicyError("active firewall changed during SSH verification")
    batch = REPLACE + without_attempt(current)
    nft(batch, check=True)
    if snapshot() != current or time.monotonic_ns() >= pending.deadline:
        raise PolicyError("firewall changed or the verification deadline expired")
    write_verified(Verified(pending.source, pending.runtime, attempt), batch)
    finish_pending(attempt)


def stable_for_unit() -> tuple[Verified, bytes]:
    if pending_file() is not None:
        raise PolicyError("firewall change is awaiting SSH verification or rollback")
    require_quiescent()
    stable = verified_file()
    if stable is None:
        raise PolicyError("no verified firewall policy installed")
    return stable


def load_verified() -> None:
    stable = stable_for_unit()
    if live_digest(snapshot()) != stable[0].runtime:
        restore(stable)


def require_active(expected: str) -> None:
    stable, _ = stable_for_unit()
    require_quiescent(SSH_ROLLBACK)
    if stable.source != expected or live_digest(snapshot()) != stable.runtime:
        raise PolicyError("active firewall policy does not match the required verified source")


def stop_verified() -> None:
    stable_for_unit()
    if snapshot() is not None:
        nft(b"delete table inet steward\n")


def rollback(attempt: str) -> None:
    pending = pending_file()
    if pending is not None and pending.attempt == attempt:
        recover(pending)


def digest_arg(value: str) -> str:
    if not is_digest(value):
        raise argparse.ArgumentTypeError("expected a SHA-256 hexadecimal value")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for op in ("inspect", "apply", "load-verified", "stop-verified"):
        commands.add_parser(op)
    for op in ("bootstrap", "commit", "rollback", "require-active"):
        commands.add_parser(op).add_argument("value", type=digest_arg)
    args = parser.parse_args()
    try:
        if os.geteuid() != OWNER:
            raise PolicyError("firewall policy management requires root")
        if args.command == "inspect":
            print(json.dumps(inspect()))
            return
        if args.command == "apply":
            source = sys.stdin.buffer.read(MAX_BATCH + 1)
            if not source or len(source) > MAX_BATCH:
                raise PolicyError("invalid firewall policy input length")
        if args.command == "require-active":
            # An activation or verified boot has already initialized the lock.
            with policy_lock(create=False):
                require_active(args.value)
            return
        with policy_lock(ROLLBACK_LOCK_WAIT if args.command == "rollback" else 25):
            match args.command:
                case "apply":
                    print(json.dumps(apply(source)))
                case "bootstrap":
                    bootstrap(args.value)
                case "commit":
                    commit(args.value)
                case "rollback":
                    rollback(args.value)
                case "load-verified":
                    load_verified()
                case "stop-verified":
                    stop_verified()
    except (OSError, PolicyError, ValueError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"firewall policy: {error}\n")


if __name__ == "__main__":
    main()
