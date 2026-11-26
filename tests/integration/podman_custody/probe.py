"""Exercise a verified experimental Podman binary in an isolated rootless fixture."""

import argparse
import fcntl
import grp
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from contextlib import ExitStack, suppress
from pathlib import Path

from verify import PROTOCOL, verify_bundle, verify_runtime_package

PROFILE = "resolute-amd64-sqlite-vfs-file"
STOCK = "/usr/bin/podman"
IMAGE = "localhost/steward-custody-fixture:probe"
FULL_ID = re.compile(r"[0-9a-f]{64}")
TIMEOUT = 30
WAIT_INTERVAL = 0.05


class ProbeError(ValueError):
    """The fixture or one of its evidence checks failed."""


def require(condition, message):
    if not condition:
        raise ProbeError(message)


def exact_id(value):
    require(isinstance(value, str) and FULL_ID.fullmatch(value), f"expected full ID: {value!r}")
    return value


def fixture_user(uid, gid):
    require(os.geteuid() == 0 and uid > 0 and gid > 0, "requires root and nonroot fixture IDs")
    account = pwd.getpwuid(uid)
    group = grp.getgrgid(gid)
    require(
        account.pw_gid == gid
        and account.pw_name == group.gr_name
        and re.fullmatch(r"stw-custody-[a-z0-9-]+", account.pw_name),
        "UID/GID must select the explicitly provisioned stw-custody-* fixture account",
    )
    return account.pw_name


def process_start(pid):
    # The command name is parenthesized and can itself contain spaces and parentheses.
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def blocked_waiters(locks, info):
    for row in locks.splitlines():
        fields = row.split()
        if len(fields) == 9 and fields[1:5] == ["->", "POSIX", "ADVISORY", "WRITE"]:
            major, minor, inode = fields[6].split(":")
            if (int(major, 16), int(minor, 16), int(inode)) == (
                os.major(info.st_dev),
                os.minor(info.st_dev),
                info.st_ino,
            ):
                yield int(fields[5])


def waiter_groups(info):
    observed = {}
    for pid in blocked_waiters(Path("/proc/locks").read_text(), info):
        with suppress(ProcessLookupError):
            observed[pid] = os.getpgid(pid)
    return observed


def process_stopped(pid):
    with suppress(FileNotFoundError):
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        return state == "T"
    return False


class Fixture:
    def __init__(self, root, uid, gid, username, artifact):
        self.root = root
        self.uid = uid
        self.gid = gid
        self.artifact = artifact
        self.pause_fd = None
        # The parent and configuration stay root-owned. Only the empty fixture stores
        # and identity directories are writable by the Podman subprocesses.
        root.chmod(0o711)
        for name in ("home", "config", "data", "cache", "runtime", "graph", "run", "tmp", "image"):
            directory = root / name
            directory.mkdir(mode=0o700)
            os.chown(directory, uid, gid)
        hooks = root / "hooks"
        hooks.mkdir(mode=0o755)
        # The fixture UID must be able to read hooks under a restrictive umask.
        hooks.chmod(0o755)
        for name in ("mounts.conf", "registries.conf", "policy.json"):
            (root / name).write_text("")
        (root / "policy.json").write_text(
            '{"default":[{"type":"reject"}],"transports":'
            '{"tarball":{"":[{"type":"insecureAcceptAnything"}]}}}\n'
        )
        (root / "containers.conf").write_text(
            "[engine]\n"
            'database_backend = "sqlite"\n'
            'lock_type = "file"\n'
            'cgroup_manager = "cgroupfs"\n'
            'events_logger = "file"\n'
            f"hooks_dir = [{json.dumps(str(root / 'hooks'))}]\n"
            f"volume_path = {json.dumps(str(root / 'graph/volumes'))}\n"
        )
        (root / "storage.conf").write_text(
            '[storage]\ndriver = "vfs"\n'
            f"graphroot = {json.dumps(str(root / 'graph'))}\n"
            f"runroot = {json.dumps(str(root / 'run'))}\n"
        )
        for name in (
            "mounts.conf",
            "registries.conf",
            "policy.json",
            "containers.conf",
            "storage.conf",
        ):
            (root / name).chmod(0o644)
        self.env = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "USER": username,
            "LOGNAME": username,
            "HOME": str(root / "home"),
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_DATA_HOME": str(root / "data"),
            "XDG_CACHE_HOME": str(root / "cache"),
            "XDG_RUNTIME_DIR": str(root / "runtime"),
            "TMPDIR": str(root / "image"),
            "CONTAINERS_CONF": str(root / "containers.conf"),
            "CONTAINERS_STORAGE_CONF": str(root / "storage.conf"),
            "CONTAINERS_REGISTRIES_CONF": str(root / "registries.conf"),
        }
        self.flags = [
            "--remote=false",
            "--root",
            str(root / "graph"),
            "--runroot",
            str(root / "run"),
            "--tmpdir",
            str(root / "tmp"),
            "--storage-driver=vfs",
            "--default-mounts-file",
            str(root / "mounts.conf"),
        ]

    def launch(self, *args, candidate=False):
        executable = f"/proc/self/fd/{self.artifact}" if candidate else STOCK
        # Retain Podman's argv[0] convention for its existing rootless namespace
        # shortcut. The executable itself always comes from the verified fd.
        command = "podman-steward-custody" if candidate else STOCK
        return subprocess.Popen(
            [command, *self.flags, *args],
            executable=executable,
            cwd=self.root / "home",
            env=self.env,
            user=self.uid,
            group=self.gid,
            extra_groups=[],
            umask=0o077,
            pass_fds=(self.artifact,) if candidate else (),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            text=True,
        )

    @staticmethod
    def reap(process):
        if process.returncode is not None:
            return
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=5)

    def result(self, process, timeout=TIMEOUT):
        try:
            output, error = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self.reap(process)
            raise ProbeError(f"timed out: {process.args!r}") from exc
        return process.returncode, output, error

    def stock(self, *args):
        status, output, error = self.result(self.launch(*args))
        require(status == 0, f"stock command {args!r} failed ({status}): {error.strip()}")
        return output.strip()

    def custody(self, *args):
        return self.launch("pod", "steward-custody-v1", *args, candidate=True)

    def expect(self, process, token):
        self.expect_result(self.result(process), token)

    @staticmethod
    def expect_result(result, token):
        status, output, error = result
        require(
            (status == 0 if token in ("removed", PROTOCOL) else status > 0)
            and output == f"{token}\n",
            f"expected {token!r}; got status={status} stdout={output!r} stderr={error!r}",
        )

    def bind_pause(self):
        pidfile = self.root / "runtime/libpod/tmp/pause.pid"
        fd = os.open(pidfile, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(info.st_mode) and info.st_uid == self.uid, "invalid fixture pause file"
            )
            pid = int(stream.read(32))
        require(pid > 1, "invalid fixture pause PID")
        fd = os.pidfd_open(pid)
        try:
            proc = Path(f"/proc/{pid}")
            env = proc.joinpath("environ").read_bytes().split(b"\0")
            require(
                proc.stat().st_uid == self.uid
                and b"_PODMAN_PAUSE=1" in env
                and os.fsencode(f"XDG_RUNTIME_DIR={self.env['XDG_RUNTIME_DIR']}") in env,
                "pause process is outside the fixture",
            )
        except BaseException:
            os.close(fd)
            raise
        self.pause_fd = fd

    def inventory(self, kind):
        args = ("pod", "ps") if kind == "pod" else ("ps", "--all", "--external")
        return {exact_id(line) for line in self.stock(*args, "--quiet", "--no-trunc").splitlines()}

    def initialize(self, busybox):
        try:
            info = json.loads(self.stock("info", "--format=json"))
        finally:
            if (self.root / "runtime/libpod/tmp/pause.pid").exists():
                self.bind_pause()
        require(self.pause_fd is not None, "missing fixture pause process")
        host = info["host"]
        store = info["store"]
        require(
            host["arch"] == "amd64"
            and host["security"]["rootless"] is True
            and host["databaseBackend"] == "sqlite"
            and host["cgroupManager"] == "cgroupfs"
            and host["eventLogger"] == "file"
            and store["graphDriverName"] == "vfs"
            and store["graphRoot"] == str(self.root / "graph")
            and store["runRoot"] == str(self.root / "run")
            and store["volumePath"] == str(self.root / "graph/volumes"),
            f"isolated runtime does not match {PROFILE}",
        )
        require(
            self.inventory("pod") == self.inventory("container") == set()
            and store["imageStore"]["number"] == 0,
            "fixture storage was not empty",
        )
        archive = self.root / "payload.tar"
        with tarfile.open(archive, "w") as tar:
            tar.add(busybox.resolve(strict=True), "bin/busybox", recursive=False)
        archive.chmod(0o644)
        self.stock(
            "import",
            "--signature-policy",
            str(self.root / "policy.json"),
            "--change",
            'ENTRYPOINT ["/bin/busybox","sleep","3600"]',
            str(archive),
            IMAGE,
        )

    def create_pod_args(self, name):
        return (
            "pod",
            "create",
            "--name",
            name,
            "--network=none",
            "--share-parent=false",
            "--infra-image",
            IMAGE,
        )

    def pod(self, name):
        pod = exact_id(self.stock(*self.create_pod_args(name)))
        infra = exact_id(self.stock("pod", "inspect", "--format", "{{.InfraContainerID}}", pod))
        require(
            pod in self.inventory("pod") and infra in self.inventory("container"),
            "missing fixture IDs",
        )
        return pod, infra

    def container(self, cid):
        output = self.stock("container", "inspect", cid)
        [container] = json.loads(output)
        require(container["Id"] == cid, "container inspect resolved a different ID")
        state = container["State"]
        return container["Pod"], state["Status"], state["Pid"]

    def join_args(self, pod, name):
        return (
            "create",
            "--pod",
            pod,
            "--name",
            name,
            "--pull=never",
            "--entrypoint",
            "/bin/busybox",
            IMAGE,
            "sh",
            "-c",
            "echo custody-fixture >/custody-proof; exec /bin/busybox sleep 3600",
        )

    def remove_empty(self, pod, infra, token):
        self.expect(self.custody("remove-empty", pod, infra), token)

    def preserve(self, pod, infra):
        require(
            pod in self.inventory("pod") and infra in self.inventory("container"),
            "pod or infra disappeared",
        )
        require(
            self.stock("pod", "inspect", "--format", "{{.InfraContainerID}}", pod) == infra,
            "infra identity changed",
        )

    def cleanup_pod(self, pod):
        self.stock("pod", "rm", "--force", exact_id(pod))

    def cleanup(self):
        # A failed CLI call can still have created an object. Read exact IDs only
        # from this invocation's initially empty, private fixture store.
        try:
            if self.pause_fd is not None:
                for pod in sorted(self.inventory("pod")):
                    self.cleanup_pod(pod)
                for cid in sorted(self.inventory("container")):
                    self.stock("container", "rm", "--force", cid)
        finally:
            if self.pause_fd is not None:
                with suppress(ProcessLookupError):
                    signal.pidfd_send_signal(self.pause_fd, signal.SIGKILL)
                os.close(self.pause_fd)

    def identity_cases(self):
        absent = uuid.uuid4().hex + uuid.uuid4().hex
        pod, infra = self.pod(absent)
        require(absent not in self.inventory("pod"), "lookalike name is an actual Pod ID")
        self.remove_empty(absent, infra, "not_found")
        self.remove_empty(pod[:12], infra, "conflict")
        self.remove_empty(pod, infra[:12], "conflict")
        self.remove_empty(pod, absent, "conflict")
        self.preserve(pod, infra)
        status, output, error = self.result(self.launch(*self.create_pod_args(absent)))
        require(
            status > 0 and not output and f'name "{absent}" is in use' in error,
            f"second process did not refuse the exact name collision: {error.strip()}",
        )
        require(self.inventory("pod") == {pod}, "name collision changed pod inventory")
        self.preserve(pod, infra)
        infra_pod, infra_state, infra_pid = self.container(infra)
        require(
            infra_pod == pod and infra_state in ("configured", "created") and infra_pid == 0,
            "infra must start inactive",
        )
        self.remove_empty(pod, infra, "removed")
        require(
            self.inventory("pod") == self.inventory("container") == set(),
            "empty removal left fixture IDs",
        )
        print("PASS exact IDs, name collision, and inactive infra removal", flush=True)

    def live_identity(self, cid):
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            state = self.container(cid)
            require(state[1] == "running" and state[2] > 1, "fixture member is not running")
            status, output, _ = self.result(
                self.launch("exec", cid, "/bin/busybox", "cat", "/custody-proof")
            )
            if status == 0 and output == "custody-fixture\n":
                return state, process_start(state[2])
            time.sleep(WAIT_INTERVAL)
        raise ProbeError("fixture payload did not become readable")

    def member_case(self, kind):
        pod, infra = self.pod(f"custody-{kind}")
        cid = exact_id(self.stock(*self.join_args(pod, f"foreign-{kind}")))
        if kind in ("running", "stopped"):
            self.stock("start", cid)
            self.live_identity(cid)
        if kind == "stopped":
            self.stock("stop", "--time=0", cid)
        before = self.container(cid)
        expected = {
            "created": {"configured", "created"},
            "stopped": {"stopped", "exited"},
            "running": {"running"},
        }
        require(
            before[0] == pod and before[1] in expected[kind],
            f"unexpected {kind} member state: {before}",
        )
        live = self.live_identity(cid) if kind == "running" else None
        infra_before = self.container(infra)
        self.remove_empty(pod, infra, "not_empty")
        self.preserve(pod, infra)
        require(
            self.container(cid) == before and self.container(infra) == infra_before,
            "member or infra state changed",
        )
        if live is not None:
            require(self.live_identity(cid) == live, "running member process or payload changed")
        self.cleanup_pod(pod)
        print(f"PASS {kind} foreign member preserved", flush=True)

    def race(self, join_first):
        first = "join" if join_first else "remove"
        pod, infra = self.pod(f"custody-race-{first}")
        lock_number = int(self.stock("pod", "inspect", "--format", "{{.LockNumber}}", pod))
        require(lock_number >= 0, "Podman did not report a file lock index")
        with ExitStack() as stack:
            fd = os.open(self.root / "tmp/locks" / str(lock_number), os.O_RDWR | os.O_NOFOLLOW)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            require(
                stat.S_ISREG(info.st_mode) and info.st_uid == self.uid, "invalid fixture lock inode"
            )
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            join = self.launch(*self.join_args(pod, "foreign-racer"))
            stack.callback(self.reap, join)
            remove = self.custody("remove-empty", pod, infra)
            stack.callback(self.reap, remove)
            winner, parked = (join, remove) if join_first else (remove, join)
            winner_result, parked_result = self.ordered_race(fd, info, winner, parked)
            join_result, remove_result = (
                (winner_result, parked_result) if join_first else (parked_result, winner_result)
            )
            status, output, error = join_result
            if join_first:
                require(status == 0, f"admission failed before removal: {error.strip()}")
                cid = exact_id(output.strip())
                self.expect_result(remove_result, "not_empty")
                self.preserve(pod, infra)
                member = self.container(cid)
                require(
                    member[0] == pod and member[1] in ("configured", "created"),
                    "joined member disappeared or changed",
                )
                require(
                    self.inventory("container") == {infra, cid},
                    "unexpected joining process effects",
                )
                self.cleanup_pod(pod)
                outcome = "join first, member preserved"
            else:
                self.expect_result(remove_result, "removed")
                # The pinned stock binary reports this SQLite admission failure
                # after the waiting create command resumes against a removed Pod.
                require(
                    status == 125
                    and output == ""
                    and error == f"Error: no pod with ID {pod} found in database: no such pod\n",
                    f"expected Pod disappearance; got status={status} stdout={output!r} "
                    f"stderr={error!r}",
                )
                pods = self.inventory("pod")
                containers = self.inventory("container")
                require(
                    not pods and not containers,
                    f"failed join left Pod IDs {sorted(pods)} or container IDs {sorted(containers)}",
                )
                outcome = "remove first, no member admitted"
        print(f"PASS observed competing waiters on Pod file lock ({outcome})", flush=True)

    def ordered_race(self, fd, info, winner, parked):
        observed = self.await_both_waiters(info, winner, parked)
        parked_pids = {parked.pid} | {pid for pid, group in observed.items() if group == parked.pid}
        os.killpg(parked.pid, signal.SIGSTOP)
        try:
            deadline = time.monotonic() + TIMEOUT
            while time.monotonic() < deadline:
                queued = set(waiter_groups(info).values())
                if (
                    winner.pid in queued
                    and parked.pid not in queued
                    and all(process_stopped(pid) for pid in parked_pids)
                ):
                    break
                time.sleep(WAIT_INTERVAL)
            else:
                raise ProbeError("did not observe the stopped contender leave the Pod lock queue")
            fcntl.lockf(fd, fcntl.LOCK_UN)
            winner_result = self.result(winner)
            require(
                all(process_stopped(pid) for pid in parked_pids),
                "parked contender resumed before the first contender finished",
            )
        finally:
            with suppress(ProcessLookupError):
                os.killpg(parked.pid, signal.SIGCONT)
        return winner_result, self.result(parked)

    @staticmethod
    def await_both_waiters(info, *processes):
        target = {process.pid for process in processes}
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            observed = waiter_groups(info)
            if target <= set(observed.values()):
                return observed
            require(
                all(process.poll() is None for process in processes),
                "a contender exited before both Pod lock waits were observed",
            )
            time.sleep(WAIT_INTERVAL)
        raise ProbeError("did not observe both contenders blocked on the same Pod lock inode")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--busybox", type=Path, default=Path("/usr/bin/busybox"))
    options = parser.parse_args()
    try:
        username = fixture_user(options.uid, options.gid)
        verify_runtime_package()
        fd = verify_bundle(options.bundle, options.manifest_sha256, PROFILE)
        with ExitStack() as stack:
            stack.callback(os.close, fd)
            name = stack.enter_context(
                tempfile.TemporaryDirectory(prefix="steward-custody-", dir="/tmp")
            )
            fixture = Fixture(Path(name), options.uid, options.gid, username, fd)
            stack.callback(fixture.cleanup)
            fixture.expect(fixture.custody("protocol"), PROTOCOL)
            fixture.initialize(options.busybox)
            fixture.identity_cases()
            for state in ("created", "stopped", "running"):
                fixture.member_case(state)
            fixture.race(join_first=True)
            fixture.race(join_first=False)
    except (OSError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Custody probe incomplete: {exc}", file=sys.stderr)
        return 1
    print(f"PASS verified custody candidate on {PROFILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
