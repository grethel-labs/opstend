"""R03: rootless-podman command construction and host checks against a fake host."""

from __future__ import annotations

import json
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from builder_testkit import policy
from steward.core import builder as bd
from steward.core import builder_podman as bp
from steward.core import builder_scope as bs
from steward.core import repositories as repos
from steward.core import repository_source_handoff as handoff

SOURCES = ("pypi.org", "registry.example.org")
RULESET = "table inet steward_build { ... }"
IMAGE_ID = "sha256:" + "c" * 64
MANIFEST = "sha256:" + "d" * 64
UID = 1500
GID = 1501
RUNTIME = Path(f"/run/user/{UID}")
BUS = f"unix:path={RUNTIME}/bus"
STAGES = ("probe", "build", "push")


def scope(job, stage):
    return f"steward-build-{job}-{stage}.scope"


def cgroup(job, stage):
    return f"/user.slice/user-{UID}.slice/user@{UID}.service/app.slice/{scope(job, stage)}"


def option(argv, name):
    for i, arg in enumerate(argv):
        if arg == name:
            return argv[i + 1]
        if arg.startswith(name + "="):
            return arg.split("=", 1)[1]
    raise AssertionError(f"missing {name} in {argv}")


def stage_commands(host):
    return [argv for argv in host.calls if argv[0] == bp.SYSTEMD_RUN]


def assert_cleanup(host, job):
    expected = {scope(job, stage) for stage in (*STAGES, "clean")}
    commands = [c for c in host.calls if c[0] == bp.SYSTEMCTL]
    assert all(c[:3] == [bp.SYSTEMCTL, "--user", "stop"] for c in commands)
    units = [unit for cmd in commands for unit in cmd[3:]]
    assert set(units) == expected
    assert len(units) == len(set(units))
    for cmd in commands:
        env = host.envs[host.calls.index(cmd)]
        assert env["XDG_RUNTIME_DIR"] == str(RUNTIME)
        assert env["DBUS_SESSION_BUS_ADDRESS"] == BUS


class FakeHost:
    """Answers probes and 'runs' podman by writing the files the real one would."""

    def __init__(self, **over):
        self.over = over
        self.calls: list[list[str]] = []
        self.envs: list[dict] = []

    def run(self, argv, *, env, cwd, spool, timeout_s, log_bytes, **kw):
        self.calls.append(argv)
        self.envs.append(env)
        tool = argv[0]
        if tool == "/usr/bin/test":
            return bd.RunResult(0 if argv[-1] in self.over.get("reachable", ()) else 1, b"")
        if tool == bp.SYSTEMCTL:
            assert "show" not in argv
            return bd.RunResult(0, b"")
        assert tool == bp.SYSTEMD_RUN
        podman = argv[argv.index(bp.PODMAN) :]
        return self._podman(podman, cwd, **kw)

    def _podman(self, argv, cwd, **kw):
        if "unshare" in argv:
            for path in argv[argv.index("--one-file-system") + 2 :]:
                shutil.rmtree(path)
            return bd.RunResult(0, b"")
        if self.over.get("poll") and not kw["on_poll"]():
            return bd.RunResult(None, b"killed", "lost_lease")
        if "info" in argv:
            if self.over.get("probe_rc"):
                return bd.RunResult(self.over["probe_rc"], b"scope refused")
            info = {
                "host": {"security": {"rootless": self.over.get("rootless", True)}},
                "version": {"Version": "4.9.3"},
            }
            return bd.RunResult(0, json.dumps(info).encode())
        stage = "build" if "build" in argv else "push"
        if stage == self.over.get("fail_stage", "build") and self.over.get("reason"):
            return bd.RunResult(None, b"killed", self.over["reason"])
        if "build" in argv:
            if self.over.get("build_rc"):
                return bd.RunResult(self.over["build_rc"], b"error: RUN failed")
            if self.over.get("storage"):
                (cwd / "graph" / "subordinate").mkdir(mode=0o700)
            (cwd / "iid").write_text(IMAGE_ID.removeprefix("sha256:"))
        if "push" in argv:
            if self.over.get("push_rc"):
                return bd.RunResult(self.over["push_rc"], b"error: push failed")
            (cwd / "digest").write_text(self.over.get("digest", MANIFEST))
        return bd.RunResult(0, b"ok")


@pytest.fixture(autouse=True)
def identity(monkeypatch, tmp_path):
    fake_cgroup = tmp_path / "cgroup"
    fake_cgroup.mkdir()
    (fake_cgroup / "cgroup.controllers").write_text("cpu memory pids\n")
    monkeypatch.setattr(bp, "CGROUP", fake_cgroup)

    def temporary_directory(*, prefix, dir=None):
        scratch = tmp_path if dir is None or dir == "/var/tmp" else dir
        return tempfile.TemporaryDirectory(prefix=prefix, dir=scratch)

    monkeypatch.setattr(
        bp,
        "tempfile",
        SimpleNamespace(TemporaryDirectory=temporary_directory, mkdtemp=tempfile.mkdtemp),
    )
    state = SimpleNamespace(
        passwd=SimpleNamespace(pw_uid=UID, pw_gid=GID),
        uids=(UID, UID, UID),
        gids=(GID, GID, GID),
        files={
            RUNTIME: SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=UID),
            RUNTIME / "systemd": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=UID),
            RUNTIME / "systemd/private": SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=UID),
            RUNTIME / "bus": SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=UID),
        },
        lookups=[],
    )

    def getpwnam(user):
        state.lookups.append(user)
        if state.passwd is None:
            raise KeyError(user)
        return state.passwd

    def fake_stat(original):
        def inspect(path, *args, **kwargs):
            if path == RUNTIME or RUNTIME in path.parents:
                if path not in state.files:
                    raise FileNotFoundError(str(path))
                return state.files[path]
            return original(path, *args, **kwargs)

        return inspect

    monkeypatch.setattr(bp.pwd, "getpwnam", getpwnam)
    monkeypatch.setattr(bp.os, "getresuid", lambda: state.uids)
    monkeypatch.setattr(bp.os, "getresgid", lambda: state.gids)
    monkeypatch.setattr(Path, "stat", fake_stat(Path.stat))
    lstat = fake_stat(Path.lstat)

    def fake_lstat(path):
        info = lstat(path)
        if path.name in ("graph", "run", "tmp") and bd.JOB_ID.fullmatch(path.parent.name):
            return SimpleNamespace(st_mode=info.st_mode, st_uid=UID)
        return info

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    return state


@pytest.fixture
def build_root(tmp_path):
    path = tmp_path / "build"
    path.mkdir(mode=0o700)
    return path


@pytest.fixture
def request_(tmp_path, monkeypatch):
    def export(request, dest, limits, policy, *, on_poll=None):
        dest.mkdir()
        return {"files": 1, "bytes": 0}

    monkeypatch.setattr(bd, "export_source", export)
    record = bd.SourceRecord(
        repository="shop", application="shop", service="backend",
        url="https://example.invalid/shop.git", ref="refs/heads/main",
        requested_revision=None, commit="1" * 40, tree="2" * 40,
        source_digest="sha256:" + "3" * 64, store="shop.git",
        fetched_at="2026-11-26T00:00:00Z",
    )  # fmt: skip
    return bd.BuildRequest(
        record, {"build": {"file": "Dockerfile", "context": "."}},
        "sha256:" + "4" * 64, {}, "sha256:" + "5" * 64, tmp_path,
    )  # fmt: skip


def attest(tmp_path, uid=1500, sources=SOURCES, ruleset=RULESET):
    path = tmp_path / "egress.json"
    path.write_text(json.dumps(bp.egress_attestation(sources, uid, ruleset)))
    return path


def make(tmp_path, build_root, host, *, sources=SOURCES, **kw):
    backend = bp.RootlessPodmanBackend(
        user="steward-build", registry="127.0.0.1:5000", launcher=host,
        egress_attestation_path=kw.pop("attestation", None) or attest(tmp_path),
        nft_listing=kw.pop("ruleset", RULESET), **kw,
    )  # fmt: skip
    pol = policy(allow_container_isolation=True, package_sources=list(sources))
    return backend, bd.BuildRunner(build_root, pol, [backend])


def test_successful_build_records_digest_level_and_toolchain(tmp_path, build_root, request_):
    host = FakeHost()
    _, run = make(tmp_path, build_root, host)
    record = run.run(request_, job_id="a" * 32)
    assert record["status"] == "succeeded"
    assert record["output"] == {
        "digest": MANIFEST,
        "ref": f"127.0.0.1:5000/steward-build/shop-backend@{MANIFEST}",
    }
    assert record["isolation"]["label"] == "container isolation, no VM protection"
    assert record["toolchain"]["podman"] == "4.9.3"
    assert record["egress"]["enforcement"] == "host-firewall-attested"
    assert record["egress"]["package_sources"] == list(SOURCES)
    assert_cleanup(host, "a" * 32)
    assert list((build_root / "work").iterdir()) == []


def test_sealed_handoff_entry_runs_scoped_backend_and_retires_workspace(
    tmp_path,
    build_root,
    request_,
    monkeypatch,
):
    host = FakeHost()
    _, runner = make(tmp_path, build_root, host)
    job = "a" * 32
    work = build_root / "work" / job
    authority = object()

    @contextmanager
    def open_handoff(expected, workspace, *, input_digest):
        assert (expected, workspace, input_digest) == (authority, work, request_.input_digest)
        yield request_

    monkeypatch.setattr(handoff, "_open_handoff", open_handoff)
    record = runner.run_handoff(
        authority, job_id=job, input_digest=request_.input_digest, on_poll=lambda: True,
    )  # fmt: skip

    assert record["status"] == "succeeded" and record["authorizes"] == []
    assert [option(cmd, "--unit") for cmd in stage_commands(host)] == [
        scope(job, stage) for stage in STAGES
    ]
    assert_cleanup(host, job)
    assert not work.exists()


def test_build_command_has_no_secrets_sockets_volumes_or_privileges(
    tmp_path, build_root, request_, monkeypatch
):
    host = FakeHost()
    job = "b" * 32
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/wrong/bus")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/wrong/runtime")
    monkeypatch.setenv("PODMAN_TOKEN", "not-for-the-builder")
    make(tmp_path, build_root, host)[1].run(request_, job_id=job)
    stages = stage_commands(host)
    assert [option(cmd, "--unit") for cmd in stages] == [scope(job, stage) for stage in STAGES]
    work = build_root / "work" / job
    for stage, cmd in zip(STAGES, stages, strict=True):
        cut = cmd.index("--")
        unit, helper = cmd[:cut], cmd[cut + 1 :]
        assert {"--scope", "--user"} <= set(unit)
        assert option(unit, "--slice") == "app.slice"
        props = {unit[i + 1] for i, arg in enumerate(unit) if arg == "-p"}
        assert {"MemoryMax=2048M", "MemorySwapMax=0", "CPUQuota=200%", "TasksMax=512"} <= props
        assert "Delegate=cpu memory pids" in props
        assert helper[:2] == [sys.executable, "-I"]
        assert Path(helper[2]) == Path(bs.__file__).resolve()
        divider = helper.index("--")
        assert helper[3:divider] == [str(UID), cgroup(job, stage), str(2048 * 2**20), "200", "512"]
        podman = helper[divider + 1 :]
        assert podman[0] == bp.PODMAN
        assert option(podman, "--cgroup-manager") == "cgroupfs"
        assert option(podman, "--root") == str(work / "graph")
        assert option(podman, "--runroot") == str(work / "run")
        assert option(podman, "--tmpdir") == str(work / "tmp")
        env = host.envs[host.calls.index(cmd)]
        assert env == {
            "PATH": bp.SAFE_PATH,
            "HOME": str(work / "home"),
            "TMPDIR": str(work / "tmp"),
            "XDG_RUNTIME_DIR": str(RUNTIME),
            "DBUS_SESSION_BUS_ADDRESS": BUS,
            "LANG": "C.UTF-8",
        }
    assert "info" in stages[0]
    wrapped = stages[1]
    argv = wrapped[wrapped.index(bp.PODMAN) :]
    assert option(argv, "--cgroup-parent") == cgroup(job, "build")
    joined = " ".join(wrapped)
    for forbidden in (
        "--volume", "-v ", "--privileged", "--secret", "--ssh", "--build-arg", "--device",
        "--network host", "--network=host", "--userns=host", "docker.sock", "podman.sock",
        "--cap-add", "CONTAINER_HOST", "DOCKER_HOST",
    ):  # fmt: skip
        assert forbidden not in joined
    assert argv[argv.index("--network") + 1] == bp.BUILD_NETWORK
    assert argv[argv.index("--cap-drop") + 1] == "all"
    assert "no-new-privileges" in argv
    assert argv[argv.index("--memory") + 1] == "2048m"
    assert "--memory-swap" not in argv
    assert argv[argv.index("--cpu-quota") + 1] == "200000"
    assert "nproc=512:512" in argv
    assert argv[-1].endswith("/src") and "/work/" + "b" * 32 in argv[-1]


def test_push_goes_only_to_the_configured_loopback_registry(tmp_path, build_root, request_):
    host = FakeHost()
    make(tmp_path, build_root, host)[1].run(request_, job_id="b" * 32)
    push = next(c for c in host.calls if "push" in c)
    assert "--tls-verify=false" in push
    assert push[-1].startswith("docker://127.0.0.1:5000/steward-build/shop-backend:in-")
    for bad in ("root", "Bad User", "a;b", ""):
        with pytest.raises(ValueError):
            bp.RootlessPodmanBackend(user=bad, registry="127.0.0.1:5000")
    with pytest.raises(ValueError):
        bp.RootlessPodmanBackend(user="builder", registry="not a registry")


def test_target_is_passed_and_context_is_inside_the_tree(tmp_path, request_):
    request = request_
    request.contract["build"].update(target="runtime")
    backend = bp.RootlessPodmanBackend(user="b-user", registry="127.0.0.1:5000")
    job = bd.BuildJob("e" * 32, request, tmp_path / "src", tmp_path, bd.BuildLimits(), SOURCES)
    argv = backend.build_argv(job)
    assert argv[argv.index("--target") + 1] == "runtime"
    assert argv[-1] == str(tmp_path / "src")


@pytest.mark.parametrize(
    "over, expect",
    [
        ({"rootless": False}, "podman_not_rootless"),
        ({"reachable": ("/run/podman/podman.sock",)}, "production_paths_reachable"),
        ({"reachable": ("/var/lib/steward",)}, "production_paths_reachable"),
        ({"probe_rc": 125}, "limits_not_delegated"),
    ],
)
def test_unready_host_fails_closed_before_any_build(tmp_path, build_root, request_, over, expect):
    host = FakeHost(**over)
    record = make(tmp_path, build_root, host)[1].run(request_)
    assert (record["status"], record["code"]) == ("failed", "host_not_ready")
    assert expect in record["log"]
    assert not any("build" in c for c in host.calls if c[0] == bp.SYSTEMD_RUN)
    assert record["egress"]["enforcement"] in ("host-firewall-attested", "none")


@pytest.mark.parametrize("case", ["no_file", "other_sources", "other_uid", "changed_ruleset"])
def test_egress_must_be_attested_for_these_sources_and_this_ruleset(
    tmp_path, build_root, request_, case
):
    kw = {}
    if case == "no_file":
        kw["attestation"] = tmp_path / "missing.json"
    if case == "other_sources":
        kw["attestation"] = attest(tmp_path, sources=("evil.example.org",))
    if case == "other_uid":
        kw["attestation"] = attest(tmp_path, uid=1501)
    if case == "changed_ruleset":
        kw["ruleset"] = RULESET + " accept"
    record = make(tmp_path, build_root, FakeHost(), **kw)[1].run(request_)
    assert record["code"] == "host_not_ready" and "egress_not_enforced" in record["log"]
    assert record["egress"]["enforcement"] == "none"


def test_standalone_host_facts_probe_uses_disposable_scoped_storage(tmp_path, build_root):
    host = FakeHost()
    backend, _ = make(tmp_path, build_root, host)
    facts = backend.host_facts(build_root, SOURCES)
    assert facts.failures() == []
    (probe,) = stage_commands(host)
    unit = option(probe, "--unit")
    job = unit.removeprefix("steward-build-").split("-", 1)[0]
    assert len(job) == 32 and unit == scope(job, "probe")
    assert "--scope" in probe
    assert cgroup(job, "probe") in probe
    podman = probe[probe.index(bp.PODMAN) :]
    storage = Path(option(podman, "--root")).parent
    assert storage.parent == build_root
    assert option(podman, "--runroot") == str(storage / "run")
    assert option(podman, "--tmpdir") == str(storage / "tmp")
    assert not storage.exists()
    assert [c for c in host.calls if c[0] == bp.SYSTEMCTL] == [
        [bp.SYSTEMCTL, "--user", "stop", unit]
    ]


def test_no_package_sources_means_no_build(tmp_path, build_root, request_):
    record = make(tmp_path, build_root, FakeHost(), sources=())[1].run(request_)
    assert record["code"] == "host_not_ready"


@pytest.mark.parametrize(
    "over, status, code",
    [
        ({"reason": "timeout"}, "timeout", "build_timeout"),
        ({"reason": "log_limit"}, "limit_exceeded", "log_limit"),
        ({"reason": "disk_limit"}, "limit_exceeded", "disk_limit"),
        ({"reason": "lost_lease"}, "failed", "lost_lease"),
        ({"build_rc": 137}, "limit_exceeded", "build_killed"),
        ({"build_rc": 1}, "failed", "build_failed"),
        ({"build_rc": 125}, "failed", "build_failed"),
        ({"digest": "latest"}, "failed", "bad_output_digest"),
        ({"push_rc": bs.REFUSED}, "failed", "scope_admission_failed"),
        ({"reason": "timeout", "fail_stage": "push"}, "timeout", "push_timeout"),
    ],
)
def test_failures_and_limits_are_classified_and_always_cleaned(
    tmp_path, build_root, request_, over, status, code
):
    host = FakeHost(**over)
    record = make(tmp_path, build_root, host)[1].run(request_, job_id="a" * 32)
    assert (record["status"], record["code"]) == (status, code)
    assert record["output"]["digest"] is None and record["cleanup"] == "ok"
    assert_cleanup(host, "a" * 32)
    assert list((build_root / "work").iterdir()) == []


@pytest.mark.parametrize(
    "case",
    [
        "unknown",
        "root",
        "uid",
        "saved_uid",
        "gid",
        "saved_gid",
        "expected_uid",
        "directory_mode",
        "directory_owner",
        "missing_bus",
        "bus_owner",
        "private_type",
        "private_symlink",
    ],
)
def test_invalid_identity_or_runtime_is_refused_before_launch(
    tmp_path, build_root, request_, identity, case
):
    kwargs = {}
    if case == "unknown":
        identity.passwd = None
    elif case == "root":
        identity.passwd.pw_uid = 0
        identity.uids = (0, 0, 0)
    elif case == "uid":
        identity.uids = (UID + 1,) * 3
    elif case == "saved_uid":
        identity.uids = (UID, UID, 0)
    elif case == "gid":
        identity.gids = (GID + 1,) * 3
    elif case == "saved_gid":
        identity.gids = (GID, GID, 0)
    elif case == "expected_uid":
        kwargs["uid"] = UID + 1
    elif case == "directory_mode":
        identity.files[RUNTIME].st_mode = stat.S_IFDIR | 0o750
    elif case == "directory_owner":
        identity.files[RUNTIME].st_uid = 0
    elif case == "missing_bus":
        del identity.files[RUNTIME / "bus"]
    elif case == "bus_owner":
        identity.files[RUNTIME / "bus"].st_uid = 0
    elif case == "private_type":
        identity.files[RUNTIME / "systemd/private"].st_mode = stat.S_IFREG | 0o600
    elif case == "private_symlink":
        identity.files[RUNTIME / "systemd/private"].st_mode = stat.S_IFLNK | 0o777
    host = FakeHost()
    _, runner = make(tmp_path, build_root, host, **kwargs)
    record = runner.run(request_, job_id="a" * 32)
    assert (record["status"], record["code"]) == ("failed", "host_not_ready")
    assert not host.calls
    assert record["cleanup"] == "ok"
    assert not (build_root / "work" / ("a" * 32)).exists()


def test_duplicate_job_does_not_touch_existing_workspace(tmp_path, build_root, request_):
    host = FakeHost()
    _, runner = make(tmp_path, build_root, host)
    job = "a" * 32
    work = build_root / "work" / job
    work.mkdir()
    runner._mark_workdir(work, job)

    with pytest.raises(bd.BuildError, match="job_workspace_exists"):
        runner.run(request_, job_id=job)

    assert (work / bd.MARKER).is_file()
    assert host.calls == []
    assert runner.load_records(request_.input_digest) == []


def test_reconcile_checks_identity_and_stops_only_orphan_scopes(
    tmp_path, build_root, identity, monkeypatch
):
    job = "f" * 32
    active = "f" * 16 + "1" * 16
    host = FakeHost()
    _, runner = make(tmp_path, build_root, host)
    for name in (job, active):
        work = build_root / "work" / name
        work.mkdir()
        runner._mark_workdir(work, name)
        (work / bp.SCOPE_MARKER).touch()
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/wrong/bus")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/wrong/runtime")
    assert runner.reconcile(active={active}) == [job]
    assert identity.lookups == ["steward-build"]
    assert_cleanup(host, job)
    assert (build_root / "work" / active).is_dir()


@pytest.mark.parametrize("root_slice", [True, False])
def test_legacy_populated_service_preserves_workspace_without_stopping_prefix(
    tmp_path, build_root, root_slice
):
    job = "b" * 32
    host = FakeHost()
    backend, runner = make(tmp_path, build_root, host)
    work = build_root / "work" / job
    work.mkdir()
    (work / bd.MARKER).write_text(f"steward-build v1 {job}\n")
    old = bp.CGROUP / backend._scope(UID, f"steward-build-{job[:16]}.service").lstrip("/")
    if root_slice:
        old = old.parent.parent / old.name
    old.mkdir(parents=True)
    events = old / "cgroup.events"
    events.write_text("populated 1\n")

    assert runner.reconcile() == []
    assert work.is_dir() and host.calls == []
    events.write_text("populated 0\n")
    assert runner.reconcile() == [job]
    assert not work.exists()
    assert_cleanup(host, job)


def test_storage_is_removed_using_bounded_job_namespace(tmp_path, build_root, request_):
    host = FakeHost(storage=True)
    _, runner = make(tmp_path, build_root, host)
    job = "a" * 32
    graph = build_root / "work" / job / "graph"
    record = runner.run(request_, job_id=job)
    assert record["status"] == "succeeded" and record["cleanup"] == "ok"
    clean = stage_commands(host)[-1]
    assert option(clean, "--unit") == scope(job, "clean")
    assert clean[-7:] == [
        "unshare", "--", "/usr/bin/rm", "-rf", "--one-file-system", "--", str(graph),
    ]  # fmt: skip
    assert host.calls[-1] == [bp.SYSTEMCTL, "--user", "stop", scope(job, "clean")]
    assert not graph.parent.exists()


def test_populated_scope_prevents_success_and_remains_for_reconciliation(
    tmp_path, build_root, request_
):
    host = FakeHost()
    job = "d" * 32
    _, runner = make(tmp_path, build_root, host)
    directory = bp.CGROUP / cgroup(job, "build").lstrip("/")
    directory.mkdir(parents=True)
    events = directory / "cgroup.events"
    events.write_text("populated 1\n")

    record = runner.run(request_, job_id=job)
    assert (record["status"], record["code"]) == ("failed", "cleanup_failed")
    assert record["output"]["digest"] is None
    assert record["cleanup"] == "backend_failed"
    assert (build_root / "work" / job / bd.MARKER).is_file()
    assert_cleanup(host, job)

    assert runner.reconcile() == []
    events.write_text("populated 0\n")
    assert runner.reconcile() == [job]
    assert not (build_root / "work" / job).exists()


@pytest.mark.parametrize("failed_stage", ["probe", "build", "push"])
def test_scoped_stages_pass_lease_poll_to_launcher(tmp_path, build_root, request_, failed_stage):
    host = FakeHost(poll=True)
    _, runner = make(tmp_path, build_root, host)
    job = "c" * 32
    failed_unit = scope(job, failed_stage)

    def lease_valid():
        return not any(option(cmd, "--unit") == failed_unit for cmd in stage_commands(host))

    record = runner.run(request_, job_id=job, on_poll=lease_valid)
    assert (record["status"], record["code"]) == ("failed", "lost_lease")
    assert [option(c, "--unit") for c in stage_commands(host)] == [
        scope(job, stage) for stage in STAGES[: STAGES.index(failed_stage) + 1]
    ]
    assert_cleanup(host, job)


def test_export_stops_waiting_git_when_lease_expires(tmp_path, monkeypatch):
    proc = SimpleNamespace(pid=1234, returncode=None)
    calls = []

    def wait(timeout=None):
        if timeout is not None:
            raise subprocess.TimeoutExpired("git", timeout)
        calls.append("reaped")

    proc.wait = wait
    proc.poll = lambda: None
    monkeypatch.setattr(repos.subprocess, "Popen", lambda *args, **kwargs: proc)
    monkeypatch.setattr(repos.os, "killpg", lambda pid, sig: calls.append((pid, sig)))

    with pytest.raises(repos.FetchError, match="lost_lease"):
        repos.run_git(
            repos.FetchPolicy(), ["ls-tree"], label="ls-tree", env={},
            spool=tmp_path, cwd=tmp_path, timeout_s=20, on_poll=lambda: False,
        )  # fmt: skip

    assert calls == [(proc.pid, repos.signal.SIGKILL), "reaped"]


def test_process_launcher_forwards_only_given_environment(tmp_path, monkeypatch):
    env = {"PATH": "/usr/bin:/bin", "ONLY": "this"}
    monkeypatch.setenv("HOST_ONLY", "omitted")
    calls = []

    def run_bounded(argv, **kwargs):
        calls.append((argv, kwargs))
        return bd.RunResult(0, b"")

    monkeypatch.setattr(bp, "run_bounded", run_bounded)
    bp.ProcessLauncher().run(
        ["/usr/bin/env"], env=env, cwd=tmp_path, spool=tmp_path, timeout_s=5, log_bytes=1000,
    )  # fmt: skip
    assert calls[0][1]["env"] == env
