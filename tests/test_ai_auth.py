"""A04: guided login lifecycle with a fake official program (no provider, no network)."""

import json
import os
import stat
import sys
from argparse import Namespace
from unittest.mock import Mock

import pytest

from steward import aihost
from steward.cli import ai_login
from steward.cli import main as cli
from steward.controller import Finding, evaluate
from steward.core.ai_auth import (
    AUTH_METHODS,
    AuthError,
    AuthManager,
    AuthStore,
    Evidence,
    MethodSpec,
    ProcessRunner,
    auth_finding,
)

SECRET = "tok-SECRET-VALUE-123456"  # noqa: S105


class FakeRunner:
    """Stands for the official program; records argv/env/cwd and simulates native state."""

    def __init__(self, store, script=None):
        self.store, self.calls, self.script = store, [], list(script or [])

    def run(self, argv, *, env, cwd, uid):
        self.calls.append((argv, env, cwd, uid))
        kind = argv[1]
        if kind == "login":
            code = self.script.pop(0) if self.script else 0
            if code == 0:
                (self.store.native_dir / "credential").write_text(SECRET)
            return code
        if kind == "check":
            return 0 if (self.store.native_dir / "credential").exists() else 1
        if kind == "logout":
            return 0
        return 9


def spec():
    return MethodSpec(
        "fake-login",
        ("prog", "login"),
        ("prog", "check"),
        ("prog", "logout"),
        {0: "active", 1: "expired", 2: "revoked"},
        Evidence("https://example.invalid/docs", "2026-11-22", "synthetic"),
    )


@pytest.fixture
def env(tmp_path):
    store = AuthStore(tmp_path / "ai", os.geteuid())
    runner = FakeRunner(store)
    now = [1000.0]
    manager = AuthManager(store, runner, methods={"fake-login": spec()}, clock=lambda: now[0])
    return store, runner, manager, now


def test_default_methods_have_no_activation_evidence_or_dispatch():
    assert set(AUTH_METHODS) == {"ollama-cloud", "claude-subscription", "chatgpt-subscription"}
    for method in AUTH_METHODS.values():
        assert method.evidence is None and not method.available
        assert method.login_argv == () and method.check_argv == ()
        assert method.logout_argv is None and method.check_codes == {}


@pytest.mark.parametrize("action", ["login", "check", "revoke"])
def test_default_methods_refuse_before_state_or_runner_access(action):
    store = Mock(spec=AuthStore)
    runner = Mock(spec=FakeRunner)
    clock = Mock(return_value=1.0)
    manager = AuthManager(store, runner, clock=clock)
    operation = getattr(manager, action)
    for method in AUTH_METHODS:
        with pytest.raises(AuthError, match="method_unavailable"):
            operation(method)
    with pytest.raises(AuthError, match="unknown_method"):
        operation("nope")
    assert store.mock_calls == []
    assert runner.mock_calls == []
    clock.assert_not_called()


@pytest.mark.parametrize(
    ("method", "reason"),
    [
        ("ollama-cloud", "dedicated cloud-enabled daemon outside the local CPU namespace"),
        ("claude-subscription", "unattended third-party subscription inference is unconfirmed"),
        ("chatgpt-subscription", "ChatGPT plan eligibility for OpsTend's unattended service"),
    ],
)
def test_default_methods_report_distinct_operator_refusal_reasons(method, reason, capsys):
    manager = AuthManager(Mock(spec=AuthStore), Mock(spec=FakeRunner), clock=lambda: 1.0)
    assert aihost.run("login", method, euid=0, manager=manager) == 2
    err = capsys.readouterr().err
    assert "method_unavailable" in err and reason in err
    assert "authorized login" in err


def test_login_pending_then_active_and_status_has_no_secret(env):
    store, runner, manager, now = env
    assert store.read()["state"] == "pending"
    doc = manager.login("fake-login")
    assert doc["state"] == "active" and doc["reason"] == "login_verified"
    argv, environment, cwd, _ = runner.calls[0]
    assert argv == ("prog", "login") and SECRET not in " ".join(argv)
    assert environment["HOME"] == str(store.native_dir) and "STEWARD" not in " ".join(environment)
    assert cwd == store.native_dir
    assert SECRET not in store.status_path.read_text()
    assert stat.S_IMODE(store.native_dir.stat().st_mode) == 0o700
    with pytest.raises(AuthError, match="already_active"):
        manager.login("fake-login")


def test_failed_login_never_marks_active(env):
    store, runner, manager, _ = env
    runner.script = [3]
    doc = manager.login("fake-login")
    assert doc["state"] == "pending" and doc["reason"] == "login_failed"


def test_relogin_rotates_credential_and_keeps_active(env):
    store, runner, manager, now = env
    manager.login("fake-login")
    now[0] = 2000.0
    doc = manager.login("fake-login", relogin=True)
    assert doc["state"] == "active" and doc["since"] == 2000.0


def test_expiry_from_check_and_from_provider_auth_error(env):
    store, runner, manager, now = env
    manager.login("fake-login")
    assert manager.observe_provider_error("fake-login", "quota") is None
    assert store.read()["state"] == "active"
    doc = manager.observe_provider_error("fake-login", "auth")
    assert doc["state"] == "expired" and doc["reason"] == "provider_rejected_credential"
    (store.native_dir / "credential").unlink()
    assert manager.check("fake-login")["state"] == "expired"
    assert manager.login("fake-login", relogin=True)["state"] == "active"


def test_clean_revocation_removes_native_state_and_reports_revoked(env):
    store, runner, manager, _ = env
    manager.login("fake-login")
    (store.native_dir / "sub").mkdir()
    (store.native_dir / "sub" / "x").write_text(SECRET)
    doc = manager.revoke("fake-login")
    assert doc["state"] == "revoked" and list(store.native_dir.iterdir()) == []
    assert ("prog", "logout") in [c[0] for c in runner.calls]
    assert auth_finding(store.read())["id"] == "ai_login_revoked"


def test_wrong_uid_and_unsafe_directories_are_refused(tmp_path):
    base = tmp_path / "ai"
    (base / "auth").mkdir(parents=True, mode=0o700)
    foreign = AuthStore(base, os.geteuid() + 12345)
    with pytest.raises(AuthError, match="wrong_owner"):
        foreign.prepare()
    store = AuthStore(base, os.geteuid())
    os.chmod(base / "auth", 0o750)  # noqa: S103
    with pytest.raises(AuthError, match="state_permissions"):
        store.prepare()
    os.chmod(base / "auth", 0o700)
    (base / "auth").rmdir()
    (tmp_path / "elsewhere").mkdir()
    (base / "auth").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(AuthError, match="state_not_directory"):
        store.prepare()
    with pytest.raises(AuthError):
        store.wipe_native()
    assert (tmp_path / "elsewhere").exists()


def test_corrupt_or_forged_status_reads_as_pending(tmp_path):
    store = AuthStore(tmp_path, os.geteuid())
    store.status_path.write_text(json.dumps({"state": "active", "reason": "x" * 10, "method": "m"}))
    assert store.read()["state"] == "pending"
    store.status_path.write_text("{" * 10)
    assert store.read()["state"] == "pending"


def test_findings_are_non_failing(raw_config):
    assert auth_finding(None) is None and auth_finding({"state": "active"}) is None
    for state in ("pending", "expired", "revoked"):
        finding = auth_finding({"state": state})
        assert finding["severity"] == "info" and "Deterministic" in finding["summary"]
        assert Finding(**finding).remediation is None
    assert callable(evaluate)


def test_real_process_runner_uses_fixed_argv_and_minimal_env(tmp_path, monkeypatch):
    out = tmp_path / "out.txt"
    code = f"import os;open({str(out)!r},'w').write(repr(sorted(os.environ))+os.getcwd())"
    monkeypatch.setenv("STEWARD_LEAK_PROBE", SECRET)
    rc = ProcessRunner().run(
        (sys.executable, "-c", code),
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        cwd=tmp_path,
        uid=os.geteuid(),
    )
    assert rc == 0 and "STEWARD_LEAK_PROBE" not in out.read_text()
    assert ProcessRunner().run(("/nonexistent/x",), env={}, cwd=tmp_path, uid=os.geteuid()) == 127


def test_host_entry_requires_root_and_refuses_unavailable_method(tmp_path, capsys):
    assert aihost.run("login", "claude-subscription", euid=1000, base=tmp_path) == 2
    store = AuthStore(tmp_path, os.geteuid())
    manager = AuthManager(store, FakeRunner(store), clock=lambda: 1.0)
    assert aihost.run("login", "claude-subscription", euid=0, manager=manager) == 2
    err = capsys.readouterr().err
    assert "method_unavailable" in err
    assert aihost.run("status", "", euid=0, manager=manager) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "pending"
    ok = AuthManager(store, FakeRunner(store), methods={"fake-login": spec()}, clock=lambda: 1.0)
    assert aihost.run("login", "fake-login", euid=0, manager=ok) == 0


def test_controller_command_is_a_fixed_ssh_argv(cfg, monkeypatch):
    monkeypatch.setenv("STEWARD_SSH_PRIVATE_KEY_FILE", "/k/id")
    argv = ai_login.ssh_argv(cfg, "login", "claude-subscription", relogin=True)
    assert argv[0] == "ssh" and "-tt" in argv and "StrictHostKeyChecking=yes" in argv
    tail = argv[argv.index("sudo") :]
    assert tail == [
        "sudo",
        "--",
        ai_login.HOST_PROGRAM,
        "ai",
        "login",
        "--method",
        "claude-subscription",
        "--relogin",
    ]
    with pytest.raises(ValueError):
        ai_login.ssh_argv(cfg, "login", "evil; rm")
    with pytest.raises(ValueError):
        ai_login.ssh_argv(cfg, "shell", None)
    parsed = cli.build_parser().parse_args(
        ["ai", "login", "--config", "c.yml", "--limit", "s", "--method", "ollama-cloud"]
    )
    assert parsed.func is cli.cmd_ai


def test_cli_requires_method(cfg, monkeypatch):
    monkeypatch.setattr(cli, "load", lambda args: cfg)
    with pytest.raises(cli.CliError):
        cli.cmd_ai(Namespace(config="c", limit="s", ai_action="login", method=None, relogin=False))
