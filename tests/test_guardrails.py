"""Fast structural checks for controls spanning several test suites."""

from __future__ import annotations

import ast
import runpy
import shlex
from importlib.util import resolve_name
from pathlib import Path
from types import SimpleNamespace

import pytest

from run_guardrails import collect_checks
from steward.executor.host import CMD_TIMEOUT_S, SAFE_ENV, Host

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
EXECUTOR = "steward.executor"


def imported_names(file: Path):
    package = ".".join(file.relative_to(SRC).parts[:-1])
    for node in ast.walk(ast.parse(file.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            yield from ((name.name, node.lineno) for name in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = resolve_name("." * node.level + (node.module or ""), package)
            yield from ((f"{module}.{name.name}", node.lineno) for name in node.names)


def test_executor_clients_import_only_the_protocol():
    base = SRC / "steward"
    clients = [
        *sorted((base / "api").rglob("*.py")),
        *(
            base / path
            for path in (
                "bot.py",
                "controller.py",
                "collector.py",
                "scannerd.py",
                "scanner.py",
                "notifier.py",
                "backupscheduler.py",
                "backupworker.py",
                "inference_worker.py",
                "core/advice.py",
                "core/advice_ipc.py",
                "core/ai_admin_ipc.py",
                "core/builder.py",
                "core/builder_podman.py",
                "core/repository_deploy.py",
            )
        ),
    ]
    violations = []
    for file in clients:
        for name, line in imported_names(file):
            if name != EXECUTOR and not name.startswith(EXECUTOR + "."):
                continue
            if name == EXECUTOR + ".protocol" or name.startswith(EXECUTOR + ".protocol."):
                continue
            if file == base / "collector.py" and name == EXECUTOR + ".server.ACTIONS":
                continue
            violations.append(f"{file.relative_to(ROOT)}:{line} imports {name}")
    assert not violations, "\n".join(violations)


def test_host_status_uses_fixed_argv_without_a_shell(monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="ActiveState=active\n")

    monkeypatch.setattr("steward.executor.host.subprocess.run", run)
    assert Host().system_unit("steward-controller.service")["active"] == "active"
    [(argv, options)] = calls
    assert argv == [
        "systemctl",
        "show",
        "steward-controller.service",
        "-p",
        "LoadState,ActiveState,SubState",
    ]
    assert not options.get("shell")
    assert options["env"] == SAFE_ENV
    assert options["timeout"] == CMD_TIMEOUT_S


def test_ssh_transport_rejects_invalid_identity_before_delegating(monkeypatch):
    ansible_errors = pytest.importorskip("ansible.errors")
    plugin = ROOT / "ansible/connection_plugins/steward_guarded_ssh.py"
    connection_class = runpy.run_path(str(plugin))["Connection"]
    values = {
        "steward_deployment_operation": "a" * 32,
        "steward_deployment_run": "b" * 32 + "\n",
        "steward_deployment_boot": "12345678-1234-1234-1234-123456789abc",
    }
    monkeypatch.setattr(connection_class, "get_option", lambda _self, key: values[key])

    calls = []

    def delegate(_self, command, **_kwargs):
        calls.append(shlex.split(command))
        return 0, b"", b""

    monkeypatch.setattr(connection_class.__base__, "exec_command", delegate)
    connection = connection_class.__new__(connection_class)
    with pytest.raises(
        ansible_errors.AnsibleConnectionFailure, match="invalid ansible_steward_deployment_run"
    ):
        connection.exec_command("true")

    assert calls == []
    values["steward_deployment_run"] = "b" * 32
    assert connection.exec_command("true") == (0, b"", b"")
    assert calls == [
        [
            "/usr/bin/python3",
            "-I",
            "/usr/local/libexec/steward/deployment-v1/launch.py",
            "--operation-id",
            values["steward_deployment_operation"],
            "--run-id",
            values["steward_deployment_run"],
            "--boot-id",
            values["steward_deployment_boot"],
            "--",
            "true",
        ]
    ]


@pytest.mark.parametrize(
    "invalid",
    [
        "",
        "### G01 Missing test\nNo test IDs",
        "### G01 Valid\n- `tests/test_guardrails.py::test_example`\n### G02 Unchecked",
    ],
)
def test_guardrail_manifest_rejects_rules_without_checks(invalid):
    with pytest.raises(ValueError):
        collect_checks(invalid)
