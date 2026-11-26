from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = {
    "ansible_steward_deployment_operation": "a" * 32,
    "ansible_steward_deployment_run": "b" * 32,
    "ansible_steward_deployment_boot": "12345678-1234-1234-1234-123456789abc",
}
GATE_ARGS = [
    "/usr/bin/python3",
    "-I",
    "/usr/local/libexec/steward/deployment-v1/launch.py",
    "--operation-id",
    IDENTITY["ansible_steward_deployment_operation"],
    "--run-id",
    IDENTITY["ansible_steward_deployment_run"],
    "--boot-id",
    IDENTITY["ansible_steward_deployment_boot"],
    "--",
]
FAKE_SSH = """
import json
import os
import shlex
import sys

args = sys.argv[1:]
with open(os.environ["TEST_STEWARD_SSH_LOG"], "a") as log:
    print(json.dumps(args), file=log)

if "-O" in args:  # reset only issues local multiplex control requests
    sys.exit(0)
gate, original = (words := shlex.split(args[-1]))[:-1], words[-1]
if gate != json.loads(os.environ["TEST_STEWARD_GATE_ARGS"]):
    sys.exit("unexpected deployment gate arguments")
os.execv("/bin/sh", ["/bin/sh", "-c", original])
"""
FAKE_SUDO = """
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["TEST_STEWARD_SUDO_LOG"], "a") as log:
    print(json.dumps(args), file=log)
shell = args.index("/bin/sh")
os.execv(args[shell], args[shell:])
"""


@pytest.fixture
def harness(tmp_path):
    pytest.importorskip("ansible")
    playbook_cli = Path(sys.executable).with_name("ansible-playbook")
    assert playbook_cli.is_file()
    ssh = tmp_path / "ssh"
    sudo = tmp_path / "sudo"
    for script, body in ((ssh, FAKE_SSH), (sudo, FAKE_SUDO)):
        script.write_text(f"#!{sys.executable}\n{body}")
        script.chmod(0o755)
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nretry_files_enabled = False\n")
    ssh_log = tmp_path / "ssh.jsonl"
    sudo_log = tmp_path / "sudo.jsonl"
    settings = {
        **IDENTITY,
        "ansible_connection": "steward_guarded_ssh",
        "ansible_host": "192.0.2.1",
        "ansible_user": "steward-deploy",
        "ansible_ssh_executable": str(ssh),
        "ansible_scp_executable": str(ssh),
        "ansible_sftp_executable": str(ssh),
        "ansible_become_exe": str(sudo),
        "ansible_python_interpreter": sys.executable,
        "ansible_remote_tmp": str(tmp_path / "remote"),
        "ansible_ssh_use_tty": False,
        "ansible_host_key_checking": True,
        "ansible_ssh_args": "-o ControlMaster=auto -o ControlPersist=60s",
        "ansible_ssh_common_args": f"-o ControlPath={tmp_path / 'mux'} -o StrictHostKeyChecking=yes",
    }

    def run(tasks, *, overrides=None, omit=None):
        hostvars = settings | (overrides or {})
        if omit:
            del hostvars[omit]
        inventory = tmp_path / "inventory.json"
        inventory.write_text(json.dumps({"all": {"hosts": {"test": hostvars}}}))
        playbook = tmp_path / "playbook.json"
        playbook.write_text(json.dumps([{"hosts": "all", "gather_facts": False, "tasks": tasks}]))
        env = {name: value for name, value in os.environ.items() if not name.startswith("ANSIBLE_")}
        process = subprocess.run(
            [str(playbook_cli), "-i", str(inventory), str(playbook)],
            cwd=tmp_path,
            env={
                **env,
                "ANSIBLE_CONFIG": str(config),
                "ANSIBLE_CONNECTION_PLUGINS": str(ROOT / "ansible" / "connection_plugins"),
                "TEST_STEWARD_SSH_LOG": str(ssh_log),
                "TEST_STEWARD_SUDO_LOG": str(sudo_log),
                "TEST_STEWARD_GATE_ARGS": json.dumps(GATE_ARGS),
            },
            capture_output=True,
            text=True,
            timeout=90,
        )
        ssh_calls = _read_records(ssh_log)
        sudo_calls = _read_records(sudo_log)
        return process, ssh_calls, sudo_calls

    return run


def _read_records(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


@pytest.mark.parametrize("transfer", ["smart", "sftp", "scp"])
def test_real_ansible_preserves_ssh_and_become_through_gate(harness, tmp_path, transfer):
    source = tmp_path / "payload"
    destination = tmp_path / "destination 'quoted'.bin"
    fetched = tmp_path / "fetched"
    payload = bytes(range(256)) + b"\x00\r\n" + bytes(reversed(range(256)))
    source.write_bytes(payload)
    command = "printf '%s\\n' \"$TEST_PAYLOAD\" && printf '%s\\n' 'stderr text' >&2"
    process, ssh_calls, sudo_calls = harness(
        [
            {"ansible.builtin.meta": "reset_connection"},
            {
                "ansible.builtin.shell": command,
                "environment": {"TEST_PAYLOAD": "quoted 'kept' $HOME"},
                "become": True,
                "become_user": "root",
                "register": "shell_result",
            },
            {
                "ansible.builtin.assert": {
                    "that": [
                        """shell_result.stdout == "quoted 'kept' $HOME" """,
                        "shell_result.stderr == 'stderr text'",
                    ]
                },
            },
            {"ansible.builtin.copy": {"src": str(source), "dest": str(destination)}},
            {
                "ansible.builtin.fetch": {
                    "src": str(destination),
                    "dest": str(fetched),
                    "flat": True,
                }
            },
        ],
        overrides={"ansible_ssh_transfer_method": transfer, "ansible_pipelining": False},
    )
    assert process.returncode == 0, process.stdout + process.stderr
    assert destination.read_bytes() == fetched.read_bytes() == payload
    assert [call[call.index("-O") + 1] for call in ssh_calls if "-O" in call] == ["check", "stop"]
    assert all("ControlMaster=auto" in call and "ControlPersist=60s" in call for call in ssh_calls)
    assert all(f"ControlPath={tmp_path / 'mux'}" in call for call in ssh_calls)
    assert all("StrictHostKeyChecking=yes" in call for call in ssh_calls)
    assert all("StrictHostKeyChecking=no" not in call for call in ssh_calls)
    invocations = [shlex.split(call[-1]) for call in ssh_calls if "-O" not in call]
    assert all(invocation[:-1] == GATE_ARGS for invocation in invocations)
    commands = [invocation[-1] for invocation in invocations]
    assert any("dd of=" in command for command in commands)
    assert any("dd if=" in command for command in commands)
    assert sum("BECOME-SUCCESS-" in command for command in commands) == 1
    assert len(sudo_calls) == 1
    flags, sudo_command = sudo_calls[0][:-1], sudo_calls[0][-1]
    assert flags == ["-H", "-S", "-n", "-u", "root", "/bin/sh", "-c"]
    assert "BECOME-SUCCESS-" in sudo_command
    assert "TEST_PAYLOAD=" in sudo_command


@pytest.mark.parametrize(
    ("option", "invalid"),
    [
        ("operation", None),
        ("operation", "A" * 32),
        ("operation", 12345678901234567890123456789012),
        ("run", "b" * 32 + "\nattack"),
        ("boot", "12345678-1234-1234-1234-123456789abC"),
    ],
)
def test_real_ansible_refuses_invalid_identity_before_ssh(harness, option, invalid):
    variable = f"ansible_steward_deployment_{option}"
    process, ssh_calls, _ = harness(
        [{"ansible.builtin.raw": "true"}],
        omit=variable if invalid is None else None,
        overrides={variable: invalid} if invalid is not None else None,
    )
    assert process.returncode != 0
    assert f"Missing or invalid {variable}" in process.stdout
    assert ssh_calls == []


@pytest.mark.parametrize(
    ("login", "become_user", "expected_sudo"),
    [("root", "root", False), ("steward-deploy", "application", True)],
)
def test_real_ansible_pipelines_module_for_explicit_become_user(
    harness, login, become_user, expected_sudo
):
    process, ssh_calls, sudo_calls = harness(
        [
            {
                "ansible.builtin.command": {
                    "argv": ["/bin/sh", "-c", "echo standard-out; echo standard-err >&2; exit 7"]
                },
                "become": True,
                "become_user": become_user,
                "register": "result",
                "failed_when": (
                    "result.rc != 7 or result.stdout != 'standard-out' "
                    "or result.stderr != 'standard-err'"
                ),
            }
        ],
        overrides={"ansible_user": login, "ansible_pipelining": True},
    )
    assert process.returncode == 0, process.stdout + process.stderr
    assert len(ssh_calls) == 1
    assert f'User="{login}"' in ssh_calls[0]
    invocation = shlex.split(ssh_calls[0][-1])
    assert invocation[:-1] == GATE_ARGS
    assert "AnsiballZ" not in invocation[-1]  # Python receives the module over stdin.
    if expected_sudo:
        (sudo_call,) = sudo_calls
        assert sudo_call[:7] == ["-H", "-S", "-n", "-u", become_user, "/bin/sh", "-c"]
        assert "BECOME-SUCCESS-" in sudo_call[-1]
    else:
        assert sudo_calls == []
        assert "BECOME-SUCCESS-" not in invocation[-1]
