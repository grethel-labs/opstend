import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, call

import pytest
import yaml

from steward.executor.host import Host

UNIT = "steward-firewall.service"
READ_STATE = ["systemctl", "show", "--property=ActiveState", "--value", UNIT]
TASKS = Path(__file__).resolve().parents[1] / "ansible/roles/firewall/tasks"


@pytest.mark.parametrize(("state", "verb"), [("active", "reload"), ("inactive", "start")])
def test_reassert_repairs_a_missing_table_without_stopping_the_unit(monkeypatch, state, verb):
    host = Host()
    run = Mock(side_effect=[(1, "table missing"), (0, state + "\n"), (0, "")])
    monkeypatch.setattr(host, "_run", run)

    assert not host.firewall_loaded()
    assert host.firewall_reassert() == (True, "")
    assert run.call_args_list == [
        call(["nft", "list", "table", "inet", "steward"]),
        call(READ_STATE),
        call(["systemctl", verb, UNIT]),
    ]


@pytest.mark.parametrize("state", [None, "active", "inactive"])
def test_reassert_propagates_systemctl_failure_without_trying_another_verb(monkeypatch, state):
    host = Host()
    results = [(1, " systemctl failed\n")]
    if state is not None:
        results.insert(0, (0, state))
    run = Mock(side_effect=results)
    monkeypatch.setattr(host, "_run", run)

    assert host.firewall_reassert() == (False, "systemctl failed")
    assert run.call_count == len(results)


def test_unit_and_ssh_probe_use_verified_paths():
    tasks = yaml.safe_load((TASKS / "configure.yml").read_text())
    commands = {
        task["ansible.builtin.command"]["argv"][2]: index
        for index, task in enumerate(tasks)
        if "ansible.builtin.command" in task
    }
    probe_index = next(
        index
        for index, task in enumerate(tasks)
        if task.get("ansible.builtin.include_tasks") == "verify-ssh.yml"
        and task.get("when") == "firewall_candidate is changed"
    )
    start_index = next(
        index
        for index, task in enumerate(tasks)
        if task.get("ansible.builtin.systemd_service", {}).get("state") == "started"
    )
    assert commands["apply"] < probe_index < commands["commit"] < start_index
    assert tasks[commands["commit"]]["when"] == "firewall_candidate is changed"
    unit = next(task for task in tasks if task["name"] == "Install firewall unit")
    unit_content = unit["ansible.builtin.copy"]["content"]
    verified = "/etc/steward/nftables/steward.nft"
    assert f"AssertPathExists={verified}" in unit_content.splitlines()
    helper = "/usr/bin/python3 /etc/steward/nftables/firewall-policy.py"
    for directive in ("ExecStart", "ExecReload"):
        assert f"{directive}={helper} load-verified" in unit_content.splitlines()
    assert f"ExecStop={helper} stop-verified" in unit_content.splitlines()

    reset, probe, port_check = yaml.safe_load((TASKS / "verify-ssh.yml").read_text())
    assert reset["ansible.builtin.meta"] == "reset_connection"
    assert probe["ansible.builtin.wait_for_connection"] == {"timeout": 90}
    assert "when" not in reset and "when" not in probe
    assert port_check["ansible.builtin.include_tasks"] == "check-ssh-port.yml"


@pytest.mark.parametrize(
    ("state", "flags", "manage", "ssh_port", "failure", "expected"),
    [
        ("fresh", [], True, 22, None, ["inspect", "enable", "apply", "probe", "commit", "start"]),
        (
            "legacy",
            [],
            True,
            22,
            None,
            ["inspect", "probe", "bootstrap", "enable", "apply", "probe", "commit", "start"],
        ),
        ("legacy", [], True, 22, "probe", ["inspect", "probe"]),
        ("fresh", [], True, 22, "probe", ["inspect", "enable", "apply", "probe"]),
        ("fresh", [], True, 22, "fresh-port", ["inspect", "enable", "apply", "probe"]),
        ("fresh", [], True, 22, "apply", ["inspect", "enable", "apply"]),
        ("verified", [], True, 22, None, ["inspect", "apply"]),
        ("fresh", ["--check"], True, 22, None, []),
        ("verified", ["--check"], True, 22, None, ["inspect"]),
        ("verified", ["--check", "--diff"], True, 22, "source-drift", ["inspect"]),
        ("verified", ["--check"], True, 22, "inspect", ["inspect"]),
        ("fresh", ["--check"], True, 2222, "port", []),
        ("fresh", [], False, 2222, None, []),
    ],
)
def test_firewall_activation_order(tmp_path, state, flags, manage, ssh_port, failure, expected):
    executable = Path(sys.executable).parent / "ansible-playbook"
    if not executable.exists():
        pytest.skip("controller Ansible environment is not installed")

    # Exercise real Ansible conditionals and systemd_service without host writes.
    role = tmp_path / "roles/firewall"
    tasks = role / "tasks"
    files = role / "files"
    tasks.mkdir(parents=True)
    files.mkdir()
    policy_directory = tmp_path / "nftables"
    unit_path = tmp_path / UNIT
    original = (TASKS / "configure.yml").read_text()
    for name in ("main.yml", "check-ssh-port.yml"):
        (tasks / name).write_text((TASKS / name).read_text())
    (tasks / "configure.yml").write_text(
        original.replace("/etc/steward/nftables", str(policy_directory))
        .replace("/etc/systemd/system/" + UNIT, str(unit_path))
        .replace("/usr/bin/python3", sys.executable)
        .replace("    owner: root\n", "")
        .replace("    group: root\n", "")
    )
    (tasks / "preview.yml").write_text(
        (TASKS / "preview.yml")
        .read_text()
        .replace("/etc/steward/nftables", str(policy_directory))
        .replace("/usr/bin/python3", sys.executable)
        .replace("uid == 0", f"uid == {os.getuid()}")
        .replace("gid == 0", f"gid == {os.getgid()}")
    )
    (tasks / "verify-ssh.yml").write_text(
        "- name: Simulate proof of a fresh SSH connection\n"
        "  ansible.builtin.command: probe\n"
        "  changed_when: false\n"
        "- name: Check the fresh SSH port\n"
        "  ansible.builtin.include_tasks: check-ssh-port.yml\n"
    )
    helper = files / "firewall-policy.py"
    helper.write_text(
        "import hashlib, json, os, sys\n"
        "from pathlib import Path\n"
        "state = os.environ['POLICY_STATE']\n"
        "command = sys.argv[1]\n"
        "with open(os.environ['ACTIVATION_LOG'], 'a') as log:\n"
        "    log.write(command + '\\n')\n"
        "if command == os.environ['FAILURE']:\n"
        "    sys.exit('simulated ' + command + ' failure')\n"
        "if command == 'inspect':\n"
        "    rendered = hashlib.sha256(b'test nftables batch').hexdigest()\n"
        "    print(json.dumps({'state': state, 'runtime': 'a' * 64, "
        "'verified_runtime': 'a' * 64, 'source': rendered}))\n"
        "elif command == 'bootstrap':\n"
        "    assert sys.argv[2:] == ['a' * 64]\n"
        "    Path(__file__).with_name('steward.nft').touch()\n"
        "elif command == 'apply':\n"
        "    assert sys.stdin.read() == 'test nftables batch'\n"
        "    changed = state != 'verified'\n"
        "    print(json.dumps({'changed': changed, 'attempt': ('b' * 32) if changed else None}))\n"
        "elif command == 'commit':\n"
        "    assert sys.argv[2:] == ['b' * 32]\n"
        "    Path(__file__).with_name('steward.nft').touch()\n"
    )
    systemctl = tmp_path / "systemctl"
    systemctl.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        '  show) printf "LoadState=loaded\\nActiveState=%s\\n" "$UNIT_STATE" ;;\n'
        '  is-enabled) if [ "$POLICY_STATE" = verified ]; then echo enabled; else exit 1; fi ;;\n'
        '  enable) printf "%s\\n" "$1" >> "$ACTIVATION_LOG" ;;\n'
        '  start) test -f "$VERIFIED_POLICY" && echo start >> "$ACTIVATION_LOG" ;;\n'
        "  daemon-reload) ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n"
    )
    systemctl.chmod(0o700)
    probe = tmp_path / "probe"
    probe.write_text('#!/bin/sh\necho probe >> "$ACTIVATION_LOG"\n[ "$FAILURE" != probe ]\n')
    probe.chmod(0o700)
    printenv = tmp_path / "printenv"
    printenv.write_text(
        "#!/bin/sh\n"
        'if [ "$FAILURE" = fresh-port ] && grep -qx probe "$ACTIVATION_LOG" 2>/dev/null; then\n'
        '  echo "127.0.0.1 12345 127.0.0.1 2222"\n'
        "else\n"
        '  /usr/bin/printenv "$1"\n'
        "fi\n"
    )
    printenv.chmod(0o700)
    log = tmp_path / "activation.log"
    if state == "verified":
        # An active systemd unit and unchanged installed files on the second run.
        policy_directory.mkdir(mode=0o700)
        (policy_directory / "steward.nft").touch()
        installed_helper = policy_directory / helper.name
        installed_helper.write_bytes(helper.read_bytes())
        installed_helper.chmod(0o700)
        unit = next(
            task["ansible.builtin.copy"]["content"]
            for task in yaml.safe_load((tasks / "configure.yml").read_text())
            if task["name"] == "Install firewall unit"
        )
        unit_path.write_text(unit)
        unit_path.chmod(0o644)

    playbook = tmp_path / "test.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "vars": {
                        "ansible_python_interpreter": sys.executable,
                        "ansible_remote_tmp": str(tmp_path / "remote"),
                        "steward_hardening": {"firewall": {"manage": manage}},
                        "steward_ssh_port": ssh_port,
                        "steward_nftables": "changed nftables batch"
                        if failure == "source-drift"
                        else "test nftables batch",
                    },
                    "environment": {
                        "PATH": f"{tmp_path}:/usr/bin:/bin",
                        "ACTIVATION_LOG": str(log),
                        "VERIFIED_POLICY": str(policy_directory / "steward.nft"),
                        "POLICY_STATE": state,
                        "UNIT_STATE": "active" if state == "verified" else "inactive",
                        "SSH_CONNECTION": "127.0.0.1 12345 127.0.0.1 22",
                        "FAILURE": failure or "",
                    },
                    "roles": ["firewall"],
                }
            ]
        )
    )
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    result = subprocess.run(
        [str(executable), "-i", "localhost,", *flags, str(playbook)],
        cwd=tmp_path,
        env={
            "PATH": f"{executable.parent}:/usr/bin:/bin",
            "HOME": str(tmp_path),
            "ANSIBLE_CONFIG": str(config),
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
        },
        capture_output=True,
        text=True,
        timeout=90,
    )

    fails = failure in {"apply", "probe", "port", "fresh-port"}
    assert result.returncode == (2 if fails else 0), result.stdout + result.stderr
    assert (log.read_text().splitlines() if log.exists() else []) == expected
    assert (policy_directory / "steward.nft").exists() == (
        state == "verified" or "commit" in expected
    )
    if not expected:
        assert not policy_directory.exists()
        assert not unit_path.exists()
    if state == "verified" or "--check" in flags and not fails:
        changed = int("--check" in flags and (state == "fresh" or failure is not None))
        assert f"changed={changed}" in result.stdout
    if failure == "fresh-port":
        assert "this connection arrives on port 2222" in result.stdout
    if failure == "port":
        assert "this connection arrives on port 22" in result.stdout
