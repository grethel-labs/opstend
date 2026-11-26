"""Exercise the actual SSH backup cleanup task under Ansible."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


def test_real_ssh_backup_cleanup_with_and_without_a_backup(tmp_path):
    executable = Path(sys.executable).parent / "ansible-playbook"
    if not executable.exists():
        pytest.skip("controller Ansible environment is not installed")
    root = Path(__file__).resolve().parents[1]

    def find(tasks):
        for task in tasks:
            if task.get("name") == "Remove SSH backup":
                return task
            found = find(task.get("block", []))
            if found:
                return found
        return None

    task = find(yaml.safe_load((root / "ansible/roles/base/tasks/ssh.yml").read_text()))
    assert task is not None
    backup = tmp_path / "original.backup"
    backup.write_text("temporary fixture")
    tasks = [
        {"block": [task], "vars": {"base_ssh": {"backup_file": str(backup)}}},
        {"ansible.builtin.stat": {"path": str(backup)}, "register": "cleanup_result"},
        {"ansible.builtin.assert": {"that": "not cleanup_result.stat.exists"}},
        {"block": [task], "vars": {"base_ssh": {"backup_file": ""}}},
        {"block": [task], "vars": {"base_ssh": {}}},
    ]
    playbook = tmp_path / "play.yml"
    playbook.write_text(
        yaml.safe_dump([{"hosts": "localhost", "gather_facts": False, "tasks": tasks}])
    )
    env = os.environ.copy()
    env.update(ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible-local"), ANSIBLE_NOCOLOR="1")
    result = subprocess.run(
        [str(executable), "-i", "localhost,", "-c", "local", str(playbook)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
