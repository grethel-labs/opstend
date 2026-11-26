"""Execute the real activation tasks with a harmless temporary-role handler."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from steward.core import render


def test_interrupted_activation_requeues_without_losing_idempotence_or_secret_rotation(
    tmp_path, cfg
):
    executable = Path(sys.executable).parent / "ansible-playbook"
    if not executable.exists():
        pytest.skip("controller Ansible environment is not installed")
    root = Path(__file__).resolve().parents[1]
    role = tmp_path / "roles/probe"
    (role / "tasks").mkdir(parents=True)
    (role / "handlers").mkdir()
    source = root / "ansible/roles/platform"
    shutil.copyfile(source / "tasks/activation.yml", role / "tasks/main.yml")
    shutil.copytree(source / "templates", role / "templates")
    credential, record, handler = (tmp_path / name for name in ("credential", "record", "handler"))
    credential.write_text("private-fixture-token-one")
    credential.chmod(0o600)
    # The only handler writes into this test's temporary directory; production
    # service handlers are never imported or executed by this test.
    (role / "handlers/main.yml").write_text(
        yaml.safe_dump(
            [
                {
                    "name": "Restart platform services",
                    "ansible.builtin.copy": {
                        "content": "{{ platform_activation_fingerprint }}\n",
                        "dest": str(handler),
                        "mode": "0600",
                    },
                }
            ]
        )
    )
    environment = {
        "PATH": str(executable.parent) + ":/usr/bin:/bin",
        "HOME": str(tmp_path),
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
        "ANSIBLE_NOCOLOR": "1",
    }
    configuration = tmp_path / "ansible.cfg"
    configuration.write_text("[defaults]\nroles_path = roles\nhost_key_checking = True\n")
    environment["ANSIBLE_CONFIG"] = str(configuration)
    variables = render.render_vars(
        cfg,
        release={
            "version": "0.1.0.dev0",
            "files": {"dist/app.whl": "a" * 64},
            "wheel": "app.whl",
            "dir": str(tmp_path),
        },
        ssh_port=22,
    )
    variables.update(
        {
            "ansible_python_interpreter": sys.executable,
            "ansible_remote_tmp": str(tmp_path / "remote"),
            "platform_activation_record_path": str(record),
            "steward_activation_secrets": [
                {"name": "admin-token", "kind": "file", "target": str(credential)}
            ],
        }
    )

    def run(*, revision, abort=False):
        variables["steward_config_revision"] = revision
        tasks = [{"ansible.builtin.include_role": {"name": "probe"}}]
        tasks += [{"ansible.builtin.assert": {"that": ["platform_activation_required is boolean"]}}]
        if abort:
            tasks += [{"ansible.builtin.fail": {"msg": "deliberate pre-handler interruption"}}]
        tasks += [
            {"ansible.builtin.meta": "flush_handlers"},
            {
                "ansible.builtin.copy": {
                    "dest": str(record),
                    "content": "{{ platform_activation_fingerprint }}\n",
                    "mode": "0600",
                }
            },
        ]
        playbook = tmp_path / "probe.yml"
        playbook.write_text(
            yaml.safe_dump(
                [
                    {
                        "hosts": "localhost",
                        "connection": "local",
                        "gather_facts": False,
                        "vars": variables,
                        "tasks": tasks,
                    }
                ],
                sort_keys=False,
            )
        )
        result = subprocess.run(
            [str(executable), "-i", "localhost,", str(playbook)],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            timeout=60,
        )
        assert result.returncode == (2 if abort else 0), (
            result.stdout.decode() + result.stderr.decode()
        )
        assert b"private-fixture-token" not in result.stdout + result.stderr
        return result

    run(revision="a" * 64)
    old = record.read_text()
    assert handler.read_text() == old
    run(revision="b" * 64, abort=True)
    # Desired inputs changed, but an interrupted run activated/recorded nothing.
    assert record.read_text() == handler.read_text() == old
    run(revision="b" * 64)
    new = record.read_text()
    assert new != old and handler.read_text() == new
    mtime = handler.stat().st_mtime_ns
    result = run(revision="b" * 64)
    assert handler.stat().st_mtime_ns == mtime
    assert b"changed=0" in result.stdout
    credential.write_text("private-fixture-token-two")
    run(revision="b" * 64)
    rotated = record.read_text()
    assert rotated != new and handler.read_text() == rotated
    unit = role / "templates/steward-api.service.j2"
    unit.write_text(unit.read_text() + "\n# fixture unit input change\n")
    run(revision="b" * 64)
    assert record.read_text() != rotated and handler.read_text() == record.read_text()
    previous = record.read_text()
    # Same version/configuration, a different wheel: the lost activation must
    # also reinstall the package instead of trusting "pip state: present".
    variables["steward_release"]["files"]["dist/app.whl"] = "b" * 64
    run(revision="b" * 64, abort=True)
    assert record.read_text() == previous
    run(revision="b" * 64)
    assert record.read_text() != previous and handler.read_text() == record.read_text()


def test_backup_credential_rotation_notifies_only_backup_handler(tmp_path, cfg):
    executable = Path(sys.executable).parent / "ansible-playbook"
    if not executable.exists():
        pytest.skip("controller Ansible environment is not installed")
    root = Path(__file__).resolve().parents[1]
    source = root / "ansible/roles/platform"
    role = tmp_path / "roles/probe"
    (role / "tasks").mkdir(parents=True)
    (role / "handlers").mkdir()
    for name in ("activation.yml", "backup_activation.yml"):
        shutil.copyfile(source / "tasks" / name, role / "tasks" / name)
    shutil.copytree(source / "templates", role / "templates")
    (role / "handlers/main.yml").write_text(
        yaml.safe_dump(
            [
                {
                    "name": "Restart platform services",
                    "ansible.builtin.set_fact": {
                        "platform_count": "{{ (platform_count | default(0) | int) + 1 }}"
                    },
                },
                {
                    "name": "Restart backup service",
                    "ansible.builtin.set_fact": {
                        "backup_count": "{{ (backup_count | default(0) | int) + 1 }}"
                    },
                },
            ]
        )
    )
    admin, repo, password = (tmp_path / n for n in ("admin", "repo", "password"))
    for path, content in (
        (admin, "private-admin-one"),
        (repo, "private-repository-one"),
        (password, "private-password-one"),
    ):
        path.write_text(content)
        path.chmod(0o600)
    cfg.backup.enabled = True
    cfg.backup.repository_ref = "env:REPOSITORY"
    cfg.backup.password_ref = "env:PASSWORD"
    variables = render.render_vars(
        cfg,
        release={
            "version": "0.1.0.dev0",
            "files": {"dist/app.whl": "a" * 64},
            "wheel": "app.whl",
            "dir": str(tmp_path),
        },
        ssh_port=22,
    )
    variables.update(
        {
            "ansible_python_interpreter": sys.executable,
            "ansible_remote_tmp": str(tmp_path / "remote"),
            "platform_activation_record_path": str(tmp_path / "platform-record"),
            "platform_backup_activation_record_path": str(tmp_path / "backup-record"),
            "steward_activation_secrets": [
                {"name": "admin-token", "kind": "file", "target": str(admin)}
            ],
            "steward_backup_secrets": [
                {"name": "repository", "kind": "file", "target": str(repo)},
                {"name": "password", "kind": "file", "target": str(password)},
            ],
        }
    )

    def include(task):
        return {"ansible.builtin.include_role": {"name": "probe", "tasks_from": task}}

    def write_record(name, value):
        return {
            "ansible.builtin.copy": {
                "dest": str(tmp_path / name),
                "content": "{{ " + value + " }}\n",
                "mode": "0600",
            }
        }

    tasks = [
        include("activation.yml"),
        include("backup_activation.yml"),
        {"ansible.builtin.meta": "flush_handlers"},
        {
            "ansible.builtin.assert": {
                "that": ["platform_count | int == 1", "backup_count | int == 1"]
            }
        },
        write_record("platform-record", "platform_activation_fingerprint"),
        write_record("backup-record", "platform_backup_activation_fingerprint"),
        {
            "ansible.builtin.copy": {
                "dest": str(password),
                "content": "private-password-two",
                "mode": "0600",
            },
            "no_log": True,
        },
        include("activation.yml"),
        include("backup_activation.yml"),
        {"ansible.builtin.meta": "flush_handlers"},
        {
            "ansible.builtin.assert": {
                "that": ["platform_count | int == 1", "backup_count | int == 2"]
            }
        },
    ]
    playbook = tmp_path / "rotation.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "vars": variables,
                    "tasks": tasks,
                }
            ],
            sort_keys=False,
        )
    )
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nroles_path = roles\nhost_key_checking = True\n")
    env = {
        "PATH": str(executable.parent) + ":/usr/bin:/bin",
        "HOME": str(tmp_path),
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_CONFIG": str(config),
    }
    result = subprocess.run(
        [str(executable), "-i", "localhost,", str(playbook)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout.decode() + result.stderr.decode()
    assert b"private-password" not in result.stdout + result.stderr
