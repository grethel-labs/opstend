"""Ansible SSH transport that admits each remote command to the deployment gate."""

from __future__ import annotations

import re
import shlex

import yaml
from ansible.errors import AnsibleConnectionFailure
from ansible.plugins.connection import ssh

_HEX_TOKEN = re.compile(r"[0-9a-f]{32}")
_BOOT_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_IDENTITY = (
    ("operation", _HEX_TOKEN),
    ("run", _HEX_TOKEN),
    ("boot", _BOOT_UUID),
)


def _documentation() -> str:
    documentation = yaml.safe_load(ssh.DOCUMENTATION)
    documentation.update(
        name="steward_guarded_ssh",
        short_description="Connect via SSH through the Steward deployment gate",
    )
    for name, _pattern in _IDENTITY:
        option = f"steward_deployment_{name}"
        documentation["options"][option] = {
            "description": f"Active Steward deployment {name} identity.",
            "type": "raw",
            "vars": [{"name": f"ansible_{option}"}],
        }
    documentation["options"]["ssh_transfer_method"]["description"] = (
        "The guarded transport always uses the piped method."
    )
    return yaml.safe_dump(documentation)


DOCUMENTATION = _documentation()


class Connection(ssh.Connection):
    transport = "steward_guarded_ssh"

    def _identity(self) -> list[str]:
        identity = []
        for name, pattern in _IDENTITY:
            option = f"steward_deployment_{name}"
            value = self.get_option(option)
            if not isinstance(value, str) or pattern.fullmatch(value) is None:
                raise AnsibleConnectionFailure(f"Missing or invalid ansible_{option}")
            identity.extend((f"--{name}-id", value))
        return identity

    def set_options(self, task_keys=None, var_options=None, direct=None):
        super().set_options(task_keys=task_keys, var_options=var_options, direct=direct)
        self._identity()

    def get_option(self, option, hostvars=None):
        if option == "ssh_transfer_method":
            return "piped"
        return super().get_option(option, hostvars=hostvars)

    def _file_transport_command(self, in_path, out_path, sftp_action):
        if sftp_action == "put":
            # The upstream piped upload inserts this path directly into its dd command.
            out_path = self._shell.quote(out_path)
        return super()._file_transport_command(in_path, out_path, sftp_action)

    def exec_command(
        self, cmd: str, in_data: bytes | None = None, sudoable: bool = True
    ) -> tuple[int, bytes, bytes]:
        launcher = shlex.join(
            [
                "/usr/bin/python3",
                "-I",
                "/usr/local/libexec/steward/deployment-v1/launch.py",
                *self._identity(),
                "--",
                cmd,
            ]
        )
        return super().exec_command(launcher, in_data=in_data, sudoable=sudoable)
