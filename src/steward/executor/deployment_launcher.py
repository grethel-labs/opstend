"""Admit one remote command to the local Steward deployment gate."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

RUNTIME = Path("/run/steward-deployment")
ID = re.compile(r"[0-9a-f]{32}")
BOOT_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
CREDENTIALS = struct.Struct("=iII")
PACKET_LIMIT = 512
ACK = b"OK\n"


class GateError(Exception):
    pass


@dataclass(frozen=True)
class Identity:
    operation_id: str
    run_id: str
    boot_id: str

    def __post_init__(self):
        for value, pattern in (
            (self.operation_id, ID),
            (self.run_id, ID),
            (self.boot_id, BOOT_UUID),
        ):
            if not isinstance(value, str) or pattern.fullmatch(value) is None:
                raise GateError("invalid deployment identity")

    @property
    def scope_prefix(self):
        return f"stewardcommand{self.run_id}"

    @property
    def slice(self):
        return f"stewarddeploy{self.run_id}.slice"


def parse_json(data):
    def unique_fields(items):
        fields = dict(items)
        if len(fields) != len(items):
            raise GateError("duplicate deployment field")
        return fields

    value = json.loads(data, object_pairs_hook=unique_fields)
    if not isinstance(value, dict):
        raise GateError("invalid deployment message")
    return value


def peer_credentials(connection):
    return CREDENTIALS.unpack(
        connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, CREDENTIALS.size)
    )


def receive(connection):
    data, _, flags, _ = connection.recvmsg(PACKET_LIMIT)
    if flags & socket.MSG_TRUNC or not data.endswith(b"\n"):
        raise GateError("invalid deployment packet")
    return data


def enter(identity, command):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(15)
        connection.connect(str(RUNTIME / "gate.sock"))
        if peer_credentials(connection)[1] != 0:
            raise GateError("deployment gate is not root-owned")
        connection.sendall(json.dumps(asdict(identity)).encode("ascii") + b"\n")
        if receive(connection) != ACK:
            raise GateError("deployment gate did not acknowledge admission")
    os.execv("/bin/sh", ["/bin/sh", "-c", command])  # noqa: S606


def add_enter_arguments(parser):
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--boot-id", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)


def enter_from_args(parser, args):
    if len(args.command) != 2 or args.command[0] != "--":
        parser.error("enter requires -- followed by one command string")
    enter(Identity(args.operation_id, args.run_id, args.boot_id), args.command[1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_enter_arguments(parser)
    args = parser.parse_args()
    try:
        enter_from_args(parser, args)
    except (GateError, OSError, ValueError) as error:
        print(f"deployment launcher: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
