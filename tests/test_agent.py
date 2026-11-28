import asyncio
import os
import pwd

import pytest

from opstend.adapters.runner import Result
from opstend.agent import Agent, AgentRunner, check


def test_check_allows_listed_and_refuses_shells():
    check(["apt-get", "-s", "upgrade"])
    check(["cat", "/etc/os-release"])
    for bad in (
        ["bash", "-c", "id"],
        ["podman", "exec", "x", "sh"],
        ["cat", "/etc/shadow"],
        ["env", "bash"],
        ["apt-get", "purge", "openssh-server"],
    ):
        with pytest.raises(PermissionError):
            check(bad)


class Fake:
    async def run(self, argv, **kw):
        return Result(argv, 0, "ok\n", "")


async def test_agent_roundtrip_over_unix_socket(tmp_path):
    me = pwd.getpwuid(os.getuid()).pw_name
    path = tmp_path / "agent.sock"
    agent = Agent(user=me, path=path, runner=Fake())  # type: ignore[arg-type]
    server = await asyncio.start_unix_server(agent.handle, path=str(path))
    async with server:
        runner = AgentRunner(path)
        out = await runner.run(["uname", "-a"])
        assert out.stdout == "ok\n"
        with pytest.raises(PermissionError):
            await runner.run(["bash", "-c", "id"])
