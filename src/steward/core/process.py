"""Bounded subprocess output and process-group cleanup for trusted fixed argv."""

from __future__ import annotations

import contextlib
import os
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO


class CommandError(Exception):
    def __init__(self, error_class: str, *, exit_code: int | None = None):
        super().__init__(error_class)
        self.error_class = error_class
        self.exit_code = exit_code


def run_bounded(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    max_bytes: int,
    on_start: Callable[[int], None] | None = None,
    stderr: BinaryIO | None = None,
) -> bytes:
    process = None
    read_fd = write_fd = None
    try:
        launch = argv
        inherited = ()
        if on_start is not None:
            read_fd, write_fd = os.pipe()
            # The child cannot execute the target until the durable callback succeeds.
            # If the parent dies first, the pipe closes and the child exits.
            barrier = (
                "import os,sys;f=int(sys.argv[1]);"
                "b=os.read(f,1);os.close(f);"
                "b==b'1' or os._exit(125);"
                "os.execvpe(sys.argv[2],sys.argv[2:],os.environ)"
            )
            launch = [sys.executable, "-c", barrier, str(read_fd), *argv]
            inherited = (read_fd,)
        process = subprocess.Popen(
            launch,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=stderr if stderr is not None else subprocess.DEVNULL,
            start_new_session=True,
            pass_fds=inherited,
        )
        if on_start is not None:
            os.close(read_fd)
            read_fd = None
            on_start(process.pid)
            os.write(write_fd, b"1")
            os.close(write_fd)
            write_fd = None
        deadline, data = time.monotonic() + timeout, bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise CommandError("timeout")
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                if len(data) + len(chunk) > max_bytes:
                    raise CommandError("output_limit")
                data.extend(chunk)
        # Observe exit without reaping: keep the PID reserved until descendants
        # have been killed, so cleanup cannot target a recycled process group.
        while True:
            status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                break
            if time.monotonic() >= deadline:
                raise CommandError("timeout")
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        if status.si_code != os.CLD_EXITED or status.si_status != 0:
            raise CommandError(
                "unavailable",
                exit_code=status.si_status if status.si_code == os.CLD_EXITED else None,
            )
        return bytes(data)
    except OSError:
        raise CommandError("unavailable") from None
    finally:
        if read_fd is not None:
            os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
        if process is not None:
            # Also remove descendants that retained stdout or outlived the parent.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            if process.stdout:
                process.stdout.close()
