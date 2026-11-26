"""Pure pre-install checks and fixed layout for the local Ollama runtime (A02).

The install tasks (Ansible, not part of this module) call `plan_local_install` with
facts gathered on the host and refuse to proceed on any problem. Nothing here
downloads, executes or touches the host. The model is never pulled implicitly: the
planned download is the one explicitly configured, size-checked artifact.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import Ai

SERVICE_USER = "steward-ai"
STATE_DIR = "/var/lib/steward-ai"
LISTEN = "127.0.0.1:11434"  # loopback only; never a public port
DISK_HEADROOM_MB = 1024
RAM_HEADROOM_MB = 256


class LocalInstallRejected(Exception):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass(frozen=True)
class LocalInstallPlan:
    model: str
    download_mb: int
    service_user: str = SERVICE_USER
    state_dir: str = STATE_DIR
    listen: str = LISTEN
    device: str = "cpu"
    allow_pull: bool = False  # the install step downloads exactly `model`, nothing else


def plan_local_install(
    ai: Ai,
    *,
    ram_total_mb: int,
    disk_free_mb: int,
    reserved_memory_mb: int,
    gpu_requested: bool = False,
) -> LocalInstallPlan:
    problems: list[str] = []
    if ai.provider != "ollama":
        problems.append("ai.provider is not ollama")
    if not ai.model:
        problems.append("ai.model is not configured")
    local = ai.local
    if local is None:
        problems.append("ai.local resource limits are not declared")
    else:
        if not local.license_ack:
            problems.append("the model license has not been accepted (ai.local.license_ack)")
        usable_ram = ram_total_mb - reserved_memory_mb - RAM_HEADROOM_MB
        if local.ram_mb > usable_ram:
            problems.append(f"insufficient RAM: model needs {local.ram_mb} MB, {usable_ram} free")
        needed_disk = local.download_mb + local.disk_mb + DISK_HEADROOM_MB
        if needed_disk > disk_free_mb:
            problems.append(f"insufficient disk: {needed_disk} MB needed, {disk_free_mb} free")
    if gpu_requested:
        problems.append("GPU devices are not supported without a device-isolation check")
    if problems or local is None or ai.model is None:
        raise LocalInstallRejected(problems)
    return LocalInstallPlan(model=ai.model, download_mb=local.download_mb)
