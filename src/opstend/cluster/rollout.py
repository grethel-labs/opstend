"""Coordinated updates across every managed system.

One rollout updates OpsTend nodes, Proxmox hosts, Linux servers, UniFi devices
and applications in waves that keep the fleet working:

* a canary first, then leaves before the systems they depend on
  (access points before switches before the gateway),
* never more voters offline than the quorum tolerates,
* at most one network core device per wave and never a device together with
  something that reaches the fleet through it,
* guests are drained or migrated before their host goes down,
* every wave must pass a health gate. A failure stops the rollout and rolls
  the failed target back where the platform supports it.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from pydantic import Field

from opstend.core.models import Model, utcnow


class TargetKind(StrEnum):
    OPSTEND = "opstend"
    PROXMOX = "proxmox"
    LINUX = "linux"
    UNIFI_GATEWAY = "unifi-gateway"
    UNIFI_SWITCH = "unifi-switch"
    UNIFI_AP = "unifi-ap"
    APP = "app"


NETWORK_RANK = {TargetKind.UNIFI_AP: 0, TargetKind.UNIFI_SWITCH: 1, TargetKind.UNIFI_GATEWAY: 2}


class Target(Model):
    id: str
    name: str
    kind: TargetKind
    site: str = "default"
    current: str = ""
    available: str = ""
    voter: bool = False
    depends_on: list[str] = Field(default_factory=list)  # e.g. its uplink switch
    guests: list[str] = Field(default_factory=list)
    reboot: bool = True
    criticality: int = 1  # 0 = canary material, 3 = core


class WaveState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class Wave(Model):
    index: int
    targets: list[str]
    reason: str
    state: WaveState = WaveState.PENDING
    errors: dict[str, str] = Field(default_factory=dict)


class RolloutState(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    PAUSED = "paused"
    DONE = "done"
    FAILED = "failed"


class Rollout(Model):
    id: str
    title: str
    waves: list[Wave]
    state: RolloutState = RolloutState.PLANNED
    created_at: str = Field(default_factory=lambda: utcnow().isoformat())
    message: str = ""


class PlanError(ValueError):
    pass


@dataclass
class Constraints:
    voters_total: int = 1
    max_parallel: int = 3
    canary: bool = True


def _closure(targets: dict[str, Target]) -> dict[str, set[str]]:
    """All targets that each target reaches the fleet through (transitively)."""
    out: dict[str, set[str]] = {}

    def walk(tid: str, seen: set[str]) -> set[str]:
        for dep in targets[tid].depends_on:
            if dep in targets and dep not in seen:
                seen.add(dep)
                walk(dep, seen)
        return seen

    for tid in targets:
        out[tid] = walk(tid, set())
    return out


def plan(targets: list[Target], constraints: Constraints) -> list[Wave]:
    by_id = {t.id: t for t in targets}
    if len(by_id) != len(targets):
        raise PlanError("duplicate target ids")
    upstream = _closure(by_id)
    for tid, ups in upstream.items():
        if tid in ups:
            raise PlanError(f"dependency cycle through {tid}")
    downstream: dict[str, set[str]] = {t: set() for t in by_id}
    for tid, ups in upstream.items():
        for up in ups:
            downstream[up].add(tid)
    quorum = constraints.voters_total // 2 + 1
    voter_slack = max(0, constraints.voters_total - quorum)
    if (
        voter_slack == 0
        and any(t.voter and t.reboot for t in targets)
        and constraints.voters_total > 1
    ):
        raise PlanError("voters cannot be updated without losing quorum")

    remaining = set(by_id)
    waves: list[Wave] = []

    def ready(tid: str) -> bool:
        # A target may go once everything that depends on it is done.
        return not (downstream[tid] & remaining - {tid})

    def order_key(tid: str) -> tuple[int, int, int, str]:
        t = by_id[tid]
        return (t.criticality, NETWORK_RANK.get(TargetKind(t.kind), -1), int(t.voter), t.name)

    if constraints.canary and len(targets) > 1:
        candidates = sorted(
            (t for t in remaining if ready(t) and not by_id[t].voter), key=order_key
        )
        if candidates:
            first = candidates[0]
            waves.append(Wave(index=0, targets=[first], reason="canary: lowest risk target first"))
            remaining.discard(first)

    while remaining:
        wave: list[str] = []
        voters_out = 0
        core_in_wave = False
        for tid in sorted((t for t in remaining if ready(t)), key=order_key):
            t = by_id[tid]
            if len(wave) >= constraints.max_parallel:
                break
            if t.voter and t.reboot:
                if voters_out >= max(voter_slack, 1 if constraints.voters_total == 1 else 0):
                    continue
            kind = TargetKind(t.kind)
            is_core = kind in (TargetKind.UNIFI_SWITCH, TargetKind.UNIFI_GATEWAY)
            if is_core and (core_in_wave or wave):
                continue
            if core_in_wave:
                break
            if any(tid in upstream[o] or o in upstream[tid] for o in wave):
                continue
            wave.append(tid)
            voters_out += int(t.voter and t.reboot)
            core_in_wave = core_in_wave or is_core
        if not wave:
            raise PlanError("no target can be updated safely; check dependencies")
        names = ", ".join(by_id[t].name for t in wave)
        if core_in_wave:
            reason = f"network core alone: {names}"
        elif any(by_id[t].voter for t in wave):
            reason = f"keeps quorum ({quorum} of {constraints.voters_total} voters up): {names}"
        else:
            reason = f"independent targets: {names}"
        waves.append(Wave(index=len(waves), targets=wave, reason=reason))
        remaining -= set(wave)
    return waves


class Updater(Protocol):
    async def precheck(self, target: Target) -> None: ...
    async def drain(self, target: Target) -> None: ...
    async def apply(self, target: Target) -> None: ...
    async def healthy(self, target: Target) -> bool: ...
    async def rollback(self, target: Target) -> None: ...
    async def restore(self, target: Target) -> None: ...


@dataclass
class Runner:
    updaters: dict[str, Updater]
    on_change: Callable[[Rollout], Awaitable[None] | None] | None = None
    health_retries: int = 30
    health_interval: Callable[[], Awaitable[None]] | None = None
    log: list[str] = field(default_factory=list)

    async def _emit(self, rollout: Rollout) -> None:
        if self.on_change:
            result = self.on_change(rollout)
            if result is not None:
                await result

    async def _gate(self, updater: Updater, target: Target) -> bool:
        for _ in range(self.health_retries):
            if await updater.healthy(target):
                return True
            if self.health_interval:
                await self.health_interval()
        return False

    async def run(self, rollout: Rollout, targets: dict[str, Target]) -> Rollout:
        rollout.state = RolloutState.RUNNING
        await self._emit(rollout)
        for wave in rollout.waves:
            if wave.state == WaveState.DONE:
                continue
            wave.state = WaveState.RUNNING
            await self._emit(rollout)
            for tid in wave.targets:
                target = targets[tid]
                updater = self.updaters[TargetKind(target.kind)]
                try:
                    await updater.precheck(target)
                    await updater.drain(target)
                    await updater.apply(target)
                    if not await self._gate(updater, target):
                        raise RuntimeError("health gate failed after update")
                    await updater.restore(target)
                    self.log.append(f"{target.name}: updated to {target.available}")
                except Exception as exc:
                    wave.errors[tid] = str(exc)
                    self.log.append(f"{target.name}: failed ({exc}); rolling back")
                    try:
                        await updater.rollback(target)
                        await updater.restore(target)
                    except Exception as rb:
                        wave.errors[tid] += f"; rollback failed: {rb}"
            if wave.errors:
                wave.state = WaveState.FAILED
                rollout.state = RolloutState.PAUSED
                rollout.message = (
                    f"Wave {wave.index + 1} failed. The rollout is paused; "
                    "later waves did not start."
                )
                await self._emit(rollout)
                return rollout
            wave.state = WaveState.DONE
            await self._emit(rollout)
        rollout.state = RolloutState.DONE
        rollout.message = "All targets updated and healthy."
        await self._emit(rollout)
        return rollout
