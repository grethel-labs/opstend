#!/usr/bin/env python3
"""Qualify PX03 on the authorized disposable single-node PVE fixture."""

import argparse
import hashlib
import json
import os
import platform
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

CLI = (
    "/opt/opstend-pve/current/venv/bin/python",
    "-I",
    "-B",
    "-m",
    "steward.cli.main",
    "pve-native",
)
PVESH = "/usr/bin/pvesh"
FIXTURE = {"qemu": (190, 194, 196, "qm"), "lxc": (191, 195, 197, "vz")}
POOL, STORAGE, BRIDGE = "rc2-managed", "local-lvm", "vmbr0"
NETWORK = {"index": 0, "bridge": BRIDGE, "vlan_tag": None, "link_down": True}
SHA = re.compile(r"[0-9a-f]{64}")
QEMU_CONSOLE = "/var/run/qemu-server/190.serial0"


class GateFailure(ValueError):
    """A fixed reason safe to write to the receipt."""


def require(condition, reason):
    if not condition:
        raise GateFailure(reason)


def invoke(argv, timeout):
    try:
        return subprocess.run(
            argv,
            cwd="/",
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise GateFailure("command_timeout") from None


def pve(path, *options):
    reply = invoke((PVESH, "--noproxy", "get", path, *options, "--output-format", "json"), 8)
    require(reply.returncode == 0, "native_read_failed")
    return json.loads(reply.stdout)


def cli(family, action, *options, timeout=65):
    reply = invoke((*CLI, family, action, *options), timeout)
    require(reply.returncode in (0, 1, 5) and reply.stdout, "signed_cli_refused")
    job = json.loads(reply.stdout)
    require(
        re.fullmatch(r"[0-9a-f]{32}", job["job_id"]) and job["schema_version"] == 1, "invalid_job"
    )
    expected = 0 if action == "status" else {"failed": 1, "uncertain": 5}.get(job["state"], 0)
    require(reply.returncode == expected, "cli_exit_mismatch")
    return job


def action(family, command, job, *options, timeout=65):
    flag = "--confirm" if command == "execute" else "--job-id"
    updated = cli(family, command, flag, job["job_id"], *options, timeout=timeout)
    require(updated["job_id"] == job["job_id"], "job_identity_changed")
    return updated


def reconcile(family, job):
    deadline = time.monotonic() + 100
    while job["next_action"] == "reconcile":
        require(job["state"] != "uncertain", "uncertain_native_outcome")
        time.sleep(1)
        remaining = deadline - time.monotonic()
        require(remaining > 0, "reconcile_timeout")
        job = action(family, "reconcile", job, timeout=min(65, remaining))
    return job


def roster():
    rows = pve("/cluster/resources", "--type", "vm")
    indexed = {int(row["vmid"]): row for row in rows}
    require(len(rows) == len(indexed), "duplicate_roster_vmid")
    return indexed


def generation(row):
    uid, rtime = row["uid"], row["rtime"]
    require(
        re.fullmatch(r"[a-z2-7]{20}", uid) and type(rtime) is int and rtime > 0,
        "invalid_generation",
    )
    return uid, rtime


def _qemu_login_prompt(deadline):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as console:
        console.settimeout(1)
        console.connect(QEMU_CONSOLE)
        console.sendall(b"\r")
        prompt = bytearray()
        while len(prompt) < 4096:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            console.settimeout(remaining)
            data = console.recv(min(1024, 4096 - len(prompt)))
            if not data:
                break
            prompt.extend(data)
            if b"login:" in prompt:
                return True
    return False


def wait_qemu_login():
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            if _qemu_login_prompt(min(deadline, time.monotonic() + 3)):
                return
        except OSError:
            pass
        time.sleep(1)
    raise GateFailure("qemu_guest_not_ready_for_graceful_shutdown")


class Gate:
    def __init__(self, receipt_path):
        self.start = time.monotonic()
        self.receipt_path = receipt_path
        self.evidence = {
            "schema_version": 1,
            "started_at": datetime.now(UTC).isoformat(),
            "checks": [],
        }
        self.node = ""
        self.phase = "preflight"
        self.job_id = None

    def checkpoint(self, result="running", failure=None):
        current = {"phase": self.phase, "job_id": self.job_id}
        receipt = {
            **self.evidence,
            "elapsed_seconds": round(time.monotonic() - self.start, 3),
            "current": current,
            "result": result,
        }
        if failure:
            receipt["failure"] = {**current, "code": failure}
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.receipt_path.parent, delete=False
            ) as output:
                temporary = Path(output.name)
                json.dump(receipt, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.receipt_path)
            directory = os.open(self.receipt_path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def target(self, kind, vmid):
        return {"node": self.node, "kind": kind, "vmid": vmid}

    def guest(self, kind, vmid, path, *options):
        return pve(f"/nodes/{self.node}/{kind}/{vmid}/{path}", *options)

    def live(self, kind, vmid):
        return self.guest(kind, vmid, "status/current")["status"]

    def config(self, kind, vmid):
        return self.guest(kind, vmid, "config", "--current", "1")

    def history(self, vmid, workers, since):
        tasks = set()
        for worker in workers:
            rows = pve(
                f"/nodes/{self.node}/tasks",
                "--vmid",
                str(vmid),
                "--typefilter",
                worker,
                "--source",
                "all",
                "--since",
                str(since),
                "--limit",
                "64",
            )
            require(len(rows) < 64, "incomplete_task_history")
            for row in rows:
                upid = row["upid"]
                require(
                    row["node"] == self.node
                    and row["type"] == worker
                    and str(row["id"]) == str(vmid)
                    and re.fullmatch(
                        rf"UPID:{re.escape(self.node)}:[0-9A-F]{{8}}:[0-9A-F]{{8,9}}:"
                        rf"[0-9A-F]{{8}}:{worker}:{vmid}:[A-Za-z0-9_.+%@!-]+:",
                        upid,
                    )
                    and len(upid) <= 512
                    and (worker, upid) not in tasks,
                    "unexpected_task_history",
                )
                tasks.add((worker, upid))
        return tasks

    def native_task(self, vmid, worker, operation, new, leg, *, collision=None):
        require(len(new) == 1, "native_task_count_mismatch")
        ((actual_worker, upid),) = new
        ref = hashlib.sha256(upid.encode("ascii")).hexdigest()
        state = "succeeded" if collision is None else "failed"
        require(
            actual_worker == worker
            and leg == {"operation": operation, "task_ref": ref, "state": state},
            "native_task_ref_mismatch",
        )
        path = f"/nodes/{self.node}/tasks"
        # The local pvesh router takes the raw validated path component.
        status = pve(f"{path}/{upid}/status")
        require(
            status["upid"] == upid
            and status["node"] == self.node
            and status["type"] == worker
            and str(status["id"]) == str(vmid)
            and status["status"] == "stopped",
            "native_task_status_mismatch",
        )
        reason = status["exitstatus"]
        if collision is None:
            require(reason == "OK", "native_task_failed")
        else:
            require(
                reason == f"unable to create VM {collision}: config file already exists"
                or re.fullmatch(
                    rf"(?:VM|CT) {collision} already exists(?: on node '{re.escape(self.node)}')?",
                    reason,
                ),
                "native_collision_reason_mismatch",
            )
        return ref

    def plan(self, family, kind, vmid, operation, *options):
        self.job_id = None
        job = cli(family, "plan", "--vmid", str(vmid), *options)
        self.job_id = job["job_id"]
        require(
            job["target"] == self.target(kind, vmid)
            and job["operation"] == operation
            and job["state"] == "prepared"
            and job["next_action"] == "execute"
            and job["tasks"] == [],
            "plan_scope_mismatch",
        )
        return job

    def dispatch(self, family, job, *options):
        self.checkpoint()
        started = action(family, "execute", job, *options)
        require(started["state"] == "accepted", "native_dispatch_not_accepted")
        require(action(family, "execute", job, *options) == started, "dispatch_replay_changed_job")
        result = reconcile(family, started)
        require(
            action(family, "execute", job, *options) == result
            and action(family, "status", job) == result,
            "replay_or_status_mismatch",
        )
        return result

    def record(self, **details):
        self.evidence["checks"].append({"phase": self.phase, "job_id": self.job_id, **details})
        self.checkpoint()

    def power_plan(self, kind, vmid, operation):
        job = self.plan("power", kind, vmid, operation, "--operation", operation)
        state = "stopped" if operation == "start" else "running"
        require(job["observed_state"] == state, "power_plan_state_mismatch")
        return job

    def power_leg(self, kind, vmid, prefix, job, leg, *, continuation=False):
        self.job_id = job["job_id"]
        if kind == "qemu" and leg == "shutdown":
            wait_qemu_login()
        since, workers = int(time.time()), (prefix + "start", prefix + "shutdown")
        before = self.history(vmid, workers, since)
        result = self.dispatch("power", job, *(("--continue-reboot",) if continuation else ()))
        state = "running" if leg == "start" else "stopped"
        first_reboot = job["operation"] == "reboot" and not continuation
        require(
            result["state"] == ("verifying" if first_reboot else "succeeded")
            and result["next_action"] == ("execute" if first_reboot else None)
            and len(result["tasks"]) == (2 if continuation else 1)
            and result["current_state"] == self.live(kind, vmid) == state,
            "power_readback_mismatch",
        )
        if continuation:
            require(result["tasks"][:1] == job["tasks"], "verified_shutdown_changed")
        after = self.history(vmid, workers, since)
        require(before <= after, "task_history_changed")
        ref = self.native_task(vmid, prefix + leg, leg, after - before, result["tasks"][-1])
        self.record(
            kind=kind,
            vmid=vmid,
            operation=job["operation"],
            leg=leg,
            live_state=state,
            native_task_count=1,
            native_task_ref=ref,
            native_exit_ok=True,
            replay_verified=True,
        )
        return result

    def power(self, kind, vmid, prefix):
        self.phase = "prepare_power"
        state = self.live(kind, vmid)
        require(state in ("running", "stopped"), "unexpected_initial_state")
        if state == "stopped":
            self.power_leg(kind, vmid, prefix, self.power_plan(kind, vmid, "start"), "start")
        self.phase = "power_shutdown"
        stale = self.power_plan(kind, vmid, "shutdown")
        self.power_leg(kind, vmid, prefix, self.power_plan(kind, vmid, "shutdown"), "shutdown")
        self.phase = "stale_confirmation"
        self.job_id = stale["job_id"]
        since, workers = int(time.time()), (prefix + "start", prefix + "shutdown")
        before = self.history(vmid, workers, since)
        self.checkpoint()
        refused = action("power", "execute", stale)
        require(
            refused["state"] == "failed"
            and refused["error_code"] == "state_changed"
            and refused["tasks"] == []
            and refused["next_action"] is None
            and self.live(kind, vmid) == "stopped"
            and self.history(vmid, workers, since) == before,
            "stale_plan_not_refused",
        )
        self.record(
            kind=kind,
            vmid=vmid,
            error_code="state_changed",
            native_task_count=0,
            live_state="stopped",
        )
        self.phase = "power_start"
        self.power_leg(kind, vmid, prefix, self.power_plan(kind, vmid, "start"), "start")
        self.phase = "reboot_shutdown"
        stopped = self.power_leg(
            kind, vmid, prefix, self.power_plan(kind, vmid, "reboot"), "shutdown"
        )
        self.phase = "reboot_start"
        self.power_leg(kind, vmid, prefix, stopped, "start", continuation=True)

    def clone_plan(self, kind, source, vmid, name):
        job = self.plan(
            "provision", kind, vmid, "clone", "--template-vmid", str(source), "--name", name
        )
        require(
            job["source"] == self.target(kind, source)
            and job["name"] == name
            and job["pool"] == POOL
            and job["storage"] == STORAGE
            and job["networks"] == [NETWORK],
            "clone_policy_mismatch",
        )
        return job

    def volumes(self, kind, cfg):
        if kind == "lxc":
            return {cfg["rootfs"].partition(",")[0]}
        return {
            value.partition(",")[0]
            for key, value in cfg.items()
            if re.fullmatch(r"(?:ide|sata|scsi|virtio)[0-9]+", key)
            and "media=cdrom" not in value.split(",")
        }

    def clone_readback(self, kind, vmid, name):
        row, cfg = roster()[vmid], self.config(kind, vmid)
        pools = pve("/pools", "--poolid", POOL)
        require(len(pools) == 1 and pools[0]["poolid"] == POOL, "clone_pool_mismatch")
        members = pools[0]["members"]
        name_key = "name" if kind == "qemu" else "hostname"
        require(
            row["type"] == kind
            and row["node"] == self.node
            and sum(int(m.get("vmid", 0)) == vmid and m.get("type") == kind for m in members) == 1
            and not cfg.get("template")
            and cfg[name_key] == name
            and self.live(kind, vmid) == "stopped",
            "clone_readback_mismatch",
        )
        nic = cfg["net0"].split(",")
        require(
            f"bridge={BRIDGE}" in nic
            and "link_down=1" in nic
            and not any(field.startswith("tag=") for field in nic)
            and not any(re.fullmatch(r"net[1-9][0-9]*", key) for key in cfg),
            "clone_network_mismatch",
        )
        if kind == "lxc":
            require(cfg["unprivileged"] == 1, "clone_lxc_privilege_mismatch")
        volumes = self.volumes(kind, cfg)
        require(
            volumes
            and all(re.fullmatch(rf"{STORAGE}:vm-{vmid}-disk-[0-9]+", value) for value in volumes)
            and re.fullmatch(r"[0-9a-f]{40}", cfg["digest"]),
            "clone_storage_mismatch",
        )
        return generation(row), cfg

    def clone(self, kind, source, vmid, prefix):
        worker, name = prefix + "clone", f"px03-{kind}-{vmid}"
        self.phase = "clone"
        require(vmid not in roster(), "destination_occupied_before_clone")
        job = self.clone_plan(kind, source, vmid, name)
        since = int(time.time())
        before = self.history(source, (worker,), since)
        result = self.dispatch("provision", job)
        require(
            result["state"] == "succeeded"
            and result["next_action"] is None
            and len(result["tasks"]) == 1
            and result["result"]["state"] == "stopped"
            and SHA.fullmatch(result["result"]["generation"]),
            "clone_verification_failed",
        )
        after = self.history(source, (worker,), since)
        require(before <= after, "task_history_changed")
        ref = self.native_task(source, worker, "clone", after - before, result["tasks"][0])
        generation_before, cfg = self.clone_readback(kind, vmid, name)
        uid, registered_at = generation_before
        generation_ref = hashlib.sha256(f"{uid}:{registered_at}".encode("ascii")).hexdigest()
        require(result["result"]["generation"] == generation_ref, "clone_generation_mismatch")
        source_volumes = self.volumes(kind, self.config(kind, source))
        require(
            source_volumes and source_volumes.isdisjoint(self.volumes(kind, cfg)),
            "clone_shared_source_volume",
        )
        self.record(
            kind=kind,
            vmid=vmid,
            source_vmid=source,
            native_task_ref=ref,
            native_task_count=1,
            native_exit_ok=True,
            live_state="stopped",
            pool=POOL,
            storage=STORAGE,
            bridge=BRIDGE,
            link_down=True,
            generation_ref=generation_ref,
            distinct_source_volumes=True,
            config_digest=cfg["digest"],
            replay_verified=True,
        )

        self.phase = "vmid_collision"
        job = self.clone_plan(kind, source, vmid, f"{name}-occupied")
        since = int(time.time())
        before = self.history(source, (worker,), since)
        self.checkpoint()
        refused = reconcile("provision", action("provision", "execute", job))
        require(
            refused["state"] == "failed"
            and refused["error_code"] == "vmid_conflict"
            and refused["next_action"] is None,
            "provider_collision_not_confirmed",
        )
        require(action("provision", "execute", job) == refused, "collision_replay_changed_job")
        after = self.history(source, (worker,), since)
        require(before <= after, "task_history_changed")
        tasks = after - before
        ref = None
        if refused["tasks"]:
            require(len(refused["tasks"]) == 1, "collision_task_count_mismatch")
            ref = self.native_task(
                source, worker, "clone", tasks, refused["tasks"][0], collision=vmid
            )
        else:
            require(not tasks, "unexpected_collision_task")
        require(
            self.clone_readback(kind, vmid, name) == (generation_before, cfg),
            "collision_changed_existing_guest",
        )
        self.record(
            kind=kind,
            vmid=vmid,
            source_vmid=source,
            error_code="vmid_conflict",
            provider_evidence="native_task" if ref else "synchronous_clone_refusal",
            native_task_ref=ref,
            native_task_count=len(tasks),
            generation_unchanged=True,
            config_unchanged=True,
            replay_verified=True,
        )

    def preflight(self):
        require(
            platform.machine() == "x86_64" and pve("/version")["version"] == "9.3.1",
            "unsupported_pve_version_or_architecture",
        )
        self.evidence["pve_version"] = "9.3.1"
        nodes = pve("/nodes")
        require(len(nodes) == 1 and nodes[0]["status"] == "online", "expected_single_online_node")
        self.node = nodes[0]["node"]
        require(
            re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,62}", self.node)
            and Path("/etc/pve/local").resolve() == Path("/etc/pve/nodes") / self.node,
            "unexpected_local_node",
        )
        install = json.loads(Path("/etc/opstend-pve/install.json").read_bytes())
        version = install["active"]
        manifest = install["releases"][version]["manifest"]
        require(
            install["intent"]["mode"] == "standalone"
            and SHA.fullmatch(manifest)
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:rc[0-9]+)?", version),
            "unexpected_signed_installation",
        )
        self.evidence.update(release=version, manifest_sha256=manifest)
        directory = Path("/var/lib/opstend-pve-executor")
        power = json.loads((directory / "power.json").read_bytes())
        provision = json.loads((directory / "provision.json").read_bytes())
        require(
            power["node"] == provision["node"] == self.node
            and power["write_token_file"] != provision["write_token_file"],
            "policy_scope_mismatch",
        )
        guests = {row["vmid"]: row for row in power["guests"]}
        sources = {row["vmid"]: row for row in provision["templates"]}
        destinations = {row["vmid"]: row for row in provision["targets"]}
        rows = roster()
        require(
            set(guests) == {190, 191}
            and set(sources) == {194, 195}
            and set(destinations) == {196, 197},
            "policy_scope_mismatch",
        )
        require(self.config("qemu", 190).get("serial0") == "socket", "fixture_serial_missing")
        for kind, (vmid, source, destination, _) in FIXTURE.items():
            for entry in (guests[vmid], sources[source]):
                row = rows[entry["vmid"]]
                require(
                    row["node"] == self.node
                    and row["type"] == entry["kind"] == kind
                    and generation(row) == (entry["pve_uid"], entry["registered_at_ms"]),
                    "fixture_generation_mismatch",
                )
            cfg, dst = self.config(kind, source), destinations[destination]
            require(
                cfg.get("template") == 1
                and cfg["digest"] == sources[source]["config_digest"]
                and dst["template_vmid"] == source
                and dst["pool"] == POOL
                and dst["storage"] == STORAGE
                and destination not in rows
                and len(dst["networks"]) == 1
                and dst["networks"][0]["link_down"] is True
                and {**NETWORK, **dst["networks"][0]} == NETWORK
                and set(guests[vmid]["operations"]) == {"start", "shutdown", "reboot"},
                "fixture_policy_mismatch",
            )

    def run(self):
        self.preflight()
        for kind, (vmid, _, _, prefix) in FIXTURE.items():
            self.job_id = None
            self.power(kind, vmid, prefix)
        for kind, (_, source, destination, prefix) in FIXTURE.items():
            self.job_id = None
            self.clone(kind, source, destination, prefix)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-disposable-pve", action="store_true", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root on the authorized disposable PVE fixture")
    try:
        parent = args.evidence.parent.resolve(strict=True)
        info = parent.stat()
        require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, "private_directory")
        evidence_path = parent / args.evidence.name
        os.close(
            os.open(evidence_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        )
    except (OSError, GateFailure):
        parser.error("provide a fresh evidence path in a root-owned mode 0700 directory")

    gate = Gate(evidence_path)
    failure = None
    try:
        gate.checkpoint()
        gate.run()
    except GateFailure as exc:
        failure = str(exc)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OSError):
        failure = "invalid_or_unavailable_evidence"
    except KeyboardInterrupt:
        failure = "interrupted"
    try:
        gate.checkpoint("failed" if failure else "passed", failure)
    except OSError:
        print("PX03 native gate could not update its private receipt.", file=sys.stderr)
        return 1
    if failure:
        print(f"PX03 native gate failed in {gate.phase}: {failure}", file=sys.stderr)
    return int(failure is not None)


if __name__ == "__main__":
    sys.exit(main())
