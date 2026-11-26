#!/usr/bin/env python3
"""Own one disposable Proxmox VM, with pinned source and guarded fresh-OS resets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tarfile
import uuid
from pathlib import Path


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def digest(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def write_private(path, body):
    path.write_text(body)
    path.chmod(0o600)


def recorded_uuid(value):
    """Extract one canonical UUID from a recorded Proxmox SMBIOS value."""
    try:
        values = [
            part.removeprefix("uuid=") for part in value.split(",") if part.startswith("uuid=")
        ]
        if len(values) != 1:
            raise ValueError("invalid VM UUID")
        return str(uuid.UUID(values[0]))
    except (TypeError, ValueError, AttributeError):
        raise RuntimeError("invalid recorded VM UUID") from None


def owned_pair(source, target):
    """Check distinct recorded node-side VM identities and disks without mutation."""
    first, second = source.state, target.state
    if recorded_uuid(first.get("smbios1")) == recorded_uuid(second.get("smbios1")) or (
        first.get("node"),
        first.get("vmid"),
    ) == (second.get("node"), second.get("vmid")):
        raise RuntimeError("source and target must be distinct recorded VMs")
    return source.owned_config(), target.owned_config()


GUEST_MEASURE = """
import json,os,pathlib,shutil,subprocess
memory={}
for line in pathlib.Path('/proc/meminfo').read_text().splitlines():
 key,value=line.split(':',1); memory[key]=int(value.strip().split()[0])*1024
units=['steward-'+name+'.service' for name in ['executor','api','controller','collector','notifier','bot','scanner']]
p=subprocess.run(['systemctl','show',*units,'-p','Id','-p','ActiveState','-p','SubState','-p','NRestarts','-p','MemoryCurrent','-p','CPUUsageNSec','-p','MainPID'],capture_output=True,text=True,check=True)
services=[]
for block in p.stdout.strip().split('\\n\\n'):
 item=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
 pid=int(item.get('MainPID','0'))
 if pid:
  for line in pathlib.Path('/proc/'+str(pid)+'/status').read_text().splitlines():
   if line.startswith('VmRSS:'): item['main_rss_bytes']=int(line.split()[1])*1024
 services.append(item)
disk=shutil.disk_usage('/')
print(json.dumps({'cpus':os.cpu_count(),'kernel':os.uname().release,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'uptime_s':float(pathlib.Path('/proc/uptime').read_text().split()[0]),'load':os.getloadavg(),'memory_bytes':{k:memory[k] for k in ['MemTotal','MemAvailable','MemFree']},'root_disk_bytes':{'total':disk.total,'used':disk.used,'free':disk.free},'services':services}))
"""

GUEST_IDENTITY = """\
import json,pathlib
print(json.dumps({
    'uuid': pathlib.Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower(),
    'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip().lower(),
}))
"""

GUEST_RESTORE_INSPECT = """\
import json,os,pathlib,pwd,subprocess,sys
image=sys.argv[1]
paths=('/etc/steward','/opt/steward','/srv/steward','/var/lib/steward-executor',
       '/var/lib/steward-backup','/var/lib/steward-backup-import')
accounts=[entry.pw_name for entry in pwd.getpwall()
          if entry.pw_name.startswith(('steward-', 'stw-'))]
def output(*args):
 return subprocess.check_output(args,text=True,timeout=30).strip()
unit_lines=output('/usr/bin/systemctl','list-unit-files','--no-legend','--plain').splitlines()
active_lines=output('/usr/bin/systemctl','list-units','--all','--no-legend','--plain').splitlines()
if not unit_lines or not active_lines: raise ValueError('unit enumeration unavailable')
units=[line for line in unit_lines+active_lines
       if any(part.startswith('steward-') for part in line.split())]
containers=json.loads(output('/usr/bin/podman','ps','--all','--format','json'))
if not isinstance(containers,list): raise ValueError('invalid container enumeration')
digests=json.loads(output('/usr/bin/podman','image','inspect','--format',
                          '{{json .RepoDigests}}',image))
print(json.dumps({
 'uuid': output('/usr/bin/sudo','-n','/usr/bin/cat','/sys/class/dmi/id/product_uuid').lower(),
 'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip().lower(),
 'uid': os.getuid(), 'platform_paths_absent': all(not os.path.lexists(path) for path in paths),
 'platform_accounts_absent': not accounts, 'platform_units_absent': not units,
 'container_count': len(containers),
 'rootless': output('/usr/bin/podman','info','--format','{{.Host.Security.Rootless}}') == 'true',
 'image_present': isinstance(digests,list) and image in digests,
}))
"""


class Harness:
    def __init__(self, work):
        self.work = work.resolve()
        self.record = self.work / "ownership.json"
        self.state = json.loads(self.record.read_text())
        self.ssh = [
            "ssh",
            "-F",
            self.state["ssh_config"],
            "-o",
            "StrictHostKeyChecking=yes",
            self.state["alias"],
        ]

    def save(self):
        write_private(self.record, json.dumps(self.state, indent=2) + "\n")

    def remote(self, *argv, check=True):
        result = subprocess.run(
            self.ssh + [shlex.join(map(str, argv))], capture_output=True, text=True, timeout=900
        )
        if check and result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())
        return result

    def config(self):
        result = self.remote(
            "pvesh",
            "get",
            f"/nodes/{self.state['node']}/qemu/{self.state['vmid']}/config",
            "--output-format",
            "json",
            check=False,
        )
        if result.returncode:
            # Confirm absence explicitly; transport/API failures must not mean "free".
            self.remote("test", "!", "-e", f"/etc/pve/qemu-server/{self.state['vmid']}.conf")
            return None
        return json.loads(result.stdout)

    def owned_config(self):
        """Read and validate this VM's recorded identity without changing the host."""
        return self._verify_owned_config(self.config(), operation="operation")

    def _verify_owned_config(self, config, *, operation):
        if not config:
            raise RuntimeError(f"Owned VM missing; refusing {operation}")
        s = self.state
        if not s.get("smbios1") or config.get("smbios1") != s["smbios1"]:
            raise RuntimeError(f"VM UUID differs; refusing {operation}")
        if config.get("name") != s["name"] or s["tag"] not in config.get("tags", "").split(";"):
            raise RuntimeError(f"VM name/tag differs; refusing {operation}")
        disks = {
            k: v
            for k, v in config.items()
            if k != "scsihw"
            and k.startswith(("scsi", "sata", "ide", "virtio", "unused", "efidisk", "tpmstate"))
        }
        if disks != s.get("disks"):
            raise RuntimeError(f"VM disks differ; refusing {operation}")
        return config

    def guest_identity(self, expected_boot):
        """Check the guest UUID and a previously recorded boot over a fresh pinned SSH connection."""
        try:
            boot = str(uuid.UUID(expected_boot))
            guest_uuid = recorded_uuid(self.state["smbios1"])
            port = int(self.state["local_port"])
            if not 1024 <= port <= 65535:
                raise ValueError("invalid guest port")
        except (KeyError, TypeError, ValueError, AttributeError):
            raise RuntimeError("invalid recorded guest identity") from None
        self.owned_config()
        command = self._guest_command(port, "sudo -n /usr/bin/python3 -")
        result = run(command, input=GUEST_IDENTITY, text=True, capture_output=True, timeout=30)
        try:
            facts = json.loads(result.stdout)
            if set(facts) != {"uuid", "boot_id"} or (
                str(uuid.UUID(facts["uuid"])) != guest_uuid
                or str(uuid.UUID(facts["boot_id"])) != boot
            ):
                raise ValueError("guest identity mismatch")
        except (ValueError, TypeError, KeyError, AttributeError):
            raise RuntimeError("guest UUID or boot does not match the recorded VM") from None
        return {"uuid": guest_uuid, "boot_id": boot}

    def _guest_command(self, port, remote):
        return [
            "ssh",
            "-F",
            "/dev/null",
            "-S",
            "none",
            "-i",
            self.state["identity"],
            "-p",
            str(port),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "UserKnownHostsFile=" + str(self.work / "known_hosts"),
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ConnectTimeout=10",
            "deploy@127.0.0.1",
            remote,
        ]

    def guest_restore_preflight(self, expected_boot, image):
        """Check known platform remnants and pinned rootless runtime on the recorded guest."""
        if (
            not isinstance(image, str)
            or len(image) > 512
            or not re.fullmatch(r"[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}", image)
        ):
            raise RuntimeError("invalid pinned restore image")
        identity = self.guest_identity(expected_boot)
        remote = shlex.join(["/usr/bin/python3", "-c", GUEST_RESTORE_INSPECT, image])
        command = self._guest_command(int(self.state["local_port"]), remote)
        result = run(command, text=True, capture_output=True, timeout=90)
        try:
            facts = json.loads(result.stdout)
            flags = (
                "platform_paths_absent",
                "platform_accounts_absent",
                "platform_units_absent",
                "rootless",
                "image_present",
            )
            if (
                not isinstance(facts, dict)
                or set(facts) != {"uuid", "boot_id", "uid", "container_count", *flags}
                or str(uuid.UUID(facts["uuid"])) != identity["uuid"]
                or str(uuid.UUID(facts["boot_id"])) != identity["boot_id"]
                or type(facts["uid"]) is not int
                or facts["uid"] <= 0
                or type(facts["container_count"]) is not int
                or facts["container_count"] != 0
                or any(facts[flag] is not True for flag in flags)
            ):
                raise ValueError("restore preflight mismatch")
        except (ValueError, TypeError, KeyError, AttributeError):
            raise RuntimeError("guest restore preflight failed") from None
        return facts

    def provision(self, reset=False):
        s = self.state
        vmid = str(s["vmid"])
        if digest(s["base"]) != s["base_sha256"]:
            raise RuntimeError("Local base checksum changed")
        config = self.config()
        if config:
            if not reset:
                raise RuntimeError("VMID occupied; use reset only for the recorded owned VM")
            self._verify_owned_config(config, operation="reset")
            # Prove the available recovery image before touching the running VM.
            remote_base = s["remote_dir"] + "/base.img"
            if (
                not self.remote("test", "-f", remote_base, check=False).returncode
                and self.remote("sha256sum", remote_base).stdout.split()[0] != s["base_sha256"]
            ):
                raise RuntimeError("Remote base checksum differs")
            self.remote("qm", "shutdown", vmid, "--timeout", "60", check=False)
            status = json.loads(
                self.remote(
                    "pvesh",
                    "get",
                    f"/nodes/{s['node']}/qemu/{vmid}/status/current",
                    "--output-format",
                    "json",
                ).stdout
            )
            if status["status"] != "stopped":
                self.remote("qm", "stop", vmid)
            self.remote("qm", "destroy", vmid, "--purge", "1")
        elif reset:
            raise RuntimeError("Owned VM missing; refusing reset")
        self.remote("test", "!", "-e", f"/etc/pve/lxc/{vmid}.conf")
        listeners = self.remote("ss", "-H", "-ltn").stdout.splitlines()
        if any(line.split()[3].rsplit(":", 1)[-1] == str(s["remote_port"]) for line in listeners):
            raise RuntimeError("Requested loopback forwarding port occupied")
        self.remote("mkdir", "-m", "700", "-p", s["remote_dir"])
        remote_base = s["remote_dir"] + "/base.img"
        if self.remote("test", "-f", remote_base, check=False).returncode:
            with Path(s["base"]).open("rb") as handle:
                run(
                    self.ssh + ["umask 077; cat > " + shlex.quote(remote_base)],
                    stdin=handle,
                    timeout=900,
                )
        if self.remote("sha256sum", remote_base).stdout.split()[0] != s["base_sha256"]:
            raise RuntimeError("Remote base checksum differs")
        iso_volume = s["iso_storage"] + ":iso/steward-acceptance-" + s["token"] + ".iso"
        iso_path = self.remote("pvesm", "path", iso_volume).stdout.strip()
        with (self.work / "seed.iso").open("rb") as handle:
            run(self.ssh + ["umask 077; cat > " + shlex.quote(iso_path)], stdin=handle, timeout=120)
        self.remote(
            "qm",
            "create",
            vmid,
            "--name",
            s["name"],
            "--tags",
            s["tag"],
            "--description",
            "Disposable Steward acceptance " + s["token"],
            "--cores",
            str(s["cores"]),
            "--memory",
            str(s["memory"]),
            "--cpu",
            "host",
            "--kvm",
            "1",
            "--machine",
            "q35",
            "--ostype",
            "l26",
            "--scsihw",
            "virtio-scsi-pci",
            "--serial0",
            "socket",
            "--vga",
            "serial0",
            "--onboot",
            "0",
            "--args",
            "-netdev user,id=stewardnet,hostfwd=tcp:127.0.0.1:"
            + str(s["remote_port"])
            + "-:22 -device virtio-net-pci,netdev=stewardnet",
        )
        self.remote("qm", "importdisk", vmid, remote_base, s["storage"], "--format", "raw")
        config = self.config()
        imported = {k: v for k, v in config.items() if k.startswith("unused")}
        if len(imported) != 1:
            raise RuntimeError("Unexpected imported volume set; inspect owned VM before continuing")
        volume = next(iter(imported.values())).split(",")[0]
        if not volume.startswith(s["storage"] + ":vm-" + vmid + "-disk-"):
            raise RuntimeError("Imported volume does not belong to this VM")
        self.remote(
            "qm",
            "set",
            vmid,
            "--scsi0",
            volume + ",discard=on",
            "--ide2",
            iso_volume + ",media=cdrom",
            "--boot",
            "order=scsi0",
        )
        self.remote("qm", "resize", vmid, "scsi0", str(s["disk_gib"]) + "G")
        config = self.config()
        s.update(
            smbios1=config["smbios1"],
            disks={k: config[k] for k in ["scsi0", "ide2"]},
            status="provisioned",
        )
        self.save()
        self.remote("qm", "start", vmid)
        print(f"owned VM {vmid} started; connect the separate tunnel and wait for cloud-init")

    def tunnel(self):
        s = self.state
        return subprocess.call(
            self.ssh[:-1]
            + [
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ServerAliveInterval=15",
                "-N",
                "-L",
                f"127.0.0.1:{s['local_port']}:127.0.0.1:{s['remote_port']}",
                s["alias"],
            ],
        )

    def cli(self, arguments):
        s = self.state
        source = Path(s["source"])
        if (source / ".source-commit").read_text().strip() != s["commit"]:
            raise RuntimeError("Pinned source identity changed")
        env = os.environ.copy()
        env.update(
            STEWARD_ROOT=str(source),
            PYTHONPATH=str(source / "src"),
            STEWARD_SSH_PRIVATE_KEY_FILE=s["identity"],
            ANSIBLE_TIMEOUT="120",
            PYTHONUNBUFFERED="1",
            ANSIBLE_NOCOLOR="1",
        )
        return subprocess.call(
            [
                s["python"],
                "-m",
                "steward.cli.main",
                *arguments,
                "--config",
                str(self.work / "server.yml"),
                "--limit",
                s["server_name"],
            ],
            env=env,
        )

    def checks(self):
        s = self.state
        source = Path(s["source"])
        text = (source / "tests/integration/vm/checks.sh").read_text()
        text = text.replace(
            'ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"', "ROOT=" + shlex.quote(str(source))
        )
        text = text.replace("--limit steward-vm", "--limit " + s["server_name"])
        text = text.replace("-p 2222", "-p " + str(s["local_port"]))
        target = self.work / "checks.sh"
        target.write_text(text)
        # Only target/transport adaptations; retain original acceptance assertions.
        env = os.environ.copy()
        env["STEWARD_SSH_PRIVATE_KEY_FILE"] = s["identity"]
        return subprocess.call(
            ["bash", str(target), str(self.work), str(self.work / "server.yml")], env=env
        )

    def measure(self):
        s = self.state
        command = [
            "ssh",
            "-i",
            s["identity"],
            "-p",
            str(s["local_port"]),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + str(self.work / "known_hosts"),
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "deploy@127.0.0.1",
            "sudo /usr/bin/python3 -",
        ]
        result = run(command, input=GUEST_MEASURE, text=True, capture_output=True, timeout=120)
        value = json.loads(result.stdout)
        value.update(commit=s["commit"], vmid=s["vmid"], server_name=s["server_name"])
        write_private(self.work / "measurements.json", json.dumps(value, indent=2) + "\n")
        print(json.dumps(value))


def initialize(args, work):
    import yaml  # available in the toolkit controller environment

    if not re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", args.server_name):
        raise ValueError("invalid server name")
    if not re.fullmatch(r"[A-Za-z0-9-]+", args.node):
        raise ValueError("invalid Proxmox node")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.alias):
        raise ValueError("invalid SSH alias")
    if args.name and not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9-]*", args.name):
        raise ValueError("invalid VM name")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", args.tag):
        raise ValueError("invalid ownership tag")
    if args.cores < 1 or args.memory < 512 or args.disk_gib < 4:
        raise ValueError("invalid VM resources")
    if not 100 <= args.vmid <= 999999999 or not all(
        1024 <= x <= 65535 for x in [args.local_port, args.remote_port]
    ):
        raise ValueError("invalid VMID or unprivileged forwarding port")
    base = args.base.resolve()
    if not re.fullmatch(r"[a-f0-9]{64}", args.base_sha256) or digest(base) != args.base_sha256:
        raise ValueError("verified Ubuntu base checksum mismatch")
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    seed = work / "seed"
    seed.mkdir(mode=0o700)
    token = uuid.uuid4().hex
    source = work / "source"
    source.mkdir()
    commit = subprocess.check_output(
        ["git", "-C", str(args.repo.resolve()), "rev-parse", args.commit + "^{commit}"], text=True
    ).strip()
    archive = subprocess.Popen(
        ["git", "-C", str(args.repo.resolve()), "archive", commit], stdout=subprocess.PIPE
    )
    with tarfile.open(fileobj=archive.stdout, mode="r|") as handle:
        handle.extractall(source, filter="data")
    if archive.wait():
        raise RuntimeError("cannot snapshot committed source")
    (source / ".source-commit").write_text(commit + "\n")
    (source / ".steward").mkdir()
    (source / ".steward/venv").symlink_to(args.venv.resolve())
    (source / ".steward/collections").symlink_to(args.collections.resolve())
    env = os.environ.copy()
    env.update(STEWARD_ROOT=str(source), PYTHONPATH=str(source / "src"))
    python = str(args.venv.resolve() / "bin/python")
    with (work / "release-build.log").open("w") as output:
        run(
            [python, "-m", "steward.cli.main", "release", "build"],
            env=env,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
    host_key = work / "guest_host_ed25519"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)])
    identity = args.identity.resolve()
    public_file = Path(str(identity) + ".pub")
    public = (
        public_file.read_text().strip()
        if public_file.is_file()
        else subprocess.check_output(
            ["ssh-keygen", "-y", "-f", str(identity)], text=True, stdin=subprocess.DEVNULL
        ).strip()
    )
    user_data = {
        "hostname": args.server_name,
        "users": [
            {
                "name": "deploy",
                "shell": "/bin/bash",
                "sudo": "ALL=(ALL) NOPASSWD:ALL",
                "lock_passwd": True,
                "ssh_authorized_keys": [public],
            }
        ],
        "ssh_pwauth": False,
        "ssh_keys": {
            "ed25519_private": host_key.read_text(),
            "ed25519_public": host_key.with_suffix(".pub").read_text().strip(),
        },
    }
    write_private(seed / "user-data", "#cloud-config\n" + yaml.safe_dump(user_data))
    (seed / "meta-data").write_text(
        yaml.safe_dump({"instance-id": "steward-" + token, "local-hostname": args.server_name})
    )
    with (work / "seed-build.log").open("w") as output:
        run(
            [
                "xorriso",
                "-as",
                "mkisofs",
                "-quiet",
                "-o",
                str(work / "seed.iso"),
                "-V",
                "cidata",
                "-J",
                "-r",
                str(seed / "user-data"),
                str(seed / "meta-data"),
            ],
            stdout=output,
            stderr=subprocess.STDOUT,
        )
    (work / "seed.iso").chmod(0o600)
    host_public = host_key.with_suffix(".pub").read_text().split()
    (work / "known_hosts").write_text(
        f"[127.0.0.1]:{args.local_port} {host_public[0]} {host_public[1]}\n"
    )
    (work / "id_test").symlink_to(identity)
    cfg = yaml.safe_load(args.config.read_text())
    cfg["server"].update(
        name=args.server_name,
        host="127.0.0.1",
        port=args.local_port,
        user="deploy",
        known_hosts_file=str(work / "known_hosts"),
    )
    write_private(work / "server.yml", yaml.safe_dump(cfg, sort_keys=False))
    state = {
        "vmid": args.vmid,
        "name": args.name or args.server_name,
        "tag": args.tag,
        "token": token,
        "ssh_config": str(args.ssh_config.resolve()),
        "alias": args.alias,
        "node": args.node,
        "source": str(source),
        "commit": commit,
        "python": python,
        "identity": str(identity),
        "server_name": args.server_name,
        "base": str(base),
        "base_sha256": args.base_sha256,
        "storage": args.storage,
        "iso_storage": args.iso_storage,
        "remote_dir": f"/var/tmp/steward-acceptance-{args.vmid}-{token}",
        "local_port": args.local_port,
        "remote_port": args.remote_port,
        "cores": args.cores,
        "memory": args.memory,
        "disk_gib": args.disk_gib,
    }
    write_private(work / "ownership.json", json.dumps(state, indent=2) + "\n")
    print("Private state prepared. Review host/VM inventory before provision.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    for name in ["ssh-config", "repo", "venv", "collections", "identity", "config", "base"]:
        init.add_argument("--" + name, type=Path, required=True)
    for name in ["alias", "node", "server-name", "commit", "base-sha256"]:
        init.add_argument("--" + name, required=True)
    for name in ["vmid", "local-port", "remote-port"]:
        init.add_argument("--" + name, type=int, required=True)
    init.add_argument("--cores", type=int, default=4)
    init.add_argument("--name")
    init.add_argument("--tag", default="steward-acceptance")
    init.add_argument("--memory", type=int, default=8192)
    init.add_argument("--disk-gib", type=int, default=24)
    init.add_argument("--storage", default="local-lvm")
    init.add_argument("--iso-storage", default="local")
    for command in ["provision", "reset", "tunnel", "checks", "measure"]:
        sub.add_parser(command)
    preflight = sub.add_parser("restore-preflight")
    preflight.add_argument("--boot-id", required=True, help="boot ID from the fresh-guest proof")
    preflight.add_argument("--image", required=True, help="exact digest-pinned restore image")
    cli = sub.add_parser("cli")
    cli.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    work = args.workdir.resolve()
    if args.command == "init":
        initialize(args, work)
        return 0
    harness = Harness(work)
    if args.command in ["provision", "reset"]:
        harness.provision(reset=args.command == "reset")
    elif args.command == "tunnel":
        return harness.tunnel()
    elif args.command == "checks":
        return harness.checks()
    elif args.command == "measure":
        harness.measure()
    elif args.command == "restore-preflight":
        print(json.dumps(harness.guest_restore_preflight(args.boot_id, args.image)))
    elif args.command == "cli":
        return harness.cli(args.arguments)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"proxmox acceptance: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
