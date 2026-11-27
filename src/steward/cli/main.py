"""`opstend` controller CLI.

    ./opstend deploy --config ./config/server.yml --limit my-server

One call validates locally, runs a read-only remote preflight, checks for
conflicting revisions, shows the plan, applies after authorisation and verifies
the running result.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import re
import shlex
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

import yaml

from .. import __version__
from .. import release as release_tools
from ..core import canonical, render
from ..core.ai_auth import AUTH_METHODS
from ..core.config import Config, ConfigError, effective, load_config_file, parse_config
from ..core.pve_native import MODES, PROFILE, PreflightError, collect_preflight, install_plan
from ..core.retirement import retirement_lines
from ..core.secrets import (
    SecretError,
    check_env_value,
    generate_admin_token,
    resolve,
    validate_admin_token,
)

ROOT = Path(
    os.environ.get("OPSTEND_ROOT")
    or os.environ.get("STEWARD_ROOT")
    or Path(__file__).resolve().parents[3]
)
WORK = ROOT / ".steward"
RELEASE_DIR = ROOT / "dist" / "release"
EXIT_INVALID, EXIT_FAILED, EXIT_UNAVAILABLE, EXIT_CONFLICT, EXIT_DEGRADED = 2, 1, 3, 4, 5
RECAP = re.compile(
    r"^(\S+)\s*:\s*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)", re.M
)


class CliError(Exception):
    def __init__(self, message: str, code: int = EXIT_FAILED):
        super().__init__(message)
        self.code = code


def say(message: str = "") -> None:
    print(message, flush=True)


# ---- configuration ----------------------------------------------------------------


def load(args: argparse.Namespace) -> Config:
    try:
        cfg = load_config_file(Path(args.config))
    except ConfigError as exc:
        raise CliError(
            "configuration is invalid:\n  - " + "\n  - ".join(exc.problems), EXIT_INVALID
        ) from None
    if args.limit != cfg.server.name:
        raise CliError(
            f"--limit {args.limit!r} does not match server.name {cfg.server.name!r} in "
            f"{args.config}. Target must be unambiguous.",
            EXIT_INVALID,
        )
    return cfg


def check_secrets(cfg: Config) -> None:
    """Every reference must resolve now; values are checked but never stored or shown."""
    problems = []
    try:
        validate_admin_token(resolve(cfg.admin.token_ref))
    except SecretError as exc:
        problems.append(
            f"admin.token_ref: {exc} (create one with: opstend secrets init-admin-token)"
        )
    for endpoint in cfg.bot.endpoints:
        try:
            from ..adapters.queries import DiscordQuery, SignedQuery

            key = resolve(endpoint.verification_key_ref)
            if endpoint.adapter == "discord":
                DiscordQuery(key, endpoint.application_id)
            else:
                SignedQuery(key)
        except (SecretError, ValueError):
            problems.append(
                f"bot.endpoints[{endpoint.id}]: invalid or unavailable verification key"
            )
    for channel in cfg.channels:
        try:
            from ..adapters.notifications import DiscordWebhook, SignedWebhook

            url = resolve(channel.url_ref)
            if channel.adapter == "discord":
                DiscordWebhook(url)
            else:
                SignedWebhook(url, resolve(channel.signing_key_ref))
        except (SecretError, ValueError):
            problems.append(f"channels[{channel.id}]: invalid or unavailable credentials")
    if cfg.backup.enabled:
        if (
            cfg.backup.endpoint is None
            or not cfg.backup.repository_ref
            or not cfg.backup.password_ref
        ):
            problems.append(
                "backup.enabled: endpoint, repository_ref and password_ref are required"
            )
        else:
            try:
                from ..adapters.backups import credential_line, repository_for_endpoint
                from ..core.backups import BackupError

                repository_for_endpoint(
                    resolve(cfg.backup.repository_ref).encode(), cfg.backup.endpoint
                )
                credential_line(resolve(cfg.backup.password_ref).encode(), minimum=32)
                if cfg.backup.username_ref:
                    username = credential_line(resolve(cfg.backup.username_ref).encode())
                    if b":" in username:
                        raise BackupError("invalid_credentials")
                    credential_line(resolve(cfg.backup.auth_password_ref).encode())
                if cfg.backup.ca_ref:
                    ssl.create_default_context(cadata=resolve(cfg.backup.ca_ref))
            except (SecretError, BackupError, ValueError, OSError):
                problems.append("backup: target/credentials/CA are invalid or unavailable")
    for project in cfg.managed_projects:
        for secret in project.secrets:
            try:
                check_env_value(secret.name, resolve(secret.ref))
            except SecretError as exc:
                problems.append(f"projects[{project.id}].secrets: {exc}")
    if problems:
        raise CliError("secrets are not ready:\n  - " + "\n  - ".join(problems), EXIT_INVALID)


# ---- release ------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_release() -> dict[str, Any]:
    manifest_path = RELEASE_DIR / "manifest.json"
    if not manifest_path.is_file():
        raise CliError(
            f"no release found in {RELEASE_DIR}. Build one with: ./opstend release build"
        )
    manifest = json.loads(manifest_path.read_text())
    for name, expected in manifest["files"].items():
        path = RELEASE_DIR / name
        if not path.is_file() or sha256_file(path) != expected:
            raise CliError(f"release file {name} is missing or does not match the manifest")
    check_release_version(manifest["version"], local=True)
    return {**manifest, "dir": str(RELEASE_DIR)}


def check_release_version(version: str, *, local: bool = False) -> None:
    if version != __version__:
        hint = "; rebuild with: ./opstend release build" if local else ""
        raise CliError(f"release {version} does not match this CLI ({__version__}){hint}")


def cmd_release_build(args: argparse.Namespace) -> int:
    subset_path = Path(args.accepted_subset or ROOT / release_tools.DEFAULT_SUBSET)
    signing_ref = args.signing_key_ref or os.environ.get("STEWARD_RELEASE_SIGNING_KEY_REF")
    try:
        # Fail before the long build when subset or key are unusable.
        release_tools.load_accepted_subset(subset_path)
        signing_key = (
            release_tools.load_private_key(signing_ref, forbidden_root=ROOT)
            if signing_ref
            else None
        )
    except release_tools.ReleaseError as exc:
        raise CliError(str(exc), EXIT_INVALID) from None
    for tool in ("uv", "npm"):
        if not shutil.which(tool):
            raise CliError(f"release build needs {tool} on the controller")
    web = ROOT / "webapp"
    static = ROOT / "src" / "steward" / "api" / "static"
    subprocess.run(["npm", "ci", "--no-audit", "--no-fund"], cwd=web, check=True)
    subprocess.run(["npm", "run", "build"], cwd=web, check=True)
    shutil.rmtree(static, ignore_errors=True)
    shutil.copytree(web / "dist", static)
    shutil.rmtree(RELEASE_DIR, ignore_errors=True)
    RELEASE_DIR.mkdir(parents=True)
    subprocess.run(["uv", "build", "--wheel", "--out-dir", str(RELEASE_DIR)], cwd=ROOT, check=True)
    subprocess.run(
        [
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--no-emit-project",
            "--format",
            "requirements-txt",
            "--output-file",
            str(RELEASE_DIR / "requirements.txt"),
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    shutil.copytree(
        ROOT / "sample-app", RELEASE_DIR / "bundles", ignore=shutil.ignore_patterns("__pycache__")
    )
    for stray in RELEASE_DIR.glob(".gitignore"):
        stray.unlink()
    files = {
        str(p.relative_to(RELEASE_DIR)): sha256_file(p)
        for p in sorted(RELEASE_DIR.rglob("*"))
        if p.is_file()
    }
    wheel = next(name for name in files if name.endswith(".whl"))
    try:
        release_tools.finalize_release(
            RELEASE_DIR,
            version=__version__,
            files=files,
            wheel=wheel,
            root=ROOT,
            subset_path=subset_path,
            signing_key=signing_key,
        )
    except release_tools.ReleaseError as exc:
        raise CliError(f"release build failed: {exc}") from None
    say(f"release {__version__} built in {RELEASE_DIR} ({len(files)} files)")
    if signing_key is None:
        say("release is UNSIGNED: pass --signing-key-ref to sign; it will not verify")
    else:
        say(f"manifest signed with key {release_tools.key_id(signing_key.public_key())}")
    return 0


def cmd_release_verify(args: argparse.Namespace) -> int:
    try:
        trusted = release_tools.load_public_key(Path(args.public_key))
    except release_tools.ReleaseError as exc:
        raise CliError(str(exc), EXIT_INVALID) from None
    report = release_tools.verify_release(Path(args.target), trusted, allow_dirty=args.allow_dirty)
    for warning in report.warnings:
        say(f"warning: {warning}")
    if not report.ok:
        for problem in report.errors:
            print(f"error: {problem}", file=sys.stderr)
        say("release NOT verified")
        return EXIT_FAILED
    say(
        f"release {report.version} verified: signature by trusted key {report.key_id}, "
        f"{report.file_count} file hashes, SBOM and provenance consistent with the manifest; "
        f"accepted subset: {', '.join(report.features)}"
    )
    return 0


def cmd_release_pack(args: argparse.Namespace) -> int:
    manifest = RELEASE_DIR / "manifest.json"
    if not manifest.is_file():
        raise CliError(f"no release found in {RELEASE_DIR}. Build one first")
    version = json.loads(manifest.read_text())["version"]
    output = Path(args.output or ROOT / "dist" / f"opstend-release-{version}.tar.gz")
    try:
        digest = release_tools.pack_release(RELEASE_DIR, output)
    except (release_tools.ReleaseError, OSError) as exc:
        raise CliError(f"release pack failed: {exc}") from None
    say(f"archive {output} sha256 {digest}")
    return 0


def cmd_release_sign(args: argparse.Namespace) -> int:
    output = Path(args.output)
    try:
        report, digest = release_tools.sign_release_archive(
            Path(args.archive), output, signing_key_ref=args.signing_key_ref, forbidden_root=ROOT
        )
    except (release_tools.ReleaseError, OSError) as exc:
        raise CliError(f"release sign failed: {exc}") from None
    for warning in report.warnings:
        say(f"warning: {warning}")
    say(f"release {report.version} signed with key {report.key_id}")
    say(f"archive {output} sha256 {digest}")
    return 0


def cmd_release_keygen(args: argparse.Namespace) -> int:
    private = Path(args.private_out).expanduser().resolve()
    if private == ROOT.resolve() or ROOT.resolve() in private.parents:
        raise CliError("private key must be written outside the repository tree", EXIT_INVALID)
    try:
        fingerprint = release_tools.generate_keypair(private, Path(args.public_out))
    except OSError as exc:
        raise CliError(f"key generation failed: {exc.strerror}") from None
    say(f"key id {fingerprint}; private key {private} (0600), public key {args.public_out}")
    return 0


# ---- ansible ------------------------------------------------------------------------


def generated_dir(cfg: Config) -> Path:
    path = WORK / "generated" / cfg.server.name
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return Path(tempfile.mkdtemp(prefix="run-", dir=path))


def generate(
    cfg: Config,
    release: dict[str, Any] | None,
    ssh_port: int | None = None,
    *,
    out: Path | None = None,
) -> Path:
    """Render isolated invocation artifacts; rerender only within that invocation."""
    out = out if out is not None else generated_dir(cfg)
    host: dict[str, Any] = {
        "ansible_host": cfg.server.host,
        "ansible_port": cfg.server.port,
        "ansible_user": cfg.server.user,
    }
    ssh_args = ["-o StrictHostKeyChecking=yes"]
    if cfg.server.known_hosts_file:
        known = Path(cfg.server.known_hosts_file).expanduser().resolve()
        # Preserve the filename through Ansible's shlex split and OpenSSH's -o parser.
        filename = str(known).replace("\\", "\\\\").replace('"', '\\"')
        ssh_args.append("-o " + shlex.quote(f'UserKnownHostsFile="{filename}"'))
    host["ansible_ssh_common_args"] = " ".join(ssh_args)
    if os.environ.get("STEWARD_SSH_PRIVATE_KEY_FILE"):
        host["ansible_ssh_private_key_file"] = os.environ["STEWARD_SSH_PRIVATE_KEY_FILE"]
        # Offer only this key; agent keys tried first can exhaust sshd's MaxAuthTries.
        ssh_args.append("-o IdentitiesOnly=yes")
        host["ansible_ssh_common_args"] = " ".join(ssh_args)
    inventory = {"all": {"hosts": {cfg.server.name: host}}}
    (out / "inventory.yml").write_text(
        render.HEADER + "\n" + yaml.safe_dump(inventory, sort_keys=True)
    )
    release = release or {"version": __version__, "dir": "", "files": {}, "wheel": ""}
    # The firewall must open the port sshd listens on, which differs from
    # server.port behind NAT or a port forward. The preflight reports the real one.
    variables = render.render_vars(cfg, release=release, ssh_port=ssh_port or cfg.server.port)
    variables["steward_local_dir"] = str(out)
    vars_path = out / "vars.json"
    vars_path.write_text(json.dumps(variables, indent=1, sort_keys=True))
    vars_path.chmod(0o600)
    return out


def ansible(
    playbook: str, cfg: Config, out: Path, *, extra: list[str] | None = None, quiet: bool = False
) -> dict[str, int]:
    """Run a playbook from this release against exactly one host. Returns the recap."""
    env = {
        **os.environ,
        "ANSIBLE_CONFIG": str(ROOT / "ansible" / "ansible.cfg"),
        "ANSIBLE_CONNECTION_PLUGINS": str(ROOT / "ansible" / "connection_plugins"),
        "ANSIBLE_COLLECTIONS_PATH": str(WORK / "collections"),
        "ANSIBLE_HOST_KEY_CHECKING": "True",
        "ANSIBLE_NOCOWS": "1",
        "ANSIBLE_LOCAL_TEMP": str(WORK / "tmp"),
    }
    cmd = [
        str(Path(sys.executable).parent / "ansible-playbook"),
        "-i",
        str(out / "inventory.yml"),
        "--limit",
        cfg.server.name,
        "-e",
        f"@{out / 'vars.json'}",
        str(ROOT / "ansible" / "playbooks" / playbook),
        *(extra or []),
    ]
    # Keep the socket path short and private so each invocation checks its own host trust.
    with tempfile.TemporaryDirectory(prefix="stw-cp-", dir="/tmp") as control_dir:
        env["ANSIBLE_SSH_ARGS"] = (
            f"-C -o ControlMaster=auto -o ControlPersist=15s -o ControlPath={control_dir}/%C"
        )
        proc = subprocess.Popen(
            cmd,
            cwd=ROOT / "ansible",
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        lines = []
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.append(line)
            if not quiet:
                sys.stdout.write(line)
        proc.wait()
    output = "".join(lines)
    match = RECAP.search(output)
    recap = (
        dict(
            zip(
                ("ok", "changed", "unreachable", "failed"),
                map(int, match.groups()[1:]),
                strict=True,
            )
        )
        if match
        else {}
    )
    if proc.returncode != 0:
        if quiet:
            sys.stdout.write(output[-6000:])
        if "STEWARD_CONFIG_MOVED" in output:
            raise CliError(
                "the server's applied configuration changed during this deployment (for example "
                "an executor-applied revision); nothing was overwritten. Run "
                "`./opstend config pull`, review and deploy again",
                EXIT_CONFLICT,
            )
        raise CliError(f"{playbook} failed (exit {proc.returncode}); see output above")
    return recap


def become_args(args: argparse.Namespace) -> list[str]:
    return ["--ask-become-pass"] if getattr(args, "ask_become_pass", False) else []


def preflight(cfg: Config, out: Path, args: argparse.Namespace) -> dict[str, Any]:
    say("==> remote preflight (read-only)")
    extra = become_args(args)
    if operation := getattr(args, "resume_deployment", None):
        extra.extend(["-e", json.dumps({"steward_resume_deployment": operation})])
    ansible("preflight.yml", cfg, out, extra=extra, quiet=not args.verbose)
    state = json.loads((out / "remote-state.json").read_text())
    say(
        f"    ok: {state['architecture']}, kernel {state['kernel']}, "
        f"{state['memtotal_mb']} MB RAM, "
        f"{'existing OpsTend installation' if state['installed'] else 'fresh host'}"
    )
    return state


# ---- plan ---------------------------------------------------------------------------


def deployment_operation_id(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise argparse.ArgumentTypeError(
            "expected an exact 32-character lowercase hex operation ID"
        )
    return value


def exact_deployment_status(state: dict, operation: str) -> dict:
    receipt = state.get("deployment")
    patterns = {
        "operation_id": r"[0-9a-f]{32}",
        "run_id": r"[0-9a-f]{32}",
        "boot_id": r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
        "desired_revision": r"[0-9a-f]{64}",
        "base_revision": r"[0-9a-f]{64}",
        "release_hash": r"[0-9a-f]{64}",
        "state": r"pending|active|closing|revoked|complete",
    }
    if (
        not isinstance(receipt, dict)
        or receipt.keys() != patterns.keys()
        or receipt["operation_id"] != operation
        or any(
            not (isinstance(receipt[key], str) and re.fullmatch(pattern, receipt[key]))
            and not (
                receipt["state"] == "complete"
                and key in ("base_revision", "release_hash")
                and receipt[key] is None
            )
            for key, pattern in patterns.items()
        )
    ):
        raise CliError("invalid protected status for the requested deployment", EXIT_CONFLICT)
    return receipt


def check_exact_deployment(cfg: Config, state: dict, receipt: dict, release: dict) -> list[dict]:
    desired = effective(cfg)
    revision = canonical.revision_id(desired)
    binding = {key: release[key] for key in ("version", "files", "wheel")}
    if (
        revision != receipt["desired_revision"]
        or canonical.revision_id(binding) != receipt["release_hash"]
    ):
        raise CliError(
            "configuration or release manifest differs from the original deployment",
            EXIT_CONFLICT,
        )
    applied = state.get("applied")
    observed = canonical.revision_id(applied) if isinstance(applied, dict) else None
    boundaries = (receipt["base_revision"], revision)
    if observed not in boundaries:
        raise CliError(
            "the root desired revision differs from both original deployment revisions",
            EXIT_CONFLICT,
        )
    exported = state.get("head")
    if (
        not isinstance(exported, dict)
        or exported.keys() != {"head", "applied", "config"}
        or exported["head"] != exported["applied"]
        or exported["head"] not in boundaries
        or not isinstance(exported["config"], dict)
        or canonical.revision_id(exported["config"]) != exported["head"]
    ):
        raise CliError(
            "exact deployment recovery requires a consistent API export without a pending UI edit",
            EXIT_CONFLICT,
        )
    say(
        f"    deployment {receipt['operation_id']} ({receipt['state']}), "
        f"observed root revision {observed}"
    )
    return canonical.diff(applied, desired)


def local_state_path(cfg: Config) -> Path:
    return WORK / "state" / f"{cfg.server.name}.json"


def check_conflicts(cfg: Config, state: dict[str, Any], args: argparse.Namespace) -> list[dict]:
    """Compare the local revision with what the server applied and what is pending there."""
    local_rev = canonical.revision_id(effective(cfg))
    applied = state.get("applied")
    applied_rev = canonical.revision_id(applied) if applied else None
    exported = state.get("head") or {}
    head = exported.get("head")
    try:
        known = json.loads(local_state_path(cfg).read_text())["applied"]
    except (OSError, ValueError, KeyError):
        known = None
    # An interrupted apply can install this exact desired file before the old
    # API process observes it. Only accept its unchanged, previously known head;
    # an actual pending UI edit or inconsistent export still requires review.
    resumed = bool(
        head
        and head == exported.get("applied") == known
        and applied_rev == local_rev
        and isinstance(exported.get("config"), dict)
        and canonical.revision_id(exported["config"]) == head
    )
    reviewed_partial = getattr(args, "resume_from", None)
    if reviewed_partial is not None:
        if (
            not isinstance(reviewed_partial, str)
            or len(reviewed_partial) != 64
            or any(c not in "0123456789abcdef" for c in reviewed_partial)
            or reviewed_partial != applied_rev
            or head not in (known, applied_rev)
            or head != exported.get("applied")
            or not isinstance(exported.get("config"), dict)
            or canonical.revision_id(exported["config"]) != head
        ):
            raise CliError(
                "--resume-from requires the exact reviewed root desired revision and "
                "a consistent API export without a pending UI edit.",
                EXIT_CONFLICT,
            )
        resumed = True
    if (
        head
        and head not in (applied_rev, local_rev)
        and not getattr(args, "discard_pending", False)
        and not resumed
    ):
        raise CliError(
            f"the API exports configuration revision {head[:12]} that differs from this file "
            "and the root desired revision; this may be pending UI work or an interrupted apply.\n"
            f"Adopt it with: ./opstend config pull --config {args.config} --limit {args.limit}\n"
            "For a reviewed interrupted apply, bind --resume-from to the exact root desired hash; "
            "otherwise preserve or explicitly discard UI work with --discard-pending.",
            EXIT_CONFLICT,
        )
    if resumed and head != local_rev:
        say(
            "    resuming an interrupted apply: consistent API export and "
            + (
                "explicitly reviewed desired revision"
                if reviewed_partial
                else "known controller revision"
            )
        )
    if applied_rev and applied_rev not in (known, local_rev) and not resumed:
        # Also reached after the executor applied a verified image update: the file
        # would silently downgrade it. Never plan or deploy from a stale file.
        raise CliError(
            f"the server applied configuration revision {applied_rev[:12]}, which this file "
            "does not contain (another controller, or an executor-applied update).\n"
            f"Adopt it with: ./opstend config pull --config {args.config} --limit {args.limit} "
            "(restart steward-api first if the pull returns the old revision), review, then "
            "plan again.",
            EXIT_CONFLICT,
        )
    return canonical.diff(applied or {}, effective(cfg))


def show_plan(cfg: Config, changes: list[dict], state: dict[str, Any]) -> None:
    say(f"==> plan for {cfg.server.name} ({cfg.server.user}@{cfg.server.host}:{cfg.server.port})")
    say(
        f"    release {__version__}, configuration revision "
        f"{canonical.revision_id(effective(cfg))[:12]}, automation profile {cfg.automation.profile}"
    )
    for url in admin_lan_urls(cfg):
        say(f"    admin UI: {url}")
    if not state["installed"]:
        say("    first installation: base hardening, firewall, platform services, reverse proxy")
    elif state.get("initializing"):
        say("    resuming an incomplete installation owned by this server name")
    for project in cfg.projects:
        action = (
            "skip (manage: false)"
            if not project.manage
            else "stop, keep data (deploy: false)"
            if not project.deploy
            else "run"
        )
        say(f"    project {project.id}: {action}")
    for line in retirement_lines(state.get("applied") if state["installed"] else None, cfg):
        say(line)
    if not changes:
        say("    configuration: no changes against the applied revision")
    for change in changes[:200] if state["installed"] else []:
        old, new = change.get("old", "-"), change.get("new", "-")
        if "token_ref" in change["path"] or ".secrets" in change["path"]:
            old, new = "[reference]", "[reference]"
        say(f"    {change['change']:8} {change['path']}: {old!r} -> {new!r}")


def confirm(cfg: Config, args: argparse.Namespace) -> None:
    if args.yes:
        return
    if not sys.stdin.isatty():
        raise CliError("refusing to apply without confirmation; pass --yes for unattended runs")
    answer = input(f"Type the server name ({cfg.server.name}) to apply: ").strip()
    if answer != cfg.server.name:
        raise CliError("not confirmed; nothing was changed")


# ---- commands -----------------------------------------------------------------------


def admin_lan_urls(cfg: Config) -> list[str]:
    lan = cfg.admin.lan
    if lan is None or lan.bind is None:
        return []
    addresses = [lan.bind.ip]
    if lan.advertise_ipv4 is not None and lan.advertise_ipv4 != lan.bind.ip:
        addresses.append(lan.advertise_ipv4)
    return [f"https://{address}:{cfg.admin.port}" for address in addresses]


def resolve_admin_lan(cfg: Config, state: dict[str, Any]) -> Config:
    if cfg.admin.access != "private-lan" or (cfg.admin.lan and cfg.admin.lan.bind is not None):
        return cfg

    desired = effective(cfg)
    admin = desired["admin"]
    requested = admin.get("lan") or {}
    applied_admin = (state.get("applied") or {}).get("admin") or {}
    guidance = (
        "Set admin.lan.interface and admin.lan.bind explicitly, or set "
        "admin.access to private-loopback and use an SSH tunnel."
    )
    previously_lan = applied_admin.get("access") == "private-lan"
    pinned = applied_admin.get("lan") if previously_lan else None
    if (previously_lan and not (pinned and pinned.get("bind"))) or (
        state.get("installed") and not state.get("initializing") and not applied_admin
    ):
        raise CliError(
            "configuration is invalid: preflight could not read the applied admin scope. "
            + guidance,
            EXIT_INVALID,
        )
    # Apply the previous source scope and alias to the pin, even when the input
    # leaves them at their defaults.
    scope = pinned or requested
    candidates: dict[tuple[str, str], Config] = {}
    for row in state.get("admin_lan_candidates") or []:
        if not isinstance(row, dict):
            continue
        interface, bind = row.get("interface"), row.get("bind")
        if not isinstance(interface, str) or not isinstance(bind, str):
            continue
        admin["lan"] = {**scope, "interface": interface, "bind": bind}
        try:
            resolved = parse_config(desired)
        except ConfigError:
            continue
        lan = resolved.admin.lan
        candidates[(lan.interface, str(lan.bind))] = resolved

    if pinned:
        reused = candidates.get((pinned.get("interface"), pinned["bind"]))
        if reused is None or any(
            requested.get(key) and requested[key] != pinned.get(key)
            for key in ("allowed_sources", "advertise_ipv4")
        ):
            raise CliError(
                "configuration is invalid: the installed admin LAN scope cannot be reused. "
                + guidance,
                EXIT_INVALID,
            )
        return reused

    if len(candidates) == 1:
        return next(iter(candidates.values()))
    reason = "multiple usable" if candidates else "no usable"
    raise CliError(
        f"configuration is invalid: found {reason} private IPv4 admin LAN candidates. " + guidance,
        EXIT_INVALID,
    )


def cmd_validate(args: argparse.Namespace) -> int:
    cfg = load(args)
    check_secrets(cfg)
    generate(cfg, None)
    say(
        f"ok: {args.config} is valid (revision {canonical.revision_id(effective(cfg))[:12]}, "
        f"{len(cfg.managed_projects)} managed project(s))"
    )
    return 0


def prepare(
    args: argparse.Namespace, cfg: Config | None = None, release: dict[str, Any] | None = None
):
    cfg = cfg if cfg is not None else load(args)
    operation = getattr(args, "resume_deployment", None)
    if operation is None:
        check_secrets(cfg)
        if release is None:
            release = load_release()
    out = generate(cfg, release)
    state = preflight(cfg, out, args)
    if operation is not None:
        receipt = exact_deployment_status(state, operation)
        if receipt["state"] == "complete":
            return cfg, out, state
        if receipt["state"] in ("active", "closing"):
            raise CliError(
                f"deployment {operation} is {receipt['state']}. Review its exact status "
                "on the host and revoke the existing run only if the original deployment "
                "has been abandoned",
                EXIT_CONFLICT,
            )
        check_secrets(cfg)
        if release is None:
            release = load_release()
    cfg = resolve_admin_lan(cfg, state)
    generate(cfg, release, ssh_port=int(state["ssh_port"]), out=out)
    if operation is not None:
        changes = check_exact_deployment(cfg, state, receipt, release)
    else:
        changes = check_conflicts(cfg, state, args)
    show_plan(cfg, changes, state)
    return cfg, out, state


def cmd_plan(args: argparse.Namespace) -> int:
    cfg, out, state = prepare(args)
    if state["installed"]:
        say("==> file-level preview (check mode, no changes)")
        ansible("site.yml", cfg, out, extra=["--check", "--diff", *become_args(args)])
    else:
        say("    file-level preview is available once the host is installed")
    return 0


@contextmanager
def deployment_lock(cfg: Config):
    """Serialize this controller's deploys to one SSH endpoint, including preflight."""
    directory = WORK / "locks"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = canonical.revision_id({"host": cfg.server.host, "port": cfg.server.port})
    fd = os.open(directory / f"deploy-{key}.lock", os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise CliError(
                "another deployment from this controller is using this SSH target", EXIT_CONFLICT
            ) from None
        yield
    finally:
        os.close(fd)


def cmd_deploy(args: argparse.Namespace) -> int:
    from packaging.version import Version

    archive = args.release_archive
    public_key = args.release_public_key
    development = args.allow_unsigned_development_release
    if development and (archive is not None or public_key is not None):
        raise CliError(
            "--allow-unsigned-development-release cannot be combined with "
            "--release-archive or --release-public-key",
            EXIT_INVALID,
        )
    if (archive is None) != (public_key is None):
        raise CliError(
            "--release-archive and --release-public-key must be supplied together", EXIT_INVALID
        )
    if development:
        print("warning: allowing an unsigned local development release", file=sys.stderr)
    elif archive is None and Version(__version__) >= Version("0.1.0rc1"):
        raise CliError(
            "deploy requires --release-archive and --release-public-key from RC1", EXIT_INVALID
        )

    with ExitStack() as stack:
        release = None
        if archive is not None:
            try:
                trusted_key = release_tools.load_public_key(public_key)
                release = stack.enter_context(
                    release_tools.staged_verified_release(archive, trusted_key)
                )
            except release_tools.ReleaseError as exc:
                raise CliError(f"release verification failed: {exc}") from None
            check_release_version(release["version"])
        elif development:
            release = load_release()
        cfg = load(args)
        stack.enter_context(deployment_lock(cfg))
        return _deploy(args, cfg, release)


def _deploy(args: argparse.Namespace, cfg: Config, release: dict[str, Any] | None = None) -> int:
    cfg, out, state = prepare(args, cfg=cfg, release=release)
    operation = getattr(args, "resume_deployment", None)
    receipt = state["deployment"] if operation is not None else None
    if receipt is not None and receipt["state"] == "complete":
        say(
            f"==> verified completion receipt for deployment {operation}, "
            f"revision {receipt['desired_revision']}"
        )
        return 0
    vars_path = out / "vars.json"
    variables = json.loads(vars_path.read_text())
    prepared_release = variables["steward_release"]
    manifest_fingerprint = canonical.revision_id(
        {
            "version": prepared_release["version"],
            "files": prepared_release["files"],
        }
    )
    confirm(cfg, args)
    if receipt is not None:
        variables.update(
            steward_resume_deployment=operation,
            steward_base_revision=receipt["base_revision"],
            steward_observed_revision=canonical.revision_id(state["applied"]),
        )
    elif state.get("applied") is not None:
        variables["steward_base_revision"] = canonical.revision_id(state["applied"])
    if "steward_base_revision" in variables:
        vars_path.write_text(json.dumps(variables, indent=1, sort_keys=True))
    say("==> apply")
    try:
        recap = ansible("site.yml", cfg, out, extra=become_args(args))
    except CliError as exc:
        if operation is None:
            raise
        raise CliError(
            f"{exc}. Check or retry deployment {operation} with the same "
            "--resume-deployment option, configuration and release",
            exc.code,
        ) from None
    path = local_state_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(
                {
                    "applied": canonical.revision_id(effective(cfg)),
                    "release": __version__,
                    "manifest_fingerprint": manifest_fingerprint,
                },
                handle,
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)
    say(f"==> deployed and verified: changed={recap.get('changed', '?')}")
    for url in admin_lan_urls(cfg):
        say(f"    admin UI: {url}")
    say(
        f"    admin UI tunnel: ssh -N -p {cfg.server.port} "
        f"-L {cfg.admin.port}:127.0.0.1:{cfg.admin.port} "
        f"{cfg.server.user}@{cfg.server.host}  then open https://localhost:{cfg.admin.port}"
    )
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    cfg = load(args)
    out = generate(cfg, None)
    ansible("status.yml", cfg, out, extra=become_args(args), quiet=not args.verbose)
    status = json.loads((out / "status.json").read_text())
    if args.json:
        say(json.dumps(status, indent=2))
    degraded = print_status(status, canonical.revision_id(effective(cfg)))
    return EXIT_DEGRADED if degraded else 0


def print_status(status: dict[str, Any], local_rev: str) -> bool:
    problems = []
    say(
        f"release {status['release']}  revision {status['config_revision'][:12]}  "
        f"automation {status['automation_profile']}  kill switch "
        f"{'ON' if status['kill_switch'] else 'off'}"
    )
    if status["config_revision"] != local_rev:
        say("  note: the server runs a different configuration revision than this file")
    fw = status["firewall"]
    say(f"firewall: {'loaded' if fw['loaded'] else 'NOT LOADED' if fw['managed'] else 'unmanaged'}")
    if fw["managed"] and not fw["loaded"]:
        problems.append("firewall")
    for unit in [*status["platform_units"], status["proxy"]]:
        say(f"  {unit['unit']:32} {unit['active']}/{unit['sub']}")
        if unit["active"] != "active":
            problems.append(unit["unit"])
    for project_id, project in status["projects"].items():
        if not project["deploy"]:
            say(f"  project {project_id:24} stopped by configuration")
            continue
        health = project["health"]
        violations = project["hardening"]["violations"]
        say(
            f"  project {project_id:24} {project['unit']['active']}  health "
            f"{'ok' if health['ok'] else 'FAILED'}  isolation "
            f"{'ok' if not violations else 'DRIFT: ' + ', '.join(violations)}"
        )
        if project["unit"]["active"] != "active" or not health["ok"] or violations:
            problems.append(project_id)
    if status["reboot_required"]:
        say("  reboot required to finish installed updates")
    if status["failed_units"]:
        say("  failed units: " + ", ".join(status["failed_units"]))
    say("status: " + ("DEGRADED (" + ", ".join(problems) + ")" if problems else "ok"))
    return bool(problems)


def cmd_doctor(args: argparse.Namespace) -> int:
    say(f"opstend {__version__}, python {sys.version.split()[0]}")
    ansible_bin = Path(sys.executable).parent / "ansible-playbook"
    say(f"ansible-playbook: {'ok' if ansible_bin.exists() else 'MISSING (run ./opstend)'}")
    say(f"collections: {'ok' if (WORK / 'collections').is_dir() else 'MISSING (run ./opstend)'}")
    try:
        release = load_release()
        say(f"release: ok ({release['version']})")
    except CliError as exc:
        say(f"release: {exc}")
    cfg = load(args)
    say("configuration: ok")
    check_secrets(cfg)
    say("secret references: ok")
    preflight(cfg, generate(cfg, None), args)
    return 0


def make_private_dirs(directory: Path) -> None:
    """Create each missing directory with private permissions."""
    missing = []
    for path in (directory, *directory.parents):
        if path.is_dir():
            break
        missing.append(path)
    for path in reversed(missing):
        path.mkdir(mode=0o700, exist_ok=True)


def cmd_config_pull(args: argparse.Namespace) -> int:
    bootstrap = args.config is None
    if bootstrap:
        if not args.host or not args.user or not args.out:
            raise CliError("without --config, --host, --user and --out are required", EXIT_INVALID)
        try:
            cfg = parse_config(
                {
                    "schema_version": 1,
                    "server": {
                        "name": args.limit,
                        "host": args.host,
                        "user": args.user,
                        "port": args.port,
                        "known_hosts_file": args.known_hosts_file,
                    },
                    "admin": {"token_ref": "env:STEWARD_ADMIN_TOKEN"},
                }
            )
        except ConfigError as exc:
            raise CliError(str(exc), EXIT_INVALID) from None
    else:
        if args.host or args.user or args.known_hosts_file or args.port != 22:
            raise CliError("connection options belong to pulls without --config", EXIT_INVALID)
        cfg = load(args)
    if args.out and os.path.lexists(args.out):
        raise CliError("configuration output already exists", EXIT_CONFLICT)
    out = generate(cfg, None)
    ansible("config-pull.yml", cfg, out, extra=become_args(args), quiet=not args.verbose)
    state = json.loads((out / "remote-state.json").read_text())
    head = state.get("head") or {}
    if not head.get("config"):
        raise CliError("the server has no configuration revision to pull")
    if canonical.revision_id(head["config"]) != head.get("head"):
        raise CliError("server configuration revision does not match its content", EXIT_CONFLICT)
    try:
        pulled = parse_config(head["config"])
    except ConfigError as exc:
        raise CliError(f"server configuration is invalid: {exc}", EXIT_INVALID) from None
    if pulled.server.name != cfg.server.name:
        raise CliError("server configuration belongs to another server", EXIT_CONFLICT)
    data = effective(pulled)
    data["server"] = effective(cfg)["server"]
    if not bootstrap:
        data["admin"]["token_ref"] = cfg.admin.token_ref
    target = Path(args.out or args.config)
    if target.is_symlink():
        raise CliError("refusing to replace a symlink", EXIT_INVALID)
    make_private_dirs(target.parent)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=target.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(yaml.safe_dump(data, sort_keys=False))
            handle.flush()
            os.fsync(handle.fileno())
        if args.out:
            try:
                os.link(temporary, target)
            except FileExistsError:
                raise CliError("configuration output already exists", EXIT_CONFLICT) from None
        else:
            os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    say(f"wrote revision {head['head'][:12]} to {target}; review it, then run deploy")
    return 0


def cmd_init_token(args: argparse.Namespace) -> int:
    try:
        cfg = load_config_file(Path(args.config))
    except ConfigError as exc:
        raise CliError(
            "configuration is invalid:\n  - " + "\n  - ".join(exc.problems), EXIT_INVALID
        ) from None
    kind, _, target = cfg.admin.token_ref.partition(":")
    if kind != "file":
        raise CliError("admin.token_ref must be a file: reference to generate a token")
    try:
        generate_admin_token(Path(target), force=args.force)
    except SecretError as exc:
        raise CliError(str(exc)) from None
    say(
        f"admin token written to {Path(target).expanduser()} (mode 0600). It is not shown here; "
        "read the file when you log in. Deploy to activate it"
        + (" - all sessions are revoked." if args.force else ".")
    )
    return 0


def cmd_killswitch(args: argparse.Namespace) -> int:
    cfg = load(args)
    out = generate(cfg, None)
    ansible(
        "killswitch.yml",
        cfg,
        out,
        extra=["-e", f"steward_killswitch_state={args.state}", *become_args(args)],
    )
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    """Request the root-owned cadence-bound capture for one explicit project."""
    cfg = load(args)
    if not cfg.backup.enabled:
        raise CliError("scheduled backups are disabled; no capture was requested", EXIT_UNAVAILABLE)
    project = next((item for item in cfg.managed_projects if item.id == args.project), None)
    if not project or project.data_path is None or not project.maintenance.allow_backup_pause:
        raise CliError("project is not registered for scheduled backup", EXIT_INVALID)
    out = generate(cfg, None)
    revision = canonical.revision_id(effective(cfg))
    vars_path = out / "vars.json"
    variables = json.loads(vars_path.read_text())
    variables.update(steward_backup_project=project.id, steward_backup_expected_revision=revision)
    vars_path.write_text(json.dumps(variables, indent=1, sort_keys=True))
    vars_path.chmod(0o600)
    ansible("backup.yml", cfg, out, extra=become_args(args), quiet=not args.verbose)
    try:
        result = json.loads((out / "backup-result.json").read_text())
        if (
            not isinstance(result, dict)
            or result.get("project_id") != project.id
            or result.get("config_revision") != revision
            or result.get("uploaded") is not False
            or not isinstance(result.get("capture_id"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", result["capture_id"])
            or type(result.get("reused")) is not bool
        ):
            raise ValueError("unexpected response")
    except (OSError, ValueError, TypeError):
        raise CliError("backup response is unavailable or does not match the request") from None
    say(
        f"Capture {'reused' if result['reused'] else 'prepared'} for {project.id}: "
        f"{result['capture_id']}."
    )
    say("Upload and restore verification are not established by this request; check backup status.")
    return 0


def cmd_backup_receipt(args: argparse.Namespace) -> int:
    """Export one exact worker-reported receipt to a new private local file."""
    from ..core.backups import Receipt

    cfg = load(args)
    if not cfg.backup.enabled:
        raise CliError("scheduled backups are disabled; no receipt was requested", EXIT_UNAVAILABLE)
    project = next((item for item in cfg.managed_projects if item.id == args.project), None)
    if not project or project.data_path is None:
        raise CliError("project is not registered for backup", EXIT_INVALID)
    selection = {
        "config_revision": args.config_revision,
        "repository_id": args.repository_id,
        "capture_id": args.capture_id,
        "snapshot_id": args.snapshot_id,
    }
    if any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in selection.values()):
        raise CliError("receipt selection requires full SHA256 identifiers", EXIT_INVALID)
    target = Path(args.out).expanduser().absolute()
    if os.path.lexists(target):
        raise CliError("receipt output already exists", EXIT_CONFLICT)
    try:
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError:
        raise CliError("receipt output directory is unavailable", EXIT_INVALID) from None
    out = generate(cfg, None)
    vars_path = out / "vars.json"
    variables = json.loads(vars_path.read_text())
    variables["steward_backup_project"] = project.id
    variables.update({"steward_backup_" + key: value for key, value in selection.items()})
    vars_path.write_text(json.dumps(variables, indent=1, sort_keys=True))
    vars_path.chmod(0o600)
    response_path = out / "backup-receipt-result.json"
    try:
        ansible("backup-receipt.yml", cfg, out, extra=become_args(args), quiet=not args.verbose)
        fd = os.open(response_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_nlink != 1
                or info.st_size > 65536
            ):
                raise ValueError("unsafe receipt response")
            with os.fdopen(os.dup(fd), "rb") as handle:
                raw = handle.read(65537)
            after = os.fstat(fd)
            if len(raw) > 65536 or (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("receipt response changed")
            payload = json.loads(raw)
        finally:
            os.close(fd)
        if (
            not isinstance(payload, dict)
            or set(payload) != {"receipt", "provenance", "production_restore_authorized"}
            or payload["provenance"] != "worker_reported"
            or payload["production_restore_authorized"] is not False
        ):
            raise ValueError("invalid receipt response")
        receipt = Receipt.model_validate(payload["receipt"])
        if (
            receipt.capture.binding.server != cfg.server.name
            or receipt.capture.binding.project != project.id
            or receipt.capture.binding.config_revision != selection["config_revision"]
            or receipt.repository_id != selection["repository_id"]
            or receipt.capture.id != selection["capture_id"]
            or receipt.snapshot_id != selection["snapshot_id"]
            or receipt.integrity_checked_at is None
            or receipt.restore_verified_at is None
        ):
            raise ValueError("receipt binding mismatch")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=target.parent, mode="w", encoding="utf-8", delete=False
            ) as handle:
                temporary = Path(handle.name)
                json.dump(receipt.model_dump(mode="json"), handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, target, follow_symlinks=False)
            parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    except FileExistsError:
        raise CliError("receipt output already exists", EXIT_CONFLICT) from None
    except (OSError, ValueError, TypeError, KeyError):
        raise CliError("backup receipt unavailable or does not match the selection") from None
    finally:
        response_path.unlink(missing_ok=True)
    say(
        f"wrote worker-reported backup receipt to {target}; "
        "this does not authorize production recovery"
    )
    return 0


def _private_restore_document(path: Path, model):
    """Read a bounded operator-owned document without following links."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or info.st_size > 65536
        ):
            raise ValueError("unsafe restore document")
        with os.fdopen(os.dup(fd), "rb") as handle:
            raw = handle.read(65537)
        after = os.fstat(fd)
        if len(raw) > 65536 or (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("restore document changed")
        return model.model_validate_json(raw)
    finally:
        os.close(fd)


def cmd_restore_test(args: argparse.Namespace) -> int:
    """Run a bound sample-app drill locally, without replacing production data."""
    from ..adapters.backups import Restic, line_secret, repository_for_endpoint, secret_file
    from ..core.backups import BackupError, FilesystemCapture, Receipt, digest_file
    from ..restore_drill import (
        SOURCE_REVISION,
        SOURCE_SHA256,
        DrillSpec,
        PodmanSample,
        run_drill,
        validate_report,
    )

    if os.geteuid() == 0:
        raise CliError("restore-test must run as an unprivileged user", EXIT_INVALID)
    cfg = load(args)
    if not cfg.backup.enabled:
        raise CliError(
            "scheduled backups are disabled; no restore test was started", EXIT_UNAVAILABLE
        )
    if cfg.backup.endpoint is None:
        raise CliError("backup endpoint is not configured", EXIT_INVALID)
    project = next((item for item in cfg.managed_projects if item.id == args.project), None)
    if not project or project.data_path is None or project.bundle != "sample-notes":
        raise CliError("project is not registered for the sample restore drill", EXIT_INVALID)
    if args.ask_become_pass:
        raise CliError("restore-test runs locally without privilege escalation", EXIT_INVALID)
    selection = {
        "config_revision": args.config_revision,
        "repository_id": args.repository_id,
        "capture_id": args.capture_id,
        "snapshot_id": args.snapshot_id,
    }
    if any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in selection.values()):
        raise CliError("restore selection requires full SHA256 identifiers", EXIT_INVALID)
    target = args.out.expanduser().absolute()
    if os.path.lexists(target):
        raise CliError("restore evidence output already exists", EXIT_CONFLICT)
    try:
        receipt = _private_restore_document(args.receipt.expanduser(), Receipt)
        spec = _private_restore_document(args.spec.expanduser(), DrillSpec)
        if (
            not isinstance(receipt.capture, FilesystemCapture)
            or receipt.capture.binding.server != cfg.server.name
            or receipt.capture.binding.project != project.id
            or receipt.capture.binding.config_revision != selection["config_revision"]
            or receipt.repository_id != selection["repository_id"]
            or receipt.capture.id != selection["capture_id"]
            or receipt.snapshot_id != selection["snapshot_id"]
            or receipt.integrity_checked_at is None
            or spec.repository_id != receipt.repository_id
            or spec.snapshot_id != receipt.snapshot_id
            or spec.capture_id != receipt.capture.id
            or spec.binding != receipt.capture.binding
            or spec.binding.source_revision != SOURCE_REVISION
            or spec.app_sha256 != SOURCE_SHA256
            or digest_file(args.app.expanduser(), max_bytes=1024 * 1024)[0] != spec.app_sha256
        ):
            raise BackupError("evidence_mismatch")
        encryption_password = line_secret(args.password_file.expanduser(), minimum=32)
        reader_password = line_secret(args.reader_password_file.expanduser())
        if hmac.compare_digest(encryption_password, reader_password):
            raise BackupError("invalid_credentials")
        repository_for_endpoint(secret_file(args.repository_file.expanduser()), cfg.backup.endpoint)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        adapter = Restic(
            repository_file=args.repository_file.expanduser(),
            password_file=args.password_file.expanduser(),
            username_file=args.reader_username_file.expanduser(),
            auth_password_file=args.reader_password_file.expanduser(),
            ca_file=args.ca_file.expanduser() if args.ca_file else None,
            state_dir=args.state_dir.expanduser(),
            binary=args.restic_binary.expanduser() if args.restic_binary else None,
            endpoint=cfg.backup.endpoint,
            read_only=True,
        )
        report = run_drill(adapter, receipt, spec, args.app.expanduser(), PodmanSample())
        validate_report(report, receipt, spec)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=target.parent, mode="w", encoding="utf-8", delete=False
            ) as handle:
                temporary = Path(handle.name)
                json.dump(report, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, target, follow_symlinks=False)
            parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    except FileExistsError:
        raise CliError("restore evidence output already exists", EXIT_CONFLICT) from None
    except BackupError as exc:
        raise CliError(f"restore test failed: {exc.error_class}") from None
    except (OSError, ValueError, TypeError, KeyError):
        raise CliError("restore test input or local state is invalid") from None
    say(
        f"wrote isolated restore evidence to {target}; "
        "fresh VM and production recovery are not proven"
    )
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    """Return one applied verified update to its previous image through the executor."""
    cfg = load(args)
    project = next((item for item in cfg.managed_projects if item.id == args.project), None)
    if project is None or project.update is None:
        raise CliError(
            "project has no verified update contract; there is nothing to roll back",
            EXIT_UNAVAILABLE,
        )
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", args.approval_id) or not re.fullmatch(
        r"sha256:[a-f0-9]{64}", args.digest
    ):
        raise CliError("approval id or digest is malformed", EXIT_INVALID)
    out = generate(cfg, None)
    vars_path = out / "vars.json"
    variables = json.loads(vars_path.read_text())
    variables.update(
        steward_rollback_project=project.id,
        steward_rollback_approval=args.approval_id,
        steward_rollback_digest=args.digest,
        steward_rollback_restore=bool(args.acknowledge_data_restore),
    )
    vars_path.write_text(json.dumps(variables, indent=1, sort_keys=True))
    vars_path.chmod(0o600)
    ansible("rollback.yml", cfg, out, extra=become_args(args), quiet=not args.verbose)
    try:
        result = json.loads((out / "rollback-result.json").read_text())
        if (
            not isinstance(result, dict)
            or result.get("project_id") != project.id
            or result.get("approval_id") != args.approval_id
            or result.get("state") != "rolled_back"
            or not isinstance(result.get("image"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", str(result.get("config_revision")))
            or not isinstance(result.get("verified"), dict)
            or result["verified"].get("image_verified") is not True
        ):
            raise ValueError("unexpected response")
    except (OSError, ValueError, TypeError):
        raise CliError(
            "rollback response is unavailable or does not match the request; "
            "check `opstend status` before retrying"
        ) from None
    revision = result["config_revision"]
    say(f"Rolled back {project.id} to {result['image']} (configuration {revision}).")
    if result.get("preserved_data"):
        say(
            "Data written since the update was preserved on the server as "
            f"{result['preserved_data']} and is not live; nothing was deleted."
        )
    say("Pending web UI revisions were not touched; adopt the applied state with `config pull`.")
    return 0


def cmd_config_apply(args: argparse.Namespace) -> int:
    """Apply the exact reviewed pending UI revision through the executor (L10)."""
    cfg = load(args)
    for value in (args.head,):
        if not re.fullmatch(r"[a-f0-9]{64}", value):
            raise CliError("--head must be a full 64-digit revision", EXIT_INVALID)
    out = generate(cfg, None)
    ansible("config-pull.yml", cfg, out, extra=become_args(args), quiet=not args.verbose)
    head = json.loads((out / "remote-state.json").read_text()).get("head") or {}
    if head.get("head") != args.head or not re.fullmatch(r"[a-f0-9]{64}", str(head.get("applied"))):
        raise CliError(
            f"the server head is {str(head.get('head'))[:12]}, not the reviewed {args.head[:12]}; "
            "review the pending revision again",
            EXIT_CONFLICT,
        )
    applied = head["applied"]
    if applied == args.head:
        raise CliError("the head revision is already applied; nothing to do")
    variables = json.loads((out / "vars.json").read_text())
    variables.update(steward_apply_head=args.head, steward_apply_applied=applied)
    (out / "vars.json").write_text(json.dumps(variables, indent=1, sort_keys=True))
    (out / "vars.json").chmod(0o600)
    ansible("config-apply.yml", cfg, out, extra=become_args(args), quiet=not args.verbose)
    try:
        result = json.loads((out / "config-apply-result.json").read_text())
        if (
            not isinstance(result, dict)
            or result.get("state") not in ("applied", "already_applied")
            or result.get("config_revision") != args.head
            or result.get("verified") is not True
        ):
            raise ValueError("unexpected response")
    except (OSError, ValueError, TypeError):
        raise CliError(
            "apply response is unavailable or does not match the request; "
            "check `opstend status` before retrying"
        ) from None
    say(f"Applied revision {args.head[:12]} on the server ({result['state']}).")
    say(
        "The server configuration changed: run `./opstend config pull` to adopt it into your "
        "file before the next `plan`/`deploy`. Unused update approvals bound to the old "
        "revision are no longer valid."
    )
    return 0


def cmd_ai(args: argparse.Namespace) -> int:
    """Run the root-owned host login entry point in an interactive SSH session (A04)."""
    from . import ai_login

    cfg = load(args)
    if args.ai_action != "status" and not args.method:
        raise CliError("--method is required", EXIT_INVALID)
    return ai_login.run(cfg, args.ai_action, args.method, relogin=args.relogin)


def cmd_pve_native(args: argparse.Namespace) -> int:
    try:
        result = collect_preflight(
            mode=args.mode,
            api_name=args.api_name,
            ca_file=args.ca_file,
            token_file=args.token_file,
        )
    except PreflightError as exc:
        raise CliError(str(exc), EXIT_INVALID) from None
    if args.pve_command == "plan":
        result["install_plan"] = install_plan(args.mode)
    say(json.dumps(result, indent=2))
    return 0 if result["ready"] else EXIT_UNAVAILABLE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opstend", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    def target(name: str, func, help_text: str) -> argparse.ArgumentParser:
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("--config", required=True, help="path to the server configuration")
        cmd.add_argument("--limit", required=True, help="server name; must match server.name")
        cmd.add_argument("--ask-become-pass", "-K", action="store_true")
        cmd.add_argument("--verbose", "-v", action="store_true")
        cmd.set_defaults(func=func)
        return cmd

    target("validate", cmd_validate, "validate configuration and secret references locally")
    for name, func, text in (
        ("plan", cmd_plan, "preflight, conflict check and preview"),
        ("deploy", cmd_deploy, "validate, preflight, plan, apply, verify"),
    ):
        cmd = target(name, func, text)
        cmd.add_argument(
            "--yes",
            action="store_true",
            help="apply without prompt; never unlocks blocked migrations or conflicts",
        )
        recovery = cmd.add_mutually_exclusive_group()
        recovery.add_argument(
            "--discard-pending",
            action="store_true",
            help="overwrite a pending web UI revision on the server",
        )
        recovery.add_argument(
            "--resume-from",
            metavar="DESIRED_SHA256",
            help="resume a reviewed interrupted desired revision; never discards UI edits",
        )
        if name == "deploy":
            cmd.add_argument("--release-archive", type=Path, help="signed release .tar.gz archive")
            cmd.add_argument("--release-public-key", type=Path, help="trusted Ed25519 public PEM")
            cmd.add_argument(
                "--allow-unsigned-development-release",
                action="store_true",
                help="allow the local dist/release build without signature verification",
            )
            recovery.add_argument(
                "--resume-deployment",
                type=deployment_operation_id,
                metavar="OPERATION_ID",
                help="resume a guarded deployment with its original configuration and release",
            )
    status = target("status", cmd_status, "verified status of the running platform")
    status.add_argument("--json", action="store_true")
    target("doctor", cmd_doctor, "check controller environment and target")
    kill = target("killswitch", cmd_killswitch, "stop or resume automatic mutations")
    kill.add_argument("state", choices=["on", "off", "status"])
    backup = target("backup", cmd_backup, "request one scheduled project capture")
    backup.add_argument("--project", required=True, help="registered project ID")
    receipt = target("backup-receipt", cmd_backup_receipt, "export one exact completed receipt")
    receipt.add_argument("--project", required=True, help="registered project ID")
    for option in ("config-revision", "repository-id", "capture-id", "snapshot-id"):
        receipt.add_argument("--" + option, required=True, help="full SHA256 identifier")
    receipt.add_argument("--out", required=True, help="new private output file")
    restore = target(
        "restore-test", cmd_restore_test, "run a bound local isolated application drill"
    )
    restore.add_argument("--project", required=True, help="registered sample project ID")
    for option in ("config-revision", "repository-id", "capture-id", "snapshot-id"):
        restore.add_argument("--" + option, required=True, help="full SHA256 identifier")
    for option in (
        "receipt",
        "spec",
        "app",
        "repository-file",
        "password-file",
        "reader-username-file",
        "reader-password-file",
        "state-dir",
        "out",
    ):
        restore.add_argument("--" + option, type=Path, required=True)
    restore.add_argument("--ca-file", type=Path)
    restore.add_argument("--restic-binary", type=Path)
    rollback = target(
        "rollback", cmd_rollback, "return one applied verified update to its previous image"
    )
    rollback.add_argument("--project", required=True, help="registered project ID")
    rollback.add_argument("--approval-id", required=True, help="approval of the applied update")
    rollback.add_argument("--digest", required=True, help="sha256:<hex> digest of that update")
    rollback.add_argument(
        "--acknowledge-data-restore",
        action="store_true",
        help="allow the exact data restore a migrating update needs; newer data is preserved",
    )

    ai = target(
        "ai", cmd_ai, "guided AI login over SSH (the credential never reaches this machine)"
    )
    ai.add_argument("ai_action", choices=["login", "status", "check", "revoke"])
    ai.add_argument("--method", choices=sorted(AUTH_METHODS))
    ai.add_argument("--relogin", action="store_true", help="replace a valid credential")

    config = sub.add_parser("config", help="configuration revisions")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    pull = config_sub.add_parser("pull", help="fetch the server's head revision into a file")
    pull.add_argument("--config", help="existing local configuration, if available")
    pull.add_argument("--host", help="SSH host for restoring a fresh checkout")
    pull.add_argument("--user", help="SSH user for restoring a fresh checkout")
    pull.add_argument("--port", type=int, default=22)
    pull.add_argument("--known-hosts-file")
    pull.add_argument("--limit", required=True)
    pull.add_argument("--out")
    pull.add_argument("--ask-become-pass", "-K", action="store_true")
    pull.add_argument("--verbose", "-v", action="store_true")
    pull.set_defaults(func=cmd_config_pull)

    apply = config_sub.add_parser(
        "apply", help="apply the reviewed pending web UI revision on the server"
    )
    apply.add_argument("--config", required=True)
    apply.add_argument("--limit", required=True)
    apply.add_argument("--head", required=True, help="the full pending head revision you reviewed")
    apply.add_argument("--ask-become-pass", "-K", action="store_true")
    apply.add_argument("--verbose", "-v", action="store_true")
    apply.set_defaults(func=cmd_config_apply)

    secrets = sub.add_parser("secrets", help="secret setup")
    secrets_sub = secrets.add_subparsers(dest="secrets_command", required=True)
    token = secrets_sub.add_parser("init-admin-token", help="generate the admin token file")
    token.add_argument("--config", required=True)
    token.add_argument("--force", action="store_true", help="rotate an existing token")
    token.set_defaults(func=cmd_init_token)

    pve = sub.add_parser("pve-native", help=f"inspect the local Proxmox VE host ({PROFILE})")
    pve_sub = pve.add_subparsers(dest="pve_command", required=True)
    for name, help_text in (
        ("preflight", "check compatibility and readiness for the native profile"),
        ("plan", "check readiness and show the prospective native installation"),
    ):
        command = pve_sub.add_parser(name, help=help_text)
        command.add_argument("--mode", required=True, choices=MODES)
        command.add_argument("--api-name", required=True, help="TLS name on the PVE certificate")
        command.add_argument("--ca-file", required=True, type=Path, help="trusted PVE CA file")
        command.add_argument("--token-file", required=True, type=Path, help="0600 PVE token file")
        command.set_defaults(func=cmd_pve_native)

    release = sub.add_parser("release", help="release tooling")
    release_sub = release.add_subparsers(dest="release_command", required=True)
    build = release_sub.add_parser(
        "build", help="build wheel, lock file, SBOM, provenance, manifest"
    )
    build.add_argument(
        "--accepted-subset", help="accepted feature subset (default: release/accepted-subset.yml)"
    )
    build.add_argument(
        "--signing-key-ref",
        help="reference to the Ed25519 signing key, file:/path (0600, outside the repository) "
        "or env:NAME; without it the release is unsigned",
    )
    build.set_defaults(func=cmd_release_build)
    verify = release_sub.add_parser("verify", help="verify a release directory or archive")
    verify.add_argument("target", help="release directory or .tar.gz archive")
    verify.add_argument("--public-key", required=True, help="trusted Ed25519 public key (PEM)")
    verify.add_argument(
        "--allow-dirty",
        action="store_true",
        help="warn instead of failing for builds from a dirty tree",
    )
    verify.set_defaults(func=cmd_release_verify)
    pack = release_sub.add_parser(
        "pack", help="pack the built release into a deterministic archive"
    )
    pack.add_argument("--output")
    pack.set_defaults(func=cmd_release_pack)
    sign = release_sub.add_parser("sign", help="sign an already-built release archive offline")
    sign.add_argument("archive", help="unsigned release .tar.gz archive")
    sign.add_argument("--output", required=True, help="new signed release archive")
    sign.add_argument(
        "--signing-key-ref",
        required=True,
        help="explicit Ed25519 key reference, file:/path (0600, outside the repository) "
        "or env:NAME",
    )
    sign.set_defaults(func=cmd_release_sign)
    keygen = release_sub.add_parser(
        "keygen", help="generate a signing key pair outside the repository"
    )
    keygen.add_argument("--private-out", required=True)
    keygen.add_argument("--public-out", required=True)
    keygen.set_defaults(func=cmd_release_keygen)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        sys.exit(args.func(args))
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(exc.code)
    except subprocess.CalledProcessError as exc:
        print(f"error: command failed: {' '.join(map(str, exc.cmd))}", file=sys.stderr)
        sys.exit(EXIT_FAILED)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
