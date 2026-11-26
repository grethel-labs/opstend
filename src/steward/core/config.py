"""Declarative configuration schema (version 1).

This model is the single source of the desired infrastructure state. CLI, API and
web UI all validate through it; Ansible only consumes artifacts rendered from it.

Every string that later ends up in a unit file, firewall rule or proxy route is
constrained by a strict pattern here, so rendering never has to escape free text.
"""

from __future__ import annotations

import heapq
import ipaddress
import re
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

SCHEMA_VERSION = 1
ROOT_EXAMPLES = Path(__file__).resolve().parents[3] / "examples"

# Features that exist in the schema but are not implemented in this release.
# Enabling one is a validation error: an enabled but non-functional service must
# never be reported as deployed.
UNAVAILABLE_FEATURES: dict[str, str] = {
    "profile.local-ai": "local Ollama installation (planned: stage 4)",
    "automation.patch": "autonomous updates (planned: stage 3)",
    "automation.repair": "autonomous code repair (planned: stage 5)",
    "ai.provider": "AI inference providers (planned: stage 4)",
    "backup.enabled": "Restic backups (planned: stage 3)",
    "applications": "application stacks (planned: lifecycle stage 3)",
    "repositories": "repository deployments (planned: stage 5, cards R01-R05)",
    "build": "isolated repository builds (planned: stage 5, card R03)",
    "maintenance.drills": "announced maintenance drills (planned: L11)",
    "projects.update": "verified image updates (planned: accepted with the L06 patch profile)",
    "applications.on_critical": (
        "per-application critical-risk response (exposure removal and quarantine, "
        "planned: accepted with milestone M4)"
    ),
    "admin.access.public": "public admin access (needs OIDC/MFA option, planned: stage 6)",
}

Slug = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")]
Hostname = Annotated[
    str,
    StringConstraints(
        max_length=253,
        pattern=r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
    ),
]
ImageRef = Annotated[
    str,
    StringConstraints(
        pattern=r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)+@sha256:[a-f0-9]{64}$"
    ),
]
EnvName = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")]
SecretRef = Annotated[
    str, StringConstraints(pattern=r"^(env:[A-Za-z_][A-Za-z0-9_]*|file:[^\x00\n]+)$")
]
UrlPath = Annotated[str, StringConstraints(pattern=r"^/[A-Za-z0-9._~/-]{0,200}$")]
CmdArg = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9@%+=:,./_-]{1,200}$")]

_REPO_HOST = r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?"
_REPO_SSH_USER = r"[a-z_][a-z0-9_-]{0,31}"
_REPO_PATH_CHARS = r"[A-Za-z0-9._~/-]"
_REPO_PATH_LIMIT = 200

RepoUrl = Annotated[
    str,
    StringConstraints(
        pattern=(
            rf"^(https://{_REPO_HOST}(:[0-9]{{1,5}})?"
            rf"|ssh://{_REPO_SSH_USER}@{_REPO_HOST}(:[0-9]{{1,5}})?)/"
            rf"{_REPO_PATH_CHARS}{{1,{_REPO_PATH_LIMIT}}}$"
        )
    ),
]
# Absolute paths cannot start with /~, which Git interprets as tilde-relative
# in ssh:// URLs. Ordinary relative paths need two characters for the ~/ prefix.
_SCP_REPO_URL_PATTERN = (
    rf"^{_REPO_SSH_USER}@{_REPO_HOST}:("
    rf"/[A-Za-z0-9._-]{_REPO_PATH_CHARS}{{0,{_REPO_PATH_LIMIT - 1}}}"
    rf"|~{_REPO_PATH_CHARS}{{0,{_REPO_PATH_LIMIT - 1}}}"
    rf"|[A-Za-z0-9._]{_REPO_PATH_CHARS}{{0,{_REPO_PATH_LIMIT - 3}}})$"
)
_SCP_REPO_URL = re.compile(_SCP_REPO_URL_PATTERN)
ScpRepoUrl = Annotated[str, StringConstraints(pattern=_SCP_REPO_URL_PATTERN)]

RepoRef = Annotated[
    str, StringConstraints(pattern=r"^refs/(heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]{0,120}$")
]
GitCommit = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
HostKeyLine = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^(ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ssh-rsa) "
            r"[A-Za-z0-9+/]{20,800}={0,2}$"
        )
    ),
]
RepoPath = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$", max_length=200)
]

RESERVED_PORTS = {8080, 8443}  # proxy entrypoints on the host
_RFC1918_NETWORKS = tuple(
    ipaddress.IPv4Network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Server(Model):
    name: Slug
    host: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")]
    port: int = Field(22, ge=1, le=65535)
    user: Annotated[str, StringConstraints(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")]
    os_profile: Literal["ubuntu-26.04"] = "ubuntu-26.04"
    known_hosts_file: str | None = Field(
        None, description="Defaults to the controller user's ~/.ssh/known_hosts."
    )


class Automation(Model):
    profile: Literal["observe", "patch", "repair"] = "observe"


def _admin_lan_source_cidr(value: Any) -> Any:
    if isinstance(value, ipaddress.IPv4Network):
        return value
    if not isinstance(value, str) or not re.fullmatch(r"[0-9.]+/[0-9]{1,2}", value):
        raise ValueError("admin LAN allowed_sources requires IPv4 CIDRs with prefix lengths")
    return value


class AdminLan(Model):
    interface: (
        Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")] | None
    ) = None
    bind: ipaddress.IPv4Interface | None = None
    allowed_sources: list[
        Annotated[ipaddress.IPv4Network, BeforeValidator(_admin_lan_source_cidr)]
    ] = Field(
        default_factory=list,
        max_length=32,
        description="Private source CIDRs. An empty list uses the bind network.",
        json_schema_extra={"uniqueItems": True},
    )
    advertise_ipv4: ipaddress.IPv4Address | None = None

    @field_validator("bind", mode="before")
    @classmethod
    def _bind_prefix(cls, value: Any) -> Any:
        if value is None or isinstance(value, ipaddress.IPv4Interface):
            return value
        if not isinstance(value, str) or not re.fullmatch(r"[0-9.]+/[0-9]{1,2}", value):
            raise ValueError("admin LAN bind requires an IPv4 address and prefix length")
        return value

    @field_validator("allowed_sources")
    @classmethod
    def _source_networks(cls, value: list[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
        if len(value) != len(set(value)):
            raise ValueError("admin LAN allowed_sources must be unique")
        if any(not any(source.subnet_of(block) for block in _RFC1918_NETWORKS) for source in value):
            raise ValueError("admin LAN allowed_sources must be within RFC1918")
        return value

    @field_validator("advertise_ipv4", mode="before")
    @classmethod
    def _alias_address(cls, value: Any) -> Any:
        if isinstance(value, ipaddress.IPv4Interface) or not isinstance(
            value, (str, ipaddress.IPv4Address, type(None))
        ):
            raise ValueError("admin LAN advertise_ipv4 requires an IPv4 address")
        return value

    @model_validator(mode="after")
    def _scope(self) -> AdminLan:
        if (self.interface is None) != (self.bind is None):
            raise ValueError("admin LAN interface and bind must be supplied together")
        if self.advertise_ipv4 is not None and not any(
            self.advertise_ipv4 in block for block in _RFC1918_NETWORKS
        ):
            raise ValueError("admin LAN advertise_ipv4 must be within RFC1918")
        if self.bind is not None:
            network = self.bind.network
            if not any(network.subnet_of(block) for block in _RFC1918_NETWORKS):
                raise ValueError("admin LAN bind network must be within RFC1918")
            if network.prefixlen < 31:
                endpoints = {network.network_address, network.broadcast_address}
                if self.bind.ip in endpoints or self.advertise_ipv4 in endpoints:
                    raise ValueError(
                        "admin LAN bind and advertise_ipv4 must be usable host addresses"
                    )
            if network.prefixlen == 32 and not self.allowed_sources:
                raise ValueError("admin LAN /32 bind requires explicit allowed_sources")
        return self


class Admin(Model):
    access: Literal["private", "private-loopback", "private-lan", "public"] = "private"
    hostname: Hostname = "localhost"
    port: int = Field(9443, ge=1024, le=65535, description="Admin TLS port on the host.")
    backend_port: int = Field(9080, ge=1024, le=65535)
    token_ref: SecretRef
    session_ttl_minutes: int = Field(480, ge=5, le=1440)
    lan: AdminLan | None = None

    @model_validator(mode="after")
    def _lan_access(self) -> Admin:
        if self.lan is not None and self.access != "private-lan":
            raise ValueError("admin.lan requires admin.access private-lan")
        return self


class Proxy(Model):
    image: ImageRef = (
        "docker.io/library/traefik@sha256:"
        "44b61e76a251fe586d17d881fc900452d0a7b4a4b08c97ce6eac86d45b4c8b9d"
    )
    image_version: str = Field("v3.7.19", pattern=r"^[A-Za-z0-9._-]{1,40}$")
    acme_email: Annotated[str, StringConstraints(pattern=r"^[^@\s\"']+@[^@\s\"']+$")] | None = None
    memory_mb: int = Field(192, ge=64, le=4096)


class SshHardening(Model):
    manage: bool = True
    password_authentication: bool = False
    permit_root_login: Literal["no", "prohibit-password"] = "prohibit-password"


class FirewallHardening(Model):
    manage: bool = True


class Journald(Model):
    system_max_use_mb: int = Field(500, ge=50, le=20000)
    retention_days: int = Field(30, ge=1, le=365)


class Hardening(Model):
    ssh: SshHardening = SshHardening()
    firewall: FirewallHardening = FirewallHardening()
    journald: Journald = Journald()
    unattended_security_upgrades: bool = True


class Route(Model):
    host: Hostname
    tls: Literal["acme", "internal"] = "acme"


class SecretBinding(Model):
    name: EnvName
    ref: SecretRef


class EgressRule(Model):
    proto: Literal["tcp", "udp"]
    cidr: str
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(min_length=1, max_length=16)

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v: str) -> str:
        if "%" in v:
            raise ValueError("egress CIDRs cannot contain an IPv6 scope identifier")
        return str(ipaddress.ip_network(v, strict=True))


class Egress(Model):
    """Outbound policy, enforced per service UID in nftables (IPv4 and IPv6).

    `public-web` allows DNS via the host resolver plus TCP 80/443 to public
    addresses. It is not a domain allowlist.
    """

    mode: Literal["none", "public-web", "rules"] = "none"
    rules: list[EgressRule] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def _rules(self) -> Egress:
        if self.mode != "rules" and self.rules:
            raise ValueError("egress.rules requires egress.mode 'rules'")
        if self.mode == "rules" and not self.rules:
            raise ValueError("egress.mode 'rules' needs at least one rule")
        return self


class Health(Model):
    path: UrlPath = "/healthz"
    interval_s: int = Field(30, ge=5, le=3600)
    timeout_s: int = Field(5, ge=1, le=60)
    retries: int = Field(3, ge=1, le=10)
    probe: Literal["http", "tcp", "container"] | None = Field(
        None,
        description=(
            "Probe kind; unset means http. tcp checks the loopback port accepts; "
            "container runs the image's own declared healthcheck."
        ),
    )
    max_response_ms: int | None = Field(
        None,
        ge=50,
        le=60000,
        description="A healthy answer slower than this counts as a hang.",
    )

    @model_validator(mode="after")
    def _threshold_within_timeout(self) -> Health:
        if self.max_response_ms is not None and self.max_response_ms >= self.timeout_s * 1000:
            raise ValueError("max_response_ms must be below the probe timeout")
        return self


class Resources(Model):
    memory_mb: int = Field(256, ge=16, le=1048576)
    cpus: float = Field(0.5, gt=0, le=256)
    pids: int = Field(128, ge=8, le=32768)
    log_burst: int = Field(
        10000, ge=100, le=1000000, description="Max log lines per 30 s before journald drops."
    )


Level = Literal["ephemeral_vm", "external_ci", "container_rootless"]


class BuildPolicy(Model):
    """Isolated repository builds (R03). The container tier is weaker than VM isolation."""

    minimum_isolation: Level | None = None
    allow_container_isolation: bool = Field(
        False,
        description=(
            "Permit the rootless dedicated-user build tier, labelled "
            "'container isolation, no VM protection' in all evidence."
        ),
    )
    package_sources: list[Hostname] = Field(
        default_factory=list,
        max_length=32,
        description="Hosts the build network may reach (package and base-image sources).",
    )
    timeout_s: int = Field(1800, ge=60, le=14400)
    memory_mb: int = Field(2048, ge=256, le=65536)
    cpus: float = Field(2.0, gt=0, le=64)
    pids: int = Field(512, ge=32, le=32768)
    disk_mb: int = Field(4096, ge=256, le=1048576)
    log_kb: int = Field(1024, ge=16, le=16384, description="Kept build output, kilobytes.")


class Maintenance(Model):
    allow_backup_pause: bool = Field(
        False, description="Permit the operator's registered backup capture to pause this workload."
    )
    allow_restart: bool = Field(
        True,
        description=(
            "Maintenance contract for restarts: lets the controller restart this service "
            "when it is down or unhealthy (budgeted, audited). Set false to exempt it."
        ),
    )


UpdateVersion = Annotated[str, StringConstraints(pattern=r"^[0-9]{1,6}(\.[0-9]{1,6}){0,3}$")]
ImageRepository = Annotated[
    str,
    StringConstraints(
        pattern=r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)+$"
    ),
]


class TrustedKey(Model):
    """Public Ed25519 key (raw 32 bytes, base64). Public material, never a secret."""

    id: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
    public_key: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9+/]{43}=$")]


class VersionRange(Model):
    min: UpdateVersion
    max: UpdateVersion

    @model_validator(mode="after")
    def _ordered(self) -> VersionRange:
        def key(text: str) -> tuple[int, ...]:
            return tuple(int(part) for part in text.split("."))

        low, high = key(self.min), key(self.max)
        width = max(len(low), len(high))
        pad = lambda value: value + (0,) * (width - len(value))  # noqa: E731
        if pad(low) > pad(high):
            raise ValueError("version range minimum exceeds its maximum")
        return self


DEFAULT_ROLLBACK_WINDOW_S = 1800
DEFAULT_MIN_HEALTHY_S = 1800


class UpdatePolicy(Model):
    """Root-owned contract for operator-verified image updates (ADR 0002 sections 3, 5, 8).

    Trust anchors live here, never in the artifact being validated: the image
    attestation must be signed by one of `signers` (independent test/signing
    identity) and the approval by one of `approvers`; the two sets must differ.
    """

    repository: ImageRepository = Field(
        description="Expected image repository; candidates from elsewhere are refused."
    )
    versions: VersionRange
    signers: list[TrustedKey] = Field(min_length=1, max_length=8)
    approvers: list[TrustedKey] = Field(min_length=1, max_length=8)
    allowed_migrations: list[Literal["none", "reversible", "restore_required"]] = Field(
        default_factory=lambda: ["none"],
        min_length=1,
        max_length=3,
        description="Data compatibility kinds an update may declare.",
    )
    require_scan: bool = True
    scan_max_age_s: int = Field(86400, ge=300, le=604800)
    backup_max_age_s: int = Field(3600, ge=60, le=604800)
    approval_max_ttl_s: int = Field(86400, ge=60, le=604800)
    apply_seconds: int = Field(
        600, ge=60, le=3600, description="Time the update needs; it must fit before window end."
    )
    verify_timeout_s: int = Field(120, ge=10, le=600)
    # Optional hardening settings (L06). Unset means the default and stays out of
    # canonical data, registries and policy revisions (see `canonical_dump`).
    rollback_window_s: int | None = Field(
        None,
        ge=0,
        le=86400,
        description=(
            "Window after apply in which the patch controller may roll back an update with "
            "migration `none` that became durably unhealthy (unset: 1800; 0: never)."
        ),
    )
    min_healthy_s: int | None = Field(
        None,
        ge=0,
        le=86400,
        description=(
            "The patch controller updates a service only after this much continuous "
            "health (unset: 1800; 0: healthy now)."
        ),
    )

    def canonical_dump(self) -> dict[str, Any]:
        """JSON form without the optional settings that are unset (stable revisions)."""
        data = self.model_dump(mode="json")
        for key in ("rollback_window_s", "min_healthy_s"):
            if data.get(key) is None:
                data.pop(key, None)
        return data

    @property
    def effective_rollback_window_s(self) -> int:
        return (
            DEFAULT_ROLLBACK_WINDOW_S if self.rollback_window_s is None else self.rollback_window_s
        )

    @property
    def effective_min_healthy_s(self) -> int:
        return DEFAULT_MIN_HEALTHY_S if self.min_healthy_s is None else self.min_healthy_s

    @model_validator(mode="after")
    def _separate_identities(self) -> UpdatePolicy:
        for keys in (self.signers, self.approvers):
            if len({k.id for k in keys}) != len(keys):
                raise ValueError("duplicate trusted key ids")
        if {k.public_key for k in self.signers} & {k.public_key for k in self.approvers}:
            raise ValueError("signers and approvers must be different identities")
        if len(set(self.allowed_migrations)) != len(self.allowed_migrations):
            raise ValueError("duplicate allowed migration")
        return self


class Project(Model):
    """Workload contract for one isolated service."""

    id: Slug
    manage: bool = Field(True, description="false: skip this project entirely.")
    deploy: bool = Field(True, description="false: stop the service, keep its data.")
    image: ImageRef
    source_revision: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9@:._/+-]{1,200}$")]
    bundle: Literal["sample-notes"] | None = Field(
        None, description="Mount an application shipped with the release read-only at /app."
    )
    command: list[CmdArg] = Field(default_factory=list, max_length=16)
    run_as: int = Field(10001, ge=1000, le=60000, description="UID/GID inside the container.")
    container_port: int = Field(8080, ge=1024, le=65535)
    host_port: int = Field(ge=20000, le=29999, description="Loopback port, proxy-only.")
    routes: list[Route] = Field(default_factory=list, max_length=8)
    secrets: list[SecretBinding] = Field(default_factory=list, max_length=32)
    egress: Egress = Egress()
    health: Health = Health()
    resources: Resources = Resources()
    data_path: UrlPath | None = Field("/data", description="Persistent data mount point.")
    maintenance: Maintenance = Maintenance()
    update: UpdatePolicy | None = Field(
        None,
        description="Verified image update contract (unavailable until patch acceptance).",
    )

    @model_validator(mode="after")
    def _checks(self) -> Project:
        names = [s.name for s in self.secrets]
        if len(names) != len(set(names)):
            raise ValueError("duplicate secret names")
        if self.bundle and not self.command:
            raise ValueError("bundle projects need an explicit command")
        return self

    @property
    def user(self) -> str:
        return f"stw-{self.id}"


class Service(Project):
    """Prepared service contract; dependencies are local to its application."""

    depends_on: list[Slug] = Field(default_factory=list, max_length=64)


def _validate_instruction_text(value: str) -> str:
    if any(ord(char) < 32 and char not in "\n\t" for char in value):
        raise ValueError("instruction must not contain control characters")
    return value


InstructionText = Annotated[
    str, StringConstraints(max_length=2000), AfterValidator(_validate_instruction_text)
]


class Application(Model):
    id: Slug
    isolation: Literal["shared", "separate"] = "separate"
    on_critical: Literal["quarantine", "notify"] | None = Field(
        None,
        description="Critical exposed finding response (unset: quarantine; ADR 0002 section 5).",
    )
    stateless: bool = Field(
        False,
        description=(
            "Explicit contract that the application keeps no data: containment may stop it "
            "without a backup. Not inferred from missing data; needs `data_path: null`."
        ),
    )
    services: list[Service] = Field(min_length=1, max_length=64)
    instruction: InstructionText | None = Field(
        None,
        description=(
            "Operator-authored application-wide goals for workload contract proposals. "
            "These goals take precedence over repository instructions and grant no authority "
            "to apply a proposal."
        ),
    )

    @model_validator(mode="after")
    def _graph(self) -> Application:
        by_id = {service.id: service for service in self.services}
        if len(by_id) != len(self.services):
            raise ValueError("duplicate service ids in application")
        if self.stateless and any(service.data_path is not None for service in self.services):
            raise ValueError("a stateless application cannot register data (data_path: null)")
        if self.isolation == "shared":
            ports = [service.container_port for service in self.services]
            if len(ports) != len(set(ports)):
                raise ValueError("shared application services need distinct container ports")
        for service in self.services:
            if len(service.depends_on) != len(set(service.depends_on)):
                raise ValueError("duplicate service dependencies")
            if service.id in service.depends_on:
                raise ValueError("service cannot depend on itself")
            if not set(service.depends_on) <= by_id.keys():
                raise ValueError("unknown service dependency")
        self.start_order()
        return self

    def start_order(self) -> list[str]:
        """Stable dependency-first order; reject cycles without recursion."""
        dependencies = {s.id: set(s.depends_on) for s in self.services}
        ready = [name for name, deps in dependencies.items() if not deps]
        heapq.heapify(ready)
        result = []
        while ready:
            name = heapq.heappop(ready)
            result.append(name)
            for other in sorted(dependencies):
                if name in dependencies[other]:
                    dependencies[other].remove(name)
                    if not dependencies[other]:
                        heapq.heappush(ready, other)
        if len(result) != len(dependencies):
            raise ValueError("application service dependency cycle")
        return result

    def stop_order(self) -> list[str]:
        return list(reversed(self.start_order()))

    def dependents(self, service_id: str) -> list[str]:
        if service_id not in {service.id for service in self.services}:
            raise ValueError("unknown service")
        affected = {service_id}
        for name in self.start_order():
            service = next(service for service in self.services if service.id == name)
            if affected.intersection(service.depends_on):
                affected.add(name)
        return [name for name in self.start_order() if name in affected and name != service_id]


def _clean_repo_path(value: str) -> str:
    """Repository-relative path: no traversal and nothing that names Git internals."""
    if value != "." and any(part in {".", "..", ".git"} for part in value.split("/")):
        raise ValueError("path must stay inside the repository")
    return value


def _clean_ref_name(value: str) -> str:
    """Reject sequences Git itself refuses and lock-file suffixes."""
    if (
        ".." in value
        or "//" in value
        or value.endswith(("/", ".", ".lock"))
        or any(part.startswith(".") or part.endswith(".lock") for part in value.split("/"))
    ):
        raise ValueError("invalid Git reference name")
    return value


class ContractBuild(Model):
    kind: Literal["dockerfile"] = "dockerfile"
    context: RepoPath = "."
    file: RepoPath = "Dockerfile"
    target: (
        Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")] | None
    ) = None

    @field_validator("context", "file")
    @classmethod
    def _inside_repository(cls, value: str) -> str:
        return _clean_repo_path(value)

    @model_validator(mode="after")
    def _file_in_context(self) -> ContractBuild:
        if self.context != "." and not self.file.startswith(self.context + "/"):
            raise ValueError("build.file must be inside build.context")
        return self


class ContractRequirements(Model):
    """What the workload asks of its isolation. Safe values are the defaults; the
    suitability check rejects the rest regardless of what a proposer claims."""

    read_only_rootfs: bool = True
    host_network: bool = False
    engine_socket: bool = False
    privileged: bool = False
    devices: list[Annotated[str, StringConstraints(pattern=r"^/dev/[A-Za-z0-9._/-]{1,60}$")]] = (
        Field(default_factory=list, max_length=8)
    )
    add_capabilities: list[Annotated[str, StringConstraints(pattern=r"^CAP_[A-Z_]{1,40}$")]] = (
        Field(default_factory=list, max_length=8)
    )
    production_secrets: list[EnvName] = Field(default_factory=list, max_length=16)


class ContractBackup(Model):
    strategy: Literal["none", "data-path", "database-dump"] = "none"
    database: Literal["postgres", "mysql", "sqlite"] | None = None

    @model_validator(mode="after")
    def _dump_needs_database(self) -> ContractBackup:
        if (self.strategy == "database-dump") != (self.database is not None):
            raise ValueError("backup.database is required for, and only for, database-dump")
        return self


class WorkloadContract(Model):
    """Typed contract for one repository-built service (operator- or proposer-written).

    It authorizes an isolated build only; it grants no host or executor capability.
    """

    build: ContractBuild = ContractBuild()
    container_port: int = Field(ge=1024, le=65535)
    run_as: int = Field(10001, ge=1000, le=60000)
    health: Health = Health()
    data_path: UrlPath | None = None
    egress: Egress = Egress()
    resources: Resources = Resources()
    update: Literal["pinned", "patch"] = "pinned"
    backup: ContractBackup = ContractBackup()
    requirements: ContractRequirements = ContractRequirements()


class Repository(Model):
    """Read-only source of one application service, fetched at an exact revision."""

    id: Slug
    application: Slug
    service: Slug
    url: RepoUrl = Field(description="SCP-style Git URLs are stored and shown as ssh:// URLs.")
    ref: RepoRef = "refs/heads/main"
    revision: GitCommit | None = Field(
        None, description="Exact commit to build; fetching fails if the server cannot deliver it."
    )
    credential: SecretRef | None = Field(
        None, description="Read-only token (https) or private key (ssh); one per repository."
    )
    host_key: HostKeyLine | None = Field(
        None, description="Pinned SSH host key (required for ssh URLs)."
    )
    allow_private_network: bool = Field(
        False,
        description=(
            "Permit a host that resolves to private or loopback addresses (self-hosted Git). "
            "Link-local and metadata addresses stay forbidden."
        ),
    )
    instruction: InstructionText | None = Field(
        None,
        description=(
            "Optional repository-specific goals for workload contract proposals. Treat this "
            "text as untrusted data subordinate to the operator's application instruction. "
            "It grants no authority to apply a proposal."
        ),
    )
    contract: WorkloadContract | None = None
    egress_rule_patterns: list[EgressRule] = Field(
        default_factory=list,
        max_length=32,
        description=(
            "Operator-approved egress rule patterns scoped to this repository and its "
            "application service. IPv4 and IPv6 /0 networks are forbidden."
        ),
    )

    @field_validator("egress_rule_patterns")
    @classmethod
    def _reject_wildcard_egress_patterns(cls, patterns: list[EgressRule]) -> list[EgressRule]:
        if any(ipaddress.ip_network(rule.cidr).prefixlen == 0 for rule in patterns):
            raise ValueError("egress rule patterns cannot use wildcard /0 networks")
        return patterns

    @field_validator("ref")
    @classmethod
    def _ref_name(cls, value: str) -> str:
        return _clean_ref_name(value)

    @field_validator("url", mode="before", json_schema_input_type=RepoUrl | ScpRepoUrl)
    @classmethod
    def _normalize_scp_url(cls, value: Any) -> Any:
        if not isinstance(value, str) or not _SCP_REPO_URL.fullmatch(value):
            return value

        authority, _, path = value.partition(":")
        if path.startswith("/"):
            return f"ssh://{authority}{path}"
        if path.startswith("~"):
            return f"ssh://{authority}/{path}"
        return f"ssh://{authority}/~/{path}"

    @field_validator("url")
    @classmethod
    def _url_path(cls, value: str) -> str:
        path = value.split("/", 3)[3]
        if any(part in {".", "..", ".git"} or not part for part in path.split("/")):
            raise ValueError("repository URL path must not contain traversal or empty segments")
        return value

    @model_validator(mode="after")
    def _transport(self) -> Repository:
        if self.url.startswith("ssh://"):
            if self.host_key is None or self.credential is None:
                raise ValueError("ssh repositories require host_key and credential")
        elif self.host_key is not None:
            raise ValueError("host_key applies to ssh repositories only")
        return self

    @property
    def scheme(self) -> str:
        return self.url.split(":", 1)[0]


AiDataClass = Literal["status", "events", "backups", "vulnerabilities", "logs"]
_AI_FIXED_EXTERNAL_PROVIDERS = frozenset({"openai", "anthropic", "ollama-cloud-api"})
AI_EXTERNAL_PROVIDERS = _AI_FIXED_EXTERNAL_PROVIDERS | {"openai-compatible"}
ModelName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")]


class AiScopeLimits(Model):
    """Per-window (UTC calendar month) limits for one budget scope; unset = not limited."""

    tokens: int | None = Field(None, ge=1, le=10**12)
    cost_micro: int | None = Field(None, ge=1, le=10**15)
    seconds: int | None = Field(None, ge=1, le=10**8)


class AiPrice(Model):
    """Operator-declared prices in budget-currency micro-units per million tokens."""

    input_per_mtok_micro: int = Field(ge=0, le=10**12)
    output_per_mtok_micro: int = Field(ge=0, le=10**12)


class AiBudget(Model):
    monthly: AiScopeLimits = AiScopeLimits()
    per_project: AiScopeLimits = AiScopeLimits()
    max_concurrent: int = Field(1, ge=1, le=8)
    price: AiPrice | None = None


class AiLocal(Model):
    """Operator-declared limits of the local model (checked before any download)."""

    download_mb: int = Field(ge=1, le=10**6)
    ram_mb: int = Field(ge=128, le=1048576)
    disk_mb: int = Field(ge=1, le=10**7)
    license_ack: bool = Field(False, description="The operator accepted the model's license.")
    device: Literal["cpu"] = "cpu"  # GPU access needs its own isolation checks


class AiModelPrice(Model):
    """Operator-declared price of one model with its date; stale prices block a switch."""

    model: ModelName
    input_per_mtok_micro: int = Field(ge=0, le=10**12)
    output_per_mtok_micro: int = Field(ge=0, le=10**12)
    as_of: Annotated[str, StringConstraints(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")]

    @field_validator("as_of")
    @classmethod
    def _date(cls, value: str) -> str:
        import datetime

        datetime.date.fromisoformat(value)
        return value


class AiModelPolicy(Model):
    """Selection rule (ADR 0002 section 2): families and an evaluation budget, not a model.

    The weekly selection (A05) only ever switches within the configured provider and data
    class; it never expands sharing or changes the provider."""

    families: list[Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,23}$")]] = Field(
        min_length=1, max_length=4
    )
    evaluate: Literal["weekly"] = "weekly"
    prices: list[AiModelPrice] = Field(default_factory=list, max_length=64)
    price_max_age_days: int = Field(35, ge=1, le=120)
    max_eval_tokens: int = Field(ge=1000, le=10**7)
    max_eval_cost_micro: int | None = Field(None, ge=1, le=10**15)

    @model_validator(mode="after")
    def _unique(self) -> AiModelPolicy:
        if len(set(self.families)) != len(self.families):
            raise ValueError("duplicate ai.model_policy family")
        if len({p.model for p in self.prices}) != len(self.prices):
            raise ValueError("duplicate ai.model_policy price")
        return self


ECB_FX_URL = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml"


class AiFx(Model):
    """Exchange rate between the price currency and the budget unit (decision 7).

    `operator`: the operator sets `rate_ppm` with its date. `fetched`: one fixed HTTPS source
    (`source_url`, fixed parser) is read inside the maintenance window. The automatic
    `ecb_daily_xml_v1` parser requires the exact ECB daily XML URL and returns EUR per USD.
    Automatic refresh requires `ai.local_only: false`. A rate older than `max_age_days`
    makes cost-limited reservations deny."""

    mode: Literal["operator", "fetched"]
    rate_ppm: int | None = Field(None, ge=1, le=10**12, description="1000000 = parity.")
    as_of: Annotated[str, StringConstraints(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")] | None = None
    source_url: (
        Annotated[str, StringConstraints(max_length=300, pattern=r"^https://[^\s]+$")] | None
    ) = None
    parser: Literal["json_rate_v1", "ecb_daily_xml_v1"] | None = Field(
        None, description=f"ecb_daily_xml_v1 requires source_url {ECB_FX_URL}."
    )
    max_age_days: int = Field(7, ge=1, le=90)

    @model_validator(mode="after")
    def _mode(self) -> AiFx:
        import datetime

        if self.as_of is not None:
            datetime.date.fromisoformat(self.as_of)
        if self.mode == "operator":
            if self.rate_ppm is None or self.as_of is None:
                raise ValueError("ai.fx mode operator needs rate_ppm and as_of")
            if self.source_url is not None or self.parser is not None:
                raise ValueError("ai.fx mode operator takes no source")
        else:
            if self.source_url is None or self.parser is None:
                raise ValueError("ai.fx mode fetched needs source_url and parser")
            if self.rate_ppm is not None or self.as_of is not None:
                raise ValueError("ai.fx mode fetched stores its rate at runtime, not here")
            if self.parser == "ecb_daily_xml_v1" and self.source_url != ECB_FX_URL:
                raise ValueError("ai.fx ECB parser requires the exact ECB daily XML URL")
            from .inference_endpoint import public_https_url

            if not public_https_url(self.source_url):
                raise ValueError("ai.fx.source_url must be a public https URL")
        return self


class Ai(Model):
    provider: Literal[
        "none", "ollama", "openai", "anthropic", "openai-compatible", "ollama-cloud-api"
    ] = "none"
    local_only: bool = True
    # Optional inference settings (A01-A03). They stay out of canonical revisions
    # while unset (see `effective`); the provider itself stays unavailable.
    model: ModelName | None = None
    api_key_ref: SecretRef | None = None
    base_url: (
        Annotated[str, StringConstraints(max_length=300, pattern=r"^https?://[^\s]+$")] | None
    ) = None
    share: list[AiDataClass] = Field(default_factory=list, max_length=5)
    budget: AiBudget | None = None
    local: AiLocal | None = None
    model_policy: AiModelPolicy | None = None
    fx: AiFx | None = None

    @model_validator(mode="after")
    def _provider_policy(self) -> Ai:
        extras = (
            self.model,
            self.api_key_ref,
            self.base_url,
            self.budget,
            self.local,
            self.model_policy,
            self.fx,
            self.share or None,
        )
        if self.provider == "none":
            if any(item is not None for item in extras):
                raise ValueError("ai settings require ai.provider")
            return self
        if self.model is None:
            raise ValueError("ai.provider requires an explicitly configured ai.model")
        if len(set(self.share)) != len(self.share):
            raise ValueError("duplicate ai.share data class")
        if self.model_policy is not None and self.provider not in ("openai", "anthropic"):
            raise ValueError("ai.model_policy needs a provider with a model family rule")
        if self.provider in _AI_FIXED_EXTERNAL_PROVIDERS:
            if self.api_key_ref is None:
                raise ValueError(f"ai.provider {self.provider} requires ai.api_key_ref")
            if self.base_url is not None:
                raise ValueError(f"ai.provider {self.provider} uses a fixed official endpoint")
        if self.local is not None and self.provider != "ollama":
            raise ValueError("ai.local applies to ollama only")
        if self.provider == "ollama":
            if self.api_key_ref is not None:
                raise ValueError("ai.provider ollama does not use an API key")
            if self.share:
                raise ValueError("ai.share applies to external providers only")
            if self.base_url is not None:
                from .inference_endpoint import loopback_url

                if not loopback_url(self.base_url, schemes=("http",)):
                    raise ValueError("ai.base_url for ollama must be an http loopback address")
        if self.provider == "openai-compatible":
            if self.base_url is None:
                raise ValueError("ai.provider openai-compatible requires ai.base_url")
            from .inference_endpoint import loopback_url, public_https_url

            if not (loopback_url(self.base_url) or public_https_url(self.base_url)):
                raise ValueError(
                    "ai.base_url must be an https URL without credentials or a loopback address"
                )
        if self.is_external:
            if self.local_only:
                raise ValueError("ai.local_only forbids an external provider")
            if not self.share:
                raise ValueError("an external ai.provider needs explicit ai.share data classes")
            if self.budget is None or self.budget.monthly.tokens is None:
                raise ValueError("an external ai.provider needs ai.budget.monthly.tokens")
        elif self.share:
            raise ValueError("ai.share applies to external providers only")
        if self.budget is not None:
            limits = (self.budget.monthly.cost_micro, self.budget.per_project.cost_micro)
            if any(v is not None for v in limits) and self.budget.price is None:
                raise ValueError(
                    "a cost budget needs ai.budget.price (unknown prices stay unknown)"
                )
        return self

    @property
    def is_external(self) -> bool:
        if self.provider in _AI_FIXED_EXTERNAL_PROVIDERS:
            return True
        if self.provider == "openai-compatible" and self.base_url is not None:
            from .inference_endpoint import loopback_url

            return not loopback_url(self.base_url)
        return False


class BackupEndpoint(Model):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(443, ge=1, le=65535)
    addresses: list[str] = Field(min_length=1, max_length=8)

    @field_validator("host")
    @classmethod
    def host_name(cls, value):
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            if (
                not re.fullmatch(
                    r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*",
                    value,
                )
                or value == "localhost"
                or value.endswith(".localhost")
            ):
                raise ValueError(
                    "backup endpoint needs a literal IP or constrained external hostname"
                ) from None
            return value

    @field_validator("addresses")
    @classmethod
    def pinned_addresses(cls, values):
        result = []
        for value in values:
            address = ipaddress.ip_address(value)
            if (
                address.is_loopback
                or address.is_link_local
                or address.is_unspecified
                or address.is_multicast
                or getattr(address, "ipv4_mapped", None)
                or getattr(address, "scope_id", None)
                or (address.version == 4 and (int(address) >> 24 == 0 or int(address) == 2**32 - 1))
            ):
                raise ValueError(
                    "backup target addresses must exclude local/metadata/multicast endpoints"
                )
            normalized = str(address)
            if normalized in result:
                raise ValueError("backup target addresses must be unique")
            result.append(normalized)
        return result

    @model_validator(mode="after")
    def literal_pin(self):
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError:
            return self
        if str(address) not in self.addresses:
            raise ValueError("literal backup host must match an explicitly pinned address")
        return self


class Backup(Model):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "allOf": [
                {
                    "if": {"properties": {"enabled": {"const": True}}, "required": ["enabled"]},
                    "then": {
                        "required": ["endpoint", "repository_ref", "password_ref"],
                        "properties": {
                            "endpoint": {"not": {"type": "null"}},
                            "repository_ref": {"not": {"type": "null"}},
                            "password_ref": {"not": {"type": "null"}},
                        },
                    },
                },
                {
                    "if": {
                        "properties": {"username_ref": {"type": "string"}},
                        "required": ["username_ref"],
                    },
                    "then": {
                        "required": ["auth_password_ref"],
                        "properties": {"auth_password_ref": {"type": "string"}},
                    },
                },
                {
                    "if": {
                        "properties": {"auth_password_ref": {"type": "string"}},
                        "required": ["auth_password_ref"],
                    },
                    "then": {
                        "required": ["username_ref"],
                        "properties": {"username_ref": {"type": "string"}},
                    },
                },
            ],
        },
    )
    enabled: bool = False
    interval_s: int = Field(86400, ge=3600, le=604800)
    max_mib: int = Field(256, ge=1, le=1024)
    endpoint: BackupEndpoint | None = None
    repository_ref: SecretRef | None = None
    password_ref: SecretRef | None = None
    username_ref: SecretRef | None = None
    auth_password_ref: SecretRef | None = None
    ca_ref: SecretRef | None = None

    @model_validator(mode="after")
    def auth_pair(self):
        if bool(self.username_ref) != bool(self.auth_password_ref):
            raise ValueError("backup REST username/auth password references must be paired")
        return self

    @property
    def secret_refs(self) -> dict[str, str]:
        return {
            name: ref
            for name, ref in (
                ("repository", self.repository_ref),
                ("password", self.password_ref),
                ("username", self.username_ref),
                ("auth-password", self.auth_password_ref),
                ("ca", self.ca_ref),
            )
            if ref is not None
        }


class Events(Model):
    """Bounded event log kept by the collector."""

    retention_days: int = Field(30, ge=1, le=365)
    max_events: int = Field(200_000, ge=1_000, le=5_000_000)


class Channel(Model):
    """Outbound notification destination; credentials stay in secret references."""

    id: Slug
    adapter: Literal["discord", "webhook"]
    url_ref: SecretRef
    signing_key_ref: SecretRef | None = None
    heartbeat_interval_s: int | None = Field(None, ge=30, le=3600)
    audit_export: bool = False

    @model_validator(mode="after")
    def _signing_key(self) -> Channel:
        if self.adapter == "webhook" and not self.signing_key_ref:
            raise ValueError("webhook requires signing_key_ref")
        if self.adapter == "discord" and self.audit_export:
            raise ValueError("audit export requires a signed webhook destination")
        if self.adapter == "discord" and self.signing_key_ref:
            raise ValueError("Discord does not use signing_key_ref")
        return self


Identity = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,100}$")]


class QueryGrant(Model):
    tenant: Identity
    user: Identity
    host: bool = False
    projects: list[Slug] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def _scope(self) -> QueryGrant:
        if not self.host and not self.projects:
            raise ValueError("a query grant needs host access or explicit projects")
        return self


class QueryEndpoint(Model):
    id: Slug
    adapter: Literal["webhook", "discord"]
    verification_key_ref: SecretRef
    application_id: Annotated[str, StringConstraints(pattern=r"^[0-9]{1,30}$")] | None = None
    grants: list[QueryGrant] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def _identity(self) -> QueryEndpoint:
        if self.adapter == "discord" and not self.application_id:
            raise ValueError("Discord requires application_id")
        identities = [(g.tenant, g.user) for g in self.grants]
        if len(identities) != len(set(identities)):
            raise ValueError("duplicate query identities")
        return self


class Bot(Model):
    port: int = Field(9090, ge=1024, le=65535)
    public_hostname: Hostname | None = None
    endpoints: list[QueryEndpoint] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def _endpoints(self) -> Bot:
        ids = [e.id for e in self.endpoints]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate bot endpoint ids")
        if self.public_hostname and not self.endpoints:
            raise ValueError("a public bot requires endpoints")
        return self


class Scanning(Model):
    enabled: bool = False
    osv: bool = True
    trivy: bool = True
    kev: bool = False
    epss: bool = False
    context_max_requests: int = Field(100, ge=1, le=1000)
    interval_s: int = Field(21600, ge=300, le=86400)
    max_age_s: int = Field(86400, ge=300, le=604800)
    max_requests: int = Field(1000, ge=1, le=10000)

    @model_validator(mode="after")
    def _limits(self):
        if self.max_age_s < self.interval_s:
            raise ValueError("scan freshness limit must cover the scheduling interval")
        if self.enabled and not (self.osv or self.trivy):
            raise ValueError("enabled scanning needs at least one provider")
        return self


class MaintenanceEmergency(Model):
    notice_minutes: int = Field(
        60, ge=15, le=1440, description="Notice before an unscheduled one-hour window opens."
    )
    immediate_if_known_exploited: bool = Field(
        True,
        description="Disconnect a known-exploited, network-reachable service without notice.",
    )


class MaintenancePolicy(Model):
    """Server-wide maintenance windows (ADR 0002 section 8).

    Distinct from the per-workload `Maintenance` contract on projects/services.
    """

    weekly_window: str = Field(
        description="Fixed one-hour window, for example 'Sun 03:00 Europe/Berlin'."
    )
    allow_reboot: bool = Field(False, description="Explicit consent for host reboots in a window.")
    emergency: MaintenanceEmergency = MaintenanceEmergency()
    drills: list[Literal["resources", "restart", "restore"]] = Field(
        default_factory=list, max_length=3
    )

    @field_validator("weekly_window")
    @classmethod
    def _valid_window(cls, value: str) -> str:
        from .maintenance import parse_window_spec

        parse_window_spec(value)
        return value

    @field_validator("drills")
    @classmethod
    def _unique_drills(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("duplicate drill")
        return value


class Config(Model):
    schema_version: Literal[1]
    server: Server
    profile: Literal["api", "local-ai"] = "api"
    automation: Automation = Automation()
    admin: Admin
    proxy: Proxy = Proxy()
    hardening: Hardening = Hardening()
    reserved_memory_mb: int = Field(
        512, ge=128, le=65536, description="Memory kept free for the base platform."
    )
    projects: list[Project] = Field(default_factory=list, max_length=64)
    applications: list[Application] = Field(default_factory=list, max_length=16)
    repositories: list[Repository] = Field(default_factory=list, max_length=64)
    ai: Ai = Ai()
    channels: list[Channel] = Field(default_factory=list, max_length=16)
    backup: Backup = Backup()
    events: Events = Events()
    bot: Bot = Bot()
    scanning: Scanning = Scanning()
    maintenance: MaintenancePolicy | None = None
    build: BuildPolicy | None = None

    @model_validator(mode="after")
    def _cross_checks(self) -> Config:
        if self.admin.access == "private-lan" and not self.hardening.firewall.manage:
            raise ValueError("admin.access private-lan requires a managed firewall")
        # The executor also validates a deliberately redacted Backup policy, so
        # complete credential requirements belong to the full user config.
        if self.backup.enabled and (
            self.backup.endpoint is None
            or not self.backup.repository_ref
            or not self.backup.password_ref
        ):
            raise ValueError("enabled backup requires endpoint, repository_ref and password_ref")
        channel_ids = [c.id for c in self.channels]
        if len(channel_ids) != len(set(channel_ids)):
            raise ValueError("duplicate channel ids")
        ids = [p.id for p in self.projects]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate project ids")
        application_ids = [application.id for application in self.applications]
        if len(application_ids) != len(set(application_ids)):
            raise ValueError("duplicate application ids")
        services = [
            service for application in self.applications for service in application.services
        ]
        self._check_repositories()
        if len(self.projects) + len(services) > 64:
            raise ValueError("at most 64 projects and services are allowed")
        workloads = [*self.projects, *services]
        ports = [p.host_port for p in workloads] + [
            self.admin.port,
            self.admin.backend_port,
            self.bot.port,
        ]
        if len(ports) != len(set(ports)):
            raise ValueError("host ports (projects, admin) must be unique")
        if RESERVED_PORTS & set(ports):
            raise ValueError(f"ports {sorted(RESERVED_PORTS)} are reserved for the proxy")
        hosts = [r.host for p in workloads for r in p.routes]
        if len(hosts) != len(set(hosts)):
            raise ValueError("a route host may only be used once")
        if self.bot.public_hostname:
            if self.bot.public_hostname in hosts or self.bot.public_hostname == self.admin.hostname:
                raise ValueError("bot hostname collides with another route")
            if not self.proxy.acme_email:
                raise ValueError("public bot requires proxy.acme_email")
        project_ids = {p.id for p in self.projects}
        for endpoint in self.bot.endpoints:
            for grant in endpoint.grants:
                if not set(grant.projects) <= project_ids:
                    raise ValueError("query grant references an unknown project")
        if self.admin.hostname in hosts:
            raise ValueError("admin hostname collides with a project route")
        uses_acme = any(r.tls == "acme" for p in workloads if p.manage for r in p.routes)
        if uses_acme and not self.proxy.acme_email:
            raise ValueError("routes with tls 'acme' require proxy.acme_email")
        return self

    def _check_repositories(self) -> None:
        known = {
            (application.id, service.id)
            for application in self.applications
            for service in application.services
        }
        bound: set[tuple[str, str]] = set()
        for repository in self.repositories:
            binding = (repository.application, repository.service)
            if binding not in known:
                raise ValueError(f"repository {repository.id} names an unknown application service")
            if binding in bound:
                raise ValueError("a service may have only one repository")
            bound.add(binding)
        ids = [r.id for r in self.repositories]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate repository ids")
        credentials = [r.credential for r in self.repositories if r.credential]
        if len(credentials) != len(set(credentials)):
            raise ValueError("repositories must not share a credential reference")

    @property
    def managed_projects(self) -> list[Project]:
        return [p for p in self.projects if p.manage]

    def unavailable_features(self) -> list[str]:
        """Enabled features that this release cannot deliver."""
        hits = []
        if self.profile == "local-ai":
            hits.append("profile.local-ai")
        if self.automation.profile != "observe":
            hits.append(f"automation.{self.automation.profile}")
        if self.ai.provider != "none":
            hits.append("ai.provider")
        if self.backup.enabled:
            hits.append("backup.enabled")
        if self.applications:
            hits.append("applications")
            if any(a.on_critical is not None for a in self.applications):
                hits.append("applications.on_critical")
        if self.repositories:
            hits.append("repositories")
        if self.build is not None:
            hits.append("build")
        if self.maintenance is not None and self.maintenance.drills:
            hits.append("maintenance.drills")
        workloads = [*self.projects, *(s for a in self.applications for s in a.services)]
        if any(workload.update is not None for workload in workloads):
            hits.append("projects.update")
        if self.admin.access == "public":
            hits.append("admin.access.public")
        return hits


class ConfigError(Exception):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def _format_errors(exc: ValidationError) -> list[str]:
    out = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err["loc"]) or "(root)"
        out.append(f"{loc}: {re.sub(r'^Value error, ', '', err['msg'])}")
    return out


def parse_config(data: Any, *, allow_unavailable: bool = False) -> Config:
    """Validate raw data. Raises ConfigError listing every problem."""
    if not isinstance(data, dict):
        raise ConfigError(["configuration must be a mapping"])
    try:
        cfg = Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(_format_errors(exc)) from None
    if not allow_unavailable:
        hits = cfg.unavailable_features()
        if hits:
            raise ConfigError(
                [f"{h}: not available in this release - {UNAVAILABLE_FEATURES[h]}" for h in hits]
            )
    return cfg


def load_yaml(text: str) -> Any:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError([f"invalid YAML: {exc}"]) from None


def load_config_file(path: Path, *, allow_unavailable: bool = False) -> Config:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError([f"cannot read {path}: {exc.strerror}"]) from None
    return parse_config(load_yaml(text), allow_unavailable=allow_unavailable)


def effective(cfg: Config) -> dict[str, Any]:
    """Canonical configuration; omit empty optional sections to preserve v1 revisions."""
    data = cfg.model_dump(mode="json")
    lan = data["admin"].pop("lan")
    if lan is not None:
        lan = {key: value for key, value in lan.items() if value}
        if lan:
            data["admin"]["lan"] = lan
    if not data["applications"]:
        del data["applications"]
    for application in data.get("applications", []):
        for key in ("on_critical", "instruction"):
            if application.get(key) is None:
                application.pop(key, None)
        if not application.get("stateless"):
            application.pop("stateless", None)
    if not data["repositories"]:
        del data["repositories"]
    for repository in data.get("repositories", []):
        if not repository["egress_rule_patterns"]:
            del repository["egress_rule_patterns"]
    if data["maintenance"] is None:
        del data["maintenance"]
    if data["build"] is None:
        del data["build"]
    elif data["build"]["minimum_isolation"] is None:
        del data["build"]["minimum_isolation"]
    for key in ("model", "api_key_ref", "base_url", "budget", "local", "model_policy", "fx"):
        if data["ai"].get(key) is None:
            data["ai"].pop(key, None)
    if not data["ai"].get("share"):
        data["ai"].pop("share", None)
    # Optional health fields stay out of canonical data until set (stable revisions).
    workloads = list(data["projects"])
    for application in data.get("applications", []):
        workloads.extend(application["services"])
    for workload in workloads:
        for key in ("probe", "max_response_ms"):
            if workload["health"].get(key) is None:
                workload["health"].pop(key, None)
        if workload.get("update") is None:
            workload.pop("update", None)
        else:
            for key in ("rollback_window_s", "min_healthy_s"):
                if workload["update"].get(key) is None:
                    workload["update"].pop(key, None)
    return data
