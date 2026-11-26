"""Independent validation of a repository build artifact, and its approval (R04).

The builder (R03) yields an *untrusted candidate*: a record that names an output
digest and claims nothing it can prove. This module is the separate validator that
decides whether that digest may be deployed. It shares no identity, no writable
directory and no trust with the builder, and it never takes the builder's word:

- the record is re-bound to inputs the validator derives itself (source digest,
  contract digest, recipe, inventory, input digest) and must claim no authority;
- the artifact is inspected by digest through the validator's own registry access
  (manifest digest, origin/signature policy, SBOM and base images);
- the prescribed tests run against the artifact in a separate environment and
  observe the container's real isolation (user, read-only rootfs, capabilities,
  network, sockets, port, health, data path, egress, data compatibility);
- dependencies, base images and the image join the vulnerability inventory and are
  scanned; only complete, fresh ``not_affected`` evidence passes;
- on acceptance the image is copied by digest into the repository named by the
  root-owned update contract, and a *signed attestation* (L04) is issued by the
  validator's signing identity.

A report, an attestation or a build record authorizes nothing by itself. Applying
needs an approval signed by a *different* identity (:func:`issue_approval`), bound to
server, project, configuration revision, policy revision, digest, tests and expiry,
and the executor's own ``update_validate`` / ``apply_verified_image`` path (L04/L05).
Everything fails closed: a missing fact, an unknown field or an exception is a
rejection, never an acceptance. Nothing here touches a host.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import ipaddress
import json
import os
import re
import secrets as _secrets
import stat
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Annotated, Protocol, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from .builder import DIGEST, LEVEL_RANK, BuildRequest, isolation_rejection
from .canonical import canonical_json, revision_id
from .config import (
    BuildPolicy,
    Config,
    Egress,
    EgressRule,
    Level,
    UpdatePolicy,
    WorkloadContract,
    effective,
)
from .ids import graph_identifier
from .render import PRIVATE_V4, PRIVATE_V6
from .repositories import SHA1
from .repository_contract import ContractProposal, check_suitability
from .update_evidence import (
    Attestation,
    RepositoryCompatibility,
    UpdateRejected,
    policy_revision,
    public_key_b64,
    require_clean_scan,
    require_repository_validation,
    sign_statement,
    verify_attestation,
)
from .vulnerabilities import Component

REPORT_SCHEMA = 1
TEST_SCHEME = "steward-artifact-tests-v1"
MAX_COMPONENTS = 20000
MAX_RECORD_BYTES = 256 * 1024
_NO_DATA_PATH = "no data path"
_DATA_FORMAT_UNCHANGED = "data format unchanged"
CHECK_NAMES = (
    "record_binding",
    "contract_suitability",
    "isolation_level",
    "artifact_identity",
    "origin_policy",
    "inventory",
    "isolation_tests",
    "health_and_data",
    "data_compatibility",
    "vulnerability_scan",
    "promotion",
)


class ValidationFailure(Exception):
    """Programming or configuration error (not a rejected artifact)."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


class Data(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


# --- the validator's own observations (never the builder's) -----------------------------


class SbomComponent(Data):
    ecosystem: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=300)
    version: str = Field(min_length=1, max_length=200)


class SignatureFact(Data):
    signer: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._@:/-]{1,200}$")]
    valid: bool


class ArtifactFacts(Data):
    """What the validator's registry access reports for one image, read by digest."""

    manifest_digest: Annotated[str, StringConstraints(pattern=DIGEST.pattern)]
    sbom: list[SbomComponent] | None = Field(None, max_length=MAX_COMPONENTS)
    base_images: list[Annotated[str, StringConstraints(pattern=DIGEST.pattern)]] = Field(
        default_factory=list, max_length=64
    )
    signature: SignatureFact | None = None


class ProbeResult(Data):
    """Observations from running the artifact in the separate test environment."""

    started: bool
    uid: int | None = None
    read_only_rootfs: bool = False
    privileged: bool = True
    capabilities: list[str] = Field(default_factory=lambda: ["unknown"], max_length=64)
    host_network: bool = True
    engine_socket: bool = True
    listening_ports: list[int] = Field(default_factory=list, max_length=64)
    health_status: int | None = None
    data_writable: bool | None = None
    egress_reachable: list[str] = Field(default_factory=list, max_length=64)
    data_readable: bool | None = None  # previous data opened by the candidate
    data_migrated: bool | None = None  # candidate rewrote the data format


class ArtifactRegistry(Protocol):
    """The validator's own registry identity. Reads and copies by digest only."""

    def inspect(self, ref: str) -> ArtifactFacts: ...

    def copy(self, source_ref: str, target_ref: str) -> str:
        """Copy by digest; returns the digest now present at ``target_ref``."""


class ArtifactProbe(Protocol):
    """Runs the prescribed tests in an environment the builder cannot reach."""

    def run(self, image_ref: str, contract: dict, *, with_previous_data: bool) -> ProbeResult: ...


class Scanner(Protocol):
    def scan(self, subjects: list[Component], *, inventory_revision: str, now: float) -> list: ...


@dataclass(frozen=True)
class Signer:
    """A signing identity. The id must be listed in the root-owned update contract."""

    key_id: str
    key: Ed25519PrivateKey

    @property
    def public_key(self) -> str:
        return public_key_b64(self.key)


@dataclass(frozen=True)
class OriginPolicy:
    """External signatures are optional. Validator acceptance still requires all checks."""

    require_signature: bool = False
    trusted_signers: frozenset[str] = frozenset()
    allow_unresolved_inventory: bool = False


# --- independence -----------------------------------------------------------------------


def _overlaps(a: Path, b: Path) -> bool:
    a, b = a.resolve(), b.resolve()
    return a == b or a in b.parents or b in a.parents


def ensure_independent(
    *,
    validator_root: Path,
    builder_root: Path,
    validator_identity: str,
    builder_identity: str,
    validator_uid: int | None = None,
    builder_uid: int | None = None,
    key_paths: tuple[Path, ...] = (),
) -> None:
    """Refuse a validator that shares identity or writable state with the builder."""
    if validator_identity == builder_identity or not validator_identity:
        raise ValidationFailure("not_independent", "validator and builder share an identity")
    if validator_uid is not None and validator_uid == builder_uid:
        raise ValidationFailure("not_independent", "validator and builder share a UID")
    if _overlaps(validator_root, builder_root):
        raise ValidationFailure("not_independent", "validator and builder share a directory")
    if any(_overlaps(path, builder_root) for path in key_paths):
        raise ValidationFailure("not_independent", "a signing key is readable by the builder")


# --- report -----------------------------------------------------------------------------


@dataclass
class ValidationReport:
    accepted: bool
    project: str
    application: str
    service: str
    input_digest: str
    digest: str | None
    image: str | None
    version: str
    isolation_level: str | None
    isolation_label: str | None
    test_revision: str
    migration: str | None
    inventory_revision: str | None
    components: int
    scan: dict | None
    checks: list[dict]
    validated_at: float
    validator: str
    attestation: dict | None = None
    egress_mode: str = "none"
    unresolved: list[dict] = field(default_factory=list)
    trust: str = "validated_candidate"
    authorizes: list[str] = field(default_factory=list)  # a report never authorizes

    def to_dict(self) -> dict:
        return {"schema": REPORT_SCHEMA, **{k: getattr(self, k) for k in self.__dataclass_fields__}}

    @property
    def failed(self) -> list[str]:
        return [c["name"] + ":" + c["code"] for c in self.checks if not c["ok"]]


def test_revision(contract: dict, contract_digest: str) -> str:
    """Digest of what was prescribed (checks plus the contract they derive from)."""
    return hashlib.sha256(
        canonical_json(
            {
                "scheme": TEST_SCHEME,
                "checks": sorted(CHECK_NAMES),
                "contract_digest": contract_digest,
                "health": contract.get("health"),
                "port": contract.get("container_port"),
            }
        ).encode()
    ).hexdigest()


def _repository_binding(
    repo: str, application: str, service: str, url: str, ref: str, revision: str | None
) -> str:
    return revision_id(
        {
            "repository": repo,
            "application": application,
            "service": service,
            "url": url,
            "ref": ref,
            "revision": revision,
        }
    )


class _Checks:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def add(self, name: str, ok: bool, code: str = "ok", detail: str = "") -> bool:
        self.items.append(
            {"name": name, "ok": bool(ok), "code": code if not ok else "ok", "detail": detail[:200]}
        )
        return bool(ok)


# --- validator --------------------------------------------------------------------------


class ArtifactValidator:
    """Validates build records. Holds only its own root, registry, probe and keys."""

    def __init__(
        self,
        root: Path,
        *,
        registry: ArtifactRegistry,
        probe: ArtifactProbe,
        scanner: Scanner,
        signer: Signer,
        identity: str = "steward-validate",
        builder_root: Path,
        builder_identity: str = "steward-build",
        validator_uid: int | None = None,
        builder_uid: int | None = None,
        origin: OriginPolicy = OriginPolicy(),  # noqa: B008 - frozen value object
        minimum_level: str | None = None,
        build_policy: BuildPolicy | None = None,
    ):
        ensure_independent(
            validator_root=root,
            builder_root=builder_root,
            validator_identity=identity,
            builder_identity=builder_identity,
            validator_uid=validator_uid,
            builder_uid=builder_uid,
        )
        if minimum_level is not None and (
            not isinstance(minimum_level, str) or minimum_level not in LEVEL_RANK
        ):
            raise ValidationFailure("bad_policy", "unknown minimum isolation level")
        self.root = root
        self.registry = registry
        self.probe = probe
        self.scanner = scanner
        self.signer = signer
        self.identity = identity
        self.origin = origin
        self.minimum_level = minimum_level
        self.build_policy = build_policy
        (root / "reports").mkdir(mode=0o700, parents=True, exist_ok=True)
        info = (root / "reports").lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValidationFailure("bad_root", "reports is not a private directory")

    # -- public
    def validate(
        self,
        request: BuildRequest,
        record: dict,
        *,
        project: str,
        version: str,
        policy: UpdatePolicy,
        now: float,
    ) -> ValidationReport:
        """Validate one build record against independently derived inputs."""
        checks = _Checks()
        contract = copy.deepcopy(request.contract)
        request = replace(request, contract=contract)
        report = ValidationReport(
            accepted=False,
            project=project,
            application=request.record.application,
            service=request.record.service,
            input_digest=request.input_digest,
            digest=None,
            image=None,
            version=version,
            isolation_level=None,
            isolation_label=None,
            test_revision=test_revision(contract, request.contract_digest),
            migration=None,
            inventory_revision=None,
            components=0,
            scan=None,
            checks=checks.items,
            validated_at=now,
            validator=self.identity,
            egress_mode=str(contract.get("egress", {}).get("mode", "none")),
        )
        compatibility = None
        try:
            compatibility = self._run(
                report, checks, request, record, project, version, policy, now
            )
        except Exception as exc:  # noqa: BLE001 - any failure of a check is a rejection
            checks.add("validator", False, "validator_error", type(exc).__name__)
        if compatibility is not None and all(c["ok"] for c in checks.items):
            report.attestation = self._attest(report, request, compatibility)
            report.accepted = True
        self._persist(report)
        return report

    def accepted_digests(self, input_digest: str) -> set[str]:
        """Digests this validator accepted for exactly these inputs (for build reuse)."""
        # Older reports used "none" for an unobserved migration too.
        compatibility_details = (_NO_DATA_PATH, _DATA_FORMAT_UNCHANGED, "restore_required")
        out = set()
        for path in (self.root / "reports" / input_digest).glob("*.json"):
            with contextlib.suppress(OSError, ValueError):
                data = json.loads(path.read_text(encoding="utf-8"))
                if (
                    isinstance(data, dict)
                    and data.get("accepted")
                    and data.get("input_digest") == input_digest
                    and isinstance(digest := data.get("digest"), str)
                    and self._isolation_rejection(data.get("isolation_level")) is None
                    and isinstance(checks := data.get("checks"), list)
                    and any(
                        isinstance(check, dict)
                        and check.get("name") == "data_compatibility"
                        and check.get("ok") is True
                        and check.get("detail") in compatibility_details
                        for check in checks
                    )
                ):
                    out.add(digest)
        return out

    def _isolation_rejection(self, level: object) -> str | None:
        return isolation_rejection(
            self.build_policy, level, minimum=cast(Level | None, self.minimum_level)
        )

    # -- steps
    def _run(
        self, report, checks, request, record, project, version, policy, now
    ) -> RepositoryCompatibility | None:
        contract_model = WorkloadContract.model_validate(contract := request.contract)
        report.egress_mode = contract_model.egress.mode
        reason = (
            self._bind_record(record, request)
            if revision_id(contract) == request.contract_digest
            else "contract_digest_mismatch"
        )
        if not checks.add("record_binding", reason is None, reason or "", "build record"):
            return None  # nothing in an unbound record is worth inspecting
        isolation = record.get("isolation")
        level = isolation.get("level") if isinstance(isolation, dict) else None
        rejection = self._isolation_rejection(level)
        isolation_codes = {
            "unknown_level": "unknown_isolation_level",
            "not_allowed": "isolation_not_allowed",
            "below_minimum": "below_minimum_isolation",
        }
        digest = record["output"]["digest"]
        report.digest = digest
        if isinstance(level, str) and level in LEVEL_RANK:
            report.isolation_level = level
            report.isolation_label = isolation.get("label")
        if not checks.add(
            "isolation_level",
            rejection is None,
            isolation_codes[rejection] if rejection is not None else "",
            report.isolation_level or "",
        ):
            return None
        reasons = check_suitability(ContractProposal.model_validate(contract))
        if not checks.add(
            "contract_suitability", not reasons, reasons[0]["code"] if reasons else ""
        ):
            return None
        image = f"{policy.repository}@{digest}"
        report.image = image
        source_ref = record["output"].get("ref") or image

        facts = ArtifactFacts.model_validate(self.registry.inspect(source_ref).model_dump())
        if not checks.add(
            "artifact_identity", facts.manifest_digest == digest, "digest_mismatch", digest
        ):
            return None
        self._origin(checks, facts)
        components = self._inventory(report, checks, request, facts, project, image, digest)

        probe = ProbeResult.model_validate(
            self.probe.run(
                source_ref, copy.deepcopy(contract), with_previous_data=False
            ).model_dump()
        )
        self._isolation(checks, contract_model, probe)
        self._health_and_data(checks, contract_model, probe)
        compat = ProbeResult.model_validate(
            self.probe.run(
                source_ref, copy.deepcopy(contract), with_previous_data=True
            ).model_dump()
        )
        compatibility = self._compatibility(checks, contract_model, compat)
        if compatibility is not None:
            report.migration = compatibility.migration

        if components is not None:
            self._scan(report, checks, components, policy, now)
        if all(c["ok"] for c in checks.items):
            self._promote(checks, source_ref, image, digest)
        return compatibility

    @staticmethod
    def _bind_record(record: dict, request: BuildRequest) -> str | None:
        """Return a rejection code, or None when the record matches independent inputs."""
        try:
            if len(canonical_json(record)) > MAX_RECORD_BYTES:
                return "record_too_large"
            output = record.get("output") or {}
            digest = output.get("digest")
            ref = output.get("ref")
            expected = {
                "repository": request.record.repository,
                "application": request.record.application,
                "service": request.record.service,
                "commit": request.record.commit,
                "tree": request.record.tree,
                "source_digest": request.record.source_digest,
                "contract_digest": request.contract_digest,
                "input_digest": request.input_digest,
                "recipe": request.recipe,
                "recipe_digest": hashlib.sha256(
                    canonical_json(request.recipe).encode()
                ).hexdigest(),
                "inventory_digest": hashlib.sha256(
                    canonical_json(request.inventory).encode()
                ).hexdigest(),
            }
        except (TypeError, ValueError, AttributeError):
            return "malformed_record"
        if record.get("status") != "succeeded" or not (
            isinstance(digest, str) and DIGEST.fullmatch(digest)
        ):
            return "build_not_succeeded"
        if any(record.get(key) != value for key, value in expected.items()):
            return "inputs_changed"
        if record.get("authorizes") not in ([], None) or record.get("trust") != (
            "untrusted_candidate"
        ):
            return "record_claims_authority"
        if ref is not None and not (isinstance(ref, str) and ref.endswith("@" + digest)):
            return "unpinned_output_ref"
        return None

    def _origin(self, checks: _Checks, facts: ArtifactFacts) -> None:
        sig = facts.signature
        ok = True
        code = ""
        if self.origin.require_signature:
            if sig is None or not sig.valid:
                ok, code = False, "signature_missing_or_invalid"
            elif self.origin.trusted_signers and sig.signer not in self.origin.trusted_signers:
                ok, code = False, "untrusted_signer"
        elif sig is not None and not sig.valid:
            ok, code = False, "signature_invalid"
        checks.add("origin_policy", ok, code)

    def _inventory(self, report, checks, request, facts, project, image, digest):
        unresolved = list(request.inventory.get("unresolved", []))
        report.unresolved = unresolved
        if facts.sbom is None:
            checks.add("inventory", False, "no_sbom")
            return None
        if unresolved and not self.origin.allow_unresolved_inventory:
            checks.add("inventory", False, "unresolved_dependencies", unresolved[0].get("code", ""))
            return None
        seen: dict[str, Component] = {}
        repository = image.rsplit("@", 1)[0]
        subjects = [
            Component(kind="image", scope=project, name=repository, version=digest, image=image)
        ]
        raw = [(c.ecosystem, c.name, c.version) for c in facts.sbom] + [
            (str(c.get("ecosystem")), str(c.get("name")), str(c.get("version")))
            for c in request.inventory.get("components", [])
            if isinstance(c, dict) and c.get("name") and c.get("version")
        ]
        for ecosystem, name, component_version in raw:
            component = Component(
                kind="dependency",
                scope=project,
                name=name,
                version=component_version,
                ecosystem=ecosystem,
            )
            seen.setdefault(component.key, component)
        subjects.extend(seen[key] for key in sorted(seen))
        if len(subjects) > MAX_COMPONENTS:
            checks.add("inventory", False, "inventory_too_large")
            return None
        report.components = len(subjects)
        report.inventory_revision = revision_id(
            {"image": image, "components": [c.key for c in subjects]}
        )
        checks.add("inventory", True, detail=f"{len(subjects)} components")
        return subjects

    @staticmethod
    def _isolation(checks: _Checks, contract: WorkloadContract, probe: ProbeResult) -> None:
        problems = []
        if not probe.started:
            problems.append("not_started")
        if probe.uid is None or probe.uid < 1000 or probe.uid != contract.run_as:
            problems.append("wrong_user")
        if not probe.read_only_rootfs:
            problems.append("writable_rootfs")
        if probe.privileged:
            problems.append("privileged")
        if probe.capabilities:
            problems.append("capabilities")
        if probe.host_network:
            problems.append("host_network")
        if probe.engine_socket:
            problems.append("engine_socket")
        if contract.egress.mode == "none" and probe.egress_reachable:
            problems.append("egress_reachable")
        checks.add(
            "isolation_tests", not problems, problems[0] if problems else "", ",".join(problems)
        )

    @staticmethod
    def _health_and_data(checks: _Checks, contract: WorkloadContract, probe: ProbeResult) -> None:
        problems = []
        if contract.container_port not in probe.listening_ports:
            problems.append("port_not_listening")
        if contract.health.probe in (None, "http") and not (
            probe.health_status is not None and 200 <= probe.health_status < 300
        ):
            problems.append("unhealthy")
        if contract.data_path is not None and probe.data_writable is not True:
            problems.append("data_not_writable")
        checks.add(
            "health_and_data", not problems, problems[0] if problems else "", ",".join(problems)
        )

    @staticmethod
    def _compatibility(
        checks: _Checks, contract: WorkloadContract, probe: ProbeResult
    ) -> RepositoryCompatibility | None:
        """Run against a copy of previous data; the migration kind is observed, not claimed."""
        if contract.data_path is None:
            checks.add("data_compatibility", True, detail=_NO_DATA_PATH)
            return RepositoryCompatibility.NO_DATA_PATH
        if not probe.started or probe.data_readable is not True:
            checks.add("data_compatibility", False, "incompatible_migration")
            return None
        if probe.data_migrated is None:
            checks.add("data_compatibility", False, "migration_unobserved")
            return None
        # A format change cannot be proven reversible here: require the exact capture path.
        if probe.data_migrated:
            checks.add("data_compatibility", True, detail="restore_required")
            return RepositoryCompatibility.RESTORE_REQUIRED
        checks.add("data_compatibility", True, detail=_DATA_FORMAT_UNCHANGED)
        return RepositoryCompatibility.DATA_FORMAT_UNCHANGED

    def _scan(self, report, checks, subjects, policy: UpdatePolicy, now: float) -> None:
        revision = report.inventory_revision
        results = {
            r.subject.key: r
            for r in self.scanner.scan(subjects, inventory_revision=revision, now=now)
        }
        worst = "ok"
        for subject in subjects:
            result = results.get(subject.key)
            if result is None:
                worst = "scan_incomplete"
                break
            state = result.state_at(
                now, inventory_revision=revision, max_age_s=policy.scan_max_age_s
            )
            if state != "not_affected":
                worst = {"confirmed": "scan_not_clean", "stale": "stale_scan"}.get(
                    state, "scan_incomplete"
                )
                break
        if worst != "ok" or not results:
            checks.add("vulnerability_scan", False, worst if worst != "ok" else "scan_incomplete")
            return
        image_result = results[subjects[0].key]
        report.scan = {
            "source": image_result.source,
            "state": "not_affected",
            "checked_at": min(r.checked_at for r in results.values()),
        }
        checks.add("vulnerability_scan", True)

    def _promote(self, checks: _Checks, source_ref: str, image: str, digest: str) -> None:
        try:
            present = self.registry.copy(source_ref, image)
        except Exception:  # noqa: BLE001
            checks.add("promotion", False, "promotion_failed")
            return
        checks.add("promotion", present == digest, "promotion_digest_mismatch", present[:80])

    # -- evidence
    def _attest(
        self,
        report: ValidationReport,
        request: BuildRequest,
        compatibility: RepositoryCompatibility,
    ) -> dict:
        record = request.record
        assert report.scan is not None
        statement = {
            "type": "steward.image-attestation.v1",
            "project": report.project,
            "image": report.image,
            "version": report.version,
            "source_revision": f"git:{record.commit}",
            "test_revision": report.test_revision,
            "migration": compatibility.migration,
            "created_at": report.validated_at,
            "repository_validation": {
                "source_binding": _repository_binding(
                    record.repository,
                    record.application,
                    record.service,
                    record.url,
                    record.ref,
                    record.requested_revision,
                ),
                "application_project": graph_identifier("s", record.application, record.service),
                "egress_mode": report.egress_mode,
                "scan": report.scan.copy(),
                "compatibility": compatibility.value,
            },
        }
        return sign_statement(self.signer.key, self.signer.key_id, statement)

    def _persist(self, report: ValidationReport) -> None:
        key = (report.digest or "none").split(":")[-1][:64]
        directory = self.root / "reports" / report.input_digest
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / f"{key}-{int(report.validated_at)}-{_secrets.token_hex(3)}.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(report.to_dict(), sort_keys=True, indent=2) + "\n")


# --- approval ---------------------------------------------------------------------------

APPROVAL_ID = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


def approval_id_for(report: ValidationReport, config_revision: str, policy_rev: str) -> str:
    """Stable per (artifact, configuration, policy): a repeat reuses the same approval."""
    att = revision_id(report.attestation["statement"]) if report.attestation else "none"
    return "r04-" + revision_id({"a": att, "c": config_revision, "p": policy_rev})[:32]


def _egress_covered(requested: Egress, active: Egress, patterns: list[EgressRule]) -> bool:
    if requested.mode == "none":
        return True
    if requested.mode == "public-web":
        return active.mode == "public-web"

    allowed = [(rule, ipaddress.ip_network(rule.cidr)) for rule in [*active.rules, *patterns]]
    for rule in requested.rules:
        network = ipaddress.ip_network(rule.cidr)
        public_web = active.mode == "public-web" and rule.proto == "tcp"
        uncovered_by_web = []
        if public_web:
            # Both renderer modes reject local destinations. Explicit rules do
            # not inherit the extra address exclusions of public-web.
            for cidr in PRIVATE_V4 if network.version == 4 else PRIVATE_V6:
                excluded = ipaddress.ip_network(cidr)
                if network.overlaps(excluded):
                    uncovered_by_web.append(network if network.subnet_of(excluded) else excluded)
        for port in rule.ports:
            needed = uncovered_by_web if public_web and port in (80, 443) else [network]
            covering = tuple(
                ipaddress.collapse_addresses(
                    block
                    for grant, block in allowed
                    if grant.proto == rule.proto
                    and port in grant.ports
                    and block.version == network.version
                )
            )
            if not all(any(part.subnet_of(block) for block in covering) for part in needed):
                return False
    return True


def _configured_egress_covered(
    report: ValidationReport,
    attested: Attestation,
    current_config: Config,
    workload_contract: dict,
    *,
    server: str,
    config_revision: str,
    policy: UpdatePolicy,
) -> bool:
    """Compare the signed contract with a trusted, current canonical configuration."""
    try:
        cfg = Config.model_validate(current_config.model_dump(mode="json"))
        raw_contract = copy.deepcopy(workload_contract)
        contract = WorkloadContract.model_validate(raw_contract)
        candidate_tests = test_revision(raw_contract, revision_id(raw_contract))
    except (ValidationError, TypeError, ValueError):
        raise ValidationFailure(
            "egress_binding_mismatch", "invalid configuration or contract"
        ) from None

    if cfg.server.name != server or revision_id(effective(cfg)) != config_revision:
        raise ValidationFailure("egress_binding_mismatch", "configuration or server differs")
    binding = attested.repository_validation
    if (
        binding is None
        or binding.egress_mode != contract.egress.mode
        or binding.egress_mode != report.egress_mode
        or attested.test_revision != candidate_tests
    ):
        raise ValidationFailure("egress_binding_mismatch", "contract differs from validation")
    target = (report.application, report.service)
    app = next((a for a in cfg.applications if a.id == target[0]), None)
    service = next((s for s in app.services if s.id == target[1]), None) if app else None
    repo = next(
        (r for r in cfg.repositories if (r.application, r.service) == target),
        None,
    )
    if (
        app is None
        or service is None
        or repo is None
        or attested.project != graph_identifier("s", app.id, service.id)
        or attested.project != binding.application_project
        or any(project.id == attested.project for project in cfg.projects)
        or service.update is None
        or policy_revision(service.update) != policy_revision(policy)
    ):
        raise ValidationFailure("egress_binding_mismatch", "target or update policy differs")
    if (
        binding.source_binding
        != _repository_binding(repo.id, app.id, service.id, repo.url, repo.ref, repo.revision)
        or not attested.source_revision.startswith("git:")
        or not SHA1.fullmatch(attested.source_revision.removeprefix("git:"))
        or (repo.revision is not None and attested.source_revision != f"git:{repo.revision}")
        or (repo.contract is not None and repo.contract != contract)
    ):
        raise ValidationFailure("egress_binding_mismatch", "repository source or contract differs")

    active = Egress()
    if (
        cfg.hardening.firewall.manage
        and app.isolation == "separate"
        and service.manage
        and service.deploy
    ):
        active = service.egress
    return _egress_covered(contract.egress, active, repo.egress_rule_patterns)


def issue_approval(
    report: ValidationReport,
    approver: Signer,
    *,
    policy: UpdatePolicy,
    server: str,
    config_revision: str,
    now: float,
    ttl_s: int = 3600,
    operator_confirmed_egress: bool = False,
    current_config: Config | None = None,
    workload_contract: dict | None = None,
) -> dict:
    """Sign the approval of an accepted report with an identity other than the validator's.

    For a mapped application project, pass the trusted active configuration and
    the exact validated workload contract. The executor checks the authoritative
    configuration revision again before applying.
    """
    if not report.accepted or report.attestation is None or report.scan is None:
        raise ValidationFailure("not_accepted", "only an accepted report can be approved")
    policy = policy.model_copy(deep=True)
    attestation = copy.deepcopy(report.attestation)
    try:
        statement, attested = verify_attestation(attestation, policy)
    except UpdateRejected as exc:
        raise ValidationFailure("invalid_attestation", exc.code) from None
    if (
        (report.project, report.image, report.test_revision)
        != (attested.project, attested.image, attested.test_revision)
        or (report.version, report.migration, report.validated_at)
        != (attested.version, attested.migration, attested.created_at)
        or attested.image.rsplit("@", 1) != [policy.repository, report.digest]
    ):
        raise ValidationFailure("attestation_mismatch", "report or image policy differs")
    signer_id = attestation["key_id"]
    if approver.key_id == signer_id:
        raise ValidationFailure("not_independent", "the approver is the validating identity")
    if approver.public_key in {k.public_key for k in policy.signers}:
        raise ValidationFailure("not_independent", "the approver key is a validator key")
    if not any(
        k.id == approver.key_id and k.public_key == approver.public_key for k in policy.approvers
    ):
        raise ValidationFailure("unknown_approver", "approver is not a trusted identity")
    if not 60 <= ttl_s <= policy.approval_max_ttl_s:
        raise ValidationFailure("bad_ttl", "approval lifetime outside policy")
    try:
        binding = require_repository_validation(attested)
        scan = binding.scan.model_dump(mode="json")
        if scan != report.scan:
            raise UpdateRejected("scan_mismatch", "scan differs from validator evidence")
        require_clean_scan(binding.scan, now=now, max_age_s=policy.scan_max_age_s)
    except UpdateRejected as exc:
        raise ValidationFailure(exc.code, exc.detail) from None
    covered = binding.egress_mode == report.egress_mode == "none"
    if current_config is not None and workload_contract is not None:
        covered = _configured_egress_covered(
            report,
            attested,
            current_config,
            workload_contract,
            server=server,
            config_revision=config_revision,
            policy=policy,
        )
    elif (
        current_config is not None
        or workload_contract is not None
        or binding.application_project == attested.project
    ):
        raise ValidationFailure(
            "egress_binding_mismatch", "configuration and contract are required"
        )
    if not covered and operator_confirmed_egress is not True:
        raise ValidationFailure("egress_unconfirmed", "widened egress needs operator confirmation")
    policy_rev = policy_revision(policy)
    approval = {
        "type": "steward.update-approval.v1",
        "approval_id": approval_id_for(
            replace(report, attestation=attestation), config_revision, policy_rev
        ),
        "server": server,
        "project": attested.project,
        "config_revision": config_revision,
        "policy_revision": policy_rev,
        "image": attested.image,
        "attestation_digest": revision_id(statement),
        "test_revision": attested.test_revision,
        "scan": scan,
        "issued_at": now,
        "expires_at": now + ttl_s,
    }
    return sign_statement(approver.key, approver.key_id, approval)


__all__ = [
    "ArtifactFacts",
    "ArtifactValidator",
    "OriginPolicy",
    "ProbeResult",
    "SbomComponent",
    "SignatureFact",
    "Signer",
    "ValidationFailure",
    "ValidationReport",
    "ensure_independent",
    "issue_approval",
    "test_revision",
]
