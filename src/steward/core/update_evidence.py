"""Update artifact validation and bound approval evidence (L04).

Two independently signed statements make one candidate image applicable:

- the **attestation** names the exact image digest, version, source revision,
  independent test revision and data-migration kind; it is signed by an identity
  listed under `update.signers` in the root-owned contract;
- the **approval** binds that attestation to one target (server, project), the
  exact configuration and policy revision, the scan evidence and an expiry; it is
  signed by a different identity listed under `update.approvers`.

Trust anchors, version range, repository and limits come only from the contract
(root-owned registry), never from the artifacts. Untrusted test prose, a scanner
score, a builder's own success claim or a model proposal carry no signature and
therefore cannot create a valid approval. Any change of a bound value makes the
approval invalid; a used approval cannot be used again (see `UpdateLedger`).

This module validates and records. It never touches the host.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import sqlite3
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from .canonical import canonical_json, revision_id
from .config import ImageRef, Slug, UpdatePolicy, UpdateVersion
from .inventory import Digest

ATTESTATION_TYPE = "steward.image-attestation.v1"
APPROVAL_TYPE = "steward.update-approval.v1"
SIGNATURE_DOMAIN = b"steward-update-evidence-v1\n"
CLOCK_SKEW_S = 60.0
MAX_DOCUMENT_BYTES = 16 * 1024

Migration = Literal["none", "reversible", "restore_required"]
REJECTION_CODES = (
    "malformed",
    "unknown_signer",
    "bad_signature",
    "target_mismatch",
    "repository_mismatch",
    "digest_mismatch",
    "version_out_of_range",
    "migration_unobserved",
    "migration_not_allowed",
    "revision_mismatch",
    "policy_mismatch",
    "not_yet_valid",
    "expired",
    "ttl_too_long",
    "scan_missing",
    "scan_mismatch",
    "scan_not_clean",
    "stale_scan",
    "already_current",
    "missing_backup",
    "stale_backup",
    "replay",
    "in_progress",
    "approval_conflict",
    "invalidated",
    "unknown_approval",
    "recovery_unavailable",
)


class UpdateRejected(Exception):
    """Evidence does not authorize the update. `code` is stable; detail is bounded."""

    def __init__(self, code: str, detail: str = ""):
        assert code in REJECTION_CODES
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail[:200]


class Data(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class ScanEvidence(Data):
    source: Literal["osv", "trivy"]
    state: Literal["unknown", "stale", "scan_failed", "not_affected", "confirmed"]
    checked_at: float = Field(ge=0)


class RepositoryCompatibility(StrEnum):
    NO_DATA_PATH = "no_data_path"
    DATA_FORMAT_UNCHANGED = "data_format_unchanged"
    RESTORE_REQUIRED = "restore_required"

    @property
    def migration(self) -> Migration:
        return "restore_required" if self is RepositoryCompatibility.RESTORE_REQUIRED else "none"


class RepositoryValidation(Data):
    source_binding: Digest
    application_project: Slug
    egress_mode: Literal["none", "public-web", "rules"]
    scan: ScanEvidence
    compatibility: RepositoryCompatibility | None = None


class Attestation(Data):
    type: Literal["steward.image-attestation.v1"]
    project: Slug
    image: ImageRef
    version: UpdateVersion
    source_revision: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9@:._/+-]{1,200}$")]
    test_revision: Digest
    migration: Migration
    created_at: float = Field(ge=0)
    repository_validation: RepositoryValidation | None = None


class Approval(Data):
    type: Literal["steward.update-approval.v1"]
    approval_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{16,64}$")]
    server: Slug
    project: Slug
    config_revision: Digest
    policy_revision: Digest
    image: ImageRef
    attestation_digest: Digest
    test_revision: Digest
    scan: ScanEvidence | None = None
    issued_at: float = Field(ge=0)
    expires_at: float = Field(ge=0)


class Envelope(Data):
    v: Literal[1] = 1
    statement: dict[str, Any]
    key_id: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
    signature: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9+/]{86}==$")]


@dataclass(frozen=True)
class ValidatedUpdate:
    project: str
    approval_id: str
    image: str
    digest: str  # sha256:<hex> manifest digest of `image`
    version: str
    source_revision: str
    test_revision: str
    migration: str
    config_revision: str
    policy_revision: str
    attestation_digest: str
    expires_at: float
    scan_checked_at: float | None

    @property
    def binding(self) -> str:
        return revision_id(self.__dict__)


def policy_revision(contract: UpdatePolicy | dict[str, Any]) -> str:
    body = contract.canonical_dump() if isinstance(contract, UpdatePolicy) else contract
    return revision_id(body)


def parse_version(text: str) -> tuple[int, ...]:
    if not re.fullmatch(r"[0-9]{1,6}(\.[0-9]{1,6}){0,3}", text):
        raise ValueError("invalid version")
    return tuple(int(part) for part in text.split("."))


def _padded(version: tuple[int, ...], width: int = 4) -> tuple[int, ...]:
    return version + (0,) * (width - len(version))


def version_in_range(version: str, low: str, high: str) -> bool:
    return (
        _padded(parse_version(low))
        <= _padded(parse_version(version))
        <= _padded(parse_version(high))
    )


def _message(statement: dict[str, Any]) -> bytes:
    return SIGNATURE_DOMAIN + canonical_json(statement).encode("utf-8")


def sign_statement(private_key: Ed25519PrivateKey, key_id: str, statement: dict[str, Any]) -> dict:
    """Producer helper for signers and tests; the executor only verifies."""
    signature = base64.b64encode(private_key.sign(_message(statement))).decode()
    return {"v": 1, "statement": statement, "key_id": key_id, "signature": signature}


def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


def _envelope(document: Any) -> Envelope:
    try:
        if len(canonical_json(document)) > MAX_DOCUMENT_BYTES:
            raise UpdateRejected("malformed", "document too large")
        return Envelope.model_validate(document)
    except (ValidationError, TypeError, ValueError):
        raise UpdateRejected("malformed", "invalid signed document") from None


def _verified_statement(document: Any, keys: list, kind: str) -> dict[str, Any]:
    envelope = _envelope(document)
    key = next((k for k in keys if k.id == envelope.key_id), None)
    if key is None:
        raise UpdateRejected("unknown_signer", f"{kind} key is not a trusted identity")
    try:
        raw = base64.b64decode(key.public_key, validate=True)
        signature = base64.b64decode(envelope.signature, validate=True)
        Ed25519PublicKey.from_public_bytes(raw).verify(signature, _message(envelope.statement))
    except (InvalidSignature, binascii.Error, ValueError):
        raise UpdateRejected("bad_signature", f"{kind} signature does not verify") from None
    return envelope.statement


def _model(cls, statement: dict[str, Any], kind: str):
    try:
        return cls.model_validate(statement)
    except ValidationError:
        raise UpdateRejected("malformed", f"{kind} statement is invalid") from None


def verify_attestation(document: Any, contract: UpdatePolicy) -> tuple[dict[str, Any], Attestation]:
    """Return the verified statement and its parsed values, preserving the signed digest."""
    statement = _verified_statement(document, contract.signers, "attestation")
    return statement, _model(Attestation, statement, "attestation")


def require_repository_validation(attested: Attestation) -> RepositoryValidation:
    validation = attested.repository_validation
    if (
        validation is None
        or validation.compatibility is None
        or validation.compatibility.migration != attested.migration
    ):
        raise UpdateRejected("migration_unobserved", "repository compatibility needs revalidation")
    return validation


def require_clean_scan(scan: ScanEvidence, *, now: float, max_age_s: int) -> None:
    if scan.checked_at > now + CLOCK_SKEW_S or now - scan.checked_at > max_age_s:
        raise UpdateRejected("stale_scan", "scan evidence is not fresh")
    if scan.state != "not_affected":
        raise UpdateRejected("scan_not_clean", f"scan state is {scan.state}")


def validate_update(
    contract: UpdatePolicy,
    *,
    server: str,
    project: str,
    config_revision: str,
    current_image: str,
    candidate_digest: str,
    attestation: Any,
    approval: Any,
    now: float,
) -> ValidatedUpdate:
    """Check every binding. Raises UpdateRejected; success is only this return value."""
    attested_statement, attested = verify_attestation(attestation, contract)
    approved = _model(
        Approval, _verified_statement(approval, contract.approvers, "approval"), "approval"
    )
    if attested.project != project or approved.project != project or approved.server != server:
        raise UpdateRejected("target_mismatch", "evidence names a different target")
    if attested.image.rsplit("@", 1)[0] != contract.repository:
        raise UpdateRejected("repository_mismatch", "image is not from the expected repository")
    digest = attested.image.rsplit("@", 1)[1]
    if approved.image != attested.image or candidate_digest != digest:
        raise UpdateRejected("digest_mismatch", "approval, attestation and request disagree")
    if approved.attestation_digest != revision_id(attested_statement):
        raise UpdateRejected("digest_mismatch", "approval binds a different attestation")
    if approved.test_revision != attested.test_revision:
        raise UpdateRejected("digest_mismatch", "approval binds a different test revision")
    scan = approved.scan
    if "repository_validation" in attested_statement:
        scan = require_repository_validation(attested).scan
        if approved.scan != scan:
            raise UpdateRejected("scan_mismatch", "approval differs from the validator's scan")
    if current_image == attested.image:
        raise UpdateRejected("already_current", "candidate is the running image")
    if not version_in_range(attested.version, contract.versions.min, contract.versions.max):
        raise UpdateRejected("version_out_of_range", "version is outside the permitted range")
    if attested.migration not in contract.allowed_migrations:
        raise UpdateRejected("migration_not_allowed", "data migration kind is not permitted")
    if approved.config_revision != config_revision:
        raise UpdateRejected("revision_mismatch", "approval binds another configuration revision")
    if approved.policy_revision != policy_revision(contract):
        raise UpdateRejected("policy_mismatch", "approval binds another update policy")
    if approved.issued_at > now + CLOCK_SKEW_S:
        raise UpdateRejected("not_yet_valid", "approval is issued in the future")
    if approved.expires_at <= now:
        raise UpdateRejected("expired", "approval has expired")
    if approved.expires_at - approved.issued_at > contract.approval_max_ttl_s:
        raise UpdateRejected("ttl_too_long", "approval lifetime exceeds the policy limit")
    if scan is None:
        if contract.require_scan:
            raise UpdateRejected("scan_missing", "the policy requires scan evidence")
    else:
        require_clean_scan(scan, now=now, max_age_s=contract.scan_max_age_s)
    return ValidatedUpdate(
        project=project,
        approval_id=approved.approval_id,
        image=attested.image,
        digest=digest,
        version=attested.version,
        source_revision=attested.source_revision,
        test_revision=attested.test_revision,
        migration=attested.migration,
        config_revision=approved.config_revision,
        policy_revision=approved.policy_revision,
        attestation_digest=approved.attestation_digest,
        expires_at=approved.expires_at,
        scan_checked_at=scan.checked_at if scan else None,
    )


def require_fresh_backup(completed_at: float | None, *, now: float, max_age_s: int) -> None:
    """Backup evidence must exist and be recent; its absence is never success."""
    if completed_at is None:
        raise UpdateRejected("missing_backup", "no capture is bound to the current deployment")
    if completed_at > now + CLOCK_SKEW_S or now - completed_at > max_age_s:
        raise UpdateRejected("stale_backup", "the newest capture is too old")


# ---- durable idempotency -----------------------------------------------------------

TERMINAL = frozenset(
    {"applied", "failed", "revert_failed", "invalidated", "rolled_back", "rollback_failed"}
)
# `applied`, `revert_failed` and `rollback_failed` stay eligible for an explicit rollback.
ROLLBACK_FROM = ("applied", "revert_failed", "rollback_failed")
IN_FLIGHT = ("applying", "rolling_back")
LEDGER_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS update_approvals ("
    "approval_id TEXT PRIMARY KEY, project TEXT NOT NULL, binding TEXT NOT NULL, "
    "state TEXT NOT NULL, body TEXT NOT NULL, updated_at REAL NOT NULL)"
)


class UpdateLedger:
    """Single-use approvals with a durable journal.

    States: validated -> applying -> applied | failed | revert_failed; an applied
    update can be rolled back: applied -> rolling_back -> rolled_back |
    rollback_failed (L06). Any state may become invalidated when a binding
    changes. A terminal approval is never accepted for a new apply, and the same
    id with different bindings is a conflict.
    """

    def __init__(self, db: Callable[[], AbstractContextManager[sqlite3.Connection]]):
        self._db = db
        with self._db() as conn:
            conn.execute(LEDGER_SCHEMA)

    def record(self, update: ValidatedUpdate, attestation: Any, approval: Any) -> str:
        """Persist validated evidence. Returns 'new' or 'same' (idempotent repeat)."""
        candidate = {
            "image": update.image,
            "digest": update.digest,
            "version": update.version,
            "migration": update.migration,
            "expires_at": update.expires_at,
        }
        body = json.dumps(
            {
                "attestation": attestation,
                "approval": approval,
                "journal": {},
                "candidate": candidate,
            },
            sort_keys=True,
        )
        conflict = False
        with self._db() as conn:
            row = conn.execute(
                "SELECT binding, state FROM update_approvals WHERE approval_id=?",
                (update.approval_id,),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO update_approvals VALUES (?,?,?,?,?,?)",
                    (
                        update.approval_id,
                        update.project,
                        update.binding,
                        "validated",
                        body,
                        time.time(),
                    ),
                )
                return "new"
            if row[0] != update.binding:
                conflict = True
                conn.execute(
                    "UPDATE update_approvals SET state='invalidated', updated_at=? "
                    "WHERE approval_id=?",
                    (time.time(), update.approval_id),
                )
        # Raise only after the transaction committed the invalidation.
        if conflict:
            raise UpdateRejected("approval_conflict", "approval id reused with other bindings")
        if row[1] == "validated":
            return "same"
        raise UpdateRejected("replay" if row[1] in TERMINAL else "in_progress")

    def get(self, approval_id: str) -> dict[str, Any] | None:
        with self._db() as conn:
            row = conn.execute(
                "SELECT project, binding, state, body FROM update_approvals WHERE approval_id=?",
                (approval_id,),
            ).fetchone()
        if row is None:
            return None
        body = json.loads(row[3])
        return {
            "approval_id": approval_id,
            "project": row[0],
            "binding": row[1],
            "state": row[2],
            **body,
        }

    def claim(self, approval_id: str) -> None:
        """validated -> applying, exactly once."""
        with self._db() as conn:
            cur = conn.execute(
                "UPDATE update_approvals SET state='applying', updated_at=? "
                "WHERE approval_id=? AND state='validated' "
                "AND NOT EXISTS (SELECT 1 FROM update_approvals "
                "WHERE state IN ('applying','rolling_back') "
                "AND project=(SELECT project FROM update_approvals WHERE approval_id=?))",
                (time.time(), approval_id, approval_id),
            )
            if cur.rowcount == 1:
                return
            row = conn.execute(
                "SELECT state FROM update_approvals WHERE approval_id=?", (approval_id,)
            ).fetchone()
        if row is None:
            raise UpdateRejected("unknown_approval")
        state = row[0]
        if state == "validated":
            raise UpdateRejected("in_progress", "another update of this project is applying")
        raise UpdateRejected("in_progress" if state in IN_FLIGHT else "replay")

    def begin_rollback(self, approval_id: str) -> str:
        """applied | revert_failed | rollback_failed -> rolling_back, exactly one at a time.

        Returns the state it left. Never starts while another update or rollback of the
        same project is in flight."""
        with self._db() as conn:
            row = conn.execute(
                "SELECT project, state FROM update_approvals WHERE approval_id=?", (approval_id,)
            ).fetchone()
            if row is None:
                raise UpdateRejected("unknown_approval")
            project, state = row
            busy = conn.execute(
                "SELECT 1 FROM update_approvals WHERE project=? "
                "AND state IN ('applying','rolling_back') LIMIT 1",
                (project,),
            ).fetchone()
            if busy:
                raise UpdateRejected("in_progress", "another update of this project is in flight")
            if state not in ROLLBACK_FROM:
                raise UpdateRejected("replay", f"approval is {state}; nothing to roll back")
            conn.execute(
                "UPDATE update_approvals SET state='rolling_back', updated_at=? "
                "WHERE approval_id=? AND state=?",
                (time.time(), approval_id, state),
            )
        return state

    def journal(self, approval_id: str, **fields: Any) -> None:
        """Merge fields into the durable journal (state unchanged)."""
        self._write(approval_id, None, fields)

    def finish(self, approval_id: str, state: str, **fields: Any) -> None:
        assert state in TERMINAL
        self._write(approval_id, state, fields)

    def _write(self, approval_id: str, state: str | None, fields: dict[str, Any]) -> None:
        with self._db() as conn:
            row = conn.execute(
                "SELECT body, state FROM update_approvals WHERE approval_id=?", (approval_id,)
            ).fetchone()
            if row is None:
                raise UpdateRejected("unknown_approval")
            body = json.loads(row[0])
            body["journal"].update(fields)
            conn.execute(
                "UPDATE update_approvals SET body=?, state=?, updated_at=? WHERE approval_id=?",
                (json.dumps(body, sort_keys=True), state or row[1], time.time(), approval_id),
            )

    def invalidate(self, approval_id: str) -> None:
        with self._db() as conn:
            conn.execute(
                "UPDATE update_approvals SET state='invalidated', updated_at=? "
                "WHERE approval_id=? AND state='validated'",
                (time.time(), approval_id),
            )

    def pending_count(self) -> int:
        with self._db() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM update_approvals "
                "WHERE state IN ('validated','applying','rolling_back')"
            ).fetchone()[0]

    def summaries(self, project: str, limit: int = 20) -> list[dict[str, Any]]:
        with self._db() as conn:
            rows = conn.execute(
                "SELECT approval_id, state, body, updated_at FROM update_approvals "
                "WHERE project=? ORDER BY updated_at DESC, approval_id LIMIT ?",
                (project, limit),
            ).fetchall()
        keep = (
            "phase",
            "reason",
            "reverted",
            "new_image",
            "old_image",
            "new_config_revision",
            "migration",
            "recovery_mode",
            "capture_id",
            "data_restore",
            "preserved_data",
            "applied_at",
            "auto_rollback",
            "emergency_reason",
        )
        out = []
        for approval_id, state, body, updated_at in rows:
            document = json.loads(body)
            journal = document["journal"]
            item = {
                "approval_id": approval_id,
                "state": state,
                "updated_at": updated_at,
                **{k: journal[k] for k in keep if k in journal},
            }
            if state == "validated" and "candidate" in document:
                item["candidate"] = document["candidate"]  # what a patch controller may apply
            out.append(item)
        return out

    def capture_records(self, project: str, limit: int = 200) -> list[dict[str, Any]]:
        """Captures taken by updates of this project (journal `recovery_capture`)."""
        with self._db() as conn:
            rows = conn.execute(
                "SELECT approval_id, state, body FROM update_approvals "
                "WHERE project=? ORDER BY updated_at DESC, approval_id LIMIT ?",
                (project, limit),
            ).fetchall()
        out = []
        for approval_id, state, body in rows:
            journal = json.loads(body)["journal"]
            ref = journal.get("recovery_capture")
            if not isinstance(ref, dict) or not isinstance(ref.get("artifact"), str):
                continue
            out.append(
                {
                    "approval_id": approval_id,
                    "state": state,
                    "artifact": ref["artifact"],
                    "completed_at": ref.get("completed_at"),
                    "preserved": journal.get("preserved_data"),
                    "preserved_at": journal.get("preserved_at"),
                }
            )
        return out

    def applying(self, project: str | None = None) -> list[str]:
        return self._in_state("applying", project)

    def rolling_back(self, project: str | None = None) -> list[str]:
        return self._in_state("rolling_back", project)

    def _in_state(self, state: str, project: str | None) -> list[str]:
        with self._db() as conn:
            rows = conn.execute(
                "SELECT approval_id FROM update_approvals WHERE state=? "
                "AND (? IS NULL OR project=?) ORDER BY approval_id",
                (state, project, project),
            ).fetchall()
        return [r[0] for r in rows]
