"""Scanner contract data: exact subjects, evidence, freshness and failure states.

A confirmed match is a provider's affected-version observation. It does not
assert exploitability, exposure, a successful fix or authority to mutate.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .canonical import revision_id
from .config import ImageRef, Slug
from .intelligence import CVEContext
from .inventory import ApplicationServiceScope, Digest, Inventory
from .secrets import redact

State = Literal["unknown", "stale", "scan_failed", "not_affected", "confirmed"]
Severity = Literal["unknown", "low", "medium", "high", "critical"]
ErrorClass = Literal[
    "unavailable",
    "timeout",
    "invalid_response",
    "unsupported",
    "quota_exhausted",
    "incomplete",
    "evidence_mismatch",
]
Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:-]{1,120}$")]


class Data(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Component(Data):
    kind: Literal["os_package", "dependency", "image"]
    scope: Literal["host"] | Slug | ApplicationServiceScope
    name: str = Field(min_length=1, max_length=300)
    version: str = Field(min_length=1, max_length=200)
    ecosystem: str | None = Field(None, max_length=80)
    image: ImageRef | None = None
    runtime_verified: bool = False
    expected_image_id: (
        Annotated[str, StringConstraints(pattern=r"^sha256:[a-f0-9]{64}$")] | None
    ) = None

    @model_validator(mode="after")
    def _subject(self) -> Component:
        if self.kind == "image" and (not self.image or not self.image.endswith("@" + self.version)):
            raise ValueError("image subjects require the exact manifest digest")
        if self.kind != "image" and (
            self.image is not None or self.runtime_verified or self.expected_image_id is not None
        ):
            raise ValueError("package subjects cannot claim image runtime verification")
        if self.kind != "image" and "/" in self.scope:
            raise ValueError("qualified application service scopes require image subjects")
        return self

    @property
    def key(self) -> str:
        excluded = {"runtime_verified"}
        if self.expected_image_id is None:
            excluded.add("expected_image_id")
        return revision_id(self.model_dump(mode="json", exclude=excluded))


class Advisory(Data):
    id: Identifier
    aliases: list[Identifier] = Field(default_factory=list, max_length=100)
    severity: Severity = "unknown"
    summary: str = Field(max_length=500)
    modified: str | None = Field(None, max_length=80)
    affected_package: str | None = Field(None, max_length=300)
    installed_version: str | None = Field(None, max_length=200)
    fixed_versions: list[Annotated[str, StringConstraints(max_length=200)]] = Field(
        default_factory=list, max_length=100
    )
    source_url: str | None = Field(None, max_length=500)
    exploit_context: list[CVEContext] = Field(default_factory=list, max_length=20)
    context_truncated: bool = False

    @field_validator("summary", mode="before")
    @classmethod
    def _summary(cls, value):
        return redact(str(value))[:500]


class ScanResult(Data):
    v: Literal[1] = 1
    source: Literal["osv", "trivy"]
    inventory_revision: Digest
    subject: Component
    checked_at: float = Field(ge=0)
    database_updated_at: float | None = Field(None, ge=0)
    state: State
    findings: list[Advisory] = Field(default_factory=list, max_length=1000)
    error_class: ErrorClass | None = None
    retry_after_s: float | None = Field(None, ge=1, le=3153600000)
    complete: bool = False

    @model_validator(mode="after")
    def _evidence(self) -> ScanResult:
        if self.retry_after_s is not None and self.error_class != "quota_exhausted":
            raise ValueError("retry delay requires a quota failure")
        if self.state in ("confirmed", "not_affected"):
            if (
                not self.complete
                or bool(self.findings) != (self.state == "confirmed")
                or self.error_class
            ):
                raise ValueError("successful scan state requires complete, consistent evidence")
        elif self.complete:
            raise ValueError("unknown/stale/failed results cannot claim complete evidence")
        return self

    def state_at(self, now: float, *, inventory_revision: str, max_age_s: int = 86400) -> State:
        if inventory_revision != self.inventory_revision:
            return "unknown"
        if (
            now < self.checked_at
            or now - self.checked_at > max_age_s
            or (
                self.database_updated_at is not None
                and (now < self.database_updated_at or now - self.database_updated_at > max_age_s)
            )
        ):
            return "stale"
        return self.state


class ScanError(Exception):
    def __init__(self, error_class: ErrorClass, *, retry_after_s: float | None = None):
        super().__init__(error_class)
        self.error_class = error_class
        self.retry_after_s = retry_after_s


def packages(inventory: Inventory) -> list[Component]:
    ecosystem = (
        f"Ubuntu:{inventory.os_version}:LTS"
        if inventory.os_id == "ubuntu"
        and inventory.os_version in {"20.04", "22.04", "24.04", "26.04"}
        else f"Debian:{inventory.os_version}"
        if inventory.os_id == "debian"
        else None
    )
    unique = {(p.source_name, p.source_version) for p in inventory.packages}
    return [
        Component(kind="os_package", scope="host", name=name, version=version, ecosystem=ecosystem)
        for name, version in sorted(unique)
    ]
