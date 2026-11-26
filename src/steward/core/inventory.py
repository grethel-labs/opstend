"""Versioned read-only inventory and revision-bound pagination."""

from __future__ import annotations

from collections.abc import Callable
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

Name = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9+.-]{0,199}$")]
Version = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9.+:~_-]{1,200}$")]
Digest = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
ApplicationServiceScope = Annotated[
    str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,30}[a-z0-9]/[a-z][a-z0-9-]{1,30}[a-z0-9]$")
]


class Package(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: Name
    version: Version
    architecture: Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]{1,40}$")]
    source_name: Name
    source_version: Version


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    v: Literal[1] = 1
    os_id: Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]{1,40}$")]
    os_version: Annotated[str, StringConstraints(pattern=r"^[0-9.]{1,40}$")]
    running_kernel: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._+:-]{1,200}$")]
    reboot_required: bool | None = None
    kernel_build: str | None = Field(None, max_length=300)
    config_revision: Digest
    projects: list[str] = Field(default_factory=list, max_length=64)
    application_services: list[ApplicationServiceScope] | None = Field(None, max_length=64)
    packages: list[Package] = Field(max_length=50000)

    @field_validator("application_services")
    @classmethod
    def _application_services(
        cls, services: list[ApplicationServiceScope] | None
    ) -> list[ApplicationServiceScope] | None:
        if services and len(services) != len(set(services)):
            raise ValueError("duplicate application service")
        return services or None

    @model_validator(mode="after")
    def _image_target_limit(self) -> Inventory:
        if len(self.projects) + len(self.application_services or ()) > 64:
            raise ValueError("at most 64 image targets are supported")
        return self

    @property
    def revision(self) -> str:
        body = self.model_dump(mode="json", exclude_none=True)
        if not self.application_services:
            body.pop("application_services", None)
        return revision_id(body)


def collect(executor: Callable, *, socket_path: str) -> Inventory:
    """No mixed snapshots: every page and the final body bind the same revision."""
    from ..executor.protocol import ExecutorError

    packages, revision, total, metadata = [], None, None, None
    for _ in range(251):
        result = executor(
            "inventory_page",
            {"offset": len(packages), "limit": 200, "expected_revision": revision},
            socket_path=socket_path,
        )
        if revision is None:
            revision, total, metadata = result["revision"], result["total"], result["metadata"]
            if not isinstance(total, int) or not 0 <= total <= 50000:
                raise ExecutorError("internal", "invalid inventory size")
        if result["revision"] != revision or result["total"] != total:
            raise ExecutorError("unavailable", "inventory changed during collection")
        page = result["packages"]
        if not isinstance(page, list) or len(page) > 200 or len(packages) + len(page) > total:
            raise ExecutorError("internal", "invalid inventory page")
        packages.extend(page)
        if len(packages) == total:
            inventory = Inventory.model_validate({**metadata, "packages": packages})
            if inventory.revision != revision:
                raise ExecutorError("internal", "inventory content does not match revision")
            return inventory
        if not page:
            raise ExecutorError("internal", "incomplete inventory")
    raise ExecutorError("internal", "inventory page budget exhausted")
