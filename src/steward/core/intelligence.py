"""Supplemental exploitation context; never affected-version or mutation proof."""

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

CVE = Annotated[str, StringConstraints(pattern=r"^CVE-[0-9]{4}-[0-9]{4,19}$")]
IntelState = Literal["disabled", "unknown", "available", "stale", "fetch_failed"]


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    source: Literal["kev", "epss"]
    state: IntelState = "disabled"
    checked_at: float | None = Field(None, ge=0)
    published_at: float | None = Field(None, ge=0)
    catalog_version: str | None = Field(None, min_length=1, max_length=80)
    listed: bool | None = None
    score: float | None = Field(None, ge=0, le=1)
    percentile: float | None = Field(None, ge=0, le=1)
    error_class: str | None = Field(None, max_length=40)

    @field_validator("checked_at", "published_at", "score", "percentile", mode="before")
    @classmethod
    def _not_boolean(cls, value):
        if isinstance(value, bool):
            raise ValueError("boolean is not a numeric observation")
        return value

    @model_validator(mode="after")
    def _source(self):
        if self.source == "kev" and (self.score is not None or self.percentile is not None):
            raise ValueError("KEV does not provide EPSS scores")
        if self.source == "epss" and (self.listed is not None or self.catalog_version is not None):
            raise ValueError("EPSS does not establish KEV membership")
        if self.state == "available":
            if self.checked_at is None or self.published_at is None or self.error_class:
                raise ValueError("available intelligence requires dated source evidence")
            if self.source == "kev" and (self.listed is None or self.catalog_version is None):
                raise ValueError("available KEV evidence requires a complete catalog")
            if self.source == "epss" and (self.score is None or self.percentile is None):
                raise ValueError("available EPSS evidence requires score and percentile")
        return self

    def state_at(self, now: float, *, max_age_s: int = 259200) -> IntelState:
        if self.state in ("available", "stale"):
            if any(
                t is None or not 0 <= now - t <= max_age_s
                for t in (self.checked_at, self.published_at)
            ):
                return "stale"
            return "available"
        return self.state


class CVEContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve: CVE
    kev: Evidence = Evidence(source="kev")
    epss: Evidence = Evidence(source="epss")

    @model_validator(mode="after")
    def _sources(self):
        if self.kev.source != "kev" or self.epss.source != "epss":
            raise ValueError("context source mismatch")
        return self


def context_key(finding: dict, now: float) -> tuple[int, float]:
    """KEV first, then EPSS for equal provider severity (callers add that rank)."""
    contexts = [CVEContext.model_validate(c) for c in finding.get("exploit_context", [])]
    kev = any(c.kev.state_at(now) == "available" and c.kev.listed is True for c in contexts)
    epss = max((c.epss.score for c in contexts if c.epss.state_at(now) == "available"), default=0)
    return int(kev), epss


def at_time(finding: dict, now: float) -> dict:
    contexts = []
    for value in finding.get("exploit_context", []):
        context = CVEContext.model_validate(value)
        for evidence in (context.kev, context.epss):
            evidence.state = evidence.state_at(now)
        contexts.append(context.model_dump(mode="json"))
    return {**finding, "exploit_context": contexts}


def fingerprint(finding: dict, now: float) -> dict:
    """Semantic changes only; refresh times and daily score drift are not alerts."""
    value = at_time(finding, now)
    value["exploit_context"] = [
        {
            "cve": c["cve"],
            "kev_state": c["kev"]["state"],
            "kev_listed": c["kev"]["listed"],
            "epss_state": c["epss"]["state"],
        }
        for c in value["exploit_context"]
    ]
    return value
