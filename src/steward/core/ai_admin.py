"""Transport-independent control operations for AI onboarding."""

from __future__ import annotations

import shutil
import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .ai_onboarding import HostFacts, LocalDownload, Onboarding, OnboardingError
from .config import AiFx
from .fx_rate import FxStore, rate_state
from .model_sources import SourceError

Name = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class LocalBody(_Body):
    model: str = Name
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    download_mb: int = Field(ge=1, le=10**6)
    ram_mb: int = Field(ge=128, le=1048576)
    disk_mb: int = Field(ge=1, le=10**7)
    license_ack: bool


class ProviderBody(_Body):
    option: str = Field(pattern=r"^[a-z][a-z0-9-]{2,31}$")
    key_ref: str | None = Field(None, max_length=300)
    local: LocalBody | None = None
    replace: bool = False


class ModelBody(_Body):
    model: str = Name


class AutoBody(_Body):
    enabled: bool


class SourceBody(_Body):
    url: str = Field(max_length=300)
    parser: str = Field(pattern=r"^[a-z][a-z0-9_]{2,40}$")


class ModeBody(_Body):
    mode: Literal["propose_confirm", "allowlist", "fixed", "automatic"]


class DomainsBody(_Body):
    domains: list[str] = Field(max_length=32)


class DecisionBody(_Body):
    accept: bool


def read_host_facts(path: Path, reserved_memory_mb: int = 1024) -> HostFacts:
    """Real RAM/disk of this host (never client-supplied)."""
    ram_kb = 0
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                ram_kb = int(line.split()[1])
    except (OSError, ValueError):
        pass
    probe = path if path.exists() else path.parent
    return HostFacts(
        ram_kb // 1024, shutil.disk_usage(probe).free // (1024 * 1024), reserved_memory_mb
    )


MAX_SOURCE_ID_LENGTH = 8192
SourceId = Annotated[str, Field(min_length=1, max_length=MAX_SOURCE_ID_LENGTH)]


class SourceIdBody(_Body):
    source_id: SourceId


class SourceDecisionBody(SourceIdBody, DecisionBody):
    pass


class InvalidAdminRequest(ValueError):
    """The action parameters do not conform to the control contract."""


class UnknownAdminAction(ValueError):
    """The action is outside the admin control surface."""


def valid_key(key: object) -> bool:
    return isinstance(key, str) and 8 <= len(key) <= 80 and key.replace("-", "").isalnum()


class AdminControl:
    def __init__(
        self,
        onboarding: Onboarding,
        *,
        fx_store: FxStore,
        read_fx: Callable[[], AiFx | None],
        clock: Callable[[], float] = time.time,
        host_facts: Callable[[], HostFacts] | None = None,
    ):
        self.onboarding = onboarding
        self.fx_store = fx_store
        self.read_fx = read_fx
        self.clock = clock
        self.host_facts = host_facts or (lambda: read_host_facts(onboarding.base))

    def dispatch(self, action: str, params: object) -> dict:
        if action not in self._ACTIONS:
            raise UnknownAdminAction
        model, operation = self._ACTIONS[action]
        if action == "view":
            if not isinstance(params, dict) or params:
                raise InvalidAdminRequest
            return {"status": "ok", "body": operation(self, _Body())}

        if (
            not isinstance(params, dict)
            or params.keys() != {"key", "body"}
            or not valid_key(params["key"])
            or not isinstance(params["body"], dict)
        ):
            raise InvalidAdminRequest
        try:
            body = model.model_validate(params["body"], strict=True)
        except ValidationError:
            raise InvalidAdminRequest from None

        try:
            with self.onboarding.control():
                result, replayed = self.onboarding.once(
                    f"{action}:{params['key']}", lambda: operation(self, body)
                )
        except (OnboardingError, SourceError) as exc:
            return {
                "status": "rejected",
                "code": exc.code,
                "problems": getattr(exc, "problems", []),
            }
        return {"status": "ok", "body": result, "replayed": replayed}

    def _view(self, _: _Body) -> dict:
        return self.onboarding.view(self._fx_state)

    def _fx_state(self) -> dict | None:
        fx = self.read_fx()
        if fx is None:
            return None
        rate, status = rate_state(fx, self.fx_store, self.clock())
        return {
            "status": status,
            "mode": fx.mode,
            "max_age_days": fx.max_age_days,
            "rate_ppm": rate.rate_ppm if rate else None,
            "as_of": rate.as_of if rate else None,
            "source": rate.source if rate else None,
        }

    def _brief(self) -> dict:
        state = self.onboarding.state()
        return {
            "status": state["status"],
            "pinned": state["pinned"],
            "auto_selection": state["auto"],
            "report_due": state["report_due"],
        }

    def _provider(self, body: ProviderBody) -> dict:
        local = LocalDownload(**body.local.model_dump()) if body.local else None
        self.onboarding.choose_provider(
            body.option, key_ref=body.key_ref, local=local,
            host=self.host_facts() if local else None, replace=body.replace,
        )  # fmt: skip
        return self._brief()

    def _scan(self, _: _Body) -> dict:
        return self.onboarding.request_action("scan")

    def _initial(self, body: ModelBody) -> dict:
        self.onboarding.pick_initial(body.model)
        self.onboarding.request_action("initial_check")
        return self._brief()

    def _pin(self, body: ModelBody) -> dict:
        self.onboarding.pin(body.model)
        if self.onboarding.state()["report_due"]:
            self.onboarding.request_action("initial_check")
        return self._brief()

    def _unpin(self, _: _Body) -> dict:
        self.onboarding.unpin()
        return self._brief()

    def _auto(self, body: AutoBody) -> dict:
        self.onboarding.set_auto(body.enabled)
        return self._brief()

    def _best_now(self, _: _Body) -> dict:
        if self.onboarding.state()["pinned"]:
            raise OnboardingError("model_pinned")
        return self.onboarding.request_action("best_now")

    def _source_add(self, body: SourceBody) -> dict:
        return {"id": self.onboarding.sources.add_source(body.url, body.parser, actor="operator")}

    def _source_remove(self, body: SourceIdBody) -> dict:
        self.onboarding.sources.remove_source(body.source_id, actor="operator")
        return {"removed": body.source_id}

    def _source_decision(self, body: SourceDecisionBody) -> dict:
        self.onboarding.sources.decide(body.source_id, body.accept, actor="operator")
        return {"id": body.source_id, "accepted": body.accept}

    def _source_mode(self, body: ModeBody) -> dict:
        self.onboarding.sources.set_mode(body.mode, actor="operator")
        return {"mode": body.mode}

    def _source_domains(self, body: DomainsBody) -> dict:
        self.onboarding.sources.set_allowed_domains(body.domains, actor="operator")
        return {"domains": self.onboarding.sources.allowed_domains()}

    def _source_research(self, _: _Body) -> dict:
        return self.onboarding.request_action("source_research")

    _ACTIONS = {
        "view": (_Body, _view),
        "provider": (ProviderBody, _provider),
        "scan": (_Body, _scan),
        "initial-model": (ModelBody, _initial),
        "pin": (ModelBody, _pin),
        "unpin": (_Body, _unpin),
        "auto": (AutoBody, _auto),
        "best-now": (_Body, _best_now),
        "source-add": (SourceBody, _source_add),
        "source-remove": (SourceIdBody, _source_remove),
        "source-decision": (SourceDecisionBody, _source_decision),
        "source-mode": (ModeBody, _source_mode),
        "source-domains": (DomainsBody, _source_domains),
        "source-research": (_Body, _source_research),
    }
