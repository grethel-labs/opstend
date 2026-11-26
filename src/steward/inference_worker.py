"""Run AI onboarding and scheduled selection or serve managed inference IPC."""

from __future__ import annotations

import fcntl
import json
import math
import os
import pwd
import re
import selectors
import socket
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .adapters.inference import OLLAMA_URL, OllamaProvider, build_provider
from .core.advice import ADVICE_TASK
from .core.advice_ipc import (
    MANAGED_DIRECTORY,
    MANAGED_ROLES,
    WORKER_TIMEOUT_S,
    AdviceServer,
    ManagedAdviceServer,
    managed_socket_path,
)
from .core.ai_admin import AdminControl, InvalidAdminRequest, ProviderBody, valid_key
from .core.ai_admin_ipc import CANDIDATE_SCOPE_CODE, MANAGED_SOCKET, _AdminServer, _validate_uid
from .core.ai_onboarding import MODEL_NAME, Onboarding, OnboardingError, evaluate_model
from .core.audit import AuditLog
from .core.canonical import revision_id
from .core.config import UNAVAILABLE_FEATURES, Ai, AiBudget, AiFx, AiScopeLimits
from .core.fx_rate import FxStore, fetch_in_window, make_rate_guard, pinned_https_fetcher
from .core.inference import (
    VERSION,
    InferenceError,
    InferenceProvider,
    InferenceService,
    Outcome,
    Policy,
)
from .core.inference_budget import Ledger, Price
from .core.inference_models import PROVIDER_OPTIONS
from .core.inference_snapshot import Item, Scope
from .core.maintenance import admit, parse_window_spec
from .core.maintenance_runs import MaintenanceRuns
from .core.model_selection import (
    WORK_ID,
    WORK_SECONDS,
    Decision,
    RunResult,
    SelectionGuards,
    SelectionStore,
    WeeklySelection,
    price_state,
)
from .core.model_sources import SourceStore
from .core.model_suite import SUITE_DATA_CLASS, SUITE_REVISION
from .core.store import Store

PROJECTION_PATH = Path("/etc/steward/inference/selection.json")
KILL_SWITCH_PATH = Path("/etc/steward/killswitch")
STATE_DIR = Path("/var/lib/steward-inference")
MAX_PROJECTION_BYTES = 128 * 1024


@dataclass(frozen=True)
class AppliedPolicy:
    revision: str
    ai: Ai
    weekly_window: str | None
    generation: str | None = None
    manifest_sha256: str | None = None


ProviderBuilder = Callable[[Ai], InferenceProvider]
PolicyReader = Callable[[], AppliedPolicy | None]


def _data_class(ai: Ai) -> str:
    return "external" if ai.is_external else "local"


def _matches(ai: Ai, state: dict) -> bool:
    option = PROVIDER_OPTIONS.get(state["provider"] or "")
    return bool(
        option
        and option.adapter == ai.provider
        and option.data_class == _data_class(ai)
        and option.auth in ("api_key", "none")
        and state["key_ref"] == ai.api_key_ref
    )


def _candidate_declaration(policy: AppliedPolicy) -> dict:
    local = policy.ai.local
    assert local is not None
    return local.model_dump(exclude={"device"}) | {
        "model": policy.ai.model,
        "sha256": policy.manifest_sha256,
    }


def _candidate_matches(policy: AppliedPolicy, state: dict) -> bool:
    return (
        bool(state["choice_id"])
        and state["provider"] == "ollama-local"
        and state["key_ref"] is None
        and state["local"] == _candidate_declaration(policy)
    )


def _ready(state: dict) -> bool:
    return state["status"] == "ready" and (
        state["provider"] != "ollama-local" or state["download_confirmed"] is True
    )


def _active(selection: SelectionStore, ai: Ai, state: dict) -> dict | None:
    if not state["choice_id"] or not _ready(state) or not _matches(ai, state):
        return None
    active = selection.active(provider=ai.provider, data_class=_data_class(ai))
    if (
        active
        and active["choice_id"] == state["choice_id"]
        and isinstance(active["model"], str)
        and MODEL_NAME.fullmatch(active["model"])
    ):
        return active
    return None


def _build(ai: Ai, model: str, builder: ProviderBuilder) -> InferenceProvider:
    if not MODEL_NAME.fullmatch(model):
        raise InferenceError("model_unavailable", spend="none")
    try:
        configured = Ai.model_validate(ai.model_dump() | {"model": model})
        provider = builder(configured)
        if (
            provider.name == ai.provider
            and provider.data_class == _data_class(ai)
            and provider.model == model
        ):
            return provider
    except InferenceError:
        raise
    except Exception:
        raise InferenceError("unavailable", spend="none") from None
    raise InferenceError("policy_denied", spend="none")


def build_effective_provider(
    *, policy: AppliedPolicy, state_dir: Path | str, provider_builder: ProviderBuilder | None = None
) -> InferenceProvider | None:
    """Use the current bound selection, falling back to the configured model."""
    ai = policy.ai
    if ai.provider == "none" or ai.model is None:
        return None
    base = Path(state_dir)
    model = ai.model
    # A missing or unreadable selection cannot override the applied model.
    with suppress(Exception):
        if (base / "onboarding.db").is_file() and (base / "selection.db").is_file():
            onboarding = _onboarding(base, time.time)
            with onboarding.control():
                active = _active(onboarding.selection, ai, onboarding.state())
                if active:
                    model = active["model"]
    try:
        return _build(ai, model, provider_builder or build_provider)
    except InferenceError:
        return None


def _read_policy(reader: PolicyReader) -> AppliedPolicy | None:
    try:
        policy = reader()
        if isinstance(policy, AppliedPolicy) and type(policy.revision) is str and policy.revision:
            if policy.weekly_window is not None:
                parse_window_spec(policy.weekly_window)
            # Detach the binding from mutable objects owned by the caller.
            ai = Ai.model_validate(policy.ai.model_dump())
            if policy.generation is None:
                if policy.manifest_sha256 is not None:
                    return None
            elif (
                not re.fullmatch(r"[a-f0-9]{32}", policy.generation)
                or not re.fullmatch(r"[a-f0-9]{64}", policy.manifest_sha256 or "")
                or ai.provider != "ollama"
                or not ai.local_only
                or ai.local is None
                or not ai.local.license_ack
                or ai.api_key_ref is not None
                or ai.share
                or ai.fx is not None
                or ai.model_policy is not None
                or ai.base_url not in (None, OLLAMA_URL)
            ):
                return None
            return AppliedPolicy(
                policy.revision, ai, policy.weekly_window, policy.generation, policy.manifest_sha256
            )
    except Exception:
        return None
    return None


def _allowed(kill_switch: Callable[[], object]) -> bool:
    try:
        return kill_switch() is False
    except Exception:
        return False


def _onboarding(base: Path, clock: Callable[[], float], audit=None) -> Onboarding:
    return Onboarding(
        base,
        SelectionStore(base / "selection.db"),
        SourceStore(base / "sources.db", clock=clock),
        clock=clock,
        audit=audit,
    )


def _worker_audit(base: Path) -> Callable[[dict], None]:
    log = AuditLog(base / "worker-audit.jsonl")

    def audit(event: dict) -> None:
        with suppress(Exception):
            log.append(event["event"], **{key: val for key, val in event.items() if key != "event"})

    return audit


def _private_state_dir(base: Path) -> None:
    base.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = base.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise PermissionError


@contextmanager
def _process_lock(base: Path) -> Iterator[bool]:
    _private_state_dir(base)
    fd = os.open(
        base / "worker.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
    )
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PermissionError
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
        else:
            yield True
    finally:
        os.close(fd)


class _GuardedProvider:
    """Recheck the immutable binding and cap timeouts at actual dispatch."""

    def __init__(
        self,
        provider: InferenceProvider,
        dispatch_guard: Callable[[], str | None],
        remaining: Callable[[], float],
    ):
        self._provider = provider
        self._guard = dispatch_guard
        self._remaining = remaining
        self.name, self.data_class, self.model = provider.name, provider.data_class, provider.model
        self.version, self.max_input_bytes = provider.version, provider.max_input_bytes
        self.capabilities = provider.capabilities
        self.timeout_s = provider.timeout_s

    def _timeout(self, requested: float) -> float:
        reason = self._guard()
        remaining = self._remaining()
        if remaining <= 0:
            raise InferenceError("timeout", spend="none")
        if reason is not None or (
            self._provider.name,
            self._provider.data_class,
            self._provider.model,
        ) != (
            self.name,
            self.data_class,
            self.model,
        ):
            raise InferenceError("policy_denied", spend="none")
        return min(requested, self.timeout_s, remaining)

    def list_models(self, timeout_s: float = 10.0) -> list[str]:
        lister = getattr(self._provider, "list_models", None)
        if lister is None:
            raise InferenceError("unsupported", spend="none")
        try:
            names = lister(timeout_s=self._timeout(timeout_s))
            return [name for name in names if isinstance(name, str) and MODEL_NAME.fullmatch(name)]
        except InferenceError:
            raise
        except Exception:
            raise InferenceError("unavailable", spend="unknown") from None

    def complete(self, system, user, *, schema, max_output_tokens, timeout_s):
        return self._provider.complete(
            system,
            user,
            schema=schema,
            max_output_tokens=max_output_tokens,
            timeout_s=self._timeout(timeout_s),
        )


def _incomplete(model: str, reason: str) -> dict:
    return {
        "suite_revision": SUITE_REVISION,
        "model": model,
        "complete": False,
        "passed": False,
        "error": reason,
        "cases": 0,
        "schema_ok": 0,
        "task_ok": 0,
        "runtime_s": 0.0,
        "tokens": 0,
        "cost_micro": None,
    }


def _identity(state: dict) -> tuple:
    return state["choice_id"], state["provider"], state["key_ref"]


class _Tick:
    def __init__(
        self,
        base,
        read_policy,
        kill_switch,
        builder,
        clock,
        monotonic,
        before_activation,
        runs,
        candidate_policy,
    ):
        self.read_policy, self.kill_switch, self.builder = read_policy, kill_switch, builder
        self.clock, self.monotonic, self.before_activation = clock, monotonic, before_activation
        self.runs = runs
        self.audit = _worker_audit(base)
        self.onboarding = _onboarding(base, clock, self.audit)
        self.selection = self.onboarding.selection
        self.fx = FxStore(base / "fx.db")
        self.selection_started = False
        self.candidate_policy = candidate_policy

    def policy(self) -> AppliedPolicy | None:
        policy = _read_policy(self.read_policy)
        if self.candidate_policy is not None and policy != self.candidate_policy:
            return None
        return policy

    def _snapshot(self, row: dict | None = None) -> tuple[dict, AppliedPolicy | None, dict | None]:
        state = self.onboarding.state()
        if row is not None and row["choice_id"] != state["choice_id"]:
            raise OnboardingError("choice_changed")
        policy = self.policy()
        active = (
            _active(self.selection, policy.ai, state)
            if policy and self.candidate_policy is None
            else None
        )
        return state, policy, active

    def _binding_reason(self, state: dict, policy: AppliedPolicy | None) -> str | None:
        if policy is None:
            return "applied_policy_unavailable"
        if policy.generation is not None:
            if not _candidate_matches(policy, state):
                return "applied_provider_mismatch"
        elif not _matches(policy.ai, state):
            return "applied_provider_mismatch"
        if not _allowed(self.kill_switch):
            return "kill_switch"
        return None

    def _guarded_provider(self, ai, model, guard, remaining) -> _GuardedProvider:
        with self.onboarding.control():
            if remaining() <= 0:
                raise InferenceError("timeout", spend="none")
            if guard() is not None:
                raise InferenceError("policy_denied", spend="none")
        provider = _build(ai, model, self.builder)

        def dispatch_guard() -> str | None:
            with self.onboarding.control():
                return guard()

        try:
            guarded = _GuardedProvider(provider, dispatch_guard, remaining)
            if (
                guarded.version == VERSION
                and guarded.max_input_bytes > 0
                and math.isfinite(guarded.timeout_s)
                and guarded.timeout_s > 0
            ):
                return guarded
        except (AttributeError, TypeError, ValueError):
            raise InferenceError("unavailable", spend="none") from None
        raise InferenceError("unavailable", spend="none")

    def scan(self, row: dict) -> str:
        with self.onboarding.control():
            state, policy, _ = self._snapshot(row)
        if reason := self._binding_reason(state, policy):
            raise OnboardingError(reason)
        assert policy is not None and policy.ai.model is not None

        def publish_guard() -> str | None:
            current = self.onboarding.state()
            if _identity(current) != _identity(state):
                return "choice_changed"
            if self.policy() != policy:
                return "applied_policy_changed"
            return self._binding_reason(current, policy)

        provider = self._guarded_provider(
            policy.ai, policy.ai.model, publish_guard, lambda: float("inf")
        )
        self.onboarding.scan(provider, publish_guard=publish_guard)
        return "ok"

    def initial_check(self, row: dict) -> str:
        with self.onboarding.control():
            state, policy, active = self._snapshot(row)
            # Fence incomplete reports even when applied policy is absent.
            option = PROVIDER_OPTIONS.get(state["provider"] or "")
            pointer = (
                self.selection.active(provider=option.adapter, data_class=option.data_class)
                if option
                else None
            )
        due = state["report_due"]

        def publish_guard() -> str | None:
            current = self.onboarding.state()
            if _identity(current) != _identity(state) or current["report_due"] != due:
                return "report_due_changed"
            if self.policy() != policy:
                return "applied_policy_changed"
            if (
                option
                and self.selection.active(provider=option.adapter, data_class=option.data_class)
                != pointer
            ):
                return "active_selection_changed"
            return None

        def dispatch_guard() -> str | None:
            return publish_guard() or self._binding_reason(self.onboarding.state(), policy)

        def check(model: str) -> dict:
            if reason := self._binding_reason(state, policy):
                return _incomplete(model, reason)
            assert policy is not None
            ai = policy.ai
            if active is None or active["model"] != model:
                return _incomplete(model, "onboarding_incomplete")
            if ai.is_external and SUITE_DATA_CLASS not in ai.share:
                return _incomplete(model, "suite_data_class_not_shared")
            evaluation = ai.model_policy
            if evaluation is None:
                return _incomplete(model, "evaluation_policy_unavailable")
            try:
                provider = self._guarded_provider(ai, model, dispatch_guard, lambda: float("inf"))
            except InferenceError as exc:
                return _incomplete(model, exc.error_class)
            price, _ = price_state(
                evaluation, model, datetime.fromtimestamp(self.clock(), UTC).date()
            )
            ledger = Ledger(
                self.onboarding.ledger_path("initial_check"),
                AiBudget(
                    monthly=AiScopeLimits(
                        tokens=evaluation.max_eval_tokens, cost_micro=evaluation.max_eval_cost_micro
                    )
                ),
                rate_guard=make_rate_guard(ai.fx, self.fx),
            )
            try:
                return evaluate_model(
                    provider,
                    ledger,
                    price=price,
                    share=frozenset(ai.share),
                    clock=self.clock,
                    monotonic=self.monotonic,
                )
            finally:
                ledger.close()

        report = self.onboarding.ensure_report(check, publish_guard=publish_guard)
        if report is None:
            return "no_report_due"
        return "complete" if report["body"]["complete"] else "incomplete"

    def select(self, mode: str, row: dict | None = None) -> RunResult:
        if self.selection_started:
            return RunResult("skipped", "selection_already_attempted")
        with self.onboarding.control():
            state, policy, active = self._snapshot(row)
        if reason := self._binding_reason(state, policy):
            return RunResult("skipped", reason)
        if not active:
            return RunResult("skipped", "onboarding_incomplete")
        if state["pinned"]:
            return RunResult("skipped", "model_pinned")
        if mode == "weekly" and state["auto"] is not True:
            return RunResult("skipped", "auto_selection_disabled")
        assert policy is not None
        ai = policy.ai
        window_spec = policy.weekly_window
        if ai.model_policy is None:
            return RunResult("skipped", "evaluation_policy_unavailable")
        if ai.is_external and SUITE_DATA_CLASS not in ai.share:
            return RunResult("skipped", "suite_data_class_not_shared")
        if window_spec is None:
            return RunResult("not_admitted", "maintenance_window_unavailable")
        start = self.clock()
        admitted = admit(window_spec, datetime.fromtimestamp(start, UTC), work_seconds=WORK_SECONDS)
        if not admitted.allowed or admitted.window is None:
            return RunResult("not_admitted", admitted.reason)
        window_start = admitted.window.start.timestamp()
        wall_end = min(admitted.window.end.timestamp(), start + WORK_SECONDS)
        mono_end = self.monotonic() + WORK_SECONDS
        incumbent_id = active["decision_id"]

        def remaining() -> float:
            now = self.clock()
            return min(wall_end - now, mono_end - self.monotonic()) if now >= window_start else 0.0

        def guard() -> str | None:
            if remaining() <= 0:
                return "selection_deadline"
            if self.policy() != policy:
                return "applied_policy_changed"
            current = self.onboarding.state()
            if _identity(current) != _identity(state):
                return "choice_changed"
            if reason := self._binding_reason(current, policy):
                return reason
            if current["pinned"]:
                return "model_pinned"
            if mode == "weekly" and current["auto"] is not True:
                return "auto_selection_disabled"
            current_active = _active(self.selection, ai, current)
            if not current_active or current_active["decision_id"] != incumbent_id:
                return "active_selection_changed"
            return None

        source_guard = self.onboarding.sources.switch_guard(start)

        def activate(
            did: str,
            decision: Decision,
            expected_id: str | None,
            price_check: Callable[[float], str | None],
        ) -> str | None:
            with self.onboarding.control():
                if reason := guard() or source_guard(decision):
                    return reason
                if reason := guard():
                    return reason
                now = self.clock()
                if reason := price_check(now):
                    return reason
                if expected_id != incumbent_id or not self.selection.activate(
                    did, now=now, expected_active=expected_id
                ):
                    return "activation_refused"
            return None

        def make_selection(_guards, _work_id, ledger_path):
            return WeeklySelection(
                ai=ai,
                window_spec=window_spec,
                runs=self.runs,
                store=self.selection,
                eval_ledger_path=ledger_path,
                make_provider=lambda model: self._guarded_provider(ai, model, guard, remaining),
                clock=self.clock,
                monotonic=self.monotonic,
                audit=self.audit,
                before_activation=(
                    (lambda _did: self.before_activation())
                    if self.before_activation is not None
                    else None
                ),
                work_id=WORK_ID,
                guards=SelectionGuards(skip=guard, switch=source_guard),
                rate_guard=make_rate_guard(ai.fx, self.fx),
                activate_decision=activate,
                metadata={"mode": mode, "choice_id": state["choice_id"]},
                recover_pending=False,
            )

        with self.onboarding.control():
            if reason := guard():
                return RunResult("skipped", reason)
        self.selection_started = True
        if mode == "best_now":
            return self.onboarding.best_now(make_selection)
        selection = make_selection(None, WORK_ID, self.onboarding.ledger_path("weekly"))
        result = selection.run()
        with self.onboarding.control():
            if _identity(self.onboarding.state()) == _identity(state):
                self.onboarding.on_selection_result(result)
        return result

    def recover(self) -> None:
        with self.onboarding.control():
            self.selection.recover()
            self.onboarding.recover_requests()
            state = self.onboarding.state()
            policy = self.policy()
            if policy is None or not _active(self.selection, policy.ai, state):
                return
            ai = policy.ai
            row = self.selection.latest_activated(
                provider=ai.provider, data_class=_data_class(ai), choice_id=state["choice_id"]
            )
            if row is None:
                return
            body = row["body"]
            decision = Decision(
                row["action"], row["incumbent"], row["chosen"], tuple(body.get("reasons", ()))
            )
            self.onboarding.on_selection_result(
                RunResult("switched", decision=decision, decision_id=row["id"], body=body)
            )

    def refresh_ecb_rate(self) -> None:
        policy = self.policy()
        if (
            policy is None
            or policy.generation is not None
            or policy.weekly_window is None
            or policy.ai.local_only
        ):
            return
        fx = policy.ai.fx
        if fx is None or fx.mode != "fetched" or fx.parser != "ecb_daily_xml_v1":
            return

        def guard() -> str | None:
            if self.policy() != policy:
                return "applied_policy_changed"
            if not _allowed(self.kill_switch):
                return "kill_switch"
            return None

        fetch_in_window(
            fx,
            self.fx,
            self.runs,
            policy.weekly_window,
            pinned_https_fetcher(),
            clock=self.clock,
            audit=self.audit,
            guard=guard,
        )

    def run(self) -> dict:
        if self.candidate_policy is not None:
            with self.onboarding.control():
                if self.policy() is None:
                    return {"status": "unavailable", "reason": "applied_policy_unavailable"}
                self.onboarding.recover_requests()
            handlers = {"scan": self.scan}
        else:
            self.runs.recover(self.clock())
            self.recover()
            self.refresh_ecb_rate()
            handlers = {
                "scan": self.scan,
                "initial_check": self.initial_check,
                "best_now": lambda row: self.select("best_now", row),
                "source_research": lambda row: "source_research_unavailable",
            }
        requests = self.onboarding.process_requests(
            handlers,
            limit=4,
            bind_choice=True,
        )
        weekly = (
            RunResult("skipped", CANDIDATE_SCOPE_CODE)
            if self.candidate_policy is not None
            else self.select("weekly")
        )
        self.audit(
            {"event": "inference.worker_tick", "status": weekly.status, "reason": weekly.reason}
        )
        return {
            "status": "ok",
            "requests": requests,
            "weekly": {"status": weekly.status, "reason": weekly.reason},
        }


def run_once(
    *,
    read_policy: PolicyReader,
    state_dir: Path | str,
    kill_switch: Callable[[], object],
    provider_builder: ProviderBuilder | None = None,
    clock: Callable[[], float | datetime] | None = None,
    monotonic: Callable[[], float] | None = None,
    before_activation: Callable[[], None] | None = None,
    candidate_policy: AppliedPolicy | None = None,
) -> dict[str, Any]:
    """Handle a bounded request snapshot under the private worker lock."""
    wall_clock = clock or time.time

    def now() -> float:
        value = wall_clock()
        if isinstance(value, datetime):
            if value.utcoffset() is None:
                raise ValueError("worker clock must be timezone-aware")
            return value.timestamp()
        return float(value)

    base = Path(state_dir)
    try:
        with _process_lock(base) as acquired:
            if not acquired:
                return {"status": "busy"}
            store = Store(base / "maintenance.db")
            try:
                tick = _Tick(
                    base,
                    read_policy,
                    kill_switch,
                    provider_builder or build_provider,
                    now,
                    monotonic or time.monotonic,
                    before_activation,
                    MaintenanceRuns(store),
                    candidate_policy,
                )
                return tick.run()
            finally:
                store.close()
    except Exception:
        return {"status": "unavailable", "reason": "worker_state_unavailable"}


def _trusted_directory(path: Path) -> bool:
    for directory in (*reversed(path.parents), path):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            return False
    return os.access(path, os.X_OK)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate projection field")
        obj[key] = value
    return obj


def read_projection(path: Path = PROJECTION_PATH) -> AppliedPolicy | None:
    try:
        if not path.is_absolute() or not _trusted_directory(path.parent):
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return None
            body = file.read(MAX_PROJECTION_BYTES + 1)
        if len(body) > MAX_PROJECTION_BYTES:
            return None
        obj = json.loads(body, object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(obj, dict) or obj.keys() != {"revision", "ai", "weekly_window"}:
            return None
        ai = Ai.model_validate(obj["ai"], strict=True)
        policy = AppliedPolicy(obj["revision"], ai, obj["weekly_window"])
        return _read_policy(lambda: policy)
    except (OSError, ValueError, TypeError, RecursionError):
        return None


def _read_candidate() -> AppliedPolicy | None:
    from .core.inference_deployment import read_candidate_policy

    policy = read_candidate_policy()
    if policy is None:
        return None
    return AppliedPolicy(
        policy.revision, policy.ai, policy.weekly_window, policy.generation, policy.manifest_sha256
    )


class _CandidateAdminControl(AdminControl):
    def __init__(self, *args, read_policy: PolicyReader, **kwargs):
        super().__init__(*args, **kwargs)
        self.read_policy = read_policy

    def _require_policy(self, expected: AppliedPolicy | None = None) -> AppliedPolicy:
        policy = _read_policy(self.read_policy)
        if policy is None or policy.generation is None or (expected and policy != expected):
            raise InvalidAdminRequest
        return policy

    def _refuse(self, policy: AppliedPolicy) -> dict:
        self._require_policy(policy)
        return {"status": "rejected", "code": CANDIDATE_SCOPE_CODE, "problems": []}

    def dispatch(self, action: str, params: object) -> dict:
        policy = self._require_policy()
        if action == "view":
            state = self.onboarding.state()
            if state["provider"] is not None and not _candidate_matches(policy, state):
                return self._refuse(policy)
            result = super().dispatch(action, params)
            self._require_policy(policy)
            current = self.onboarding.state()
            if current["provider"] is not None and not _candidate_matches(policy, current):
                return self._refuse(policy)
            return result
        if action not in ("provider", "scan"):
            return self._refuse(policy)
        if (
            not isinstance(params, dict)
            or params.keys() != {"key", "body"}
            or not valid_key(params["key"])
            or not isinstance(params["body"], dict)
        ):
            raise InvalidAdminRequest
        try:
            with self.onboarding.control():
                self._require_policy(policy)
                binding = revision_id([policy.revision, _candidate_declaration(policy)])
                key = f"candidate:{binding}:{action}:{params['key']}"
                if action == "provider":
                    body = ProviderBody.model_validate(params["body"], strict=True)
                    if (
                        body.option != "ollama-local"
                        or body.key_ref is not None
                        or body.local is None
                        or body.local.model_dump() != _candidate_declaration(policy)
                    ):
                        return self._refuse(policy)
                    operation = partial(self._provider, body)
                else:
                    if params["body"]:
                        raise InvalidAdminRequest
                    state = self.onboarding.state()
                    if not _candidate_matches(policy, state):
                        return self._refuse(policy)
                    key = f"{key}:{state['choice_id']}"
                    operation = partial(self.onboarding.request_action, "scan")

                def mutate() -> dict:
                    self._require_policy(policy)
                    return operation()

                result, replayed = self.onboarding.once(key, mutate)
                self._require_policy(policy)
                if not _candidate_matches(policy, self.onboarding.state()):
                    return self._refuse(policy)
        except ValidationError:
            raise InvalidAdminRequest from None
        except OnboardingError as exc:
            self._require_policy(policy)
            return {"status": "rejected", "code": exc.code, "problems": exc.problems}
        return {"status": "ok", "body": result, "replayed": replayed}


def make_advice_server(
    listener: socket.socket,
    *,
    bot_uid: int,
    provider: InferenceProvider,
    ledger: Ledger,
    policy: Policy,
    prices: Mapping[str, Price | None] | None = None,
    audit: Callable[[dict], None] | None = None,
    clock: Callable[[], float] = time.time,
) -> AdviceServer:
    """Compose the dedicated advice listener from trusted startup inputs."""
    inference = InferenceService(
        provider, ledger, policy, prices=prices, audit=audit, max_attempts=1, clock=clock
    )
    return AdviceServer(listener, bot_uid, inference)


def make_admin_server(
    listener: socket.socket,
    *,
    socket_path: Path,
    state_dir: Path,
    admin_uid: int,
    read_policy: PolicyReader = read_projection,
    clock: Callable[[], float] = time.time,
    candidate: bool = False,
) -> _AdminServer:
    """Adopt a dedicated, already-listening socket and serve worker-owned admin state."""
    _validate_uid(admin_uid)
    if not socket_path.is_absolute() or not _trusted_directory(socket_path.parent):
        raise PermissionError("untrusted AI admin socket directory")
    if (
        listener.family != socket.AF_UNIX
        or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
        or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        or listener.getsockname() != str(socket_path)
        or not stat.S_ISSOCK(socket_path.lstat().st_mode)
    ):
        raise ValueError("invalid AI admin listener")

    _private_state_dir(state_dir)

    def read_fx() -> AiFx | None:
        policy = _read_policy(read_policy)
        return policy.ai.fx if policy is not None else None

    onboarding = _onboarding(state_dir, clock, _worker_audit(state_dir))
    options = {"fx_store": FxStore(state_dir / "fx.db"), "read_fx": read_fx, "clock": clock}
    control = (
        _CandidateAdminControl(onboarding, read_policy=read_policy, **options)
        if candidate
        else AdminControl(onboarding, **options)
    )
    return _AdminServer(listener, admin_uid, control.dispatch)


def read_kill_switch(path: Path = KILL_SWITCH_PATH) -> bool:
    """Treat an inaccessible marker or an untrusted parent as a stop."""
    try:
        if not path.is_absolute() or not _trusted_directory(path.parent):
            return True
        try:
            path.lstat()
        except FileNotFoundError:
            return False
    except OSError:
        return True
    return True


def _managed_admin_uid() -> tuple[int, int]:
    api = pwd.getpwnam("steward-api")
    inference = pwd.getpwnam("steward-inference")
    ollama = pwd.getpwnam("steward-ai")
    for uid in (api.pw_uid, inference.pw_uid, ollama.pw_uid):
        _validate_uid(uid)
    if len({0, api.pw_uid, inference.pw_uid, ollama.pw_uid}) != 4:
        raise PermissionError("AI services must have distinct non-root UIDs")
    if os.getuid() != inference.pw_uid or os.geteuid() != inference.pw_uid:
        raise PermissionError("unexpected inference service UID")
    return api.pw_uid, api.pw_gid


def _serve_managed_admin() -> None:
    if os.environ.pop("LISTEN_PID", None) != str(os.getpid()):
        raise ValueError("invalid systemd listener PID")
    if os.environ.pop("LISTEN_FDS", None) != "1":
        raise ValueError("expected one systemd listener")
    os.environ.pop("LISTEN_FDNAMES", None)
    admin_uid, admin_gid = _managed_admin_uid()
    path = Path(MANAGED_SOCKET)
    if not _trusted_directory(path.parent):
        raise PermissionError("untrusted manager socket directory")
    info = path.lstat()
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != admin_gid
        or stat.S_IMODE(info.st_mode) != 0o660
    ):
        raise PermissionError("invalid manager socket ownership or permissions")
    with socket.socket(fileno=3) as listener:
        listener.set_inheritable(False)
        with make_admin_server(
            listener,
            socket_path=path,
            state_dir=STATE_DIR,
            admin_uid=admin_uid,
            read_policy=_read_candidate,
            candidate=True,
        ) as server:
            server.serve_forever()


def _managed_advice_accounts() -> dict[str, pwd.struct_passwd]:
    accounts = {name: pwd.getpwnam(f"steward-{name}") for name in ("bot", "api", "inference", "ai")}
    uids = {account.pw_uid for account in accounts.values()}
    for uid in uids:
        _validate_uid(uid)
    if len(uids) != 4 or 0 in uids:
        raise PermissionError("advice services must have distinct non-root UIDs")
    worker_uid = accounts["inference"].pw_uid
    if os.getuid() != worker_uid or os.geteuid() != worker_uid:
        raise PermissionError("unexpected advice worker UID")
    return accounts


def _run_managed_advice(
    base: Path, items: list[Item], scope: Scope, sources: tuple[str, ...], deadline: float
) -> Outcome:
    from .core.inference_deployment import read_candidate_policy

    denied = Outcome(False, error_class="policy_denied")
    if not _allowed(read_kill_switch):
        return denied
    policy = read_candidate_policy()
    if policy is None or policy.advice is not True:
        return denied
    ai = policy.ai
    budget = ai.budget
    # The verified candidate policy validates advice budget limits before publication and read.
    if ai.model is None or budget is None:
        return denied

    def guard() -> str | None:
        current = read_candidate_policy()
        if current != policy or not _allowed(read_kill_switch):
            return "policy_denied"
        return None

    ollama = OllamaProvider(
        ai.model, base_url=OLLAMA_URL, timeout_s=WORKER_TIMEOUT_S, require_exact_model=True
    )
    provider = _GuardedProvider(ollama, guard, lambda: deadline - time.monotonic())
    ledger = Ledger(base / "ledger.db", budget)
    audit = AuditLog(base / "audit.jsonl")

    def emit(event: dict) -> None:
        audit.append(
            event["event"],
            generation=policy.generation,
            **{key: value for key, value in event.items() if key != "event"},
        )

    try:
        inference = InferenceService(
            provider,
            ledger,
            Policy.from_config(ai),
            max_attempts=1,
            audit=emit,
            input_token_reservation=ollama.num_ctx,
        )
        if guard() is not None:
            return denied
        outcome = inference.run(
            ADVICE_TASK, items, scope, expected_sources=sources, deadline=deadline
        )
    finally:
        ledger.close()
    return outcome if guard() is None else denied


def _advice_invocation() -> bytes:
    invocation = os.environ.get("INVOCATION_ID", "")
    if not re.fullmatch(r"[a-f0-9]{32}", invocation):
        raise ValueError("invalid systemd advice invocation")
    return invocation.encode("ascii")


def _publish_advice_ready(base: Path) -> None:
    invocation = _advice_invocation()
    fd, path = tempfile.mkstemp(dir=base)
    with os.fdopen(fd, "wb") as handle:
        try:
            handle.write(invocation)
            handle.flush()
            os.replace(path, base / "listener-ready")
        finally:
            Path(path).unlink(missing_ok=True)


def _wait_for_advice_ready(base: Path, *, timeout: float = 5.0) -> None:
    invocation = _advice_invocation()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            fd = os.open(base / "listener-ready", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            pass
        else:
            with os.fdopen(fd, "rb") as handle:
                info = os.fstat(handle.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                ):
                    raise PermissionError("unsafe advice readiness file")
                if handle.read(len(invocation) + 1) == invocation:
                    return
        time.sleep(0.05)
    raise TimeoutError("managed advice listeners did not become ready")


def _serve_managed_advice() -> None:
    if os.environ.pop("LISTEN_PID", None) != str(os.getpid()):
        raise ValueError("invalid systemd listener PID")
    if os.environ.pop("LISTEN_FDS", None) != "2":
        raise ValueError("expected two advice listeners")
    names = os.environ.pop("LISTEN_FDNAMES", "").split(":")
    if sorted(names) != sorted(MANAGED_ROLES):
        raise ValueError("unexpected systemd advice listener names")
    accounts = _managed_advice_accounts()
    if not _trusted_directory(MANAGED_DIRECTORY):
        raise PermissionError("untrusted advice socket directory")
    directory = MANAGED_DIRECTORY.lstat()
    if (directory.st_uid, directory.st_gid, stat.S_IMODE(directory.st_mode)) != (0, 0, 0o755):
        raise PermissionError("invalid advice socket directory ownership or permissions")
    _private_state_dir(STATE_DIR)
    base = STATE_DIR / "advice"
    _private_state_dir(base)

    with ExitStack() as stack:
        selector = stack.enter_context(selectors.DefaultSelector())
        for role in MANAGED_ROLES:
            fd = 3 + names.index(role)
            account = accounts[role]
            listener = stack.enter_context(socket.socket(fileno=fd))
            listener.set_inheritable(False)
            path = managed_socket_path(role)
            info = path.lstat()
            if (
                account.pw_gid == 0
                or not stat.S_ISSOCK(info.st_mode)
                or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                != (0, account.pw_gid, 0o660)
                or listener.getsockname() != str(path)
            ):
                raise PermissionError("invalid advice listener path or permissions")
            listener.setblocking(False)
            server = stack.enter_context(
                ManagedAdviceServer(listener, account.pw_uid, partial(_run_managed_advice, base))
            )
            selector.register(server, selectors.EVENT_READ)
        _publish_advice_ready(base)
        while True:
            for key, _events in selector.select():
                key.fileobj.handle_request()


class _CandidateInventory(OllamaProvider):
    def list_models(self, timeout_s: float = 10) -> list[str]:
        return [model for model in super().list_models(timeout_s) if model == self.model]

    def complete(self, system, user, *, schema, max_output_tokens, timeout_s):
        raise InferenceError("unsupported", spend="none")


def _local_candidate_tick() -> dict:
    policy = _read_policy(_read_candidate)
    if policy is None or policy.generation is None:
        return {"status": "unavailable", "reason": "applied_policy_unavailable"}

    def builder(ai: Ai) -> InferenceProvider:
        if ai != policy.ai or ai.model is None:
            raise InferenceError("policy_denied", spend="none")
        return _CandidateInventory(ai.model, base_url=OLLAMA_URL)

    return run_once(
        read_policy=_read_candidate,
        state_dir=STATE_DIR,
        kill_switch=read_kill_switch,
        provider_builder=builder,
        candidate_policy=policy,
    )


def main() -> None:
    args = sys.argv[1:]
    if args == ["_managed-admin"]:
        os.umask(0o077)
        _serve_managed_admin()
        return
    if args == ["_managed-advice"]:
        os.umask(0o077)
        _serve_managed_advice()
        return
    if args == ["_wait-for-advice-ready"]:
        _wait_for_advice_ready(STATE_DIR / "advice")
        return
    if args == ["_local-candidate-tick"]:
        os.umask(0o077)
        _managed_admin_uid()
        print(json.dumps(_local_candidate_tick(), sort_keys=True))
        return
    if "ai.provider" in UNAVAILABLE_FEATURES:
        result = {"status": "unavailable", "reason": "ai_provider_unavailable"}
    else:
        result = run_once(
            read_policy=read_projection, state_dir=STATE_DIR, kill_switch=read_kill_switch
        )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
