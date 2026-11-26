# ADR 0007: Inference provider contract v1

Status: accepted for implementation (A01-A03) · Date: 2026-11-21 · Extends
[ADR 0002 section 2](0002-repositories-ai-and-application-lifecycle.md)

This ADR only specifies the contract that cards A01-A03 implement. It decides no
new product behavior: AI stays optional, off by default, and `ai.provider` stays
in `UNAVAILABLE_FEATURES` until the provider gates in the
[implementation work queue](../implementation-plan.md) pass.

## Process and data boundaries

Inference runs in its own process identity with its own SQLite file (budget
ledger). It receives snapshots, never database handles, sockets or secrets other
than its own provider credential. Nothing in `core/inference*.py` or
`adapters/inference.py` imports the executor protocol; an `Outcome` is data with
`untrusted = True` and cannot approve, schedule or execute anything. Proposals
derived from an `Outcome` enter the existing controller/registered-policy path.

## Call pipeline (`core/inference.py`)

1. `Policy.check(provider)`: an external provider is refused when `local_only`
   is set or when no data class is shared; applied at construction and on every
   run/retry/fallback. Fallbacks must keep the primary's data class
   (local to external is never automatic).
2. `build_snapshot(items, scope, ...)` (`core/inference_snapshot.py`): items must
   belong to the already authorized projects (or host scope), are filtered to the
   shared data classes for external providers, other projects' ids are masked,
   secrets redacted (`core/secrets.redact`), control characters removed and size
   bounded newest-first. The payload states window, scope, expected/missing
   sources, withheld classes, omitted counts and oldest/newest evidence times.
   Unauthorized items leave no trace in the payload.
3. `Ledger.reserve(...)` (`core/inference_budget.py`): tokens, cost, seconds and
   one concurrency slot are reserved in `global` and every `project:<id>` scope
   in a single immediate transaction (UTC calendar-month windows).
4. `provider.complete(system, user, schema=..., max_output_tokens=..., timeout_s=...)`.
   The system text is a fixed template plus the code-defined `Task` instruction
   and schema; the snapshot is the user message and is declared untrusted data.
   Providers and snapshots cannot select tools, tasks, schemas, SQL or commands.
5. Output validation: at most 64 KiB, JSON (one fenced block tolerated), then a
   closed schema (`core/inference_schema.py`: all properties required, no extra
   keys, bounded strings/arrays/numbers). Anything else is `invalid_output`.
6. Settlement, at most once per reservation (see below).

Provider failure never raises into callers: `InferenceService.run` returns an
`Outcome(ok=False, error_class=...)`; fixed scans and controller rules do not
depend on it.

## Provider interface

```
version: 1            name: str            data_class: "local" | "external"
model: str            capabilities: tuple  timeout_s: float   max_input_bytes: int
health() -> Health                     # local configuration only, no request
complete(system, user, *, schema, max_output_tokens, timeout_s) -> RawCompletion
```

`RawCompletion(text, usage, model)`; `Usage(input_tokens|None, output_tokens|None)`.
Adapters may offer `list_models()` (capability `models.list`, input for A05).
Errors are `InferenceError(error_class, retryable, retry_after_s, spend, usage)`
with message equal to the class. Classes: `auth`, `quota`, `rate_limited`,
`timeout`, `unavailable`, `invalid_output`, `context_limit`, `model_unavailable`,
`refused`, `unsupported`, `bad_request`, `policy_denied`, `budget_denied`,
`audit_failed`. Errors never contain endpoint URLs, response bodies or credentials.

`spend` tells settlement what happened: `none` (provider definitively did not
process: connect failure, 4xx/429 before work) releases the reservation; `known`
charges the reported usage; `unknown` (timeout, 5xx, lost connection, expired
worker) keeps the reserved amount charged. A later authoritative report may
refine an ambiguous charge once. Unknown prices are never estimated: a cost limit
without a configured price denies the reservation.

## Shared contract cases (every adapter)

Success with usage; malformed/extended/truncated output; timeout; context
limit; 401/403 -> `auth`; 429 -> `rate_limited` with bounded `retry_after_s`, or
`quota` when the provider says funds/plan are exhausted; 5xx/overloaded ->
`unavailable`; refusal; redirect not followed; response size bound; no secret in
any raised message; `health()` performs no I/O.

## Transport rules

- Ollama (`ollama`, A02): `http` to a loopback address only (`127.0.0.1`,
  `::1`, `localhost` resolving only to loopback); no redirects; never calls a
  pull/create endpoint. The configured model must already be installed;
  otherwise `model_unavailable`. Silent context truncation is detected by
  comparing the reported prompt token count with the configured context size.
- External APIs (`openai`, `anthropic`, A03): fixed official HTTPS host, port
  443, every resolved address must be public and the TLS socket connects to that
  checked address; no redirects, no environment proxies; bearer/API key resolved
  from the secret reference at construction and only placed in a request header.
- `openai-compatible`: configured base URL is either loopback (local data class,
  usable with `local_only`) or public HTTPS (external, needs `share`). Private
  LAN addresses are rejected in this release. Only the chat-completions path is
  used; compatibility is probed through `list_models()` and by validating each
  answer, never assumed.
- `ollama-cloud`, `claude-subscription`, `chatgpt-subscription` stay unavailable
  (A03 item 3 and A04 need dated official evidence first).

## Configuration

`ai.model` is required whenever `ai.provider` is set and is never defaulted;
`ai.api_key_ref` is a secret reference; `ai.share` lists explicit data classes
(`status`, `events`, `backups`, `vulnerabilities`, `logs`) and is required for an
external provider; `ai.budget` carries `monthly` and `per_project` limits
(`tokens`, `cost_micro`, `seconds`), `max_concurrent` and an operator-declared
`price`; an external provider requires `ai.budget.monthly.tokens`. Unset values do
not appear in canonical revisions. For `ollama`, `ai.local` declares the model's
download, RAM and disk needs, the license acknowledgment and `device: cpu` (GPU is
not expressible); `core/inference_local.plan_local_install` refuses an install on
insufficient RAM/disk, a missing model, limit or license acknowledgment, or a GPU
request, and plans a loopback-only listener under a dedicated `steward-ai` identity
with no implicit pulls. Concrete provider model IDs and tiers live
only in `core/inference_models.py`, which A05 replaces with discovery.
