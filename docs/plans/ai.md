# A01–A06: optional AI inference

Read the [work queue](../implementation-plan.md) first and
[ADR 0002 §2](../adr/0002-repositories-ai-and-application-lifecycle.md).
These are future capabilities. Provider methods, model names and subscription
terms in the target design are not proof of current provider support. Recheck
official documentation when implementing each integration and record dated
sources. The deterministic platform must work without AI or provider login.
Source paths below are relative to `src/steward/` unless stated otherwise.

## A01 — inference contract, redacted snapshots and reserved budgets

**Needs:** L06; existing query grants and job store. **Files:** `core/config.py`,
`core/store.py`, `core/secrets.py`, `bot.py`; **new** snapshot/budget implementation
and tests, with the inference contract specified in a focused ADR addition.

1. Define `InferenceProvider` version, capabilities, bounded structured input/
   output, health, timeout and stable authentication/quota/provider errors.
   Implement the first real transport with A02, rather than enabling an empty
   interface. Add the provider protocol and shared contract tests with A02's
   implementation; keep production AI availability blocked during contract work.
2. Build snapshots from already-authorized project/time scopes. Include source,
   evidence times and coverage; redact secrets and bound size before any call.
   Do not allow provider-supplied tool names, SQL or shell commands.
3. Reserve global/per-project token, cost, duration and concurrency budgets
   transactionally before calls. Reconcile actual usage, ambiguous timeout costs
   and expired workers without releasing spend twice or inventing unknown prices.
4. Enforce `local_only` and explicit provider/data-class policy on all retries/
   fallbacks. Provider failure must not stop fixed scans or controller rules.

**Check/done:** budget race/restart/quota and cross-project redaction tests plus
a concrete contract specification for A02. No AI output can create executor
authority. Actual provider acceptance belongs to A02–A03.

## A02 — install and accept local Ollama

**Needs:** A01. **Files:** **new** `adapters/inference.py` and shared contract tests;
`core/config.py`, `core/render.py`,
`core/tools.py`; **new** inference/Ollama platform unit/install tasks and tests;
`examples/server.local-ai.yml`.

1. Verify/pin the runtime and implement the provider contract. Require an
   explicitly configured model and checked download/license/resource limits.
   Install it under a separate service identity, private state and loopback or
   local IPC access; no publicly reachable port 11434.
2. Reject insufficient RAM/disk, unconfigured model, uncontrolled downloads and
   unsupported device access. GPU support needs its own device-isolation checks;
   do not enable it merely because a device exists.
3. Run shared success/malformed-output/timeout/context-limit tests, then a real
   bounded local inference on an owned VM. Prove network denial and no cloud
   fallback when the local runtime or model is unavailable.

**Check/done:** config/render/Ansible/provider checks plus measured VM resources,
installed model identity and actual inference evidence. Enable only the accepted
local method/profile; other methods remain explicitly unavailable.

## A03 — external API methods and explicit data sharing

**Needs:** A01 and shared contract cases from A02. **Files:** inference adapters,
configuration/rendering, service credential/network setup; **new** provider tests.

Implement one method per subtask, reusing the same contract suite:

1. OpenAI API and Anthropic API: official endpoints/auth, bounded HTTP transport,
   secret references, response validation, usage and quota handling.
2. `openai-compatible`: explicit base URL/data class, endpoint validation and
   TLS/SSRF/redirect/proxy policy. A custom endpoint is not proof of identical
   API semantics; test capabilities rather than assuming compatibility.
3. `ollama-cloud`: verify the official supported server/auth path before adding
   the external method. Keep it distinct from `ollama-local`; the ADR's desired
   default does not authorize silent external calls or purchases.

**Check/done per method:** contract/credential/429/5xx/timeout/budget tests and
an authorized real request with measured usage; no secret in logs/receipts.
Reject unsupported methods clearly. Never infer live acceptance of one API
from a mock or a successful request to a different provider.

## A04 — guided login and credential lifecycle

**Needs:** a provider from A03 that requires interactive login.
**Files:** `cli/main.py`, `hostcli.py`, inference auth/state, platform credential
setup, API/status/UI; **new** auth lifecycle tests.

1. For each subscription path, first record dated official evidence that this
   unattended server integration is supported. If it is unsupported or unclear,
   leave that method unavailable with a precise reason; API/local methods work.
2. Implement controller `opstend ai login` as SSH into the same root-owned host
   login entry point. Run the official unmodified auth program under the inference
   identity; protect its required native state. No session-token forwarding or
   unofficial OAuth proxy, and no credentials in working copies.
3. Show login pending/expired/revoked as findings without failing the core
   deployment. Test relogin, credential rotation, wrong UID and clean revocation.

**Check/done:** CLI/auth/permission tests and an authorized actual login/revoke
flow for each supported method. Document unsupported paths as open, not as a
reason to fake login or block deterministic server monitoring.

## A05 — weekly deterministic model selection

**Needs:** A02 or A03 accepted, A01 budgets and L03 window admission;
A04 for a login-dependent method. **Files:** inference provider model discovery,
`core/config.py`, `core/store.py`, event output; **new** selection suite/tests.

1. Validate a rule for allowed model families/tiers and budget; discover actual
   available models with provenance. Define deterministic family classification,
   price freshness, score ordering and tie behavior before implementing a switch.
2. Run a versioned fixed suite of synthetic toolkit tasks with budgets reserved
   for evaluation. Measure schema/task pass rate, runtime and cost; test all
   required cases. Unknown price or missing evidence prevents an automatic switch.
3. Persist decision, suite revision and fallback before activation. Stay within
   the same provider/data class; retain the old accepted model. Never switch
   provider, purchase a plan or expand data sharing automatically.

**Check/done:** fake-clock deterministic selection, disappearing model, price
change, quota, failed candidate and interrupted activation tests; bounded real
evaluation on an authorized method. Audit the measured reasons for each switch.

## A06 — advisory answers with source/time coverage

**Needs:** A01 and one accepted provider; A04 when its auth is required.
**Files:** `controller.py`, `bot.py`, `api/app.py`, UI findings/query views;
provider integration and bot/API/browser tests.

1. Add optional advice over A01 snapshots. Preserve deterministic `/status`,
   `/updates`, `/backups`, `/help`; free-form answers state sources, time range
   and missing data. Enforce identity/project grants before snapshot assembly.
2. Validate structured recommendations against fixed proposal schemas. The bot
   remains unable to execute, approve or schedule mutations; controller proposals
   still need the existing registered policy/approval path.
3. Test prompt injection in logs/repository excerpts, unauthorized project
   requests, invalid model output and exhausted budgets. Failure produces a
   visible advice gap and retains deterministic information access.

**Check/done:** real API/bot/provider path on synthetic data, hostile-text browser
rendering and evidence that inference/bot UIDs cannot access executor or secrets
outside their declared credential scope. No autonomous source repair until R05.
