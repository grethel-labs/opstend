# ADR 0008: AI onboarding, provider choice and model selection (draft from operator requirements)

Status: proposed. Source: operator answer to open question 8 on 2026-11-23. It extends
ADR 0002 section 2 and ADR 0007 and replaces the "operator pre-places a model" default.

## Operator requirements (verbatim intent)

1. No model is shipped or preloaded. The operator signs in to an AI service of their
   choice: Ollama (cloud models first; a purely local model is a separate, explicit
   option, and only then is it downloaded), a normal API with API key, and if possible a
   Codex or Claude subscription.
2. At first setup the operator picks one initial model. Only models that belong to the
   chosen provider are scanned and offered. The initial model is set as the active one;
   for Ollama-local it is downloaded locally.
3. Optional automatic price/performance selection, plus a button "pick the best model
   now". When enabled, the provider's current models are scanned cyclically and compared
   on price/performance using legitimate online comparison sources (several). The AI may
   help keep those sources updated and validated and look for new ones. This needs a
   tightly scoped prompt with a fixed result format and an encapsulated AI environment
   with internet access.
4. The best-suited model is set as default; the operator sees it with its test report in
   the admin UI. The operator can instead pin one model permanently.
5. A new test report is made only on the initial check for a provider or when the model
   selection changes.
6. Intended defaults per provider: Codex: the current "Terra" tier; Claude: the current
   Sonnet; Ollama: DeepSeek V4.1 Flash.
7. Later: the model gets an encapsulated coding environment with tools, switchable
   access rights and internet access to carry out tasks on the server and make decisions
   itself.

## Constraints that keep this inside the toolkit's safety rules

- Comparison sources and their parsed numbers are untrusted data. The selection decision
  stays deterministic code (ADR 0002 section 2, A05): family rule, strict cost rule,
  evaluation suite. A model may *propose* new sources or corrections; a proposal changes
  nothing until the operator approves the source list entry in the admin UI (sources are
  an operator-owned allowlist of exact URLs with a parser per source and a recorded
  retrieval date). Missing or stale source data means "no switch", never a guess.
- The internet-enabled AI environment is its own builder-style tier (R03 isolation
  labels): no production secrets, sockets or executor access; egress only to the
  allowlisted source hosts; output is a fixed-schema document that is validated and is
  never executed.
- Pinning a model, or turning automation off, always wins over automatic selection.
- "Pick the best now" is an operator action admitted like any other planned work (budget
  reserved first; evaluation has its own ledger).
- The coding environment of item 7 is the R05 `CodingAgentRunner` tier with switchable
  capabilities; broader autonomy (decisions on the server) stays behind the existing
  executor authorization path and the repair/patch profile gates. This ADR does not
  authorize any unattended mutation.
- A purely local model is a separate provider option with its own explicit download step
  (declared checksum and size) and resource refusal.

## Open items for the cards

A02 (provider onboarding flows and local download), A04 (login per provider), A05
(initial check and change-triggered report only, price/performance sources, pin and
"best now" actions, admin UI view), R05 (coding environment capabilities). Defaults per
provider are data in the one model registry (`core/inference_models.py`), re-verified
against provider documentation at implementation time.

## Decision 8b (operator, 2026-11-23): source control modes

The admin UI offers four selectable modes for the comparison sources, and shows the
source list with retrieval dates at all times; the operator can add and remove entries
in every mode:

1. **Propose and confirm (default):** the AI proposes new/changed sources, nothing takes
   effect until the operator confirms.
2. **Allowlist:** the AI may add sources only from operator-given domains.
3. **Fixed sources:** the operator's list only; the AI only validates reachability and
   plausibility and reports.
4. **Fully automatic:** the AI validates, cross-checks against other sources and reads
   test reports before decisions, without per-change confirmation.

Guard rails that hold in every mode, including mode 4 (deterministic code, not the AI):
a source counts only after parsing with a fixed per-source parser and recording its
retrieval date; a model switch needs agreement of at least two independent sources and
the toolkit's own evaluation suite; stale/missing/contradicting data means no switch;
the budget ledger, provider choice, pinned model and the kill switch are never changed
by source updates; every source change and every switch is audited and shown to the
operator with the report; the AI environment has egress only to hosts of listed sources
(mode 4: plus search egress, in the isolated tier, with no production access).
