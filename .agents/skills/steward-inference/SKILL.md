---
name: steward-inference
description: Change Steward optional AI providers, onboarding, isolated worker deployment, model selection, inference budgets, advice IPC or projection of sanitized evidence.
---

# Optional inference and advice

1. Start from `core/inference.py`, `core/inference_budget.py` and `adapters/inference.py`. Check scope filtering, redaction and budget reservation ahead of the provider call. Reconcile missing usage, timeout and stale prices through the existing ledger.
2. For model configuration follow ADR 0008, `inference_worker.py` and `core/inference_deployment.py`. Keep candidate staging separate from publication of verified installed state. Follow the managed worker identity and socket activation into the inference role.
3. For advice follow `core/advice.py` → `core/advice_ipc.py`. Check caller scope before collecting inputs and preserve source/time/missing-data reporting. For setup writes follow `api/ai_admin.py` → `core/ai_admin_ipc.py` → explicit worker actions.

Start with the corresponding inference budget, worker, deployment, advice and admin IPC tests. Keep feature availability tied to [STATUS](../../../docs/STATUS.md) and deterministic behavior working without a provider. [G12–G13](../../../docs/guardrails.md#g12-inference-admission).
