---
name: steward-admin-ui
description: Change the Steward React admin interface, FastAPI routes, session security, pending config editor and apply flow, or authenticated advice and AI settings screens.
---

# Admin API and UI

1. Start at `api/app.py` or `api/ai_admin.py` and trace the call through `webapp/src/api.ts` to its page. Preserve session, origin, host and CSRF handling for mutations. Keep evidence gaps and capability availability visible.
2. For configuration, trace `webapp/src/pages/Config.tsx`, `core/store.py` and `core/config_apply.py`. Preserve the draft across polling and conflicts. Bind saves and Apply to the reviewed head and installed release and show the durable job outcome.
3. Build the production bundle and exercise the real API fixture used by Playwright. Use two-tab or reload scenarios for pending edits and authorization or unavailability cases for actions. Inspect the production CSP check when changing bundling.

Start with `tests/test_api.py`, `tests/test_config_apply.py`, `tests/test_ai_admin_api.py` and the affected `webapp/e2e/` spec. [G04](../../../docs/guardrails.md#g04-config-revisions), [G17](../../../docs/guardrails.md#g17-admin-session).
