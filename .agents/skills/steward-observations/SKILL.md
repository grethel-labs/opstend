---
name: steward-observations
description: Change Steward scanner findings, inventory or threat intelligence, scanner or collector query IPC, event projection, notifier delivery or signed read-only bot queries.
---

# Observations and messaging

1. Follow inventory/image evidence into `scannerd.py`, the scanner adapters and `core/scan_observations.py`. Keep identity, freshness, coverage and cursor continuity attached to results. Check a partial, missing or failed source alongside a clean result.
2. Follow `collector.py` into `core/events.py`, `core/outbox.py` and `notifier.py`. Use the existing event identities and durable cursors. Test repeats, stale snapshots, and failed acknowledgment. Preserve signing of the exact body and the verified destination when touching transport.
3. For bot changes, trace the signed request and scope grant in `bot.py` and `adapters/queries.py` before gathering any evidence. Use bounded, redacted read models across private state boundaries.

Start with `tests/test_scannerd.py`, `tests/test_scan_observations.py`, `tests/test_collector.py`, `tests/test_notifier.py` or `tests/test_bot.py`. Distinguish scanner evidence from critical-risk decisions and synthetic transport tests from external delivery. [G10](../../../docs/guardrails.md#g10-qualified-evidence), [G11](../../../docs/guardrails.md#g11-messaging-boundaries).
