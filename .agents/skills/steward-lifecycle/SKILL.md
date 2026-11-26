---
name: steward-lifecycle
description: Change Steward self-healing, application group operations, maintenance windows, verified updates and rollback, critical-risk containment, archival, reactivation or drills.
---

# Workload lifecycle

1. Pick the state machine for the change. Use `controller.py` and `core/health.py` for self-healing, `core/maintenance*.py` for scheduled admission, and `core/application_ops.py` with `core/group_checkpoint.py` for dependency-ordered group operations. Start from the installed availability and application isolation checks.
2. For updates, follow `core/update_evidence.py` → `executor/image_update.py` → recovery. Distinguish validation, admission, running digest, health and data readback. Match rollback to the exact approval, migration kind and journaled capture.
3. For critical exposure or removal, trace `core/risk_cycle.py` → `executor/containment.py`, or `executor/retirement.py` → the verified archive. Keep containment retryable after disconnection, and prove ownership and archive verification before releasing a working area.

Stress the specific transition with a fake clock, missing evidence, conflicting bindings and retry after interruption. Start with `tests/test_controller.py`, `tests/test_maintenance_admit.py`, `tests/test_group_actions.py`, `tests/test_update_recovery.py`, `tests/test_containment.py` or `tests/test_application_retirement.py`. [G06–G08](../../../docs/guardrails.md#g06-deterministic-admission).
