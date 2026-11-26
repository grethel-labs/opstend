---
name: steward-executor
description: Implement or review a privileged Steward action, executor Unix socket contract, root-owned registry lookup, mutation guard, target lock, replay fence or audit record.
---

# Executor actions

1. Start at `executor/server.py` in `Executor.handle` and `ACTIONS`. Trace the caller through `executor/protocol.py` and the role/UID in the rendered registry. Register a typed action with explicit roles and mutability. Resolve targets from registered IDs and use the existing Host boundary for fixed argv.
2. Locate the policy, target lock and budget appropriate to the operation. Re-check mutable facts at the lock boundary. Use existing durable intents when an action has several effects. Record enough identity to distinguish exact retry, stale work and newer state.
3. Test an allowed caller and the relevant rejected caller, input, replay, expiry, kill-switch and contention paths. Assert refused requests leave host state unchanged. Use the audit tests to verify observable refusals.

Start with `tests/test_executor.py` and the action's contract tests. See [Extending Steward](../../../docs/extending.md) and [G01–G03](../../../docs/guardrails.md#g01-executor-boundary).
