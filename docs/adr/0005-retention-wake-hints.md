# ADR 0005: bounded retention wake hints

Status: accepted for implementation · 2026-11-16

ADR 0003 requires retention to be considered after an upload. The backup worker
cannot grant root deletion authority or supply a restore proof, and periodic root
sweeps alone delay consideration after upload. A one-way, bounded wake hint
addresses timing without transferring ownership or trust.

The backup peer may request `backup_retention_hint` with only project, artifact
and capture IDs. The executor applies normal peer authorization, freshness and
kill-switch checks; it validates that an enabled, registered project has the
matching root-owned upload registration and no cancellation. A stale or
cancelled hint is acknowledged as a no-op. A valid hint can only wake the
existing root sweep: it cannot create an acknowledgement, clear a pending job,
assert upload/restore success, choose a deletion target or change retention
policy. Root checks its own acknowledgement and all protection rules again.

Wakeups are coalesced at the executor and full-data retention attempts remain
limited to one per host per five minutes even under repeated hints while the
executor remains running; a process restart resets this in-memory timer. The periodic
sweep remains the fallback for a lost or coalesced hint. The managed worker
commits a bounded private wake outbox atomically with its upload receipt, retries
unacknowledged hints after restart and coalesces old hints if the outbox reaches
1280 entries. These entries are interchangeable scheduling hints, not evidence.
A later integrity or restore failure remains a separate result; a wake hint
never asserts those phases succeeded. Standalone worker mode does not send hints.

The backup peer may also call the narrow read-only
`backup_worker_capacity_report` operation with no parameters. It is an
explicitly attributed, rate-limited report about the global worker ledger, not a
root-verified capacity measurement or retention authority. It remains observable
with the kill switch on, never wakes the retention sweep, and cannot acknowledge,
prune, recover or otherwise mutate backup data. This report also covers legacy
imports without a root capture registration.
