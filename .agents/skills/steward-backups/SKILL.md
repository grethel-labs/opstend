---
name: steward-backups
description: Change Steward local captures, backup scheduling, immutable export, Restic uploads and receipts, restore drills, backup credentials, retention or import cleanup.
---

# Backups and recovery

1. Trace executor capture/pause/recovery → sealed export in `core/backupexport.py` → `backupworker.py` and the Restic adapter → `restore_drill.py`. Keep capture, upload, check and restore evidence distinct. Bind receipts and retries to the exact capture, revision, endpoint and snapshot.
2. For retention, read `core/backupretention.py`, `core/backupretire.py` and ADR 0003. Trace executor protection, acknowledgment, age and the import lock before any deletion. Exercise lost response, lease expiration, invalid metadata and resumed cleanup.
3. When touching credentials, trace the role's delivery and `core/backup_credentials.py`. Verify owner/mode, endpoint pinning and that failed jobs keep secret values out of their evidence.

Start with `tests/test_backup_executor.py`, `tests/test_backupworker.py`, `tests/test_backup_policy.py` and the retention and restore tests. Use [STATUS](../../../docs/STATUS.md) for the B08 gate and [Backup foundation](../../../docs/backup-foundation.md) for the data path. [G03](../../../docs/guardrails.md#g03-secret-transport), [G09](../../../docs/guardrails.md#g09-backup-proof-and-retention).
