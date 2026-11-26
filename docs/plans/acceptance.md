# V01–V03: close existing acceptance gaps

Read the [work queue](../implementation-plan.md) first. These tasks verify
already implemented features; they do not authorize another deployment or an
external message by themselves. Use an explicitly assigned disposable fixture.
If access is missing, prepare local harness checks and record the unrun gate.
Source paths without a leading directory below are relative to `src/steward/`.

Evidence in [STATUS](../STATUS.md) is scoped: core KVM acceptance, signed bot
queries, backup capture/crash/export and a warm-cache Trivy service have passed.
Do not rerun them as if no evidence existed. Later code needs acceptance for the
behavior it changes. Read the latest milestone before deciding what remains.

## V01 — CLI planning and configuration recovery on a real host

**Needs:** an owned managed test VM; current core acceptance evidence.
**Entry points:** `src/steward/cli/main.py`, `ansible/playbooks/config-pull.yml`,
`tests/test_cli.py`, [VM harness](../../tests/integration/proxmox/README.md).

1. Run `plan` with the fixture's existing configuration; capture its exit status,
   diff and absence of host mutations. Exercise a pending UI revision and prove
   the normal stale-local-config conflict is preserved.
2. From a fresh checkout without a local configuration, run `config pull` using
   its documented host/user/server/output parameters. Check file mode, canonical
   revision and secret references without printing secret values.
3. Verify wrong server identity, modified exported revision and an existing
   output conflict fail safely. Add missing harness assertions rather than
   changing host state by hand to manufacture success.
4. Record the tested commit and exact commands. Only broaden core fresh-install/
   reboot acceptance if intervening changes or the selected acceptance scope
   require it; keep historical evidence and new evidence separate.

**Check/done:** relevant CLI unit tests and actual SSH outcomes recorded in
`STATUS.md`; no lost pending revision or overwritten operator credentials.

## V02 — notifier, private queries and independent receiver acceptance

**Needs:** an owned VM plus authorized test-only Discord/webhook destinations
and an independent receiver. A loopback refusal fixture cannot prove delivery.
**Entry points:** `src/steward/notifier.py`, `bot.py`, `core/outbox.py`,
`tests/integration/vm/messaging.py`, notifier/bot platform units;
[operations](../operations.md) messaging sections.

1. Check actual notifier/bot UIDs, credential permissions, socket access and
   network separation. Send a synthetic redacted event through the real
   collector/outbox and obtain transport acknowledgments for both adapters.
2. Exercise process restart, retry/rate-limit cooldown, duplicate delivery,
   invalid webhook targets and destination outage. Persisted pending messages
   must remain pending; provider outage must not block a security operation.
3. Exercise signed queries through deployed TLS, project grants, replay after
   restart, wrong signature/timestamp and unauthorized identity/project. Reuse
   existing signed-bot evidence where the tested path has not changed.
4. On the independent receiver verify heartbeat freshness, missing-heartbeat
   detection, executor audit anchors and discontinuity reporting after interruption.
   API-audit export is separate future work, not part of this implemented path.

**Check/done:** local notifier/outbox/bot tests plus actual per-adapter and
receiver evidence in `STATUS.md`. If one provider is unavailable, keep its gate
open rather than treating the other provider as proof of both.

## V03 — complete scanner evidence beyond the bounded warm-cache fixture

**Needs:** an owned VM, authorized provider network access and resource budget.
**Entry points:** `src/steward/scannerd.py`, `core/inventory.py`,
`core/scan_observations.py`, `adapters/scanners.py`, `adapters/intelligence.py`,
scanner platform unit; `tests/test_scannerd.py`, `tests/test_scanners.py`,
`tests/test_intelligence.py`.

1. Start from the accepted real warm-cache Trivy gate. Add a bounded OSV-enabled
   host/package scan and cold-database download/resource measurement as separate
   gates; record exact inventory coverage and provider limits.
2. Through the real systemd/collector/API/UI path test provider outage, persistent
   cooldown, daemon restart, inventory/image change during scan and stale data.
   Partial evidence must not become a complete host-scan success.
3. With enrichment opted in, verify dated KEV/EPSS context and source failure
   states remain distinct from affected-version/runtime evidence. Do not use
   a live critical service as a containment test.

**Check/done:** local scanner cases plus actual service/provider/resource
receipts; each source's complete/partial/failed coverage is explicit. This task
does not enable quarantine or remediation; L04–L08 require their own authority.
