# Testing

Use the test level that exercises the effect you want to verify. Local
fixtures cover contracts. Real systemd, network policy, separate UIDs,
reboots and provider delivery need the relevant host or provider environment.
[STATUS](STATUS.md) records the evidence already collected.

## Level 1 — unit and contract tests

Run the full suite with `uv run pytest -n auto` on a workstation or isolated
CI runner. Run only the [guardrail checks](guardrails.md) locally with
`uv run python tests/run_guardrails.py`.

The CI Python job runs the guardrails first and then uses `--exclude-guardrails`
for the remaining tests. The ordinary pytest command includes all cases.
Tests use synthetic fixtures and need no external network or root access.

| File | Evidence |
|---|---|
| `test_config.py` | Schema, rejection of unsafe values and unimplemented features, revision IDs, diff |
| `test_secrets.py` | Secret references, file permissions, token generation, redaction |
| `test_store.py` | Revision conflicts, idempotency keys, target lock, lease, backoff, recovery, audit chain |
| `test_render.py` | nftables/Traefik/Quadlet output; ruleset actually loaded in a private network namespace; Quadlet generator processes units |
| `test_executor.py` | Peer identity over real Unix socket, roles, schema, policy, kill switch, replay, expiry, budget, target lock, audit |
| `test_controller.py` | Rules, self-healing, cooldown, escalation, kill switch, observation gap |
| `test_api.py` | Startup only with strong secret, cookie attributes, CSRF, origin, host, rate limit, revocation, rotation, conflicts, jobs |
| `test_scannerd.py` | Durable schedule/restart, lease expiry, changed-inventory discard, real daemon/socket, reader roles, collector cursor replay, snapshot fences, job retention |
| `test_scan_observations.py` | Atomic validated snapshots, history, retention, Unicode byte bounds and freshness |
| `test_scanners.py` | OSV/Trivy contracts, persistent quota delay, bounded process execution and CLI publication |
| `test_intelligence.py` | Exact CVE binding, complete KEV catalog, EPSS page/score validation, stale/failed history, cache/cooldown, limits, prioritization and alert deduplication |
| `test_release.py` | Subset and pin parsing, SBOM/provenance content, deterministic build, signature by key reference, rejection of unsigned, wrong-key, tampered, missing, extra, symlink, mismatched-manifest and hostile-archive releases (local logic only; no archive installation) |

Not proven: behavior against real systemd, actual user separation, firewall rule
effectiveness in the data path. Executor host access (`executor/host.py`) is
replaced by a fake here.

## Browser acceptance (`cd webapp && npm run test:e2e`)

Install dependencies with `uv sync --frozen` and `cd webapp && npm ci`, then
`npx playwright install chromium` (on a new CI host, use `--with-deps`).
Playwright starts a disposable API on `http://localhost:19080`, serving the real
production bundle with production CSP/session settings. It refuses to reuse an
existing server. Test state lives in a temporary directory and is discarded.
No executor, production data or external service is accessed.

The scanner browser fixture uses a real private scanner query socket and the
production API with synthetic provider evidence. Tests traverse bounded findings,
render hostile advisory text safely and keep scanner form edits in the YAML draft.
This proves the browser/API/socket path, not real provider or systemd behavior.

Checks cover invalid/valid login, HttpOnly/Secure/Strict cookies, reload/logout,
project navigation, disabled actions without live status, YAML validation, diff,
pending revision persistence, concurrent-tab conflict rejection, and form/YAML
synchronization with comment preservation and diff invalidation. API calls
are real; no browser network interception is used. Only Chromium is covered.
This proves browser/API integration, not deployment, TLS proxy or host actions.
The configuration follows Playwright's official [web server support](https://playwright.dev/docs/test-webserver).

## Level 2 — local rootless test (`tests/integration/local_rootless.sh`)

Requires Podman and network, no root. Starts the **generated** example
configuration units as the current user: image flow (digest → tag → archive →
load), example application with all hardening flags, Traefik with generated
routes, admin API.

Proves: isolation as reported by `podman inspect` at runtime; read-only rootfs;
state survives restart; workload cannot reach host loopback; login through the
proxy; security headers.

Not proven: nftables, separate service users, systemd units, boot behavior.

## Level 3 — fresh VM (`tests/integration/vm/`)

The actual acceptance test: Ubuntu 26.04 cloud image, `./steward deploy`, second
run with `changed=0`, reboot, then checks from outside and inside.
Instructions and scripts: [tests/integration/vm/README.md](../tests/integration/vm/README.md).

## Acceptance gates

Use the [work queue](implementation-plan.md) for card-specific acceptance
criteria and the [Proxmox fixture guide](../tests/integration/proxmox/README.md)
to set up an authorized VM. The [card table](STATUS.md#card-state) records open
gates and the scope of prior runs. The [support matrix](support-matrix.md)
tracks tested platform combinations.
