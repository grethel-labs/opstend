# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
There is no published release yet.

## [Unreleased] – 0.1.0rc1

### Added

- `release build` records the accepted subset, CycloneDX SBOM and in-toto
  provenance. The operator uses `release sign` offline to add an Ed25519
  signature to a prepared archive from `release pack`. `release verify` checks
  the signature, hashes and attestations against a separately trusted public key.
  See [the release process](docs/release.md).

- Optional CISA KEV and FIRST EPSS context on exact CVE aliases, with private
  caches, persistent rate-limit cooldowns, dated source states, prioritization
  and UI/CLI/configuration controls. Scanner severity and version evidence stay
  separate from exploitation context.

- Opt-in scheduled scanner service with a dedicated unprivileged identity,
  durable leased jobs, revalidated inventory, persistent OSV cooldowns and pinned
  SHA256-verified Trivy installation. Read-only collector/API/UI integration,
  vulnerability notifications and configuration form controls.

- Private scanner observation snapshots and a retained atomic change feed,
  populated by standalone scans, with freshness-aware bounded query pages.

- Configuration schema v1 with content-addressed revisions and diffs.
- `steward` CLI: `validate`, `plan`, `deploy`, `status`, `doctor`, `killswitch`,
  `config pull`, `secrets init-admin-token`, `release build`.
- Ansible roles: preflight, base hardening (SSH with rollback timer, sysctls,
  journald, security updates), identities, nftables firewall with per-service
  egress rules, platform, Traefik proxy, workloads, verification.
- Privileged host executor with registered actions and an audit chain.
- Deterministic self-management controller.
- Admin API with sessions, CSRF/origin checks, and web UI.
- `sample-notes` example application.
- Event log: collector service (`steward-col`) with its own SQLite store and
  query socket; events from executor audit, journald (redacted by the
  executor), controller findings and deployments; correlation ids linking a
  finding with its actions and resolution; fixed delivery classes; retention
  settings `events.retention_days` / `events.max_events`; `/api/events`,
  Events page, `steward-host events`.

- Notification worker with its own identity and systemd credentials: Discord
  incoming webhooks and HMAC-signed HTTPS webhooks, DNS-pinned TLS/SSRF guards,
  durable outbox, atomic feed cursors/digests, retry limits and rate-limit delays.

- Configuration recovery from a fresh checkout: `config pull --host --user
  --limit --out`, with remote identity/revision validation and private atomic
  output, without a pre-existing configuration or local secret values.

- Notification observation-gap alerts on collector retention loss or database
  replacement, with persistent stream identity and safe cursor recovery.

- Chromium browser acceptance tests against the built UI and disposable real
  API: login/session/logout, navigation, configuration validation and conflicts;
  integrated into CI.

- Read-only information bot: signed webhook and Discord interaction inputs,
  explicit identity/project grants, deterministic status/update/backup/help
  responses, replay/rate-limit protection, dedicated service identity and
  optional public bot-only route.

- Optional external heartbeat messages with collector freshness, observation
  timestamps, stale-message coalescing and priority over daily digests.

- Opt-in signed executor audit export: root-side redaction, bounded views with
  original hash anchors, and durable per-destination feed/outbox delivery.

- Configuration form fields for common administration, event, resource, health
  and restart settings, synchronized with YAML while preserving comments and
  revision conflict checks; covered by a third real browser test.

- Read-only package/source/kernel and registered image inventory with bounded
  revision-bound pages, a restricted scanner role and `steward-host inventory`.

- ScannerAdapter v1 with exact-version OSV and digest-bound Trivy observations,
  explicit coverage/failure states and unprivileged `steward-scan`; persistent
  historical evidence, private reports and bounded network/process execution.

### Changed

- From RC1, deploy and exact resume verify a signed archive against a separately
  trusted public key before remote preflight. Run the command from a trusted
  controller checkout for the same version. Local development deployment
  requires the explicit `--allow-unsigned-development-release` exception.
- Executor audit: successful read-only requests are summarised hourly instead
  of one record each; mutations and refusals are still recorded individually.
- `maintenance.allow_restart` now defaults to `true`.

### Fixed

- Runtime image verification handles OCI archive manifest changes using an exact
  root-cache pinned-reference/content-ID/running-container chain. Trivy must
  report that same content ID; a shared manifest-index reference alone is insufficient.

- Collector socket startup no longer dies under seccomp: narrowly allow the
  ownership calls needed to assign its own socket to the observation group.
  Kernel UID/group checks and the empty capability set still restrict ownership.

- Interrupted first installations can resume from an atomic root-owned layout
  claim made before host mutations. Foreign or untrusted layouts remain blocked;
  completion is recorded only after all deployment verification succeeds.

- Malformed request IDs cannot poison audit collection; legacy oversized records
  remain traversable with exact byte/hash cursors. Audit and event socket pages
  respect a byte budget, including Unicode, and event views disclose truncation.

- Expired job owners cannot revive a lease or report success before reconciliation;
  lease boundaries are consistent and invalid durations are rejected.

- Concurrent CLI commands no longer overwrite an active deployment's generated
  inventory/variables. Learned SSH-port rendering uses the same invocation
  directory; local deploys to one SSH endpoint are serialized through completion.

### Known gaps

- The signed RC1 archive and its install, upgrade, unchanged redeploy and reboot
  evidence are pending. Earlier VM evidence covers the single-host baseline,
  guarded configuration recovery, bounded OSV/Trivy scanning and the tested
  maintenance window and project health probe paths. The healthy container
  probe host gate and released public HTTPS and real Discord delivery gates
  remain open.
- Public configuration guards keep Restic backup activation, application stacks
  and critical-risk response, verified updates and rollback, maintenance drills,
  AI and advice workflows, repository deployment and builds, and automatic
  patch/repair unavailable. See [card state](docs/STATUS.md#card-state).
- Additional OS and architecture profiles (S02), including Ubuntu 26.04 arm64,
  and public administration with OIDC/MFA (S03) are unsupported.
