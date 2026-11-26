# Status

Candidate source version **0.1.0rc1** · Evidence summary as of 2026-11-26.

[Delivery goal](goal.md) tracks milestone exit criteria. [Release scope](../release/accepted-subset.yml) defines the supported feature subset. The card table records prior acceptance and the limits of that evidence. Site-specific records are kept by the operators who ran the gates.

## Verified baseline

Prior KVM runs on Ubuntu Server 26.04 LTS (amd64) exercised fresh installation, unchanged redeployment, workload isolation and reboot persistence. Guarded configuration recovery passed on a test host. Installed scanner checks covered bounded OSV and Trivy behavior, including coverage gaps and dated threat context. Maintenance-window admission and bounded HTTP/TCP probes passed, along with the container probe's unknown result. A routed private IPv4 test exercised automatic LAN binding, numeric-IP HTTPS, authenticated sessions and CSRF protection. The direct bridged client path remains untested.

This evidence supports the five entries in the release subset. The exact signed candidate still needs independent key verification, installation and upgrade, unchanged redeployment and reboot acceptance.

## Card state

| Card | State and evidence | Remaining gate or release limit |
| --- | --- | --- |
| Stage 1 core | Accepted on KVM for the verified baseline | See the [support matrix](support-matrix.md) for supported targets |
| B01–B07 | Local and guest evidence for capture, export, Restic upload and check, scheduling, recovery and cross-guest restore with separate reader credentials and application readback | Released Restic operation depends on B08 |
| B08 | Partial. Retention age gates and independent offline recovery passed. A prior private candidate exercised enabled redeploy, reboot, scheduling and interrupted-upload recovery | Integrated activation and scheduled application restore on the normal enabled release path remain open. `backup.enabled` stays guarded |
| V01 | Accepted on a test host for read-only planning, stale and pending conflict handling, guarded configuration pull and dedicated SSH trust | A trusted output location and appropriately scoped SSH credentials are required |
| V02 | Partial. Signed bot queries over TLS, outbox replay and simulated Discord delivery exercised | Released public HTTPS, authorized real Discord delivery, independent heartbeat and audit-anchor checks remain open |
| V03 | Accepted for the bounded host/package and registered-image scanner baseline | Coverage can remain incomplete after feed recovery. Application-scoped scanner handoff needs M4 acceptance |
| L01–L02 | L01 locally accepted. L02 accepted for separately isolated groups through the guarded private renderer | Public application-stack validation stays guarded. Shared mutation custody is deferred to X1 |
| L03 | Accepted for the window model, durable admission, lifecycle events, HTTP/TCP checks and the container unknown path | Healthy-container G8 deferred for RC1 after two fixture custody failures before deployment |
| Private LAN admin | Accepted for routed IPv4 access with managed source rules, numeric-IP HTTPS and loopback support | Direct bridged client coverage remains open. Public administration is unsupported |
| S01 | Partial. An unsigned candidate was built locally. Offline signing mechanics, pre-SSH verification and protected-ref workflow checks were exercised locally | Operator signature, independent trusted public key, exact-archive host acceptance and the hosted protected workflow run remain open |
| L04–L06 | Prior host gates exercised verified updates, recovery and patch behavior with candidate guards lifted for the tests. Additional update hardening has partial host evidence | `projects.update` and `automation.patch` stay guarded. Unknown-probe coverage and B08-dependent release acceptance remain open |
| L07–L08 | Partial. Containment and reactivation with supplied scan evidence exercised on a test host. Qualified scanner handoff covered locally | Wired scanner-to-host acceptance and backup activation remain open. `applications.on_critical` stays guarded |
| L09 | Partial. Manual retire and re-add exercised on a test host. Guarded automatic path exercised locally | Automatic-path host acceptance and B08 remain open |
| L10 | Partial. Installed browser-to-host Apply exercised | Mid-write interruption and B08-dependent update admission remain open |
| L11 | Partial. Drill contracts exercised locally and selected host paths exercised with candidate guards lifted | Off-site restore depends on B08. `maintenance.drills` stays guarded |
| A01–A03 | Partial. Inference contracts, guarded CPU-only Ollama packaging and a direct external API-key adapter exercised in their respective test scopes | Runtime integration and authorized live provider calls remain open. Public provider and local AI profiles stay guarded |
| A04–A07 | Partial. Guided login, model selection, advice and browser onboarding have local or selected installed fixture evidence | Eligible provider authentication, live inference/advice, external evaluation and the remaining deployment checks are open |
| R01–R02 | Partial. Separate-identity fetch and contract outcomes have fixture evidence. Packaged fetch exercised locally | Installed SSH, egress, custody, reboot and withdrawal remain open. Public repository configuration stays guarded |
| R03 | Partial. Local build isolation contracts and offline verification exercised | Installed build resource delegation, per-job write isolation and egress acceptance remain open. Public builds stay guarded |
| R04 | Partial. Digest promotion and inventory exercised in a loopback registry fixture | Installed validator, application-update mapping and approval authority remain open |
| R05 | Partial. Local repair and pull-request binding exercised | Qualified runner, installed validation, host branch custody and an authorized forge test remain open. `automation.repair` stays guarded |
| S02–S03 | Deferred for RC1 | Additional target profiles and public administration with OIDC/MFA remain unsupported |
