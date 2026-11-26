# Roadmap overview

[STATUS](STATUS.md#card-state) tracks implementation and host evidence.
The [delivery goal](goal.md#milestones) defines the order and exit criteria for
RC1. The [implementation work queue](implementation-plan.md) defines how to
pick up a card and record its checks.

## Workstreams through RC1

| Workstream | Scope and cards |
|---|---|
| Single-host baseline | Configuration revisions, guarded deployment, isolated workloads, admin UI and deterministic self-healing. See [architecture](architecture.md) and the [verified baseline](STATUS.md#verified-baseline). |
| Host and provider acceptance | CLI recovery, signed queries, notification receivers and scanner evidence. [V01–V03](plans/acceptance.md) |
| Backups and recovery | Scheduled capture, sealed export, Restic upload and restore evidence, retention and acceptance. [B01–B08](plans/backups.md) |
| Application lifecycle | Application graphs, group operations, maintenance, verified updates, quarantine, archive and reactivation, config apply and drills. [L01–L11](plans/lifecycle.md) |
| Optional inference | Provider and budget contracts, guided setup, model selection and scoped advice. [A01–A06](plans/ai.md) · [Onboarding and model selection](adr/0008-ai-onboarding-and-model-selection.md) |
| Repository delivery and repair | Exact source fetch, workload contracts, isolated builds, independent validation and repair pull requests. [R01–R05](plans/repositories-release.md#r01--fetch-an-exact-repository-revision-with-scoped-credentials) |
| Release and support | Signed packaging, additional OS and architecture profiles, public admin access. [S01–S03](plans/repositories-release.md#s01--verifiable-signed-release-for-an-accepted-feature-subset) |

## After RC1

The [post-RC1 roadmap](post-rc1.md) orders milestones M9–M15 for native Proxmox
management, fleet operations, backup and recovery, topology views, Proxmox HA
and Steward HA. The [infrastructure design](plans/infrastructure-design/README.md)
contains the reference profile and follow-up studies.
