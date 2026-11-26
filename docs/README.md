# Steward documentation

Start with the [installation quick start](../README.md#quick-start), the
[support matrix](support-matrix.md) for tested platforms, and
[STATUS](STATUS.md#card-state) for the available feature set and open acceptance
gates. STATUS records the evidence for each card as it lands.

## Operate a host

| If you need to | Read |
|---|---|
| Upgrade, change configuration, recover a deployment or rotate the admin token | [Operations](operations.md) |
| Configure scanning, notifications or signed read-only queries | [Scanning](operations.md#scheduled-vulnerability-scans) · [Notifications](operations.md#outbound-notifications) · [Information bot](operations.md#read-only-information-bot) |
| Understand capture, Restic receipts, restore drills or retention | [Backup foundation](backup-foundation.md) |
| Build or verify a toolkit release | [Release process](release.md) |
| Report a security issue | [Security policy](../SECURITY.md) |

## Understand or change Steward

| If you need to | Read |
|---|---|
| Trace components, trust boundaries or host state | [Architecture](architecture.md) · [Diagram gallery](diagrams/README.md) |
| Find a component's skill and code entry points | [Working guide](working-guide.md) · [Agent instructions](../AGENTS.md) |
| Extend an executor action, adapter or service | [Extending Steward](extending.md) · [Contribution rules](../CONTRIBUTING.md) |
| Choose a check or understand the security and CI contracts | [Testing](testing.md) · [Threat model](threat-model.md) · [Guardrails](guardrails.md) · [Working guidelines](working-guidelines.md) |
| Find the design decision behind a boundary | [Architecture decision records](adr/) |

## Follow development

| If you need to | Read |
|---|---|
| Find a workstream and its cards | [Roadmap overview](roadmap.md) · [Implementation work queue](implementation-plan.md) |
| Check milestone order, dependencies and completion criteria for RC1 | [Delivery goal](goal.md) |
| Find deferred work and prior acceptance summaries | [Backlog](backlog.md) · [Status](STATUS.md) |
| Explore planned Proxmox, fleet, storage and HA work | [Post-RC1 roadmap](post-rc1.md) · [Infrastructure design](plans/infrastructure-design/README.md) |
