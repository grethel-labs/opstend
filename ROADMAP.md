# Roadmap

This file is the single place for status and plans. It says what is built, how it is
verified, and what comes next. "Verified" means tested against the real thing;
"contract-tested" means tested against recorded API or command output.

## Built in 0.2 (the rebuild)

| Area | State | Verification |
| --- | --- | --- |
| Job engine (preview, approval, fencing, readback, rollback), audit chain, policy | done | unit tests |
| Raft control state, placement, voter changes, learners, join tokens, mTLS | done | unit tests + **three real processes**: join, replication, leader failure and re-election (`pytest -m cluster`) |
| Coordinated rollout planner and runner | done | unit tests |
| OpsTend self-update (Sigstore, atomic switch, health gate, rollback) | done | unit tests; first real run with the first signed release |
| Proxmox adapter | done | contract-tested |
| Linux adapter (apt, dnf, zypper, apk, pacman; systemd, OpenRC; Podman, libvirt) | done | contract-tested; installer runs on 6 distributions × amd64/arm64 in CI and on armv7, ppc64le, s390x, riscv64, 386 under QEMU |
| UniFi adapter | done | contract-tested |
| Network graph, insights, path explanation, excaliplant topology | done | unit + browser tests |
| Security scans (Trivy/OSV, KEV, EPSS, exposure, hardening) | done | unit tests |
| Self-management (restart, reschedule, quarantine, patch, backup triggers) | done | unit + API tests |
| AI-assisted deployment (analyzer, validator, hardened Podman) | done | unit + browser tests |
| Zorec (rules, Claude, local models) | done | unit + browser tests (rules); model providers contract-only |
| Web app (PWA, de/en, light/dark, phone) | done | 11 browser tests (desktop and phone) |
| Release pipeline (versioning, Sigstore, provenance, multi-arch install tests) | done | runs on the first merge to `main` |

## Next

1. **Real-hardware acceptance** on the reference site: Proxmox 9 node, two Linux
   servers (amd64, arm64), UniFi gateway + switch + AP. Run every action once,
   record the result here.
2. **Live network changes:** `unifi.port_vlans` and `unifi.firewall_block` on real
   UniFi (today: demo backend), Linux bridge VLAN awareness.
3. **Publications:** manage the HTTPS proxy and WireGuard tunnel as jobs (today:
   inventory and withdrawal in the demo).
4. **Backups:** Proxmox Backup Server and restic targets with scheduled restore tests.
5. **Adoption by pairing code:** approve discovered agents in the UI instead of
   copying a join command.
6. **Secret store** for workload secrets entered in the deployment wizard.
7. **Passkeys/TOTP** and OIDC for the web app.
8. **Push notifications** to the installed app for incidents and decisions.

## Archived

The previous implementation (Steward/RC1) is kept at tag `archive/rc1-steward`.
