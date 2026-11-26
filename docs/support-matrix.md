# Support matrix

The table records prior installation evidence for each target profile. Signed
0.1.0rc1 archive acceptance is pending, including installation, upgrade,
unchanged redeploy and reboot. See [STATUS](STATUS.md) for the S01 gate state.

## Target system

| Operating system | x86_64 | arm64 |
|---|---|---|
| Ubuntu Server 26.04 LTS | **Baseline tested** on Proxmox/KVM, including repeat deployment, isolation and reboot; 8 GiB guest accepted again after reset; earlier emulated test also retained | Unsupported (S02). Preflight permits `aarch64`, and the profile has no installation evidence. |
| Ubuntu Server 24.04 LTS | Unsupported (rejected by preflight) | Unsupported |
| Debian | Unsupported (rejected by preflight) | Unsupported |
| RHEL-compatible | Unsupported (rejected by preflight; SELinux path missing) | Unsupported |

Verified components of the target profile: systemd, cgroup v2, Podman ≥ 5.4
(developed against 5.7.0), nftables 1.1, Python 3.14.

All additional OS and architecture profiles (S02) are unsupported. Public
administration with OIDC/MFA (S03) is unsupported and public configuration
validation rejects `admin.access: public`. Private administration supports
`private-loopback` over an SSH tunnel and `private-lan` for RFC1918 IPv4 guest
addresses and source networks. The previous `private` value and omitted access
setting use loopback. Private LAN host acceptance is pending. A private IPv4
alias must use the same admin port as the guest. Clients must trust the
installation's internal CA. Scope changes use the normal deploy path with
staged firewall verification on schema 1 and guarded admission on schema 2.
Upgrading an older schema 2 installation to LAN mode takes two signed deploys.

The candidate subset draws on earlier host evidence for the single-host
baseline, guarded configuration recovery, bounded host and project scanning,
and weekly maintenance windows and tested project probe paths. The healthy
container probe gate and released public HTTPS and real Discord delivery
acceptance remain open. See [card state](STATUS.md#card-state).

## Controller machine

Signed deployment uses a separately trusted controller checkout at the matching
OpsTend version and an independently obtained release public key. These rows
record source and bootstrap evidence. See the [signed deployment process](release.md#deploy-a-signed-archive).

| System | Status |
|---|---|
| Linux, Python 3.14 | Bootstrap and all local tests run |
| Linux, Python 3.12/3.13 | Expected to work, not run |
| macOS | Expected to work, not run |
| Windows | Unsupported (WSL untested) |

## Pinned versions

| Component | Version |
|---|---|
| ansible-core | 2.20.x (`requirements/controller.txt`, with hashes) |
| ansible.posix / community.crypto | 2.1.0 / 3.0.5 |
| Traefik | v3.7.19 (`docker.io/library/traefik@sha256:44b61e76…`) |
| Example application | `docker.io/library/python@sha256:5862d971…` (3.14.10-alpine3.24) |
| React / Vite / TypeScript | 19.3.1 / 8.3.8 / 7.0.2 (`webapp/package-lock.json`) |

## Minimum resources

No reliable lower bound. A single measurement on the test VM (2 vCPU, 2 GB RAM)
after installation with the example application: 488 MB RAM and 3.4 GB disk used.
Preflight requires `reserved_memory_mb` (default 512) + proxy limit (192) + sum of
project limits, plus 5 GiB free disk space. Measured requirements will be
published only after tests on real hardware.

A Proxmox/KVM guest matching the intended server allocation (4 vCPU, 8 GiB RAM,
24 GiB disk) passed two fresh installations and the baseline acceptance checks.
Scanning was disabled. This allocation is evidence for the tested baseline.
Minimum sizing for scanning, backups and AI workloads remains unmeasured.
