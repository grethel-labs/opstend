# Native OpsTend preflight on Proxmox VE

The first native profile targets **Proxmox VE 9.3 with `pve-manager 9.3.1` on
Debian 13 amd64** for lab qualification. The installed package and the API
must agree on the approved version. Additional package versions require
qualification with the same host and API checks. See the PX01 card for the
remaining installation, upgrade, reboot, and removal gates.
[PX01](plans/proxmox.md#px01--native-installation-und-preflight)

## Run on the PVE node

Use the `opstend` executable from an existing OpsTend Python environment. Pass
a CA file that trusts the certificate served by the local PVE API and set
`--api-name` to a name on that certificate. The connection goes to
`127.0.0.1:8006` and uses the supplied name for TLS verification.

Create a dedicated PVE API token with privilege separation enabled. Preflight
checks that the token has no effective privileges at the time of the request.
Store the full token on one line in a private file readable by the invoking
account with mode `0600` or `0400`. The format is `<user>@<realm>!<token>=<UUID>`. Pass the file
path to `--token-file` to keep the credential out of the command line. The only
API requests are GETs for the token's effective permissions and the API
version. [PVE user and token management](https://github.com/proxmox/pve-docs/blob/master/pveum.adoc) ·
[PVE API viewer](https://pve.proxmox.com/pve-docs/api-viewer/)

```sh
opstend pve-native preflight --mode standalone --api-name pve.example.net \
  --ca-file /path/to/pve-ca.pem --token-file /path/to/pve-token
opstend pve-native plan --mode agent --api-name pve.example.net \
  --ca-file /path/to/pve-ca.pem --token-file /path/to/pve-token
```

Both commands print JSON. `preflight` reports readiness and individual checks
for the host, package version, resources, conflicts, listener, TLS,
permissions, and API version. `plan` adds the prospective layout under
`install_plan`, including when a readiness check fails. Exit `0` indicates
readiness, `2` indicates invalid input, and `3` indicates a failed readiness
check. The commands only read local host state and query the local API.

The minimum is one CPU, 256 MiB of available RAM, and 1 GiB of available space
for each of the install and state paths. When those paths share a filesystem,
it needs 2 GiB available. The installation, state, configuration, and systemd
unit locations must be on writable filesystems. The passive port check treats
an IPv6 wildcard listener as a possible conflict with the standalone port.

## Prospective installation

Both modes use `/opt/opstend-pve` for installed files, `/etc/opstend-pve` for
configuration, and `/var/lib/opstend-pve` for state. Both run the
`opstend-pve-agent.service` unit as `opstend-pve-agent`, with outbound access
to the local PVE API on port 8006.

| Mode | Services and listeners |
|---|---|
| `agent` | Agent service with zero inbound listeners. |
| `standalone` | Agent service plus `opstend-pve-ui.service` as `opstend-pve-ui`, with an authenticated UI planned on `127.0.0.1:8447`. |

Native installation in PX01 step 2 requires a verified signed archive. The
preflight and plan can run before an archive is available.
