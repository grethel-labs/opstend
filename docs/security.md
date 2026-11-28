# Security

## Trust boundaries

| Boundary | Protection |
| --- | --- |
| Browser → API | HTTPS, scrypt passwords, HttpOnly SameSite=Strict session, CSRF header, role checks (viewer, operator, admin), login rate limit, strict CSP |
| API → host | Unprivileged service; root work only through the agent's allowlist; no shell strings |
| Node ↔ node | Mutual TLS 1.3 with the cluster CA; join tokens are single-use, expire after 30 min and are bound to the certificate request |
| OpsTend → Proxmox/UniFi | Least-privilege accounts; certificate pinned at adoption |
| OpsTend → Linux | SSH keys, `StrictHostKeyChecking=yes` with a pinned known_hosts |
| Releases → nodes | Sigstore signature of SHA256SUMS bound to the release workflow identity; checksum of the wheel; fail closed; automatic rollback when the new version is unhealthy |
| Model → actions | Model output is data; actions are checked against the registry and need the same approval as any job |

## Secrets

Secrets live in files under `/etc/opstend/secrets` (0600, owner `opstend`) or systemd
credentials. They are never stored in the replicated state, jobs, logs or Zorec context.
Join tokens are the exception: the one-time secret is replicated so any voter can
verify the proof; it expires after 30 minutes and is deleted on use.

## Automation limits

Disruptive work waits for the maintenance window unless a known exploited issue is
reachable from outside. Each target has a retry budget and cooldown; when they are
used up OpsTend stops and asks. The kill switch pauses all automatic changes.

## Reporting

Please report vulnerabilities privately through GitHub security advisories of
`grethel-labs/opstend`.
