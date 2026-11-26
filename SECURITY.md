# Security Policy

## Reporting vulnerabilities

Please do **not** open public issues for vulnerabilities. Use this repository's
GitHub private reporting feature ("Security" → "Report a vulnerability"). Include
the affected version/commit, a configuration excerpt without secrets,
reproduction steps, and expected impact.

This is a pre-release project with no guaranteed response times. Reports are
handled on a best-effort basis; fixes appear on the main branch and in the
changelog.

## Supported versions

Only the current main branch. There is no stable release yet.

## Scope

Focus areas: bypassing executor checks, escaping service isolation, bypassing
admin API sessions/CSRF protection, configuration injection into generated files,
and leaking secrets into logs or plans.

The threat model and explicitly stated limitations are in
[docs/threat-model.md](docs/threat-model.md). Please test only on disposable
systems you own.
