# Contributing

## Ground rules

- **Honesty before completeness.** Only claim in code, documentation, and PRs
  what was actually run. Update [STATUS](docs/STATUS.md) when a card's state or
  acceptance evidence changes.
- **No empty shells.** A feature exists only with implementation and tests.
  Unimplemented features must fail clearly when enabled.
- **Reduce privileges only.** New privileged capabilities must be registered
  executor actions (see `docs/extending.md`), never unrestricted parameters.

## Workflow

```bash
uv sync --extra controller
uv run pytest -n auto
uv run ruff check . && uv run ruff format --check .
(cd ansible && ANSIBLE_COLLECTIONS_PATH=../.steward/collections uv run ansible-lint playbooks roles)
(cd webapp && npm ci && npm run build)
tests/integration/local_rootless.sh     # when rendering, units, or API are affected
```

- Submit small, focused pull requests with a rationale.
- Security changes (executor, rendering, authentication, Ansible roles, CI)
  need a test demonstrating the failure case.
- Ansible: use existing modules; use `command` only with `creates`, a state
  check, or a strict link to a change. A second run must yield `changed=0`.
  Protect secrets with `no_log: true` and `diff: false`.
- Do not commit operator-specific values, credentials, or runtime data;
  `config/` is ignored.
- Changes to `.github/`, lint/test configuration, and policy files receive
  separate review and must not be mixed with feature changes.
- Pull requests produced by the repair coding agent (card R05) are untrusted
  until a human or a separately configured approver has reviewed them. They
  never touch `.github/`, code owners, test or policy configuration, the
  workload contract or the toolkit's own control code (such a diff is rejected
  before validation), and merging one does not deploy anything.

## Contribution license

Contributions are licensed under Apache-2.0 (see `LICENSE`). Only submit code
for which you have the necessary rights; third-party code requires source and
license attribution in the PR.
