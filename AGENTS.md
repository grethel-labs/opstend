# Working on OpsTend

Read the skills before changing anything:

- `.claude/skills/opstend-guidelines` – security invariants, UX language, automation rules, code conventions
- `.claude/skills/opstend-maintenance` – layout, commands, CI, releases, dependencies
- `.claude/skills/opstend-integration` – adding or extending Proxmox, Linux, UniFi or new integrations

Checks before every push: `uv run ruff check src tests`, `uv run ruff format --check src tests`,
`uv run mypy`, `uv run pytest`, `(cd web && npm run build && npm run test:e2e)`.
PR titles follow Conventional Commits; merging to `main` releases automatically.
Status and plans belong in `ROADMAP.md`.
