---
name: opstend-maintenance
description: How to work on OpsTend day to day – run the demo, test, debug CI, release, update dependencies and excaliplant, take screenshots. Use when asked to fix, extend, test, release or maintain OpsTend.
---

# Maintaining OpsTend

## Layout

```
src/opstend/            Python package (one name everywhere)
  core/                 models, store, audit log, jobs, policy, windows
  cluster/              raft consensus, placement, enrollment, node, discovery, rollout
  adapters/             proxmox, linux (all distros/archs), unifi, safe runner
  network/              unified graph, insights, excaliplant PlantUML
  security/ updates/ selfmanage/ deploy/ zorec/
  api/                  FastAPI app, auth; api/static is the built web app (not in git)
  actions.py            every job action + demo and live backends
  runtime.py            wires a node together and runs its loops
  agent.py              privileged host agent (root, Unix socket)
web/                    React PWA (Vite), e2e tests in web/e2e
packaging/              install.sh, systemd and OpenRC units, example config
tests/                  unit tests; tests/integration = multi-process cluster test
scripts/release.py      next version and notes from Conventional Commits
```

## Everyday commands

```sh
uv sync                                   # Python env
(cd web && npm ci && npm run build)       # web app into src/opstend/api/static
uv run opstend demo                       # http://127.0.0.1:8080 with example data
(cd web && npm run dev)                   # live-reload UI against the demo on :8080
uv run pytest                             # unit tests (fast)
uv run pytest -m cluster tests/integration   # three real nodes, leader failover (~60 s)
(cd web && npm run test:e2e -- --trace off)  # browser tests, desktop + phone
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy
```

Before you push: all of the above green. CI runs the same plus installs the wheel on
Debian, Ubuntu, Fedora, Alpine, openSUSE and Arch on amd64 and arm64.

## Releasing (automatic)

Merging to `main` runs `.github/workflows/release.yml`: CI → `scripts/release.py`
decides the version (feat → minor, fix/perf/security/refactor → patch, before 1.0
breaking changes bump the minor) → build → Sigstore signature and provenance →
GitHub release with `install.sh`, wheel and `SHA256SUMS` → install tests on armv7,
ppc64le, s390x, riscv64 and 386 under QEMU. Nodes find the release, verify it and
update in waves (`opstend self-update`, rollout planner). Nobody tags or signs by hand.
To influence the version, choose the right PR title.

## Dependencies

Dependabot opens grouped PRs weekly; patch and minor updates merge automatically when
CI is green. Major updates need a person: read the changelog, run the full checks.
excaliplant is pinned exactly in `web/package.json`; after updating, open the
topology in the demo, check both themes and run the e2e topology test.

## Debugging CI

- `ci-ok` is the required check; open the failing job, not the summary.
- e2e failures upload `web/test-results`; reproduce with
  `npx playwright test -g "<name>" --trace on`.
- Install failures: run the same `docker run … install.sh --wheel … --no-service`
  command locally with the image from the matrix.
- Cluster test failures: logs of each node are in the pytest tmp dir
  (`a/log`, `b/log`, `c/log`).

## Adding things

- **New action:** add description, category and FACTS in `actions.py`, implement it
  in `DemoBackend` and `LiveBackend`, add an API trigger or Zorec rule, test the job
  flow in `tests/test_api.py` and, if visible, in `web/e2e`.
- **New integration:** see the `opstend-integration` skill.
- **New insight:** a function in `network/analysis.py` returning `Insight`s with
  bilingual text and, if possible, a `fix` that maps to an action; add it to
  `analyze()` and a test in `tests/test_network.py`.

## Screenshots for README and reviews

`node web/scripts/screenshots.mjs` (with the demo running on :8080) writes
`docs/screenshots/*.png` at 1440×900 and phone size.
