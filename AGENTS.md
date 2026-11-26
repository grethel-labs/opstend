# Working in Steward

Use [the working guide](docs/working-guide.md) to locate the system and its
entry points. Load the relevant repo skill from `.agents/skills/` when the
task spans its trust boundary or workflow. Python module paths in the skills
are relative to `src/steward/`.

| Area | Skill |
|---|---|
| Config, rendering, Ansible, boot and guarded deploy | [steward-config-deploy](.agents/skills/steward-config-deploy/SKILL.md) |
| Privileged actions, registry, locks and audit | [steward-executor](.agents/skills/steward-executor/SKILL.md) |
| Health, maintenance, updates and application lifecycle | [steward-lifecycle](.agents/skills/steward-lifecycle/SKILL.md) |
| Capture, Restic, restore and retention | [steward-backups](.agents/skills/steward-backups/SKILL.md) |
| Scanner, collector, notifier and bot | [steward-observations](.agents/skills/steward-observations/SKILL.md) |
| Inference, model selection and advice | [steward-inference](.agents/skills/steward-inference/SKILL.md) |
| Source fetching, build, validation, repair and release | [steward-repository-release](.agents/skills/steward-repository-release/SKILL.md) |
| Admin API and browser | [steward-admin-ui](.agents/skills/steward-admin-ui/SKILL.md) |

[Guardrails](docs/guardrails.md) lists the enforced contracts and their CI
checks. [Working guidelines](docs/working-guidelines.md) explains how to trace
a change and choose evidence. Use [STATUS](docs/STATUS.md) for feature
availability and host acceptance.

# Roadmap goal orchestration

Apply these instructions when planning, implementing, or resuming the roadmap
goal. The plan is [docs/goal.md](docs/goal.md): milestones M1–M8, budgets and the
rules that prevent circling. Card scope is in [the work queue](docs/implementation-plan.md);
current state is the table in [STATUS.md](docs/STATUS.md). Read `goal.md` first.

## Goal text

Reach release candidate RC1 by completing milestones M1–M8 in `docs/goal.md`
in order, starting at the first open milestone. Use one fresh lead agent
(`gpt-6.2-sol`, `high` reasoning) per card step; the lead spawns `gpt-6.2-sol`
workers at `low` reasoning for implementation, tests and one review. The parent
verifies the combined result and commits each tested step. Run one dedicated acceptance VM batch
per milestone, not per step. Time-gated gates (B08 retention) run as a parallel
lane and never block code work. Stop rules in `goal.md` take precedence over
thoroughness: new findings go to `docs/backlog.md`, at most two commits per card
step, no design-only steps for decided matters.

## One step at a time

1. The parent selects the first unfinished step of the first open milestone
   whose prerequisites hold, and reuses existing evidence. Spawn the lead with
   `model: gpt-6.2-sol`, `reasoning_effort: high`, `fork_turns: none`. Pass the
   task ID, workspace, relevant paths, current state, the card's *Check/done*
   line, `goal.md` rules 1–10 and allowed test targets.
2. The lead inspects the sources and returns a plan (division of work,
   dependencies, checks) or a concrete blocker. For a step touching at most
   about eight files and no privileged host path, the lead plans and implements
   in the same run; otherwise this phase is read-only and the parent checks the
   plan against the card before authorizing implementation.
3. The lead spawns workers (`model: gpt-6.2-sol`, `reasoning_effort: low`,
   `fork_turns: none`), each with a concrete task, needed context and an
   explicit write scope. Independent work runs in parallel; dependent work in
   order. Only the lead delegates. One step is in implementation at a time.
4. The lead reports the merged diff, exact checks and remaining limits after
   one independent review of the diff. The parent runs the full local suite,
   coordinates acceptance VM access and restoration of temporary settings, verifies,
   updates the `STATUS.md` card table (≤ 15 evidence lines) and commits.
5. If a gate awaits time, infrastructure or authorization, record the exact
   condition and date in `STATUS.md` and continue with the next step. Partial
   evidence is not acceptance; it is also not a reason to stop.
