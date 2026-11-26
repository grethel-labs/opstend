# Working guidelines

1. Start from the normal entry point and one representative existing test.
   Follow the request or data to its owner, the first authorization decision,
   its durable state and the reader of that state. The [working guide](working-guide.md)
   points to the main flows and [AGENTS.md](../AGENTS.md) routes to the skills.
2. Read the owning ADR or card alongside the installed behavior. Check
   [STATUS](STATUS.md) before changing an availability guard or describing a
   candidate path. The implementation, what ships, and what a real host has
   proved can be at different stages.
3. Place a decision where its required facts are owned. Use existing helpers for
   canonical revision IDs, registry lookup, peer identity, locking, evidence and
   redaction. In Python, begin with the smallest relevant contract test. For a
   generated artifact, compare the renderer and the role that consumes it.
4. Exercise an allowed case and a refusal for a trust-boundary change. Ask what
   would happen if the request arrived twice, the configuration changed in
   between, or the service stopped halfway through. Cover the relevant case
   at the boundary that can observe the result.
5. Use [the test matrix](implementation-plan.md#checks-to-run-for-a-task) to
   scale verification. In the handoff, record the command and the evidence it
   actually collected. Follow the [roadmap](goal.md) for card steps and VM
   batches. Host authorization, external delivery and live evidence are
   operator or reviewer decisions.

The [guardrails](guardrails.md) are the CI-enforced contracts. When one changes,
update its linked test cases with it. Start a focused local check with
`uv run python tests/run_guardrails.py`.
