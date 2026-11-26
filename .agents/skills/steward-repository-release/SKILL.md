---
name: steward-repository-release
description: Change Steward Git fetching, workload contract proposals, isolated builds, validator and deployment handoff, repair diffs or toolkit release packaging and verification.
---

# Repositories and toolkit release

1. Follow `core/repositories.py` → `core/repository_contract.py` → `core/builder.py`. Keep fetch revision and source identity stable and treat repo content as data. Check operator contract precedence, credential scope, and the build's minimum isolation and immutable output identity.
2. Trace accepted build artifacts through `core/artifact_validation.py` and a separate approver into `core/repository_deploy.py`. Preserve executor validation/apply and service dependency order. For repair start at `core/repair.py` and `core/repair_diff.py`, with protected paths and publication limited to a PR.
3. For the toolkit's own release, follow `release.py` and `docs/release.md`. Verify the subset, inputs, SBOM, provenance and signature; check tampering and wrong keys. Read STATUS before describing deploy verification or supported platforms as accepted.

Use the repository, builder, validator, repo deploy, repair and release contract tests. [G14–G16](../../../docs/guardrails.md#g14-repository-and-build-custody).
