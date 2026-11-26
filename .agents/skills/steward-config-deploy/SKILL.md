---
name: steward-config-deploy
description: Change Steward configuration, canonical revisions, generated host artifacts, or the guarded CLI and Ansible deploy path. Use for schema, SSH trust, firewall, Quadlet, systemd and application boot changes.
---

# Configuration and deployment

1. Trace `core/config.py` → `effective()` → `core/canonical.py` → `core/render.py` → `cli/main.py` and the role consuming the artifact. Keep old effective revisions stable when optional fields are unset. Regenerate the schema with `uv run python -m steward.core.schema`.
2. For config apply, follow `core/config_apply.py` and `executor/config_apply.py`. Check whether the change fits the registry-only plan or requires a site deployment. For site changes follow `ansible/playbooks/site.yml`, `executor/site_deployment.py` and `ansible/connection_plugins/steward_guarded_ssh.py`. Preserve the exact operation and revision binding across failure and resume.
3. For SSH or network changes, inspect verify and rollback ordering in the firewall/base roles. For workload changes, follow the generated registry into the identity, workload and boot roles. Compare the default, disabled, existing-install and interrupted paths.

Start with `tests/test_config.py`, `tests/test_render.py`, and the affected config apply, deployment, transport or role tests. Use the [host evidence levels](../../../docs/testing.md) for real transport, reload and reboot claims. [G03–G05](../../../docs/guardrails.md#g03-secret-transport).
