# OpsTend guardrails

These contracts apply to changes in the corresponding systems. CI runs the
listed test functions in parallel before host tooling is installed. After this
check passes, the remaining Python tests run in parallel with these cases excluded.
A missing test, skip or xfail fails the early check.
After `uv sync --frozen --extra controller`, run `uv run python tests/run_guardrails.py`
locally. Declare each rule under a `### Gnn` heading and list each pytest node ID
on its own bullet line. Host acceptance and roadmap decisions use their own
evidence and review in [STATUS](STATUS.md).

### G01 Executor boundary

Unprivileged clients request registered actions through the executor protocol.
The executor authorizes by kernel peer UID and explicit role. The collector's
read-only action metadata is the existing import exception.

- `tests/test_guardrails.py::test_executor_clients_import_only_the_protocol`
- `tests/test_executor.py::test_real_socket_identifies_peer_by_kernel_credentials`
- `tests/test_executor.py::test_role_cannot_call_actions_outside_its_set`

### G02 Typed and guarded mutations

Privileged requests use typed parameters and registered target IDs. Host
commands use fixed argv. Mutations and refusals are audited. Automatic writes
respect kill switch, request freshness, replay protection, target locks and
applicable budgets. CI's Ruff check also covers shell-enabled Python APIs.

- `tests/test_guardrails.py::test_host_status_uses_fixed_argv_without_a_shell`
- `tests/test_executor.py::test_parameters_are_schema_checked`
- `tests/test_executor.py::test_unregistered_project_is_denied`
- `tests/test_executor.py::test_kill_switch_stops_mutations_but_not_observation`
- `tests/test_executor.py::test_replayed_request_is_rejected`
- `tests/test_executor.py::test_expired_or_far_future_requests_are_rejected`
- `tests/test_executor.py::test_concurrent_mutation_of_one_target_is_refused`
- `tests/test_executor.py::test_restart_budget_is_enforced`
- `tests/test_executor.py::test_mutations_and_refusals_are_audited_individually_in_an_intact_chain`
- `tests/test_config.py::test_unsafe_or_inconsistent_values_are_rejected`

### G03 Secret transport

Configuration carries secret references. Secret files and delivery stay scoped
to the intended principal. Audit exports, provider errors and API responses
keep credential values out.

- `tests/test_config.py::test_unsafe_or_inconsistent_values_are_rejected`
- `tests/test_secrets.py::test_file_reference_requires_private_permissions`
- `tests/test_collector.py::test_audit_export_is_redacted_at_root_and_preserves_original_hash_anchors`
- `tests/test_notifications.py::test_contract_network_failure_hides_credentials`
- `tests/test_api.py::test_login_sets_hardened_cookie_and_never_echoes_the_token`
- `tests/test_backup_policy.py::test_backup_unit_loads_only_declared_credentials_and_pins_hosts`

### G04 Config revisions

The committed schema follows the model. A UI save creates a pending revision.
Apply and deploy writes compare the reviewed revision against current state,
and Apply also checks the installed release.

- `tests/test_config.py::test_committed_json_schema_is_current`
- `tests/test_api.py::test_commit_creates_pending_revision_and_detects_conflicts`
- `tests/test_config_apply.py::test_apply_request_is_guarded_and_version_bound`
- `tests/test_config_apply.py::test_deployment_writes_are_compare_and_set`

### G05 Deployment custody

Guarded deploy keeps its target and fence until the verified result is bound
to the exact operation. The SSH transport rejects an invalid identity before
connecting. Firewall activation observes SSH and follows the rollback order.

- `tests/test_site_deployment.py::test_verified_receipt_is_exact_and_replayable_after_fence_release`
- `tests/test_guardrails.py::test_ssh_transport_rejects_invalid_identity_before_delegating`
- `tests/test_firewall_activation.py::test_unit_and_ssh_probe_use_verified_paths`

### G06 Deterministic admission

Starter configuration is private, starts in `observe` and uses default-deny
workload egress. The public parser rejects currently unavailable features.
Health self-healing works without AI. Scheduled maintenance uses the configured
window and durable single-run admission.

- `tests/test_config.py::test_example_is_valid_and_starts_in_observe`
- `tests/test_config.py::test_enabled_but_unimplemented_features_are_rejected`
- `tests/test_controller.py::test_stopped_workload_is_restarted_without_any_ai`
- `tests/test_maintenance_admit.py::test_outside_window_is_refused_and_records_nothing`
- `tests/test_maintenance_admit.py::test_inside_window_is_admitted_once_then_refused`

### G07 Update custody

Updates bind signed evidence and separate approval to the current revision
and exact image. Automatic apply requires the patch profile. A migrating
rollback restores the journaled capture and preserves newer data.

- `tests/test_update_evidence.py::test_contract_requires_separate_signer_and_approver_identities`
- `tests/test_update_evidence.py::test_attestation_changed_after_signing_fails_the_signature`
- `tests/test_remediation.py::test_changed_configuration_revision_invalidates_the_approval`
- `tests/test_remediation.py::test_apply_by_controller_needs_patch_profile_which_stays_unavailable`
- `tests/test_update_recovery.py::test_rollback_with_migration_restores_the_exact_capture_and_preserves_newer_data`

### G08 Application custody

Group actions preserve dependency order and the original running state.
Critical exposure is blocked before quarantine, and failed backup leaves the
workload disconnected and running. A retirement releases a working area only
after ownership and archive verification.

- `tests/test_group_actions.py::test_operator_stop_and_resume_preserve_dependency_order_and_original_intent`
- `tests/test_containment.py::test_failed_backup_leaves_stack_running_disconnected_and_escalated`
- `tests/test_containment.py::test_stack_without_registered_data_is_never_quarantined`
- `tests/test_application_retirement.py::test_guarded_bad_archives_never_release_working_area`

### G09 Backup proof and retention

Only sealed imports reach the worker. Upload, check and restore retain
separate evidence for the same snapshot. Cleanup requires exact protection,
age and root authorization, and refuses pending or unknown data.

- `tests/test_backupworker.py::test_unsealed_import_is_never_uploaded`
- `tests/test_backupworker.py::test_upload_check_and_restore_are_separate_durable_evidence`
- `tests/test_backupworker.py::test_snapshot_identity_cannot_change_between_evidence_phases`
- `tests/test_backupretention.py::test_protection_age_and_root_authority_all_gate_cleanup`
- `tests/test_backup_executor.py::test_retirement_refuses_pending_or_unknown_data`

### G10 Qualified evidence

State stays private to its owner across trust domains. Readers receive
scoped, bounded observations. Missing, stale or truncated scan evidence
remains unknown for a risk decision.

- `tests/test_scan_observations.py::test_database_file_is_private_and_rejects_nonregular_files`
- `tests/test_scan_observations.py::test_query_pages_bound_unicode_and_keep_all_subjects`
- `tests/test_critical_risk.py::test_unbound_truncated_and_failed_records_are_never_clean`
- `tests/test_ai_admin_ipc.py::test_rejects_nonprivate_backend_before_opening_stores`

### G11 Messaging boundaries

Bot queries are signed and scoped before reading evidence. Delivery binds
the timestamp and ID to the exact body, verifies the TLS peer and pins the
checked destination address.

- `tests/test_bot.py::test_authorization_happens_before_any_data_read`
- `tests/test_bot.py::test_discord_ping_is_signed_and_does_not_read_data`
- `tests/test_bot.py::test_status_scopes_projects_and_reports_staleness`
- `tests/test_notifications.py::test_signature_binds_timestamp_id_and_exact_body`
- `tests/test_notifications.py::test_connection_pins_checked_ip_and_verifies_hostname`
- `tests/test_notifications.py::test_private_dns_rejected_including_mixed_answers`

### G12 Inference admission

Inference is optional. It reserves budget before provider use and retains
the charge if usage is missing. Advice sends only scoped, redacted evidence
and handles tool-like text as untrusted data.

- `tests/test_inference_config.py::test_ai_provider_stays_unavailable_for_users`
- `tests/test_inference.py::test_budget_denial_is_an_outcome_not_an_exception`
- `tests/test_inference_budget.py::test_race_never_exceeds_the_token_limit`
- `tests/test_inference_budget.py::test_missing_usage_keeps_the_reservation_charged`
- `tests/test_inference.py::test_secrets_are_redacted_and_control_characters_removed`
- `tests/test_advice.py::test_other_projects_never_reach_the_provider_or_the_reply`
- `tests/test_advice.py::test_hostile_text_in_logs_and_output_is_inert`

### G13 Worker trust

AI admin and advice IPC require the expected kernel peer. Failed or superseded
deployment attempts cannot publish inference authority.

- `tests/test_advice_ipc.py::test_worker_rejects_wrong_client_uid_before_reading_or_reserving`
- `tests/test_ai_admin_ipc.py::test_client_sends_no_request_to_wrong_kernel_uid`
- `tests/test_ai_admin_ipc.py::test_server_checks_kernel_uid_before_waiting_for_a_request`
- `tests/test_inference_deployment.py::test_publish_refuses_failed_or_superseded_attempt`

### G14 Repository and build custody

Git fetch binds an exact revision and refuses credential forwarding through
redirects. Repository proposals grant build input only. The build meets the
configured isolation floor, validation keeps separate identity and state,
and a separately approved digest uses the executor update path.

- `tests/test_repositories.py::test_pinned_revision_wins_over_the_moving_ref`
- `tests/test_repositories.py::test_redirect_is_an_error_and_credentials_do_not_follow`
- `tests/test_repository_contract.py::test_repository_contract_file_is_checked_and_authorizes_only_the_build`
- `tests/test_builder.py::test_minimum_level_refuses_a_weaker_build`
- `tests/test_artifact_validation.py::test_the_validator_refuses_to_share_identity_or_state_with_the_builder`
- `tests/test_artifact_validation.py::test_approval_is_refused_for_rejected_reports_and_wrong_identities`
- `tests/test_repository_deploy.py::test_fetch_build_validate_deploy_then_an_unchanged_repeat_changes_nothing`
- `tests/test_repository_deploy.py::test_an_artifact_replaced_after_validation_is_refused`
- `tests/test_repository_deploy.py::test_invalid_repository_evidence_is_denied_at_validation_and_apply`

### G15 Repair authority

Repair proposals cannot change CI, tests already in the base tree, agent
instructions or policy controls. The publication interface is limited to
opening a PR, with no deployment or approval authority.

- `tests/test_repair_diff.py::test_the_agent_cannot_touch_its_approval_chain_tests_or_other_code`
- `tests/test_repair.py::test_a_validated_repair_without_publication_authority_stays_a_local_patch`
- `tests/test_repair.py::test_a_pull_request_is_opened_once_with_explicit_authority`

### G16 Release verification

Release verification rejects an unsigned release, an untrusted signer and
modified artifacts or attestations. Release installation and enforcement by
`deploy` have separate acceptance gates.

- `tests/test_release.py::test_unsigned_release_is_rejected`
- `tests/test_release.py::test_untrusted_signer_is_rejected`
- `tests/test_release.py::test_tampered_artifact_is_rejected`
- `tests/test_release.py::test_tampered_attestation_is_rejected`

### G17 Admin session

Admin routes require an authenticated session. Mutating HTTP requests require an
allowed origin and CSRF token. Host checks and secure session cookies apply.
The webapp job checks CSP compatibility on the built entry point and exercises
the production UI and API together in Chromium.

- `tests/test_api.py::test_everything_is_closed_without_session`
- `tests/test_api.py::test_unknown_host_header_is_rejected`
- `tests/test_api.py::test_unsafe_requests_need_origin_and_csrf_token`
- `tests/test_api.py::test_login_sets_hardened_cookie_and_never_echoes_the_token`

### G18 CI trust

Pull requests use read-only CI with pinned actions, no checked-out credentials
and no secrets. The Python job runs the guardrail lane before tests that need
host tooling.

- `tests/test_guardrails.py::test_ci_preserves_unprivileged_guardrail_step`
- `tests/test_guardrails.py::test_guardrail_manifest_rejects_rules_without_checks`
