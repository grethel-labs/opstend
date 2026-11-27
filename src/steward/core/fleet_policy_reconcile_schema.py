"""Coordinator tables for ordered reports and durable policy claims."""

RECONCILE_SCHEMA = """
CREATE TABLE IF NOT EXISTS fleet_policy_report_state (
    kind TEXT NOT NULL, target_id TEXT NOT NULL, generation INTEGER NOT NULL,
    approval_id TEXT,
    PRIMARY KEY (kind, target_id, generation)
);
CREATE TABLE IF NOT EXISTS fleet_policy_remote_reports (
    kind TEXT NOT NULL, target_id TEXT NOT NULL, generation INTEGER NOT NULL,
    agent_id TEXT NOT NULL, sequence INTEGER NOT NULL,
    request TEXT NOT NULL,
    PRIMARY KEY (kind, target_id, generation, agent_id)
);
CREATE TABLE IF NOT EXISTS fleet_policy_remote_claims (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    grant_generation INTEGER NOT NULL,
    approval_id TEXT NOT NULL REFERENCES fleet_policy_approvals(id),
    kind TEXT NOT NULL, target_id TEXT NOT NULL, generation INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    receipt TEXT NOT NULL,
    UNIQUE (kind, target_id, generation, agent_id, sequence)
);
"""
