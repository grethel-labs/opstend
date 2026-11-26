// API client. The session lives in an HttpOnly cookie the script cannot read;
// the CSRF token is kept in memory only (never in localStorage or the URL).

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public detail?: unknown,
  ) {
    super(message);
  }
}

let csrf = "";

export function setCsrf(token: string): void {
  csrf = token;
}

export async function request<T>(method: string, path: string, body?: unknown, headers?: Record<string, string>): Promise<T> {
  const init: RequestInit = {
    method,
    credentials: "same-origin",
    headers: { Accept: "application/json", ...headers },
  };
  if (method !== "GET") {
    (init.headers as Record<string, string>)["X-CSRF-Token"] = csrf;
    if (body !== undefined) {
      (init.headers as Record<string, string>)["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
  }
  const response = await fetch(path, init);
  const text = await response.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON error body */
  }
  if (!response.ok) {
    const detail = (data as { detail?: unknown } | null)?.detail;
    const message = typeof detail === "string" ? detail : `request failed (${response.status})`;
    throw new ApiError(response.status, message, detail);
  }
  return data as T;
}

export interface BackupRecord {
  project: string; registered: boolean; capture_state: string; capture_id: string | null;
  capture_created_at: number | null; capture_freshness: "fresh" | "stale" | "unknown";
  config_revision: string | null; worker_state: string;
  job_state: string | null; job_error: string | null; repository_id: string | null;
  snapshot_id: string | null; uploaded_at: number | null; integrity_checked_at: number | null;
  restored_bytes_at: number | null; application_drill_at: null;
  root_provenance: string | null; worker_provenance: string | null;
}

export interface BackupsResponse {
  enabled: boolean | null; freshness: "fresh" | "stale" | "unknown";
  generated_at: number | null; projects: BackupRecord[];
}

export interface ScanEvidence {
  source: "osv" | "trivy";
  checked_at: number;
  complete: boolean;
  state: "unknown" | "stale" | "scan_failed" | "not_affected" | "confirmed";
  subject: { scope: string; name: string; version: string; runtime_verified: boolean; kind: string; expected_image_id?: string | null };
  subject_key: string;
  error_class: string | null;
  retry_after_s: number | null;
  findings_total: number;
  findings: Array<{
    id: string; severity: string; summary: string; fixed_versions: string[];
    context_truncated?: boolean;
    exploit_context?: Array<{ cve: string; kev: IntelEvidence; epss: IntelEvidence }>;
  }>;
  last_success?: ScanEvidence | null;
  details_omitted?: boolean;
}

export interface IntelEvidence {
  state: "disabled" | "unknown" | "available" | "stale" | "fetch_failed";
  checked_at: number | null; published_at: number | null; catalog_version: string | null;
  listed: boolean | null; score: number | null; percentile: number | null; error_class: string | null;
}

export interface ScansResponse {
  records: ScanEvidence[];
  total: number;
  next_offset: number | null;
  snapshot_id: string | null;
  summary: {
    enabled: boolean; complete: boolean; stale: boolean; configuration_matches: boolean;
    generated_at?: number; inventory_revision?: string; counts: Record<string, number>;
    runtime_images_verified?: boolean;
    context_enabled?: { kev?: boolean; epss?: boolean };
    context_counts?: Record<string, Record<string, number>>;
    kernel?: { state: string; release: string; reboot_required: boolean | null };
  };
  jobs: Array<{ id: string; state: string; attempts: number; max_attempts: number; error: string | null }>;
}

export interface ScanFilter {
  project?: string; source?: string; subject?: string; offset?: number; finding_offset?: number;
  snapshot_id?: string;
}

export interface Unit {
  unit: string;
  active: string;
  sub: string;
  restarts?: number;
}

export interface ProjectStatus {
  deploy: boolean;
  allow_restart: boolean;
  unit: Unit;
  health?: { ok: boolean; status?: number; error?: string };
  hardening?: { inspected: boolean; violations: string[]; apparmor_profile?: string | null };
}

export interface HostStatus {
  checked_at: number;
  release: string;
  config_revision: string;
  automation_profile: string;
  kill_switch: boolean;
  reboot_required: boolean;
  firewall: { managed: boolean; loaded: boolean | null };
  platform_units: Unit[];
  proxy: Unit;
  failed_units: string[];
  resources: { memory_total_mb: number; memory_available_mb: number; disk_total_mb: number; disk_free_mb: number };
  projects: Record<string, ProjectStatus>;
}

export interface Finding {
  id: string;
  severity: "info" | "warning" | "high" | "critical";
  target: string;
  summary: string;
  remediation: string | null;
  blocked: string | null;
}

export interface AuditEntry {
  ts: number;
  event: string;
  [key: string]: unknown;
}

export interface StatusResponse {
  source: string;
  stale: boolean;
  status_ok: boolean;
  generated_at: number | null;
  age_s?: number;
  gap?: string;
  status: HostStatus | null;
  findings: Finding[] | null;
  actions?: AuditEntry[];
}

export interface DiffEntry {
  path: string;
  change: "added" | "removed" | "changed";
  old?: unknown;
  new?: unknown;
}

export interface ConfigResponse {
  head: string | null;
  applied: string | null;
  pending: boolean;
  config: { projects: Array<Record<string, unknown>> } | null;
  yaml: string;
}

export interface Revision {
  id: string;
  parent: string | null;
  created_at: number;
  author: string;
  source: string;
  message: string;
}

export interface Job {
  id: string;
  kind: string;
  target: string;
  state: string;
  attempts: number;
  max_attempts: number;
  error: string | null;
  created_by: string;
  created_at: number;
  updated_at: number;
}

export interface AuditLog {
  chain_ok?: boolean;
  records?: number;
  entries?: AuditEntry[];
  gap?: string;
}

export interface EventRecord {
  id: number;
  ts: number;
  source: string;
  kind: string;
  severity: "info" | "warning" | "high" | "critical";
  project: string | null;
  target: string | null;
  correlation_id: string | null;
  outcome: string | null;
  summary: string;
  delivery: "immediate" | "digest" | "none";
}

export interface EventCoverage {
  oldest: number | null;
  newest: number | null;
  count: number;
  pruned_before: number | null;
  last_cycle: number | null;
  lag_s: number | null;
  open_gaps: Array<{ source: string; since: number; reason: string }>;
}

export interface EventFilter {
  min_severity?: string;
  project?: string;
  correlation_id?: string;
  kind_prefix?: string;
}

export interface ApplyPlan {
  supported: boolean; reason: string | null; applied: string; head: string;
  areas: string[]; operations: string[]; diff: DiffEntry[];
}

export interface ApplyPlanResponse {
  head: string | null; applied: string | null; release: string;
  plan: ApplyPlan | null; jobs: ConfigApplyJob[];
  tracked_job?: ConfigApplyJob | null;
}

export interface ConfigApplyJob extends Job {
  payload: { head: string; applied: string; release: string };
  result: Record<string, unknown> | null;
}

export const api = {
  login: (token: string) => request<{ csrf: string }>("POST", "/api/login", { token }),
  logout: () => request<unknown>("POST", "/api/logout"),
  session: () => request<{ csrf: string; expires_at: number; version: string }>("GET", "/api/session"),
  backups: () => request<BackupsResponse>("GET", "/api/backups"),
  status: (live = false) => request<StatusResponse>("GET", `/api/status${live ? "?live=true" : ""}`),
  advice: () => request<{ enabled: boolean }>("GET", "/api/advice"),
  askAdvice: (question: string) => request<{ text: string }>("POST", "/api/advice", { question }),
  config: () => request<ConfigResponse>("GET", "/api/config"),
  validate: (yaml: string) =>
    request<{ revision: string; diff: DiffEntry[] }>("POST", "/api/config/validate", { yaml }),
  commit: (yaml: string, parent: string | null, message: string) =>
    request<{ revision: string; pending: boolean }>("POST", "/api/config/revisions", { yaml, parent, message }),
  revisions: () => request<{ head: string | null; applied: string | null; revisions: Revision[] }>("GET", "/api/config/revisions"),
  applyPlan: (jobId?: string) =>
    request<ApplyPlanResponse>("GET", `/api/config/apply-plan${jobId ? `?job_id=${encodeURIComponent(jobId)}` : ""}`),
  applyConfig: (head: string, applied: string) =>
    request<ConfigApplyJob>("POST", "/api/config/apply", { head, applied }, { "Idempotency-Key": crypto.randomUUID() }),
  jobs: () => request<{ jobs: Job[] }>("GET", "/api/jobs"),
  restart: (projectId: string) =>
    request<Job>("POST", `/api/projects/${encodeURIComponent(projectId)}/restart`, undefined, {
      "Idempotency-Key": crypto.randomUUID(),
    }),
  audit: () => request<{ api: AuditLog; executor: AuditLog }>("GET", "/api/audit"),
  events: (filter: EventFilter) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(filter)) if (value) query.set(key, value);
    return request<{ events: EventRecord[]; coverage: EventCoverage; truncated?: boolean }>("GET", `/api/events?${query}`);
  },
  scans: (filter: ScanFilter) => {
    const query = new URLSearchParams();
    Object.entries(filter).forEach(([key, value]) => { if (value !== undefined) query.set(key, String(value)); });
    return request<ScansResponse>("GET", `/api/scans?${query}`);
  },
};
