// Thin API client: JSON, CSRF header, typed errors and a live event stream.

export type Session = {
  user: string | null;
  name?: string;
  role?: "viewer" | "operator" | "admin";
  csrf?: string;
  lang?: "de" | "en";
  demo: boolean;
  version: string;
  site?: string;
  setup?: boolean;
};

let csrf = "";
export let offline = false;

export function setCsrf(token: string | undefined) {
  csrf = token ?? "";
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET") headers["x-csrf-token"] = csrf;
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  offline = res.headers.get("x-opstend-offline") === "1";
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const detail = data?.detail;
    throw new ApiError(res.status, typeof detail === "string" ? detail : res.statusText);
  }
  return data as T;
}

export const api = {
  get: <T,>(path: string) => request<T>("GET", path),
  post: <T,>(path: string, body: unknown = {}) => request<T>("POST", path, body),
  put: <T,>(path: string, body: unknown) => request<T>("PUT", path, body),
  del: <T,>(path: string) => request<T>("DELETE", path),
};

type Listener = (event: { type: string; [key: string]: unknown }) => void;
const listeners = new Set<Listener>();
let source: EventSource | null = null;

export function onLive(listener: Listener): () => void {
  listeners.add(listener);
  if (!source) {
    source = new EventSource("/api/stream");
    source.onmessage = (msg) => {
      try {
        const event = JSON.parse(msg.data);
        listeners.forEach((l) => l(event));
      } catch {
        /* ignore malformed events */
      }
    };
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0 && source) {
      source.close();
      source = null;
    }
  };
}

// --- shared types -------------------------------------------------------------

export type Health = "ok" | "warning" | "critical" | "unknown" | "maintenance";
export type Usage = { cpu_pct: number | null; memory_mb: number | null; disk_gb: number | null };
export type Resources = { cpu_cores: number; memory_mb: number; disk_gb: number; gpu: number };
export type Observed = { source: string; observed_at: string; max_age_s: number } | null;

export type Host = {
  id: string; name: string; platform: "proxmox" | "linux" | "unifi"; address: string; site: string;
  os: string; version: string; health: Health; capacity: Resources; usage: Usage; observed: Observed;
  tags: string[]; guests?: number; running?: number; updates?: number; stale?: boolean;
};

export type Nic = { name: string; mac: string | null; bridge: string | null; vlan: number | null; ips: string[]; firewall: boolean };

export type Guest = {
  id: string; host_id: string; kind: "vm" | "lxc" | "container"; native_id: string; name: string;
  state: "running" | "stopped" | "paused" | "unknown"; capacity: Resources; usage: Usage; nics: Nic[];
  snapshots: { name: string; created_at: string | null; description: string }[]; template: boolean;
  tags: string[]; image: string | null; uptime_s: number | null; observed: Observed;
  host_name?: string; platform?: string; capabilities?: string[];
};

export type Step = { action: string; params: Record<string, unknown>; title: string; state: string; effect: string; error: string | null; started_at: string | null; finished_at: string | null };

export type Job = {
  id: string; title: string; category: string; target: string; reason: string; requested_by: string;
  state: string; steps: Step[]; fingerprint: string; approved_by: string | null; created_at: string;
  updated_at: string; not_before: string | null; message: string;
};

export type Port = {
  index: number; name: string; up: boolean; speed_mbps: number | null; max_speed_mbps: number | null;
  full_duplex: boolean; poe_watts: number | null; poe_enabled: boolean; native_vlan: number | null;
  tagged_vlans: number[]; profile: string | null; rx_errors: number; tx_errors: number;
  lldp: { chassis: string; port: string; name: string | null } | null; is_uplink: boolean;
};

export type Device = {
  id: string; name: string; kind: "gateway" | "switch" | "ap" | "other"; mac: string; model: string;
  address: string | null; firmware: string; upgrade_to: string | null; health: Health; ports: Port[];
  uplink_mac: string | null; uplink_port: number | null; poe_budget_watts: number | null; site: string;
};

export type Insight = {
  id: string; code: string; severity: "low" | "medium" | "high" | "critical"; title: string;
  detail: string; objects: string[]; fix: { summary: string; action: string } | null; tags: string[];
};

export type Finding = {
  id: string; target: string; kind: string; severity: "low" | "medium" | "high" | "critical"; title: string;
  detail: string; cve: string | null; package: string | null; installed: string | null; fixed: string | null;
  kev: boolean; epss: number | null; exposed: boolean; recommendation: string | null;
};

export type Service = {
  id: string; name: string; description: string; guest_id: string | null; health: Health;
  endpoints: string[]; core: boolean; version: string | null; exposed: boolean;
  guest?: Guest | null; host_name?: string | null;
};

export type AuditEntry = { seq: number; at: string; actor: string; action: string; target: string; job_id: string | null; outcome: string; detail: Record<string, unknown> };
