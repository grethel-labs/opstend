import { useCallback, useEffect, useState } from "react";
import { ApiError } from "./api";

export interface Loaded<T> {
  data: T | null;
  error: string;
  loading: boolean;
  reload: () => void;
}

/** Load data, optionally polling. A 401 hands control back to the login screen. */
export function useLoad<T>(loader: () => Promise<T>, onAuthLost: () => void, pollMs = 0): Loaded<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const reload = useCallback(() => {
    loader()
      .then((result) => {
        setData(result);
        setError("");
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError && err.status === 401) onAuthLost();
        else setError(err instanceof Error ? err.message : "request failed");
      })
      .finally(() => setLoading(false));
    // loader identity is stable per page; onAuthLost only flips state
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    reload();
    if (!pollMs) return;
    const timer = window.setInterval(reload, pollMs);
    return () => window.clearInterval(timer);
  }, [reload, pollMs]);

  return { data, error, loading, reload };
}

export function Problem({ loaded }: { loaded: Loaded<unknown> }) {
  if (loaded.loading) return <p className="muted">Loading…</p>;
  if (loaded.error) return <p className="error" role="alert">{loaded.error}</p>;
  return null;
}

export function time(ts: number | null | undefined): string {
  return ts ? new Date(ts * 1000).toLocaleString() : "–";
}

export function short(rev: string | null | undefined): string {
  return rev ? rev.slice(0, 12) : "–";
}

export function Badge({ tone, children }: { tone: "ok" | "warn" | "bad" | "info"; children: React.ReactNode }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
