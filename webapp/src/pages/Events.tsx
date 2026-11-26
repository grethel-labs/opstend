import { useEffect, useState } from "react";
import type { PageProps } from "../App";
import { ApiError, type EventCoverage, type EventFilter, type EventRecord, api } from "../api";
import { Badge, time } from "../hooks";

const TONE = { info: "info", warning: "warn", high: "bad", critical: "bad" } as const;
const SEVERITIES = ["info", "warning", "high", "critical"];

function Coverage({ coverage }: { coverage: EventCoverage }) {
  const stale = coverage.lag_s === null || coverage.lag_s > 120;
  return (
    <>
      {(stale || coverage.open_gaps.length > 0) && (
        <div className="banner bad" role="alert">
          {stale && <p>The collector has not completed a cycle recently; newer events may be missing.</p>}
          {coverage.open_gaps.map((gap) => (
            <p key={gap.source}>
              Open observation gap ({gap.source}) since {time(gap.since)}: {gap.reason}
            </p>
          ))}
        </div>
      )}
      <p className="muted">
        {coverage.count} events from {time(coverage.oldest)} to {time(coverage.newest)}
        {coverage.pruned_before ? ` · older events removed by retention before ${time(coverage.pruned_before)}` : ""}
        {coverage.lag_s !== null ? ` · last collection ${Math.round(coverage.lag_s)} s ago` : ""}
      </p>
    </>
  );
}

export function EventsPage({ onAuthLost }: PageProps) {
  const [filter, setFilter] = useState<EventFilter>({ min_severity: "info" });
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [coverage, setCoverage] = useState<EventCoverage | null>(null);
  const [error, setError] = useState("");
  const [truncated, setTruncated] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      api
        .events(filter)
        .then((result) => {
          if (cancelled) return;
          setEvents(result.events);
          setCoverage(result.coverage);
          setTruncated(Boolean(result.truncated));
          setError("");
        })
        .catch((err: unknown) => {
          if (cancelled) return;
          if (err instanceof ApiError && err.status === 401) onAuthLost();
          else setError(err instanceof Error ? err.message : "request failed");
        });
    void load();
    const timer = window.setInterval(load, 15000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [filter, onAuthLost]);

  const set = (patch: EventFilter) => setFilter((current) => ({ ...current, ...patch }));

  return (
    <>
      <div className="row">
        <label>
          Minimum severity
          <select value={filter.min_severity} onChange={(e) => set({ min_severity: e.target.value })}>
            {SEVERITIES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        <label>
          Project
          <input
            value={filter.project ?? ""}
            placeholder="all"
            onChange={(e) => set({ project: e.target.value.trim() || undefined })}
          />
        </label>
        {filter.correlation_id && (
          <button className="secondary" onClick={() => set({ correlation_id: undefined })}>
            Show all, not only {filter.correlation_id.slice(0, 12)}
          </button>
        )}
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {coverage && <Coverage coverage={coverage} />}
      {truncated && <p role="status">More events match. Narrow the filters to view the remaining events.</p>}
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>Kind</th>
            <th>Target</th>
            <th>Summary</th>
            <th>Notification</th>
            <th>Story</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td>{time(event.ts)}</td>
              <td>
                <Badge tone={TONE[event.severity]}>{event.severity}</Badge>
              </td>
              <td>
                <code>{event.kind}</code>
              </td>
              <td>{event.project ?? event.target ?? "–"}</td>
              {/* Rendered as text: event content can come from logs and is untrusted. */}
              <td>{event.summary}</td>
              <td>{event.delivery === "immediate" ? <Badge tone="warn">immediate</Badge> : event.delivery}</td>
              <td>
                {event.correlation_id && (
                  <button className="secondary" onClick={() => set({ correlation_id: event.correlation_id ?? undefined })}>
                    {event.correlation_id.slice(0, 10)}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {events.length === 0 && !error && <p>No events match this filter.</p>}
    </>
  );
}
