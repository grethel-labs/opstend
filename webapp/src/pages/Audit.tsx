import type { PageProps } from "../App";
import { type AuditLog, api } from "../api";
import { Badge, Problem, time, useLoad } from "../hooks";

function Log({ title, log }: { title: string; log: AuditLog }) {
  return (
    <>
      <h2>{title}</h2>
      {log.gap ? (
        <p className="banner bad">{log.gap}</p>
      ) : (
        <>
          <p>
            Hash chain:{" "}
            {log.chain_ok ? <Badge tone="ok">intact</Badge> : <Badge tone="bad">BROKEN</Badge>} · {log.records} records
          </p>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {[...(log.entries ?? [])].reverse().map((entry, index) => {
                const { ts, event, prev: _prev, hash: _hash, ...rest } = entry;
                return (
                  <tr key={index}>
                    <td>{time(ts)}</td>
                    <td>{event}</td>
                    {/* Rendered as text: log content is untrusted data. */}
                    <td><code>{JSON.stringify(rest)}</code></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      )}
    </>
  );
}

export function AuditPage({ onAuthLost }: PageProps) {
  const loaded = useLoad(() => api.audit(), onAuthLost);
  return (
    <>
      <Problem loaded={loaded} />
      {loaded.data && (
        <>
          <Log title="Host executor (privileged actions)" log={loaded.data.executor} />
          <Log title="Administration API" log={loaded.data.api} />
        </>
      )}
    </>
  );
}
