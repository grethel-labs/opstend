import type { PageProps } from "../App";
import { api } from "../api";
import { Badge, Problem, time, useLoad } from "../hooks";

const TONE = { queued: "info", running: "warn", succeeded: "ok", failed: "bad" } as const;

export function JobsPage({ onAuthLost }: PageProps) {
  const loaded = useLoad(() => api.jobs(), onAuthLost, 5000);
  return (
    <>
      <Problem loaded={loaded} />
      {loaded.data?.jobs.length === 0 && <p>No jobs yet.</p>}
      {loaded.data && loaded.data.jobs.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Job</th>
              <th>Kind</th>
              <th>Target</th>
              <th>State</th>
              <th>Attempts</th>
              <th>Created</th>
              <th>Updated</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {loaded.data.jobs.map((job) => (
              <tr key={job.id}>
                <td><code>{job.id.slice(0, 12)}</code></td>
                <td>{job.kind}</td>
                <td>{job.target}</td>
                <td>
                  <Badge tone={TONE[job.state as keyof typeof TONE] ?? "info"}>{job.state}</Badge>
                </td>
                <td>
                  {job.attempts}/{job.max_attempts}
                </td>
                <td>{time(job.created_at)}</td>
                <td>{time(job.updated_at)}</td>
                <td>{job.error ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
