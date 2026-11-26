import type { PageProps } from "../App";
import { api } from "../api";
import { Problem, short, time, useLoad } from "../hooks";

function evidenceTime(value: number | null): string {
  return value === null ? "unknown" : time(value);
}

export function BackupsPage({ onAuthLost }: PageProps) {
  const loaded = useLoad(api.backups, onAuthLost, 15000);
  const data = loaded.data;
  return <>
    <p>Capture provenance comes from the executor. Upload, integrity and restored-byte evidence is reported by the backup worker. These are separate claims.</p>
    <Problem loaded={loaded} />
    {data && <>
      {data.freshness !== "fresh" && <p className="banner warn" role="status">Backup observations are {data.freshness}. Any listed evidence is historical and cannot establish current coverage.</p>}
      {data.enabled === false && <p className="banner warn" role="status">Scheduled backups are disabled. Prior evidence does not establish current coverage.</p>}
      {data.enabled === null && <p className="banner warn" role="status">Backup configuration is unknown.</p>}
      <p className="muted">Controller observation: {time(data.generated_at)}. An empty view does not prove backup success.</p>
      <table><thead><tr><th>Project</th><th>Capture</th><th>Worker upload</th><th>Verification</th></tr></thead>
        <tbody>{data.projects.map(item => <tr key={item.project}>
          <td>{item.project}{!item.registered && <p>Project not present in the observation.</p>}</td>
          <td>State: {data.enabled === false ? "disabled" : item.capture_state}<br />Captured: {evidenceTime(item.capture_created_at)} ({item.capture_freshness})<br />Capture: <code>{short(item.capture_id)}</code><br />Configuration: <code>{short(item.config_revision)}</code><p className="muted">Source: {item.root_provenance ?? "unknown"}</p></td>
          <td>State: {data.enabled === false ? "disabled" : item.worker_state}<br />Job: {item.job_state ?? "unknown"}{item.job_error && <p>Reported error: {item.job_error}</p>}
            Uploaded: {evidenceTime(item.uploaded_at)}<br />Repository: <code>{short(item.repository_id)}</code><br />Snapshot: <code>{short(item.snapshot_id)}</code><p className="muted">Source: {item.worker_provenance ?? "unknown"}</p></td>
          <td>Full-data integrity: {evidenceTime(item.integrity_checked_at)}<br />Restored bytes: {evidenceTime(item.restored_bytes_at)}<br />Independent application drill: unknown</td>
        </tr>)}</tbody>
      </table>
      {data.projects.length === 0 && <p>No project evidence is available.</p>}
    </>}
  </>;
}
