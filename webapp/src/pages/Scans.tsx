import { useEffect, useState } from "react";
import type { PageProps } from "../App";
import { ApiError, api, type ScanEvidence, type ScanFilter, type ScansResponse } from "../api";
import { Badge, time } from "../hooks";

function Findings({ evidence }: { evidence: ScanEvidence }) {
  return <>
    {evidence.details_omitted && <p>Historical details were omitted from this page. The stored successful query remains historical evidence.</p>}
    {evidence.findings.map(f => <div key={f.id}>
      <p><strong>{f.id}</strong> · {f.severity}: {f.summary}
      {f.fixed_versions.length > 0 && <span> · Provider-listed fixed versions: {f.fixed_versions.join(", ")}</span>}
      </p>
      {f.context_truncated && <p>Only a bounded subset of CVE aliases has context; remaining aliases are unknown.</p>}
      {!f.exploit_context?.length && <p>No supplemental CVE evidence is stored for this finding; context is unknown or disabled.</p>}
      {f.exploit_context?.map(context => <div key={context.cve} className="muted">
        <p>Context for {context.cve}</p>
        <p>KEV {context.kev.state}: {context.kev.listed === null ? "membership unknown" : context.kev.listed ? "listed" : "not listed"}
          {context.kev.state !== "available" && context.kev.listed !== null ? " (historical; no current proof)" : ""}
          {context.kev.catalog_version ? ` · catalog ${context.kev.catalog_version}` : ""}
          {` · published ${time(context.kev.published_at)} · retrieved ${time(context.kev.checked_at)}`}
          {context.kev.error_class ? ` · ${context.kev.error_class}` : ""}</p>
        <p>EPSS {context.epss.state}: {context.epss.score === null ? "probability unknown" : `${(context.epss.score * 100).toFixed(2)}% estimated exploitation probability over 30 days`}
          {context.epss.state !== "available" && context.epss.score !== null ? " (historical; no current proof)" : ""}
          {context.epss.percentile === null ? "" : ` · percentile ${(context.epss.percentile * 100).toFixed(2)}%`}
          {` · score date ${time(context.epss.published_at)} · retrieved ${time(context.epss.checked_at)}`}
          {context.epss.error_class ? ` · ${context.epss.error_class}` : ""}</p>
      </div>)}
    </div>)}
    {evidence.findings_total === 0 && <p>No findings in this result.</p>}
  </>;
}

export function ScansPage({ onAuthLost }: PageProps) {
  const [filter, setFilter] = useState<ScanFilter>({});
  const [data, setData] = useState<ScansResponse | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let cancelled = false;
    setData(null);
    const load = async () => {
      try {
        const result = await api.scans(filter);
        if (!cancelled) { setData(result); setError(""); }
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 401) onAuthLost();
        else if (err instanceof ApiError && err.status === 409) setFilter(current => ({ project: current.project, source: current.source }));
        else setError(err instanceof Error ? err.message : "Scanner unavailable; coverage is unknown.");
      }
    };
    void load();
    const timer = window.setInterval(load, 15000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [filter, onAuthLost]);

  const summary = data?.summary;
  return <>
    <p>Provider matches describe exact versions or image digests. They do not prove exploitability or a running fix.</p>
    <p className="muted">Optional KEV/EPSS context supplements prioritization; it does not prove exploitation on this host. Query coverage below describes the version/image scanners.</p>
    {error && <p className="error" role="alert">{error} Coverage is unknown while this view cannot refresh.</p>}
    {summary && <>
      {!summary.enabled && <p className="banner warn" role="status">Scanning is disabled. Coverage is unknown; prior results remain historical.</p>}
      {summary.enabled && !summary.complete && <p className="banner warn" role="status">Scan coverage is incomplete{summary.stale ? " or stale" : ""}. Unknown results are not evidence that a component is unaffected.</p>}
      <p className="muted">Last snapshot: {time(summary.generated_at)} · {data?.total} matching subjects · {Object.entries(summary.counts).map(([state, count]) => `${state}: ${count}`).join(" · ")}</p>
      <p className="muted">Context requested: KEV {summary.context_enabled?.kev ? "on" : "off"}, EPSS {summary.context_enabled?.epss ? "on" : "off"}. {Object.entries(summary.context_counts ?? {}).map(([source, counts]) => `${source}: ${Object.entries(counts).map(([state, count]) => `${state} ${count}`).join(", ")}`).join(" · ")}</p>
      {summary.kernel && <p>Running kernel {summary.kernel.release}: <strong>{summary.kernel.state}</strong> · Reboot required: {summary.kernel.reboot_required === null ? "unknown" : summary.kernel.reboot_required ? "yes" : "no"}</p>}
      {!summary.configuration_matches && <p>These results do not establish coverage for the current configuration.</p>}
    </>}
    <div className="row">
      <label>Project<input value={filter.project ?? ""} placeholder="all or host" onChange={e => setFilter({ project: e.target.value.trim() || undefined, source: filter.source })} /></label>
      <label>Source<select value={filter.source ?? ""} onChange={e => setFilter({ project: filter.project, source: e.target.value || undefined })}>
        <option value="">all</option><option value="osv">OSV</option><option value="trivy">Trivy</option>
      </select></label>
      {filter.subject && <button className="secondary" onClick={() => setFilter({ project: filter.project, source: filter.source })}>All subjects</button>}
    </div>
    <table><thead><tr><th>Subject</th><th>Source / checked</th><th>State</th><th>Evidence</th></tr></thead>
      <tbody>{data?.records.map(record => <tr key={`${record.source}:${record.subject_key}`}>
        <td>{record.subject.scope}: {record.subject.name}<br /><code>{record.subject.version}</code>
          {record.subject.kind === "image" && <><p>Running image identity verified at scan time: {record.subject.runtime_verified ? "yes" : "no"}</p>
            {record.subject.expected_image_id && <p>Expected image content ID: <code>{record.subject.expected_image_id}</code></p>}</>}</td>
        <td>{record.source}<br />{time(record.checked_at)}</td>
        <td><Badge tone={record.state === "confirmed" || record.state === "scan_failed" ? "bad" : record.state === "not_affected" ? "info" : "warn"}>{record.state}</Badge>
          {record.error_class && <p>{record.error_class}</p>}
          {record.retry_after_s && <p>Retry delay recorded: {Math.ceil(record.retry_after_s)} s</p>}</td>
        <td><Findings evidence={record} />
          {record.last_success && <details><summary>Historical successful query · {time(record.last_success.checked_at)}</summary><Findings evidence={record.last_success} /><p>This does not establish the current state.</p></details>}
          {Math.max(record.findings_total, record.last_success?.findings_total ?? 0) > (filter.finding_offset ?? 0) + 1 && <button className="secondary" onClick={() => setFilter({ ...filter, subject: record.subject_key, source: record.source, offset: 0, finding_offset: (filter.finding_offset ?? 0) + 1, snapshot_id: data?.snapshot_id ?? undefined })}>Next finding for {record.subject.name}</button>}
        </td>
      </tr>)}</tbody></table>
    {summary?.enabled && data?.records.length === 0 && <p>No stored subjects match this filter. This does not prove complete coverage.</p>}
    <div className="row">
      {(filter.offset ?? 0) > 0 && <button onClick={() => setFilter({ ...filter, offset: 0 })}>First page</button>}
      {data?.next_offset !== null && data?.next_offset !== undefined && <button onClick={() => setFilter({ ...filter, offset: data.next_offset ?? 0, snapshot_id: data.snapshot_id ?? undefined })}>Next subjects</button>}
    </div>
    {data && <p className="muted">Recent scan jobs: {data.jobs.map(job => `${job.state} (${job.attempts}/${job.max_attempts})${job.error ? `: ${job.error}` : ""}`).join(" · ") || "none"}</p>}
  </>;
}
