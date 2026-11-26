import { useMemo } from "react";
import { parseDocument } from "yaml";

type Path = Array<string | number>;

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function ConfigFields({ text, onChange }: { text: string; onChange: (text: string) => void }) {
  const parsed = useMemo(() => {
    if (text.length > 512 * 1024) return null;
    try {
      const document = parseDocument(text, { uniqueKeys: true, logLevel: "silent" });
      if (document.errors.length) return null;
      const data: unknown = document.toJS({ maxAliasCount: 0 });
      if (!object(data) || !object(data.admin) || !object(data.events) || !Array.isArray(data.projects)) return null;
      return { document, data };
    } catch {
      return null;
    }
  }, [text]);

  function update(path: Path, value: unknown) {
    if (!parsed) return;
    const next = parsed.document.clone();
    next.setIn(path, value);
    onChange(next.toString());
  }

  function number(label: string, path: Path, min: number, max: number, step = 1, fallback?: number) {
    const value: unknown = parsed?.document.getIn(path) ?? fallback;
    return (
      <label>
        {label}
        <input
          type="number" min={min} max={max} step={step}
          value={typeof value === "number" && Number.isFinite(value) ? value : ""}
          onChange={event => update(path, event.target.value === "" ? null : event.target.valueAsNumber)}
        />
      </label>
    );
  }

  function checkbox(label: string, path: Path, fallback = false) {
    return (
      <label className="check-field">
        <input type="checkbox" checked={(parsed?.document.getIn(path) ?? fallback) === true}
          onChange={event => update(path, event.target.checked)} />
        {label}
      </label>
    );
  }

  const projects = parsed?.data.projects as unknown[] | undefined;
  return (
    <details className="config-fields card">
      <summary>Form fields</summary>
      <p className="muted">Edit common settings here or use YAML below. Validate and review the changes before saving a revision.</p>
      {!parsed ? <p>Form fields need a valid configuration mapping without YAML aliases. Correct the YAML below first.</p> : (
        <>
          <fieldset>
            <legend>Administration and event history</legend>
            <div className="field-grid">
              {number("Session lifetime (minutes)", ["admin", "session_ttl_minutes"], 5, 1440)}
              {number("Event retention (days)", ["events", "retention_days"], 1, 365)}
              {number("Maximum stored events", ["events", "max_events"], 1000, 5000000)}
            </div>
          </fieldset>
          <fieldset>
            <legend>Vulnerability scans</legend>
            <p className="muted">Enabled providers receive package names, exact versions and image identifiers. Saving a revision takes effect after deployment.</p>
            {checkbox("Enable scheduled vulnerability scans", ["scanning", "enabled"])}
            {checkbox("Query OSV package advisories", ["scanning", "osv"], true)}
            {checkbox("Scan pinned images with Trivy", ["scanning", "trivy"], true)}
            {checkbox("Fetch CISA KEV exploitation context", ["scanning", "kev"])}
            {checkbox("Query FIRST EPSS with CVE identifiers", ["scanning", "epss"])}
            <div className="field-grid">
              {number("Scan interval (seconds)", ["scanning", "interval_s"], 300, 86400, 1, 21600)}
              {number("Scan freshness limit (seconds)", ["scanning", "max_age_s"], 300, 604800, 1, 86400)}
              {number("Maximum OSV requests per scan", ["scanning", "max_requests"], 1, 10000, 1, 1000)}
              {number("Maximum context requests per scan", ["scanning", "context_max_requests"], 1, 1000, 1, 100)}
            </div>
          </fieldset>
          {projects?.map((project, index) => {
            if (!object(project) || typeof project.id !== "string" || !object(project.resources) || !object(project.health) || !object(project.maintenance)) return null;
            const path = ["projects", index];
            return (
              <fieldset key={`${project.id}:${index}`}>
                <legend>{project.id}</legend>
                {checkbox(`${project.id}: manage this project`, [...path, "manage"])}
                {checkbox(`${project.id}: keep service running`, [...path, "deploy"])}
                {checkbox(`${project.id}: allow automatic restart`, [...path, "maintenance", "allow_restart"])}
                <div className="field-grid">
                  {number(`${project.id} memory (MiB)`, [...path, "resources", "memory_mb"], 16, 1048576)}
                  {number(`${project.id} CPU limit`, [...path, "resources", "cpus"], 0.01, 256, 0.01)}
                  {number(`${project.id} process limit`, [...path, "resources", "pids"], 8, 32768)}
                  {number(`${project.id} health interval (seconds)`, [...path, "health", "interval_s"], 5, 3600)}
                  {number(`${project.id} health timeout (seconds)`, [...path, "health", "timeout_s"], 1, 60)}
                  {number(`${project.id} health retries`, [...path, "health", "retries"], 1, 10)}
                </div>
              </fieldset>
            );
          })}
        </>
      )}
    </details>
  );
}
