import { useState, type FormEvent } from "react";
import type { PageProps } from "../App";
import { ApiError, request } from "../api";
import { Badge, Problem, time, useLoad } from "../hooks";

interface ProviderOption {
  id: string;
  label: string;
  auth: string;
  data_class: string;
  available: boolean;
  reason: string;
}

interface AiView {
  status: string;
  provider: { id: string; label: string; runtime_enabled: boolean } | null;
  options: ProviderOption[];
  active: { model: string } | null;
  local_download: { model: string; sha256: string; download_mb: number; ram_mb: number; disk_mb: number } | null;
  scanned: { models: string[] } | null;
  suggested: string | null;
  pinned: string | null;
  auto_selection: boolean;
  requests: Array<{ id: string; kind: string; state: string; result: string }>;
  report: unknown;
  exchange_rate: { status: string; as_of: string | null } | null;
  sources: {
    mode: string;
    list: Array<{
      id: string; url: string; state: string; suspect: boolean; origin: string;
      retrieved_at: number | null; note: string;
    }>;
  };
}

const KEY_REFERENCE = /^(?:env:[A-Za-z_][A-Za-z0-9_]*|file:[^\x00\r\n]+)$/;

function ProviderForm({
  options, saving, onSave, onError,
}: {
  options: ProviderOption[];
  saving: boolean;
  onSave: (body: object) => void;
  onError: (message: string) => void;
}) {
  const [choice, setChoice] = useState("");
  const selected = options.find(option => option.id === choice && option.available);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    const fields = new FormData(event.currentTarget);
    if (selected.auth === "api_key") {
      const keyRef = String(fields.get("key_ref") ?? "");
      if (keyRef.length > 300 || !KEY_REFERENCE.test(keyRef)) {
        onError("Enter an env: or file: key reference.");
        return;
      }
      onSave({ option: selected.id, key_ref: keyRef });
    } else if (selected.id === "ollama-local") {
      onSave({
        option: selected.id,
        local: {
          model: fields.get("model"),
          sha256: fields.get("sha256"),
          download_mb: Number(fields.get("download_mb")),
          ram_mb: Number(fields.get("ram_mb")),
          disk_mb: Number(fields.get("disk_mb")),
          license_ack: fields.has("license_ack"),
        },
      });
    } else {
      onSave({ option: selected.id });
    }
  }

  return (
    <form onSubmit={submit}>
      <fieldset disabled={saving}>
        <legend>Choose a provider</legend>
        {options.map(option => (
          <div key={option.id}>
            <label>
              <input
                type="radio" name="option" value={option.id} checked={choice === option.id}
                disabled={!option.available} onChange={() => { setChoice(option.id); onError(""); }}
              />{" "}
              {option.label}
            </label>
            {!option.available && <span className="muted"> — unavailable ({option.reason})</span>}
          </div>
        ))}
        {selected?.auth === "api_key" && (
          <p key={selected.id}>
            <label>
              API key reference{" "}
              <input name="key_ref" placeholder="env:STEWARD_AI_KEY" autoComplete="off" maxLength={300} required />
            </label>{" "}
            <span className="muted">Enter an env: or file: reference.</span>
          </p>
        )}
        {selected?.id === "ollama-local" && (
          <div>
            <p>Declare the artifact and its requirements. Saving records the declaration.</p>
            <p><label>Model <input name="model" pattern="[A-Za-z0-9][A-Za-z0-9._:\/\-]{0,127}" required /></label></p>
            <p><label>SHA256 <input name="sha256" pattern="[a-f0-9]{64}" required /></label></p>
            <p><label>Download size (MB) <input name="download_mb" type="number" min={1} max={1000000} required /></label></p>
            <p><label>Required RAM (MB) <input name="ram_mb" type="number" min={128} max={1048576} required /></label></p>
            <p><label>Required disk (MB) <input name="disk_mb" type="number" min={1} max={10000000} required /></label></p>
            <p><label><input name="license_ack" type="checkbox" required /> I accept the model license</label></p>
          </div>
        )}
        <button type="submit" disabled={!selected}>Save provider</button>
      </fieldset>
    </form>
  );
}

function idem(): string {
  return crypto.randomUUID();
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>("POST", path, body, { "Idempotency-Key": idem() });
}

export function AiPage({ onAuthLost }: PageProps) {
  const loaded = useLoad<AiView>(() => request("GET", "/api/ai"), onAuthLost, 5000);
  const [message, setMessage] = useState("");
  const [url, setUrl] = useState("");
  const [savingProvider, setSavingProvider] = useState(false);

  async function run(action: () => Promise<unknown>) {
    try {
      const result = await action();
      setMessage("");
      loaded.reload();
      return result;
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthLost();
        return;
      }
      const detail = err instanceof ApiError ? err.detail : undefined;
      if (detail && typeof detail === "object" && "code" in detail && typeof detail.code === "string") {
        const problems = "problems" in detail && Array.isArray(detail.problems) ? detail.problems : [];
        setMessage([detail.code, ...problems.filter(problem => typeof problem === "string")].join(" — "));
      } else {
        setMessage(err instanceof Error ? err.message : "request failed");
      }
    }
  }

  async function saveProvider(body: object) {
    setSavingProvider(true);
    const saved = await run(() => post("/api/ai/provider", body));
    if (!saved) setSavingProvider(false);
  }

  const view = loaded.data;
  const provider = view?.provider;
  const savedOption = view?.options.find(option => option.id === provider?.id);
  const local = provider?.id === "ollama-local" ? view?.local_download : null;
  const choosingInitial = view?.status === "provider_chosen" || view?.status === "scanned";
  const scanQueued = view?.requests.some(item => item.kind === "scan" && ["pending", "running"].includes(item.state));
  return (
    <>
      <p className="muted">AI is optional. Deterministic features run independently.</p>
      <Problem loaded={loaded} />
      {message && <p className="error" role="alert">{message}</p>}
      {view && (
        <>
          <h2>Provider</h2>
          <p>
            Status <Badge tone="info">{view.status}</Badge>{" "}
            {view.provider ? view.provider.label : "no provider chosen"}
          </p>
          {provider ? (
            !provider.runtime_enabled && (
              <p role="status">
                Provider runtime is disabled pending release acceptance.
              </p>
            )
          ) : (
            <ProviderForm options={view.options} saving={savingProvider} onSave={saveProvider} onError={setMessage} />
          )}
          <p>
            {provider?.runtime_enabled ? "Active model" : "Selected model"}: <code>{view.active?.model ?? "–"}</code>{" "}
            {view.pinned ? <Badge tone="warn">pinned</Badge> : null}
          </p>
          <p>
            {savedOption?.available && savedOption.auth === "api_key" && savedOption.data_class === "external" && (
              <button disabled={scanQueued} onClick={() => run(() => post("/api/ai/scan"))}>Queue model scan</button>
            )}{" "}
            <button onClick={() => run(() => post("/api/ai/best-now"))} disabled={!!view.pinned}>
              Pick best now
            </button>{" "}
            <button onClick={() => run(() => post("/api/ai/auto", { enabled: !view.auto_selection }))}>
              Automatic selection: {view.auto_selection ? "on" : "off"}
            </button>{" "}
            {view.pinned && <button onClick={() => run(() => post("/api/ai/unpin"))}>Unpin</button>}
          </p>
          {local && (
            <>
              <p>
                Declared model <code>{local.model}</code>, SHA256 <code>{local.sha256}</code>,
                download {local.download_mb} MB, RAM {local.ram_mb} MB, disk {local.disk_mb} MB.
              </p>
              {choosingInitial && (
                <button onClick={() => run(() => post("/api/ai/initial-model", { model: local.model }))}>
                  Choose declared model
                </button>
              )}
              {view.status === "ready" && !view.pinned && (
                <button onClick={() => run(() => post("/api/ai/pin", { model: local.model }))}>Pin</button>
              )}
              {view.status === "awaiting_download" && (
                <p role="status">Awaiting download and checksum verification. The model is staged for installation.</p>
              )}
            </>
          )}
          {provider && !local && view.scanned && (
            <>
              {view.scanned.models.length === 0 && <p>No models were returned for this provider.</p>}
              <ul>
                {view.scanned.models.map((m: string) => (
                  <li key={m}>
                    <code>{m}</code>{" "}
                    {view.suggested === m && <span className="muted">Suggested model </span>}
                    {choosingInitial ? (
                      <button onClick={() => run(() => post("/api/ai/initial-model", { model: m }))}>
                        Choose {m} as initial model
                      </button>
                    ) : (
                      <button onClick={() => run(() => post("/api/ai/pin", { model: m }))}>Pin</button>
                    )}
                  </li>
                ))}
              </ul>
            </>
          )}
          {view.requests.length > 0 && (
            <>
              <h2>Recent AI requests</h2>
              <ul aria-label="Recent AI requests">
                {view.requests.map(item => (
                  <li key={item.id}>
                    {item.kind} — {item.state === "pending" ? "queued (pending)" : item.state}
                    {item.result && <> — {item.result}</>}
                  </li>
                ))}
              </ul>
            </>
          )}
          <h2>Latest test report</h2>
          {view.report != null ? (
            <pre>{JSON.stringify(view.report, null, 2)}</pre>
          ) : (
            <p>No report yet.</p>
          )}
          <h2>Exchange rate</h2>
          <p>{view.exchange_rate ? `${view.exchange_rate.status} (${view.exchange_rate.as_of ?? "–"})` : "not configured"}</p>
          <h2>Comparison sources</h2>
          <p>
            Mode:{" "}
            <select
              value={view.sources.mode}
              onChange={(e) => run(() => post("/api/ai/source-mode", { mode: e.target.value }))}
            >
              {["propose_confirm", "allowlist", "fixed", "automatic"].map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
          </p>
          <table>
            <thead>
              <tr><th>URL</th><th>State</th><th>Origin</th><th>Retrieved</th><th>Note</th><th /></tr>
            </thead>
            <tbody>
              {view.sources.list.map((s) => (
                <tr key={s.id}>
                  <td>{s.url}</td>
                  <td>{s.state}{s.suspect ? " (suspect)" : ""}</td>
                  <td>{s.origin}</td>
                  <td>{time(s.retrieved_at)}</td>
                  <td>{s.note}</td>
                  <td>
                    {s.state === "proposed" && (
                      <button onClick={() => run(() => post(`/api/ai/sources/${s.id}/decision`, { accept: true }))}>
                        Confirm
                      </button>
                    )}{" "}
                    <button
                      onClick={() =>
                        run(() => request("DELETE", `/api/ai/sources/${s.id}`, undefined, { "Idempotency-Key": idem() }))
                      }
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p>
            <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…" />{" "}
            <button
              onClick={() =>
                run(() => post("/api/ai/sources", { url, parser: "json_comparison_v1" }).then(() => setUrl("")))
              }
            >
              Add source
            </button>
          </p>
        </>
      )}
    </>
  );
}
