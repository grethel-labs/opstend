import { type FormEvent, useState } from "react";
import type { PageProps } from "../App";
import { ApiError, type Finding, type Unit, api } from "../api";
import { Badge, Problem, time, useLoad } from "../hooks";
import { Zorec, type ZorecGesture } from "../Zorec";

const TONE: Record<Finding["severity"], "info" | "warn" | "bad"> = {
  info: "info",
  warning: "warn",
  high: "bad",
  critical: "bad",
};

function UnitRow({ unit }: { unit: Unit }) {
  return (
    <tr>
      <td>{unit.unit}</td>
      <td>
        <Badge tone={unit.active === "active" ? "ok" : "bad"}>
          {unit.active}/{unit.sub}
        </Badge>
      </td>
    </tr>
  );
}

const ADVICE_QUESTION_LIMIT = 500;
const ADVICE_GAP = "Advice gap";

function adviceGesture(busy: boolean, result: string, question: string): ZorecGesture {
  if (busy) return "thinking";
  // The advice endpoint returns formatted text with a fixed prefix for gaps.
  if (result.startsWith("Advice gap: the AI budget is exhausted.")) return "limit";
  if (result.startsWith("Advice gap: the provider is unavailable.")) return "offline";
  if (result === ADVICE_GAP || result.startsWith(ADVICE_GAP + ":")) return "missing-data";
  if (result) return "answered";
  return question ? "listening" : "neutral";
}

function Advice({ onAuthLost }: PageProps) {
  const { data } = useLoad(api.advice, onAuthLost);
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState("");
  const trimmedQuestion = question.trim();

  async function ask(event: FormEvent) {
    event.preventDefault();
    if (busy || !trimmedQuestion || trimmedQuestion.length > ADVICE_QUESTION_LIMIT) return;
    setBusy(true);
    setResult("");
    try {
      const answer = await api.askAdvice(trimmedQuestion);
      setResult(typeof answer?.text === "string" && answer.text.trim() ? answer.text : ADVICE_GAP);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) onAuthLost();
      else setResult(ADVICE_GAP);
    } finally {
      setBusy(false);
    }
  }

  if (data?.enabled !== true) return null;

  return (
    <section className="card zorec-panel" aria-labelledby="advice-heading">
      <div className="zorec-heading">
        <Zorec gesture={adviceGesture(busy, result, trimmedQuestion)} />
        <div>
          <h2 id="advice-heading">Ask Zorec</h2>
          <p className="muted">Ask about service health, backups, or vulnerabilities.</p>
        </div>
      </div>
      <form onSubmit={ask}>
        <label htmlFor="advice-question">Advice question</label>
        <div className="zorec-question">
          <input
            id="advice-question"
            type="text"
            maxLength={ADVICE_QUESTION_LIMIT}
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
          />
          <button type="submit" disabled={busy || !trimmedQuestion}>
            {busy ? "Asking…" : "Ask Zorec"}
          </button>
        </div>
      </form>
      <p className="advice-response" role="status">{result}</p>
    </section>
  );
}

export function OverviewPage({ onAuthLost }: PageProps) {
  const loaded = useLoad(() => api.status(), onAuthLost, 15000);
  const snapshot = loaded.data;
  const status = snapshot?.status;

  return (
    <>
      <Problem loaded={loaded} />
      {snapshot && (snapshot.stale || !snapshot.status_ok) && (
        <p className="banner bad" role="alert">
          Observation gap: {snapshot.gap ?? "the controller snapshot is stale or the executor is unavailable"}.
          Values below may be outdated (last snapshot: {time(snapshot.generated_at)}).
        </p>
      )}
      {status && (
        <>
          <section className="tiles" aria-label="Host summary">
            <div className="card">
              <span className="muted">Release</span>
              <strong>{status.release}</strong>
            </div>
            <div className="card">
              <span className="muted">Automation profile</span>
              <strong>{status.automation_profile}</strong>
            </div>
            <div className="card">
              <span className="muted">Firewall</span>
              <span>
                <Badge tone={!status.firewall.managed ? "info" : status.firewall.loaded ? "ok" : "bad"}>
                  {status.firewall.managed ? (status.firewall.loaded ? "loaded" : "NOT LOADED") : "unmanaged"}
                </Badge>
              </span>
            </div>
            <div className="card">
              <span className="muted">Kill switch</span>
              <span>
                <Badge tone={status.kill_switch ? "warn" : "info"}>
                  {status.kill_switch ? "ON – mutations stopped" : "off"}
                </Badge>
              </span>
            </div>
            <div className="card">
              <span className="muted">Memory available</span>
              <strong>
                {status.resources.memory_available_mb} / {status.resources.memory_total_mb} MB
              </strong>
            </div>
            <div className="card">
              <span className="muted">Disk free</span>
              <strong>{Math.round(status.resources.disk_free_mb / 1024)} GB</strong>
            </div>
          </section>

          <h2>Findings</h2>
          {snapshot.findings && snapshot.findings.length === 0 && (
            <p>No findings. Checked {time(snapshot.generated_at)} by the controller.</p>
          )}
          {snapshot.findings && snapshot.findings.length > 0 && (
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Target</th>
                  <th>Finding</th>
                  <th>Automatic handling</th>
                </tr>
              </thead>
              <tbody>
                {snapshot.findings.map((finding) => (
                  <tr key={finding.id}>
                    <td>
                      <Badge tone={TONE[finding.severity]}>{finding.severity}</Badge>
                    </td>
                    <td>{finding.target}</td>
                    <td>{finding.summary}</td>
                    <td>
                      {finding.blocked
                        ? `none: ${finding.blocked}`
                        : finding.remediation
                          ? `requested: ${finding.remediation}`
                          : "none registered"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
      <Advice onAuthLost={onAuthLost} />
      {status && (
        <>
          <h2>Platform services</h2>
          <table>
            <tbody>
              {status.platform_units.map((unit) => (
                <UnitRow key={unit.unit} unit={unit} />
              ))}
              <UnitRow unit={status.proxy} />
            </tbody>
          </table>

          {snapshot.actions && snapshot.actions.length > 0 && (
            <>
              <h2>Controller actions</h2>
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Action</th>
                    <th>Target</th>
                    <th>Outcome</th>
                  </tr>
                </thead>
                <tbody>
                  {[...snapshot.actions].reverse().slice(0, 20).map((entry, index) => (
                    <tr key={index}>
                      <td>{time(entry.ts)}</td>
                      <td>{String(entry.action)}</td>
                      <td>{String(entry.target)}</td>
                      <td>{String(entry.outcome)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </>
      )}
    </>
  );
}
