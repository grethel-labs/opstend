import { useEffect, useRef, useState } from "react";
import type { PageProps } from "../App";
import { ApiError, api, type ApplyPlanResponse, type ConfigApplyJob, type ConfigResponse, type DiffEntry } from "../api";
import { Badge, short, time } from "../hooks";
import { ConfigFields } from "./ConfigFields";

function show(value: unknown): string {
  return value === undefined ? "–" : JSON.stringify(value);
}

interface Snapshot {
  config: ConfigResponse;
  apply: ApplyPlanResponse;
  revisions: Awaited<ReturnType<typeof api.revisions>>;
}

interface Draft {
  text: string;
  parent: string | null;
  saved?: boolean;
}

function isActive(job: ConfigApplyJob): boolean {
  return job.state === "queued" || job.state === "running";
}

export function ConfigPage({ onAuthLost }: PageProps) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [readError, setReadError] = useState("");
  const [refreshing, setRefreshing] = useState(true);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [message, setMessage] = useState("");
  const [diff, setDiff] = useState<DiffEntry[] | null>(null);
  const [problems, setProblems] = useState<string[]>([]);
  const [notice, setNotice] = useState("");
  const [refreshCount, setRefreshCount] = useState(0);
  const [submitted, setSubmitted] = useState<ConfigApplyJob | null>(null);
  const mutation = useRef(false);
  const readVersion = useRef(0);
  const validation = useRef(0);

  useEffect(() => {
    const version = ++readVersion.current;
    let timer: number | undefined;

    async function refresh() {
      try {
        // Refresh the pointers after reading the durable outcome.
        const apply = await api.applyPlan(submitted?.id);
        if (version !== readVersion.current) return;
        const [config, revisions] = await Promise.all([api.config(), api.revisions()]);
        if (version !== readVersion.current) return;
        if ((!apply.plan || (apply.plan.head === apply.head && apply.plan.applied === apply.applied)) &&
            apply.head === config.head && apply.applied === config.applied &&
            revisions.head === config.head && revisions.applied === config.applied) {
          setSnapshot({ apply, config, revisions });
          setDraft(current => current?.saved ? null : current);
          setReadError("");
          setRefreshing(false);
          const tracked = apply.tracked_job;
          if (!apply.jobs.some(isActive) && (!submitted || (tracked && !isActive(tracked)))) return;
        }
      } catch (err) {
        if (version !== readVersion.current) return;
        if (err instanceof ApiError && err.status === 401) return onAuthLost();
        setReadError(err instanceof Error ? err.message : "request failed");
      }
      timer = window.setTimeout(refresh, 1000);
    }

    void refresh();
    return () => {
      ++readVersion.current;
      window.clearTimeout(timer);
    };
  }, [refreshCount, submitted, onAuthLost]);

  const config = snapshot?.config;
  const text = draft?.text ?? config?.yaml ?? "";
  const parent = draft ? draft.parent : config?.head ?? null;
  const stale = !refreshing && !!config && parent !== config.head;

  function edit(value: string) {
    ++validation.current;
    setDraft({ text: value, parent });
    setDiff(null);
    setNotice("");
  }

  function loadLatest() {
    ++validation.current;
    setDraft(null);
    setDiff(null);
    setProblems([]);
  }

  function fail(err: unknown) {
    setDiff(null);
    if (err instanceof ApiError && err.status === 401) return onAuthLost();
    if (err instanceof ApiError && err.status === 409) {
      const detail = err.detail as { message?: string } | undefined;
      setProblems([`Conflict: ${detail?.message ?? "the configuration changed elsewhere"}. Review the latest revision.`]);
    } else if (err instanceof ApiError && err.status === 422) {
      const detail = err.detail as { problems?: string[] } | undefined;
      setProblems(detail?.problems ?? [err.message]);
    } else setProblems([err instanceof Error ? err.message : "request failed"]);
  }

  async function validate() {
    const version = ++validation.current;
    setDraft(draft ?? { text, parent });
    setNotice("");
    setProblems([]);
    setDiff(null);
    try {
      const result = await api.validate(text);
      if (version === validation.current) setDiff(result.diff);
    } catch (err) {
      if (version === validation.current) fail(err);
    }
  }

  async function mutate(action: () => Promise<void>) {
    if (mutation.current) return;
    mutation.current = true;
    ++readVersion.current;
    ++validation.current;
    setRefreshing(true);
    setNotice("");
    setProblems([]);
    try {
      await action();
    } catch (err) {
      fail(err);
    } finally {
      mutation.current = false;
      setRefreshCount(count => count + 1);
    }
  }

  function commit() {
    return mutate(async () => {
      const result = await api.commit(text, parent, message);
      setNotice(
        result.pending
          ? `Saved revision ${result.revision}. It is pending: run "./opstend config pull" and "./opstend deploy" on the controller to apply it.`
          : `Revision ${result.revision} equals the applied configuration.`,
      );
      setDraft(current => current === draft
        ? { text, parent: result.revision, saved: true }
        : current && { ...current, parent: result.revision });
      setMessage(current => current === message ? "" : current);
      setDiff(null);
    });
  }

  const plan = snapshot?.apply.plan;
  const jobs = snapshot?.apply.jobs ?? [];
  const tracked = snapshot?.apply.tracked_job;
  const ownOutcome = tracked && tracked.id === submitted?.id ? tracked : submitted;
  const lastApply = ownOutcome ?? jobs.find(isActive) ?? jobs[0];
  const applying = jobs.some(isActive) || (ownOutcome !== null && isActive(ownOutcome));

  function applyPending(head: string, applied: string) {
    if (applying) return;
    return mutate(async () => {
      setSubmitted(await api.applyConfig(head, applied));
    });
  }

  return (
    <>
      {readError && <p className="error" role="alert">{readError}</p>}
      {!snapshot && !readError && <p className="muted">Loading…</p>}
      {config && (
        <p>
          Head <code>{config.head ?? "–"}</code> · applied <code>{config.applied ?? "–"}</code>{" "}
          {config.pending ? <Badge tone="warn">pending deployment</Badge> : <Badge tone="ok">in sync</Badge>}
        </p>
      )}
      {plan && (
        <section aria-label="Apply pending revision">
          <h2>Apply pending revision</h2>
          <p>
            Head <code>{plan.head}</code> · base applied <code>{plan.applied}</code> · release{" "}
            <code>{snapshot.apply.release}</code>
          </p>
          <p>Areas {plan.areas.join(", ") || "–"} · operations {plan.operations.join(", ") || "–"}</p>
          {plan.supported ? (
            <button disabled={refreshing || applying || !!readError} onClick={() => applyPending(plan.head, plan.applied)}>
              Apply on server
            </button>
          ) : (
            <p>This revision needs <code>./opstend deploy</code> ({plan.reason}).</p>
          )}
        </section>
      )}
      {lastApply && (
        <section aria-label="Apply outcome" aria-live="polite">
          <h2>Apply outcome</h2>
          <p>
            <Badge tone={lastApply.state === "succeeded" ? "ok" : lastApply.state === "failed" ? "bad" : "warn"}>
              {lastApply.state}
            </Badge>{" "}
            <code>{lastApply.payload.head}</code>
          </p>
          {lastApply.error && <p>{lastApply.error}</p>}
        </section>
      )}
      {(plan || lastApply) && (
        <p className="muted">
          On the controller, run <code>./opstend config pull</code> to adopt the server head.
          To apply a pending revision from the controller, pull it and run <code>./opstend deploy</code>.
        </p>
      )}
      <p className="muted">
        This is the effective configuration including all defaults. Secrets appear only as references. The
        deployment target (<code>server</code>) can only be changed from the controller.
      </p>
      <ConfigFields text={text} onChange={edit} />
      <label htmlFor="yaml">Configuration (YAML)</label>
      <textarea id="yaml" spellCheck={false} value={text} disabled={!config} onChange={e => edit(e.target.value)} />
      {problems.length > 0 && (
        <ul className="banner bad" role="alert">
          {problems.map((problem) => (
            <li key={problem}>{problem}</li>
          ))}
        </ul>
      )}
      {stale && (
        <p>
          Your draft is based on <code>{parent ?? "–"}</code>. Copy any edits you want to keep before replacing it
          with the latest YAML. Your change note will be kept.{" "}
          <button className="secondary" onClick={loadLatest}>Load latest YAML</button>
        </p>
      )}
      {notice && <p className="banner info" role="status">{notice}</p>}
      {diff && (
        <>
          <h2>Changes against head</h2>
          {diff.length === 0 ? (
            <p>No changes.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Path</th>
                  <th>Change</th>
                  <th>Old</th>
                  <th>New</th>
                </tr>
              </thead>
              <tbody>
                {diff.map((entry) => (
                  <tr key={entry.path}>
                    <td><code>{entry.path}</code></td>
                    <td>{entry.change}</td>
                    <td><code>{show(entry.old)}</code></td>
                    <td><code>{show(entry.new)}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
      <div className="row">
        <button className="secondary" onClick={validate} disabled={refreshing || stale}>Validate and show diff</button>
        <input
          aria-label="Change note"
          placeholder="Change note"
          maxLength={500}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
        />
        <button onClick={commit} disabled={refreshing || stale || !diff || diff.length === 0}>Save revision</button>
      </div>

      <h2>Revisions</h2>
      <table>
        <thead>
          <tr>
            <th>Revision</th>
            <th>Created</th>
            <th>Source</th>
            <th>Author</th>
            <th>Note</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {snapshot?.revisions.revisions.map((rev) => (
            <tr key={rev.id}>
              <td><code>{short(rev.id)}</code></td>
              <td>{time(rev.created_at)}</td>
              <td>{rev.source}</td>
              <td>{rev.author}</td>
              <td>{rev.message}</td>
              <td>
                {rev.id === snapshot?.revisions.head && <Badge tone="info">head</Badge>}{" "}
                {rev.id === snapshot?.revisions.applied && <Badge tone="ok">applied</Badge>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
