import { useCallback, useEffect, useState } from "react";
import { FleetCommandsPanel } from "./FleetCommands";
import type { PageProps } from "../App";
import { api, ApiError, type FleetPolicyApproval, type FleetPolicyHead, type FleetPolicyPlan, type FleetTarget } from "../api";

const revisionPattern = /^[a-f0-9]{64}$/;

function targetKey(target: FleetTarget) {
  return `${target.kind}:${target.id}:${target.generation}`;
}

function Target({ target }: { target: FleetTarget }) {
  return <>{target.kind.replaceAll("_", " ")} <code>{target.id}</code> · generation {target.generation}</>;
}

function PolicyPreview({ plan }: { plan: FleetPolicyPlan }) {
  return (
    <>
      <p>Revision <code>{plan.revision}</code></p>
      <p>Plan digest <code>{plan.digest}</code></p>
      <p>Approval expires <time dateTime={plan.expires_at}>{new Date(plan.expires_at).toLocaleString()}</time>.</p>
      {plan.targets.map(({ target, applied_revision, applied_approval_id, local_revision, observed_at, effective }) => {
        const values = {
          maintenance_windows: effective.values.maintenance_windows,
          role_assignments: effective.values.role_assignments.map(({ subject, role }) => `${subject} (${role})`),
          credential_refs: effective.values.credential_refs,
          backup_profile_refs: effective.values.backup_profile_refs,
        };
        return (
          <details key={targetKey(target)} open>
            <summary><Target target={target} /> · {effective.status}</summary>
            <p>Previously applied fleet revision <code>{applied_revision ?? "none"}</code>
              {applied_approval_id && <> · approval <code>{applied_approval_id}</code></>}
            </p>
            <p>Local safety revision <code>{local_revision ?? "unknown"}</code>
              {observed_at && <> · reported <time dateTime={observed_at}>{new Date(observed_at).toLocaleString()}</time></>}
            </p>
            <dl>
              {(Object.keys(values) as Array<keyof typeof values>).map((field) => (
                <div key={field}>
                  <dt>{field.replaceAll("_", " ")}</dt>
                  <dd>{values[field].join(", ") || "—"}
                    {effective.provenance[field]?.map(({ scope, id }) => (
                      <div className="muted" key={`${scope}:${id}`}>{scope}{id && <> <code>{id}</code></>}</div>
                    ))}
                  </dd>
                </div>
              ))}
            </dl>
            {effective.issues.length > 0 && (
              <ul>{effective.issues.map(({ code, property, scope_ids }) => (
                <li key={`${code}:${property}:${scope_ids.join(",")}`}>
                  {code.replaceAll("_", " ")}{property && ` · ${property.replaceAll("_", " ")}`}
                  {scope_ids.length > 0 && <> · <code>{scope_ids.join(", ")}</code></>}
                </li>
              ))}</ul>
            )}
          </details>
        );
      })}
    </>
  );
}

export function FleetPolicyPage({ onAuthLost }: PageProps) {
  const [head, setHead] = useState<FleetPolicyHead | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [review, setReview] = useState<{ plan: FleetPolicyPlan; key: string } | null>(null);
  const [trackedId, setTrackedId] = useState("");
  const [approval, setApproval] = useState<FleetPolicyApproval | null>(null);
  const [draft, setDraft] = useState("");
  const [draftParent, setDraftParent] = useState<string | null>(null);
  const [earlier, setEarlier] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const loadHead = useCallback(async () => {
    const current = await api.fleetPolicy();
    setHead(current);
  }, []);

  const fail = useCallback((err: unknown) => {
    if (err instanceof ApiError && err.status === 401) {
      onAuthLost();
    } else if (err instanceof ApiError && err.status === 409) {
      setReview(null);
      setError("The fleet head or target evidence changed. Review the current revision again.");
      void loadHead().catch(() => undefined);
    } else {
      setError(err instanceof ApiError ? err.message : "Fleet policy request failed.");
    }
  }, [loadHead, onAuthLost]);

  useEffect(() => { void loadHead().catch(fail); }, [loadHead, fail]);

  const activeId = trackedId || head?.approval_ids[0] || "";
  const loadApproval = useCallback(async () => {
    if (activeId) setApproval(await api.fleetPolicyApproval(activeId));
  }, [activeId]);

  useEffect(() => {
    if (!activeId) return;
    let current = true;
    const poll = () => void api.fleetPolicyApproval(activeId).then(
      (result) => { if (current) setApproval(result); },
      (err: unknown) => { if (current) { setApproval(null); fail(err); } },
    );
    poll();
    const timer = window.setInterval(poll, 5000);
    return () => { current = false; window.clearInterval(timer); };
  }, [activeId, fail]);

  async function run(operation: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await operation();
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  }

  const targets = head?.targets.filter(({ target }) => selected.includes(targetKey(target))) ?? [];
  const outcome = approval?.id === activeId ? approval : null;

  return (
    <>
      {error && <p className="error" role="alert">{error}</p>}
      <section className="card">
        <h2>Current revision</h2>
        <p><code>{head?.head ?? (head ? "No revision staged" : "Loading…")}</code></p>
        <button className="secondary" type="button" disabled={busy}
          onClick={() => void run(async () => { await loadHead(); await loadApproval(); })}>Refresh</button>
        {head && !head.targets.length && <p>No policy targets in your scope.</p>}
        {head?.targets.length ? (
          <fieldset>
            <legend>Targets to review</legend>
            {head.targets.map(({
              target, site_id, group_ids, applied_revision, local_revision, observed_at, conflict_owner, can_write,
            }) => {
              const key = targetKey(target);
              return (
                <div key={key}>
                  <label>
                    <input type="checkbox" checked={selected.includes(key)} disabled={busy} onChange={(event) => {
                      setSelected(event.target.checked ? [...selected, key] : selected.filter((id) => id !== key));
                      setReview(null);
                    }} /> <Target target={target} />
                  </label>
                  <p className="muted">Site <code>{site_id}</code>
                    {group_ids.length > 0 && <> · groups {group_ids.join(", ")}</>}
                    {" · applied "}<code>{applied_revision ?? "none reported"}</code>
                    {!can_write && " · read only"}
                  </p>
                  {observed_at && <p className="muted">
                    Local safety revision <code>{local_revision}</code>
                    {" · reported "}<time dateTime={observed_at}>{new Date(observed_at).toLocaleString()}</time>
                  </p>}
                  {conflict_owner && <p>Local safety conflict · Owned by the local operator</p>}
                </div>
              );
            })}
          </fieldset>
        ) : null}
        <button type="button" disabled={busy || !head?.head || !targets.length}
          onClick={() => void run(async () => {
            if (!head?.head) return;
            setReview(null);
            const plan = await api.previewFleetPolicy(head.head, targets.map(({ target }) => target));
            setReview({ plan, key: crypto.randomUUID() });
          })}>Preview selected targets</button>
      </section>

      {review && (
        <section className="card">
          <h2>Policy preview</h2>
          <PolicyPreview plan={review.plan} />
          <button type="button"
            disabled={busy || review.plan.revision !== head?.head || targets.some(({ can_write }) => !can_write)}
            onClick={() => void run(async () => {
              const result = await api.approveFleetPolicy(review.plan.digest, review.key);
              setTrackedId(result.id);
              setApproval(result);
              setReview(null);
              await loadHead();
            })}>Approve reviewed revision</button>
        </section>
      )}

      {head && (
        <section className="card">
          <h2>Approval outcomes</h2>
          {head.approval_ids.length > 0 ? (
            <>
              <label htmlFor="fleet-approval">Approval</label>
              <select id="fleet-approval" value={activeId} onChange={(event) => setTrackedId(event.target.value)}>
                {head.approval_ids.map((id) => <option key={id} value={id}>{id}</option>)}
              </select>
            </>
          ) : <p>No recorded approvals in your scope.</p>}
          {outcome && (
            <>
              <p>Approved revision <code>{outcome.revision}</code></p>
              <p>Plan digest <code>{outcome.digest}</code></p>
              <table>
                <thead><tr><th>Target</th><th>Outcome</th><th>Reason</th></tr></thead>
                <tbody>{outcome.outcomes.map(({ target, status, reason, conflict_owner }) => (
                  <tr key={targetKey(target)}>
                    <th scope="row"><Target target={target} /></th>
                    <td>{status}</td>
                    <td>{reason?.replaceAll("_", " ") ?? "—"}
                      {conflict_owner && <> · Owned by the local operator</>}
                    </td>
                  </tr>
                ))}</tbody>
              </table>
            </>
          )}
        </section>
      )}

      {head?.can_manage && (
        <section className="card">
          <h2>Stage a revision</h2>
          <button type="button" className="secondary" disabled={busy || !head.head}
            onClick={() => void run(async () => {
              if (!head.head) return;
              const current = await api.fleetPolicyRevision(head.head);
              setDraft(JSON.stringify(current.policy, null, 2));
              setDraftParent(current.id);
            })}>Load current policy</button>
          <label htmlFor="fleet-draft">Fleet policy (JSON)</label>
          <textarea id="fleet-draft" rows={9} value={draft} disabled={busy} onChange={(event) => {
            if (!draft) setDraftParent(head.head);
            setDraft(event.target.value);
          }} />
          {draft && draftParent !== head.head && (
            <p>
              Draft parent <code>{draftParent ?? "none"}</code>.
              <button type="button" className="secondary" disabled={busy}
                onClick={() => setDraftParent(head.head)}>Use current head as parent</button>
            </p>
          )}
          <button type="button" disabled={busy || !draft.trim() || draftParent !== head.head}
            onClick={() => void run(async () => {
              let policy: unknown;
              try { policy = JSON.parse(draft); } catch { policy = null; }
              if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
                setError("Enter a fleet policy JSON object.");
                return;
              }
              const result = await api.stageFleetPolicy(policy as Record<string, unknown>, draftParent);
              setDraftParent(result.id);
              setReview(null);
              await loadHead();
            })}>Stage policy</button>
          <h3>Roll back desired policy</h3>
          <label htmlFor="fleet-rollback">Earlier revision</label>
          <input id="fleet-rollback" value={earlier} disabled={busy} onChange={(event) => setEarlier(event.target.value)} />
          <button type="button" disabled={busy || !head.head || !revisionPattern.test(earlier) || earlier === head.head}
            onClick={() => void run(async () => {
              if (!head.head) return;
              await api.rollbackFleetPolicy(earlier, head.head);
              setEarlier("");
              setReview(null);
              await loadHead();
            })}>Stage rollback revision</button>
        </section>
      )}
      <FleetCommandsPanel onAuthLost={onAuthLost} />
    </>
  );
}
