import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api, type FleetCommand, type FleetCommands } from "../api";

const STATUS: Record<FleetCommand["state"], string> = {
  preparing: "Waiting for the target to prepare a preview",
  review: "Ready for approval",
  queued: "Approved · waiting for the target",
  released: "Waiting for native execution evidence",
  accepted: "Native task accepted · awaiting readback",
  uncertain: "Native outcome uncertain",
  succeeded: "Start verified",
  failed: "Start failed",
  refused: "Command refused",
  expired: "Approval expired",
};

function guestLabel(guest: { name: string | null; kind: string; vmid: number; node: string }) {
  const kind = guest.kind === "qemu" ? "VM" : "LXC";
  return `${guest.name ? `${guest.name} · ` : ""}${kind} ${guest.vmid} on ${guest.node}`;
}

export function FleetCommandsPanel({ onAuthLost }: { onAuthLost: () => void }) {
  const [catalog, setCatalog] = useState<FleetCommands | null>(null);
  const [selected, setSelected] = useState("");
  const [trackedId, setTrackedId] = useState("");
  const [tracked, setTracked] = useState<FleetCommand | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const previewKey = useRef("");
  const approvalKey = useRef("");
  const readVersion = useRef(0);

  const fail = useCallback((err: unknown) => {
    if (err instanceof ApiError && err.status === 401) onAuthLost();
    else setError(err instanceof Error ? err.message : "Fleet command request failed.");
  }, [onAuthLost]);

  const load = useCallback(async () => {
    setCatalog(await api.fleetCommands());
  }, []);

  useEffect(() => { void load().catch(fail); }, [load, fail]);

  const activeId = trackedId || catalog?.commands[0]?.command_id || "";
  const command = tracked?.command_id === activeId
    ? tracked
    : catalog?.commands.find(({ command_id }) => command_id === activeId);

  useEffect(() => {
    if (!activeId) return;
    let mounted = true;
    let polling = false;
    const poll = async () => {
      if (polling) return;
      polling = true;
      const version = readVersion.current;
      try {
        const result = await api.fleetCommand(activeId);
        if (mounted && version === readVersion.current) setTracked(result);
      } catch (err) {
        if (!mounted || version !== readVersion.current) return;
        if (err instanceof ApiError && (err.status === 403 || err.status === 404)) {
          setTracked(null);
          setTrackedId("");
          setCatalog((current) => current && {
            ...current, commands: current.commands.filter(({ command_id }) => command_id !== activeId),
          });
        }
        fail(err);
      } finally {
        polling = false;
      }
    };
    void poll();
    const timer = window.setInterval(() => { void poll(); }, 2500);
    return () => { mounted = false; window.clearInterval(timer); };
  }, [activeId, fail]);

  function showCommand(result: FleetCommand) {
    readVersion.current += 1;
    setTrackedId(result.command_id);
    setTracked(result);
    setCatalog((current) => current && {
      ...current,
      commands: [result, ...current.commands.filter(({ command_id }) => command_id !== result.command_id)],
    });
  }

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

  const guest = catalog?.targets.find(({ target }) => target.id === selected);
  return (
    <section className="card" aria-labelledby="fleet-commands-title">
      <h2 id="fleet-commands-title">Guest power</h2>
      {error && <p className="error" role="alert">{error}</p>}
      <button type="button" className="secondary" disabled={busy}
        onClick={() => void run(load)}>Refresh guests</button>
      {catalog && catalog.targets.length === 0 && <p>No registered guests with start permission.</p>}
      {catalog && catalog.targets.length > 0 && <>
        <label htmlFor="fleet-power-guest">Guest to start</label>
        <select id="fleet-power-guest" value={selected} disabled={busy} onChange={(event) => {
          setSelected(event.target.value);
          previewKey.current = "";
        }}>
          <option value="">Select a guest</option>
          {catalog.targets.map((target) => (
            <option key={target.target.id} value={target.target.id}>
              {guestLabel(target)} · instance {target.instance_id.slice(0, 8)}
            </option>
          ))}
        </select>
        <button type="button" disabled={busy || !guest} onClick={() => void run(async () => {
          if (!guest) return;
          previewKey.current ||= crypto.randomUUID();
          const result = await api.previewFleetCommand(guest.target, guest.policy_revision, previewKey.current);
          previewKey.current = "";
          approvalKey.current = "";
          showCommand(result);
        })}>Preview guest start</button>
      </>}
      {catalog && catalog.commands.length > 0 && <>
        <label htmlFor="fleet-power-command">Guest command</label>
        <select id="fleet-power-command" value={activeId} disabled={busy} onChange={(event) => {
          setTrackedId(event.target.value);
          approvalKey.current = "";
        }}>
          {catalog.commands.map((entry) => (
            <option key={entry.command_id} value={entry.command_id}>
              {guestLabel(entry)} · {entry.command_id.slice(0, 8)}
            </option>
          ))}
        </select>
      </>}
      {command && <>
        <h3>{guestLabel(command)}</h3>
        <p role="status">{STATUS[command.state]}</p>
        <dl>
          <dt>Command</dt><dd><code>{command.command_id}</code></dd>
          <dt>Instance</dt><dd><code>{command.instance_id}</code></dd>
          <dt>Guest generation</dt><dd>{command.target.generation}</dd>
          <dt>Requested by</dt><dd>{command.subject} · {command.role}</dd>
          <dt>Applied fleet revision</dt><dd><code>{command.policy_revision}</code></dd>
          <dt>Expires</dt>
          <dd><time dateTime={command.expires_at}>{new Date(command.expires_at).toLocaleString()}</time></dd>
          {command.observed_state && <><dt>Observed power state</dt><dd>{command.observed_state}</dd></>}
          {command.reason && <><dt>Reason</dt><dd>{command.reason.replaceAll("_", " ")}</dd></>}
          {command.task_ref && <><dt>Native task reference</dt><dd><code>{command.task_ref}</code></dd></>}
        </dl>
        {command.state === "review" && command.digest && <>
          <p>Reviewed plan <code>{command.digest}</code></p>
          <button type="button" disabled={busy} onClick={() => void run(async () => {
            if (!command.digest) return;
            approvalKey.current ||= crypto.randomUUID();
            showCommand(await api.approveFleetCommand(command.command_id, command.digest, approvalKey.current));
            approvalKey.current = "";
          })}>Approve guest start</button>
        </>}
      </>}
    </section>
  );
}
