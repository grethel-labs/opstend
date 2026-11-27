(function () {
  "use strict";

  const modeKey = "opstend-rc2-autonomy-enabled-v1";
  const journalKey = "opstend-rc2-autonomy-journal-v1";
  const policyRevision = 2;
  const changed = "opstend:autonomy-changed";
  const announce = () => window.dispatchEvent(new CustomEvent(changed));
  let queued = false;

  function enabled() {
    try {
      return localStorage.getItem(modeKey) === "1";
    } catch {
      return false;
    }
  }

  function recorded() {
    try {
      const runs = JSON.parse(localStorage.getItem(journalKey));
      return Array.isArray(runs) ? runs.filter((run) => typeof run?.id === "string" && ["review", "blocked"].includes(run.outcome)) : [];
    } catch {
      return [];
    }
  }

  function eligible() {
    const profile = window.opstendZorecPolicy.get()["admin-edit"];
    return profile.enabled && profile.automation && ["operate", "full"].includes(profile.access);
  }

  function effective() {
    return enabled() && eligible();
  }

  function setEnabled(value) {
    if (value && !eligible()) return { ok: false, error: [
      "Aktiviere Admin Edit mit Schreibumfang für Betriebsaktionen und Freigabe für KI-Automationen.",
      "Enable Admin Edit with operations access and permission for AI automations.",
    ] };
    try {
      localStorage.setItem(modeKey, value ? "1" : "0");
    } catch {
      return { ok: false, error: ["Der Browser konnte den Modus nicht speichern.", "The browser could not save the mode."] };
    }
    announce();
    schedule();
    return { ok: true };
  }

  const jobText = (text) => [text, window.opstendViews.englishJobText(text) || text];

  function maintenanceContext(record, history) {
    const affected = record.workloads.filter(({ handling }) => handling === "restart").map(({ name }) => name);
    const targets = affected.join(", ");
    const previous = history?.length ? [history.map(([de]) => de).join(", "), history.map(([, en]) => en).join(", ")] : null;
    return {
      jobId: record.id, host: record.host, title: [`Hostwartung · ${record.host}`, `Host maintenance · ${record.host}`],
      context: previous ? [`Neustart mit bestätigter Unterbrechung. Zuletzt am Host geprüft wurden ${previous[0]}.`,
        `Restart with acknowledged interruption. Previous host events reviewed include ${previous[1]}.`]
        : ["Neustart mit bestätigter Unterbrechung. Für den Host liegen keine früheren Ereignisse vor.",
          "Restart with acknowledged interruption. No earlier events are available for this host."],
      impact: affected.length ? [`Lokaler Wiederanlauf: ${targets}.`, `Local restart: ${targets}.`]
        : ["Kein laufender Gast oder Dienst betroffen.", "No running guest or service is affected."],
    };
  }

  function approvals() {
    return window.opstendHostMaintenance.records().flatMap((record) => {
      const event = record.events.find(({ action, actor }) => action === "approve" && actor === "zorec");
      if (!event) return [];
      return [{ ...maintenanceContext(record, event.history), id: `${record.id}:approved`, at: event.at, outcome: "approved",
        reason: ["Demo-Regel für freigegebene Hostwartung erfüllt. Inventar und Wartungsfenster erneut geprüft.",
          "Demo policy for host maintenance approval passed. Inventory and the maintenance window were rechecked."],
        ...(record.stage !== "rejected" ? { notice: { startAt: record.window.startAt, endAt: record.window.endAt } } : {}),
      }];
    });
  }

  function recoveryContext(service) {
    return {
      jobId: "sensorik", host: service.host, title: ["Sensorik erneut prüfen", "Recheck Sensorik"],
      context: ["Der Neustart wurde protokolliert. Die anschließende Health-Nachprüfung ist fehlgeschlagen.",
        "The restart was recorded. The follow-up health check failed."],
      impact: ["Die Nachprüfung liest den Health-Zustand des laufenden Dienstes.", "The recheck reads health evidence from the running service."],
      source: ["Registrierter Health-Pfad von Sensorik · simulierte Prüfung", "Sensorik's registered health endpoint · simulated check"],
    };
  }

  function recoveryDecisions(snapshot) {
    const demo = window.opstendDemo;
    const service = snapshot.services.find(({ id }) => id === "sensorik");
    const recovery = demo.recoveryFor(service);
    const events = recovery?.events ?? [];
    return events.flatMap((event, index) => {
      if (event.action !== "retry" || event.actor !== "zorec") return [];
      const after = events[index + 1]?.action;
      const readback = after === "probe-pass" ? ["Die simulierte Prüfung war erfolgreich.", "The simulated check passed."]
        : after === "probe-fail" ? ["Die simulierte Prüfung ist fehlgeschlagen.", "The simulated check failed."]
          : recovery.phase === "historical" ? ["Für das frühere Ziel liegt kein Ergebnis vor.", "No result was recorded for the previous target."]
            : ["Das simulierte Ergebnis steht aus.", "The simulated result is pending."];
      return [{ ...recoveryContext(service), id: `sensorik:retry:${event.at}`, at: event.at, outcome: "started", readback,
        reason: ["Die Demo-Regel erlaubt eine zusätzliche Health-Prüfung pro Vorfall. Zorec hat sie angestoßen.",
          "The demo policy allows one additional health check per incident. Zorec requested it."],
      }];
    });
  }

  function get() {
    const snapshot = window.opstendDemo.getInventory();
    return { enabled: enabled(),
      runs: [...recorded(), ...recoveryDecisions(snapshot), ...approvals()].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)) };
  }

  function reviewContext(job) {
    const last = job.events.filter(([time]) => !["Ausstehend", "Läuft"].includes(time)).at(-1);
    return { jobId: job.id, host: job.host, title: jobText(job.title),
      context: jobText(last?.[2] || job.context || job.attention.status),
      impact: jobText(job.attention.impact),
      source: last ? jobText(last[1]) : undefined,
      reason: job.id === "route" ? [
        "Die Veröffentlichung ändert den Zugriff von außen. Für diese Reichweite verlangt die Demo eine Betreiberfreigabe.",
        "Publishing changes external access. The demo requires operator approval for this exposure.",
      ] : ["Für diesen Auftrag ist in der Demo keine automatische Freigabe hinterlegt. Er bleibt unter Anstehende Entscheidungen sichtbar.",
        "This job has no automatic approval policy in the demo. It remains visible under Pending decisions."],
    };
  }

  async function reviewRecovery(job, service, id, at) {
    const demo = window.opstendDemo;
    const proposal = demo.recoveryAutonomy(service);
    const context = service ? recoveryContext(service) : reviewContext(job);
    if (!proposal.ok) return { ...context, id, at, outcome: "blocked", reason: proposal.reason,
      readback: jobText(job.verification) };
    const result = await demo.advanceRecovery(job.serviceId, "retry", job.recovery.revision, { actor: "zorec" });
    if (result === true || !effective()) return null;
    const snapshot = demo.getInventory({ fresh: true });
    const current = demo.recoveryFor(snapshot.services.find(({ id }) => id === job.serviceId));
    if (current?.phase !== "failed" || current.revision !== job.recovery.revision) return null;
    return { ...context, id, at, outcome: "blocked", reason: jobText(result) };
  }

  async function inspectQueue() {
    if (!effective()) return;
    const state = { host: "", inventory: window.opstendDemo.getInventory({ fresh: true }) };
    const maintenance = window.opstendHostMaintenance;
    const pending = new Map(maintenance.records(state).filter(({ stage }) => stage === "pending").map((record) => [record.id, record]));
    const decisions = window.opstendViews.attention(state).filter(({ attention }) => attention.kind === "decision");
    const seen = new Set(recorded().map(({ id }) => id));
    const runs = [];
    for (const job of decisions) {
      if (!effective()) break;
      const record = pending.get(job.id);
      const sensorik = job.id === "sensorik" && job.recovery?.phase === "failed";
      const service = sensorik ? state.inventory.services.find(({ id }) => id === job.serviceId) : null;
      const binding = service ? [service.id, service.host, service.ip, service.power] : null;
      const id = JSON.stringify([job.id, record?.revision ?? job.revision ?? job.recovery?.revision ?? 0, policyRevision, binding]);
      if (seen.has(id)) continue;
      seen.add(id);
      const at = new Date().toISOString();
      if (record) {
        const previous = window.opstendViews.eventsForScope({ ...state, host: record.host })
          .filter((entry) => entry.jobId !== record.id).slice(0, 3);
        const history = previous.map(({ title }) => [title, window.opstendViews.englishJobText(title) || title]);
        const result = await maintenance.advance(state, record.id, "approve", record.revision, { actor: "zorec", history });
        if (!result.ok && effective() && maintenance.latest(state, record.host)?.stage === "pending") {
          runs.push({ ...maintenanceContext(record, history), id, at, outcome: "blocked", reason: [result.error, result.errorEn || result.error] });
        }
      } else if (sensorik) {
        const review = await reviewRecovery(job, service, id, at);
        if (review) runs.push(review);
      } else {
        runs.push({ ...reviewContext(job), id, at, outcome: "review" });
      }
    }
    if (!runs.length) return;
    try {
      localStorage.setItem(journalKey, JSON.stringify([...runs, ...recorded()].slice(0, 100)));
    } catch { return; }
    announce();
  }

  function schedule() {
    if (queued || !effective()) return;
    queued = true;
    setTimeout(async () => {
      queued = false;
      if (navigator.locks) await navigator.locks.request(journalKey, inspectQueue);
      else await inspectQueue();
    }, 0);
  }

  window.addEventListener("storage", (event) => {
    if ([modeKey, journalKey, null].includes(event.key)) announce();
  });
  window.addEventListener("opstend:zorec-policy-changed", () => {
    announce();
    schedule();
  });
  function decisionFor(jobId, host) {
    return get().runs.find((run) => run.jobId === jobId && run.host === host) ?? null;
  }

  window.opstendAutonomy = { get, decisionFor, eligible, effective, setEnabled, schedule };
})();
