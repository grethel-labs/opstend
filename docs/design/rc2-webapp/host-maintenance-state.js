(function () {
  "use strict";

  const storageKey = "opstend-rc2-host-maintenance-v1";
  const changedEvent = "opstend:host-maintenance-changed";
  const fixtureTime = Date.parse("2026-11-27T13:21:00Z");
  const berlin = "Europe/Berlin";
  const berlinDate = new Intl.DateTimeFormat("en-CA", { timeZone: berlin, year: "numeric", month: "numeric", day: "numeric" });
  const berlinOffset = new Intl.DateTimeFormat("en", { timeZone: berlin, timeZoneName: "longOffset" });
  const terminal = new Set(["rejected", "finished"]);
  const unavailable = new Set(["Ausgefallen", "Nicht erreichbar", "Offline", "Wartung"]);
  const unknown = new Set(["Vorgemerkt", "Ausgefallen", "Offline", "Unbekannt"]);
  const stopped = new Set(["Stillgelegt", "Entfernung vorgemerkt", "Gestoppt"]);
  const running = new Set(["Gesund", "Warnung", "Health offen", "Wird geprüft", "Läuft"]);
  const transitions = {
    approve: { from: ["pending"], to: "approved" },
    reject: { from: ["pending", "approved"], to: "rejected" },
    start: { from: ["approved"], to: "active" },
    finish: { from: ["active"], to: "finished" },
  };
  const history = {
    pending: ["request"], approved: ["request", "approve"], rejected: ["request", "reject"],
    active: ["request", "approve", "start"], finished: ["request", "approve", "start", "finish"],
  };

  const fail = (error, errorEn) => ({ ok: false, error, errorEn });
  const announce = () => window.dispatchEvent(new CustomEvent(changedEvent));
  const inScope = (state, hostId) => !state?.host || state.host === hostId;
  const same = (value, baseline) => JSON.stringify(value) === JSON.stringify(baseline);

  function berlinHour(day, hour) {
    const utc = day + hour * 3_600_000;
    const offset = berlinOffset.formatToParts(utc).find(({ type }) => type === "timeZoneName").value;
    const [, sign, hours, minutes] = offset.match(/^GMT([+-])(\d{2}):(\d{2})$/);
    return utc - (sign === "-" ? -1 : 1) * (Number(hours) * 60 + Number(minutes)) * 60_000;
  }

  function windowFor(hostId) {
    const override = hostId === "edge-01";
    const firstHour = override ? 4 : 3;
    const asOf = window.opstendMonitoringData?.asOf ?? fixtureTime;
    const local = Object.fromEntries(berlinDate.formatToParts(asOf).map(({ type, value }) => [type, value]));
    const today = Date.UTC(Number(local.year), Number(local.month) - 1, Number(local.day));
    let sunday = today + ((7 - new Date(today).getUTCDay()) % 7) * 86_400_000;
    if (berlinHour(sunday, firstHour) <= asOf) sunday += 7 * 86_400_000;
    const hours = `0${firstHour}:00–05:00`;
    return {
      label: `Sonntag, ${hours}`, labelEn: `Sunday, ${hours}`, timezone: berlin,
      source: override ? "Host-Ausnahme" : "Flottenvorgabe", sourceEn: override ? "Host override" : "Fleet default",
      startAt: new Date(berlinHour(sunday, firstHour)).toISOString(), endAt: new Date(berlinHour(sunday, 5)).toISOString(),
    };
  }

  function validRecord(record) {
    const events = record?.stage === "rejected" && record.events?.length === 3 ? ["request", "approve", "reject"]
      : record && Object.hasOwn(history, record.stage) ? history[record.stage] : null;
    return events && typeof record.id === "string" && record.id.startsWith("host-maintenance-")
      && typeof record.host === "string" && record.host.length > 0
      && Array.isArray(record.events) && events.length === record.events.length && record.revision === events.length - 1
      && record.events.every((event, index) => event?.action === events[index] && Number.isFinite(Date.parse(event.at))
        && (event.actor === undefined || (event.actor === "zorec" && event.action === "approve")))
      && Date.parse(record.window?.startAt) < Date.parse(record.window?.endAt)
      && ["label", "labelEn", "source", "sourceEn"].every((key) => typeof record.window[key] === "string")
      && Array.isArray(record.workloads) && record.workloads.every((item) => item && ["restart", "leave-stopped"].includes(item.handling)
        && ["id", "name", "kind", "reason", "reasonEn"].every((key) => typeof item[key] === "string"))
      && Array.isArray(record.binding?.host) && record.binding.host[0] === record.host
      && Array.isArray(record.binding.workloads) && record.binding.workloads.length === record.workloads.length
      && record.binding.workloads.every((item, index) => Array.isArray(item) && item[0] === record.workloads[index].id);
  }

  function readJournal() {
    try {
      const records = JSON.parse(localStorage.getItem(storageKey) ?? "[]");
      return Array.isArray(records) && records.every(validRecord)
        && new Set(records.map(({ id }) => id)).size === records.length ? records : null;
    } catch {
      return null;
    }
  }

  function saveJournal(records, record) {
    try {
      localStorage.setItem(storageKey, JSON.stringify(records));
    } catch {
      return fail("Der Browser konnte das Wartungsprotokoll nicht speichern.", "The browser could not save the maintenance journal.");
    }
    announce();
    return { ok: true, record };
  }

  const journalUnavailable = () => fail("Das Wartungsprotokoll ist nicht verfügbar.", "The maintenance journal is unavailable.");

  function hostBinding(host) {
    return [host.id, host.name, host.ip, host.site, host.type, host.runtime].map((value) => value ?? null);
  }

  function workloadBinding(snapshot, service) {
    if (service.maintenanceState === "restart-check" && Array.isArray(service.maintenanceBaseline)) return service.maintenanceBaseline;
    const lastRuntime = snapshot.changes?.find(({ kind, serviceId }) => kind === "runtime" && serviceId === service.id);
    return [service.id, service.host, service.name, service.kind, service.ip, service.status, service.power,
      service.sourceHost, service.managed, service.mode, service.group, service.instance, service.gpu, service.passthrough,
      service.recovery?.revision, service.provisioning?.readbackAt, lastRuntime?.id].map((value) => value ?? null);
  }

  function runtime(service) {
    if (unknown.has(service.status)) return "unknown";
    if (stopped.has(service.status) || service.power === "stopped") return "stopped";
    if (service.power === "running" || (service.power == null && running.has(service.status))) return "running";
    return "unknown";
  }

  function impact(service, snapshot) {
    const { id, name, kind } = service;
    const entry = (handling, reason, reasonEn) => ({ id, name, kind, handling, reason, reasonEn });
    const hardware = id === "medien" ? ["GPU mit HDMI und USB-Gerät", "GPU with HDMI and USB device"]
      : service.gpu ? ["gebundene GPU", "attached GPU"] : null;
    if (window.opstendDemo.pendingRuntime(service.id, snapshot)) {
      return entry("blocked", "Für diese Instanz ist ein Laufzeitauftrag offen.", "This workload has an open runtime job.");
    }
    const recovery = window.opstendDemo?.recoveryFor?.(service);
    if (service.status === "Wird geprüft" || ["pending", "failed"].includes(recovery?.phase)) {
      return entry("blocked", "Die Wiederanlaufprüfung dieses Dienstes ist offen.", "This workload has an unresolved recovery check.");
    }
    const power = runtime(service);
    if (power === "unknown") return entry("blocked", "Der Laufzustand ist unbekannt.", "The runtime state is unknown.");
    if (power === "stopped") return entry("leave-stopped",
      hardware ? `Bleibt gestoppt. Am Quellhost: ${hardware[0]}.` : "Der bisherige Stopp bleibt bestehen.",
      hardware ? `Remains stopped. Attached to the source host: ${hardware[1]}.` : "The workload remains stopped.");
    if (service.managed === false || ["local", "observed", "excluded"].includes(service.mode)) {
      return entry("blocked", "Der laufende Dienst wird außerhalb von OpsTend verwaltet.", "The running workload is managed outside OpsTend.");
    }
    if (hardware) return entry("restart", `Lokaler Neustart. Am Quellhost: ${hardware[0]}.`,
      `Local restart. Attached to the source host: ${hardware[1]}.`);
    if (service.group) return entry("restart", "Lokaler Neustart der Instanz. Der Zustand der Dienstgruppe bleibt separat zu prüfen.",
      "Local restart of this instance. Group health remains to be checked separately.");
    return entry("restart", "Wird für den Host-Neustart gestoppt und startet anschließend am selben Host.",
      "Stops for the host restart and starts again on the same host.");
  }

  function hostWorkloads(snapshot, hostId) {
    const services = snapshot.services.filter(({ host }) => host === hostId);
    const enrollment = window.opstendHostEnrollment;
    if (hostId === enrollment?.candidate?.id) {
      const registration = enrollment.read();
      if (registration.phase === "registered") {
        services.push(...registration.services.filter(({ mode, id }) => mode === "excluded" && !services.some((item) => item.id === id)));
      }
    }
    return services.sort((first, second) => first.id.localeCompare(second.id));
  }

  function buildPreview(state, hostId, journal, exceptId) {
    const window = windowFor(hostId);
    const plan = { host: hostId, window, workloads: [], binding: null };
    const snapshot = state?.inventory;
    const host = inScope(state, hostId) && snapshot?.hosts?.find(({ id }) => id === hostId);
    if (!host) return { ...plan, ...fail("Der Host ist im gewählten Bereich nicht verfügbar.", "The host is unavailable in the selected scope.") };
    const services = hostWorkloads(snapshot, hostId);
    plan.workloads = services.map((service) => impact(service, snapshot));
    plan.binding = { host: hostBinding(host), workloads: services.map((service) => workloadBinding(snapshot, service)) };
    if (journal === null) return { ...plan, ...journalUnavailable() };
    if (journal.some((record) => record.host === hostId && record.id !== exceptId && !terminal.has(record.stage))) {
      return { ...plan, ...fail("Für diesen Host gibt es bereits einen offenen Wartungsauftrag.", "This host already has an open maintenance job.") };
    }
    if (unavailable.has(host.status) || host.observation?.reachability === "offline") {
      return { ...plan, ...fail("Der Host ist offline oder bereits in Wartung.", "The host is offline or already in maintenance.") };
    }
    if (!["PVE", "Linux"].includes(host.type) || !host.runtime) {
      return { ...plan, ...fail("Die Laufzeitumgebung dieses Hosts ist unbekannt.", "This host's runtime environment is unknown.") };
    }
    if (plan.workloads.some(({ handling }) => handling === "blocked")) {
      return { ...plan, ...fail("Klär die blockierten Dienste vor der Wartung.", "Resolve the blocked workloads before scheduling maintenance.") };
    }
    const groups = new Set(services.map(({ group }) => group).filter(Boolean));
    const reserved = new Set(journal.filter((record) => record.id !== exceptId && ["approved", "active"].includes(record.stage)
      && record.window.startAt < window.endAt && window.startAt < record.window.endAt).map(({ host }) => host));
    const peerHosts = new Set(snapshot.hosts.filter((peer) => peer.id !== hostId && !unavailable.has(peer.status)
      && !reserved.has(peer.id)).map(({ id }) => id));
    for (const group of groups) {
      const healthyHosts = new Set(snapshot.services.filter((service) => service.group === group && peerHosts.has(service.host)
        && service.status === "Gesund" && runtime(service) === "running").map(({ host }) => host));
      if (healthyHosts.size < 2) return { ...plan, ...fail(
        `Für ${group} müssen zwei gesunde Instanzen auf anderen Hosts belegt sein.`,
        `Two healthy instances of ${group} on other hosts must be verified.`) };
    }
    return { ...plan, ok: true };
  }

  function preview(state, hostId) {
    return buildPreview(state, hostId, readJournal());
  }

  function records(state) {
    return (readJournal() ?? []).filter(({ host }) => inScope(state, host));
  }

  function latest(state, hostId) {
    return records(state).find(({ host }) => host === hostId) ?? null;
  }

  function active(hostId) {
    return (readJournal() ?? []).some(({ host, stage }) => host === hostId && stage === "active");
  }

  function freshState(state) {
    return { ...state, inventory: window.opstendDemo?.getInventory?.({ fresh: true }) ?? state?.inventory };
  }

  function withLock(task) {
    return navigator.locks ? navigator.locks.request(storageKey, task) : task();
  }

  const changedPlan = () => fail("Inventar oder Wartungsfenster haben sich geändert. Prüfe einen neuen Wartungsplan.",
    "Inventory or the maintenance window changed. Review a new maintenance plan.");
  const event = (action, actor, history) => ({ action, at: new Date().toISOString(),
    ...(actor === "zorec" ? { actor, history } : {}) });

  async function request(state, plan) {
    if (!plan?.ok) return fail("Erstelle zuerst einen ausführbaren Wartungsplan.", "Prepare an eligible maintenance plan first.");
    return withLock(() => {
      const journal = readJournal();
      const current = buildPreview(freshState(state), plan.host, journal);
      if (!current.ok) return current;
      if (!same(current.binding, plan.binding) || !same(current.window, plan.window)) return changedPlan();
      const record = {
        id: "host-maintenance-" + crypto.randomUUID(), host: current.host, stage: "pending", revision: 0,
        window: current.window, workloads: current.workloads, binding: current.binding, events: [event("request")],
      };
      return saveJournal([record, ...journal], record);
    });
  }

  async function advance(state, id, action, revision, { actor, history } = {}) {
    return withLock(() => {
      if (actor === "zorec" && (action !== "approve" || !window.opstendAutonomy?.effective?.())) {
        return fail("Zorec hat keine automatische Freigabe für diesen Schritt.", "Zorec has no automatic approval permission for this step.");
      }
      const journal = readJournal();
      if (journal === null) return journalUnavailable();
      const index = journal.findIndex((record) => record.id === id && inScope(state, record.host));
      const current = journal[index];
      const transition = Object.hasOwn(transitions, action) ? transitions[action] : null;
      if (!current || current.revision !== revision || !transition?.from.includes(current.stage)) {
        return fail("Der Wartungsauftrag hat sich geändert. Öffne seinen aktuellen Stand.", "This maintenance job changed. Open its current state.");
      }
      if (action === "approve" || action === "start") {
        const plan = buildPreview(freshState(state), current.host, journal, id);
        if (!plan.ok || !same(plan.binding, current.binding) || !same(plan.window, current.window)) return changedPlan();
      }
      const record = { ...current, stage: transition.to, revision: revision + 1, events: [...current.events, event(action, actor, history)] };
      journal[index] = record;
      return saveJournal(journal, record);
    });
  }

  function project(snapshot) {
    const journal = readJournal();
    if (!journal?.length) return snapshot;
    for (const host of snapshot.hosts) {
      const record = journal.find((item) => item.host === host.id && ["active", "finished"].includes(item.stage));
      if (!record || !same(hostBinding(host), record.binding.host) || unavailable.has(host.status)) continue;
      const inMaintenance = record.stage === "active";
      if (inMaintenance) host.status = "Wartung";
      host.maintenanceState = record.stage;
      host.maintenanceJobId = record.id;
      for (const service of snapshot.services.filter((item) => item.host === host.id)) {
        const index = record.workloads.findIndex(({ id, handling }) => id === service.id && handling === "restart");
        if (index < 0 || !same(workloadBinding(snapshot, service), record.binding.workloads[index])) continue;
        service.status = inMaintenance ? "Gestoppt" : "Health offen";
        service.power = inMaintenance ? "stopped" : "running";
        service.maintenanceState = inMaintenance ? "stopped" : "restart-check";
        service.maintenanceBaseline = record.binding.workloads[index];
      }
    }
    return snapshot;
  }

  window.addEventListener("storage", (event) => {
    if (event.key === storageKey || event.key === null) announce();
  });

  window.opstendHostMaintenance = { windowFor, preview, request, records, latest, advance, project, active };
})();
