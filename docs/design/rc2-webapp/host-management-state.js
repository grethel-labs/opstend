(function () {
  "use strict";

  const storageKey = "opstend-rc2-host-enrollment-v1";
  const changedEvent = "opstend:host-enrollment-changed";
  const destination = "host-b";
  const capacities = ["cpu", "ram", "storage"];
  const capacityLabels = { cpu: "CPU-Kerne", ram: "GiB RAM", storage: "GiB Speicher" };
  const defaults = Object.freeze({ cpu: 4, ram: 16, storage: 120, gpu: false });
  const hardware = Object.freeze({ cpu: 8, ram: 32, storage: 512, gpu: true });
  const workloads = Object.freeze([
    Object.freeze({ id: "linux-neu-paperless", name: "Paperless", kind: "Container · Podman", detail: "Dokumentenablage mit lokalem Datenverzeichnis", ip: "10.20.20.41", cpu: 2, ram: 4, storage: 60, gpu: false }),
    Object.freeze({ id: "linux-neu-render", name: "Renderdienst", kind: "Container · Podman", detail: "Renderaufträge mit exklusiv genutzter GPU", ip: "10.20.20.42", cpu: 2, ram: 6, storage: 60, gpu: true }),
  ]);
  const catalog = new Map(workloads.map((service) => [service.id, service]));
  const phases = new Set(["unregistered", "registered", "reset", "removed"]);
  const modes = new Set(["local", "managed", "observed", "excluded"]);
  const joinModes = { manage: "managed", observe: "observed", exclude: "excluded" };
  const issued = new Map();

  const candidate = Object.freeze({
    id: "linux-neu", name: "linux-neu", ip: "10.20.10.41", runtime: "Ubuntu · Podman", site: "Werkstatt", type: "Linux",
    physical: hardware, budgets: defaults, services: workloads,
  });

  const operationNames = { join: "Host aufgenommen", reset: "Host zurückgesetzt", remove: "Host entfernt" };
  const effects = {
    manage: "OpsTend verwaltet den vorhandenen Dienst mit seinen lokalen Daten.",
    observe: "OpsTend liest den Betriebszustand. Der bisherige Betreiber verwaltet den Dienst.",
    exclude: "Der Dienst bleibt außerhalb von OpsTend und verwendet seine bisherigen Ressourcen.",
    keep: "Der bisherige Betreiber übernimmt den Dienst auf linux-neu mit dem zuletzt beobachteten Laufzustand.",
    migrate: "OpsTend übernimmt den Dienst und seine Daten auf host-b.",
    stop: "Der Dienst wird angehalten. Seine Daten bleiben auf linux-neu.",
  };

  const fail = (error) => ({ ok: false, error });

  function initial() {
    return { phase: "unregistered", revision: 0, budgets: null,
      services: workloads.map(({ id }) => ({ id, mode: "local", power: "running" })), migrated: [], history: [] };
  }

  function budget(input) {
    if (!input || typeof input.gpu !== "boolean") return null;
    const result = { gpu: input.gpu };
    for (const key of capacities) {
      const raw = input[key];
      const value = typeof raw === "string" && /^\d+$/.test(raw.trim()) ? Number(raw) : raw;
      if (!Number.isInteger(value) || value < 0 || value > hardware[key]) return null;
      result[key] = value;
    }
    return result;
  }

  function validRecord(record) {
    return record && catalog.has(record.id) && modes.has(record.mode) && ["running", "stopped"].includes(record.power);
  }

  function stored() {
    try {
      const data = JSON.parse(localStorage.getItem(storageKey));
      if (!data || !phases.has(data.phase) || !Number.isSafeInteger(data.revision) || data.revision < 0
        || !Array.isArray(data.services) || !Array.isArray(data.migrated) || !Array.isArray(data.history)) return initial();
      const records = [...data.services, ...data.migrated];
      if (records.length !== workloads.length || !records.every(validRecord)
        || new Set(records.map(({ id }) => id)).size !== records.length
        || (data.phase === "registered" ? !budget(data.budgets) : data.budgets !== null)) return initial();
      return data;
    } catch {
      return initial();
    }
  }

  function describe(record, host) {
    return { ...catalog.get(record.id), ...record, host };
  }

  function describeState(state) {
    return { ...structuredClone(state), services: state.services.map((item) => describe(item, candidate.id)),
      migrated: state.migrated.map((item) => describe(item, destination)) };
  }

  function read() {
    return describeState(stored());
  }

  function inspect() {
    const state = read();
    return { ...candidate, services: state.services, revision: state.revision, source: "Zorecs Bestandsaufnahme · Demo-Daten" };
  }

  function checkJoinBudget(checked, services) {
    if (!checked) return "Gib CPU-Kerne, GiB RAM, GiB Speicher und die GPU-Nutzung innerhalb der physischen Grenzen an.";
    const managed = services.filter((service) => service.action === "manage").map((service) => catalog.get(service.id));
    const external = services.filter((service) => service.action !== "manage").map((service) => catalog.get(service.id));
    for (const key of capacities) {
      const used = managed.reduce((total, service) => total + service[key], 0);
      const reserved = external.reduce((total, service) => total + service[key], 0);
      if (used > checked[key]) return `Die übernommenen Dienste brauchen mindestens ${used} ${capacityLabels[key]}.`;
      const free = hardware[key] - reserved;
      if (checked[key] > free) return `Neben den extern verwalteten Diensten stehen höchstens ${free} ${capacityLabels[key]} zur Freigabe bereit.`;
    }
    if (managed.some((service) => service.gpu) && !checked.gpu) return "Gib die GPU für den Renderdienst frei oder lasse ihn außerhalb der Verwaltung.";
    if (checked.gpu && external.some((service) => service.gpu)) return "Der externe Renderdienst belegt die GPU bereits exklusiv.";
    return "";
  }

  function preview(input = {}) {
    if (!input || typeof input !== "object") return fail("Wähle Aufnahme, Reset oder Austritt.");
    const { operation, serviceActions } = input;
    if (!Object.hasOwn(operationNames, operation)) return fail("Wähle Aufnahme, Reset oder Austritt.");
    const state = stored();
    const joining = operation === "join";
    if (joining === (state.phase === "registered")) return fail(joining ? "linux-neu ist bereits aufgenommen." : "Für diesen Vorgang muss linux-neu aufgenommen sein.");
    if (!serviceActions || typeof serviceActions !== "object" || Array.isArray(serviceActions)
      || Object.keys(serviceActions).length !== state.services.length) return fail("Entscheide für jeden vorhandenen Dienst, wie es weitergeht.");

    const services = [];
    for (const service of state.services) {
      const { name, gpu } = catalog.get(service.id);
      const action = serviceActions[service.id];
      if (joining ? !Object.hasOwn(joinModes, action) : !["keep", "migrate", "stop"].includes(action)) {
        return fail(`Wähle eine gültige Behandlung für ${name}.`);
      }
      if (!joining && action !== "keep" && service.mode !== "managed") return fail(`${name} wird außerhalb von OpsTend verwaltet und kann hier nur vor Ort bleiben.`);
      if (action === "migrate" && gpu) return fail(`Für ${name} ist am Ziel host-b keine passende GPU-Zuordnung belegt.`);
      services.push({ id: service.id, name, mode: service.mode, action, effect: effects[action] });
    }
    const maintenance = maintenanceConflict(services);
    if (maintenance) return fail(maintenance);
    const budgets = joining ? budget(input.budgets) : null;
    if (joining) {
      const error = checkJoinBudget(budgets, services);
      if (error) return fail(error);
    }
    const plan = { id: crypto.randomUUID(), operation, expectedRevision: state.revision, target: candidate.id, budgets, services };
    if (issued.size >= 8) issued.delete(issued.keys().next().value);
    issued.set(plan.id, plan);
    return { ok: true, plan: structuredClone(plan) };
  }

  function announce() {
    window.dispatchEvent(new CustomEvent(changedEvent, { detail: { state: read() } }));
  }

  function maintenanceConflict(services) {
    const restriction = window.opstendDemo.maintenanceRestriction;
    return restriction(candidate.id) || (services.some(({ action }) => action === "migrate") ? restriction(destination) : "");
  }

  function commit(confirmed) {
    const plan = issued.get(confirmed?.id);
    if (!plan) return fail("Erstelle eine neue Vorschau und bestätige den angezeigten Plan.");
    try {
      if (JSON.stringify(plan) !== JSON.stringify(confirmed)) return fail("Der angezeigte Plan wurde geändert. Erstelle eine neue Vorschau.");
    } catch {
      return fail("Der angezeigte Plan ist ungültig. Erstelle eine neue Vorschau.");
    }
    const state = stored();
    if (state.revision !== plan.expectedRevision) {
      issued.delete(plan.id);
      return fail("Der Hoststand hat sich geändert. Prüfe die neue Vorschau.");
    }
    const maintenance = maintenanceConflict(plan.services);
    if (maintenance) return fail(maintenance);
    const next = structuredClone(state);
    const actions = new Map(plan.services.map(({ id, action }) => [id, action]));
    next.revision += 1;
    next.budgets = plan.budgets;
    if (plan.operation === "join") {
      next.phase = "registered";
      for (const service of next.services) service.mode = joinModes[actions.get(service.id)];
    } else {
      next.phase = plan.operation === "reset" ? "reset" : "removed";
      next.services = next.services.filter((service) => {
        const action = actions.get(service.id);
        if (action === "migrate") {
          next.migrated.push(service);
          return false;
        }
        service.mode = "local";
        if (action === "stop") service.power = "stopped";
        return true;
      });
    }
    next.history = [{ revision: next.revision, operation: plan.operation, at: new Date().toISOString(),
      services: plan.services, budgets: plan.budgets }, ...next.history].slice(0, 12);
    try {
      localStorage.setItem(storageKey, JSON.stringify(next));
    } catch {
      return fail("Der neue Hoststand konnte im Browser nicht gespeichert werden.");
    }
    issued.delete(plan.id);
    announce();
    return { ok: true, state: describeState(next) };
  }

  async function apply(plan) {
    if (navigator.locks) return navigator.locks.request(storageKey, () => commit(plan));
    return commit(plan);
  }

  function projectService(record, host) {
    const service = catalog.get(record.id);
    return { id: service.id, name: service.name, kind: service.kind, host, ip: service.ip, cpu: `${service.cpu} CPU`, ram: `${service.ram} GiB`,
      storage: `${service.storage} GiB`, status: record.power === "running" ? "Health offen" : "Gestoppt", role: "Anwendung", network: "VLAN 20",
      managed: record.mode === "managed", mode: record.mode, power: record.power, sourceHost: candidate.id };
  }

  function projection() {
    const state = stored();
    const registered = state.phase === "registered";
    const { id, name, ip, runtime, site, type, physical } = candidate;
    const hosts = registered ? [{ id, name, ip, runtime, site, type, physical, budgets: state.budgets }] : [];
    const services = state.migrated.map((record) => projectService(record, destination));
    if (registered) services.push(...state.services.filter(({ mode }) => ["managed", "observed"].includes(mode)).map((record) => projectService(record, id)));
    const changes = state.history.filter((event) => event?.operation && Object.hasOwn(operationNames, event.operation) && Array.isArray(event.services)).map((event) => ({
      id: `host-enrollment-${event.revision}`, kind: "host-enrollment", host: id, name: `${operationNames[event.operation]} · ${name}`,
      status: operationNames[event.operation], at: event.at, operation: event.operation, services: event.services, budgets: event.budgets,
      ...(event.services.some((service) => service.action === "migrate") ? { relatedHost: destination } : {}),
    }));
    return { hosts, services, links: [], changes };
  }

  window.addEventListener("storage", (event) => {
    if (event.key === storageKey || event.key === null) announce();
  });
  window.opstendHostEnrollment = { candidate, read, inspect, preview, apply, projection };
})();
