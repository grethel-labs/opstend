(function () {
  "use strict";

  const prefix = "opstend-rc2-self-update-v1:";
  const changedEvent = "opstend:self-update-changed";
  const versions = Object.freeze({ installed: "0.1.0rc1", available: "0.1.0rc2" });
  const catalog = {
    "log-format": {
      label: "Strukturierte Ereignisse",
      base: "format: text",
      local: "format: json",
      upstream: "format: json",
    },
    "archive-label": {
      label: "Lokales Archivpräfix",
      base: "prefix: opstend",
      local: "prefix: werkstatt",
      upstream: "prefix: opstend",
    },
    "maintenance-window": {
      label: "Lokales Wartungsfenster",
      base: 'start: "03:00"\nminutes: 60',
      local: 'start: "02:00"\nminutes: 90',
      upstream: 'start: "04:00"\nminutes: 60\ntimezone: Europe/Berlin',
    },
  };
  const initialPatches = Object.freeze(Object.entries(catalog).map(([id, patch]) => Object.freeze({ id, label: patch.label, value: patch.local })));
  const validPolicies = ["manual", "automatic"];
  const validPhases = ["idle", "available", "prepared", "applied", "rolled-back"];

  function hostName(host) {
    return typeof host === "string" && /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(host)
      && window.opstendDemo?.getInventory().hosts.some((entry) => entry.id === host);
  }

  function initial(host) {
    return { host, revision: 0, version: versions.installed, patches: structuredClone(initialPatches),
      policy: "manual", phase: "idle", candidate: null, rollback: null, history: [] };
  }

  function read(host) {
    if (!hostName(host)) return null;
    try {
      const saved = JSON.parse(localStorage.getItem(prefix + host));
      if (saved?.host === host && Number.isSafeInteger(saved.revision) && saved.revision >= 0
        && [versions.installed, versions.available].includes(saved.version) && validPolicies.includes(saved.policy)
        && validPhases.includes(saved.phase) && Array.isArray(saved.patches) && Array.isArray(saved.history)
        && (!["available", "prepared"].includes(saved.phase) || Array.isArray(saved.candidate?.items))) return saved;
    } catch {}
    return initial(host);
  }

  function snapshot(state) {
    return { version: state.version, patches: structuredClone(state.patches) };
  }

  function compare({ patches }) {
    return patches.map(({ id, label, value: local }) => {
      const { base, upstream } = catalog[id];
      const kind = local === upstream || local === base ? "absorbed" : upstream === base ? "portable" : "conflict";
      return { id, label, base, local, upstream, kind, proposed: null, approved: false };
    });
  }

  function checked(state) {
    if (state.version === versions.available) return `${state.version} ist auf dieser Demo-Instanz installiert.`;
    if (!state.candidate) {
      state.candidate = { version: versions.available, items: [], snapshot: null };
      state.phase = "available";
    }
    return `Version ${state.candidate.version} ist für die Demo verfügbar.`;
  }

  function prepare(state) {
    if (state.phase !== "available") return { error: "Prüfe zuerst, ob eine neuere Version verfügbar ist." };
    const before = snapshot(state);
    state.candidate = { version: state.candidate.version, snapshot: before, items: compare(before) };
    state.phase = "prepared";
    return `Ausgangsstand ${before.version} und ${before.patches.length} lokale Anpassungen vor dem Vergleich gesichert.`;
  }

  function resolve(state, action, patchId) {
    if (state.phase !== "prepared") return { error: "Bereite zuerst den Versionsvergleich vor." };
    const patch = state.candidate.items.find((item) => item.id === patchId && item.kind === "conflict");
    if (!patch) return { error: "Die gewählte Anpassung hat keinen offenen Vergleichskonflikt." };
    if (action === "suggest") {
      patch.proposed ??= `${patch.local}\n${patch.upstream.split("\n").at(-1)}`;
      return `Vorschlag zum Wartungsfenster erstellt. Startzeit und Dauer bleiben lokal, die Zeitzone kommt aus der neuen Version.`;
    }
    if (patch.proposed === null) return { error: "Für die Freigabe braucht der Konflikt zuerst einen Änderungsvorschlag." };
    patch.approved = true;
    return `Vorschlag für ${patch.label} freigegeben.`;
  }

  function apply(state, automatic) {
    if (automatic && state.policy !== "automatic") return { error: "Automatische Updates sind für diese Demo-Instanz deaktiviert." };
    if (state.phase !== "prepared") return { error: "Für die Aktualisierung braucht es eine vorbereitete Vorschau." };
    const { version, snapshot: before, items } = state.candidate;
    if (items.some((patch) => patch.kind === "conflict" && !patch.approved)) {
      return { error: "Gib den Vorschlag für das lokale Wartungsfenster frei, bevor du aktualisierst." };
    }
    state.rollback = before;
    state.patches = items.filter((patch) => patch.kind !== "absorbed").map((patch) => ({
      id: patch.id, label: patch.label, value: patch.kind === "conflict" ? patch.proposed : patch.local,
    }));
    state.version = version;
    state.phase = "applied";
    return `Version ${version} mit ${state.patches.length} lokalen Anpassungen im Demo-Zustand übernommen.`;
  }

  function transition(state, action, payload) {
    switch (action) {
      case "policy":
        if (!validPolicies.includes(payload?.policy)) return { error: "Wähle einen gültigen Aktualisierungsmodus." };
        state.policy = payload.policy;
        return state.policy === "automatic" ? "Automatische Aktualisierung im Wartungsfenster gewählt." : "Manuelle Aktualisierung gewählt.";
      case "check":
        return checked(state);
      case "prepare":
        return prepare(state);
      case "suggest":
      case "approve":
        return resolve(state, action, payload?.patchId);
      case "cancel":
        if (state.phase !== "prepared") return { error: "Für diese Instanz ist kein Vergleich vorbereitet." };
        state.candidate = { ...state.candidate, items: [] };
        state.phase = "available";
        return `Vorschau verworfen. Version ${state.version} bleibt im Demo-Zustand installiert.`;
      case "apply":
      case "window":
        return apply(state, action === "window");
      case "rollback": {
        if (state.phase !== "applied" || !state.rollback) return { error: "Für diese Instanz ist kein vorheriger Stand zur Wiederherstellung gespeichert." };
        const before = state.rollback;
        state.version = before.version;
        state.patches = before.patches;
        state.phase = "rolled-back";
        state.candidate = null;
        state.rollback = null;
        return `Version ${state.version} und ${state.patches.length} gesicherte lokale Anpassungen wiederhergestellt.`;
      }
      default:
        return { error: "Die gewählte Aktion ist für die Demo-Instanz nicht verfügbar." };
    }
  }

  function notify(host, state) {
    window.dispatchEvent(new CustomEvent(changedEvent, { detail: { host, state } }));
  }

  function write(host, expectedRevision, action, payload) {
    const previous = read(host);
    if (previous.revision !== expectedRevision) {
      return { ok: false, error: "Die Demo-Instanz hat sich geändert. Prüfe den aktuellen Stand erneut.", state: previous };
    }
    const state = structuredClone(previous);
    const detail = transition(state, action, payload);
    if (typeof detail !== "string") return { ok: false, ...detail, state: previous };
    state.revision += 1;
    state.history.unshift({ at: new Date().toISOString(), action, detail });
    try {
      localStorage.setItem(prefix + host, JSON.stringify(state));
    } catch {
      return { ok: false, error: "Der neue Stand konnte im Browser nicht gespeichert werden.", state: previous };
    }
    notify(host, state);
    return { ok: true, state };
  }

  async function mutate(host, expectedRevision, action, payload = {}) {
    if (!hostName(host)) return { ok: false, error: "Wähle eine gültige Demo-Instanz.", state: null };
    const task = () => write(host, expectedRevision, action, payload);
    if (navigator.locks) return navigator.locks.request(prefix + host, task);
    return task();
  }

  window.addEventListener("storage", (event) => {
    if (!event.key?.startsWith(prefix)) return;
    const host = event.key.slice(prefix.length);
    if (hostName(host)) notify(host, read(host));
  });

  window.opstendSelfUpdate = { read, mutate, versions, initialPatches };
})();
