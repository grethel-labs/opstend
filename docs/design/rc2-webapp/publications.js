(function () {
  "use strict";

  const storageKey = "opstend-rc2-publication-v1";
  const changedEvent = "opstend:publication-changed";
  const common = { proxyId: "https-proxy", proxyHost: "edge-01", targetHost: "nuc-a", tunnelId: "edge-tunnel", tunnelHost: "host-b" };
  const definitions = [
    { ...common, id: "medien-publication", serviceId: "medien", jobId: "route", linkId: "medien-release",
      label: "HTTPS-Freigabe für Medien", labelEn: "HTTPS approval for Medien", domain: "medien.werkstatt.example" },
    { ...common, id: "fotos-publication", serviceId: "fotos", jobId: null, linkId: "fotos-release",
      label: "HTTPS-Freigabe für Fotos", labelEn: "HTTPS approval for Fotos", domain: "fotos.werkstatt.example" },
  ];
  const transitions = {
    approve: { from: ["draft"], to: "approved" },
    reject: { from: ["draft"], to: "rejected" },
    apply: { from: ["approved"], to: "applied" },
    "probe-pass": { from: ["applied", "failed"], to: "verified" },
    "probe-fail": { from: ["applied", "failed"], to: "failed" },
    withdraw: { from: ["approved", "applied", "verified", "failed"], to: "withdrawn" },
    replan: { from: ["approved", "rejected", "withdrawn"], to: "draft" },
  };
  const boundStages = new Set(["approved", "applied", "verified", "failed"]);
  const appliedStages = new Set(["applied", "verified", "failed", "configured"]);
  const requiresPath = new Set(["approve", "apply", "probe-pass", "probe-fail", "replan"]);
  const unavailable = new Set(["Offline", "Ausgefallen", "Nicht erreichbar", "Wartung"]);
  const stageLabels = {
    draft: ["Entwurf", "Draft"],
    approved: ["Freigegeben", "Approved"],
    applied: ["Prüfung offen", "Check pending"],
    verified: ["Simuliert erreichbar", "Simulated reachable"],
    failed: ["Externe Probe fehlgeschlagen", "External check failed"],
    rejected: ["Abgelehnt", "Rejected"],
    withdrawn: ["Zurückgezogen", "Withdrawn"],
    configured: ["Konfiguriert", "Configured"],
  };
  const earlierApprovalBinding = JSON.stringify([
    "medien.werkstatt.example", "werkstatt.example",
    ["medien", "nuc-a", "10.20.20.21", "VLAN 20", null], ["https-proxy", "edge-01", "10.31.0.10", "VPN", null],
    [["10.20.10.11", null], ["10.31.0.5", null], ["10.20.10.12", null]],
    ["edge-01", "host-b", "access", "WireGuard · Tunnel", false],
  ]);

  const fail = (error, errorEn) => ({ ok: false, error, errorEn });
  const announce = () => window.dispatchEvent(new CustomEvent(changedEvent));
  const initial = () => ({ stage: "draft", revision: 0, binding: null, events: [] });

  function validJournal(record) {
    if (!Array.isArray(record?.events) || record.revision !== record.events.length) return false;
    let stage = "draft";
    for (const [index, event] of record.events.entries()) {
      const next = event && Object.hasOwn(transitions, event.action) && transitions[event.action];
      const legacy = index === 0 && event?.legacy === true && ["approve", "reject"].includes(event.action);
      if (!next || !next.from.includes(stage) || !(legacy && event.at === null || Number.isFinite(Date.parse(event.at)))) return false;
      stage = next.to;
    }
    return stage === record.stage && (boundStages.has(stage) ? typeof record.binding === "string" : record.binding === null);
  }

  function readJournal(snapshot) {
    try {
      const value = localStorage.getItem(storageKey);
      if (value !== null) {
        const record = JSON.parse(value);
        return validJournal(record) ? record : null;
      }
    } catch {
      return null;
    }
    const legacy = snapshot?.changes?.find(({ id }) => id === "route-decision");
    const action = legacy?.status === "In der Demo freigegeben" ? "approve" : legacy?.status === "Abgelehnt" ? "reject" : null;
    if (!action) return initial();
    return {
      stage: transitions[action].to, revision: 1, binding: action === "approve" ? earlierApprovalBinding : null,
      events: [{ action, at: Number.isFinite(Date.parse(legacy.at)) ? legacy.at : null, legacy: true }],
    };
  }

  function path(snapshot, definition) {
    const workload = (id) => snapshot.services.find((service) => service.id === id);
    const machine = (id) => snapshot.hosts.find((host) => host.id === id);
    const target = workload(definition.serviceId);
    const proxy = workload(definition.proxyId);
    const hosts = [definition.targetHost, definition.proxyHost, definition.tunnelHost].map(machine);
    const tunnel = snapshot.links.find(({ id }) => id === definition.tunnelId);
    const zone = snapshot.domains?.find(({ id }) => id === "workshop")?.name;
    const boundWorkload = (service) => service ? [service.id, service.host, service.ip, service.network,
      snapshot.changes?.find((change) => change.kind === "runtime" && change.serviceId === service.id
        && (!change.stage || change.attemptedAt))?.id ?? null] : null;
    const binding = JSON.stringify([
      definition.domain, zone, boundWorkload(target), boundWorkload(proxy), hosts.map((host) => [host?.ip, host?.maintenanceJobId ?? null]),
      tunnel ? [tunnel.from, tunnel.to, tunnel.layer, tunnel.label, !!tunnel.evidenceStale] : null,
    ]);
    const missing = (error, errorEn) => ({ ...fail(error, errorEn), binding });

    if (target?.host !== definition.targetHost || proxy?.host !== definition.proxyHost
      || !target.ip || !proxy.ip || hosts.some((host) => !host?.ip)) {
      return missing("Ziel, Proxy oder zugehöriger Host fehlt im registrierten Pfad.", "The target, proxy, or a related host is missing from the registered path.");
    }
    if (!zone || !definition.domain.endsWith("." + zone)) {
      return missing("Die Domain liegt außerhalb der erfassten Beispielzone.", "The domain is outside the configured sample zone.");
    }
    if (tunnel?.layer !== "access" || ![tunnel.from, tunnel.to].includes(definition.proxyHost)
      || ![tunnel.from, tunnel.to].includes(definition.tunnelHost)) {
      return missing("Der VPN-Pfad muss den Proxy-Host mit dem internen Tunnelendpunkt verbinden.",
        "The VPN path must connect the proxy host to the internal tunnel endpoint.");
    }
    if (hosts.some(({ status }) => unavailable.has(status)) || [target, proxy].some((service) => window.opstendDemo.serviceRuntime(service) !== "running")) {
      return missing("Für den Pfad müssen Hosts, Proxy und Zieldienst verfügbar sein.", "The path requires available hosts, proxy, and target service.");
    }
    if (!definition.jobId && !snapshot.links.some(({ id, from, to, layer }) =>
      id === definition.linkId && from === definition.proxyId && to === definition.serviceId && layer === "access")) {
      return missing("Die erfasste Proxy-Weiterleitung passt nicht mehr zum Ziel.", "The recorded proxy route no longer matches the target.");
    }
    return { ok: true, binding };
  }

  function resolve(state, definition, journal) {
    const { inventory, host } = state;
    if (host && ![definition.targetHost, definition.proxyHost, definition.tunnelHost].includes(host)) return null;
    const current = definition.jobId ? journal ?? initial() : { stage: "configured", revision: 0, binding: null, events: [] };
    const check = path(inventory, definition);
    const storageError = definition.jobId && journal === null;
    const ready = check.ok && !storageError;
    const stale = boundStages.has(current.stage) && (!ready || current.binding !== check.binding)
      || (current.stage === "configured" && !ready);
    const latestProbe = current.events.findLast(({ action }) => ["probe-pass", "probe-fail", "replan", "withdraw"].includes(action));
    const probe = latestProbe?.action.startsWith("probe-") ? {
      result: latestProbe.action === "probe-pass" ? "pass" : "fail", at: latestProbe.at, stale,
    } : null;
    const [stageLabel, stageLabelEn] = stageLabels[current.stage];
    return { ...definition, stage: current.stage, stageLabel, stageLabelEn, revision: current.revision, events: current.events,
      ready, stale, applied: appliedStages.has(current.stage), binding: check.binding, probe,
      error: storageError ? "Das Freigabeprotokoll ist nicht verfügbar." : check.error
        ?? (stale ? "Die Freigabe oder Prüfung gehört zu einem früheren Pfad." : undefined),
      errorEn: storageError ? "The publication journal is unavailable." : check.errorEn
        ?? (stale ? "The approval or check applies to an earlier path." : undefined),
    };
  }

  function list(state, journal = readJournal(state?.inventory)) {
    if (!state?.inventory) return [];
    return definitions.map((definition) => resolve(state, definition, journal)).filter(Boolean);
  }

  function get(state, id) {
    return list(state).find((publication) => publication.id === id) ?? null;
  }

  async function advance(state, id, action, expectedRevision, binding) {
    const commit = () => {
      const inventory = window.opstendDemo.getInventory({ fresh: true });
      const journal = readJournal(inventory);
      if (!journal) return fail("Das Freigabeprotokoll ist nicht verfügbar.", "The publication journal is unavailable.");
      const publication = list({ ...state, inventory }, journal).find((entry) => entry.id === id);
      if (!publication?.jobId) return fail("Für diese Veröffentlichung ist hier keine Änderung verfügbar.",
        "Changes to this publication are unavailable here.");
      if (publication.revision !== expectedRevision || publication.binding !== binding) {
        return fail("Der Pfad oder die Freigabe hat sich geändert. Prüfe den aktuellen Stand.", "The path or approval changed. Review the current state.");
      }
      const next = Object.hasOwn(transitions, action) && transitions[action];
      if (!next?.from.includes(publication.stage) || (action === "replan" && publication.stage === "approved" && !publication.stale)) {
        return fail("Dieser Schritt ist für den aktuellen Freigabestand nicht verfügbar.", "This step is unavailable for the current approval state.");
      }
      if (requiresPath.has(action) && !publication.ready) return fail(publication.error, publication.errorEn);
      if (publication.stale && ["apply", "probe-pass", "probe-fail"].includes(action)) {
        return fail("Die Freigabe gilt für einen früheren Pfad. Prüfe den aktuellen Pfad erneut.",
          "The approval applies to an earlier path. Review the current path again.");
      }
      const record = { stage: next.to, revision: journal.revision + 1,
        binding: boundStages.has(next.to) ? publication.binding : null,
        events: [...journal.events, { action, at: new Date().toISOString() }],
      };
      try {
        localStorage.setItem(storageKey, JSON.stringify(record));
      } catch {
        return fail("Die Änderung konnte im Browser nicht gespeichert werden.", "The browser could not save the change.");
      }
      announce();
      return { ok: true, publication: list({ ...state, inventory }, record).find((entry) => entry.id === id) };
    };
    return navigator.locks ? navigator.locks.request(storageKey, commit) : commit();
  }

  function evidenceFor(publication) {
    const { stage, probe, stale, serviceId } = publication;
    const name = serviceId === "medien" ? "Medien" : "Fotos";
    const label = `HTTPS ${name} · ${stale ? "Beleg überholt" : publication.stageLabel}`;
    const labelEn = `HTTPS ${name} · ${stale ? "check outdated" : publication.stageLabelEn}`;
    const base = { label, labelEn, source: "Proxy-Profil · Beispieldaten", sourceEn: "Proxy profile · Sample data" };
    if (probe) {
      const proof = { ...base, source: "Externer Prüfpunkt · Simulation", sourceEn: "External check · Simulation", observedAt: probe.at };
      if (stale) return { ...proof, type: "Historische Verbindungsprüfung",
        detail: "Die simulierte Probe gilt für den früheren Pfad.", detailEn: "The simulated check applies to the previous path." };
      return { ...proof, type: "Verbindungsprüfung",
        detail: probe.result === "pass" ? "Der simulierte externe Prüfpunkt erreichte den HTTPS-Dienst." : "Der simulierte externe Prüfpunkt erreichte den HTTPS-Dienst nicht.",
        detailEn: probe.result === "pass" ? "The simulated external check reached the HTTPS service." : "The simulated external check failed to reach the HTTPS service." };
    }
    if (stale) return { ...base, type: "Entwurf",
      detail: "Für den aktuellen Pfad fehlt ein gültiger Freigabe- oder Prüfbeleg.",
      detailEn: "The current path lacks valid approval or verification evidence." };
    if (publication.applied) return { ...base, type: "Konfigurierte Beziehung",
      detail: "Der Proxy-Pfad ist in der Demo konfiguriert. Von außen liegt kein Prüfbeleg vor.",
      detailEn: "The proxy path is configured in the demo. External verification is unavailable." };
    return { ...base, type: "Entwurf",
      detail: stage === "approved" ? "Die Freigabe ist gespeichert. Die Anwendung des Proxy-Pfads steht aus." : "Zu diesem Auftrag ist kein Proxy-Pfad eingerichtet.",
      detailEn: stage === "approved" ? "The approval is saved. Applying the proxy path is pending." : "This job has no configured proxy path." };
  }

  function project(snapshot) {
    const publications = list({ inventory: snapshot });
    const byLink = new Map(publications.map((publication) => [publication.linkId, publication]));
    const withEvidence = (link, publication) => ({ ...link, publicationId: publication.id, tunnelId: publication.tunnelId,
      publicationStage: publication.stage, publicationStale: publication.stale, publicationEvidence: evidenceFor(publication) });
    const links = snapshot.links.filter(({ id }) => id !== "medien-release").map((link) =>
      byLink.has(link.id) ? withEvidence(link, byLink.get(link.id)) : link);
    const medien = byLink.get("medien-release");
    if ([medien.proxyId, medien.serviceId].every((id) => snapshot.services.some((service) => service.id === id))) {
      links.push(withEvidence({ id: medien.linkId, from: medien.proxyId, to: medien.serviceId, layer: "access",
        label: evidenceFor(medien).label }, medien));
    }
    return { ...snapshot, links };
  }

  function evidence(link) {
    if (!definitions.some(({ id, linkId }) => id === link.publicationId && linkId === link.id) || !link.publicationEvidence) return null;
    const proof = link.publicationEvidence;
    return { ...proof, source: window.opstendLocale?.t(proof.source, proof.sourceEn) ?? proof.source };
  }

  window.addEventListener("storage", (event) => {
    if (event.key === storageKey || event.key === null) announce();
  });
  window.opstendPublications = { list, get, advance, project, evidence };
})();
