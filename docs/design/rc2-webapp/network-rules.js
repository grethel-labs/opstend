(function () {
  "use strict";

  const storageKey = "opstend-rc2-network-rules-v1";
  const changedEvent = "opstend:network-rules-changed";
  const t = (de, en) => window.opstendLocale?.t(de, en) ?? de;
  const effects = ["allow", "block"];
  const ruleDefinitions = [
    {
      id: "storage-nfs", name: "NFS für Medien", nameEn: "NFS for Medien", kind: "firewall", deviceId: "gateway",
      sourceId: "medien", targetId: "nas", sourceNetworkId: "services", targetNetworkId: "storage",
      protocol: "TCP", port: 2049, linkId: "nfs-probe", editable: true, effect: "allow",
    },
    {
      id: "protect-management", name: "Verwaltung schützen", nameEn: "Protect management", kind: "acl", deviceId: "switch",
      sourceId: "services", targetId: "management", sourceNetworkId: "services", targetNetworkId: "management",
      protocol: "TCP", port: 443, linkId: null, editable: false, effect: "block",
    },
  ];
  const editableIds = new Set(ruleDefinitions.filter((rule) => rule.editable).map((rule) => rule.id));

  const error = (de, en) => ({ ok: false, error: t(de, en) });
  const announce = () => window.dispatchEvent(new CustomEvent(changedEvent));

  function validRecord(record) {
    return record && typeof record.id === "string" && record.id.startsWith("network-rule-")
      && editableIds.has(record.ruleId) && typeof record.host === "string" && record.host.length > 0
      && typeof record.name === "string" && typeof record.nameEn === "string"
      && effects.includes(record.before) && effects.includes(record.after) && record.before !== record.after
      && Number.isSafeInteger(record.revision) && record.revision >= 0
      && Number.isFinite(Date.parse(record.requestedAt))
      && (record.status === "pending" ? record.decidedAt === null
        : ["applied", "rejected"].includes(record.status) && Number.isFinite(Date.parse(record.decidedAt)));
  }

  function readJournal() {
    try {
      const records = JSON.parse(localStorage.getItem(storageKey) ?? "[]");
      return Array.isArray(records) && records.every(validRecord)
        && new Set(records.map((record) => record.id)).size === records.length ? records : null;
    } catch {
      return null;
    }
  }

  function storeJournal(records, record) {
    try {
      localStorage.setItem(storageKey, JSON.stringify(records));
    } catch {
      return error("Die Regeländerung konnte im Browser nicht gespeichert werden.", "The browser could not save the rule change.");
    }
    announce();
    return { ok: true, record };
  }

  function memberOf(network, workload) {
    return window.opstendViews?.serviceInNetwork?.(network, workload)
      ?? workload.network === network.name.split(" · ")[0];
  }

  function switchCarriesNetwork(state, deviceId, ids) {
    return state.inventory.links.some(({ id, from, to, layer }) => {
      if (layer !== "physical" || ![from, to].includes(deviceId) || ![from, to].includes(state.host)) return false;
      const port = window.opstendDemo?.portConfiguration?.(id, state.inventory);
      return port && [port.current.nativeVlan, ...port.current.taggedVlans].some((networkId) => ids.includes(networkId));
    });
  }

  function resolveRule(state, definition, journal, filter) {
    const { inventory, host } = state;
    const { deviceId, sourceId, targetId, sourceNetworkId, targetNetworkId, kind } = definition;
    if (!inventory.devices.some(({ id }) => id === deviceId)) return null;
    const sourceNetwork = inventory.networks.find(({ id }) => id === sourceNetworkId);
    const targetNetwork = inventory.networks.find(({ id }) => id === targetNetworkId);
    if (!sourceNetwork || !targetNetwork) return null;
    const networkIds = [sourceNetworkId, targetNetworkId];
    if (filter.networkId && !networkIds.includes(filter.networkId)) return null;

    const source = inventory.services.find(({ id }) => id === sourceId);
    if (kind === "firewall") {
      if (!source || !inventory.hosts.some(({ id }) => id === source.host)
        || !inventory.devices.some(({ id }) => id === targetId) || (host && source.host !== host)
        || (filter.serviceId && source.id !== filter.serviceId)) return null;
    } else {
      const matchesNetwork = (service) => memberOf(sourceNetwork, service) || memberOf(targetNetwork, service);
      if (filter.serviceId && !inventory.services.some((service) => service.id === filter.serviceId
        && (!host || service.host === host) && matchesNetwork(service))) return null;
      if (host && !inventory.services.some((service) => service.host === host && matchesNetwork(service))
        && !switchCarriesNetwork(state, deviceId, networkIds)) return null;
    }

    const link = inventory.links.find(({ id, from, to, layer }) =>
      id === definition.linkId && from === sourceId && to === targetId && layer === "network");
    if (filter.linkId && link?.id !== filter.linkId) return null;
    const current = journal.find((record) => record.ruleId === definition.id && record.status === "applied");
    const pending = journal.find((record) => record.ruleId === definition.id && record.status === "pending") ?? null;
    return { ...definition, linkId: link?.id ?? null, host: source?.host ?? "",
      effect: current?.after ?? definition.effect, revision: current ? current.revision + 1 : 0, pending };
  }

  function list(state, filter = {}, journal = readJournal()) {
    if (!state?.inventory || journal === null || (state.host && !state.inventory.hosts.some(({ id }) => id === state.host))) return [];
    return ruleDefinitions.map((definition) => resolveRule(state, definition, journal, filter)).filter(Boolean);
  }

  function get(state, id) {
    return list(state).find((rule) => rule.id === id) ?? null;
  }

  function preview(state, id, effect, revision, journal = readJournal()) {
    if (journal === null) return error("Das Regelprotokoll ist nicht verfügbar.", "The rule journal is unavailable.");
    const rule = list(state, {}, journal).find((item) => item.id === id);
    if (!rule) return error("Diese Regel ist im gewählten Bereich nicht verfügbar.", "This rule is unavailable in the selected scope.");
    if (!rule.editable) return error("Diese Regel steht als lesender Beleg bereit.", "This rule is available as read-only evidence.");
    if (!effects.includes(effect)) return error("Wähle Zulassen oder Blockieren.", "Choose Allow or Block.");
    if (rule.revision !== revision || rule.pending) {
      return error("Der Regelstand hat sich geändert. Öffne die Regel für die aktuelle Revision oder Entscheidung.", "The rule changed. Open it for the current revision or decision.");
    }
    if (rule.effect === effect) return error("Die Regel hat diese Wirkung bereits.", "The rule already has this effect.");
    return { ok: true, rule, before: rule.effect, after: effect };
  }

  const freshState = (state) => ({ ...state, inventory: window.opstendDemo?.getInventory?.() ?? state.inventory });
  const visibleRecord = (state, record) => !state.host || state.host === record.host;

  async function transaction(commit) {
    if (navigator.locks) return navigator.locks.request(storageKey, commit);
    return commit();
  }

  async function queue(state, id, effect, revision) {
    const checked = preview(state, id, effect, revision);
    if (!checked.ok) return checked;
    return transaction(() => {
      const journal = readJournal();
      const result = preview(freshState(state), id, effect, revision, journal);
      if (!result.ok) return result;
      const { rule, before, after } = result;
      if (rule.host !== checked.rule.host) {
        return error("Der Dienst wurde verschoben. Prüfe die Regel für den aktuellen Host erneut.", "The service moved. Review the rule for the current host.");
      }
      const record = {
        id: "network-rule-" + crypto.randomUUID(), ruleId: rule.id, host: rule.host,
        name: rule.name, nameEn: rule.nameEn, before, after, revision, status: "pending",
        requestedAt: new Date().toISOString(), decidedAt: null,
      };
      return storeJournal([record, ...journal], record);
    });
  }

  function decide(state, jobId, decision) {
    return transaction(() => {
      const journal = readJournal();
      const index = journal?.findIndex((record) => record.id === jobId && visibleRecord(state, record)) ?? -1;
      const pending = journal?.[index];
      if (pending?.status !== "pending" || !["approve", "reject"].includes(decision)) {
        return error("Für diesen Entwurf ist keine offene Entscheidung verfügbar.", "This draft has no pending decision.");
      }
      if (decision === "approve") {
        const rule = list(freshState(state), {}, journal).find((item) => item.id === pending.ruleId);
        if (!rule?.editable || rule.host !== pending.host || rule.revision !== pending.revision || rule.effect !== pending.before) {
          return error("Der Entwurf bezieht sich auf einen früheren Regelstand. Verwirf ihn und prüfe die aktuelle Regel.", "This draft references an earlier rule state. Reject it and review the current rule.");
        }
      }
      const record = { ...pending, status: decision === "approve" ? "applied" : "rejected", decidedAt: new Date().toISOString() };
      const next = [...journal];
      next[index] = record;
      return storeJournal(next, record);
    });
  }

  function records(state) {
    return (readJournal() ?? []).filter((record) => visibleRecord(state, record));
  }

  window.addEventListener("storage", (event) => {
    if (event.key === storageKey || event.key === null) announce();
  });

  window.opstendNetworkRules = { list, get, preview, queue, decide, records };
})();
