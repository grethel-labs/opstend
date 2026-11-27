(function () {
  "use strict";

  const storageKey = "opstend-rc2-inventory-v1";
  const seed = {
    hosts: [
      { id: "nuc-a", name: "nuc-a", site: "Werkstatt", ip: "10.20.10.11", runtime: "Proxmox VE", type: "PVE" },
      { id: "host-b", name: "host-b", site: "Werkstatt", ip: "10.20.10.12", runtime: "Ubuntu · Podman", type: "Linux" },
      { id: "nuc-c", name: "nuc-c", site: "Werkstatt", ip: "10.20.10.13", runtime: "Ubuntu · Podman", type: "Linux" },
      { id: "nuc-d", name: "nuc-d", site: "Werkstatt", ip: "10.20.10.14", runtime: "Ubuntu · Podman", type: "Linux", status: "Wartung" },
      { id: "edge-01", name: "edge-01", site: "Extern", ip: "10.31.0.5", runtime: "Ubuntu · Podman", type: "Linux" },
    ],
    services: [
      { id: "medien", name: "Medien", kind: "VM · QEMU", host: "nuc-a", ip: "10.20.20.21", cpu: "4 vCPU", ram: "8 GiB", status: "Gesund", role: "Anwendung",
        pendingNativeChanges: [{ field: "RAM", current: "8 GiB", pending: "10 GiB" }] },
      { id: "fotos", name: "Fotos", kind: "LXC", host: "nuc-a", ip: "10.20.20.22", cpu: "2 vCPU", ram: "2 GiB", status: "Gesund", role: "Anwendung" },
      { id: "entwicklung", name: "Entwicklung", kind: "VM · QEMU", host: "nuc-a", ip: "10.20.20.23", cpu: "4 vCPU", ram: "6 GiB", status: "Gesund", role: "Anwendung" },
      { id: "sensorik", name: "Sensorik", kind: "Container · Podman", host: "host-b", ip: "10.20.20.31", cpu: "2 CPU", ram: "2 GiB", status: "Wird geprüft", role: "Anwendung" },
      { id: "zeitdienst", name: "Zeitdienst", kind: "Container · Podman", host: "host-b", ip: "10.20.20.32", cpu: "1 CPU", ram: "128 MiB", status: "Gesund", role: "Zeit" },
      { id: "https-proxy", name: "HTTPS-Proxy", kind: "Container · Podman", host: "edge-01", ip: "10.31.0.10", network: "VPN", cpu: "1 CPU", ram: "512 MiB", status: "Gesund", role: "Veröffentlichung" },
      { id: "control-a", name: "Steuerung A", kind: "LXC", host: "nuc-a", ip: "10.20.20.61", cpu: "1 vCPU", ram: "1 GiB", status: "Gesund", role: "Steuerung", group: "OpsTend Steuerung", instance: "Aktiv",
        nativeHaManaged: true },
      { id: "control-b", name: "Steuerung B", kind: "Container · Podman", host: "host-b", ip: "10.20.20.62", cpu: "1 CPU", ram: "1 GiB", status: "Gesund", role: "Steuerung", group: "OpsTend Steuerung", instance: "Standby" },
      { id: "control-c", name: "Steuerung C", kind: "Container · Podman", host: "nuc-c", ip: "10.20.20.63", cpu: "1 CPU", ram: "1 GiB", status: "Gesund", role: "Steuerung", group: "OpsTend Steuerung", instance: "Standby" },
      { id: "web", name: "OpsTend Web", kind: "Container · Podman", host: "nuc-c", ip: "10.20.20.64", cpu: "1 CPU", ram: "512 MiB", status: "Gesund", role: "Weboberfläche" },
      { id: "zorec", name: "Zorec", kind: "Container · Podman", host: "host-b", ip: "10.20.20.65", cpu: "2 CPU", ram: "2 GiB", status: "Gesund", role: "Assistenz" },
      { id: "ipa", name: "IPA / DNS", kind: "LXC", host: "nuc-a", ip: "10.20.20.66", cpu: "2 vCPU", ram: "2 GiB", status: "Gesund", role: "Identität" },
    ].map((service) => ({ network: "VLAN 20", ...service })),
    devices: [
      { id: "gateway", name: "UniFi Cloud Gateway", site: "Werkstatt", kind: "Gateway", ip: "10.20.10.1" },
      { id: "switch", name: "sw-werkstatt", site: "Werkstatt", kind: "Switch", ip: "10.20.10.2" },
      { id: "nas", name: "Pi-NAS", site: "Werkstatt", kind: "NAS", ip: "10.20.30.10" },
    ],
    links: [
      { id: "gateway-switch", from: "gateway", to: "switch", layer: "physical", label: "P1 · 10 Gbit/s" },
      { id: "link-nuc-a", from: "switch", to: "nuc-a", layer: "physical", label: "P2 · 10 Gbit/s" },
      { id: "link-host-b", from: "switch", to: "host-b", layer: "physical", label: "P3 · 2,5 Gbit/s" },
      { id: "link-nas", from: "switch", to: "nas", layer: "physical", label: "P4 · 2,5 Gbit/s" },
      { id: "link-nuc-c", from: "switch", to: "nuc-c", layer: "physical", label: "P5 · 2,5 Gbit/s" },
      { id: "link-nuc-d", from: "switch", to: "nuc-d", layer: "physical", label: "P6 · 2,5 Gbit/s" },
      { id: "nfs-probe", from: "medien", to: "nas", layer: "network", label: "NFS · TCP 2049 geprüft" },
      { id: "web-control", from: "web", to: "control-a", layer: "network", label: "Steuer-API · TLS" },
      { id: "zorec-control", from: "zorec", to: "control-a", layer: "network", label: "Beobachtungen · API" },
      { id: "ipa-control", from: "control-a", to: "ipa", layer: "network", label: "Identität · DNS" },
      { id: "edge-tunnel", from: "edge-01", to: "host-b", layer: "access", label: "WireGuard · Tunnel" },
      { id: "fotos-release", from: "https-proxy", to: "fotos", layer: "access", label: "HTTPS · veröffentlichte Website" },
    ],
    networks: [
      { id: "management", name: "VLAN 10 · Verwaltung", cidr: "10.20.10.0/24" },
      { id: "services", name: "VLAN 20 · Dienste", cidr: "10.20.20.0/24" },
      { id: "storage", name: "VLAN 30 · Speicher", cidr: "10.20.30.0/24" },
    ],
    domains: [{ id: "workshop", name: "werkstatt.example" }],
    secretRefs: [
      { id: "registry-reader", name: "Keystore · registry-reader" },
      { id: "application-database", name: "Keystore · application-database" },
    ],
    changes: [],
  };

  const configuredLinkDetails = new Map([
    ["web-control", ["Steuerungsprofil", "Hinterlegter Aufruf der Steuer-API über TLS."]],
    ["zorec-control", ["Steuerungsprofil", "Hinterlegter API-Pfad zum Melden von Beobachtungen."]],
    ["ipa-control", ["Identitätsprofil", "Hinterlegte Zuordnung für Identität und DNS."]],
    ["edge-tunnel", ["VPN-Profil", "Hinterlegter WireGuard-Pfad zwischen den Standorten."]],
    ["fotos-release", ["Proxy-Profil", "Hinterlegte HTTPS-Weiterleitung vom Proxy zum LXC Fotos."]],
  ]);
  const seedLinks = new Map(seed.links.map((link) => [link.id, link]));
  const seedAddresses = new Map([...seed.hosts, ...seed.services, ...seed.devices].map((item) => [item.id, item.ip]));
  const portDefaults = new Map([
    ["gateway-switch", { mode: "trunk", nativeVlan: "management", taggedVlans: ["services", "storage"] }],
    ["link-nuc-a", { mode: "trunk", nativeVlan: "management", taggedVlans: ["services"] }],
    ["link-host-b", { mode: "trunk", nativeVlan: "management", taggedVlans: ["services"] }],
    ["link-nas", { mode: "access", nativeVlan: "storage", taggedVlans: [] }],
    ["link-nuc-c", { mode: "trunk", nativeVlan: "management", taggedVlans: ["services"] }],
    ["link-nuc-d", { mode: "trunk", nativeVlan: "management", taggedVlans: ["services"] }],
  ]);

  function savedInventory() {
    try {
      const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
      if (saved && Object.keys(seed).every((key) => Array.isArray(saved[key]))) {
        for (const host of saved.hosts) {
          const fallback = seed.hosts.find((item) => item.id === host.id);
          if (host.status === undefined && fallback?.status) host.status = fallback.status;
        }
        for (const service of saved.services) {
          const fixture = seed.services.find((item) => item.id === service.id);
          if (service.pendingNativeChanges === undefined && fixture?.pendingNativeChanges) {
            service.pendingNativeChanges = structuredClone(fixture.pendingNativeChanges);
          }
          if (service.nativeHaManaged === undefined && fixture?.nativeHaManaged) service.nativeHaManaged = true;
        }
        return saved;
      }
    } catch {}
    return null;
  }

  function load() {
    return savedInventory() ?? structuredClone(seed);
  }

  let inventory = load();
  const entities = () => [...inventory.hosts, ...inventory.services, ...inventory.devices];
  const validIp = (value) => /^[0-9]{1,3}([.][0-9]{1,3}){3}$/.test(value)
    && value.split(".").every((part) => Number(part) <= 255 && String(Number(part)) === part);
  const text = (value, maximum) => typeof value === "string" ? value.trim().slice(0, maximum) : "";

  function persist(next = inventory) {
    try {
      localStorage.setItem(storageKey, JSON.stringify(next));
      return true;
    } catch {
      return false;
    }
  }

  function linkEvidence(link) {
    const publication = window.opstendPublications?.evidence(link);
    if (publication) return publication;
    const baseline = seedLinks.get(link.id);
    if (!baseline) return {
      type: "Unbekannt", source: "Demo-Inventar", detail: "Für diese Verbindung steht ein Beispielbeleg aus.",
    };
    const probe = baseline.id === "nfs-probe";
    const addressesChanged = probe && entities()
      .some((item) => (item.id === link.from || item.id === link.to) && item.ip !== seedAddresses.get(item.id));
    if (link.evidenceStale || addressesChanged || link.from !== baseline.from || link.to !== baseline.to
      || link.label !== baseline.label || link.layer !== baseline.layer) {
      return {
        type: "Entwurf", source: "Demo-Inventar", detail: "Für diese Fassung steht eine erneute Beobachtung oder Prüfung aus.",
      };
    }
    if (baseline.layer === "physical") {
      const [port, rate] = baseline.label.split(" · ");
      return {
        type: "Link-Beobachtung", source: "UniFi · Beispieldaten",
        detail: "Historische Beispielbeobachtung des Ethernet-Links.",
        observedAt: "2026-11-26T14:00:00+01:00", port, rate,
      };
    }
    if (probe) {
      const observed = { source: "OpsTend-Prüfpunkt · Beispieldaten", observedAt: "2026-11-26T14:03:00+01:00" };
      const rule = window.opstendNetworkRules?.get({ inventory, host: "" }, "storage-nfs");
      if (rule?.revision > 0) return { ...observed, type: "Historische Verbindungsprüfung",
        label: "NFS · TCP 2049 · erneute Prüfung offen", labelEn: "NFS · TCP 2049 · recheck pending",
        detail: "Die Beispielprobe bezieht sich auf den früheren Regelstand. Für die aktuelle Revision steht eine neue Prüfung aus.",
        detailEn: "The sample check applies to the previous rule. A new check is pending for the current revision." };
      return { ...observed, type: "Verbindungsprüfung", detail: "Der Beispiel-Prüfpunkt Medien erreichte am Pi-NAS den TCP-Port 2049." };
    }
    const [source, detail] = configuredLinkDetails.get(baseline.id);
    return { type: "Konfigurierte Beziehung", source: source + " · Beispieldaten", detail };
  }

  function linkLabel(link) {
    const evidence = linkEvidence(link);
    return evidence.label ? window.opstendLocale.t(evidence.label, evidence.labelEn) : link.label;
  }

  function updateEntity(id, patch) {
    const latest = savedInventory() ?? structuredClone(inventory);
    const currentEntities = [...latest.hosts, ...latest.services, ...latest.devices];
    const entity = currentEntities.find((item) => item.id === id);
    if (!entity) return "Dieses Objekt ist im Inventar nicht vorhanden.";
    const maintenance = maintenanceRestriction(entity.host || id);
    if (maintenance) return maintenance;
    const ip = text(patch.ip, 32);
    if (!validIp(ip)) return "Gib eine gültige IPv4-Adresse ein.";
    if (currentEntities.some((item) => item.id !== id && item.ip === ip)) return "Diese Adresse ist bereits belegt.";
    if (entity.ip !== ip) {
      if (latest.changes.some((job) => job.kind === "runtime" && job.attemptedAt && activeRuntimeStages.has(job.stage)
        && (job.host === id || job.serviceId === id))) {
        return window.opstendLocale.t("Ein Laufzeitauftrag für dieses Ziel wird noch ausgewertet.",
          "A runtime job is still awaiting a result for this target.");
      }
      const probe = latest.links.find((link) => link.id === "nfs-probe");
      if (probe && (probe.from === id || probe.to === id)) probe.evidenceStale = true;
    }
    entity.ip = ip;
    if (!persist(latest)) return "Die Adresse konnte im Browser nicht gespeichert werden.";
    inventory = latest;
    return true;
  }

  function updateLink(id, patch) {
    if (window.opstendPublications?.list({ inventory }).some(({ linkId }) => linkId === id)) return window.opstendLocale.t(
      "Ändere diesen Zugang über den Veröffentlichungsauftrag.", "Change this access path through the publication job.");
    const link = inventory.links.find((item) => item.id === id);
    if (!link) return "Diese Verbindung ist im Inventar nicht vorhanden.";
    const label = text(patch.label, 90);
    const from = patch.from ?? link.from;
    const to = patch.to ?? link.to;
    const known = new Set(entities().map((item) => item.id));
    if (!label) return "Gib der Verbindung eine Beschriftung.";
    if (from === to || !known.has(from) || !known.has(to)) return "Wähle zwei unterschiedliche vorhandene Endpunkte.";
    if (from !== link.from || to !== link.to || label !== link.label) link.evidenceStale = true;
    Object.assign(link, { from, to, label });
    persist();
    return true;
  }

  function normalizePortProfile(input, networks) {
    if (!input || !["access", "trunk"].includes(input.mode)) {
      return { ok: false, error: "Wähle Access oder Trunk als Portmodus." };
    }
    const known = new Set(networks.map((network) => network.id));
    if (!known.has(input.nativeVlan)) return { ok: false, error: "Wähle ein vorhandenes ungetaggtes VLAN." };
    const tags = input.taggedVlans;
    if (!Array.isArray(tags) || tags.some((tag) => !known.has(tag))) {
      return { ok: false, error: "Wähle nur vorhandene VLANs als getaggte VLANs." };
    }
    if (input.mode === "access" && tags.length) {
      return { ok: false, error: "Getaggte VLANs sind für den Trunk-Modus verfügbar." };
    }
    if (new Set(tags).size !== tags.length || tags.includes(input.nativeVlan)) {
      return { ok: false, error: "Jedes VLAN darf nur einmal pro Port zugeordnet sein." };
    }
    return {
      ok: true,
      profile: { mode: input.mode, nativeVlan: input.nativeVlan, taggedVlans: [...tags].sort() },
    };
  }

  function portConfiguration(id, snapshot = inventory) {
    const defaults = portDefaults.get(id);
    const link = snapshot.links.find((item) => item.id === id);
    if (!defaults || !link) return null;
    const baseline = seedLinks.get(id);
    const [port] = baseline.label.split(" · ");
    const stored = link.portProfile;
    const current = normalizePortProfile(stored?.current ?? defaults, snapshot.networks);
    const previous = stored?.previous && normalizePortProfile(stored.previous, snapshot.networks);
    const revision = stored?.revision ?? 0;
    let reason = "";
    if (id === "gateway-switch") reason = "Der Uplink zum Gateway ist im Demo-Inventar schreibgeschützt.";
    else if (linkEvidence(link).type !== "Link-Beobachtung") {
      reason = "Für diese Fassung der physischen Verbindung steht die Beobachtung aus.";
    } else if (!current.ok || !Number.isSafeInteger(revision) || revision < 0) {
      reason = "Im Demo-Inventar fehlt eine gültige Portzuordnung.";
    }
    const deviceId = "switch";
    return {
      id, port, deviceId, peerId: baseline.from === deviceId ? baseline.to : baseline.from,
      revision: Number.isSafeInteger(revision) && revision >= 0 ? revision : 0,
      editable: !reason,
      ...(reason ? { reason } : {}),
      current: current.ok ? current.profile : structuredClone(defaults),
      ...(previous?.ok ? { previous: previous.profile } : {}),
    };
  }

  function previewPortChange(id, input, snapshot = inventory) {
    const port = portConfiguration(id, snapshot);
    if (!port) return { ok: false, error: "Dieser Switchport ist im Inventar nicht vorhanden." };
    if (!port.editable) return { ok: false, error: port.reason };
    const result = normalizePortProfile(input, snapshot.networks);
    if (!result.ok) return result;
    const before = port.current;
    const after = result.profile;
    const changed = before.mode !== after.mode || before.nativeVlan !== after.nativeVlan
      || before.taggedVlans.join(",") !== after.taggedVlans.join(",");
    return { ok: true, port, before, after, changed };
  }

  function applyPortChange(id, input, expectedRevision) {
    const latest = savedInventory() ?? inventory;
    const preview = previewPortChange(id, input, latest);
    if (!preview.ok) return preview.error;
    const { port, before, after } = preview;
    if (port.revision !== expectedRevision) return "Die Portzuordnung wurde seit der Vorschau geändert. Prüfe die Änderung erneut.";
    if (!preview.changed) return true;
    const revision = port.revision + 1;
    const link = latest.links.find((item) => item.id === id);
    link.portProfile = { revision, current: after, previous: before };
    const device = latest.devices.find((item) => item.id === port.deviceId);
    const host = latest.hosts.find((item) => item.id === port.peerId);
    latest.changes.unshift({
      id: "network-port-" + crypto.randomUUID(), kind: "network-port", portId: id,
      ...(host ? { host: host.id } : {}),
      name: `${device?.name ?? port.deviceId} · ${port.port}`, status: "VLAN-Zuordnung im Browser gespeichert",
      at: new Date().toISOString(), before, after, revision,
    });
    inventory = latest;
    persist();
    return true;
  }

  const sensorikAdapter = {
    title: "Sensorik-Adapter",
    version: "1.0.0",
    fields: [
      { id: "intervalSeconds", label: "Messintervall (Sekunden)", type: "integer", default: 30, min: 5, max: 3600 },
      { id: "reportMode", label: "Meldemodus", type: "select", default: "changes",
        options: [["changes", "Bei Änderungen"], ["interval", "Bei jedem Intervall"]] },
      { id: "includeBattery", label: "Batteriestand miterfassen", type: "boolean", default: true },
      { id: "displayName", label: "Messstellenname", type: "text", default: "Werkstatt", min: 1, max: 48,
        help: "Wird in Meldungen zur Messstelle angezeigt." },
    ],
  };
  const sensorikNextAdapter = {
    ...sensorikAdapter,
    version: "1.1.0",
    fields: [
      ...sensorikAdapter.fields.map((field) => field.id === "reportMode"
        ? { ...field, id: "deliveryMode", label: "Meldestrategie" } : field),
      { id: "retryLimit", label: "Wiederholungsversuche", type: "integer", default: 3, min: 0, max: 12 },
    ],
  };
  const sensorikRepositories = new Set([
    "https://git.example/werkstatt/sensorik-api.git",
    "https://git.example/werkstatt/sensorik-web.git",
  ]);

  function adapterSchema(service) {
    if (service?.id === "sensorik" || service?.repositories?.some((url) => sensorikRepositories.has(url))) {
      return service.adapterSettings?.version === sensorikNextAdapter.version ? sensorikNextAdapter : sensorikAdapter;
    }
    return null;
  }

  function normalizeSetting(field, value) {
    switch (field.type) {
      case "boolean":
        if (value === true || value === "true") return true;
        if (value === false || value === "false") return false;
        return undefined;
      case "integer": {
        const number = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value;
        if (Number.isSafeInteger(number) && number >= field.min && number <= field.max) return number;
        return undefined;
      }
      case "select":
        return field.options.some(([option]) => option === value) ? value : undefined;
      case "text": {
        if (typeof value !== "string") return undefined;
        const trimmed = value.trim();
        return trimmed.length >= field.min && trimmed.length <= field.max ? trimmed : undefined;
      }
      default:
        return undefined;
    }
  }

  function currentAdapterValues(service, schema) {
    const saved = service.adapterSettings?.version === schema.version ? service.adapterSettings.values : null;
    return Object.fromEntries(schema.fields.map((field) => [
      field.id, normalizeSetting(field, saved?.[field.id]) ?? field.default,
    ]));
  }

  function adapterSettings(service) {
    const schema = adapterSchema(service);
    if (!schema) return null;
    const saved = service.adapterSettings;
    const revision = saved?.version === schema.version && Number.isSafeInteger(saved.revision) && saved.revision >= 0
      ? saved.revision : 0;
    return { ...structuredClone(schema), values: currentAdapterValues(service, schema), revision };
  }

  function previewAdapterSettings(service, input) {
    const adapter = adapterSettings(service);
    if (!adapter) return { ok: false, error: "Für diesen Dienst sind keine Adaptereinstellungen hinterlegt." };
    if (!input || typeof input !== "object" || Object.keys(input).length !== adapter.fields.length) {
      return { ok: false, error: "Gib die Felder aus dem aktuellen Adaptervertrag an." };
    }
    const values = {};
    const changes = [];
    for (const field of adapter.fields) {
      const value = Object.hasOwn(input, field.id) ? normalizeSetting(field, input[field.id]) : undefined;
      if (value === undefined) return { ok: false, error: `Prüfe die Eingabe für „${field.label}“.` };
      values[field.id] = value;
      const before = adapter.values[field.id];
      if (before !== value) changes.push({ label: field.label, before, after: value });
    }
    return { ok: true, adapter, values, changes, revision: adapter.revision };
  }

  function updateAdapterSettings(id, input, expectedRevision) {
    const latest = expectedRevision === undefined ? inventory : savedInventory() ?? inventory;
    const service = latest.services.find((item) => item.id === id);
    if (service && expectedRevision !== undefined && expectedRevision !== adapterSettings(service)?.revision) {
      return "Die Einstellungen wurden seit der Vorschau geändert. Erstelle eine neue Vorschau.";
    }
    const preview = previewAdapterSettings(service, input);
    if (!preview.ok) return preview.error;
    if (preview.changes.length === 0) return true;
    const version = preview.adapter.version;
    const revision = preview.revision + 1;
    service.adapterSettings = { ...service.adapterSettings, version, revision, values: preview.values };
    inventory = latest;
    inventory.changes.unshift({
      id: "service-config-" + crypto.randomUUID(), kind: "service-config", serviceId: service.id,
      host: service.host, name: service.name, status: "Einstellungsentwurf gespeichert", at: new Date().toISOString(),
      adapterVersion: version, adapterRevision: revision, changes: preview.changes,
    });
    persist();
    return true;
  }

  function adapterValueLabel(field, value) {
    if (field.type === "boolean") return value ? "Ja" : "Nein";
    if (field.type === "select") return field.options.find(([key]) => key === value)?.[1] ?? String(value);
    return String(value);
  }

  function adapterTransition(service, action) {
    const current = adapterSettings(service);
    if (!current) return { preview: { ok: false, error: "Für diesen Dienst ist kein Adapterwechsel verfügbar." } };
    const upgrading = action === "upgrade" && current.version === sensorikAdapter.version;
    const rollback = service.adapterSettings?.rollback;
    const rollingBack = action === "rollback" && current.version === sensorikNextAdapter.version
      && rollback?.version === sensorikAdapter.version;
    if (!upgrading && !rollingBack) {
      return { preview: { ok: false, error: "Für diese Adapterversion ist die gewählte Aktion nicht verfügbar." } };
    }

    const target = upgrading ? sensorikNextAdapter : sensorikAdapter;
    const from = { version: current.version, revision: current.revision };
    const to = { version: target.version, revision: current.revision + 1 };
    const values = {};
    const rows = [];
    const retained = new Set();
    for (const field of target.fields) {
      const previousId = field.id === "deliveryMode" ? "reportMode" : field.id === "reportMode" ? "deliveryMode" : field.id;
      const previous = current.fields.find((item) => item.id === previousId);
      const before = current.values[previousId];
      const value = normalizeSetting(field, upgrading ? before ?? field.default : rollback.values?.[field.id]);
      if (value === undefined) {
        return { preview: { ok: false, error: `Für „${field.label}“ fehlt ein gültiger Migrationswert.` } };
      }
      values[field.id] = value;
      if (previous) retained.add(previousId);
      const renamed = previous && previous.id !== field.id;
      rows.push({
        label: renamed ? `${previous.label} → ${field.label}` : field.label,
        before: previous ? adapterValueLabel(previous, before) : "—",
        after: adapterValueLabel(field, value),
        note: !previous ? "Neue Vorgabe" : renamed ? "Umbenannt" : before === value ? "Unverändert" : "Wiederhergestellt",
      });
    }
    for (const field of current.fields) {
      if (!retained.has(field.id)) rows.push({
        label: field.label,
        before: adapterValueLabel(field, current.values[field.id]),
        after: "—",
        note: "Entfällt",
      });
    }
    return {
      preview: { ok: true, action, from, to, rows },
      settings: {
        ...to, values,
        ...(upgrading ? { rollback: { version: from.version, values: current.values } } : {}),
      },
    };
  }

  function previewAdapterTransition(service, action) {
    return adapterTransition(service, action).preview;
  }

  function applyAdapterTransition(id, action, expectedVersion, expectedRevision) {
    const latest = savedInventory() ?? inventory;
    const service = latest.services.find((item) => item.id === id);
    const current = adapterSettings(service);
    if (!current) return "Für diesen Dienst ist kein Adapterwechsel verfügbar.";
    if (current.version !== expectedVersion || current.revision !== expectedRevision) {
      return "Die Adapterversion oder Konfiguration wurde seit der Vorschau geändert. Erstelle eine neue Vorschau.";
    }
    const { preview, settings } = adapterTransition(service, action);
    if (!preview.ok) return preview.error;
    service.adapterSettings = settings;
    inventory = latest;
    inventory.changes.unshift({
      id: "service-adapter-" + crypto.randomUUID(), kind: "service-adapter", serviceId: service.id,
      host: service.host, name: service.name, status: action === "upgrade" ? "Adapter-Update simuliert" : "Adapter-Rollback simuliert",
      at: new Date().toISOString(), action, from: preview.from, to: preview.to, rows: preview.rows,
    });
    persist();
    return true;
  }

  function createService(draft) {
    const name = text(draft.name, 70);
    if (!name) return { ok: false, error: "Gib dem Dienst einen Namen." };
    if (inventory.services.some((service) => service.name.toLowerCase() === name.toLowerCase() && service.status !== "Stillgelegt")) {
      return { ok: false, error: "Es gibt bereits einen Dienst mit diesem Namen." };
    }
    if (!inventory.hosts.some((host) => host.id === draft.host)) return { ok: false, error: "Wähle einen Host aus dem Inventar." };
    const maintenance = maintenanceRestriction(draft.host);
    if (maintenance) return { ok: false, error: maintenance };
    const ip = text(draft.ip, 32);
    if (ip && (!validIp(ip) || entities().some((item) => item.ip === ip))) {
      return { ok: false, error: "Die IPv4-Adresse ist ungültig oder bereits belegt." };
    }
    const repositories = Array.isArray(draft.repositories) ? draft.repositories.slice(0, 8) : [];
    if (repositories.length === 0) return { ok: false, error: "Wähle mindestens ein Repository." };
    const candidate = { repositories };
    if (draft.adapterVersion !== undefined && draft.adapterVersion !== adapterSchema(candidate)?.version) {
      return { ok: false, error: "Die Adapterversion hat sich geändert. Erstelle eine neue Vorschau." };
    }
    let settings;
    if (draft.adapterValues !== undefined) {
      const preview = previewAdapterSettings(candidate, draft.adapterValues);
      if (!preview.ok) return preview;
      settings = { version: preview.adapter.version, revision: preview.revision, values: preview.values };
    }
    const id = `deployment-${crypto.randomUUID().slice(0, 8)}`;
    inventory.services.push({
      id, name, host: draft.host, kind: text(draft.kind, 60) || "Container · Podman", ip,
      network: text(draft.network, 60) || "VLAN 20", role: text(draft.role, 60) || "Anwendung",
      status: "Vorgemerkt", cpu: "Geplant", ram: "Geplant",
      repositories, adapter: draft.adapter || {}, updates: draft.updates || false,
      ...(settings ? { adapterSettings: settings } : {}),
    });
    persist();
    return { ok: true, id };
  }

  const guestProfileCatalog = {
    PVE: [
      { id: "pve-qemu", title: "Debian-VM", kind: "VM · QEMU", cpu: 2, ram: 4, disk: 32, store: "local-lvm" },
      { id: "pve-lxc", title: "Debian-Container", kind: "LXC", cpu: 2, ram: 2, disk: 12, store: "local-lvm" },
    ],
    Linux: [
      { id: "linux-podman", title: "Podman-Basiscontainer", kind: "Container · Podman", cpu: 1, ram: 1, disk: 8, store: "Lokaler Container-Speicher" },
    ],
  };

  function profilesForHost(hostId, snapshot) {
    const type = snapshot.hosts.find((host) => host.id === hostId)?.type;
    return Object.hasOwn(guestProfileCatalog, type) ? guestProfileCatalog[type] : [];
  }

  function guestProfiles(hostId) {
    return structuredClone(profilesForHost(hostId, inventory));
  }

  function provisionPlan(input, snapshot) {
    const name = typeof input?.name === "string" ? input.name.trim() : "";
    if (!name || name.length > 70) return { ok: false, error: "Gib einen Gastnamen mit höchstens 70 Zeichen an." };
    const maintenance = maintenanceRestriction(input.host);
    if (maintenance) return { ok: false, error: maintenance };
    if (snapshot.services.some((item) => item.name.toLowerCase() === name.toLowerCase() && item.status !== "Stillgelegt")) {
      return { ok: false, error: "Im Inventar gibt es bereits einen Gast oder Dienst mit diesem Namen." };
    }
    const template = profilesForHost(input.host, snapshot).find((profile) => profile.id === input.templateId);
    if (!template) return { ok: false, error: "Wähle eine freigegebene Vorlage für den Zielhost." };
    const network = snapshot.networks.find((item) => item.id === input.networkId);
    if (!network) return { ok: false, error: "Wähle ein Netzwerk aus dem Inventar." };

    const resources = {};
    for (const [key, label, max] of [["cpu", "CPU", 16], ["ram", "RAM", 64], ["disk", "Speichergröße", 512]]) {
      const raw = input[key];
      const value = typeof raw === "string" && /^\d+$/.test(raw) ? Number(raw) : raw;
      if (!Number.isSafeInteger(value) || value < 1 || value > max) {
        return { ok: false, error: `${label} muss eine ganze Zahl zwischen 1 und ${max} sein.` };
      }
      resources[key] = value;
    }
    if (typeof input.start !== "boolean") return { ok: false, error: "Wähle den Laufzustand nach dem Anlegen." };
    return {
      ok: true,
      plan: {
        name, host: input.host, templateId: template.id, templateTitle: template.title,
        kind: template.kind, ...resources, store: template.store,
        networkId: network.id, network: network.name.split(" · ")[0], start: input.start,
      },
    };
  }

  function previewGuest(input) {
    return provisionPlan(input, inventory);
  }

  function createGuest(input) {
    const latest = savedInventory() ?? inventory;
    const result = provisionPlan(input, latest);
    if (!result.ok) return result;
    const plan = result.plan;
    const id = `provisioned-${crypto.randomUUID()}`;
    const cpuUnit = plan.kind === "Container · Podman" ? "CPU" : "vCPU";
    latest.services.push({
      id, name: plan.name, host: plan.host, kind: plan.kind, network: plan.network,
      ip: "", role: "Anwendung", status: "Vorgemerkt", cpu: `${plan.cpu} ${cpuUnit}`, ram: `${plan.ram} GiB`,
      provisioning: {
        templateId: plan.templateId, templateTitle: plan.templateTitle, plannedAt: new Date().toISOString(),
        start: plan.start, disk: plan.disk, store: plan.store,
      },
    });
    inventory = latest;
    persist();
    return { ok: true, id, jobId: `guest-${id}`, host: plan.host };
  }

  function finishGuestProvision(id) {
    const latest = savedInventory() ?? inventory;
    const service = latest.services.find((item) => item.id === id);
    if (!service?.provisioning) return "Dieser Gast hat keinen Anlageauftrag.";
    if (service.provisioning.readbackAt) return true;
    const maintenance = maintenanceRestriction(service.host);
    if (maintenance) return maintenance;
    if (service.status !== "Vorgemerkt") return "Der Anlageauftrag ist im aktuellen Zustand nicht ausführbar.";
    service.power = service.provisioning.start ? "running" : "stopped";
    service.status = service.provisioning.start ? "Health offen" : "Gestoppt";
    service.provisioning.readbackAt = new Date().toISOString();
    inventory = latest;
    persist();
    return true;
  }

  function retireService(id, removal = false) {
    const latest = savedInventory() ?? structuredClone(inventory);
    const service = latest.services.find((item) => item.id === id);
    if (!service || service.group) return "Diese Instanz wird durch ihre Dienstgruppe verwaltet.";
    const maintenance = maintenanceRestriction(service.host);
    if (maintenance) return maintenance;
    if (pendingRuntime(id, latest)) return window.opstendLocale.t(
      "Schließe zuerst den offenen Laufzeitauftrag ab.", "Finish the open runtime job first.");
    if (removal && service.status !== "Stillgelegt") return "Lege den Dienst zuerst still.";
    if (!removal && ["Stillgelegt", "Entfernung vorgemerkt"].includes(service.status)) return "Der Dienst ist bereits stillgelegt.";
    service.status = removal ? "Entfernung vorgemerkt" : "Stillgelegt";
    service.power = "stopped";
    latest.changes.unshift({ id: `${removal ? "remove" : "retire"}-${id}`, host: service.host, name: service.name, status: service.status });
    if (!persist(latest)) return "Die Änderung konnte im Browser nicht gespeichert werden.";
    inventory = latest;
    return true;
  }

  const runtimeLabels = { start: "Starten", stop: "Geordnet stoppen", restart: "Neu starten" };
  const runtimeTransitions = {
    dispatch: { from: "queued", to: "dispatched" },
    "lose-response": { from: "queued", to: "reconcile" },
    "reconcile-task": { from: "reconcile", to: "dispatched" },
    "task-pass": { from: "dispatched", to: "readback" },
    "task-fail": { from: "dispatched", to: "failed" },
    "confirm-state": { from: "readback", to: "finished" },
    cancel: { from: "queued", to: "canceled" },
  };
  const activeRuntimeStages = new Set(["queued", "dispatched", "reconcile", "readback"]);
  const runtimeStatuses = {
    queued: "Vorgemerkt", dispatched: "Ausführung läuft", reconcile: "Abgleich erforderlich",
    readback: "Rückmeldung offen", finished: "Simuliert", failed: "Fehlgeschlagen", canceled: "Abgebrochen",
  };
  const recoveryStatus = { pending: "Wird geprüft", failed: "Warnung", healthy: "Gesund" };
  const recoveryTransitions = {
    "probe-pass": { from: "pending", to: "healthy" },
    "probe-fail": { from: "pending", to: "failed" },
    retry: { from: "failed", to: "pending" },
  };

  function recoveryFor(service) {
    if (service?.id !== "sensorik") return null;
    const stored = service.recovery;
    const phase = stored?.phase ?? "pending";
    const revision = Number.isSafeInteger(stored?.revision) && stored.revision >= 0 ? stored.revision : 0;
    const current = Object.hasOwn(recoveryStatus, phase) && service.status === recoveryStatus[phase];
    return {
      phase: current ? phase : "historical",
      revision,
      events: Array.isArray(stored?.events) ? structuredClone(stored.events) : [],
    };
  }

  function recoveryAutonomy(service) {
    const recovery = recoveryFor(service);
    const decision = (ok, de, en) => ({ ok, reason: [de, en] });
    if (!recovery || service.host !== "host-b" || service.ip !== seedAddresses.get("sensorik") || serviceRuntime(service) !== "running") {
      return decision(false, "Der Dienst entspricht nicht dem registrierten Prüfziel auf host-b.",
        "The service does not match the registered target on host-b.");
    }
    if (recovery.events.some(({ action }) => action === "retry")) {
      return decision(false, "Für diesen Vorfall wurde bereits eine weitere Health-Prüfung gestartet.",
        "Another health check has already been started for this incident.");
    }
    const failure = recovery.events.at(-1);
    if (recovery.phase !== "failed" || recovery.revision !== 1 || recovery.events.length !== 1
        || failure?.action !== "probe-fail" || !Number.isFinite(Date.parse(failure.at))) {
      return decision(false, "Der erste fehlgeschlagene Prüfbeleg fehlt oder ist überholt.",
        "The first failed check result is missing or outdated.");
    }
    return decision(true, "Die Richtlinie erlaubt nach dem ersten Fehlschlag eine weitere Health-Prüfung.",
      "Policy allows one additional health check after the first failure.");
  }

  function commitRecovery(id, action, expectedRevision, actor) {
    const latest = savedInventory() ?? structuredClone(inventory);
    const service = latest.services.find((item) => item.id === id);
    const current = recoveryFor(service);
    if (!current || !Object.hasOwn(recoveryTransitions, action)) return "Dieser Prüfauftrag ist im Beispiel nicht verfügbar.";
    const maintenance = maintenanceRestriction(service.host);
    if (maintenance) return maintenance;
    if (pendingRuntime(id, latest)) return "Schließe zuerst den offenen Laufzeitauftrag ab.";
    if (current.revision !== expectedRevision) return "Der Prüfstand hat sich geändert. Öffne den Vorgang erneut.";
    const { from, to } = recoveryTransitions[action];
    if (current.phase !== from) return "Dieser Prüfschritt ist im aktuellen Zustand nicht verfügbar.";
    if (actor === "zorec") {
      const t = window.opstendLocale.t;
      if (action !== "retry" || !window.opstendAutonomy?.effective()) {
        return t("Zorec hat keine automatische Freigabe für diesen Schritt.",
          "Zorec has no automatic approval permission for this step.");
      }
      const policy = recoveryAutonomy(service);
      if (!policy.ok) return t(...policy.reason);
    }
    service.status = recoveryStatus[to];
    service.recovery = {
      phase: to, revision: current.revision + 1,
      events: [...current.events, { action, at: new Date().toISOString(), ...(actor === "zorec" ? { actor } : {}) }],
    };
    if (!persist(latest)) return window.opstendLocale.t(
      "Die Health-Entscheidung konnte im Browser nicht gespeichert werden.",
      "The health check decision could not be saved in this browser.");
    inventory = latest;
    window.dispatchEvent(new CustomEvent("opstend:inventory-changed"));
    return true;
  }

  async function advanceRecovery(id, action, expectedRevision, { actor } = {}) {
    const commit = () => commitRecovery(id, action, expectedRevision, actor);
    return navigator.locks ? navigator.locks.request(storageKey, commit) : commit();
  }

  function serviceRuntime(service) {
    if (["Vorgemerkt", "Ausgefallen"].includes(service.status)) return "unknown";
    if (["Stillgelegt", "Entfernung vorgemerkt", "Gestoppt"].includes(service.status)) return "stopped";
    return service.power === "stopped" ? "stopped" : "running";
  }

  function maintenanceRestriction(host) {
    return window.opstendHostMaintenance?.active(host) ? window.opstendLocale.t(
      "Für diesen Host läuft ein simulierter Neustart. Setze zuerst den Wartungsauftrag fort.",
      "A simulated restart is in progress for this host. Continue the maintenance job first.") : "";
  }

  function pendingRuntime(serviceId, snapshot = inventory, ignoredJobId) {
    return snapshot.changes.find((item) => item.kind === "runtime" && item.serviceId === serviceId
      && item.id !== ignoredJobId && activeRuntimeStages.has(item.stage)) ?? null;
  }

  function runtimeRestriction(service, snapshot = inventory, ignoredJobId) {
    const maintenance = maintenanceRestriction(service.host);
    if (maintenance) return maintenance;
    if (pendingRuntime(service.id, snapshot, ignoredJobId)) return window.opstendLocale.t(
      "Für diese Instanz ist ein Laufzeitauftrag offen.", "A runtime job is open for this instance.");
    if (service.sourceHost) return "Dieser Beispieldienst wird über die Hostverwaltung übernommen oder verschoben.";
    if (service.nativeHaManaged) return window.opstendLocale.t(
      "Für diesen Gast gilt der native HA-Ablauf.", "This guest uses the native HA workflow.");
    if (service.group) return "Die Dienstgruppe steuert diese Instanz.";
    if (service.status === "Wird geprüft") {
      const observation = recoveryFor(service)?.events.at(-1);
      if (observation?.actor === "zorec") return window.opstendLocale.t(
        "Die von Zorec angestoßene Health-Prüfung läuft.", "The health check started by Zorec is running.");
      return observation?.action === "retry" ? "Die manuell angestoßene Health-Prüfung läuft."
        : "Der automatische Wiederanlauf wird noch geprüft.";
    }
    if (service.status === "Vorgemerkt") return "Die Instanz ist als Deployment vorgemerkt.";
    if (["Stillgelegt", "Entfernung vorgemerkt"].includes(service.status)) return "Die Instanz ist stillgelegt.";
    if (serviceRuntime(service) === "unknown") return "Der Laufzustand ist unbekannt.";
    return "";
  }

  const runtimeFailure = (error, errorEn = error) => ({ ok: false, error, errorEn });
  const staleRuntimePlan = () => runtimeFailure("Ziel oder Belegstand der Vorschau hat sich geändert.",
    "The target or observed state from the preview has changed.");

  function runtimePlan(id, operation, snapshot, ignoredJobId) {
    const service = snapshot.services.find((item) => item.id === id);
    const host = service && snapshot.hosts.find((item) => item.id === service.host);
    if (!host || !Object.hasOwn(runtimeLabels, operation)) {
      return runtimeFailure("Der Auftrag passt zu keiner verfügbaren Aktion.", "The job does not match an available action.");
    }
    const restriction = runtimeRestriction(service, snapshot, ignoredJobId);
    if (restriction) return runtimeFailure(restriction);
    const provider = host.type === "PVE" && ["VM · QEMU", "LXC"].includes(service.kind) ? "pve"
      : host.type === "Linux" && service.kind === "Container · Podman" ? "linux" : null;
    if (!provider) {
      return runtimeFailure("Für diese Plattform ist keine passende Demo-Aktion verfügbar.",
        "This platform has no matching demo action.");
    }
    const pending = service.pendingNativeChanges ?? [];
    if (provider === "pve" && operation === "restart" && pending.length) {
      const changes = pending.map(({ field, current, pending: value }) => `${field} ${current} → ${value}`).join(", ");
      return runtimeFailure(`Ein PVE-Neustart würde die vorgemerkte Konfiguration übernehmen (${changes}). Prüfe sie vor dem Neustart.`,
        `A PVE restart would apply the pending configuration (${changes}). Review it before restarting.`);
    }
    const before = serviceRuntime(service);
    if ((before === "stopped") !== (operation === "start")) {
      return runtimeFailure("Der Laufzustand hat sich geändert. Wähle die Aktion erneut.",
        "The runtime state has changed. Select the action again.");
    }
    const after = operation === "stop" ? "stopped" : "running";
    const previous = snapshot.changes.find((item) => item.kind === "runtime" && item.serviceId === service.id && item.id !== ignoredJobId);
    const maintenance = window.opstendHostMaintenance?.latest?.({}, host.id);
    const binding = JSON.stringify([
      operation, provider, service.id, service.name, service.kind, service.ip, before,
      host.id, host.ip, host.runtime, service.provisioning?.readbackAt, service.recovery?.revision,
      service.nativeHaManaged === true, pending, previous?.id, maintenance?.stage === "finished" ? maintenance.id : null,
    ]);
    return { ok: true, plan: { serviceId: service.id, name: service.name, host: host.id, operation, before, after, binding, provider } };
  }

  function previewRuntime(id, operation, snapshot = inventory) {
    return runtimePlan(id, operation, snapshot);
  }

  function commitRuntime(snapshot, job) {
    if (!persist(snapshot)) return runtimeFailure("Der Laufzeitauftrag konnte im Browser nicht gespeichert werden.",
      "The runtime job could not be saved in the browser.");
    inventory = snapshot;
    window.dispatchEvent(new CustomEvent("opstend:inventory-changed"));
    return { ok: true, job: structuredClone(job) };
  }

  async function requestRuntime(reviewed) {
    const request = () => {
      const latest = savedInventory() ?? structuredClone(inventory);
      const current = runtimePlan(reviewed?.serviceId, reviewed?.operation, latest);
      if (!current.ok) return current;
      if (current.plan.binding !== reviewed.binding) return staleRuntimePlan();
      const at = new Date().toISOString();
      const job = { ...current.plan, id: "runtime-" + crypto.randomUUID(), kind: "runtime", stage: "queued",
        revision: 0, at, events: [{ action: "request", at }], status: runtimeStatuses.queued };
      latest.changes.unshift(job);
      return commitRuntime(latest, job);
    };
    return navigator.locks ? navigator.locks.request(storageKey, request) : request();
  }

  async function advanceRuntime(jobId, action, expectedRevision) {
    const advance = () => {
      const latest = savedInventory() ?? structuredClone(inventory);
      const job = latest.changes.find((item) => item.id === jobId && item.kind === "runtime");
      const next = Object.hasOwn(runtimeTransitions, action) ? runtimeTransitions[action] : null;
      if (!job || !next || !Array.isArray(job.events)) return runtimeFailure(
        "Für diesen Auftrag ist der Schritt nicht verfügbar.", "The step is unavailable for this job.");
      if (job.revision !== expectedRevision || job.stage !== next.from) return runtimeFailure(
        "Der Laufzeitauftrag hat sich geändert. Öffne seinen aktuellen Stand.", "The runtime job changed. Open its current state.");
      const firstDispatch = action === "dispatch" || action === "lose-response";
      if (firstDispatch || action === "confirm-state") {
        const current = runtimePlan(job.serviceId, job.operation, latest, job.id);
        if (!current.ok) return current;
        if (current.plan.binding !== job.binding) return staleRuntimePlan();
        if (action === "confirm-state") {
          const service = latest.services.find((item) => item.id === job.serviceId);
          applyRuntimeState(service, current.plan.after);
        }
      }
      const at = new Date().toISOString();
      if (firstDispatch) job.attemptedAt = at;
      if (action === "dispatch" || action === "reconcile-task") {
        job.taskId = `demo-${job.provider}-${job.id.slice("runtime-".length)}`;
      }
      job.stage = next.to;
      job.status = runtimeStatuses[next.to];
      job.revision += 1;
      job.events.push({ action, at });
      return commitRuntime(latest, job);
    };
    return navigator.locks ? navigator.locks.request(storageKey, advance) : advance();
  }

  function applyRuntimeState(service, power) {
    service.power = power;
    service.status = power === "stopped" ? "Gestoppt" : "Health offen";
  }

  function changeRuntime(id, operation) {
    const latest = savedInventory() ?? structuredClone(inventory);
    const current = runtimePlan(id, operation, latest);
    if (!current.ok) return window.opstendLocale.t(current.error, current.errorEn);
    const service = latest.services.find((item) => item.id === id);
    const { before, after } = current.plan;
    const job = {
      id: "runtime-" + crypto.randomUUID(), kind: "runtime", serviceId: service.id, host: service.host, name: service.name,
      operation, before, after, at: new Date().toISOString(), status: "Simuliert",
    };
    applyRuntimeState(service, after);
    latest.changes.unshift(job);
    if (!persist(latest)) return "Die Änderung konnte im Browser nicht gespeichert werden.";
    inventory = latest;
    return true;
  }

  function simulateReplicaFailure() {
    const group = inventory.services.filter((item) => item.group === "OpsTend Steuerung");
    const active = group.find((item) => item.instance === "Aktiv" && item.status === "Gesund");
    const peers = group.filter((item) => item.instance === "Standby" && item.status === "Gesund");
    const placed = new Set(group.map((item) => item.host));
    if (group.some((item) => maintenanceRestriction(item.host))) return window.opstendLocale.t(
      "Für einen Host der Dienstgruppe läuft eine simulierte Wartung.", "Simulated maintenance is in progress for a host in this service group.");
    const replacementHost = inventory.hosts.find((item) => item.site === "Werkstatt" && !placed.has(item.id) && !maintenanceRestriction(item.id));
    if (!active || peers.length < 2 || !replacementHost) return "Im Beispiel stehen keine zwei Standbys und kein weiterer lokaler Host bereit.";
    active.status = "Ausgefallen";
    active.instance = "Gesperrt";
    peers[0].instance = "Aktiv";
    const replacementIp = Array.from({ length: 30 }, (_, index) => `10.20.20.${70 + index}`)
      .find((ip) => !entities().some((item) => item.ip === ip));
    inventory.services.push({
      ...peers[0], id: "control-replacement", name: "Steuerung D", host: replacementHost.id,
      kind: "Container · Podman", ip: replacementIp || "", instance: "Standby",
    });
    for (const link of inventory.links) {
      if (link.layer !== "network") continue;
      if (link.from === active.id) link.from = peers[0].id;
      if (link.to === active.id) link.to = peers[0].id;
    }
    inventory.changes.unshift({ id: "placement-transfer", host: peers[0].host, name: "OpsTend Steuerung", status: "Übernahme simuliert" });
    persist();
    return true;
  }

  window.opstendDemo = {
    getInventory({ fresh = false } = {}) {
      const snapshot = structuredClone(fresh ? savedInventory() ?? inventory : inventory);
      const enrollment = window.opstendHostEnrollment?.projection();
      if (enrollment) {
        snapshot.hosts.push(...enrollment.hosts);
        snapshot.services.push(...enrollment.services);
        snapshot.links.push(...enrollment.links);
        snapshot.changes.unshift(...enrollment.changes);
      }
      const projected = window.opstendHostMaintenance?.project(snapshot) ?? snapshot;
      return window.opstendPublications?.project(projected) ?? projected;
    },
    updateEntity,
    updateLink,
    linkEvidence,
    linkLabel,
    portConfiguration,
    previewPortChange,
    applyPortChange,
    adapterSettings,
    previewAdapterSettings,
    updateAdapterSettings,
    previewAdapterTransition,
    applyAdapterTransition,
    createService,
    guestProfiles,
    previewGuest,
    createGuest,
    finishGuestProvision,
    retireService,
    runtimeLabels,
    maintenanceRestriction,
    serviceRuntime,
    runtimeRestriction,
    previewRuntime,
    requestRuntime,
    advanceRuntime,
    pendingRuntime,
    changeRuntime,
    recoveryFor,
    recoveryAutonomy,
    advanceRecovery,
    simulateReplicaFailure,
  };
  window.addEventListener("storage", (event) => {
    if (event.key !== storageKey) return;
    inventory = load();
    window.dispatchEvent(new CustomEvent("opstend:inventory-changed"));
  });
})();
