(function () {
  "use strict";

  const pages = [
    ["operations", "Betrieb", "Störungen, Entscheidungen und Betriebszustand", ["betriebsübersicht", "startseite", "störungen"]],
    ["overview", "Systemübersicht", "Gemeinsame Sicht auf Hosts, Dienste und Netz", ["flottenübersicht", "systemübersicht"]],
    ["monitoring", "Überwachung", "Messwerte, Auslastung und Datenquellen", ["monitoring", "messwerte", "auslastung", "datenquellen"]],
    ["changes", "Änderungen", "Aufträge, Freigaben und Ausführung", ["auftragsverlauf", "aufträge", "auftragsliste", "änderungen"]],
    ["events", "Ereignisprotokoll", "Protokollierte Schritte und Ereignisse", ["protokoll", "logs", "ereignisse", "historie"]],
    ["inventory", "Inventar", "Hosts, Dienste, Geräte und Ressourcen", ["ressourcenliste", "inventarliste"]],
    ["pve-inventory", "Proxmox-Inventar", "Native Proxmox-Belege und Token-Berechtigungsumfang", ["pve inventar", "proxmox belege", "proxmox inventory"]],
    ["network", "Netzwerk", "Netze, Switches, VLANs, Regeln und Verbindungen", ["netzwerkübersicht", "netzliste", "netzwerke", "netze", "firewall und acl", "firewall", "firewall rules"]],
    ["topology", "Topologie", "Karte der Beziehungen und Platzierungen", ["netzplan", "netzkarte", "infrastrukturkarte", "karte"]],
    ["services", "Dienste", "Dienste, Workloads und Deployments", ["dienstliste", "dienste und deployments", "workloads", "anwendungen"]],
    ["guest-create", "Gast aus Vorlage", "Formular für einen neuen Gast", ["gastvorlage", "gastanlage"]],
  ];

  const settings = [
    ["access", "Zugriff und Rollen", "Benutzerrechte, Anmeldung und Sitzungen", ["benutzerrechte", "zugangsrechte", "zugriffsrechte", "anmeldung", "oidc", "mfa", "meine berechtigungen", "meine rolle", "meine rechte"]],
    ["system", "Darstellung", "Helles und dunkles Farbschema", ["farbschema", "dark mode", "dunkelmodus", "hellmodus", "design"]],
    ["language", "Sprache", "Sprache der Oberfläche und von Zorec", ["spracheinstellungen", "oberflächensprache", "zorecs sprache", "language settings", "display language", "reply language"]],
    ["ai", "Zorec und KI", "Zorecs Shells, Werkzeugfreigaben, Autonomie, Anbieter und Modelle", ["ki einstellungen", "ai einstellungen", "ki konfiguration", "modellkonfiguration", "modellvergleich", "modellanbieter", "ki modell", "werkzeugfreigaben", "admin edit", "admin lesen", "zorec shell", "autonomer modus", "vollautonomer modus", "fully autonomous mode"]],
    ["api", "System-API", "Beispiele für API-Nutzung", ["api", "schnittstelle", "api demo"]],
    ["updates", "OpsTend-Updates", "Verwaltung von OpsTends eigenen Updates", ["eigenupdate", "eigenupdates", "systemupdates", "patch abgleich"]],
    ["hosts", "Hostverwaltung", "Aufnahme, Reset und Austritt von Hosts", ["host aufnahme", "host aufnehmen", "host hinzufügen", "host registrieren", "host registrierung", "host entfernen", "host zurücksetzen"]],
    ["integrations", "Integrationen", "Plattformanbieter und Identitätsquellen", ["adapter und integratoren", "anbieter integration", "identitätsquellen", "proxmox integration", "unifi integration"]],
    ["placement", "Zentrale Dienste", "Platzierung und Replikate der Steuerung", ["dienstplatzierung", "replikate", "quorum", "platzierungsrichtlinien"]],
    ["features", "Funktionskatalog", "Verfügbare Plattformfunktionen", ["funktionen", "funktionsübersicht"]],
    ["policies", "Richtlinien", "Wartungsfenster, Selbstheilung und Freigaben", ["betriebsrichtlinien", "wartungsfenster", "selbstheilung", "freigaberichtlinien"]],
    ["backup", "Schutz", "Sicherungen, Ziele und Wiederherstellung", ["backup", "backups", "sicherung", "sicherungen", "wiederherstellung", "backup einstellungen"]],
  ];

  const englishLabels = {
    operations: "Operations", overview: "System overview", monitoring: "Monitoring", changes: "Changes",
    events: "Event log", inventory: "Inventory", "pve-inventory": "Proxmox inventory", network: "Network", topology: "Topology", services: "Services",
    "guest-create": "Guest from template", "settings:access": "Access and roles", "settings:system": "Appearance",
    "settings:language": "Language", "settings:ai": "Zorec and AI", "settings:api": "System API",
    "settings:updates": "OpsTend updates", "settings:hosts": "Host management", "settings:integrations": "Integrations",
    "settings:placement": "Central services", "settings:features": "Feature catalog", "settings:policies": "Policies", "settings:backup": "Protection",
  };

  const normalize = (text) => String(text ?? "").toLocaleLowerCase("de").replace(/ß/g, "ss")
    .normalize("NFD").replace(/\p{M}/gu, "").replace(/[^\p{L}\p{N}]+/gu, " ").trim();
  const contains = (text, phrase) => phrase && ` ${text} `.includes(` ${phrase} `);
  const aliasScore = (query, aliases) => Math.max(0, ...aliases.filter((alias) => contains(query, alias)).map((alias) => alias.length));
  const contextService = (state, services) => services.find((service) => service.id === (state.view === "service" ? state.serviceId
    : state.view === "topology" ? state.topologyFocus : state.view === "events" && state.eventSubject?.startsWith("service:")
      ? state.eventSubject.slice(8) : null));

  function ipNumber(value) {
    const pieces = String(value ?? "").split(".");
    if (pieces.length !== 4 || !pieces.every((piece) => /^\d{1,3}$/.test(piece) && Number(piece) <= 255)) return null;
    return pieces.reduce((sum, piece) => sum * 256 + Number(piece), 0);
  }

  function covers(network, asset) {
    if (asset.network) return normalize(asset.network) === normalize(network.name.split(" · ")[0]);
    const [address, prefix] = (network.cidr || "").split("/");
    const bits = Number(prefix);
    const start = ipNumber(address);
    const ip = ipNumber(asset.ip);
    if (start === null || ip === null || !prefix || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    const block = 2 ** (32 - bits);
    return Math.floor(start / block) === Math.floor(ip / block);
  }

  function target(id, label, description, route, aliases = []) {
    const englishLabel = englishLabels[id] || label.replace(/^(Protokoll|Überwachung|Topologie)( · )/,
      (_, kind, separator) => ({ Protokoll: "Event log", Überwachung: "Monitoring", Topologie: "Topology" })[kind] + separator);
    return { id, label, englishLabel, description, route, aliases: [...new Set([label, englishLabel, ...aliases].map(normalize).filter(Boolean))] };
  }

  function inventoryTargets(state) {
    const { hosts = [], services = [], networks = [], devices = [], links = [] } = state.inventory || {};
    const scope = state.host || "";
    const scopedHosts = hosts.filter((host) => !scope || host.id === scope);
    const scopedServices = services.filter((service) => !scope || service.host === scope);
    const scopedAssets = [...scopedHosts, ...scopedServices];
    const assets = new Set(scopedAssets.map((item) => item.id));
    const relatedLinks = links.filter((link) => !scope || assets.has(link.from) || assets.has(link.to));
    const relatedDevices = new Set(relatedLinks.flatMap((link) => [link.from, link.to]));
    const scopedNetworkMembers = [...scopedAssets, ...devices.filter((device) => relatedDevices.has(device.id))];
    const ports = links.map((link) => window.opstendDemo?.portConfiguration?.(link.id, state.inventory)).filter(Boolean);
    const objects = [
      ...hosts.map(({ id, name, ip }) => ({ id, label: name, description: "Maschinenansicht", aliases: [name, id, ip], type: "host", host: id, allowed: !scope || scope === id })),
      ...services.map(({ id, name, ip, host }) => ({ id, label: name, description: `Dienst auf ${host}`, aliases: [name, id, ip], type: "service", host, allowed: !scope || scope === host })),
      ...networks.map(({ id, name, cidr }) => ({ id, label: name, description: "Netzdetails und zugehörige Objekte", aliases: [name, name.split(" · ")[0], cidr],
        type: "network", host: scope, allowed: !scope || scopedNetworkMembers.some((item) => covers({ name, cidr }, item)) })),
      ...devices.map(({ id, name, ip }) => ({ id, label: name, description: "Gerät in der Topologie", aliases: [name, id, ip],
        type: "device", host: scope, allowed: !scope || relatedDevices.has(id) })),
      ...ports.map(({ id, port, peerId }) => ({ id, label: `Port ${port}`, description: `Switch-Port zu ${peerId}`, aliases: [port, `Port ${port}`, `Port für ${peerId}`, `Port zu ${peerId}`],
        type: "port", host: scope, allowed: !scope || relatedLinks.some((link) => link.id === id) })),
    ];
    return { objects, services: scopedServices };
  }

  function objectTarget(object, mode = "default") {
    const { id, label, type, host, description, aliases } = object;
    const baseId = `${type}:${id}`;
    if (mode === "events") return target(`events:${baseId}`, `Protokoll · ${label}`, `Ereignisse für ${label}`,
      { view: "events", host, ...(type !== "host" ? { "event-subject": baseId } : {}) }, aliases);
    if (mode === "monitoring") return target(`monitoring:${baseId}`, `Überwachung · ${label}`,
      type === "service" ? `Messwerte des Hosts ${host}, auf dem ${label} läuft` : `Messwerte für ${label}`,
      { view: "monitoring", host, "monitor-host": host }, aliases);
    if (mode === "topology" || type === "device") return target(mode === "topology" ? `topology:${baseId}` : baseId,
      `Topologie · ${label}`, description, { view: "topology", host, layer: type === "device" ? "all" : type === "port" ? "physical" : "placement", "topology-focus": id }, aliases);
    const route = type === "service" ? { view: "service", host, "service-id": id }
      : type === "network" ? { view: "network-detail", host, "network-id": id }
        : type === "port" ? { view: "network-port", host, "port-id": id } : { view: "host", host };
    if (mode === "adapter") route["adapter-section"] = "true";
    return target(mode === "adapter" ? `adapter:${baseId}` : baseId, label, description, route, aliases);
  }

  function catalog(state, inventory = inventoryTargets(state)) {
    const scope = state.host || "";
    const service = contextService(state, inventory.services);
    return [
      ...pages.map(([view, label, description, aliases]) => target(view, label, description, { view, host: view === "events" && service ? service.host : scope,
        ...(view === "events" && service ? { "event-subject": "service:" + service.id } : {}),
        ...(view === "topology" ? { layer: "all", ...(service ? { "topology-focus": service.id } : {}) } : {}),
      }, aliases)),
      target("settings", "Configuration", "Einstellungen und Konfiguration", { view: "settings", host: scope }, ["konfiguration", "einstellungen"]),
      ...settings.map(([tab, label, description, aliases]) => target(`settings:${tab}`, label, description,
        { view: "settings", host: scope, "settings-tab": tab }, aliases)),
      ...(window.opstendNetworkRules?.list(state) || []).map(rule => ({
        ...target(`rule:${rule.id}`, rule.name, "Regelwirkung und aktueller Verbindungsbeleg",
          { view: "network-rule", host: scope, "rule-id": rule.id }, [rule.id, rule.nameEn,
            ...(rule.id === "storage-nfs" ? ["nfs regel", "nfs rule", "netzregel für medien"] : [])]),
        englishLabel: rule.nameEn,
      })),
      ...(window.opstendPublications?.list(state) || []).map(publication => ({
        ...target(`publication:${publication.id}`, publication.label, "HTTPS-Adresse, Proxy, VPN-Pfad und Abrufbeleg",
          { view: "access-detail", host: scope, "publication-id": publication.id }, [publication.domain, publication.labelEn]),
        englishLabel: publication.labelEn,
      })),
      ...inventory.objects.filter(({ allowed }) => allowed).flatMap((object) => {
        const targets = [objectTarget(object)];
        if (object.type === "service" || object.type === "host") targets.push(...["events", "monitoring", "topology"].map((mode) => objectTarget(object, mode)));
        if (object.type === "port") targets.push(objectTarget(object, "events"), objectTarget(object, "topology"));
        if (object.type === "service") targets.push(objectTarget(object, "adapter"));
        return targets;
      }),
    ];
  }

  function publicTarget({ id, label, englishLabel, description, route }) {
    return { id, label, englishLabel, description, route: { ...route } };
  }

  function intent(text) {
    const query = normalize(text).replace(/^zorec\b\s*/, "").replace(/^(?:bitte|please)\b\s*/, "");
    if (/\b(?:diagramm|diagram|excaliplant|plantuml|komponentendiagramm|sequenzdiagramm)\b/.test(query)
      || /\b(?:markier\w*|hervorheb\w*|highlight\w*|nicht|niemals|not|never)\b/.test(query)) return null;
    const explicit = /^(?:navigier(?:e)?|offne|oeffne|wechsel(?:e)?|wechsle|geh(?:e)?|bring(?:e)?|fuhr(?:e)?|spring(?:e)?|ruf(?:e)?|open|navigate|go to|take me to|switch to)\b/.test(query)
      || /^(?:kannst|konntest|wurdest) du\b.*\b(?:navigieren|offnen|oeffnen|wechseln|bringen|fuhren)\b/.test(query)
      || /^(?:can|could|would) you\b.*\b(?:open|navigate|go to|take me to|switch to)\b/.test(query);
    const location = /^(?:wo\b|where\b|how do i (?:find|get to)\b|wie (?:komme ich|gelange ich|finde ich)\b)/.test(query);
    const show = /^(?:zeig(?:e)?|show)\b/.test(query);
    return explicit || location || show ? { query, explicit: explicit || show && /\b(?:seite|unterseite|ansicht|ubersicht|page|view|overview)\b/.test(query) } : null;
  }

  function resolve(question, state) {
    const request = intent(question);
    if (!request) return null;
    const { query, explicit } = request;
    const inventory = inventoryTargets(state);
    const available = catalog(state, inventory);
    const entry = (id) => available.find((item) => item.id === id);
    const result = (chosen, candidates = []) => ({ explicit, target: chosen ? publicTarget(chosen) : null,
      candidates: candidates.slice(0, 8).map(publicTarget) });
    if (/(?:https?|file|javascript|data):|(?:^|\s)www\./i.test(question)) return result(null);

    const permissions = /\b(?:berechtigung\w*|rechte|freigabe\w*|rollen?|permissions?|privileges?|roles?)\b/.test(query);
    const assistantPrivileges = /\b(?:dein\w*|your|zorecs?|ki|ai)\s+(?:(?:werkzeug\w*|shell|tool)\s+)?(?:berechtigung\w*|rechte|freigabe\w*|rollen?|permissions?|privileges?|roles?)\b/.test(query)
      || (permissions && /\b(?:(?:von|fur) (?:zorec|dich|die ki)|der ki)\b/.test(query));
    if (assistantPrivileges) return result(entry("settings:ai"));
    if (/\b(?:my permissions|my rights|my role)\b/.test(query)) return result(entry("settings:access"));

    const networkEntries = available.filter(item => item.id.startsWith("rule:") || item.id.startsWith("publication:"))
      .map(item => ({ item, score: aliasScore(query, item.aliases) })).filter(({ score }) => score > 0)
      .sort((a, b) => b.score - a.score);
    if (networkEntries.length === 1) return result(networkEntries[0].item);
    if (networkEntries.length) return result(null, networkEntries.map(({ item }) => item));

    const staticTargets = available.filter(({ id }) => !id.includes(":") || id.startsWith("settings:"));
    const ranked = staticTargets.map((item) => ({ item, score: aliasScore(query, item.aliases) }))
      .filter(({ score }) => score > 0).sort((a, b) => b.score - a.score);
    const ambiguous = /\b(?:oder|or|vergleich\w*|compare)\b/.test(query);
    const matchingObjects = inventory.objects.map((object) => ({ object,
      score: aliasScore(query, object.aliases.map(normalize)) }))
      .filter(({ score }) => score > 0).sort((a, b) => b.score - a.score);
    const mode = /\b(?:protokoll|ereignisprotokoll|ereignisse|events|logs?|historie)\b/.test(query) ? "events"
      : /\b(?:uberwachung|monitoring|auslastung|messwerte)\b/.test(query) ? "monitoring"
        : /\b(?:topologie|topology|netzplan|netzkarte|karte|map)\b/.test(query) ? "topology"
          : /\badapter\b/.test(query) ? "adapter" : "default";
    const matches = matchingObjects.filter(({ object }) => object.type === "service" || object.type === "host"
      || mode === "default" || mode === "topology" || object.type === "port" && mode === "events");
    if (ranked[0]?.item.id.startsWith("settings:") && !ambiguous && ranked[0].score > (matches[0]?.score ?? 0)
      && ranked[0].score > (ranked[1]?.score ?? 0)) return result(ranked[0].item);
    if (matches.length && !matches[0].object.allowed) return result(null);
    if (matches.length) {
      const candidates = matches.filter(({ object }) => object.allowed).map(({ object }) => {
        const supportedMode = object.type === "service" || (object.type === "host" || object.type === "port") && mode !== "adapter" ? mode : "default";
        return objectTarget(object, supportedMode);
      });
      if (candidates.length === 1 || !ambiguous && matches[0].score > matches[1].score) return result(candidates[0]);
      return result(null, candidates);
    }

    const service = contextService(state, inventory.services);
    if (mode === "adapter" && service && /\b(?:einstellungen|konfiguration)\b/.test(query)) return result(entry(`adapter:service:${service.id}`));
    if (permissions && !ranked.some(({ item }) => item.id === "settings:access" || item.id === "settings:ai")) {
      return result(null, [entry("settings:ai"), entry("settings:access")]);
    }
    if (ranked.length === 1 || ranked.length > 1 && ranked[0].score > ranked[1].score && !ambiguous) return result(ranked[0].item);
    return result(null, ranked.length ? ranked.map(({ item }) => item) : staticTargets.filter(({ id }) => id !== "guest-create"));
  }

  window.opstendZorecNavigation = {
    resolve,
    targets: (state) => catalog(state).map(publicTarget),
  };
})();
