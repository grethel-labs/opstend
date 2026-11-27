(function () {
  "use strict";

  const { t } = window.opstendLocale;
  const layerLabels = {
    physical: ["Verkabelung", "Cabling"],
    network: ["Netze und Regeln", "Networks and rules"],
    access: ["VPN und Zugang", "VPN and access"],
  };
  const brandPrimary = "#2DB8A8";
  const palettes = {
    light: {
      internal: ["#F0FAF8", "#83C8BF"], external: ["#EDEFF5", "#69788C"],
      core: ["#CDEDE8", brandPrimary], application: ["#EAE1F9", "#8464B5"], device: ["#F3F5F8", "#8391A3"],
      offline: "#BC2E48", warning: "#AB7200", maintenance: "#2367BF", unknown: "#68788A",
    },
    dark: {
      internal: ["#112A2B", "#468F87"], external: ["#233142", "#8798B0"],
      core: ["#1D4946", brandPrimary], application: ["#42335C", "#B99EEB"], device: ["#252E3A", "#95A6BC"],
      offline: "#FF758C", warning: "#F2C355", maintenance: "#76ADFF", unknown: "#A5B2C6",
    },
  };
  const conditionLabels = { offline: ["Offline", "Offline"], warning: ["Warnung", "Warning"], maintenance: ["Wartung", "Maintenance"],
    unknown: ["Beleg offen", "Check pending"] };
  const layerLabel = (id) => t(...layerLabels[id]);
  const conditionLabel = (id) => conditionLabels[id] ? t(...conditionLabels[id]) : "";
  const displayLabels = new Map([
    ["Gesund", "Healthy"], ["Erreichbar", "Reachable"], ["Wird geprüft", "Verifying"], ["Warnung", "Warning"],
    ["Zuletzt erreichbar", "Last known reachable"], ["Ungeprüft", "Unchecked"], ["Nicht erreichbar", "Unreachable"],
    ["Vorgemerkt", "Planned"], ["Ausgefallen", "Failed"], ["Wartung", "Maintenance"], ["Gestoppt", "Stopped"],
    ["Stillgelegt", "Retired"], ["Health offen", "Health check pending"], ["Entfernung vorgemerkt", "Removal planned"],
    ["Geplant", "Planned"], ["Aktiv", "Active"],
    ["Anwendung", "Application"], ["Steuerung", "Controller"], ["Weboberfläche", "Web interface"], ["Zeit", "Time service"],
    ["Veröffentlichung", "Published access"], ["Assistenz", "Assistant"], ["Identität", "Identity"],
    ["Konfigurierte Beziehung", "Configured relationship"], ["Link-Beobachtung", "Observed link"],
    ["Verbindungsprüfung", "Connectivity check"], ["Historische Verbindungsprüfung", "Historical connectivity check"],
    ["Entwurf", "Draft"], ["Unbekannt", "Unknown"],
    ["Zorec prüft den Wiederanlauf", "Zorec is verifying recovery"], ["Wiederanlauf nicht bestätigt", "Recovery unconfirmed"],
    ["Zorec prüft das neue Ergebnis", "Zorec is verifying the new result"],
    ["Deine Entscheidung ist gefragt", "Your decision is required"], ["Deine Freigabe ist gefragt", "Your approval is required"],
    ["Update verfügbar", "Update available"],
    ["Dieses Objekt ist im Inventar nicht vorhanden.", "This object is absent from the inventory."],
    ["Gib eine gültige IPv4-Adresse ein.", "Enter a valid IPv4 address."],
    ["Diese Adresse ist bereits belegt.", "This address is already in use."],
    ["Diese Verbindung ist im Inventar nicht vorhanden.", "This connection is absent from the inventory."],
    ["Gib der Verbindung eine Beschriftung.", "Enter a label for the connection."],
    ["Wähle zwei unterschiedliche vorhandene Endpunkte.", "Choose two distinct existing endpoints."],
  ]);
  const displayLabel = (value) => t(value, displayLabels.get(value) ?? value);
  const mapLabel = (item) => Object.hasOwn(item, "from") ? window.opstendDemo.linkLabel(item) : item.name;
  const layers = new Set();
  let cleanup = () => {};
  let lastEdit = "";
  let zoomSetting = "";
  const observationTimes = ["de-DE", "en-GB"].map((locale) => new Intl.DateTimeFormat(locale, { dateStyle: "short", timeStyle: "short" }));

  const plain = (value) => String(value ?? "").replace(/[^\p{L}\p{N} .:,_+%/@()·→–-]/gu, " ").trim().slice(0, 96);
  const objects = (inventory) => [...inventory.hosts, ...inventory.services, ...inventory.devices];

  function condition(item) {
    if (["Ausgefallen", "Offline", "Nicht erreichbar", "Gestoppt", "Stillgelegt", "Entfernung vorgemerkt"].includes(item.status)) return "offline";
    if (["Warnung", "Wird geprüft", "Health offen"].includes(item.status)) return "warning";
    if (item.status === "Wartung") return "maintenance";
    if (item.observation?.reachability === "unknown") return "unknown";
    return "";
  }

  function nodeAppearance(palette, item) {
    const role = item.runtime ? (item.site === "Extern" ? "external" : "core")
      : item.host ? (item.role === "Anwendung" ? "application" : "core") : "device";
    const [fill, stroke] = palette[role];
    return [fill, palette[condition(item)] ?? stroke];
  }

  function plantStyle([fill, stroke]) {
    return ` ${fill};line:${stroke}`;
  }

  function mapLegend(theme) {
    const palette = palettes[theme];
    const items = [
      [t("Interner Standort", "Internal site"), ...palette.internal], [t("Externer Standort und Host", "External site and host"), ...palette.external],
      [t("Interner Host und Basisdienst", "Internal host and core service"), ...palette.core], [t("Zusatzdienst", "Additional service"), ...palette.application],
      ...Object.keys(conditionLabels).map((status) => [conditionLabel(status), "transparent", palette[status]]),
    ];
    return `<ul class="topology-legend" aria-label="${t("Legende", "Legend")}">${items.map(([label, fill, stroke]) => `<li>
      <span aria-hidden="true" style="--swatch-fill:${fill};--swatch-stroke:${stroke}"></span>${label}</li>`).join("")}</ul>`;
  }

  function projection(state) {
    const { inventory, host } = state;
    const byId = new Map(objects(inventory).map((item) => [item.id, item]));
    const selected = new Set([
      ...inventory.hosts.filter((item) => !host || item.id === host).map((item) => item.id),
      ...inventory.services.filter((item) => !host || item.host === host).map((item) => item.id),
    ]);
    const validLinks = inventory.links.filter((link) => byId.has(link.from) && byId.has(link.to));
    const inDirectScope = (link) => !host || selected.has(link.from) || selected.has(link.to);
    const direct = new Set(validLinks.filter(inDirectScope).map(({ id }) => id));
    const access = new Set(validLinks.filter((link) => link.publicationId && (direct.has(link.id) || direct.has(link.tunnelId)))
      .flatMap((link) => [link.id, link.tunnelId]));
    const relations = validLinks.filter((link) => direct.has(link.id) || access.has(link.id));
    const links = relations.filter((link) => layers.has(link.layer));
    for (const link of links) {
      for (const id of [link.from, link.to]) {
        selected.add(id);
        const parent = byId.get(id)?.host;
        if (parent) selected.add(parent);
      }
    }
    const nodes = objects(inventory).filter((item) => selected.has(item.id));
    return { nodes, links, relations, byId };
  }

  function createPlantUml(state, graph) {
    const palette = palettes[state.theme];
    const aliases = new Map(graph.nodes.map((item, index) => [item.id, "node_" + index]));
    const appearances = new Map(graph.nodes.map((item) => [item.id, nodeAppearance(palette, item)]));
    const hooks = new Map();
    const preamble = ["@startuml"];
    for (const item of graph.nodes) {
      const alias = aliases.get(item.id);
      hooks.set(alias, item);
      preamble.push("@hook #" + alias + " alias:" + alias + " .resource click-mode:button");
      const [fill, stroke] = appearances.get(item.id);
      for (const phase of ["hover", "click"]) {
        preamble.push(`@hook #${alias} ${phase} BackgroundColor ${fill}`);
        preamble.push(`@hook #${alias} ${phase} LineColor ${stroke}`);
      }
    }
    const body = ["top to bottom direction"];
    const sites = [...new Set(graph.nodes.map((item) => item.site).filter(Boolean))];
    for (const [index, site] of sites.entries()) {
      const external = site === "Extern";
      const siteLabel = external ? t("Extern", "External") : t("Intern", "Internal") + " · " + site;
      const siteStyle = plantStyle(palette[external ? "external" : "internal"]) + (external ? ";line.dashed" : "");
      body.push('package "' + plain(siteLabel) + '" as site_' + index + siteStyle + ' {');
      for (const host of state.inventory.hosts.filter((item) => item.site === site && aliases.has(item.id))) {
        const hostStyle = plantStyle(appearances.get(host.id));
        const hostLabel = [host.name, host.runtime + " · " + host.ip, displayLabel(host.status)].filter(Boolean).map(plain).join("\\n");
        body.push('  node "' + hostLabel + '" as ' + aliases.get(host.id) + hostStyle + ' {');
        const services = graph.nodes.filter((item) => item.host === host.id);
        for (const service of services) {
          const status = conditionLabel(condition(service)) || displayLabel(service.instance || (service.status === "Gesund" ? "" : service.status));
          const label = [plain(service.name), plain(service.kind) + (status ? " · " + plain(status) : ""), plain(service.ip)].filter(Boolean).join("\\n");
          const serviceStyle = plantStyle(appearances.get(service.id));
          body.push('    component "' + label + '" as ' + aliases.get(service.id) + serviceStyle);
        }
        for (let index = 1; index < services.length; index += 1) {
          body.push("    " + aliases.get(services[index - 1].id) + " -[hidden]down-> " + aliases.get(services[index].id));
        }
        body.push("  }");
      }
      for (const device of state.inventory.devices.filter((item) => item.site === site && aliases.has(item.id))) {
        body.push('  component "' + plain(device.name) + '\\n' + plain(device.ip) + '" as ' + aliases.get(device.id) + plantStyle(appearances.get(device.id)));
      }
      body.push("}");
    }
    for (const link of graph.links) {
      const verifiedPublication = link.publicationStage === "verified" && !link.publicationStale;
      const relation = link.layer === "physical" ? " -- " : link.layer === "access" && !verifiedPublication ? " ..> " : " --> ";
      const evidence = window.opstendDemo.linkEvidence(link);
      const label = evidence.type === "Entwurf" && !link.publicationId ? `${displayLabel(evidence.type)} · ${link.label}` : mapLabel(link);
      body.push(aliases.get(link.from) + relation + aliases.get(link.to) + " : " + plain(label));
    }
    body.push("@enduml");
    return { preamble, body, hooks, aliases };
  }

  function bindConnectionPrimitives(diagram, graph, plant) {
    const elements = diagram.excalidraw.elements;
    const arrows = elements.filter((item) => item.type === "arrow");
    const visibleEdges = diagram.model.edges.filter((item) => !item.hidden);
    if (arrows.length !== graph.links.length) throw new Error("Verbindungen sind nicht eindeutig gerendert.");
    graph.links.forEach((link, index) => {
      const edge = visibleEdges[index];
      if (edge?.from !== plant.aliases.get(link.from) || edge?.to !== plant.aliases.get(link.to)) {
        throw new Error("Die Endpunkte einer Verbindung passen nicht zur Projektion.");
      }
      const arrow = arrows[index];
      const position = elements.indexOf(arrow);
      const end = index < arrows.length - 1 ? elements.indexOf(arrows[index + 1]) : elements.length;
      const label = elements.slice(position + 1, end).find((item) => item.type === "text");
      for (const [kind, primitive] of [["edge", arrow], ["caption", label]]) {
        if (!primitive) continue;
        const id = kind + "_" + index;
        plant.hooks.set(id, link);
        plant.preamble.push("@hook #" + id + " element:" + primitive.id + " .connection click-mode:button");
      }
    });
  }

  function importSvg(markup, label = t("Interaktive Platzierung und Verbindungen", "Interactive placement and connections")) {
    const root = new DOMParser().parseFromString(markup, "image/svg+xml").documentElement;
    if (root.localName !== "svg") throw new Error("Der Renderer lieferte keine SVG-Karte.");
    const shapes = new Set(["svg", "g", "path", "rect", "ellipse", "circle", "line", "polyline", "polygon", "text", "tspan", "title", "desc"]);
    for (const element of [root, ...root.querySelectorAll("*")]) {
      if (!shapes.has(element.localName)) {
        element.remove();
        continue;
      }
      for (const attribute of [...element.attributes]) {
        if (/^on/i.test(attribute.name) || ["href", "src", "style"].includes(attribute.localName) || /url\s*\(/i.test(attribute.value)) {
          element.removeAttributeNode(attribute);
        }
      }
    }
    root.setAttribute("aria-label", label);
    root.removeAttribute("role");
    return document.importNode(root, true);
  }

  function inspector(state, element, panel, graph) {
    if (!element) {
      panel.innerHTML = `<h2>${t("Auswahl", "Selection")}</h2><p class="compact">${t("Wähle einen Knoten oder eine Verbindung.", "Select a node or connection.")}</p>`;
      return;
    }
    const esc = state.escape;
    const isLink = Object.hasOwn(element, "from");
    const relatedRules = isLink ? window.opstendNetworkRuleUi?.section(state, { linkId: element.id }) || "" : "";
    const publications = isLink ? window.opstendPublicationUi?.section(state, { linkId: element.id }) || ""
      : element.host ? window.opstendPublicationUi?.section(state, { serviceId: element.id }) || "" : "";
    const managedPublication = !!element.publicationId;
    const items = objects(state.inventory).filter((item) => !item.budgets && !item.sourceHost);
    const enrollment = element.budgets || element.sourceHost;
    const name = (id) => graph.byId.get(id)?.name ?? id;
    const targetHost = element.host || (element.runtime ? element.id : "");
    const network = state.inventory.networks.find((entry) => entry.name.split(" · ")[0] === element.network);
    const port = isLink && element.layer === "physical" && window.opstendDemo.portConfiguration?.(element.id, state.inventory);
    const cases = window.opstendViews.attention({ ...state, host: targetHost }).filter((job) =>
      element.host ? job.serviceId === element.id : targetHost && !isLink);
    const facts = isLink ? []
      : [[t("Standort oder Host", "Site or host"), element.host || element.site], ["IPv4", element.ip || t("Offen", "Pending")],
        [t("Rolle", "Role"), element.role ? displayLabel(element.role) : element.runtime || element.kind],
        [t("Zustand", "Status"), displayLabel(element.status)],
        [t("Erreichbarkeitsbeleg", "Reachability evidence"), element.observation && window.opstendViews.hostObservationNote(element)],
        [t("Netz", "Network"), element.network],
        ["CPU", displayLabel(element.cpu)], ["RAM", displayLabel(element.ram)]].filter(([, value]) => value);
    const open = isLink || !targetHost ? "" : `<button class="button" data-view="${element.host ? "service" : "host"}" data-host="${esc(targetHost)}"
      ${element.host ? `data-service-id="${esc(element.id)}"` : ""}>${element.host ? t("Dienst öffnen", "Open service") : t("Host öffnen", "Open host")}</button>`;
    const choices = (id) => items.map((item) =>
      '<option value="' + esc(item.id) + '"' + (item.id === id ? " selected" : "") + ">" + esc(item.name) + "</option>"
    ).join("");
    const selectElement = (id, label) => `<button type="button" class="text-button" data-map-target="${esc(id)}">${esc(label)}</button>`;
    const linkFacts = () => {
      const evidence = window.opstendDemo.linkEvidence(element);
      const checked = evidence.observedAt && t(...observationTimes).format(new Date(evidence.observedAt));
      const networkName = (id) => state.inventory.networks.find((item) => item.id === id)?.name || id;
      const vlanFacts = port ? [
        [t("Natives VLAN", "Native VLAN"), networkName(port.current.nativeVlan)],
        [t("Getaggte VLANs", "Tagged VLANs"), port.current.taggedVlans.map(networkName).join(", ") || t("Keine", "None")],
      ] : [];
      const details = [[t("Belegart", "Evidence type"), displayLabel(evidence.type)], [t("Datenquelle", "Data source"), evidence.source],
        [t("Letzter Beleg", "Last evidence"), checked], ["Port", evidence.port || port?.port],
        [t("Linkrate", "Link speed"), evidence.rate], ...vlanFacts].filter(([, value]) => value)
        .map(([label, value]) => `<div><dt>${label}</dt><dd>${esc(value)}</dd></div>`).join("");
      return `<dl class="topology-facts">
        <div><dt>${t("Von", "From")}</dt><dd>${selectElement(element.from, name(element.from))}</dd></div>
        <div><dt>${t("Nach", "To")}</dt><dd>${selectElement(element.to, name(element.to))}</dd></div>
        ${details}</dl><p class="topology-hint">${esc(t(evidence.detail, evidence.detailEn || evidence.detail))}</p>`;
    };
    const related = () => {
      const links = graph.relations.filter((link) => link.from === element.id || link.to === element.id);
      if (!links.length) return "";
      return `<section class="topology-related"><h3>${t("Direkte Verbindungen", "Direct connections")}</h3><ul>${links.map((link) => {
        const outward = link.from === element.id;
        const peer = name(outward ? link.to : link.from);
        const layer = layerLabel(link.layer);
        const visibility = layers.has(link.layer) ? layer : `${layer} · ${t("ausgeblendet", "hidden")}`;
        return `<li>${selectElement(link.id, mapLabel(link))}<p>${outward ? t("Zu", "To") : t("Von", "From")} ${esc(peer)} · ${esc(visibility)}</p></li>`;
      }).join("")}</ul></section>`;
    };
    panel.innerHTML =
      '<span class="badge good">' + (isLink ? layerLabel(element.layer) : esc(element.kind || t("Maschine", "Host"))) + "</span>"
      + '<h2 id="topology-detail-title" tabindex="-1">' + esc(mapLabel(element)) + "</h2>"
      + (isLink ? linkFacts() : `<dl class="topology-facts">${facts.map(([label, value]) => `<div><dt>${label}</dt><dd>${esc(value)}</dd></div>`).join("")}</dl>`)
      + relatedRules
      + publications
      + cases.map((job) => `<p class="topology-case"><button class="text-button" data-view="changes" data-job="${esc(job.id)}" data-host="${esc(targetHost)}">${esc(displayLabel(job.attention.status))}</button></p>`).join("")
      + `<div class="topology-actions">${open}
        ${isLink ? "" : window.opstendPveInventoryUI?.link(state, element.id) || ""}
        ${element.observation ? `<button type="button" class="button" data-view="monitoring" data-host="${esc(element.id)}"
          data-monitor-host="${esc(element.id)}" data-monitor-metric="cpu" data-monitor-period="1h">${t("Überwachung öffnen", "Open monitoring")}</button>` : ""}
        ${network ? `<button type="button" class="button" data-view="network-detail" data-network-id="${esc(network.id)}">${t("Netz öffnen", "Open network")}</button>` : ""}
        ${port ? `<button type="button" class="button" data-view="network-port" data-port-id="${esc(port.id)}">${t("Port öffnen", "Open port")}</button>` : ""}
        ${managedPublication ? "" : `<button type="button" class="button" id="topology-edit-toggle" aria-expanded="false" aria-controls="topology-edit-form" ${enrollment ? "disabled" : ""}>${t("Bearbeiten", "Edit")}</button>`}
        <button type="button" class="text-button" data-copy-map-link>${t("Kartenlink kopieren", "Copy map link")}</button></div>`
      + (enrollment ? `<p class="topology-hint">${t("Die Adresse stammt aus der Bestandsaufnahme.", "The address comes from the inventory scan.")}</p>` : "")
      + '<form id="topology-edit-form" class="topology-editor" hidden>'
      + (isLink
        ? `<label for="topology-from">${t("Quelle", "Source")}</label><select id="topology-from" name="from">${choices(element.from)}</select>
          <label for="topology-to">${t("Ziel", "Destination")}</label><select id="topology-to" name="to">${choices(element.to)}</select>
          <label for="topology-label">${t("Verbindung", "Connection")}</label><input id="topology-label" name="label" required maxlength="90" value="${esc(element.label)}">`
        : `<label for="topology-ip">${t("IPv4-Adresse", "IPv4 address")}</label><input id="topology-ip" name="ip" required maxlength="32" value="${esc(element.ip || "")}">`)
      + `<button class="button primary" type="submit">${t("In Demo speichern", "Save in demo")}</button>
      </form><p role="status" id="topology-edit-result">${lastEdit === element.id ? t("Im Demo-Inventar gespeichert.", "Saved in the demo inventory.") : ""}</p>`
      + (isLink ? "" : related());
    const form = panel.querySelector("form");
    const toggle = panel.querySelector("#topology-edit-toggle");
    if (!toggle) return;
    toggle.addEventListener("click", () => {
      form.hidden = !form.hidden;
      toggle.textContent = form.hidden ? t("Bearbeiten", "Edit") : t("Bearbeitung schließen", "Close editor");
      toggle.setAttribute("aria-expanded", String(!form.hidden));
      if (!form.hidden) form.querySelector("input, select").focus();
      else form.reset();
      panel.querySelector("#topology-edit-result").textContent = "";
    });
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const patch = Object.fromEntries(new FormData(event.target));
      const result = isLink ? window.opstendDemo.updateLink(element.id, patch) : window.opstendDemo.updateEntity(element.id, patch);
      if (result !== true) {
        panel.querySelector("#topology-edit-result").textContent = displayLabel(result);
        return;
      }
      lastEdit = element.id;
      window.dispatchEvent(new CustomEvent("opstend:inventory-changed"));
      document.getElementById("topology-edit-toggle")?.focus();
    });
  }

  window.opstendViews.topology = (state) => `
    <header class="page-intro topology-intro"><p class="eyebrow">${t("Flotte und Maschinen", "Fleet and hosts")}</p><h1>${t("Topologie", "Topology")}</h1>
      <p>${t("Hosts, VMs und Container bleiben sichtbar, während du Verbindungen einblendest.", "Hosts, VMs and containers stay visible as you show connections.")}</p></header>
    <div class="topology-tabs" role="group" aria-label="${t("Verbindungsebenen", "Connection layers")}">
      ${Object.keys(layerLabels).map((id) =>
        `<label class="topology-layer"><input type="checkbox" data-overlay="${id}" ${layers.has(id) ? "checked" : ""}> ${layerLabel(id)}</label>`
      ).join("")}
    </div>
    ${mapLegend(state.theme)}
    <div class="topology-grid live-topology">
      <section class="panel topology-map" aria-labelledby="topology-map-title">
        <header class="topology-map-heading topology-heading">
          <div><h2 id="topology-map-title">${t("Platzierung und Verbindungen", "Placement and connections")}</h2>
            <p>${t("Wähle Details mit Klick oder Eingabetaste.", "Click or press Enter to view details.")}</p></div>
          <div class="topology-zoom-tools">
            <label class="topology-zoom">${t("Ansicht", "View")} <select id="topology-zoom">
              <option value="scene">${t("Ganze Karte", "Fit map")}</option><option value="width">${t("Lesebreite", "Fit width")}</option>
              <option value="1">100 %</option><option value="1.25">125 %</option><option value="1.6">160 %</option>
            </select></label>
            <button type="button" class="button" id="topology-center">${t("Auswahl vergrößern", "Zoom to selection")}</button>
          </div>
        </header>
        <label class="topology-selection">${t("Objekt oder Verbindung auswählen", "Select an object or connection")} <select id="topology-selection"></select></label>
        <div class="topology-mark-note" id="topology-mark-note" hidden><p role="status"></p><button type="button" class="text-button" data-clear-topology-mark>${t("Markierung entfernen", "Clear highlight")}</button></div>
        <div class="topology-graph" tabindex="0" aria-label="${t("Interaktive Karte und Scrollbereich", "Interactive map and scroll area")}"></div>
        <p class="topology-source" id="topology-render-status" role="status">${t("Karte wird gerendert …", "Rendering map…")}</p>
      </section>
      <aside class="panel topology-detail" id="topology-inspector" aria-label="${t("Kartenauswahl", "Map selection")}"></aside>
    </div>
  `;

  window.opstendTopology = {
    importSvg,
    unmount() { cleanup(); cleanup = () => {}; },
    mount(state) {
      layers.clear();
      const initialLayers = state.topologyLayers ? state.topologyLayers.split(",")
        : state.layer === "all" ? Object.keys(layerLabels) : [state.layer];
      for (const layer of initialLayers) if (Object.hasOwn(layerLabels, layer)) layers.add(layer);
      const focusedLink = state.inventory.links.find((link) => link.id === state.topologyFocus);
      if (focusedLink) layers.add(focusedLink.layer);
      const graphElement = document.querySelector(".topology-graph");
      const selection = document.getElementById("topology-selection");
      const panel = document.getElementById("topology-inspector");
      const status = document.getElementById("topology-render-status");
      const markNote = document.getElementById("topology-mark-note");
      const zoom = document.getElementById("topology-zoom");
      const center = document.getElementById("topology-center");
      const checkboxes = [...document.querySelectorAll("[data-overlay]")];
      zoom.value = zoomSetting || (state.layer === "all" ? "scene" : "width");
      let selected = state.topologyFocus || state.host || "nuc-a";
      let graph;
      let request = 0;
      let unbind = () => {};
      const resize = new ResizeObserver(() => { if (zoom.value === "scene") applyZoom(); });
      resize.observe(graphElement);
      cleanup = () => { request += 1; unbind(); resize.disconnect(); };

      function applyZoom() {
        const svg = graphElement.querySelector("svg");
        if (!svg) return;
        const viewBox = svg.viewBox.baseVal;
        graphElement.dataset.zoom = zoom.value;
        if (zoom.value === "scene") {
          const style = getComputedStyle(graphElement);
          const availableWidth = graphElement.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
          const availableHeight = parseFloat(style.maxHeight) - parseFloat(style.paddingTop) - parseFloat(style.paddingBottom) - 2;
          const fitted = Math.min(viewBox.width, availableWidth, availableHeight * viewBox.width / viewBox.height);
          svg.style.width = Math.max(1, Math.floor(fitted)) + "px";
        } else {
          svg.style.width = zoom.value === "width" ? "100%" : viewBox.width * Number(zoom.value) + "px";
        }
      }

      function centerSelection() {
        const target = graphElement.querySelector(`[data-inventory-id="${CSS.escape(selected)}"][tabindex="0"]`);
        if (!target) return;
        const box = target.getBoundingClientRect();
        const frame = graphElement.getBoundingClientRect();
        graphElement.scrollBy({
          top: box.top + (box.height - frame.height) / 2 - frame.top,
          left: box.left + (box.width - frame.width) / 2 - frame.left,
        });
      }

      function syncLayers(persist = false) {
        for (const checkbox of checkboxes) checkbox.checked = layers.has(checkbox.dataset.overlay);
        if (persist) {
          const detail = Object.keys(layerLabels).filter((layer) => layers.has(layer)).join(",") || "-";
          window.dispatchEvent(new CustomEvent("opstend:topology-layers", { detail }));
        }
      }

      function revealDetails() {
        const heading = panel.querySelector("h2");
        if (!heading) return;
        heading.focus({ preventScroll: true });
        if (matchMedia("(max-width: 1050px)").matches) heading.scrollIntoView({ block: "nearest" });
      }

      function select(id) {
        const item = [...graph.nodes, ...graph.links].find((candidate) => candidate.id === id);
        if (!item) return;
        selected = id;
        selection.value = id;
        inspector(state, item, panel, graph);
        highlight();
        window.dispatchEvent(new CustomEvent("opstend:topology-select", { detail: id }));
      }

      async function openTarget(id) {
        const link = graph.relations.find((item) => item.id === id);
        if (link && !layers.has(link.layer)) {
          selected = id;
          layers.add(link.layer);
          syncLayers(true);
          await draw();
        } else {
          select(id);
        }
        if (!panel.isConnected) return;
        centerSelection();
        revealDetails();
      }

      function highlight() {
        for (const element of graphElement.querySelectorAll("[data-inventory-id]")) {
          element.toggleAttribute("data-selected", element.dataset.inventoryId === selected);
          element.toggleAttribute("data-zorec-mark", element.dataset.inventoryId === state.topologyMark);
        }
        const marked = [...graph.nodes, ...graph.links].find((item) => item.id === state.topologyMark);
        markNote.hidden = !marked;
        markNote.querySelector("p").textContent = marked ? `${t("Zorec markiert", "Zorec highlights")} ${marked.name || marked.label}` : "";
      }

      async function draw() {
        const generation = ++request;
        graph = projection(state);
        selection.replaceChildren(...[...graph.nodes, ...graph.links].map((item) =>
          new Option(mapLabel(item), item.id)));
        const candidate = [...graph.nodes, ...graph.links].find((item) => item.id === selected) || graph.nodes[0];
        if (candidate) select(candidate.id);
        status.textContent = t("Karte wird gerendert …", "Rendering map…");
        try {
          const { render, bindHooks } = window.opstendExcaliplant;
          const plant = createPlantUml(state, graph);
          const options = { strict: true, theme: "transparent-" + state.theme, sketch: false, seed: "opstend-demo" };
          const source = () => [...plant.preamble, ...plant.body].join("\n");
          const diagram = await render(source(), options);
          if (generation !== request) return;
          if (graph.links.length) {
            bindConnectionPrimitives(diagram, graph, plant);
            plant.preamble.push("@hook .connection hover LineThickness 3");
            plant.preamble.push("@hook .connection hover LineColor " + (state.theme === "dark" ? "#66d7c3" : "#08746a"));
          }
          const interactive = graph.links.length ? await render(source(), options) : diagram;
          const markup = await interactive.toSvg({ interactive: true, embedFont: false });
          if (generation !== request || !graphElement.isConnected) return;
          const svg = importSvg(markup);
          unbind();
          graphElement.replaceChildren(svg);
          applyZoom();
          unbind = bindHooks(svg);
          const keyboardTargets = new Set();
          for (const control of svg.querySelectorAll("[data-excaliplant-hook-id]")) {
            const item = plant.hooks.get(control.getAttribute("data-excaliplant-hook-id"));
            if (item) {
              const status = condition(item);
              if (control.getAttribute("tabindex") === "0") {
                if (keyboardTargets.has(item.id)) {
                  control.removeAttribute("tabindex");
                  control.removeAttribute("role");
                } else {
                  keyboardTargets.add(item.id);
                  control.setAttribute("aria-label", [mapLabel(item), conditionLabel(status)].filter(Boolean).join(" · "));
                }
              }
              if (status) control.setAttribute("data-node-condition", status);
              control.setAttribute("data-inventory-id", item.id);
            }
          }
          highlight();
          svg.addEventListener("excaliplant:hook", (event) => {
            const item = plant.hooks.get(event.detail.id);
            if (event.detail.type === "click" && item) {
              select(item.id);
              if (matchMedia("(max-width: 1050px)").matches) revealDetails();
            }
          });
          status.textContent = t(`${graph.nodes.length} Objekte · ${graph.links.length} sichtbare Verbindungen · aus dem Demo-Inventar gerendert`,
            `${graph.nodes.length} objects · ${graph.links.length} visible connections · rendered from demo inventory`);
        } catch (error) {
          if (generation !== request) return;
          unbind();
          graphElement.replaceChildren();
          status.textContent = t("Karte konnte nicht gerendert werden. Die Auswahl bleibt bedienbar.",
            "Could not render the map. You can still use the selection menu.");
          console.error(error);
        }
      }

      selection.addEventListener("change", () => {
        select(selection.value);
        centerSelection();
      });
      zoom.addEventListener("change", () => {
        zoomSetting = zoom.value;
        applyZoom();
        if (zoom.value === "scene") graphElement.scrollTo(0, 0);
        else centerSelection();
      });
      center.addEventListener("click", () => {
        zoom.value = "1";
        zoomSetting = zoom.value;
        applyZoom();
        centerSelection();
      });
      panel.addEventListener("click", async (event) => {
        const button = event.target.closest("button");
        if (button?.dataset.mapTarget) void openTarget(button.dataset.mapTarget);
        if (!button?.hasAttribute("data-copy-map-link")) return;
        const result = panel.querySelector("#topology-edit-result");
        try {
          await navigator.clipboard.writeText(location.href);
          result.textContent = t("Kartenlink kopiert.", "Map link copied.");
        } catch {
          const field = document.createElement("input");
          field.readOnly = true;
          field.value = location.href;
          field.setAttribute("aria-label", t("Kartenlink", "Map link"));
          result.textContent = t("Kartenlink zum Kopieren", "Map link to copy");
          result.append(field);
          field.select();
          field.focus();
        }
      });
      syncLayers();
      for (const checkbox of checkboxes) {
        checkbox.addEventListener("change", () => {
          if (checkbox.checked) layers.add(checkbox.dataset.overlay);
          else layers.delete(checkbox.dataset.overlay);
          syncLayers(true);
          void draw();
        });
      }
      void draw();
    },
  };
})();
