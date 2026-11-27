(function () {
  "use strict";

  const media = matchMedia("(prefers-color-scheme: dark)");
  const brandDirectory = "../../../webapp/public/brand";
  const paths = {
    operations: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    monitoring: '<path d="M3 5v14h18M6 15l4-5 3 3 6-7"/>',
    overview: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18m-11 0v11m4-7h3m-3 3h3"/>',
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
    inventory: '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M4 9h16M9 9v11"/>',
    services: '<path d="m12 3 9 5v8l-9 5-9-5V8zM3 8l9 5 9-5m-9 5v8"/>',
    topology: '<rect x="9" y="3" width="6" height="6" rx="1"/><rect x="2" y="15" width="6" height="6" rx="1"/><rect x="16" y="15" width="6" height="6" rx="1"/><path d="M12 9v3M5 15v-3h14v3"/>',
    changes: '<path d="M4 6h16M4 12h16M4 18h16"/><path d="M8 4v4M15 10v4M10 16v4"/>',
    events: '<path d="M8 5h12M8 12h12M8 19h12M4 5h.01M4 12h.01M4 19h.01"/>',
    settings: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3m0 14v3M2 12h3m14 0h3M5 5l2 2m10 10 2 2M5 19l2-2M17 7l2-2"/><circle cx="12" cy="12" r="8"/>',
    host: '<rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="13" width="18" height="7" rx="1"/><path d="M7 7.5h.01M7 16.5h.01M14 7.5h4M14 16.5h4"/>',
    search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4 4"/>',
    warning: '<path d="m12 3 10 18H2zM12 9v4m0 4h.01"/>',
    arrow: '<path d="M4 12h15m-6-6 6 6-6 6"/>',
    scope: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c5 4 5 14 0 18-5-4-5-14 0-18Z"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l2 2m10 10 2 2M5 19l2-2M17 7l2-2"/>',
    moon: '<path d="M20 15a8.5 8.5 0 0 1-11-11 8.5 8.5 0 1 0 11 11Z"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    shield: '<path d="M12 3 4 6v6c0 5 6 8 8 9 2-1 8-4 8-9V6zM8 12l3 3 5-6"/>',
    cpu: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4m6-4v4m-6 12v4m6-4v4M2 9h4m-4 6h4m12-6h4m-4 6h4"/><rect x="9" y="9" width="6" height="6" rx="1"/>',
    network: '<path d="M3 12h5l3-7 3 14 2-7h5"/>',
  };

  const icon = (name) => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round">${paths[name] || paths.scope}</svg>`;
  const escape = (value) => String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
  const badge = (label, type = "") => `<span class="badge ${type}"><span class="dot" aria-hidden="true"></span>${escape(label)}</span>`;
  const { t } = window.opstendLocale;
  const navigation = [
    ["Betrieb", "Operations", [["operations", "Betrieb", "Operations"], ["overview", "Systemübersicht", "System overview"],
      ["monitoring", "Überwachung", "Monitoring"], ["changes", "Änderungen", "Changes"], ["events", "Protokoll", "Event log"]]],
    ["Infrastruktur", "Infrastructure", [["inventory", "Inventar", "Inventory"], ["network", "Netzwerk", "Network"],
      ["topology", "Topologie", "Topology"], ["services", "Dienste", "Services"]]],
  ];
  const defaults = {
    view: "operations", host: "", layer: "placement", topologyFocus: "", topologyLayers: "", topologyMark: "", job: "sensorik", jobEvent: "",
    settingsTab: "access", hostTab: "overview", inventoryTab: "all", query: "", networkId: "", portId: "", ruleId: "", publicationId: "",
    serviceId: "", serviceAction: "", pveGuest: "", eventKind: "", eventQuery: "", eventSubject: "",
    monitorHost: "", monitorMetric: "cpu", monitorPeriod: "1h",
  };
  const allowed = {
    view: [...navigation.flatMap(([, , items]) => items.map(([view]) => view)), "host", "host-maintenance", "service", "guest-create", "settings", "network-detail", "network-port", "network-rule", "access-detail", "pve-inventory"],
    networkId: ["", ...window.opstendDemo.getInventory().networks.map((network) => network.id)],
    portId: ["", ...window.opstendDemo.getInventory().links.filter((link) => link.layer === "physical").map((link) => link.id)],
    eventKind: ["", "health", "network", "config", "runtime", "maintenance", "deployment", "other"],
    monitorMetric: Object.keys(window.opstendMonitoringData.metrics),
    monitorPeriod: Object.keys(window.opstendMonitoringData.periods),
    layer: ["placement", "physical", "network", "access", "all"],
    hostTab: ["overview", "resources", "network", "activity"],
    inventoryTab: ["all", "host", "workload", "device"],
    serviceAction: ["", "retire", "remove", ...Object.keys(window.opstendDemo.runtimeLabels)],
  };
  const knownHost = (id) => !id || window.opstendDemo.getInventory().hosts.some((host) => host.id === id);
  const validPveGuest = (value) => /^[1-9][0-9]{2,8}$/.test(value);
  const enrollmentHost = () => window.opstendHostEnrollment?.candidate.id;
  const app = document.getElementById("app");
  const skipLink = document.querySelector(".skip-link");
  let preferences = "system";
  try { preferences = localStorage.getItem("opstend-rc2-theme") || "system"; } catch {}
  if (!["system", "light", "dark"].includes(preferences)) preferences = "system";

  function readRoute() {
    const params = new URLSearchParams(location.hash.slice(1));
    const result = { ...defaults };
    for (const key of Object.keys(defaults)) {
      const value = params.get(key);
      if (value === null || value.length > 160) continue;
      if ((key === "host" || key === "monitorHost") && !knownHost(value)) continue;
      if (key === "pveGuest" && !validPveGuest(value)) continue;
      if (allowed[key] && !allowed[key].includes(value)) continue;
      result[key] = value;
    }
    if (result.view === "host" && !result.host) {
      if (params.get("host") === enrollmentHost()) Object.assign(result, { view: "settings", settingsTab: "hosts" });
      else result.host = "nuc-a";
    }
    return result;
  }

  let route = readRoute();
  let runtimeReview;
  let message = "";
  let navOpen = false;
  const helpers = { icon, escape, badge };

  function updateUrl(replace = false) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(route)) {
      if (key.startsWith("event") && route.view !== "events") continue;
      if (key.startsWith("monitor") && route.view !== "monitoring") continue;
      if (key === "topologyMark" && route.view !== "topology") continue;
      if (key === "jobEvent" && route.view !== "changes") continue;
      if (key === "ruleId" && route.view !== "network-rule") continue;
      if (key === "publicationId" && route.view !== "access-detail") continue;
      if (key === "pveGuest" && route.view !== "pve-inventory") continue;
      if (value !== defaults[key]) params.set(key, value);
    }
    const fragment = params.toString();
    const url = fragment ? `#${fragment}` : location.pathname + location.search;
    if (fragment !== location.hash.slice(1)) {
      if (replace) history.replaceState(null, "", url);
      else history.pushState(null, "", url);
    }
  }

  function setRoute(update, focus = "page") {
    route = { ...route, ...update };
    updateUrl();
    render();
    if (focus === "page") {
      window.scrollTo(0, 0);
      document.getElementById("content").focus({ preventScroll: true });
    } else if (focus) {
      app.querySelector(focus)?.focus({ preventScroll: true });
    }
  }

  function navigateTo(data, focus = "page") {
    message = "";
    navOpen = false;
    const host = data.host ?? route.host;
    const eventRow = data.jobEvent ? `[data-job-event-row="${CSS.escape(data.jobEvent)}"]` : "";
    const jobFocus = data.view === "changes" && data.job ? eventRow || "#manage-job-title" : "";
    setRoute({
      view: data.view,
      host: data.view === "host" && !host ? "nuc-a" : host,
      serviceAction: "",
      jobEvent: data.view === "changes" ? data.jobEvent || "" : "",
      ...(data.host ? { hostTab: "overview" } : {}),
      ...(data.hostTab ? { hostTab: data.hostTab } : {}),
      ...(data.serviceId ? { serviceId: data.serviceId } : {}),
      ...(data.networkId ? { networkId: data.networkId } : {}),
      ...(data.portId ? { portId: data.portId } : {}),
      ...(data.ruleId ? { ruleId: data.ruleId } : {}),
      ...(data.view === "access-detail" ? { publicationId: data.publicationId || "" } : {}),
      ...(data.view === "pve-inventory" ? { pveGuest: validPveGuest(data.pveGuest) ? data.pveGuest : "" } : {}),
      ...(data.view === "events" ? { eventKind: allowed.eventKind.includes(data.eventKind) ? data.eventKind : "",
        eventQuery: "", eventSubject: data.eventSubject || "" } : {}),
      ...(data.monitorHost ? { monitorHost: data.monitorHost } : {}),
      ...(data.monitorMetric ? { monitorMetric: data.monitorMetric } : {}),
      ...(data.monitorPeriod ? { monitorPeriod: data.monitorPeriod } : {}),
      ...(data.job ? { job: data.job } : {}),
      ...(data.settingsTab ? { settingsTab: data.settingsTab } : {}),
      ...(data.layer ? { layer: data.layer, topologyFocus: "", topologyLayers: "" } : {}),
      ...(data.topologyFocus ? { topologyFocus: data.topologyFocus } : {}),
      ...(data.view === "topology" ? { topologyMark: data.topologyMark || "" } : {}),
    }, focus && (jobFocus || focus));
    if (focus && jobFocus) app.querySelector(jobFocus)?.scrollIntoView({ block: eventRow ? "center" : "start" });
    if (focus && data.view === "service" && data.adapterSection) {
      const settings = document.getElementById("adapter-settings-title");
      settings?.scrollIntoView({ block: "start" });
      settings?.focus({ preventScroll: true });
    }
    if (focus && data.view === "network" && data.networkSection === "publications") {
      const section = document.getElementById("network-publications");
      section?.scrollIntoView({ block: "start" });
      section?.focus({ preventScroll: true });
    }
  }

  function render() {
    window.opstendTopology?.unmount?.();
    const theme = preferences === "system" ? (media.matches ? "dark" : "light") : preferences;
    document.documentElement.dataset.theme = theme;
    document.documentElement.lang = window.opstendLocale.ui();
    document.title = t("OpsTend RC2 · Bedienentwurf", "OpsTend RC2 · Interface preview");
    skipLink.textContent = t("Zum Inhalt", "Skip to content");
    const inventory = window.opstendDemo.getInventory();
    if (route.host && !inventory.hosts.some((host) => host.id === route.host)) {
      const wasEnrollmentHost = route.host === enrollmentHost();
      route.host = "";
      if (route.view === "host") {
        if (wasEnrollmentHost) Object.assign(route, { view: "settings", settingsTab: "hosts" });
        else route.view = "operations";
      }
      updateUrl(true);
    }
    inventory.hosts = inventory.hosts.map(window.opstendMonitoringData.projectHost);
    const hosts = Object.fromEntries(inventory.hosts.map((host) => [host.id, host]));
    const runtimeAction = route.view === "service" && Object.hasOwn(window.opstendDemo.runtimeLabels, route.serviceAction);
    if (runtimeAction) {
      const key = JSON.stringify([route.host, route.serviceId, route.serviceAction]);
      if (runtimeReview?.key !== key) runtimeReview = { key,
        preview: window.opstendDemo.previewRuntime(route.serviceId, route.serviceAction, inventory) };
    } else runtimeReview = null;
    const state = { ...route, theme, themePreference: preferences, inventory, hosts, message,
      runtimePreview: runtimeReview?.preview, ...helpers };
    const parentViews = { host: "inventory", "host-maintenance": "inventory", service: "services", "guest-create": "services",
      "network-detail": "network", "network-port": "network", "network-rule": "network", "access-detail": "network", "pve-inventory": "inventory" };
    const activeView = parentViews[route.view] || route.view;
    const menuItem = ([id, de, en]) => `<button class="nav-item" data-view="${id}" ${activeView === id ? 'aria-current="page"' : ""}>${icon(id)}${t(de, en)}</button>`;
    const nav = navigation.map(([de, en, items]) => `<nav class="nav-group" aria-label="${t(de, en)}">
      <h2>${t(de, en)}</h2>${items.map(menuItem).join("")}</nav>`).join("");
    const hostLinks = Object.values(hosts).map((host) => `<button class="host-link" ${route.view === "host" && route.host === host.name ? 'aria-current="page"' : ""} data-view="host" data-host="${host.name}">${icon("host")}${host.name}<small>${host.type}</small></button>`).join("");
    const hostOptions = Object.values(hosts).map((host) => `<option value="${host.name}" ${route.host === host.name ? "selected" : ""}>${host.name}</option>`).join("");
    const themeAction = theme === "dark" ? t("Helles Farbschema aktivieren", "Switch to light theme")
      : t("Dunkles Farbschema aktivieren", "Switch to dark theme");
    const view = window.opstendViews[route.view];
    app.innerHTML = `
      <div class="app-shell">
        <aside class="sidebar" ${navOpen ? "data-nav-open" : ""}>
          <div class="sidebar-header">
            <div class="brand">
              <img src="${brandDirectory}/opstend-dark.svg" alt="" width="37" height="37">
              <div><strong>opstend</strong><span>by Grethel Labs</span></div>
            </div>
            <button class="mobile-menu" type="button" data-nav-toggle aria-expanded="${navOpen}" aria-controls="sidebar-navigation">${icon("menu")}${t("Menü", "Menu")}</button>
          </div>
          <div class="sidebar-navigation" id="sidebar-navigation">
            <div class="nav-list">${nav}</div>
            <nav class="configuration-nav" aria-label="${t("Systemkonfiguration", "System configuration")}">${menuItem(["settings", "Configuration", "Configuration"])}</nav>
            <nav class="site-tree" aria-label="${t("Maschinen", "Hosts")}">
              <h2>${t("Maschinen", "Hosts")}</h2>
              ${hostLinks}
            </nav>
            <div class="sidebar-foot"><span>RC2-Demo${document.documentElement.dataset.demoBuild ? ` · ${escape(document.documentElement.dataset.demoBuild.slice(0, 8))}` : ""}</span></div>
          </div>
        </aside>
        <div class="workspace">
          <header class="toolbar">
            <label class="scope-control">${icon("scope")}<select id="scope" aria-label="${t("Geltungsbereich", "Scope")}"><option value="">${t("Ganze Flotte", "Entire fleet")}</option>${hostOptions}</select></label>
            <form class="quick-search" role="search" id="search">
              ${icon("search")}<input name="query" aria-label="${t("Ressourcen suchen", "Search resources")}" placeholder="${t("Host, Dienst oder Gerät suchen", "Search hosts, services, or devices")}" value="${escape(route.query)}">
            </form>
            <p class="demo-label">${t("Bedienentwurf · Beispieldaten", "Interface preview · Sample data")}</p>
            <button type="button" class="theme-control" id="theme" data-theme-toggle data-theme-preference="${theme === "dark" ? "light" : "dark"}" aria-label="${themeAction}" title="${themeAction}">${icon(theme === "dark" ? "moon" : "sun")}</button>
          </header>
          <main id="content" class="page" tabindex="-1">
            ${view ? view(state) : `<p>${t("Diese Ansicht wird vorbereitet.", "This view is under development.")}</p>`}
          </main>
        </div>
        ${window.opstendDeploy?.render(state) || ""}
      </div>`;
    window.opstendDeploy?.mount?.(state);
    if (route.view === "topology") window.opstendTopology?.mount(state);
    if (route.view === "pve-inventory") window.opstendPveInventoryUI?.mount(state);
    window.opstendAutonomy?.schedule();
  }

  function renderPreservingFocus() {
    const focused = document.activeElement?.id;
    render();
    if (focused) document.getElementById(focused)?.focus({ preventScroll: true });
  }

  async function confirmRuntime(button) {
    const { view, host, serviceId, serviceAction } = route;
    const currentPreview = window.opstendDemo.previewRuntime(serviceId, serviceAction, window.opstendDemo.getInventory({ fresh: true }));
    if (!currentPreview.ok || currentPreview.plan.binding !== button.dataset.runtimeBinding) {
      message = currentPreview.ok ? t("Der Gastzustand hat sich geändert. Öffne die Vorschau erneut.", "The guest state changed. Open the preview again.")
        : t(currentPreview.error, currentPreview.errorEn || currentPreview.error);
      setRoute({ serviceAction: "" });
      return;
    }
    button.disabled = true;
    let result;
    try {
      result = await window.opstendDemo.requestRuntime(currentPreview.plan);
    } catch {
      result = { ok: false, error: "Der Laufzeitauftrag konnte nicht gespeichert werden.", errorEn: "The runtime job could not be saved." };
    }
    if (route.view !== view || route.host !== host || route.serviceId !== serviceId || route.serviceAction !== serviceAction) return;
    if (result.ok) {
      navigateTo({ view: "changes", host: result.job.host, job: result.job.id });
    } else {
      message = t(result.error, result.errorEn || result.error);
      setRoute({ serviceAction: "" });
    }
  }

  function handleClick(event) {
    const button = event.target.closest("button");
    if (!button) return;
    const data = button.dataset;
    if ("navToggle" in data) {
      setNavigation(!navOpen);
      return;
    }
    if (["system", "light", "dark"].includes(data.themePreference)) {
      preferences = data.themePreference;
      try { localStorage.setItem("opstend-rc2-theme", preferences); } catch {}
      render();
      (app.querySelector(`[data-theme-preference="${preferences}"]:not([data-theme-toggle])`) || document.getElementById("theme")).focus({ preventScroll: true });
      return;
    }
    if (data.view) {
      navigateTo(data);
      return;
    }
    if ("openJobList" in data) {
      const list = document.getElementById("manage-jobs-title");
      list?.focus({ preventScroll: true });
      list?.scrollIntoView({ block: "start" });
      return;
    }
    if (data.serviceAction) {
      runtimeReview = null;
      message = "";
      setRoute({ serviceAction: data.serviceAction }, "#service-action");
      return;
    }
    if (route.view === "monitoring" && data.monitorHost && knownHost(data.monitorHost)) {
      setRoute({ monitorHost: data.monitorHost }, "#monitor-series-title");
      const block = matchMedia("(max-width: 1050px)").matches ? "start" : "nearest";
      document.getElementById("monitor-series-title")?.scrollIntoView({ block });
      return;
    }
    if (route.view === "topology" && "clearTopologyMark" in data) {
      setRoute({ topologyMark: "" }, "#topology-selection");
      return;
    }
    const controls = [
      ["layer", "data-layer"], ["topologyFocus", "data-topology-focus"], ["job", "data-job"],
      ["settingsTab", "data-settings-tab"], ["hostTab", "data-host-tab"], ["inventoryTab", "data-inventory-tab"],
    ];
    for (const [key, attribute] of controls) {
      if (data[key]) {
        const update = { [key]: data[key] };
        if (key === "layer") Object.assign(update, { topologyFocus: "", topologyLayers: "" });
        if (key === "job") {
          update.jobEvent = "";
          if (matchMedia("(max-width: 900px)").matches) {
            setRoute(update, "#manage-job-title");
            document.getElementById("manage-job-title")?.scrollIntoView({ block: "start" });
            return;
          }
        }
        setRoute(update, `button[${attribute}="${CSS.escape(data[key])}"]`);
        return;
      }
    }
    if ("clearSearch" in data) setRoute({ query: "" }, "#search input");
    if ("clearEvents" in data) setRoute({ eventKind: "", eventQuery: "", eventSubject: "" }, "#event-query");
    if ("cancelServiceAction" in data) setRoute({ serviceAction: "" });
    if ("confirmServiceAction" in data && route.view === "service") {
      const demo = window.opstendDemo;
      if (Object.hasOwn(demo.runtimeLabels, route.serviceAction)) {
        void confirmRuntime(button);
        return;
      }
      if (!["retire", "remove"].includes(route.serviceAction)) return;
      const result = demo.retireService(route.serviceId, route.serviceAction === "remove");
      message = result === true ? "Im Demo-Inventar gespeichert. Die Details stehen im Auftragsprotokoll." : result;
      setRoute({ serviceAction: "" });
    }
    if ("simulateReplicaFailure" in data) {
      const result = window.opstendDemo.simulateReplicaFailure();
      message = result === true ? "Ausfall simuliert. Der Ersatz wurde platziert und die aktive Instanz neu gewählt." : result;
      setRoute({});
    }
  }

  function setNavigation(open) {
    navOpen = open;
    app.querySelector(".sidebar").toggleAttribute("data-nav-open", navOpen);
    app.querySelector("[data-nav-toggle]").setAttribute("aria-expanded", String(navOpen));
  }

  app.addEventListener("click", handleClick);
  document.addEventListener("keydown", (event) => {
    if (event.defaultPrevented || document.querySelector("dialog[open]")) return;
    if (event.key === "Escape" && navOpen) {
      setNavigation(false);
      app.querySelector("[data-nav-toggle]").focus();
    }
    if (event.key === "/" && !event.ctrlKey && !event.metaKey && !event.altKey
      && !event.target.closest("input, textarea, select, [contenteditable]")) {
      event.preventDefault();
      document.querySelector("#search input").focus();
    }
  });
  app.addEventListener("submit", (event) => {
    if (event.target.id === "event-filters") {
      event.preventDefault();
      const form = new FormData(event.target);
      const query = String(form.get("eventQuery") || "").trim().slice(0, 160);
      const kind = form.get("eventKind");
      const subject = String(form.get("eventSubject") || "").slice(0, 160);
      setRoute({ eventQuery: query, eventKind: allowed.eventKind.includes(kind) ? kind : "", eventSubject: subject }, "#event-query");
      return;
    }
    if (event.target.id !== "search") return;
    event.preventDefault();
    const query = String(new FormData(event.target).get("query") || "").trim().slice(0, 160);
    setRoute({ view: "inventory", query, inventoryTab: "all" });
  });
  app.addEventListener("change", (event) => {
    const { id, value } = event.target;
    const monitorFilter = { "monitor-metric": "monitorMetric", "monitor-period": "monitorPeriod" }[id];
    if (route.view === "monitoring" && monitorFilter && allowed[monitorFilter].includes(value)) {
      setRoute({ [monitorFilter]: value }, `#${id}`);
    } else if (id === "scope") {
      const host = value;
      const service = route.view === "service" && window.opstendDemo.getInventory().services.find((item) => item.id === route.serviceId);
      let view = route.view;
      if (!host && view === "host") view = "operations";
      if (host && service && service.host !== host) view = "services";
      setRoute({ host, topologyFocus: "", topologyMark: "", view, serviceAction: "", ...(view === "events" ? { eventSubject: "" } : {}),
        ...(view === "monitoring" ? { monitorHost: host } : {}) }, "#scope");
    }
  });
  skipLink.addEventListener("click", (event) => {
    event.preventDefault();
    document.getElementById("content").focus();
  });
  window.addEventListener("hashchange", () => { route = readRoute(); render(); });
  window.addEventListener("opstend:inventory-changed", () => render());
  window.addEventListener("opstend:host-enrollment-changed", () => render());
  window.addEventListener("opstend:host-maintenance-changed", renderPreservingFocus);
  window.addEventListener("opstend:autonomy-changed", renderPreservingFocus);
  window.addEventListener("opstend:network-rules-changed", () => render());
  window.addEventListener("opstend:publication-changed", renderPreservingFocus);
  window.addEventListener("opstend:pve-inventory-changed", () => {
    if (route.view === "pve-inventory") renderPreservingFocus();
  });
  window.addEventListener("opstend:locale-changed", renderPreservingFocus);
  window.addEventListener("opstend:zorec-navigate", (event) => {
    if (!document.querySelector('#zorec-dialog[open]:is([data-shell="admin-read"], [data-shell="admin-edit"])')) return;
    const target = window.opstendZorecNavigation.targets({ ...route, inventory: window.opstendDemo.getInventory() })
      .find(({ id }) => id === event.detail?.id);
    if (!target) return;
    const data = Object.fromEntries(Object.entries(target.route).map(([key, value]) =>
      [key.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase()), value]));
    if (!allowed.view.includes(data.view)) return;
    event.preventDefault();
    navigateTo(data, false);
    window.scrollTo(0, 0);
  });
  window.addEventListener("opstend:topology-select", (event) => {
    if (route.view === "topology" && typeof event.detail === "string") {
      route.topologyFocus = event.detail;
      updateUrl(true);
      window.opstendDeploy.selectTopologyTarget(route.topologyFocus);
    }
  });
  window.addEventListener("opstend:topology-layers", (event) => {
    if (route.view === "topology" && typeof event.detail === "string") {
      route.topologyLayers = event.detail;
      updateUrl(true);
    }
  });
  media.addEventListener("change", () => { if (preferences === "system") render(); });
  render();

  const loadedBuild = document.documentElement.dataset.demoBuild;
  if (loadedBuild) {
    const poll = setInterval(checkBuild, 12000);
    document.addEventListener("visibilitychange", checkBuild);
    checkBuild();

    async function checkBuild() {
      if (document.hidden || document.querySelector(".demo-update")) return;
      try {
        const response = await fetch("demo-version.json", { cache: "no-store" });
        if (!response.ok) return;
        const { build } = await response.json();
        if (!/^[a-f0-9]{12}$/.test(build) || build === loadedBuild || document.querySelector(".demo-update")) return;
        clearInterval(poll);
        document.removeEventListener("visibilitychange", checkBuild);
        const notice = document.createElement("div");
        notice.className = "demo-update";
        notice.innerHTML = `<span role="status">${t("Neue Demo-Version verfügbar", "A new demo build is available")}</span><button type="button" class="button">${t("Aktualisieren", "Update")}</button>`;
        notice.querySelector("button").addEventListener("click", () => {
          const url = new URL(location.href);
          url.searchParams.set("build", build);
          location.replace(url);
        });
        document.body.append(notice);
      } catch { /* The local server can be between builds. */ }
    }
  }
})();
