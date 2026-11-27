(function () {
  "use strict";

  const monitoringData = window.opstendMonitoringData;
  const capacity = monitoringData.capacity;
  const tones = { Gesund: "good", Erreichbar: "good", "Wird geprüft": "warn", Warnung: "warn", Vorgemerkt: "warn",
    "Health offen": "warn", Ausgefallen: "danger", Offline: "danger", "Nicht erreichbar": "danger", Wartung: "maintenance" };
  const t = (de, en) => window.opstendLocale?.t(de, en) ?? de;
  const time = new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Berlin", hour: "2-digit", minute: "2-digit" });
  const inventoryLabels = new Map([
    ["Gesund", "Healthy"], ["Erreichbar", "Reachable"], ["Wird geprüft", "Verifying"], ["Warnung", "Warning"],
    ["Zuletzt erreichbar", "Last known reachable"], ["Ungeprüft", "Unchecked"], ["Nicht erreichbar", "Unreachable"],
    ["Vorgemerkt", "Planned"], ["Ausgefallen", "Failed"], ["Wartung", "Maintenance"], ["Gestoppt", "Stopped"],
    ["Stillgelegt", "Retired"], ["Läuft", "Running"], ["Wiederhergestellt", "Recovered"], ["Health offen", "Health check pending"],
    ["Entfernung vorgemerkt", "Removal planned"], ["Früherer Vorgang", "Previous job"], ["Abgeschlossen", "Completed"],
    ["Entscheidung ausstehend", "Decision pending"], ["Wartet auf Freigabe", "Awaiting approval"],
    ["Freigegeben", "Approved"], ["Abgelehnt", "Rejected"], ["Genehmigt", "Approved"],
    ["Update verfügbar", "Update available"], ["Update vorbereitet", "Update prepared"],
    ["Update bestätigt", "Update confirmed"], ["Voriger Stand wiederhergestellt", "Previous version restored"],
    ["Linux-Agent", "Linux agent"], ["Hostaufnahme", "Host enrollment"], ["Container · Podman", "Podman container"],
    ["Bestand", "Discovered"], ["NAS-Connector", "NAS connector"], ["NFS-Freigabe", "NFS share"], ["Netzgerät", "Network device"],
    ["Uplink offen", "Uplink unknown"], ["Nach Aufnahmerichtlinie", "Based on enrollment policy"],
    ["Virtueller Uplink · Linkrate unbekannt", "Virtual uplink · link speed unknown"],
    ["Konfigurierte Beziehung", "Configured relationship"], ["Link-Beobachtung", "Observed link"],
    ["Verbindungsprüfung", "Connectivity check"], ["Historische Verbindungsprüfung", "Historical connectivity check"],
    ["Entwurf", "Draft"], ["Unbekannt", "Unknown"],
  ]);
  const displayLabel = (value) => t(value, inventoryLabels.get(value) ?? value);

  const readingNote = (reading) => window.opstendMonitoring.readingNote(reading);
  const sourceSummary = (state) => window.opstendMonitoring.sourceSummary(state);

  function hostObservationNote(host) {
    const { at, source, freshness } = host.observation;
    if (at === null) return source ? `${t("Status aus", "Status from")} ${t("Demo-Inventar", "demo inventory")}`
      : t("Keine Erreichbarkeitsprobe", "No reachability check");
    const label = window.opstendMonitoring.sourceLabel(source);
    const mark = freshness === "stale" ? t("Beleg veraltet", "Stale check") : t("Probe", "Check");
    return `${mark} ${time.format(at)} · ${label}`;
  }

  function hostCounts(hosts) {
    const status = { reachable: 0, offline: 0, unknown: 0, maintenance: 0 };
    for (const host of hosts) {
      status[host.observation.reachability]++;
      if (host.status === "Wartung") status.maintenance++;
    }
    return status;
  }

  const intro = (scope, title, text, controls = "") => `
    <div class="page-intro split">
      <div><p class="eyebrow">${scope}</p><h1>${title}</h1>${text ? `<p>${text}</p>` : ""}</div>
      ${controls}
    </div>`;
  const metric = (state, label, value, detail, icon) => `
    <article class="panel metric"><div>${label} ${state.icon(icon)}</div><strong>${value}</strong><small>${detail}</small></article>`;
  const head = (title, subtitle = "", action = "") => `<div class="panel-head"><div><h2>${title}</h2>${subtitle ? `<p>${subtitle}</p>` : ""}</div>${action}</div>`;
  const meter = (label, value, maximum, suffix) => value === null || !maximum ? `<div class="meter"><div class="row-title"><span>${label}</span>
    <strong>${maximum ? t(`Belegung offen · ${maximum} ${suffix}`, `Usage unknown · ${maximum} ${suffix}`)
      : t("Kapazität offen", "Capacity unknown")}</strong></div></div>` : `
    <div class="meter"><div class="row-title"><span>${label}</span><strong>${value} / ${maximum} ${suffix}</strong></div>
    <div class="track" role="meter" aria-label="${label}" aria-valuemin="0" aria-valuemax="${maximum}" aria-valuenow="${value}"><span style="width:${value / maximum * 100}%"></span></div></div>`;
  const tabs = (items, current, id) => `<div class="tabs" role="group" aria-label="${id === "host-tab" ? t("Maschinenansicht", "Host view") : t("Inventarfilter", "Inventory filters")}">${items.map(([key, label]) =>
    `<button type="button" data-${id}="${key}" aria-pressed="${key === current}">${label}</button>`).join("")}</div>`;

  function coverageNote(summary) {
    return t(`${summary.measuredHosts} von ${summary.hosts} Hosts mit aktuellen Messwerten`,
      `${summary.measuredHosts} of ${summary.hosts} hosts have current readings`);
  }

  function capacityMeter(label, summary) {
    const current = summary.measuredHosts > 0;
    const maximum = current ? summary.measuredCapacity : summary.capacity;
    const partial = summary.measuredHosts !== summary.hosts;
    const total = summary.capacity && partial && current
      ? t(`${summary.capacity} GiB erfasste Gesamtkapazität`, `${summary.capacity} GiB total known capacity`) : "";
    return `<div>${meter(label, current ? summary.used : null, maximum, "GiB")}
      <p class="compact capacity-coverage">${[coverageNote(summary), total].filter(Boolean).join(" · ")}</p></div>`;
  }

  function displayJobTitle({ id, host, title }) {
    if (!t(false, true)) return title;
    if (id === "sensorik") return "Sensorik restarted";
    if (id === "route") return "HTTPS approval for Medien";
    if (id === "entwicklung") return "Entwicklung VM started";
    if (id?.startsWith("own-update-")) return "OpsTend update on " + host;
    return title;
  }

  function activity(state) {
    const observations = [
      { time: "14:03", title: t("HTTPS-Test erfolgreich", "HTTPS check succeeded"), host: "edge-01",
        status: t("Route zum LXC Fotos geprüft.", "Route to the Fotos LXC checked.") },
      { time: "13:47", title: t("GPU-Zuordnung bestätigt", "GPU assignment confirmed"), host: "nuc-a",
        status: t("QEMU-VM Medien · Beispielbeobachtung", "Medien QEMU VM · demo observation") },
    ].filter((item) => !state.host || item.host === state.host);
    const rows = [...window.opstendViews.jobsForScope(state), ...observations].slice(0, 8);
    const entries = rows.map((row) => {
      const { id, time, host, status } = row;
      const title = state.escape(displayJobTitle(row));
      return `<li>
      <time>${state.escape(time)}</time><div>
        ${id ? `<button class="text-button" data-view="changes" data-job="${state.escape(id)}">${title}</button>`
          : `<strong>${title}</strong>`}
        <p>${state.escape(host)} · ${state.escape(displayLabel(status))}</p>
      </div></li>`;
    }).join("");
    return `<section class="panel">
      ${head(t("Letzte Aktivität", "Recent activity"), "", `<button class="text-button" data-view="changes">${t("Verlauf ansehen", "View history")}</button>`)}
      ${entries ? `<ul class="feed activity-feed">${entries}</ul>` : `<p class="panel-pad compact">${t("Für diesen Host gibt es noch keine Aktivität.", "This host has no activity yet.")}</p>`}
    </section>`;
  }

  function displayAttention(job) {
    const { id, attention, recovery, selfUpdate, host } = job;
    if (!t(false, true)) return attention;
    if (id === "route") return {
      title: "Publish Medien externally", impact: "The HTTPS address would route external requests to Medien on nuc-a.",
      status: "Your approval is required", action: "Review approval",
    };
    if (id === "sensorik") {
      if (attention.kind === "decision") return {
        title: "Check Sensorik again", impact: "The approved restart ran. You can start another health check.",
        status: "Your decision is required", action: "Review health check",
      };
      if (recovery?.phase === "failed") return {
        title: "Sensorik is still unresponsive", impact: "The health check after the restart failed.",
        status: "Recovery unconfirmed", action: "View incident",
      };
      const rerun = recovery?.events?.length > 0;
      return {
        title: "Sensorik did not respond",
        impact: rerun ? "You started another health check." : "Three health checks failed. The service was restarted.",
        status: rerun ? "Zorec is verifying the new result" : "Zorec is verifying recovery",
        action: "Follow health check",
      };
    }
    if (selfUpdate) return {
      title: "OpsTend update on " + host,
      impact: attention.status === "Update verfügbar" ? "Prepare the demo release to compare patches."
        : "Review the local patch mapping and approve the update.",
      status: displayLabel(attention.status), action: "View update",
    };
    return attention;
  }

  function operationsQueue(state, jobs, title, kind, empty) {
    const decision = kind === "decision";
    return `<section class="panel ops-queue ops-queue-${kind}" aria-labelledby="ops-${kind}">
      <header class="ops-queue-head">
        <span class="ops-queue-icon">${state.icon(decision ? "shield" : "warning")}</span>
        <h2 id="ops-${kind}">${title}</h2>
        <span class="ops-queue-count">${jobs.length}</span>
      </header>
      ${jobs.length ? `<ul class="ops-cases">${jobs.map((job) => {
        const { id, host, relatedHost, tone } = job;
        const attention = displayAttention(job);
        return `
        <li>
          <h3>${state.escape(attention.title)}</h3>
          <p>${state.escape(attention.impact)}</p>
          <div class="ops-case-footer">
            <div>
              ${window.opstendMascot.render(decision ? "awaiting-approval" : tone === "warn" ? "failed" : "verifying")}
              ${state.badge(attention.status, decision || tone === "warn" ? "warn" : "active")}
            </div>
            <span class="ops-case-scope">${state.escape(host)}${relatedHost ? ` → ${state.escape(relatedHost)}` : ""}</span>
            <button type="button" class="button${decision ? " primary" : ""}" data-view="changes" data-job="${state.escape(id)}"
              data-host="${state.escape(state.host || host)}">${state.escape(attention.action)}${state.icon("arrow")}</button>
          </div>
        </li>`;
      }).join("")}</ul>` : `<p class="ops-clear">${empty}</p>`}
    </section>`;
  }

  function operations(state) {
    const host = state.host && state.hosts[state.host];
    const workloads = state.inventory.services;
    const scoped = host ? workloads.filter((item) => item.host === host.id) : workloads;
    const attention = window.opstendViews.attention(state);
    const incidents = attention.filter((job) => job.attention.kind === "incident");
    const decisions = attention.filter((job) => job.attention.kind === "decision");
    const current = host && capacity(host);
    const cpu = host && monitoringData.read(state, host.id, "cpu", "1h");
    const monitoring = window.opstendMonitoring;
    const sources = sourceSummary(state);
    const memory = monitoringData.capacityCoverage(state, "ram");
    const storage = monitoringData.capacityCoverage(state, "storage");
    const hosts = state.inventory.hosts;
    const sites = [...new Set(hosts.map((item) => item.site))];
    const { reachable, unknown, offline } = hostCounts(hosts);
    const reachability = [t(`${reachable} erreichbar`, `${reachable} reachable`),
      unknown ? t(`${unknown} Belege offen`, `${unknown} checks pending`) : "",
      offline ? `${offline} offline` : ""].filter(Boolean).join(" · ");
    const healthy = (items) => items.filter((item) => item.status === "Gesund").length;
    const metrics = host ? [
      metric(state, t("Dienste", "Services"), scoped.length, `${healthy(scoped)} ${t("gesund", "healthy")}`, "inventory"),
      metric(state, t("CPU-Auslastung", "CPU usage"), monitoring.textValue(cpu.latestValue), readingNote(cpu), "cpu"),
      metric(state, t("RAM belegt", "RAM used"), memory.measuredHosts ? `${memory.used} GiB` : "—",
        readingNote(monitoringData.read(state, host.id, "ram", "1h")), "host"),
    ] : [
      metric(state, "Hosts", hosts.length, reachability, "host"),
      metric(state, t("Dienste", "Services"), workloads.length, `${healthy(workloads)} ${t("gesund · inklusive Core-Dienste", "healthy · including core services")}`, "inventory"),
      metric(state, t("RAM belegt", "RAM used"), memory.measuredHosts ? `${memory.used} GiB` : "—", coverageNote(memory), "cpu"),
    ];
    return `
      ${intro(host ? `${state.escape(host.site)} / ${state.escape(host.name)}` : t("Ganze Flotte", "Entire fleet"),
        host ? t(`Betrieb auf ${state.escape(host.name)}`, `Operations on ${state.escape(host.name)}`) : t("Betriebsübersicht", "Operations overview"), "",
        `<button class="button" data-view="${host ? "host" : "topology"}">${state.icon(host ? "host" : "topology")}${host ? t("Maschine öffnen", "Open host") : t("Topologie öffnen", "Open topology")}</button>`)}
      <div class="ops-queues">
        ${operationsQueue(state, incidents, t("Störungen", "Incidents"), "incident", t("Keine offenen Störungen.", "No open incidents."))}
        ${operationsQueue(state, decisions, t("Anstehende Entscheidungen", "Pending decisions"), "decision", t("Keine Entscheidung ausstehend.", "No pending decisions."))}
      </div>
      <div class="metrics">${metrics.join("")}</div>
      <div class="ops-grid">
        <div class="ops-stack">
          <section class="panel">
            ${head(host ? t("Dienste", "Services") : t("Standorte", "Sites"),
              host ? t("Status der registrierten Dienste", "Status of registered services") : t("Erreichbarkeit und Arbeitslast", "Reachability and workloads"),
              `<button class="text-button" data-view="services">${t("Zu Diensten", "Go to services")} →</button>`)}
            ${host ? workloadTable(state, scoped, false) : `
              <div class="table-wrap" tabindex="0" aria-label="${t("Standorte", "Sites")}">
                <table class="data-table"><thead><tr><th scope="col">${t("Standort", "Site")}</th><th scope="col">Hosts</th><th scope="col">Workloads</th><th scope="col">${t("Zustand", "Status")}</th></tr></thead>
                <tbody>
                  ${sites.map((site) => {
                    const siteHosts = hosts.filter((item) => item.site === site);
                    const count = hostCounts(siteHosts);
                    const members = workloads.filter((item) => state.hosts[item.host]?.site === site);
                    const localIncidents = incidents.filter((item) => state.hosts[item.host]?.site === site);
                    const siteStatus = count.offline ? [t("Host offline", "Host offline"), "danger"]
                      : localIncidents.some((item) => item.tone === "warn") ? [t("Störung offen", "Open incident"), "warn"]
                        : localIncidents.length ? [t("Prüfung läuft", "Health check in progress"), "warn"]
                          : count.maintenance ? [t("Wartung", "Maintenance"), "maintenance"]
                            : count.unknown ? [t("Belege offen", "Checks pending"), ""] : [t("Erreichbar", "Reachable"), "good"];
                    return `<tr><td class="cell-main">${state.escape(site)}</td><td>${count.reachable} / ${siteHosts.length} ${t("erreichbar", "reachable")}
                      ${count.unknown ? `<small>${count.unknown} ${t("Belege offen", "checks pending")}</small>` : ""}</td><td>${members.length}</td>
                      <td>${state.badge(...siteStatus)}</td></tr>`;
                  }).join("")}
                </tbody></table>
              </div>`}
          </section>
          ${activity(state)}
        </div>
        <div class="ops-stack">
          <section class="panel">
            ${head(t("Kapazität", "Capacity"), t("Gemessene Nutzung und erfasste Kapazität", "Measured usage and known capacity"))}
            <div class="panel-pad capacity-mini">
              ${capacityMeter(t("Arbeitsspeicher", "Memory"), memory)}
              ${capacityMeter(t("Lokaler Speicher", "Local storage"), storage)}
              ${!host && state.inventory.networks.some((network) => network.id === "storage") ? `<p class="compact">${t("Geteilter Speicher · Kapazität offen", "Shared storage · capacity unknown")}
                <button type="button" class="text-button" data-view="network-detail" data-network-id="storage">${t("Speichernetz", "Storage network")}</button></p>` : ""}
            </div>
          </section>
          <section class="panel">
            ${head(t("Datenquellen", "Data sources"), t("Letzte Stunde", "Last hour"), `<button type="button" class="text-button" data-view="monitoring" data-monitor-period="1h">${t("Überwachung öffnen", "Open monitoring")}</button>`)}
            <div class="panel-pad compact">${host ? window.opstendMonitoring.sourceLabel(current.source) + " · " : ""}${sources}</div>
          </section>
        </div>
      </div>`;
  }

  function inventory(state) {
    const hostItems = Object.values(state.hosts).map((host) => {
      const resource = capacity(host);
      return { ...host, kind: "host", network: host.name === "edge-01" ? "VPN" : host.budgets ? "Bestand" : "VLAN 20", source: resource.source, label: host.runtime, currentHost: host.name,
        detail: `${resource.ram ?? "—"} / ${resource.ramTotal} GiB RAM` };
    });
    const workloadItems = state.inventory.services.map((workload) => ({
      ...workload, kind: "workload", label: workload.kind, currentHost: workload.host, site: state.hosts[workload.host].site,
      source: workload.sourceHost ? "Hostaufnahme" : capacity(state.hosts[workload.host]).source, detail: `${workload.cpu} · ${workload.ram}`,
    }));
    const deviceItems = state.inventory.devices.map((device) => ({
      ...device, kind: "device", label: device.kind, currentHost: "", status: "Erreichbar",
      network: device.id === "nas" ? "VLAN 30" : "VLAN 10 / 20 / 30",
      source: device.id === "nas" ? "NAS-Connector" : "UniFi", detail: device.id === "nas" ? "NFS-Freigabe" : "Netzgerät",
    }));
    const sourceItems = [...hostItems, ...workloadItems, ...deviceItems];
    const scoped = state.host ? sourceItems.filter((item) => item.currentHost === state.host) : sourceItems;
    const query = state.query.toLocaleLowerCase("de");
    const filtered = scoped.filter((item) => (state.inventoryTab === "all" || item.kind === state.inventoryTab)
      && (!query || [item.name, item.site, item.label, item.network, item.currentHost, item.ip, item.role].join(" ").toLocaleLowerCase("de").includes(query)));
    const filters = [["all", t("Alle", "All")], ["host", "Hosts"], ["workload", "Workloads"], ["device", t("Geräte", "Devices")]].map(([key, label]) => [
      key, `${label} (${key === "all" ? scoped.length : scoped.filter((item) => item.kind === key).length})`,
    ]);
    return `
      ${intro(state.host || t("Ganze Flotte", "Entire fleet"), t("Inventar", "Inventory"),
        t("Hosts, Workloads und Geräte nach Standort, Quelle und Zustand vergleichen.", "Compare hosts, workloads and devices by site, source and status."),
        window.opstendPveInventoryUI?.link(state) || "")}
      <section class="panel inventory-table">
        <div class="inventory-toolbar">${tabs(filters, state.inventoryTab, "inventory-tab")}
          ${query ? `<button class="button" data-clear-search>${t("Suche löschen", "Clear search")}</button>` : `<span class="compact">${t("Beobachtung", "Observation")} · 14:21</span>`}</div>
        <div class="table-wrap" tabindex="0" aria-label="${t("Inventarliste", "Inventory list")}">
          <table class="data-table"><thead><tr>
            <th scope="col">${t("Ressource", "Resource")}</th><th scope="col">${t("Typ", "Type")}</th><th scope="col">${t("Standort / Host", "Site / Host")}</th><th scope="col">${t("Netz / IPv4", "Network / IPv4")}</th><th scope="col">${t("Zustand", "Status")}</th><th scope="col">${t("Quelle", "Source")}</th>
          </tr></thead>
          <tbody>${filtered.length ? filtered.map((item) => `<tr>
            <td><button class="text-button" ${item.kind === "workload" ? `data-view="service" data-service-id="${item.id}"` : item.kind === "host"
              ? `data-view="host" data-host="${item.currentHost}"` : `data-view="topology" data-layer="physical" data-topology-focus="${item.id}"`}>${state.escape(item.name)}</button><small>${state.escape(displayLabel(item.detail))}</small></td>
            <td>${state.escape(displayLabel(item.label))}</td><td>${state.escape(item.site)}${item.kind === "workload" ? `<small>${state.escape(item.currentHost)}</small>` : ""}</td>
            <td>${state.escape(displayLabel(item.network))}<small class="mono">${state.escape(item.ip || t("Offen", "Unknown"))}</small></td><td>${state.badge(displayLabel(item.status), tones[item.status])}</td><td>${state.escape(displayLabel(item.source))}</td>
          </tr>`).join("") : `<tr><td colspan="6">${t("Keine Ressourcen entsprechen der aktuellen Suche.", "No resources match the current search.")}</td></tr>`}</tbody>
          </table>
        </div>
        <footer class="compact">${filtered.length} ${t("von", "of")} ${scoped.length} ${t("Ressourcen", "resources")}${query ? ` · ${t("Suche nach", "Searching for")} ${t("„", "“")}${state.escape(state.query)}${t("“", "”")}` : ""}</footer>
      </section>`;
  }

  function scopedNetwork(state, services) {
    const { inventory, host } = state;
    const scope = new Set([host, ...services.map((item) => item.id)]);
    const objects = new Map([...inventory.hosts, ...inventory.services, ...inventory.devices].map((item) => [item.id, item]));
    const links = inventory.links.filter((link) => objects.has(link.from) && objects.has(link.to)
      && (!host || scope.has(link.from) || scope.has(link.to)));
    const attached = new Set(links.flatMap((link) => [link.from, link.to]));
    const devices = inventory.devices.filter((item) => !host || attached.has(item.id));
    return { objects, links, devices };
  }

  function overviewHost(state, machine, serviceCount) {
    const { escape } = state;
    const id = escape(machine.id);
    const reading = monitoringData.read(state, machine.id, "cpu", "1h");
    const { textValue } = window.opstendMonitoring;
    const measurement = reading.latestValue === null ? t("CPU-Verlauf", "CPU history") : `CPU ${textValue(reading.latestValue)}`;
    const workloadCount = serviceCount === 1 ? t("1 Dienst", "1 service") : t(`${serviceCount} Dienste`, `${serviceCount} services`);
    return `<li class="fleet-host">
      <div><button class="text-button" type="button" data-view="host" data-host="${id}">${escape(machine.name)}</button>
        <small>${escape(machine.site)} · ${escape(machine.runtime)}</small></div>
      <div>${state.badge(displayLabel(machine.status), tones[machine.status])}<small>${escape(hostObservationNote(machine))}</small></div>
      <div><button class="text-button" type="button" data-view="monitoring" data-host="${id}" data-monitor-host="${id}"
        data-monitor-metric="cpu" data-monitor-period="1h">${measurement}</button><small>${escape(readingNote(reading))}</small></div>
      <button class="text-button" type="button" data-view="services" data-host="${id}">${workloadCount}</button>
    </li>`;
  }

  function overview(state) {
    const { host, inventory, escape } = state;
    const hosts = inventory.hosts.filter((item) => !host || item.id === host);
    const services = inventory.services.filter((item) => !host || item.host === host);
    const { links, devices } = scopedNetwork(state, services);
    const attention = window.opstendViews.attention(state);
    const incidents = attention.filter((job) => job.attention.kind === "incident");
    const decisions = attention.filter((job) => job.attention.kind === "decision");
    const deployments = services.filter((item) => item.status === "Vorgemerkt");
    const core = services.filter((item) => item.role !== "Anwendung");
    const eventCount = window.opstendViews.eventsForScope(state).length;
    const physicalLinks = links.filter((link) => link.layer === "physical").length;
    const accessLinks = links.filter((link) => link.layer === "access").length;
    const rules = window.opstendNetworkRules?.list(state).length || 0;
    const publications = window.opstendPublications?.list(state) || [];
    const areas = [
      [t("Betrieb", "Operations"), t(`Störungen ${incidents.length} · Entscheidungen ${decisions.length}`, `Incidents ${incidents.length} · Decisions ${decisions.length}`), "operations"],
      [t("Überwachung", "Monitoring"), sourceSummary(state), "monitoring"],
      [t("Hosts und Workloads", "Hosts and workloads"), `Hosts ${hosts.length} · ${t("Dienstinstanzen", "Service instances")} ${services.length}`, "inventory"],
      [t("Hostverwaltung", "Host management"), t("Aufnahme, Reset und Austritt", "Enrollment, reset and removal"), "settings", "hosts"],
      [t("Netzwerk", "Network"), t(`${devices.length} Geräte · ${physicalLinks} physische Links · ${accessLinks} Zugangspfade · ${rules} Regeln`,
        `${devices.length} devices · ${physicalLinks} physical links · ${accessLinks} access paths · ${rules} rules`), "network"],
      [t("HTTPS-Veröffentlichungen", "HTTPS publications"), t(`${publications.length} im Geltungsbereich`, `${publications.length} in scope`), "network", "publications"],
      [t("Zentrale Dienste", "Core services"), core.map((item) => item.name).join(", ") || t("Keine zentrale Instanz in diesem Bereich", "No core services in this scope"), "settings", "placement"],
      [t("Dienste und Deployments", "Services and deployments"), `${t("Vorgemerkte Deployments", "Planned deployments")} ${deployments.length}`, "services"],
      [t("Änderungen", "Changes"), t("Prüfungen, Freigaben und Ausführung", "Checks, approvals and execution"), "changes"],
      [t("Ereignisprotokoll", "Event log"), `${eventCount} ${eventCount === 1 ? t("Ereignis", "event") : t("Ereignisse", "events")} ${t("im Geltungsbereich", "in scope")}`, "events"],
      [t("Zugriff und Richtlinien", "Access and policies"), t("Anmeldemethoden, Rollen und Werkzeuge", "Sign-in methods, roles and tools"), "settings", "access"],
      [t("Schutz", "Protection"), t("Sicherungsziele und Wiederherstellung", "Backup targets and recovery"), "settings", "backup"],
    ];
    return `${intro(host || t("Ganze Flotte", "Entire fleet"), t("Systemübersicht", "System overview"), "",
      `<button class="button primary" data-view="topology" data-layer="all">${t("Gesamttopologie öffnen", "Open full topology")}</button>`)}
      <div class="network-tables">
        <section class="panel network-table" aria-label="${t("Fachbereiche", "Areas")}">
          <div class="table-wrap" tabindex="0" aria-label="${t("Fachbereiche als Tabelle", "Areas table")}">
            <table class="data-table"><thead><tr><th scope="col">${t("Fachbereich", "Area")}</th><th scope="col">${t("Im aktuellen Geltungsbereich", "In current scope")}</th></tr></thead>
              <tbody>${areas.map(([label, detail, view, tab]) => `<tr>
                <th scope="row"><button type="button" class="text-button" data-view="${view}"
                  ${view === "settings" && tab ? `data-settings-tab="${tab}"` : ""} ${tab === "publications" ? 'data-network-section="publications"' : ""} ${view === "events" ? 'data-event-subject=""' : ""}>${label}</button></th>
                <td>${escape(detail)}</td>
              </tr>`).join("")}</tbody>
            </table>
          </div>
        </section>
        <section class="panel network-table" aria-label="${t("Platzierung", "Placement")}">
          ${head(t("Platzierung", "Placement"), t("Betriebszustand und Messstand je Host", "Operating status and readings by host"))}
          ${hosts.length ? `<ul class="fleet-hosts" role="list" aria-label="${t("Platzierung nach Host", "Placement by host")}">
            ${hosts.map((item) => overviewHost(state, item, services.filter((service) => service.host === item.id).length)).join("")}</ul>`
            : `<p class="panel-pad compact">${t("Keine Hosts im Geltungsbereich.", "No hosts in this scope.")}</p>`}
        </section>
      </div>`;
  }

  function network(state) {
    const { inventory, host, escape } = state;
    const services = inventory.services.filter((item) => !host || item.host === host);
    const { objects, links, devices } = scopedNetwork(state, services);
    const physical = links.filter((link) => link.layer === "physical");
    const relations = links.filter((link) => link.layer === "network");
    const access = links.filter((link) => link.layer === "access");
    const demo = window.opstendDemo;
    const name = (id) => escape(objects.get(id)?.name ?? id);

    const graphLink = (item, layer, label) => `<button type="button" class="text-button"
      data-view="topology" data-layer="${layer}" data-topology-focus="${escape(item.id)}">${escape(label)}</button>`;

    const deviceRows = devices.map((item) => `<tr><td>${graphLink(item, links.find((link) => link.from === item.id || link.to === item.id)?.layer || "physical", item.name)}</td>
      <td>${escape(displayLabel(item.kind))}</td><td class="mono">${escape(item.ip || t("Offen", "Unknown"))}</td><td>${escape(item.site)}</td></tr>`).join("");
    const connectionRows = (items, showPorts = false) => items.map((item) => {
      const port = showPorts && window.opstendDemo.portConfiguration?.(item.id, inventory);
      return `<tr><td>${graphLink(item, item.layer, demo.linkLabel(item))}</td>
        <td>${name(item.from)}</td><td>${name(item.to)}</td>
        ${showPorts ? `<td>${port ? portLink(state, port) : "—"}</td>` : ""}</tr>`;
    }).join("");
    const networkRows = inventory.networks.map((item) => {
      const members = services.filter((service) => serviceInNetwork(item, service));
      return `<tr><td>${networkLink(state, item)}</td><td class="mono">${escape(item.cidr)}</td><td>${members.length}
        ${members.length ? `<small>${members.slice(0, 3).map((service) => escape(service.name)).join(", ")}${members.length > 3 ? ", …" : ""}</small>` : ""}</td></tr>`;
    }).join("");

    return `${intro(host || t("Ganze Flotte", "Entire fleet"), t("Netzwerk", "Network"), "",
      `<button class="button" data-view="topology" data-layer="physical">${t("Verkabelung öffnen", "Open physical topology")}</button>`)}
      <div class="network-tables">
        ${window.opstendNetworkRuleUi?.section(state) || ""}
        ${window.opstendPublicationUi?.section(state) || ""}
        ${networkTable(t("Geräte", "Devices"), [t("Gerät", "Device"), t("Typ", "Type"), "IPv4", t("Standort", "Site")],
          deviceRows, t("Keine Gerätebeziehungen im gewählten Bereich.", "No device relationships in the selected scope."))}
        ${networkTable(t("Switchports und Links", "Switch ports and links"),
          [t("Port und Linkrate", "Port and link speed"), t("Quelle", "Source"), t("Gegenstelle", "Peer"), t("Portdetails", "Port details")],
          connectionRows(physical, true), t("Keine physischen Links im gewählten Bereich.", "No physical links in the selected scope."))}
        ${networkTable(t("Netze und VLANs", "Networks and VLANs"),
          [t("Netz", "Network"), "CIDR", t("Dienstinstanzen im Geltungsbereich", "Service instances in scope")],
          networkRows, t("Keine Netze erfasst.", "No networks recorded."))}
        ${networkTable(t("Netzbeziehungen", "Network relationships"), [t("Verbindung", "Connection"), t("Quelle", "Source"),
          t("Ziel", "Destination"), t("Belegart", "Evidence type")], relations.map((link) => `<tr><td>${graphLink(link, link.layer, demo.linkLabel(link))}</td>
            <td>${name(link.from)}</td><td>${name(link.to)}</td><td>${escape(displayLabel(demo.linkEvidence(link).type))}</td></tr>`).join(""),
          t("Keine Netzbeziehungen im gewählten Bereich.", "No network relationships in the selected scope."))}
        ${networkTable(t("VPN und Veröffentlichung", "VPN and publishing"), [t("Verbindung", "Connection"), t("Quelle", "Source"), t("Ziel", "Destination")],
          connectionRows(access), t("Keine Zugangspfade im gewählten Bereich.", "No access paths in the selected scope."))}
      </div>`;
  }

  function networkTable(label, header, rows, empty) {
    return `<section class="panel network-table" aria-label="${label}">
      ${head(label)}
      <div class="table-wrap" tabindex="0" aria-label="${t(`${label} als Tabelle`, `${label} table`)}">
        <table class="data-table"><thead><tr>${header.map((column) => `<th scope="col">${column}</th>`).join("")}</tr></thead>
        <tbody>${rows || `<tr><td colspan="${header.length}">${empty}</td></tr>`}</tbody></table>
      </div>
    </section>`;
  }

  function networkLink(state, item) {
    return `<button type="button" class="text-button" data-view="network-detail" data-network-id="${state.escape(item.id)}">${state.escape(item.name)}</button>`;
  }

  function portLink(state, port, label = t("Port öffnen", "Open port")) {
    return `<button type="button" class="text-button" data-view="network-port" data-port-id="${state.escape(port.id)}">${state.escape(label)}</button>`;
  }

  function containsAddress(cidr, ip) {
    const toNumber = (address) => {
      const parts = address?.split(".") || [];
      if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return null;
      return parts.reduce((value, part) => (value << 8) | Number(part), 0);
    };
    const [base, prefix] = cidr.split("/");
    const start = toNumber(base);
    const address = toNumber(ip);
    const bits = Number(prefix);
    if (start === null || address === null || !prefix || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    if (bits === 0) return true;
    return (start >>> (32 - bits)) === (address >>> (32 - bits));
  }

  function serviceInNetwork(network, service) {
    return service.network ? service.network === network.name.split(" · ")[0] : containsAddress(network.cidr, service.ip);
  }

  function networkDetail(state) {
    const { inventory, escape, host } = state;
    const item = inventory.networks.find((entry) => entry.id === state.networkId);
    if (!item) {
      return `${intro(t("Netzwerk", "Network"), t("Netz nicht gefunden", "Network not found"), "",
        `<button type="button" class="button" data-view="network">${t("Alle Netze öffnen", "Open all networks")}</button>`)}`;
    }
    const hosts = inventory.hosts.filter((machine) => (!host || machine.id === host) && containsAddress(item.cidr, machine.ip));
    const workloads = inventory.services.filter((service) => (!host || service.host === host) && serviceInNetwork(item, service));
    const scoped = new Set([host, ...inventory.services.filter((service) => service.host === host).map((service) => service.id)]);
    const attached = new Set(inventory.links.filter((link) => scoped.has(link.from) || scoped.has(link.to))
      .flatMap((link) => [link.from, link.to]));
    const devices = inventory.devices.filter((device) => (!host || attached.has(device.id)) && containsAddress(item.cidr, device.ip));
    const members = new Set([...hosts, ...workloads, ...devices].map((entry) => entry.id));
    const links = inventory.links.filter((link) => (!host || scoped.has(link.from) || scoped.has(link.to))
      && (members.has(link.from) || members.has(link.to)));
    const nodes = new Map([...inventory.hosts, ...inventory.services, ...inventory.devices].map((entry) => [entry.id, entry.name]));
    const formatTime = new Intl.DateTimeFormat(t("de-DE", "en-GB"), { dateStyle: "short", timeStyle: "short" });
    const evidenceRows = links.map((link) => ({ link, evidence: window.opstendDemo.linkEvidence(link) }));
    const events = evidenceRows
      .filter(({ evidence }) => evidence.observedAt || evidence.type === "Entwurf")
      .sort((a, b) => (b.evidence.observedAt || "~").localeCompare(a.evidence.observedAt || "~"))
      .map(({ link, evidence }) => ({
        title: window.opstendDemo.linkLabel(link), status: `${displayLabel(evidence.type)} · ${evidence.source}`,
        time: evidence.observedAt ? formatTime.format(new Date(evidence.observedAt)) : "Demo",
      }));
    const mapLink = (id, layer, label) => `<button type="button" class="text-button" data-view="topology"
      data-layer="${layer}" data-topology-focus="${escape(id)}">${escape(label)}</button>`;
    const hostRows = hosts.map((machine) => `<tr><td><button type="button" class="text-button" data-view="host"
      data-host="${escape(machine.id)}">${escape(machine.name)}</button></td><td>${escape(machine.runtime)}</td><td class="mono">${escape(machine.ip)}</td></tr>`);
    const deviceRows = devices.map((device) => {
      const attachment = links.find((link) => link.from === device.id || link.to === device.id);
      return `<tr><td>${mapLink(device.id, attachment?.layer || "physical", device.name)}</td>
        <td>${escape(displayLabel(device.kind))}</td><td class="mono">${escape(device.ip)}</td></tr>`;
    });
    const connectionRows = evidenceRows.map(({ link, evidence }) => `<tr><td>${mapLink(link.id, link.layer, window.opstendDemo.linkLabel(link))}</td>
      <td>${escape(nodes.get(link.from) || link.from)} → ${escape(nodes.get(link.to) || link.to)}</td>
      <td>${escape(displayLabel(evidence.type))}</td></tr>`).join("");
    const portRows = inventory.links
      .filter((link) => link.layer === "physical")
      .map((link) => window.opstendDemo.portConfiguration?.(link.id, inventory))
      .filter((port) => port && (!host || scoped.has(port.deviceId) || scoped.has(port.peerId))
        && (port.current.nativeVlan === item.id || port.current.taggedVlans.includes(item.id)))
      .map((port) => `<tr><td>${portLink(state, port, `${nodes.get(port.deviceId) || port.deviceId} · ${port.port}`)}</td>
        <td>${escape(nodes.get(port.peerId) || port.peerId)}</td>
        <td>${port.current.nativeVlan === item.id ? t("Nativ", "Native") : t("Getaggt", "Tagged")}</td></tr>`).join("");
    const initialLink = links.find((link) => link.layer === "network") || links[0];
    return `${intro(t("Netzwerk / Übersicht", "Network / Overview"), escape(item.name), escape(item.cidr), `<div class="service-tools">
        <button type="button" class="button" data-view="network">${t("Alle Netze", "All networks")}</button>
        ${initialLink ? `<button type="button" class="button" data-view="topology" data-layer="${initialLink.layer}"
          data-topology-focus="${escape(initialLink.id)}">${t("In Topologie öffnen", "Open in topology")}</button>` : ""}
      </div>`)}
      <div class="host-overview compact-layout">
        <section class="panel">
          ${head(t("Netzprofil", "Network profile"))}
          <div class="panel-pad"><dl class="info-list">
            <div><dt>${t("Adressbereich", "Address range")}</dt><dd class="mono">${escape(item.cidr)}</dd></div>
            <div><dt>${t("Geltungsbereich", "Scope")}</dt><dd>${escape(host || t("Ganze Flotte", "Entire fleet"))}</dd></div>
            <div><dt>${t("Zuordnung", "Membership")}</dt><dd>${hosts.length + devices.length} ${t("Hosts und Geräte", "hosts and devices")} · ${workloads.length} ${t("Workloads", "workloads")}</dd></div>
          </dl><p class="compact">${t("Konsolen gehören zu Hosts und Workloads.", "Open a host or workload to use its console.")}</p></div>
        </section>
        ${window.opstendObjectUi?.ticker(state, events, null) || ""}
      </div>
      <div class="network-tables">
        ${window.opstendNetworkRuleUi?.section(state, { networkId: item.id }) || ""}
        ${networkTable(t("Hosts und Netzwerkgeräte", "Hosts and network devices"), [t("Objekt", "Object"), t("Typ", "Type"), "IPv4"], [...hostRows, ...deviceRows].join(""),
          t("Keine passenden Hosts oder Geräte im Beispielinventar.", "No matching hosts or devices in the demo inventory."))}
        <section class="panel">${head("Workloads", `${workloads.length} ${t("im gewählten Bereich", "in the selected scope")}`)}${workloadTable(state, workloads)}</section>
        ${networkTable(t("Konfigurierte Switchports", "Configured switch ports"), [t("Switchport", "Switch port"), t("Gegenstelle", "Peer"), t("VLAN-Zuordnung", "VLAN assignment")], portRows,
          t("Für dieses VLAN sind im gewählten Bereich keine Switchports konfiguriert.", "No switch ports are configured for this VLAN in the selected scope."))}
        ${networkTable(t("Verbindungen", "Connections"), [t("Verbindung", "Connection"), t("Endpunkte", "Endpoints"), t("Belegart", "Evidence type")], connectionRows,
          t("Keine Verbindungen erfasst.", "No connections recorded."))}
      </div>`;
  }

  function workloadTable(state, items, detail = true) {
    return `<div class="table-wrap" tabindex="0" aria-label="Workloads">
      <table class="data-table"><thead><tr><th scope="col">Workload</th><th scope="col">${t("Typ", "Type")}</th>
      ${detail ? `<th scope="col">${t("Zuteilung", "Allocation")}</th><th scope="col">${t("Netzwerk", "Network")}</th>` : ""}<th scope="col">${t("Zustand", "Status")}</th></tr></thead>
      <tbody>${items.map((item) => `<tr><td><button class="text-button" data-view="service" data-service-id="${item.id}">${state.escape(item.name)}</button></td><td>${state.escape(displayLabel(item.kind))}</td>
        ${detail ? `<td>${state.escape(item.cpu)} · ${state.escape(item.ram)}</td><td>${state.escape(item.network)}</td>` : ""}
        <td>${state.badge(displayLabel(item.status), tones[item.status])}</td></tr>`).join("")}
      </tbody></table></div>`;
  }

  function hardware(state, host, networks) {
    const machine = state.hosts[host];
    const item = capacity(machine);
    return `<section class="panel">
      ${head(t("Hardware und Netz", "Hardware and network"), `${t("Quelle", "Source")} · ${state.escape(displayLabel(item.source))}`)}
      <div class="panel-pad capacity-mini">
        ${capacityMeter(t("Arbeitsspeicher", "Memory"), monitoringData.capacityCoverage(state, "ram"))}
        ${capacityMeter(t("Lokaler Datenspeicher", "Local storage"), monitoringData.capacityCoverage(state, "storage"))}
        <div class="assignment">
          <div><strong>${t("Geplante Reserve", "Planned reserve")}</strong><span>${state.escape(displayLabel(item.reserve))}</span></div>
          ${machine.budgets ? `<div><strong>${t("Freigabe für OpsTend", "OpsTend allocation")}</strong><span>${machine.budgets.cpu} CPU · ${machine.budgets.ram} GiB RAM · ${machine.budgets.storage} GiB ${t("Speicher", "storage")} · GPU ${machine.budgets.gpu ? t("freigegeben", "allocated") : t("reserviert", "reserved")}</span></div>` : ""}
          ${host === "nuc-a" ? `<div><strong>${t("GPU mit HDMI", "GPU with HDMI")}</strong><span>${t("exklusiv · Medien", "exclusive · Medien")}</span></div>
            <div><strong>${t("USB-Gerät", "USB device")}</strong><span>${t("Medien · durchgereicht", "Medien · passthrough")}</span></div>` : ""}
          <div><strong>${host === "edge-01" ? "Uplink" : t("Switchanschluss", "Switch connection")}</strong><span>${state.escape(displayLabel(item.port))}</span></div>
          ${networks.length ? `<div><strong>${t("Netze", "Networks")}</strong><span>${networks.map((entry) => networkLink(state, entry)).join("<br>")}</span></div>` : ""}
        </div>
      </div>
    </section>`;
  }

  function host(state) {
    const selected = state.host || "nuc-a";
    const machine = state.hosts[selected];
    const resource = capacity(machine);
    const items = state.inventory.services.filter((item) => item.host === selected);
    const networks = state.inventory.networks.filter((item) => containsAddress(item.cidr, machine.ip)
      || items.some((service) => serviceInNetwork(item, service)));
    const actions = `<div class="service-tools"><button class="button" data-view="topology" data-layer="placement">${state.icon("topology")}${t("In Topologie öffnen", "Open in topology")}</button>
      ${window.opstendPveInventoryUI?.link(state, selected) || ""}
      <button type="button" class="button" data-view="host-maintenance" data-host="${state.escape(selected)}">${state.icon("clock")}${t("Wartung planen", "Plan maintenance")}</button>
      <button class="button" data-view="settings">${state.icon("settings")}Configuration</button>
      ${machine.budgets ? `<button type="button" class="button" data-view="settings" data-settings-tab="hosts">${t("Hostverwaltung öffnen", "Open host management")}</button>`
        : `<button class="button" type="button" data-view="guest-create" data-host="${state.escape(selected)}">${t("Gast aus Vorlage", "Guest from template")}</button>
          <button class="button primary" data-new-service>+ ${t("Neuer Dienst", "New service")}</button>`}</div>`;
    let content;
    switch (state.hostTab) {
      case "resources":
        content = `<div class="host-overview compact-layout">${hardware(state, selected, networks)}<section class="panel">
          ${head(t("Zuteilung pro Workload", "Allocation by workload"), t("CPU-Limit und reservierter Arbeitsspeicher", "CPU limit and reserved memory"))}${workloadTable(state, items)}
        </section></div>`;
        break;
      case "network":
        content = `<div class="host-overview compact-layout"><section class="panel">
          ${head(t("Netzanschlüsse", "Network connections"), `${t("Quelle", "Source")} · ${state.escape(displayLabel(resource.source))}`)}
          <div class="panel-pad"><dl class="info-list">
            <div><dt>Uplink</dt><dd>${state.escape(displayLabel(resource.port))}</dd></div>
            <div><dt>IPv4</dt><dd class="mono">${state.escape(machine.ip)}</dd></div>
            <div><dt>${t("Zugeordnete Netze", "Assigned networks")}</dt><dd>${networks.length ? networks.map((item) => networkLink(state, item)).join("<br>") : "WireGuard"}</dd></div>
            <div><dt>${t("Quellen", "Sources")}</dt><dd>${selected === "edge-01" ? displayLabel("Linux-Agent") : t("UniFi und Host-Inventar", "UniFi and host inventory")}</dd></div>
          </dl></div>
        </section><section class="panel">${head(t("Kommunikationspfade", "Communication paths"))}
          <div class="panel-pad"><p class="compact">${t("Konfigurierte Freigaben und geprüfte Wege haben eigene Einträge in der Netzansicht.", "The network view lists configured access and verified paths separately.")}</p>
          <button class="text-button" data-view="topology" data-layer="network">${t("Netzsicht öffnen", "Open network view")} →</button></div></section></div>
          ${window.opstendPublicationUi?.section({ ...state, host: selected }) || ""}`;
        break;
      case "activity":
        content = activity({ ...state, host: selected });
        break;
      default:
        content = `<div class="host-overview compact-layout">
          ${window.opstendObjectUi?.console(state, {
            name: machine.name, platform: machine.runtime,
            lines: [
              `${machine.name} · ${machine.runtime}`,
              `${t("Verwaltungsadresse", "Management address")}: ${machine.ip}`,
              `${t("Inventarstatus", "Inventory status")}: ${displayLabel(machine.status)}`,
              `${t("Inventarquelle", "Inventory source")}: ${displayLabel(resource.source)}`,
            ],
          }) || ""}
          ${window.opstendObjectUi?.ticker({ ...state, host: selected }, window.opstendViews.jobsForScope({ ...state, host: selected })) || ""}
        </div>
        <div class="host-overview">
          ${window.opstendMonitoring.hostSummary(state, selected)}
          ${hardware(state, selected, networks)}
        </div>
        <section class="panel">${head("Workloads", `${items.length} ${t("auf diesem Host", "on this host")}`)}${workloadTable(state, items)}</section>`;
    }
    const activeMaintenance = machine.maintenanceState === "active" ? `<p class="panel panel-pad">
      ${t("Der simulierte Neustart läuft. Die betroffenen Gäste und Dienste warten auf den Wiederanlauf.", "The simulated restart is in progress. Affected guests and services are awaiting recovery.")}
      <button type="button" class="text-button" data-view="changes" data-host="${state.escape(selected)}" data-job="${state.escape(machine.maintenanceJobId)}">${t("Wartungsauftrag öffnen", "Open maintenance job")}</button></p>` : "";
    return `${intro(`${t("Inventar", "Inventory")} / ${state.escape(machine.site)}`, state.escape(machine.name),
      `${state.escape(machine.runtime)} · ${state.escape(displayLabel(machine.status))} · ${state.escape(hostObservationNote(machine))}`, actions)}
      <div class="host-toolbar">${tabs([["overview", t("Übersicht", "Overview")], ["resources", t("Ressourcen", "Resources")],
        ["network", t("Netz", "Network")], ["activity", t("Aktivität", "Activity")]], state.hostTab, "host-tab")}</div>
      ${activeMaintenance}${content}`;
  }

  window.opstendViews = { operations, overview, inventory, network, "network-detail": networkDetail, host, serviceInNetwork,
    displayAttention, hostObservationNote };
})();
