(function () {
  "use strict";

  const { t, ui } = window.opstendLocale;
  const data = () => window.opstendPveInventory;
  const view = "pve-inventory";
  const labels = {
    observed: ["Beobachtet", "Observed"], absent: ["Kein Bestand gemeldet", "No resources reported"],
    restricted: ["Zugriff eingeschränkt", "Access restricted"], missing: ["Beleg fehlt", "Evidence missing"],
    unavailable: ["Nicht verfügbar", "Unavailable"], invalid: ["Ungültiger Beleg", "Invalid evidence"],
    budget: ["Abfragebudget erreicht", "Request budget reached"], stale: ["Snapshot veraltet", "Snapshot stale"],
    online: ["Online", "Online"], offline: ["Offline", "Offline"], running: ["Läuft", "Running"],
    stopped: ["Gestoppt", "Stopped"], paused: ["Pausiert", "Paused"], available: ["Verfügbar", "Available"],
    succeeded: ["Erfolgreich", "Succeeded"], warning: ["Warnung", "Warning"], failed: ["Fehlgeschlagen", "Failed"],
    cluster_resources: ["PVE-Ressourceninventar", "PVE resource inventory"], guest_config: ["PVE-Gastkonfiguration", "PVE guest configuration"],
    guest_rrd: ["PVE-RRD-Messreihe", "PVE RRD measurements"], guest_tasks: ["PVE-Taskverlauf", "PVE task history"],
    permissions: ["PVE-Leserechte", "PVE read permissions"],
  };
  const operations = {
    create: ["Anlegen", "Create"], start: ["Starten", "Start"], stop: ["Stoppen", "Stop"],
    shutdown: ["Herunterfahren", "Shutdown"], reboot: ["Neustart", "Reboot"], reset: ["Reset", "Reset"],
    suspend: ["Pausieren", "Suspend"], resume: ["Fortsetzen", "Resume"], migrate: ["Migration", "Migrate"],
  };
  const tones = {
    observed: "good", online: "good", available: "good", running: "good", succeeded: "good", paused: "warn",
    warning: "warn", restricted: "warn", stale: "warn", budget: "warn", offline: "danger", failed: "danger",
  };
  const formats = Object.fromEntries([["de", "de-DE"], ["en", "en-GB"]].map(([key, language]) => [key, {
    date: new Intl.DateTimeFormat(language, { dateStyle: "short", timeStyle: "medium", timeZone: "UTC" }),
    number: new Intl.NumberFormat(language, { maximumFractionDigits: 1 }),
    percent: new Intl.NumberFormat(language, { style: "percent", maximumFractionDigits: 1 }),
  }]));
  const label = (value) => t(...(labels[value] || ["Offen", "Unknown"]));
  const badge = (state, value) => state.badge(label(value), tones[value] || "");
  const count = (value) => Number.isFinite(value) ? formats[ui()].number.format(value) : "—";
  const percent = (value) => Number.isFinite(value) ? formats[ui()].percent.format(value) : "—";
  const kind = (guest) => guest.kind === "qemu" ? t("QEMU-VM", "QEMU VM") : "LXC";
  const inScope = (state) => !state.host || state.host === "nuc-a";
  const validVmid = (value) => /^[1-9][0-9]{2,8}$/.test(value ?? "");
  const vmidFor = (state) => validVmid(state.pveGuest) ? Number(state.pveGuest) : null;

  function bytes(value) {
    if (!Number.isFinite(value)) return "—";
    const units = [[1024 ** 4, "TiB"], [1024 ** 3, "GiB"], [1024 ** 2, "MiB"], [1024, "KiB"], [1, "B"]];
    const [scale, unit] = units.find(([divisor]) => value >= divisor) ?? units.at(-1);
    return `${count(value / scale)} ${unit}`;
  }

  function instant(state, value) {
    const time = Date.parse(value);
    if (!Number.isFinite(time)) return "—";
    return `<time datetime="${state.escape(value)}">${formats[ui()].date.format(time)} UTC</time>`;
  }

  function guestName(guest) {
    return guest.name || t(`Gast ${guest.vmid}`, `Guest ${guest.vmid}`);
  }

  function navigation(state, host, vmid, title, style = "button") {
    return `<button type="button" class="${style}" data-view="${view}" data-host="${state.escape(host ?? "")}"${vmid == null ? "" : ` data-pve-guest="${state.escape(vmid)}"`}>${state.escape(title)}</button>`;
  }

  function link(state, objectId, title) {
    if (!objectId) return inScope(state) ? navigation(state, state.host, null, title ?? t("Proxmox-Inventar", "Proxmox inventory")) : "";
    const reference = data()?.referenceFor(objectId);
    return reference ? navigation(state, reference.node, reference.vmid, title ?? t("Proxmox-Belege", "Proxmox evidence")) : "";
  }

  function evidenceText(state, evidence) {
    if (!evidence) return t("Quelle und Zeitpunkt offen", "Source and time unknown");
    return `${label(evidence.source)} · ${instant(state, evidence.observed_at)}`;
  }

  function statusPanel(state, snapshot) {
    const evidence = snapshot.evidence;
    return `<section class="panel" aria-label="${t("Datenstand", "Snapshot status")}">
      <div class="panel-head"><h2>${t("Datenstand", "Snapshot status")}</h2>${badge(state, snapshot.status)}</div>
      <div class="panel-pad"><dl class="info-list">
        <div><dt>${t("Sichtbarer Umfang", "Visible scope")}</dt><dd>${t("Token-Berechtigungsumfang", "Token permission scope")}</dd></div>
        <div><dt>${t("Quelle", "Source")}</dt><dd>${evidence ? label(evidence.source) : "—"}</dd></div>
        <div><dt>${t("Letzte Beobachtung", "Last observation")}</dt><dd>${instant(state, snapshot.observed_at)}</dd></div>
      </dl></div></section>`;
  }

  function message(text) {
    return `<div class="panel panel-pad" role="status"><p>${text}</p></div>`;
  }

  function controls(state, pending) {
    const selected = data().selected();
    return `<div class="inventory-toolbar panel"><label for="pve-profile">${t("Demo-Lesestand", "Demo read scenario")}</label>
      <div class="service-tools"><select id="pve-profile" class="button">${data().profiles.map(({ id, label, labelEn }) =>
        `<option value="${state.escape(id)}" ${id === selected ? "selected" : ""}>${state.escape(t(label, labelEn))}</option>`).join("")}</select>
        <button type="button" class="button" id="pve-refresh" aria-disabled="${String(pending)}">${t("Neu laden", "Reload")}</button></div></div>`;
  }

  function header(state, title, detail) {
    const scope = state.host || t("Ganze Flotte", "Entire fleet");
    const actions = detail ? navigation(state, state.host, null, t("Zum Proxmox-Inventar", "Back to Proxmox inventory"))
      : `<button type="button" class="button" data-view="inventory">${t("Zum Inventar", "Back to inventory")}</button>`;
    return `<header class="page-intro split"><div><p class="eyebrow">${t("Inventar", "Inventory")} / ${state.escape(scope)}</p>
      <h1>${state.escape(title)}</h1></div><div class="service-tools">${actions}</div></header>`;
  }

  function facts(state, title, items, evidence) {
    return `<section class="panel" aria-label="${title}"><div class="panel-head"><div><h2>${title}</h2>
      ${evidence ? `<p>${evidenceText(state, evidence)}</p>` : ""}</div></div><div class="panel-pad"><dl class="info-list">
      ${items.map(([key, val]) => `<div><dt>${key}</dt><dd>${val}</dd></div>`).join("")}</dl></div></section>`;
  }

  function table(state, title, columns, rows, empty, { detail = "", evidence } = {}) {
    return `<section class="panel" aria-label="${title}"><div class="panel-head"><div><h2>${title}</h2>
      ${evidence ? `<p>${evidenceText(state, evidence)}</p>` : ""}${detail ? `<p>${detail}</p>` : ""}</div>
      ${evidence ? badge(state, evidence.state) : ""}</div>
      ${rows.length ? `<div class="table-wrap" tabindex="0" aria-label="${t(`Tabelle ${title}`, `${title} table`)}"><table class="data-table">
      <thead><tr>${columns.map((column) => `<th scope="col">${column}</th>`).join("")}</tr></thead>
      <tbody>${rows.map(([first, ...rest]) => `<tr><th scope="row">${first}</th>${rest.map((value) => `<td>${value}</td>`).join("")}</tr>`).join("")}</tbody>
      </table></div>` : `<p class="panel-pad compact">${empty}</p>`}</section>`;
  }

  function inventory(state, snapshot) {
    const onHost = ({ node }) => !state.host || node === state.host;
    const guests = snapshot.guests.filter(onHost);
    const nodes = snapshot.nodes.filter(onHost);
    const relatedPools = new Set(guests.map(({ pool }) => pool));
    const pools = snapshot.pools.filter(({ pool }) => !state.host || relatedPools.has(pool));
    const datastores = snapshot.datastores.filter(onHost);
    const noRows = t("Dieser Lesestand enthält hier keine Zeilen.", "This snapshot contains no rows here.");
    const placement = guests.map((guest) => [navigation(state, state.host, guest.vmid, guestName(guest), "text-button"),
      `${kind(guest)} · ${state.escape(guest.vmid)}`, state.escape(guest.node), badge(state, guest.status), evidenceText(state, guest.evidence)]);
    return `${table(state, t("Gäste", "Guests"), [t("Gast", "Guest"), t("Typ / VMID", "Type / VMID"),
      t("Knoten", "Node"), t("Laufzustand", "Runtime state"), t("Beleg", "Evidence")], placement, noRows)}
      ${table(state, t("Knoten", "Nodes"), [t("Knoten", "Node"), t("Zustand", "Status"), "CPU", "RAM", t("Beleg", "Evidence")],
        nodes.map((node) => [state.escape(node.node), badge(state, node.status), count(node.cpu_capacity), bytes(node.max_memory_bytes), evidenceText(state, node.evidence)]), noRows)}
      ${table(state, "Datastores", [t("Speicher", "Storage"), t("Knoten", "Node"), t("Freigabe", "Sharing"), t("Zustand", "Status"),
        t("Kapazität", "Capacity"), t("Beleg", "Evidence")], datastores.map((item) => [state.escape(item.storage), state.escape(item.node),
        item.shared === true ? t("Geteilt", "Shared") : item.shared === false ? t("Lokal", "Local") : "—",
        badge(state, item.status), bytes(item.max_disk_bytes), evidenceText(state, item.evidence)]), noRows)}
      ${table(state, "Pools", ["Pool", t("Beleg", "Evidence")], pools.map((pool) => [state.escape(pool.pool),
        evidenceText(state, pool.evidence)]), noRows)}`;
  }

  function observationRows(observation, map) {
    return observation?.evidence?.state === "observed" ? observation.items.map(map) : [];
  }

  function observationMessage(observation, empty) {
    const status = observation?.evidence?.state;
    return status && status !== "observed" ? label(status) : empty;
  }

  function sampleTime(state, point, evidence) {
    const age = Math.floor((Date.parse(evidence.observed_at) - Date.parse(point.time)) / 60_000);
    const ageText = age > 0 ? t(`${age} Min. vor Erhebung`, `${age} min before collection`) : "";
    return `${instant(state, point.time)}${ageText ? ` <small>· ${ageText}</small>` : ""}`;
  }

  function guestDetails(state, guest) {
    const { network, measurements, tasks } = guest;
    const overview = facts(state, t("Gastzustand", "Guest state"), [
      [t("Identität", "Identity"), `${kind(guest)} · VMID ${state.escape(guest.vmid)}`],
      [t("Knoten", "Node"), state.escape(guest.node)], [t("Laufzustand", "Runtime state"), badge(state, guest.status)],
      ["vCPU", count(guest.cpu_capacity)], [t("CPU-Auslastung", "CPU utilization"), percent(guest.cpu_fraction)],
      ["RAM", `${bytes(guest.memory_bytes)} / ${bytes(guest.max_memory_bytes)}`], ["Pool", state.escape(guest.pool || "—")],
    ], guest.evidence);
    const networkRows = observationRows(network, (item) => [`net${state.escape(item.index)}`, state.escape(item.bridge || "—"),
      item.vlan_tag == null ? "—" : state.escape(item.vlan_tag)]);
    const networks = table(state, t("Netzanschlüsse", "Network attachments"), [t("Anschluss", "Attachment"), "Bridge", "VLAN"], networkRows,
      observationMessage(network, t("Keine Netzanschlüsse gemeldet.", "No network attachments reported.")), { evidence: network?.evidence });
    const points = observationRows(measurements, (point) => [sampleTime(state, point, measurements.evidence), percent(point.cpu_fraction),
      bytes(point.memory_bytes), bytes(point.disk_bytes)]);
    const readings = table(state, t("Messwerte", "Measurements"), [t("Messzeitpunkt", "Sample time"), "CPU", "RAM", t("Speicher", "Disk")], points,
      observationMessage(measurements, t("Keine Messpunkte gemeldet.", "No measurement points reported.")), { evidence: measurements?.evidence });
    const taskRows = observationRows(tasks, (task) => [t(...(operations[task.operation] || ["Unbekannt", "Unknown"])),
      badge(state, task.state), instant(state, task.started_at), instant(state, task.finished_at), count(task.warning_count)]);
    const activity = table(state, t("Native PVE-Tasks", "Native PVE tasks"), [t("Aktion", "Operation"), t("Zustand", "State"),
      t("Beginn", "Start"), t("Ende", "End"), t("Warnungen", "Warnings")], taskRows,
      observationMessage(tasks, t("Keine nativen Tasks gemeldet.", "No native tasks reported.")), { evidence: tasks?.evidence,
        detail: t("Beobachtungen aus Proxmox. OpsTend-Aufträge stehen unter Änderungen.", "Observations from Proxmox. OpsTend jobs are listed under Changes.") });
    return `<div class="object-overview">${overview}${networks}</div>${readings}${activity}`;
  }

  function render(state) {
    const title = t("Proxmox-Inventar", "Proxmox inventory");
    if (!inScope(state)) return header(state, title, false) + message(t("Proxmox-Inventar ist im Bereich nuc-a verfügbar.", "Proxmox inventory is available in the nuc-a scope."));
    const detail = vmidFor(state) !== null;
    const { snapshot, pending, error } = data().read(vmidFor(state));
    const hidden = t("Gast im Lesebereich nicht verfügbar.", "Guest unavailable in this read scope.");
    const guest = detail && snapshot?.status === "observed" && snapshot.guest?.vmid === vmidFor(state)
      && (!state.host || snapshot.guest.node === state.host) ? snapshot.guest : null;
    const intro = header(state, detail ? guest ? guestName(guest) : t("Proxmox-Gast", "Proxmox guest") : title, detail);
    let contents;
    if (pending) contents = message(t("Proxmox-Daten werden geladen.", "Loading Proxmox data."));
    else if (error === "file") contents = message(t("Der Proxmox-Lesestand ist in der lokalen Demo über HTTP verfügbar.", "The Proxmox snapshot is available through the local HTTP demo."));
    else if (error === "invalid") contents = message(t("Die Antwort entspricht keinem Proxmox-Lesestand.", "The response did not match the Proxmox inventory format."));
    else if (!snapshot) contents = message(t("Proxmox-Daten sind nicht verfügbar.", "Proxmox data is unavailable."));
    else if (guest) contents = statusPanel(state, snapshot) + guestDetails(state, guest);
    else if (detail && ["observed", "restricted", "absent"].includes(snapshot.status)) contents = message(hidden);
    else if (snapshot.status === "observed") contents = statusPanel(state, snapshot) + inventory(state, snapshot);
    else contents = statusPanel(state, snapshot);
    return `${intro}<div class="network-tables">${controls(state, pending)}${contents}</div>`;
  }

  function mount(state) {
    if (state.view !== view || !inScope(state)) return;
    const vmid = vmidFor(state);
    document.getElementById("pve-profile")?.addEventListener("change", (event) => data().select(event.target.value));
    document.getElementById("pve-refresh")?.addEventListener("click", () => {
      if (!data().read(vmid).pending) data().refresh(vmid);
    });
    data().ensure(vmid);
  }

  window.opstendPveInventoryUI = { render, mount, link };
  window.opstendViews[view] = render;
})();
