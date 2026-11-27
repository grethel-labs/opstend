(function () {
  "use strict";

  const { t, ui } = window.opstendLocale;
  const maintenance = window.opstendHostMaintenance;
  const formats = Object.fromEntries([["de", "de-DE"], ["en", "en-GB"]].map(([id, locale]) => [id, {
    start: new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Berlin" }),
    end: new Intl.DateTimeFormat(locale, { timeStyle: "short", timeZone: "Europe/Berlin" }),
  }]));
  const closed = new Set(["finished", "rejected"]);
  const stages = {
    pending: ["Freigabe offen", "Awaiting approval", "warn"],
    approved: ["Freigegeben", "Approved", "good"],
    active: ["Wartung läuft", "Maintenance in progress", "maintenance"],
    finished: ["Wiederanlauf simuliert", "Recovery simulated", "good"],
    rejected: ["Abgelehnt", "Rejected", "warn"],
  };
  const impacts = {
    restart: ["Unterbrechung", "Interruption", "warn"],
    "leave-stopped": ["Bleibt gestoppt", "Remains stopped", ""],
    blocked: ["Blockiert", "Blocked", "danger"],
  };
  const requests = new Set();
  let page;

  function jobButton(state, record, primary) {
    return `<button type="button" id="host-maintenance-job" class="${primary ? "button primary" : "text-button"}"
      data-view="changes" data-job="${state.escape(record.id)}" data-host="${state.escape(record.host)}">${t("Auftrag öffnen", "Open job")}</button>`;
  }

  function stageBadge(state, stage) {
    const [de, en, tone] = stages[stage];
    return state.badge(t(de, en), tone);
  }

  function windowPanel(state, window) {
    const { startAt, endAt, label, labelEn, source, sourceEn, timezone } = window;
    const { start, end } = formats[ui()];
    const startDate = new Date(startAt);
    const endDate = new Date(endAt);
    const next = startAt && endAt && Number.isFinite(startDate.getTime()) && Number.isFinite(endDate.getTime())
      ? `<time datetime="${state.escape(startAt)}">${state.escape(start.format(startDate))}</time>–<time datetime="${state.escape(endAt)}">${state.escape(end.format(endDate))}</time>`
      : t("Termin offen", "Date unknown");
    return `<section class="panel" aria-labelledby="host-maintenance-window">
      <div class="panel-head"><h2 id="host-maintenance-window">${t("Wartungsfenster", "Maintenance window")}</h2></div>
      <div class="panel-pad"><dl class="info-list">
        <div><dt>${t("Wöchentliche Regel", "Weekly schedule")}</dt><dd>${state.escape(t(label, labelEn))}</dd></div>
        <div><dt>${t("Gültige Vorgabe", "Effective policy")}</dt><dd>${state.escape(t(source, sourceEn))}</dd></div>
        <div><dt>${t("Demo-Termin", "Demo date")}</dt><dd>${next} · ${state.escape(timezone)}</dd></div>
      </dl></div>
    </section>`;
  }

  function impactPanel(state, items) {
    return `<section class="panel" aria-labelledby="host-maintenance-impacts">
      <div class="panel-head"><h2 id="host-maintenance-impacts">${t("Auswirkungen auf Gäste und Dienste", "Impact on guests and services")}</h2></div>
      ${items.length ? `<ul class="feed" role="list">${items.map((item) => {
        const [de, en, tone] = impacts[item.handling];
        const kind = item.kind === "Container · Podman" ? t(item.kind, "Podman container") : item.kind;
        const visible = state.inventory.services.some(({ id }) => id === item.id);
        return `<li><div><div class="service-tools">
          ${visible ? `<button type="button" class="text-button" data-view="service" data-host="${state.escape(state.host)}" data-service-id="${state.escape(item.id)}">${state.escape(item.name)}</button>`
            : `<strong>${state.escape(item.name)}</strong>`}
          ${state.badge(t(de, en), tone)}</div>
          <p>${state.escape(kind)} · ${state.escape(t(item.reason, item.reasonEn))}</p></div></li>`;
      }).join("")}</ul>` : `<p class="panel-pad compact">${t("Für diesen Host sind keine Gäste oder Dienste erfasst.", "This host has no recorded guests or services.")}</p>`}
    </section>`;
  }

  function requestPanel(state, plan, record, openRecord) {
    const awaiting = requests.has(plan.host);
    const interruption = plan.workloads.some(({ handling }) => handling === "restart");
    return `<section class="panel" aria-labelledby="host-maintenance-request-title">
      <div class="panel-head"><h2 id="host-maintenance-request-title">${t("Wartungsauftrag", "Maintenance job")}</h2>
        ${openRecord ? stageBadge(state, record.stage) : ""}</div>
      ${openRecord ? `<div class="panel-pad">
        <p class="compact adapter-review-context">${t("Der Auftrag hält Freigabe und Simulation im Verlauf fest.", "The job records approval and simulation in its history.")}</p>
        ${jobButton(state, record, true)}</div>`
        : `<div class="panel-pad">
          ${plan.ok ? `<form data-host-maintenance-request="${state.escape(plan.host)}" aria-busy="${awaiting}">
            ${interruption ? `<label class="deploy-check"><input type="checkbox" name="accepted" required ${awaiting ? "disabled" : ""}>
              <span>${t("Unterbrechung für die aufgeführten Gäste und Dienste bestätigen", "Confirm the interruption for the listed guests and services")}</span></label>` : ""}
            <p class="compact adapter-review-context">${t("Du kannst den Demo-Neustart nach der Freigabe im Auftrag simulieren.", "Approve the job to simulate the demo restart.")}</p>
            <button type="submit" class="button primary" ${awaiting || interruption ? "disabled" : ""}>${t("Wartung vormerken", "Queue maintenance")}</button>
          </form>` : `<p class="compact adapter-review-context">${state.escape(t(plan.error, plan.errorEn || plan.error))}</p>`}
          ${record ? `<div class="service-tools adapter-review-context">
            <span class="compact">${t("Letzter Auftrag", "Latest job")}</span>${stageBadge(state, record.stage)}${jobButton(state, record, false)}
          </div>` : ""}
        </div>`}
      <p class="panel-pad compact" id="host-maintenance-result" role="alert" tabindex="-1" hidden></p>
    </section>`;
  }

  function selectHost(state) {
    return `<section class="panel" aria-labelledby="host-maintenance-hosts">
      <div class="panel-head"><h2 id="host-maintenance-hosts">${t("Host auswählen", "Select a host")}</h2></div>
      <ul class="feed" role="list">${state.inventory.hosts.map((host) => `<li><div>
        <button type="button" class="text-button" data-view="host-maintenance" data-host="${state.escape(host.id)}">${state.escape(host.name)}</button>
        <p>${state.escape(host.runtime)}</p></div></li>`).join("")}</ul>
    </section>`;
  }

  window.opstendViews["host-maintenance"] = (state) => {
    const host = state.hosts[state.host];
    const plan = host ? maintenance.preview(state, host.id) : null;
    const record = host ? maintenance.latest(state, host.id) : null;
    const openRecord = !!record && !closed.has(record.stage);
    page = plan && { state, plan };
    return `<header class="page-intro split" data-host-maintenance-page="${state.escape(host?.id || "")}"><div>
      <p class="eyebrow">${t("Inventar", "Inventory")}${host ? ` / ${state.escape(host.name)}` : ""}</p>
      <h1>${t("Hostwartung", "Host maintenance")}</h1>
      <p>${t("Geplanter Neustart · Demo", "Planned restart · Demo")}</p></div>
      <div class="service-tools">
        ${host ? `<button type="button" class="button" data-view="host" data-host="${state.escape(host.id)}">${t("Host öffnen", "Open host")}</button>` : ""}
        <button type="button" class="text-button" data-view="settings" data-settings-tab="policies">${t("Richtlinien öffnen", "Open policies")}</button>
      </div></header>
      ${plan ? `<div class="object-overview">${windowPanel(state, openRecord ? record.window : plan.window)}
        ${impactPanel(state, openRecord ? record.workloads : plan.workloads)}</div>
        ${requestPanel(state, plan, record, openRecord)}` : selectHost(state)}`;
  };

  const formSelector = "[data-host-maintenance-request]";

  document.addEventListener("change", (event) => {
    const field = event.target;
    if (field.name !== "accepted" || !field.form?.matches(formSelector)) return;
    field.form.querySelector('button[type="submit"]').disabled = !field.checked;
  });

  document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!form.matches(formSelector)) return;
    event.preventDefault();
    const { state, plan } = page || {};
    const host = form.dataset.hostMaintenanceRequest;
    if (!plan?.ok || plan.host !== host || requests.has(host) || !form.reportValidity()) return;
    requests.add(host);
    form.setAttribute("aria-busy", "true");
    for (const control of form.elements) control.disabled = true;
    let result;
    try {
      result = await maintenance.request(state, plan);
    } catch {
      result = { ok: false, error: "Der Wartungsauftrag konnte gerade nicht gespeichert werden.", errorEn: "The maintenance job could not be saved." };
    } finally {
      requests.delete(host);
    }
    if (document.querySelector("[data-host-maintenance-page]")?.dataset.hostMaintenancePage !== host) return;
    if (result.ok) {
      document.getElementById("host-maintenance-job")?.focus({ preventScroll: true });
      return;
    }
    window.dispatchEvent(new Event("opstend:inventory-changed"));
    const status = document.getElementById("host-maintenance-result");
    status.hidden = false;
    status.textContent = t(result.error, result.errorEn || result.error);
    status.focus();
  });
})();
