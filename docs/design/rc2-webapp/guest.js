(function () {
  "use strict";

  const demo = window.opstendDemo;
  let draft = null;
  let review = null;
  let created = null;
  let scope = null;

  function initialDraft(state, host = state.host || state.inventory.hosts[0]?.id) {
    const profile = demo.guestProfiles(host)[0];
    return {
      name: "", host, templateId: profile?.id || "",
      networkId: state.inventory.networks.find((item) => item.id === "services")?.id || state.inventory.networks[0]?.id,
      cpu: profile?.cpu, ram: profile?.ram, disk: profile?.disk, start: false,
    };
  }

  function setup(state) {
    const esc = state.escape;
    const option = (id, label, active) => `<option value="${esc(id)}" ${id === active ? "selected" : ""}>${esc(label)}</option>`;
    const number = (id, label, maximum) => `<label for="guest-${id}"><span>${label}</span>
      <input id="guest-${id}" name="${id}" type="number" min="1" max="${maximum}" step="1" required value="${esc(draft[id] ?? "")}"></label>`;
    return `<form class="panel-pad" data-guest-provision>
      <div class="object-setting-fields">
        <label for="guest-name"><span>Name</span><input id="guest-name" name="name" required maxlength="70" value="${esc(draft.name)}"></label>
        <label for="guest-host"><span id="guest-host-label">Zielmaschine</span><select id="guest-host" name="host" aria-labelledby="guest-host-label">
          ${state.inventory.hosts.filter((item) => !item.budgets).map((item) => option(item.id, item.name + " · " + item.runtime, draft.host)).join("")}
        </select></label>
        <label for="guest-template"><span id="guest-template-label">Vorlage oder Profil</span><select id="guest-template" name="templateId" aria-labelledby="guest-template-label">
          ${demo.guestProfiles(draft.host).map((item) => option(item.id, item.title, draft.templateId)).join("")}
        </select></label>
        <label for="guest-network"><span id="guest-network-label">Netz</span><select id="guest-network" name="networkId" aria-labelledby="guest-network-label">
          ${state.inventory.networks.map((item) => option(item.id, item.name, draft.networkId)).join("")}
        </select></label>
        ${number("cpu", "CPU", 16)}
        ${number("ram", "RAM in GiB", 64)}
        ${number("disk", "Datenträger in GiB", 512)}
        <label for="guest-start"><span>Nach Anlage starten</span><input id="guest-start" name="start" type="checkbox" ${draft.start ? "checked" : ""}></label>
      </div>
      <div class="service-tools guest-actions"><button type="submit" class="button primary">Gastanlage prüfen</button></div>
      <p class="compact" role="status"></p>
    </form>`;
  }

  function preview(state, plan) {
    const esc = state.escape;
    const facts = [
      ["Name", plan.name], ["Zielmaschine", plan.host], ["Vorlage oder Profil", plan.templateTitle],
      ["Laufzeit", plan.kind], ["Netz", plan.network],
      ["Zuteilung", `${plan.cpu} CPU · ${plan.ram} GiB RAM · ${plan.disk} GiB`],
      ["Speicherziel", plan.store], ["Nach Anlage", plan.start ? "Starten und Health offen anzeigen" : "Gast gestoppt anzeigen"],
    ];
    return `<form class="panel-pad" data-guest-confirm>
      <h2 id="guest-preview-title" tabindex="-1">Gastanlage prüfen</h2>
      <dl class="info-list guest-facts">${facts.map(([label, value]) => `<div><dt>${label}</dt><dd>${esc(value)}</dd></div>`).join("")}</dl>
      <p class="compact adapter-review-context">Die Vorschau bindet Ziel, Vorlage und Zuteilung. Die Demo merkt einen Auftrag im Browser vor.</p>
      <div class="service-tools">
        <button type="submit" class="button primary">Gastanlage vormerken</button>
        <button type="button" class="button" data-guest-edit>Weiter bearbeiten</button>
      </div>
      <p class="compact" role="status"></p>
    </form>`;
  }

  window.opstendViews["guest-create"] = (state) => {
    if (state.hosts[state.host]?.budgets) {
      return `<header class="page-intro"><h1>Gast aus Vorlage</h1></header><section class="panel panel-pad">
        <p>Für diesen Beispielhost ist die Bestandsübernahme über Hostverwaltung verfügbar.</p>
        <button class="button" data-view="settings" data-settings-tab="hosts">Hostverwaltung öffnen</button></section>`;
    }
    if (!draft || scope !== state.host) {
      scope = state.host;
      draft = initialDraft(state);
      review = null;
      created = null;
    }
    const esc = state.escape;
    return `<header class="page-intro split">
      <div><p class="eyebrow">Dienste</p><h1>Gast aus Vorlage</h1></div>
      <button type="button" class="button" data-view="services">Zu Diensten</button>
    </header>
    <section class="panel guest-provision">
      ${created ? `<div class="panel-pad">
        <h2 id="guest-created-title" tabindex="-1">Gastanlage vorgemerkt</h2>
        <p class="compact adapter-review-context">${esc(created.name)} auf ${esc(created.host)}.</p>
        <div class="service-tools">
          <button type="button" class="button primary" data-view="changes" data-host="${esc(created.host)}" data-job="${esc(created.jobId)}">Auftrag ansehen</button>
          <button type="button" class="button" data-view="service" data-host="${esc(created.host)}" data-service-id="${esc(created.id)}">Gast öffnen</button>
          <button type="button" class="text-button" data-guest-reset>Weiteren Gast anlegen</button>
        </div>
      </div>` : review ? preview(state, review) : setup(state)}
    </section>`;
  };

  function readInput(form) {
    const fields = Object.fromEntries(new FormData(form));
    return { ...fields, start: form.elements.start.checked };
  }

  function refresh(selector) {
    window.dispatchEvent(new CustomEvent("opstend:inventory-changed"));
    document.querySelector(selector)?.focus({ preventScroll: true });
  }

  document.addEventListener("input", (event) => {
    const control = event.target;
    const form = control.closest("[data-guest-provision]");
    if (form && !["host", "templateId"].includes(control.name)) draft = readInput(form);
  });

  document.addEventListener("change", (event) => {
    const control = event.target;
    const form = control.closest("[data-guest-provision]");
    if (!form || !["host", "templateId"].includes(control.name)) return;
    draft = readInput(form);
    const profiles = demo.guestProfiles(draft.host);
    const profile = profiles.find((item) => item.id === draft.templateId) || profiles[0];
    if (profile) Object.assign(draft, { templateId: profile.id, cpu: profile.cpu, ram: profile.ram, disk: profile.disk });
    refresh(control.name === "host" ? "#guest-host" : "#guest-template");
  });

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (form.hasAttribute("data-guest-provision")) {
      event.preventDefault();
      draft = readInput(form);
      const result = demo.previewGuest(draft);
      if (!result.ok) {
        form.querySelector('[role="status"]').textContent = result.error;
        return;
      }
      review = result.plan;
      refresh("#guest-preview-title");
    } else if (form.hasAttribute("data-guest-confirm") && review) {
      event.preventDefault();
      const result = demo.createGuest(draft);
      if (!result.ok) {
        form.querySelector('[role="status"]').textContent = result.error;
        return;
      }
      created = { ...result, name: review.name };
      review = null;
      refresh("#guest-created-title");
    }
  });

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-guest-edit], [data-guest-reset]");
    if (!button) return;
    if (button.hasAttribute("data-guest-reset")) draft = null;
    review = null;
    refresh("#guest-name");
  });
})();
