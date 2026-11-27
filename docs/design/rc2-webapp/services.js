(function () {
  "use strict";

  const statusTone = { Gesund: "good", "Wird geprüft": "warn", Warnung: "warn", "Health offen": "warn", Vorgemerkt: "warn", Ausgefallen: "danger" };
  const powerLabels = { running: "Läuft", stopped: "Gestoppt", unknown: "Unbekannt" };
  const englishPowerLabels = { running: "Running", stopped: "Stopped", unknown: "Unknown" };
  const { runtimeLabels, runtimeRestriction, serviceRuntime } = window.opstendDemo;
  const { t } = window.opstendLocale;
  const englishRuntimeLabels = { start: "Start", stop: "Shut down", restart: "Restart" };
  const runtimeImpact = {
    start: ["Der Auftrag simuliert einen Start. Die Prüfung der Anwendung erfolgt separat.", "The job simulates a start. Application health is checked separately."],
    stop: ["Der Auftrag simuliert ein geordnetes Herunterfahren und prüft den gemeldeten Laufzustand.", "The job simulates a graceful shutdown and checks the reported runtime state."],
    restart: ["Der Auftrag simuliert einen Neustart und prüft den gemeldeten Laufzustand.", "The job simulates a restart and checks the reported runtime state."],
  };
  const runtimeJobMessages = {
    queued: ["Der Laufzeitauftrag ist vorgemerkt.", "The runtime job is queued."],
    dispatched: ["Der Laufzeitauftrag wartet auf das Ergebnis der Ausführung.", "The runtime job is waiting for the execution result."],
    reconcile: ["Die Antwort auf die Ausführung fehlt. Der Auftrag wartet auf den Abgleich.", "The execution response is missing. The job is waiting for reconciliation."],
    readback: ["Die Ausführung wurde gemeldet. Die Beobachtung des Laufzustands steht aus.", "Execution was reported. The observed runtime state is pending."],
  };
  const powerLabel = (power) => t(powerLabels[power], englishPowerLabels[power]);
  const runtimeLabel = (operation) => t(runtimeLabels[operation], englishRuntimeLabels[operation]);
  let lastAdapterSave = "";
  let adapterDraft = null;
  let adapterTransition = null;
  let lastAdapterJob = "";
  const groupName = "OpsTend Steuerung";

  function serviceRows(state, items) {
    return items.map((item) => {
      const label = state.escape(item.name);
      const role = item.instance ? `${item.role} · ${item.instance}` : item.role;
      const host = state.hosts[item.host];
      return `<tr>
        <td><button class="text-button" data-view="service" data-service-id="${state.escape(item.id)}">${label}</button><small>${state.escape(item.kind)}</small></td>
        <td>${state.escape(role)}</td>
        <td><button class="text-button" data-view="host" data-host="${host.id}">${state.escape(host.name)}</button><small>${state.escape(host.site)}</small></td>
        <td class="mono">${state.escape(item.ip || "Offen")}</td>
        <td>${state.badge(item.status, statusTone[item.status])}</td>
      </tr>`;
    }).join("");
  }

  function replicaSet(state) {
    const replicas = state.inventory.services.filter((item) => item.group === groupName);
    const healthy = replicas.filter((item) => item.status === "Gesund");
    const active = healthy.find((item) => item.instance === "Aktiv");
    const canSimulate = !replicas.some((item) => item.status === "Ausgefallen");
    return `
      <section class="panel replicas-panel">
        <div class="panel-head"><div><h2>${groupName}</h2><p>Dienstgruppe · Standort Werkstatt</p></div>
          ${state.badge(`${healthy.length} / 3 bereit`, healthy.length >= 2 ? "good" : "warn")}</div>
        <div class="replicas-summary"><span>Aktive Instanz <strong>${active ? state.escape(active.host) : "Unbekannt"}</strong></span><span>Quorum <strong>2 von 3</strong></span></div>
        <ol class="replicas-list">${replicas.map((item) => `<li>
          <button class="text-button" data-view="service" data-service-id="${item.id}">${item.name}</button>
          <span>${item.host}</span>${state.badge(item.instance, item.status === "Gesund" ? "good" : "danger")}
        </li>`).join("")}</ol>
        <div class="panel-pad service-tools">
          <button class="button" data-simulate-replica-failure ${canSimulate ? "" : "disabled"}>Ausfall simulieren</button>
          <button class="text-button" data-view="topology" data-layer="placement" data-topology-focus="${active?.id || "control-a"}">Platzierung ansehen →</button>
        </div>
      </section>`;
  }

  window.opstendViews.services = (state) => {
    const items = state.inventory.services.filter((item) => !state.host || item.host === state.host);
    return `
      <header class="page-intro split">
        <div><p class="eyebrow">${state.host ? state.escape(state.host) : "Ganze Flotte"}</p><h1>Dienste und Deployments</h1>
          <p>Anwendungen und Core-Dienste verwalten und ihre Platzierung prüfen.</p></div>
        <div class="service-tools">
          ${state.hosts[state.host]?.budgets ? '<button class="button" type="button" data-view="settings" data-settings-tab="hosts">Hostverwaltung öffnen</button>'
            : '<button class="button" type="button" data-view="guest-create">Gast aus Vorlage</button><button class="button primary" data-new-service>+ Neuer Dienst</button>'}
        </div>
      </header>
      ${state.message ? `<p class="service-notice" role="status">${state.escape(state.message)}</p>` : ""}
      <div class="services-layout">
        <section class="panel inventory-table">
          <div class="panel-head"><div><h2>Dienste</h2><p>${items.length} Instanzen im gewählten Bereich</p></div></div>
          <div class="table-wrap" tabindex="0" aria-label="Dienstinstanzen">
            <table class="data-table">
              <thead><tr><th scope="col">Dienst</th><th scope="col">Rolle</th><th scope="col">Host</th><th scope="col">IPv4</th><th scope="col">Status</th></tr></thead>
              <tbody>${serviceRows(state, items) || '<tr><td colspan="5">Auf dieser Maschine läuft im Beispiel kein Dienst.</td></tr>'}</tbody>
            </table>
          </div>
        </section>
        ${replicaSet(state)}
      </div>`;
  };

  function serviceAction(state, item) {
    const operation = state.serviceAction;
    const isRuntime = Object.hasOwn(runtimeLabels, operation);
    const removal = state.serviceAction === "remove";
    const title = isRuntime ? runtimeLabel(operation) : removal ? "Entfernung vormerken" : "Stilllegung prüfen";
    const impact = isRuntime ? t(...runtimeImpact[operation]) : removal
      ? "Die Vorschau merkt die Entfernung der Laufzeit vor. Daten und Sicherungen werden separat behandelt."
      : "Die Vorschau stoppt den Dienst in der Demo und hält Konfiguration sowie Datenreferenzen fest.";
    const review = isRuntime ? state.runtimePreview ?? window.opstendDemo.previewRuntime(item.id, operation, state.inventory) : null;
    const plan = review?.ok ? review.plan : null;
    const confirm = isRuntime
      ? plan && `<button type="button" class="button primary" data-confirm-service-action data-runtime-binding="${state.escape(plan.binding)}">${t("In der Demo bestätigen", "Confirm in demo")}</button>`
      : '<button type="button" class="button primary" data-confirm-service-action>Vorschau bestätigen</button>';
    return `
      <section id="service-action" class="panel panel-pad service-confirm" tabindex="-1" aria-labelledby="service-action-title">
        <h2 id="service-action-title">${title}</h2>
        ${plan ? `<dl class="info-list">
          <div><dt>${t("Ziel", "Target")}</dt><dd>${state.escape(item.name)} · ${state.escape(item.kind)} · ${state.escape(item.host)}</dd></div>
          <div><dt>${t("Beobachteter Laufzustand", "Observed runtime state")}</dt><dd>${powerLabel(plan.before)}</dd></div>
          <div><dt>${t("Erwarteter Laufzustand", "Expected runtime state")}</dt><dd>${powerLabel(plan.after)}</dd></div>
          <div><dt>${t("Ausführung", "Execution")}</dt><dd>${plan.provider === "pve" ? t("Proxmox-Task · Demo", "Proxmox task · demo") : t("Podman-Executor · Demo", "Podman executor · demo")}</dd></div>
        </dl>` : `<p>${state.escape(item.name)} auf ${state.escape(item.host)}</p>`}
        ${review && !review.ok ? `<p role="status">${state.escape(t(review.error, review.errorEn || review.error))}</p>` : `<p>${impact}</p>`}
        <div class="service-tools">
          ${confirm || ""}
          <button type="button" class="button" data-cancel-service-action>${t("Abbrechen", "Cancel")}</button>
        </div>
      </section>`;
  }

  function pendingRuntimeDetails(state, job) {
    const { escape } = state;
    const message = runtimeJobMessages[job.stage] ?? ["Der Laufzeitauftrag läuft.", "The runtime job is in progress."];
    return `<section class="panel panel-pad service-confirm" aria-labelledby="service-runtime-job-title">
      <h2 id="service-runtime-job-title">${t("Aktueller Laufzeitauftrag", "Current runtime job")}</h2>
      <p role="status">${t(...message)}</p>
      <button type="button" class="button" data-view="changes" data-host="${escape(job.host)}" data-job="${escape(job.id)}">${t("Laufzeitauftrag öffnen", "Open runtime job")}</button>
    </section>`;
  }

  function pendingNativeConfiguration(state, item) {
    const changes = item.pendingNativeChanges;
    if (!changes?.length) return "";
    const { escape } = state;
    return `<section class="panel service-confirm" aria-labelledby="service-pve-pending-title">
      <div class="panel-head"><div><h2 id="service-pve-pending-title">${t("Ausstehende PVE-Konfiguration", "Pending PVE configuration")}</h2>
        <p>${t("Prüfe die ausstehenden Werte vor einem Neustart.", "Review the pending values before a restart.")}</p></div></div>
      <div class="table-wrap"><table class="data-table">
        <thead><tr><th scope="col">${t("Einstellung", "Setting")}</th><th scope="col">${t("Aktuell", "Current")}</th><th scope="col">${t("Ausstehend", "Pending")}</th></tr></thead>
        <tbody>${changes.map((change) => `<tr><th scope="row">${escape(change.field)}</th><td>${escape(change.current)}</td><td>${escape(change.pending)}</td></tr>`).join("")}</tbody>
      </table></div>
    </section>`;
  }

  function adapterSettings(state, item) {
    const demo = window.opstendDemo;
    const adapter = demo.adapterSettings(item);
    if (!adapter) return "";
    const esc = state.escape;
    const ui = window.opstendObjectUi;
    const draft = adapterDraft?.id === item.id ? adapterDraft : null;
    const review = draft?.review;
    const transition = adapterTransition?.id === item.id ? adapterTransition.preview : null;
    const stale = review && (review.revision !== adapter.revision || review.adapter.version !== adapter.version);
    const proposed = draft?.proposal;
    const staleProposal = proposed && (draft.revision !== adapter.revision || draft.version !== adapter.version);
    const transitionStale = transition && (transition.from.revision !== adapter.revision || transition.from.version !== adapter.version);
    const actions = [["upgrade", "Adapter aktualisieren"], ["rollback", "Adapter zurücksetzen"]]
      .filter(([action]) => demo.previewAdapterTransition(item, action).ok)
      .map(([action, label]) => `<button type="button" class="button" data-adapter-transition="${action}">${label}</button>`).join("");
    const lastTransition = state.inventory.changes.find((entry) => entry.id === lastAdapterJob && entry.serviceId === item.id);
    const proposalNote = `<p id="adapter-zorec-field-note" class="zorec-field-note" aria-live="polite" ${proposed ? "" : "hidden"}>${proposed
      ? esc(window.opstendZorecFields.note(proposed, draft.values)) : ""}</p>`;
    const content = review ? `
      <h3 id="adapter-review-title" tabindex="-1">Änderung zum Speichern prüfen</h3>
      <p class="compact adapter-review-context">${esc(item.name)} auf ${esc(item.host)} · Konfigurationsrevision ${review.revision}</p>
      ${proposalNote}
      ${review.changes.length ? ui.adapterChangeTable(state, review.adapter.fields, review.changes) : '<p class="compact">Keine Änderungen.</p>'}
      <div class="service-tools">
        ${review.changes.length ? `<button type="submit" class="button primary" ${stale ? "disabled" : ""}>Einstellungsentwurf speichern</button>` : ""}
        <button type="button" class="button" data-adapter-edit>Weiter bearbeiten</button>
        <button type="button" class="text-button" data-adapter-discard>Verwerfen</button>
      </div>` : `
      <div class="object-setting-fields">${ui.adapterFields(state, adapter, draft?.version === adapter.version ? draft.values : adapter.values)}</div>
      ${proposalNote}
      <div class="service-tools"><button type="submit" class="button primary" ${staleProposal ? "disabled" : ""}>Änderung prüfen</button>
        ${proposed ? '<button type="button" class="text-button" data-adapter-discard>Verwerfen</button>' : ""}${actions}</div>`;
    const transitionForm = transition && `<form class="panel-pad" data-adapter-transition-confirm="${esc(item.id)}">
      <h3 id="adapter-transition-title" tabindex="-1">${transition.action === "rollback" ? "Rückweg prüfen" : "Adapter-Update prüfen"}</h3>
      <p class="compact adapter-review-context">${esc(item.name)} auf ${esc(item.host)} · Adapter ${esc(transition.from.version)}
        → ${esc(transition.to.version)} · Revision ${transition.from.revision} → ${transition.to.revision}</p>
      ${ui.adapterChangeTable(state, [], transition.rows)}
      <p class="compact adapter-review-context">${transition.action === "rollback"
        ? "Der Rückweg übernimmt die beim Update gesicherten Werte."
        : "Das Update sichert den aktuellen Einstellungsstand für den Rückweg."}
        Die Demo speichert den Versionswechsel im Browser.</p>
      ${adapterTransition.unsaved ? '<p class="compact adapter-review-context">Die Vorschau verwendet gespeicherte Werte. Beim Bestätigen werden offene Eingaben verworfen.</p>' : ""}
      <div class="service-tools">
        <button type="submit" class="button primary" ${transitionStale ? "disabled" : ""}>Adapterwechsel in der Demo bestätigen</button>
        <button type="button" class="button" data-adapter-transition-cancel>Abbrechen</button>
      </div>
      <p role="status">${transitionStale ? "Vorschau ist veraltet. Öffne den Versionswechsel mit der aktuellen Revision erneut." : ""}</p>
    </form>`;
    return `<section class="panel object-settings" aria-labelledby="adapter-settings-title">
      <div class="panel-head"><div><h2 id="adapter-settings-title" tabindex="-1">Dienst-Einstellungen</h2>
        <p>${esc(adapter.title)} · Adapter ${esc(adapter.version)} · Revision ${adapter.revision}</p></div></div>
      ${transitionForm || `<form class="panel-pad" data-adapter-settings="${esc(item.id)}" data-adapter-version="${esc(adapter.version)}"
        data-adapter-revision="${adapter.revision}" ${adapter.fields.some((field) => field.id === "intervalSeconds" && field.type === "integer") ? "data-zorec-adapter" : ""}
        ${proposed ? `data-zorec-draft-value="${esc(proposed.value)}"` : ""} ${staleProposal ? "data-zorec-proposal-stale" : ""}>
        ${content}
        <p role="status" id="adapter-settings-result">${stale ? "Vorschau ist veraltet. Prüfe deine Eingaben mit der aktuellen Revision erneut."
          : staleProposal ? "Der Zorec-Vorschlag gehört zu einer älteren Revision. Verwirf den Entwurf für einen neuen Vorschlag."
          : lastAdapterSave === item.id ? "Einstellungsentwurf im Browser gespeichert." : ""}</p>
        ${lastTransition ? `<p role="status">Adapter ${esc(lastTransition.to.version)} im Browser gespeichert.
          <button class="text-button" type="button" data-view="changes" data-host="${esc(item.host)}"
            data-job="${esc(lastTransition.id)}">Versionswechsel im Verlauf ansehen</button></p>` : ""}
      </form>`}
    </section>`;
  }

  function renderAdapterSettings(focus) {
    window.dispatchEvent(new CustomEvent("opstend:inventory-changed"));
    document.querySelector(focus)?.focus({ preventScroll: true });
  }

  document.addEventListener("opstend:zorec-field-proposed", (event) => {
    const form = event.target;
    if (!form.matches("[data-zorec-adapter]")) return;
    const proposal = event.detail;
    adapterDraft = {
      id: form.dataset.adapterSettings,
      version: form.dataset.adapterVersion,
      revision: Number(form.dataset.adapterRevision),
      values: window.opstendObjectUi.adapterFieldValues(form),
      review: null,
      proposal,
    };
    lastAdapterSave = "";
    form.dataset.zorecDraftValue = proposal.value;
    const field = form.elements.namedItem(proposal.name);
    field.setAttribute("aria-describedby", "adapter-zorec-field-note");
    const note = form.querySelector("#adapter-zorec-field-note");
    note.textContent = window.opstendZorecFields.note(proposal, adapterDraft.values);
    note.hidden = false;
    form.querySelector("#adapter-settings-result").textContent = "";
    if (!form.querySelector("[data-adapter-discard]")) {
      const discard = document.createElement("button");
      discard.type = "button";
      discard.className = "text-button";
      discard.dataset.adapterDiscard = "";
      discard.textContent = "Verwerfen";
      form.querySelector('button[type="submit"]').after(discard);
    }
  });

  document.addEventListener("input", (event) => {
    const field = event.target;
    if (!adapterDraft?.proposal || !field.matches("[data-adapter-field]")) return;
    const form = field.closest("[data-adapter-settings]");
    if (form?.dataset.adapterSettings !== adapterDraft.id) return;
    adapterDraft.values = window.opstendObjectUi.adapterFieldValues(form);
    form.querySelector("#adapter-zorec-field-note").textContent = window.opstendZorecFields.note(adapterDraft.proposal, adapterDraft.values);
  });

  document.addEventListener("click", (event) => {
    const transition = event.target.closest("[data-adapter-transition], [data-adapter-transition-cancel]");
    if (transition) {
      if (transition.hasAttribute("data-adapter-transition-cancel")) {
        const action = adapterTransition?.preview.action;
        adapterTransition = null;
        renderAdapterSettings(`[data-adapter-transition="${action}"]`);
        return;
      }
      const form = transition.closest("[data-adapter-settings]");
      const id = form.dataset.adapterSettings;
      const demo = window.opstendDemo;
      const item = demo.getInventory().services.find((candidate) => candidate.id === id);
      const preview = demo.previewAdapterTransition(item, transition.dataset.adapterTransition);
      if (!preview.ok) {
        form.querySelector('[role="status"]').textContent = preview.error;
        return;
      }
      const values = window.opstendObjectUi.adapterFieldValues(form);
      const edit = demo.previewAdapterSettings(item, values);
      const unsaved = !edit.ok || edit.changes.length > 0;
      const proposalDraft = adapterDraft?.id === id && adapterDraft.proposal ? adapterDraft : null;
      adapterDraft = unsaved ? { id, version: preview.from.version, ...proposalDraft, values, review: null } : null;
      adapterTransition = { id, preview, unsaved };
      lastAdapterSave = "";
      renderAdapterSettings("#adapter-transition-title");
      return;
    }
    const button = event.target.closest("[data-adapter-edit], [data-adapter-discard]");
    if (!button || !adapterDraft) return;
    if (button.hasAttribute("data-adapter-discard")) adapterDraft = null;
    else adapterDraft.review = null;
    renderAdapterSettings("[data-adapter-field]");
  });

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (form.dataset.adapterTransitionConfirm) {
      event.preventDefault();
      const id = form.dataset.adapterTransitionConfirm;
      if (adapterTransition?.id !== id) return;
      const demo = window.opstendDemo;
      const { action, from } = adapterTransition.preview;
      const result = demo.applyAdapterTransition(id, action, from.version, from.revision);
      if (result !== true) {
        form.querySelector('[role="status"]').textContent = result;
        return;
      }
      lastAdapterJob = demo.getInventory().changes.find((entry) => entry.kind === "service-adapter" && entry.serviceId === id)?.id || "";
      adapterTransition = null;
      adapterDraft = null;
      renderAdapterSettings('[data-adapter-settings] button[type="submit"]');
      return;
    }
    const id = form.dataset.adapterSettings;
    if (!id) return;
    event.preventDefault();
    const demo = window.opstendDemo;
    const notice = form.querySelector('[role="status"]');
    const review = adapterDraft?.id === id && adapterDraft.review;
    if (!review) {
      const item = demo.getInventory().services.find((candidate) => candidate.id === id);
      const values = window.opstendObjectUi.adapterFieldValues(form);
      const preview = demo.previewAdapterSettings(item, values);
      if (!preview.ok) {
        notice.textContent = preview.error;
        return;
      }
      const proposalDraft = adapterDraft?.id === id && adapterDraft.proposal ? adapterDraft : null;
      if (proposalDraft && (proposalDraft.revision !== preview.revision || proposalDraft.version !== preview.adapter.version)) {
        notice.textContent = "Der Zorec-Vorschlag gehört zu einer älteren Revision. Verwirf den Entwurf für einen neuen Vorschlag.";
        return;
      }
      lastAdapterSave = "";
      adapterDraft = { ...proposalDraft, id, version: preview.adapter.version, values: preview.values, review: preview };
      renderAdapterSettings("#adapter-review-title");
      return;
    }
    if (!review.changes.length) return;
    const result = demo.updateAdapterSettings(id, review.values, review.revision);
    if (result !== true) {
      notice.textContent = result;
      return;
    }
    adapterDraft = null;
    lastAdapterSave = id;
    renderAdapterSettings('[data-adapter-settings] button[type="submit"]');
  });

  function provisioningDetails(state, item) {
    const { escape } = state;
    const { templateTitle, store, disk, readbackAt } = item.provisioning;
    return `<dl class="info-list">
      <div><dt>Vorlage</dt><dd>${escape(templateTitle)}</dd></div>
      <div><dt>Speicher</dt><dd>${escape(store)} · ${escape(disk)} GiB</dd></div>
      <div><dt>Anlage</dt><dd>${readbackAt ? "Im Demo-Inventar bestätigt" : "Vorgemerkt"}</dd></div>
    </dl>
    <div class="service-tools service-lifecycle">
      <button class="button" type="button" data-view="changes" data-host="${escape(item.host)}" data-job="guest-${escape(item.id)}">Anlageauftrag ansehen</button>
    </div>`;
  }

  function enrollmentDetails(state, item, host) {
    if (!item.sourceHost) return "";
    const { escape, badge } = state;
    const origin = state.hosts[item.sourceHost];
    const history = state.inventory.changes.filter((change) => change.kind === "host-enrollment" && change.host === item.sourceHost);
    const latest = history.find((change) => change.services.some((service) => service.id === item.id));
    const decision = latest?.services.find((service) => service.id === item.id);
    const originStatus = { reset: "Registrierung zurückgesetzt", remove: "Aus OpsTend entfernt" }[history[0]?.operation];
    const custody = { managed: "OpsTend verwaltet", observed: "Extern verwaltet · OpsTend beobachtet" }[item.mode] || "Zuständigkeit offen";
    const jobScope = latest && (latest.host === host.id || latest.relatedHost === host.id) ? host.id : "";
    return `<section class="panel" aria-labelledby="service-enrollment-title">
      <div class="panel-head"><h2 id="service-enrollment-title">Herkunft und Zuständigkeit</h2>${badge(custody, item.mode === "managed" ? "good" : "")}</div>
      <div class="panel-pad">
        <dl class="info-list">
          <div><dt>Aktueller Host</dt><dd><button type="button" class="text-button" data-view="host" data-host="${escape(host.id)}">${escape(host.name)}</button></dd></div>
          <div><dt>Quellhost der Aufnahme</dt><dd>${origin
            ? `<button type="button" class="text-button" data-view="host" data-host="${escape(origin.id)}">${escape(origin.name)}</button>`
            : `${escape(item.sourceHost)} · ${escape(originStatus || "Registrierung offen")}`}</dd></div>
          ${latest ? `<div><dt>Letzter Hostvorgang für diesen Dienst</dt><dd>${escape(latest.status)}<br>${escape(decision.effect)}</dd></div>` : ""}
        </dl>
        ${latest ? `<div class="service-tools service-lifecycle"><button type="button" class="button" data-view="changes" data-host="${escape(jobScope)}" data-job="${escape(latest.id)}">Hostauftrag ansehen</button></div>` : ""}
      </div>
    </section>`;
  }

  function serviceNetwork(state, item, host) {
    const { escape, inventory } = state;
    const demo = window.opstendDemo;
    const network = inventory.networks.find((entry) => window.opstendViews.serviceInNetwork(entry, item));
    const ports = network ? inventory.links.flatMap((link) => {
      if (link.layer !== "physical" || (link.from !== host.id && link.to !== host.id)) return [];
      const port = demo.portConfiguration(link.id, inventory);
      if (!port || port.peerId !== host.id || demo.linkEvidence(link).type !== "Link-Beobachtung") return [];
      const native = port.current.nativeVlan === network.id;
      if (!native && !port.current.taggedVlans.includes(network.id)) return [];
      const device = inventory.devices.find((entry) => entry.id === port.deviceId);
      return [`<button type="button" class="text-button" data-view="network-port" data-host="${escape(host.id)}"
        data-port-id="${escape(port.id)}">${escape(device?.name || port.deviceId)} · ${escape(port.port)}</button><br>${native ? "VLAN nativ" : "VLAN getaggt"}`];
    }) : [];
    const connections = inventory.links.filter((link) => link.from === item.id || link.to === item.id);
    return `<div><dt>Netzwerk</dt><dd>${network ? `<button type="button" class="text-button" data-view="network-detail"
      data-network-id="${escape(network.id)}" data-host="${escape(host.id)}">${escape(network.name)}</button>`
      : `${escape(item.network || "Offen")}${item.network ? `<br><button type="button" class="text-button" data-view="topology"
        data-host="${escape(host.id)}" data-layer="${item.network === "VPN" ? "access" : "network"}"
        data-topology-focus="${escape(item.id)}">Dienst im Netzplan</button>` : ""}`}</dd></div>
      ${network ? `<div><dt>Switchport des Hosts</dt><dd>${ports.join("<br>") || "Kein beobachteter Host-Port mit dieser VLAN-Zuordnung erfasst"}</dd></div>` : ""}
      <div><dt>Direkte Verbindungen</dt><dd>${connections.length ? connections.map((link) => `<button type="button" class="text-button"
        data-view="topology" data-host="${escape(host.id)}" data-layer="${escape(link.layer)}"
        data-topology-focus="${escape(link.id)}" style="overflow-wrap:anywhere">${escape(demo.linkLabel(link))}</button><br>${escape(demo.linkEvidence(link).type)}`).join("<br>")
      : "Keine direkte Verbindung erfasst"}</dd></div>`;
  }

  window.opstendViews.service = (state) => {
    const item = state.inventory.services.find((candidate) => candidate.id === state.serviceId);
    if (!item) {
      return '<header class="page-intro"><h1>Dienst</h1><p>Dieser Dienst ist im Inventar nicht vorhanden.</p></header><button class="button" data-view="services">Zu Diensten</button>';
    }
    const host = state.hosts[item.host];
    const power = serviceRuntime(item);
    const recovery = window.opstendDemo.recoveryFor(item);
    const runtimeJob = window.opstendDemo.pendingRuntime(item.id, state.inventory);
    const restricted = runtimeRestriction(item);
    const runtimeActions = restricted || runtimeJob ? [] : power === "running" ? ["stop", "restart"] : ["start"];
    const runtimeButtons = runtimeActions.map((operation) => `<button type="button" class="button" data-service-action="${operation}">${runtimeLabel(operation)}</button>`).join("");
    const pendingProvision = item.provisioning && !item.provisioning.readbackAt && item.status === "Vorgemerkt";
    const action = item.status === "Entfernung vorgemerkt" || item.group || item.sourceHost || pendingProvision || runtimeJob ? "" : item.status === "Stillgelegt"
      ? '<button class="button" data-service-action="remove">Entfernung vormerken</button>'
      : '<button class="button" data-service-action="retire">Stilllegen</button>';
    const preview = !runtimeJob && (Object.hasOwn(runtimeLabels, state.serviceAction)
      || (action && state.serviceAction === (item.status === "Stillgelegt" ? "remove" : "retire")));
    const consoleTile = window.opstendObjectUi.console(state, {
      name: item.name,
      platform: item.kind,
      lines: [`${item.name} auf ${item.host}`, `${t("Laufzeit", "Runtime")} · ${powerLabel(power)}`,
        `IPv4: ${item.ip || "offen"}`, `Health: ${power === "running" ? item.status : "keine laufende Prüfung"}`],
      ...(item.id === "fotos" ? { ui: {
        title: "Fotos · Web-UI", summary: "Vorschau der registrierten Weboberfläche für diesen Dienst. HTTPS-Pfad über edge-01.",
      } } : {}),
    });
    const ticker = window.opstendObjectUi.ticker(
      { ...state, host: item.host },
      window.opstendViews.jobsForService(state, item.id),
      `service:${item.id}`,
    );
    return `
      <header class="page-intro split">
        <div><p class="eyebrow">Dienste / ${state.escape(host.site)}</p><h1>${state.escape(item.name)}</h1>
          <p>${state.escape(item.kind)} · ${state.escape(item.role)} · ${state.escape(host.name)}</p></div>
        <div class="service-tools">${runtimeButtons}${window.opstendPveInventoryUI?.link(state, item.id) || ""}<button class="button" data-view="topology" data-host="${host.id}" data-layer="placement" data-topology-focus="${state.escape(item.id)}">In Topologie öffnen</button></div>
      </header>
      ${state.message ? `<p class="service-notice" role="status">${state.escape(state.message)}</p>` : ""}
      ${preview ? serviceAction(state, item) : ""}
      ${runtimeJob ? pendingRuntimeDetails(state, runtimeJob) : ""}
      ${pendingNativeConfiguration(state, item)}
      <div class="object-overview">${consoleTile}${ticker}</div>
      <div class="host-overview compact-layout">
        <section class="panel">
          <div class="panel-head"><h2>Hardware und Netzwerk</h2>${state.badge(powerLabel(power), power === "running" ? "good" : "")}</div>
          <div class="panel-pad"><dl class="info-list">
            <div><dt>Health</dt><dd>${power === "running" ? state.badge(item.status, statusTone[item.status]) : "Keine laufende Prüfung"}</dd></div>
            <div><dt>Host</dt><dd><button type="button" class="text-button" data-view="host" data-host="${state.escape(host.id)}">${state.escape(host.name)}</button></dd></div>
            ${serviceNetwork(state, item, host)}
            <div><dt>IPv4</dt><dd class="mono">${state.escape(item.ip || "Offen")}</dd></div>
            <div><dt>CPU · RAM</dt><dd>${state.escape(item.cpu)} · ${state.escape(item.ram)}</dd></div>
            ${item.id === "medien" ? "<div><dt>Passthrough</dt><dd>GPU mit HDMI · USB-Gerät</dd></div>" : ""}
            ${item.group ? `<div><dt>Dienstgruppe</dt><dd>${item.group} · ${item.instance}</dd></div>` : ""}
          </dl>
          ${restricted && !runtimeJob ? `<p class="service-restriction compact">${state.escape(restricted)}</p>` : ""}
          ${recovery && recovery.phase !== "historical" ? `<div class="service-tools service-restriction">
            <button type="button" class="button" data-view="changes" data-host="${state.escape(host.id)}" data-job="sensorik">${recovery.phase === "healthy" ? "Health-Beleg ansehen" : "Wiederanlauf ansehen"}</button>
          </div>` : ""}
          </div>
        </section>
        ${enrollmentDetails(state, item, host) || `<section class="panel">
          <div class="panel-head"><h2>${item.provisioning ? "Vorlage und Anlage" : "Deployment und Wartung"}</h2></div>
          <div class="panel-pad">
            ${item.provisioning ? provisioningDetails(state, item)
              : item.repositories?.length ? `<ul class="repo-references">${item.repositories.map((repo) => `<li>${state.escape(typeof repo === "string" ? repo : repo.url || repo.name)}</li>`).join("")}</ul>`
                : '<p class="compact">Für diese Beispielinstanz ist keine Repository-Quelle hinterlegt.</p>'}
            ${item.repositories?.length ? `<p class="compact">Git-Updates · ${item.updates === true || item.updates?.enabled ? "per Richtlinie vorgesehen" : "manuell"}</p>` : ""}
            ${action ? `<div class="service-tools service-lifecycle">${action}</div>` : ""}
          </div>
        </section>`}
      </div>
      ${window.opstendNetworkRuleUi?.section({ ...state, host: item.host }, { serviceId: item.id }) || ""}
      ${window.opstendPublicationUi?.section({ ...state, host: item.host }, { serviceId: item.id }) || ""}
      ${adapterSettings(state, item)}`;
  };
})();
