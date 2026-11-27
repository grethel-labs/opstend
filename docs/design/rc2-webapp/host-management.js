(function () {
  "use strict";

  const operations = {
    join: { title: "Host hinzufügen", confirm: "Host in der Demo aufnehmen" },
    reset: { title: "OpsTend-Registrierung zurücksetzen", confirm: "Host in der Demo zurücksetzen" },
    remove: { title: "Host aus OpsTend entfernen", confirm: "Host in der Demo entfernen" },
  };
  const actions = {
    manage: "Verwaltung übernehmen",
    observe: "Nur beobachten",
    exclude: "Eigenständig belassen",
    keep: "Auf diesem Host belassen",
    migrate: "Zu host-b verlagern",
    stop: "Stoppen und Daten behalten",
  };
  const modes = { managed: "Verwaltet", observed: "Beobachtet", excluded: "Eigenständig", local: "Lokal" };
  const capacity = [
    { key: "cpu", label: "CPU", unit: "Kerne" },
    { key: "ram", label: "Arbeitsspeicher", unit: "GiB" },
    { key: "storage", label: "Speicher", unit: "GiB" },
  ];
  let flow = null;
  let notice = "";
  let view;

  const enrollment = () => window.opstendHostEnrollment;

  function button(action, label, primary = false, disabled = false) {
    return `<button type="button" class="button${primary ? " primary" : ""}" data-host-management-action="${action}" ${disabled ? "disabled" : ""}>${label}</button>`;
  }

  function inventory(state, current, candidate) {
    const { escape, badge } = state;
    const hosts = state.inventory.hosts;
    const previous = current.phase === "reset" ? "Registrierung zurückgesetzt" : current.phase === "removed" ? "Aus OpsTend entfernt" : "";
    const joinLabel = previous ? "Host erneut aufnehmen" : "Host hinzufügen";
    const last = current.history.at(0);
    return `<section class="panel" aria-labelledby="host-management-title">
      <div class="panel-head"><div><h2 id="host-management-title" tabindex="-1">Hostverwaltung</h2>
        <p>${hosts.length} ${hosts.length === 1 ? "Host" : "Hosts"} in der Demo-Flotte</p></div>
        ${current.phase !== "registered" ? button("join", joinLabel, true) : ""}</div>
      <ul class="host-members">${hosts.map((host) => {
        const managedExample = host.id === candidate.id;
        return `<li><div><button type="button" class="text-button" data-view="host" data-host="${escape(host.id)}">${escape(host.name)}</button>
          <p>${escape(host.runtime)} · ${escape(host.ip)}</p>
          ${managedExample && current.budgets ? `<p>Freigegeben · ${escape(current.budgets.cpu)} CPU · ${escape(current.budgets.ram)} GiB RAM · ${escape(current.budgets.storage)} GiB Speicher · GPU ${current.budgets.gpu ? "erlaubt" : "gesperrt"}</p>` : ""}</div>
          <div class="host-member-actions">${badge(managedExample ? "Aufgenommen" : "Bestands-Host", managedExample ? "good" : "")}
          ${managedExample && current.phase === "registered" ? `${button("reset", "Zurücksetzen")}${button("remove", "Entfernen")}` : ""}</div></li>`;
      }).join("")}</ul>
      <div class="host-management-note compact">
        ${previous ? `<p>${badge(previous, "warn")} · ${escape(candidate.name)} steht mit seinem verbliebenen Bestand zur erneuten Aufnahme bereit.</p>` : `<p>${current.phase === "registered"
          ? `Die Demo unterstützt Zurücksetzen und Entfernen für den aufgenommenen Beispielhost ${escape(candidate.name)}.`
          : `Für den Aufnahmeablauf steht ${escape(candidate.name)} mit Beispielinventar bereit.`}</p>`}
        ${last ? `<button type="button" class="text-button" data-view="changes" data-host="" data-job="host-enrollment-${escape(last.revision)}">Auftrag ansehen</button>` : ""}
      </div>
      <p class="host-management-notice compact" role="status">${escape(notice)}</p>
    </section>`;
  }

  function evidence(state, candidate, source) {
    const { escape } = state;
    const hardware = capacity.map(({ key, label, unit }) => `<div><dt>${label}</dt><dd>${escape(source.physical[key])} ${unit}</dd></div>`);
    hardware.push(`<div><dt>GPU</dt><dd>${source.physical.gpu ? "Vorhanden" : "Keine erfasst"}</dd></div>`);
    return `<dl class="host-workflow-facts"><div><dt>Ziel</dt><dd>${escape(candidate.name)} · ${escape(candidate.ip)}</dd></div>
      <div><dt>Plattform</dt><dd>${escape(source.runtime)}</dd></div><div><dt>Quelle</dt><dd>${escape(source.source)}</dd></div>${hardware.join("")}</dl>`;
  }

  function identify(state, candidate) {
    const { escape } = state;
    return `<div class="host-workflow-body">
      <p>Wähle den Beispielhost für die Bestandsaufnahme.</p>
      <label for="host-intake-target">Ziel der Bestandsaufnahme</label>
      <select id="host-intake-target" name="host"> <option value="${escape(candidate.id)}">${escape(candidate.name)} · ${escape(candidate.ip)}</option></select>
      <p class="compact">Zorec liest in diesem Ablauf ein festes Demo-Inventar mit bestehenden Diensten und Hardware.</p>
      <div class="host-workflow-buttons">${button("inspect", "Bestand mit Zorec prüfen", true)}${button("cancel", "Abbrechen")}</div>
    </div>`;
  }

  function serviceChoices(service, operation) {
    if (operation === "join") return ["manage", "observe", "exclude"];
    if (service.mode !== "managed") return ["keep"];
    return service.gpu ? ["keep", "stop"] : ["keep", "migrate", "stop"];
  }

  function serviceFields(state, services, actionChoices, operation) {
    const { escape } = state;
    if (!services.length) return '<p class="compact">Für den Host sind keine Dienste erfasst.</p>';
    return `<ul class="host-service-choices">${services.map((service, index) => {
      const options = serviceChoices(service, operation);
      const selected = actionChoices[service.id] || "";
      return `<li><div class="host-service-meta"><strong>${escape(service.name)}</strong>
        <p>${escape(service.kind)}${service.detail ? ` · ${escape(service.detail)}` : ""}${operation === "join" || !modes[service.mode] ? "" : ` · ${modes[service.mode]}`}${service.power ? ` · ${service.power === "running" ? "Läuft" : "Gestoppt"}` : ""}</p>
        ${service.cpu || service.ram || service.storage ? `<p>${escape(service.cpu ?? 0)} CPU · ${escape(service.ram ?? 0)} GiB RAM · ${escape(service.storage ?? 0)} GiB Speicher${service.gpu ? " · GPU" : ""}</p>` : ""}</div>
        <div class="host-service-action"><label for="host-service-choice-${index}">Umgang mit ${escape(service.name)}</label>
        <select id="host-service-choice-${index}" name="service:${escape(service.id)}" required>
          <option value="">Bitte auswählen</option>${options.map((action) => `<option value="${action}" ${selected === action ? "selected" : ""}>${actions[action]}</option>`).join("")}</select></div></li>`;
    }).join("")}</ul>`;
  }

  function budgetFields(state, physical, budgets) {
    const { escape } = state;
    return `<fieldset class="host-budget-fields"><legend>Ressourcen für OpsTend freigeben</legend>
      <p class="compact">Hier legst du Obergrenzen für die übernommenen Dienste fest.</p>
      <div class="host-budget-grid">${capacity.map(({ key, label, unit }) => `<label>${label} (${unit})
        <input type="number" name="${key}" step="1" min="0" max="${escape(physical[key])}" value="${escape(budgets[key])}" required>
        <small>Physisch vorhanden · ${escape(physical[key])} ${unit}</small></label>`).join("")}</div>
      <label class="host-budget-gpu"><input type="checkbox" name="gpu" ${budgets.gpu ? "checked" : ""} ${physical.gpu ? "" : "disabled"}>GPU-Nutzung erlauben</label></fieldset>`;
  }

  function decisions(state, current, candidate) {
    const join = flow.operation === "join";
    const source = join ? flow.inventory : candidate;
    const services = join ? source.services : current.services;
    return `<form class="host-workflow-body" data-host-management-decisions>
      ${join ? evidence(state, candidate, source) : ""}
      <fieldset><legend>${join ? "Vorhandene Dienste" : "Verbleib der Dienste"}</legend>
        ${serviceFields(state, services, flow.serviceActions, flow.operation)}</fieldset>
      ${join ? budgetFields(state, source.physical, flow.budgets) : ""}
      <div class="host-workflow-buttons"><button type="submit" class="button primary">Auswirkungen prüfen</button>${button("cancel", "Abbrechen")}</div>
    </form>`;
  }

  function review(state, candidate) {
    const { escape } = state;
    const { plan, operation, pending } = flow;
    const title = operations[operation];
    const join = operation === "join";
    return `<div class="host-workflow-body">
      <dl class="host-workflow-facts"><div><dt>Host</dt><dd>${escape(candidate.name)}</dd></div>
        <div><dt>Geplante Aktion</dt><dd>${title.title}</dd></div>
        ${join ? `${capacity.map(({ key, label, unit }) => `<div><dt>${label} freigegeben</dt><dd>${escape(plan.budgets[key])} ${unit}</dd></div>`).join("")}
          <div><dt>GPU freigegeben</dt><dd>${plan.budgets.gpu ? "Ja" : "Nein"}</dd></div>` : ""}</dl>
      ${plan.services.length ? `<ul class="host-reviewed-services" aria-label="Geplante Auswirkungen je Dienst">${plan.services.map((service) => `<li><strong>${escape(service.name)}</strong><span>${escape(actions[service.action])}</span><p>${escape(service.effect)}</p></li>`).join("")}</ul>` : '<p class="compact">Der Plan enthält keine Änderungen an Diensten.</p>'}
      <p class="compact">Die Bestätigung ändert das Demo-Inventar in diesem Browser.</p>
      <div class="host-workflow-buttons">${button("confirm", pending ? "Wird gespeichert …" : title.confirm, true, pending)}
        ${button("back", "Entscheidungen ändern", false, pending)}${button("cancel", "Abbrechen", false, pending)}</div>
    </div>`;
  }

  function workflow(state, current, candidate) {
    const stages = { identify: "Ziel wählen", decisions: "Dienste und Ressourcen festlegen", review: "Auswirkungen prüfen" };
    const body = flow.step === "identify" ? identify(state, candidate)
      : flow.step === "decisions" ? decisions(state, current, candidate) : review(state, candidate);
    return `<section class="panel host-workflow" aria-labelledby="host-workflow-title"><div class="panel-head"><div>
      <h2 id="host-workflow-title" tabindex="-1">${operations[flow.operation].title}</h2><p>${stages[flow.step]}</p></div></div>
      ${flow.error ? `<p class="host-workflow-error" role="alert">${state.escape(flow.error)}</p>` : ""}${body}</section>`;
  }

  function contents(state) {
    const admin = enrollment();
    if (!admin) return '<section class="panel panel-pad">Das Host-Inventar ist in dieser Demo nicht verfügbar.</section>';
    const { candidate } = admin;
    const current = admin.read();
    return flow ? workflow(state, current, candidate) : inventory(state, current, candidate);
  }

  function render(state) {
    view = state;
    return `<div data-host-management>${contents(state)}</div>`;
  }

  function refresh() {
    const root = document.querySelector("[data-host-management]");
    if (!root) return;
    root.innerHTML = contents(view);
    const title = root.querySelector("h2");
    title?.focus({ preventScroll: true });
    title?.scrollIntoView({ block: "nearest" });
  }

  function start(operation) {
    notice = "";
    const admin = enrollment();
    const current = admin.read();
    flow = { operation, step: operation === "join" ? "identify" : "decisions", revision: current.revision,
      serviceActions: {}, budgets: { ...admin.candidate.budgets }, error: "" };
    refresh();
  }

  async function confirm() {
    flow.pending = true;
    flow.error = "";
    refresh();
    try {
      const result = await enrollment().apply(flow.plan);
      if (!result.ok) {
        flow.error = result.error;
        return;
      }
      notice = { join: "Der Beispielhost wurde aufgenommen.", reset: "Die OpsTend-Registrierung wurde zurückgesetzt.",
        remove: "Der Beispielhost wurde aus OpsTend entfernt." }[flow.operation];
      flow = null;
    } catch {
      flow.error = "Der Plan konnte gerade nicht im Browser gespeichert werden.";
    } finally {
      if (flow) flow.pending = false;
      refresh();
    }
  }

  document.addEventListener("click", (event) => {
    const control = event.target.closest("[data-host-management-action]");
    if (!control || flow?.pending) return;
    const action = control.dataset.hostManagementAction;
    if (Object.hasOwn(operations, action)) {
      start(action);
      return;
    }
    if (!flow) return;
    if (action === "inspect") {
      flow.inventory = enrollment().inspect();
      flow.step = "decisions";
    } else if (action === "back") {
      flow.error = "";
      flow.step = "decisions";
    } else if (action === "cancel") {
      flow = null;
    } else if (action === "confirm" && flow.step === "review") {
      void confirm();
      return;
    }
    refresh();
  });

  document.addEventListener("submit", (event) => {
    if (!event.target.hasAttribute("data-host-management-decisions") || flow?.step !== "decisions") return;
    event.preventDefault();
    const data = new FormData(event.target);
    const admin = enrollment();
    flow.serviceActions = Object.fromEntries([...data].filter(([key]) => key.startsWith("service:")).map(([key, value]) => [key.slice(8), value]));
    if (flow.operation === "join") flow.budgets = Object.fromEntries([...capacity.map(({ key }) => [key, Number(data.get(key))]), ["gpu", data.has("gpu")]]);
    const result = admin.read().revision === flow.revision
      ? admin.preview({ operation: flow.operation, serviceActions: flow.serviceActions, budgets: flow.budgets })
      : { ok: false, error: "Der Hoststand hat sich geändert. Brich den Entwurf ab und öffne den Ablauf erneut." };
    flow.error = result.ok ? "" : result.error;
    if (result.ok) {
      flow.plan = result.plan;
      flow.step = "review";
    }
    refresh();
  });

  window.opstendHostManagement = { render };
})();
