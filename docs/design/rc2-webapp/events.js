(function () {
  "use strict";

  const { t, ui } = window.opstendLocale;
  const kinds = {
    health: ["Health und Wiederanlauf", "Health and recovery"],
    network: ["Netzwerk und Zugang", "Network and access"],
    config: ["Adapter und Konfiguration", "Adapters and configuration"],
    runtime: ["Gast- und Dienstbetrieb", "Guest and service operations"],
    maintenance: ["Hostwartung", "Host maintenance"],
    deployment: ["Deployment", "Deployment"],
    other: ["Weitere Ereignisse", "Other events"],
  };

  function subjectsFor(event) {
    return [event.ruleId && "rule:" + event.ruleId, event.serviceId && "service:" + event.serviceId,
      event.portId && "port:" + event.portId].filter(Boolean);
  }

  function subjectLabel(state, subject, related = false) {
    const [kind, id] = subject.split(":");
    if (kind === "service") {
      const service = state.inventory.services.find((item) => item.id === id && (related || !state.host || item.host === state.host));
      return service?.name;
    }
    if (kind === "port") {
      const port = window.opstendDemo.portConfiguration(id, state.inventory);
      if (port && (related || !state.host || port.peerId === state.host)) return "Port " + port.port;
    }
    if (kind === "rule") {
      const rule = window.opstendNetworkRules?.get(state, id);
      if (rule) return t(rule.name, rule.nameEn || rule.name);
    }
    return undefined;
  }

  function eventSubjectLabel(state, entry) {
    return entry.ruleName || entry.serviceName || subjectLabel(state, subjectsFor(entry)[0] || "", true);
  }

  function filters(state, entries) {
    const esc = state.escape;
    const subjects = new Map();
    for (const entry of entries) {
      for (const subject of subjectsFor(entry)) {
        const label = subject.startsWith("rule:") ? entry.ruleName
          : subject.startsWith("service:") ? entry.serviceName : undefined;
        const display = label || subjectLabel(state, subject, true);
        if (display) subjects.set(subject, display);
      }
    }
    if (state.eventSubject && !subjects.has(state.eventSubject)) {
      subjects.set(state.eventSubject, subjectLabel(state, state.eventSubject) || t("Objekt aus dem Direktlink", "Object from the direct link"));
    }

    const options = (labels, active) => [...labels].map(([id, label]) =>
      `<option value="${esc(id)}" ${id === active ? "selected" : ""}>${esc(label)}</option>`).join("");
    const filtered = state.eventKind || state.eventSubject || state.eventQuery;
    const typeOptions = Object.entries(kinds).map(([id, labels]) => [id, t(...labels)]);
    return `<form class="panel event-filters" id="event-filters">
      <div class="event-field">
        <label for="event-query">${t("In Ereignissen suchen", "Search events")}</label>
        <input id="event-query" name="eventQuery" type="search" value="${esc(state.eventQuery)}" maxlength="160">
      </div>
      <div class="event-field">
        <label for="event-kind">${t("Ereignistyp", "Event type")}</label>
        <select id="event-kind" name="eventKind">
          ${options([["", t("Alle Typen", "All types")], ...typeOptions], state.eventKind)}
        </select>
      </div>
      <div class="event-field">
        <label for="event-subject">${t("Objekt", "Object")}</label>
        <select id="event-subject" name="eventSubject">
          ${options([["", t("Alle Objekte", "All objects")], ...subjects], state.eventSubject)}
        </select>
      </div>
      <div class="service-tools">
        <button type="submit" class="button primary">${t("Filter anwenden", "Apply filters")}</button>
        ${filtered ? `<button type="button" class="text-button" data-clear-events>${t("Zurücksetzen", "Reset filters")}</button>` : ""}
      </div>
    </form>`;
  }

  function eventRow(state, entry) {
    const esc = state.escape;
    const kind = t(...(Object.hasOwn(kinds, entry.kind) ? kinds[entry.kind] : kinds.other));
    const object = eventSubjectLabel(state, entry);
    const placement = entry.relatedHost ? `${entry.host} → ${entry.relatedHost}` : entry.host;
    const metadata = [object, placement, entry.display.actor].filter(Boolean).map(esc).join(" · ");
    return `<li class="event-row">
      <div class="event-meta">
        <time ${entry.at ? `datetime="${esc(entry.at)}"` : ""}>${esc(entry.time)}</time>
        <small>${esc(kind)}</small>
      </div>
      <div class="event-description">
        <h2>${esc(entry.display.title)}</h2>
        <p>${esc(entry.display.detail)}</p>
        ${metadata ? `<p class="compact">${metadata}</p>` : ""}
      </div>
      <button type="button" class="text-button" data-view="changes" data-job="${esc(entry.jobId)}" data-job-event="${esc(entry.id)}"
        data-host="${esc(entry.navigationHost ?? state.host)}">${t("Auftrag öffnen", "Open job")}</button>
    </li>`;
  }

  window.opstendViews.events = (state) => {
    const entries = window.opstendViews.eventsForScope(state);
    const language = ui();
    const query = state.eventQuery.toLocaleLowerCase(language);
    const visible = entries.filter((entry) =>
      (!state.eventKind || entry.kind === state.eventKind)
      && (!state.eventSubject || subjectsFor(entry).includes(state.eventSubject))
      && (!query || [entry.title, entry.detail, entry.display.title, entry.display.detail, entry.host, entry.relatedHost,
        entry.actor, entry.display.actor, eventSubjectLabel(state, entry)]
        .filter(Boolean).join(" ").toLocaleLowerCase(language).includes(query)));
    const total = entries.length;
    const count = t(`${visible.length} von ${total} Ereignissen`, `${visible.length} of ${total} ${total === 1 ? "event" : "events"}`);
    return `<header class="page-intro split">
      <div><p class="eyebrow">${state.escape(state.host || t("Ganze Flotte", "Entire fleet"))}</p><h1>${t("Ereignisprotokoll", "Event log")}</h1></div>
      <button type="button" class="button" data-view="changes">${t("Zu Änderungen", "Go to Changes")}</button>
    </header>
    ${filters(state, entries)}
    <p class="compact event-result" role="status">${count}</p>
    ${visible.length ? `<ol class="panel event-list" aria-label="${t("Ereignisse", "Events")}">${visible.map((entry) => eventRow(state, entry)).join("")}</ol>`
      : `<section class="panel panel-pad"><p>${t("Für die aktuelle Auswahl gibt es keine Ereignisse.", "No events match this selection.")}</p></section>`}`;
  };
})();
