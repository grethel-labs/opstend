(function () {
  "use strict";

  function objectConsole(state, config) {
    const esc = state.escape;
    const assistant = window.opstendZorecConsole;
    const target = assistant?.targetId(state, config) || "";
    const terminal = assistant?.render(state, config, target)
      || `<pre tabindex="0" aria-label="Demo-Konsolenausgabe">${esc(config.lines.join("\n"))}</pre>`;
    const modes = config.ui ? `<div class="tabs object-console-modes" role="group" aria-label="Darstellung">
      <button type="button" data-console-mode="terminal" aria-pressed="true">Konsole</button>
      <button type="button" data-console-mode="ui" aria-pressed="false">Web-UI</button>
    </div>` : "";
    const output = `<div class="object-console-output">
      <div data-console-variant="terminal">${terminal}</div>
      ${config.ui ? `<div data-console-variant="ui" class="object-ui-preview" hidden>
        <h3>${esc(config.ui.title)}</h3><p>${esc(config.ui.summary)}</p>
      </div>` : ""}
    </div>`;
    return `<section class="panel object-console" aria-label="Konsole" data-object-console data-console-target="${esc(target)}">
      <div class="panel-head"><div><h2>Konsole</h2><p>${esc(config.platform)} · Demo-Ausgabe</p></div>
        <button class="button" type="button" data-console-open aria-haspopup="dialog">Vergrößern</button></div>
      ${modes}${output}
      <dialog class="object-console-dialog" aria-label="Konsole für ${esc(config.name)}">
        <div class="panel-head"><div><h2>${esc(config.name)}</h2><p>${esc(config.platform)} · Demo-Ausgabe</p></div>
          <button type="button" class="button" data-console-close>Schließen</button></div>
        ${modes}${output}
      </dialog>
    </section>`;
  }

  function setConsoleMode(consoleCard, mode) {
    for (const variant of consoleCard.querySelectorAll("[data-console-variant]")) {
      variant.hidden = variant.dataset.consoleVariant !== mode;
    }
    for (const control of consoleCard.querySelectorAll("[data-console-mode]")) {
      control.setAttribute("aria-pressed", String(control.dataset.consoleMode === mode));
    }
  }

  function ticker(state, events, subject = "") {
    const esc = state.escape;
    const rows = events.slice(0, 6).map((event) => {
      const host = event.navigationHost ?? event.host;
      return `<li>
      <time>${esc(event.time || "Demo")}</time><div>
        ${event.id ? `<button type="button" class="text-button" data-view="changes" data-job="${esc(event.id)}"
          ${host !== undefined ? `data-host="${esc(host)}"` : ""} ${event.jobEvent ? `data-job-event="${esc(event.jobEvent)}"` : ""}>${esc(event.title)}</button>`
          : `<strong>${esc(event.title)}</strong>`}
        <p>${esc(event.status || "")}</p>
      </div></li>`;
    }).join("");
    return `<section class="panel object-ticker" aria-labelledby="object-events-title">
      <div class="panel-head"><h2 id="object-events-title">Letzte Ereignisse</h2>
        ${subject === null ? "" : `<button type="button" class="text-button" data-view="events"
          data-event-subject="${esc(subject)}" data-host="${esc(state.host ?? "")}">Ereignisprotokoll öffnen</button>`}
      </div>
      <div role="log" aria-label="Objektereignisse">
        ${rows ? `<ul class="feed activity-feed">${rows}</ul>`
          : '<p class="panel-pad compact">Für dieses Objekt gibt es im Beispiel noch keine Ereignisse.</p>'}
      </div>
    </section>`;
  }

  function adapterValue(field, value) {
    if (field?.type === "boolean") return value ? "Ja" : "Nein";
    if (field?.type === "select") return field.options.find(([key]) => key === value)?.[1] ?? String(value);
    return String(value ?? "");
  }

  function adapterFields(state, adapter, values = adapter.values) {
    const esc = state.escape;
    return adapter.fields.map((field) => {
      const attributes = `name="${esc(field.id)}" data-adapter-field`;
      const value = values[field.id];
      let input;
      if (field.type === "boolean") {
        input = `<input type="checkbox" ${attributes} ${value ? "checked" : ""}>`;
      } else if (field.type === "select") {
        input = `<select ${attributes}>${field.options.map(([key, label]) =>
          `<option value="${esc(key)}" ${key === value ? "selected" : ""}>${esc(label)}</option>`).join("")}</select>`;
      } else if (field.type === "integer") {
        input = `<input type="number" ${attributes} value="${esc(value)}" min="${esc(field.min)}" max="${esc(field.max)}" step="1" required>`;
      } else {
        input = `<input type="text" ${attributes} value="${esc(value)}" minlength="${esc(field.min)}" maxlength="${esc(field.max)}" required>`;
      }
      return `<label><span>${esc(field.label)}</span>${input}${field.help ? `<small>${esc(field.help)}</small>` : ""}</label>`;
    }).join("");
  }

  function adapterFieldValues(element) {
    return Object.fromEntries([...element.querySelectorAll("[data-adapter-field]")].map((field) =>
      [field.name, field.type === "checkbox" ? field.checked : field.value]));
  }

  function adapterChangeTable(state, fields, changes, resultLabel = "Entwurf") {
    const esc = state.escape;
    const withNotes = changes.some((change) => change.note);
    const rows = changes.map((change) => {
      const field = fields.find((item) => item.label === change.label);
      return `<tr><th scope="row">${esc(change.label)}</th>
        <td>${esc(adapterValue(field, change.before))}</td><td>${esc(adapterValue(field, change.after))}</td>
        ${withNotes ? `<td>${esc(change.note || "")}</td>` : ""}</tr>`;
    }).join("");
    return `<div class="table-wrap"><table class="data-table">
      <thead><tr><th scope="col">Einstellung</th><th scope="col">Bisher</th><th scope="col">${esc(resultLabel)}</th>
        ${withNotes ? '<th scope="col">Umstellung</th>' : ""}</tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  }

  document.addEventListener("click", (event) => {
    const button = event.target.closest("button");
    const consoleCard = button?.closest("[data-object-console]");
    if (!consoleCard) return;
    const dialog = consoleCard.querySelector("dialog");
    if (button.hasAttribute("data-console-open")) dialog.showModal();
    if (button.hasAttribute("data-console-close")) dialog.close();
    const mode = button.dataset.consoleMode;
    if (mode) setConsoleMode(consoleCard, mode);
  });

  window.opstendObjectUi = { console: objectConsole, setConsoleMode, ticker, adapterFields, adapterFieldValues, adapterValue, adapterChangeTable };
})();
