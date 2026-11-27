(function () {
  "use strict";

  const demo = window.opstendDemo;
  const modes = { access: "Access", trunk: "Trunk" };
  let draft = null;
  let lastJob = "";

  function settingsView(state, port, config) {
    const esc = state.escape;
    return `<form class="panel-pad" data-port-form="${esc(port.id)}">
      <div class="object-setting-fields">
        <label><span id="port-mode-label">Betriebsart</span><select name="mode" aria-labelledby="port-mode-label">
          ${Object.entries(modes).map(([key, name]) =>
            `<option value="${key}" ${config.mode === key ? "selected" : ""}>${name}</option>`).join("")}
        </select></label>
        <label><span id="port-native-label">Ungetaggtes Netz</span><select name="nativeVlan" aria-labelledby="port-native-label">
          ${state.inventory.networks.map((network) =>
            `<option value="${esc(network.id)}" ${config.nativeVlan === network.id ? "selected" : ""}>${esc(network.name)}</option>`).join("")}
        </select></label>
      </div>
      <fieldset class="port-vlans" data-port-tags ${config.mode === "access" ? "hidden disabled" : ""}>
        <legend>Getaggte Netze</legend>
        ${state.inventory.networks.map((network) => `<label><input type="checkbox" name="taggedVlan" value="${esc(network.id)}"
          ${config.taggedVlans.includes(network.id) ? "checked" : ""} ${config.nativeVlan === network.id ? "disabled" : ""}>
          ${esc(network.name)}</label>`).join("")}
      </fieldset>
      <div class="service-tools">
        <button type="submit" class="button primary">Zuordnung prüfen</button>
        ${port.previous ? `<button type="button" class="button" data-port-revert="${esc(port.id)}">Vorherige Zuordnung prüfen</button>` : ""}
      </div>
      <p id="port-result" role="status"></p>
    </form>`;
  }

  function reviewView(state, port, pending) {
    const esc = state.escape;
    const { before, after, changed } = pending.preview;
    const stale = pending.preview.port.revision !== port.revision;
    const name = (id) => state.inventory.networks.find((network) => network.id === id)?.name || id;
    const tags = (config) => config.taggedVlans.map(name).join(", ") || "Keine";
    const rows = [
      { label: "Betriebsart", before: modes[before.mode], after: modes[after.mode] },
      { label: "Ungetaggtes Netz", before: name(before.nativeVlan), after: name(after.nativeVlan) },
      { label: "Getaggte Netze", before: tags(before), after: tags(after) },
    ];
    return `<form class="panel-pad" data-port-confirm="${esc(port.id)}">
      <h3 id="port-review-title" tabindex="-1">${pending.revert ? "Rückweg prüfen" : "Portänderung prüfen"}</h3>
      <p class="compact adapter-review-context">${esc(port.port)} · Ausgangsrevision ${pending.preview.port.revision}</p>
      ${window.opstendObjectUi.adapterChangeTable(state, [], rows)}
      <p class="compact adapter-review-context">Die Zuordnung bestimmt, welches VLAN ungetaggt am Port anliegt und welche VLANs getaggt zugelassen werden.
        Die Demo speichert die Einstellung im Inventar. Die Erreichbarkeit bleibt ungeprüft.</p>
      <div class="service-tools">
        ${changed ? `<button type="submit" class="button primary" ${stale ? "disabled" : ""}>In der Demo übernehmen</button>` : ""}
        <button type="button" class="button" data-port-edit>Weiter bearbeiten</button>
        <button type="button" class="text-button" data-port-discard>Verwerfen</button>
      </div>
      <p id="port-result" role="status">${stale ? "Vorschau ist veraltet. Prüfe die Zuordnung mit der aktuellen Revision erneut."
        : !changed ? "Keine Änderung an der Zuordnung." : ""}</p>
    </form>`;
  }

  window.opstendViews["network-port"] = (state) => {
    const esc = state.escape;
    const port = demo.portConfiguration(state.portId, state.inventory);
    if (!port || (state.host && port.peerId !== state.host)) {
      return `<header class="page-intro"><h1>Switchport</h1><p>Dieser Port ist im aktuellen Geltungsbereich nicht sichtbar.</p></header>
        <button type="button" class="button" data-view="network" data-host="">Netzwerk der Flotte öffnen</button>`;
    }
    const records = [...state.inventory.hosts, ...state.inventory.devices];
    const device = records.find((item) => item.id === port.deviceId);
    const peer = records.find((item) => item.id === port.peerId);
    const networkName = (id) => state.inventory.networks.find((network) => network.id === id)?.name || id;
    const networkLink = (id) => `<button type="button" class="text-button" data-view="network-detail" data-network-id="${esc(id)}">${esc(networkName(id))}</button>`;
    const link = state.inventory.links.find((item) => item.id === port.id);
    const evidence = demo.linkEvidence(link);
    const job = state.inventory.changes.find((item) => item.id === lastJob && item.portId === port.id && item.revision === port.revision);
    const current = draft?.id === port.id ? draft : null;
    const events = window.opstendViews.jobsForPort(state, port.id);
    const peerLink = state.hosts[port.peerId] ? `<button type="button" class="text-button" data-view="host" data-host="${esc(port.peerId)}">${esc(peer.name)}</button>`
      : esc(peer?.name || "Unbekannt");
    return `<header class="page-intro split">
      <div><p class="eyebrow">Netzwerk / Switchports</p><h1>Port ${esc(port.port)}</h1>
        <p>${esc(device?.name || "Switch")} · ${esc(evidence.source)}</p></div>
      <div class="service-tools"><button class="button" type="button" data-view="network">Zum Netzwerk</button>
        <button class="button" type="button" data-view="topology" data-layer="physical" data-topology-focus="${esc(port.id)}">In Topologie öffnen</button></div>
    </header>
    ${job ? `<p class="service-notice" role="status">Demo-Readback · Revision ${job.revision} im Inventar.
      <button type="button" class="text-button" data-view="changes" data-job="${esc(job.id)}">Änderung ansehen</button></p>` : ""}
    <div class="object-overview">
      <section class="panel"><div class="panel-head"><h2>Physischer Link</h2></div>
        <div class="panel-pad"><dl class="info-list">
          <div><dt>Gegenstelle</dt><dd>${peerLink}</dd></div>
          <div><dt>Linkrate</dt><dd>${esc(evidence.rate || "Offen")}</dd></div>
          <div><dt>Belegart</dt><dd>${esc(evidence.type)}</dd></div>
        </dl></div></section>
      ${window.opstendObjectUi.ticker(state, events, `port:${port.id}`)}
    </div>
    <section class="panel object-settings" aria-labelledby="port-settings-title">
      <div class="panel-head"><div><h2 id="port-settings-title">VLAN-Zuordnung</h2>
        <p>Konfigurationsrevision ${port.revision}</p></div></div>
      <div class="port-current compact">
        <span>Ungetaggt ${networkLink(port.current.nativeVlan)}</span>
        <span>Getaggt ${port.current.taggedVlans.map(networkLink).join(", ") || "Keine"}</span>
      </div>
      ${port.editable
        ? current?.preview ? reviewView(state, port, current) : settingsView(state, port, current?.input || port.current)
        : `<div class="panel-pad"><dl class="info-list">
          <div><dt>Betriebsart</dt><dd>${modes[port.current.mode]}</dd></div>
          <div><dt>Ungetaggtes Netz</dt><dd>${esc(networkName(port.current.nativeVlan))}</dd></div>
          <div><dt>Getaggte Netze</dt><dd>${esc(port.current.taggedVlans.map(networkName).join(", ") || "Keine")}</dd></div>
        </dl><p class="compact service-restriction">${esc(port.reason)}</p></div>`}
    </section>`;
  };

  function refresh(focus) {
    window.dispatchEvent(new CustomEvent("opstend:inventory-changed"));
    document.querySelector(focus)?.focus({ preventScroll: true });
  }

  function preview(id, input, revert, form) {
    const result = demo.previewPortChange(id, input);
    if (!result.ok) {
      form.querySelector("#port-result").textContent = result.error;
      return;
    }
    draft = { id, input: result.after, preview: result, revert };
    refresh("#port-review-title");
  }

  document.addEventListener("change", (event) => {
    const form = event.target.closest("[data-port-form]");
    if (!form || !["mode", "nativeVlan"].includes(event.target.name)) return;
    const tags = form.querySelector("[data-port-tags]");
    tags.hidden = tags.disabled = form.elements.mode.value === "access";
    for (const checkbox of tags.querySelectorAll('input[type="checkbox"]')) {
      checkbox.disabled = checkbox.value === form.elements.nativeVlan.value;
      if (checkbox.disabled) checkbox.checked = false;
    }
  });

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (form.dataset.portForm) {
      event.preventDefault();
      const fields = new FormData(form);
      preview(form.dataset.portForm, {
        mode: fields.get("mode"), nativeVlan: fields.get("nativeVlan"), taggedVlans: fields.getAll("taggedVlan"),
      }, false, form);
    } else if (form.dataset.portConfirm && draft?.id === form.dataset.portConfirm) {
      event.preventDefault();
      const result = demo.applyPortChange(draft.id, draft.input, draft.preview.port.revision);
      if (result !== true) {
        form.querySelector("#port-result").textContent = result;
        return;
      }
      lastJob = demo.getInventory().changes.find((item) => item.kind === "network-port" && item.portId === draft.id)?.id || "";
      draft = null;
      refresh("[data-port-form] button[type='submit']");
    }
  });

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-port-edit], [data-port-discard], [data-port-revert]");
    if (!button) return;
    if (button.dataset.portRevert) {
      const port = demo.portConfiguration(button.dataset.portRevert);
      if (port?.previous) preview(port.id, port.previous, true, button.closest("form"));
      return;
    }
    if (button.hasAttribute("data-port-discard")) draft = null;
    else if (draft) draft.preview = null;
    refresh("[data-port-form] select");
  });
})();
