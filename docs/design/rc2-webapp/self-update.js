(function () {
  "use strict";

  const instanceIds = ["nuc-a", "host-b", "nuc-c"];
  const liveStatus = new Map();
  const running = new Set();
  const statuses = { idle: "Bereit zur Prüfung", available: "Update verfügbar", prepared: "Update vorbereitet",
    applied: "Update bestätigt", "rolled-back": "Voriger Stand wiederhergestellt" };
  const changeLabels = { absorbed: "In der neuen Version enthalten", portable: "Direkt übernehmbar", conflict: "Klärung erforderlich" };
  const events = {
    policy: "Update-Richtlinie gespeichert", check: "Release geprüft", prepare: "Patchstand gesichert", suggest: "Zorec-Vorschlag erstellt",
    approve: "Patch-Portierung freigegeben", apply: "Update übernommen", window: "Wartungsfenster verarbeitet", rollback: "Voriges Release wiederhergestellt",
    cancel: "Update abgebrochen",
  };
  const clock = new Intl.DateTimeFormat("de-DE", { dateStyle: "short", timeStyle: "medium" });

  function time(at) {
    const date = new Date(at);
    return Number.isNaN(date.getTime()) ? "Demo" : clock.format(date);
  }

  function button(action, label, { primary = false, disabled = false, patch = "" } = {}) {
    return `<button type="button" class="button${primary ? " primary" : ""}" data-own-update-action="${action}"
      ${patch ? `data-own-patch="${patch}"` : ""} ${disabled ? "disabled" : ""}>${label}</button>`;
  }

  function patchRows(candidate, state, pending) {
    const { escape, badge } = state;
    return `<div class="table-wrap" tabindex="0" aria-label="Vergleich lokaler Patches"><table class="data-table own-update-table">
      <thead><tr><th scope="col">Lokaler Patch</th><th scope="col">Bisherige Basis</th><th scope="col">Eigener Wert</th><th scope="col">Neue Basis</th><th scope="col">Ergebnis</th></tr></thead>
      <tbody>${candidate.items.map((patch) => `<tr><th scope="row">${escape(patch.label)}</th><td data-label="Bisherige Basis"><code>${escape(patch.base)}</code></td>
        <td data-label="Eigener Wert"><code>${escape(patch.local)}</code></td><td data-label="Neue Basis"><code>${escape(patch.upstream)}</code></td><td data-label="Ergebnis">
        ${badge(patch.approved ? "Portierung freigegeben" : changeLabels[patch.kind], patch.kind === "conflict" && !patch.approved ? "warn" : "good")}
        ${patch.proposed !== null && patch.proposed !== undefined ? `<small>Zorec-Vorschlag · <code>${escape(patch.proposed)}</code></small>` : ""}
        ${patch.kind !== "conflict" || patch.approved ? "" : patch.proposed !== null && patch.proposed !== undefined
          ? button("approve", "Portierung freigeben", { patch: escape(patch.id), disabled: pending })
          : button("suggest", "Zorec-Vorschlag erstellen", { patch: escape(patch.id), disabled: pending })}</td></tr>`).join("")}</tbody>
    </table></div>`;
  }

  function presentInstances(state) {
    return instanceIds.filter((id) => state.inventory.hosts.some((host) => host.id === id));
  }

  function instanceLinks(state, host, instances) {
    if (!instances.length) return "";
    return `<div class="service-tools own-update-instances" aria-label="OpsTend-Installationen">${instances.map((id) =>
      `<button type="button" class="button${id === host ? " primary" : ""}" aria-pressed="${id === host}"
        data-view="settings" data-settings-tab="updates" data-host="${id}">${state.escape(id)}</button>`).join("")}</div>`;
  }

  function render(state) {
    const instances = presentInstances(state);
    const host = state.host || instances[0];
    const current = instances.includes(host) && window.opstendSelfUpdate.read(host);
    if (!current) return `<section class="panel" aria-label="OpsTend-Updates"><div class="panel-head"><h2>OpsTend-Updates</h2></div>
      <p class="panel-pad compact">In diesem Geltungsbereich ist keine OpsTend-Installation erfasst.</p>${instanceLinks(state, host, instances)}</section>`;
    const { escape, badge } = state;
    const { revision, phase, candidate, rollback, history, policy, version } = current;
    const pending = running.has(host);
    const prepared = phase === "prepared" && candidate;
    const openConflict = prepared && candidate.items.some((patch) => patch.kind === "conflict" && !patch.approved);
    const canRollback = phase === "applied" && rollback;
    const log = history.slice(0, 6);
    return `<div class="own-update" data-own-update="${escape(host)}" data-own-revision="${revision}">
      <section class="panel" aria-labelledby="own-update-title">
        <div class="panel-head"><div><h2 id="own-update-title" tabindex="-1">OpsTend-Updates</h2><p>Installation ${escape(host)} · Browser-Demo</p></div>
          ${badge(statuses[phase], phase === "available" || openConflict ? "warn" : "good")}</div>
        ${instanceLinks(state, host, instances)}
        <dl class="own-update-facts"><div><dt>Installierter Stand</dt><dd>${escape(version)}</dd></div>
          <div><dt>Quelle</dt><dd>OpsTend-Repository · Release-Kanal</dd></div>
          <div><dt>Eigene Patches</dt><dd>${current.patches.length}</dd></div></dl>
        <details class="own-update-active"><summary>Aktive eigene Patches ansehen</summary>
          <dl>${current.patches.map((patch) => `<div><dt>${escape(patch.label)}</dt><dd><code>${escape(patch.value)}</code></dd></div>`).join("")}</dl></details>
        <form class="manage-form" id="own-update-policy"><label for="own-update-mode">Update-Richtlinie</label>
          <select id="own-update-mode" name="policy" ${pending ? "disabled" : ""}>
            <option value="manual" ${policy !== "automatic" ? "selected" : ""}>Nur benachrichtigen</option>
            <option value="automatic" ${policy === "automatic" ? "selected" : ""}>Automatisch im Wartungsfenster</option>
          </select>
          <button class="button" type="submit" ${pending ? "disabled" : ""}>Richtlinie speichern</button>
        </form>
        <div class="service-tools own-update-actions">
          ${!prepared ? button("check", "Nach Release suchen", { disabled: pending }) : ""}
          ${phase === "available" ? button("prepare", "Patches sichern und abgleichen", { primary: true, disabled: pending }) : ""}
          ${canRollback ? button("rollback", "Vorigen Stand wiederherstellen", { disabled: pending }) : ""}
          ${log.length ? `<button type="button" class="text-button" data-view="changes" data-host="${escape(host)}" data-job="own-update-${escape(host)}">Auftrag ansehen</button>` : ""}
        </div>
        <p class="compact own-update-feedback" role="status">${escape(liveStatus.get(host) || "")}</p>
      </section>
      ${prepared ? `<section class="panel" aria-labelledby="own-update-compare-title">
        <div class="panel-head"><div><h2 id="own-update-compare-title">Patch-Abgleich</h2>
          <p>${escape(candidate.snapshot.version)} → ${escape(candidate.version)} · Ausgangsstand im Browser gesichert</p></div></div>
        ${patchRows(candidate, state, pending)}
        <div class="own-update-actions service-tools">
          ${button("apply", "Kandidat in der Demo übernehmen", { primary: true, disabled: pending || openConflict })}
          ${policy === "automatic" ? button("window", "Wartungsfenster simulieren", { disabled: pending }) : ""}
          ${button("cancel", "Vorbereitung abbrechen", { disabled: pending })}
        </div>
        ${openConflict ? '<p class="compact own-update-feedback">Der Konflikt braucht einen geprüften Portierungsvorschlag und deine Freigabe.</p>' : ""}
      </section>` : ""}
      ${log.length ? `<section class="panel" aria-label="Eigenupdate-Verlauf"><div class="panel-head"><h2>Verlauf</h2></div>
        <ul class="feed activity-feed">${log.map((entry) => `<li><time>${time(entry.at)}</time><div><strong>${escape(events[entry.action] || entry.action)}</strong><p>${escape(entry.detail)}</p></div></li>`).join("")}</ul>
      </section>` : ""}
    </div>`;
  }

  function jobs(state) {
    return presentInstances(state).filter((id) => !state.host || id === state.host).flatMap((host) => {
      const current = window.opstendSelfUpdate.read(host);
      const last = current?.history[0];
      if (!last) return [];
      const waiting = current.phase === "available" || current.phase === "prepared";
      const title = "OpsTend-Eigenupdate auf " + host;
      const attention = waiting ? { kind: "decision", title, status: statuses[current.phase],
        impact: current.phase === "available" ? "Das Beispielrelease kann für den Patch-Abgleich vorbereitet werden."
          : "Prüfe die Zuordnung der eigenen Patches und die Update-Freigabe.", action: "Update ansehen" } : null;
      return [{ id: "own-update-" + host, selfUpdate: true, host, title, type: "OpsTend-Eigenupdate", time: time(last.at), at: last.at,
        status: statuses[current.phase], attention, tone: waiting ? "warn" : "success", target: host, actor: "OpsTend · Demo",
        context: "Das Eigenupdate gehört zu dieser Demo-Installation. Die vorherige Version und die eigenen Patches werden vor dem Wechsel erfasst.",
        outcome: statuses[current.phase], verification: "Installierter Demo-Stand · " + current.version,
        events: current.history.toReversed().map((entry) => [time(entry.at), events[entry.action] || entry.action, entry.detail, entry.at]) }];
    });
  }

  async function update(root, action, payload) {
    const host = root.dataset.ownUpdate;
    if (running.has(host)) return;
    running.add(host);
    for (const control of root.querySelectorAll("[data-own-update-action], #own-update-policy :is(button,select)")) control.disabled = true;
    try {
      const result = await window.opstendSelfUpdate.mutate(host, Number(root.dataset.ownRevision), action, payload);
      liveStatus.set(host, result.ok ? result.state.history[0]?.detail || "Gespeichert." : result.error);
    } catch {
      liveStatus.set(host, "Der Demo-Stand konnte gerade nicht gespeichert werden.");
    } finally {
      running.delete(host);
      if (!root.isConnected && !document.querySelector(`[data-own-update="${CSS.escape(host)}"]`)) return;
      window.dispatchEvent(new CustomEvent("opstend:inventory-changed"));
      const next = document.querySelector(`[data-own-update="${CSS.escape(host)}"] [data-own-update-action="${action}"]:enabled`);
      (next || document.getElementById("own-update-title"))?.focus({ preventScroll: true });
    }
  }

  document.addEventListener("click", (event) => {
    const control = event.target.closest("[data-own-update-action]");
    if (control) void update(control.closest("[data-own-update]"), control.dataset.ownUpdateAction, { patchId: control.dataset.ownPatch });
  });
  document.addEventListener("submit", (event) => {
    if (event.target.id !== "own-update-policy") return;
    event.preventDefault();
    void update(event.target.closest("[data-own-update]"), "policy", { policy: new FormData(event.target).get("policy") });
  });
  window.addEventListener("opstend:self-update-changed", (event) => {
    if (!running.has(event.detail.host)) window.dispatchEvent(new Event("opstend:inventory-changed"));
  });

  window.opstendSelfUpdateView = { render, jobs };
})();
