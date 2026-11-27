(function () {
  "use strict";

  const { t, ui } = window.opstendLocale;
  const rules = window.opstendNetworkRules;
  const date = Object.fromEntries([["de", "de-DE"], ["en", "en-GB"]].map(([id, locale]) => [id,
    new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Berlin" }),
  ]));
  const effectLabel = (effect) => effect === "allow" ? t("Erlauben", "Allow") : t("Blockieren", "Block");
  const kindLabel = (kind) => kind === "firewall" ? "Firewall" : t("Switch-ACL", "Switch ACL");
  const ruleName = (rule) => t(rule.name, rule.nameEn);
  const evidenceCopy = new Map([
    ["Verbindungsprüfung", { type: "Connectivity check", detail: "The sample probe from Medien reached Pi-NAS on TCP 2049." }],
    ["Historische Verbindungsprüfung", { type: "Historical connectivity check", detail: "The sample probe used an earlier rule revision. A new check is pending." }],
    ["Entwurf", { type: "Draft", detail: "A new observation or connectivity check is pending for the edited path." }],
    ["Unbekannt", { type: "Unknown" }],
  ]);
  let page = null;
  let draft = null;
  let saving = false;

  function formatTime(value) {
    const instant = new Date(value);
    return value && Number.isFinite(instant.getTime()) ? date[ui()].format(instant) : "";
  }

  function findAsset(state, id) {
    return [...state.inventory.services, ...state.inventory.devices, ...state.inventory.hosts].find((item) => item.id === id);
  }

  function network(state, id) {
    return state.inventory.networks.find((item) => item.id === id);
  }

  function endpointName(state, assetId, networkId) {
    return findAsset(state, assetId)?.name || network(state, networkId)?.name || t("Offen", "Unknown");
  }

  function ruleTarget(state, rule, label) {
    return `<button type="button" class="text-button" data-view="network-rule" data-rule-id="${state.escape(rule.id)}">${state.escape(label || ruleName(rule))}</button>`;
  }

  function section(state, filter = {}) {
    const items = rules.list(state, filter);
    if (!items.length && Object.keys(filter).length) return "";
    const title = t("Firewall und ACL", "Firewall and ACLs");
    return `<section class="${filter.linkId ? "topology-related" : "panel"}" aria-label="${title}">
      ${filter.linkId ? `<h3>${title}</h3>` : `<div class="panel-head"><h2>${title}</h2></div>`}
      ${items.length ? `<ul class="feed" role="list">${items.map((rule) => {
        const source = endpointName(state, rule.sourceId, rule.sourceNetworkId);
        const target = endpointName(state, rule.targetId, rule.targetNetworkId);
        return `<li><div>${ruleTarget(state, rule)}
          ${state.badge(effectLabel(rule.effect), rule.effect === "block" ? "warn" : "good")}
          ${rule.pending ? state.badge(t("Freigabe offen", "Pending approval"), "warn") : ""}
          <p>${state.escape(source)} → ${state.escape(target)} · ${state.escape(rule.protocol)} ${state.escape(rule.port)} · ${kindLabel(rule.kind)}
            ${rule.editable ? "" : ` · ${t("Lesend", "Read-only")}`}</p></div></li>`;
      }).join("")}</ul>` : `<p class="panel-pad compact">${t("Keine Regeln im gewählten Bereich.", "No rules in the selected scope.")}</p>`}
    </section>`;
  }

  function portalButton(state, view, label, attributes = "") {
    return `<button type="button" class="text-button" data-view="${view}" ${attributes}>${state.escape(label)}</button>`;
  }

  function endpoints(state, assetId, networkId) {
    const asset = findAsset(state, assetId);
    const value = network(state, networkId);
    const name = asset ? state.escape(asset.name) : "";
    const networkLink = value ? portalButton(state, "network-detail", value.name, `data-network-id="${state.escape(value.id)}"`) : "";
    const assetLink = asset?.host ? portalButton(state, "service", asset.name,
      `data-service-id="${state.escape(asset.id)}" data-host="${state.escape(asset.host)}"`) : name;
    return [assetLink, networkLink].filter(Boolean).join(" · ") || t("Offen", "Unknown");
  }

  function evidence(state, rule) {
    const link = state.inventory.links.find(({ id }) => id === rule.linkId);
    const report = link && window.opstendDemo.linkEvidence(link);
    const copy = evidenceCopy.get(report?.type);
    const source = report?.source === "OpsTend-Prüfpunkt · Beispieldaten"
      ? t(report.source, "OpsTend probe · Sample data") : report?.source;
    return `<section class="panel" aria-label="${t("Verbindungsbeleg", "Connectivity evidence")}">
      <div class="panel-head"><h2>${t("Verbindungsbeleg", "Connectivity evidence")}</h2></div>
      <div class="panel-pad">
        ${report ? `<dl class="info-list">
          <div><dt>${t("Belegart", "Evidence type")}</dt><dd>${state.escape(t(report.type, copy?.type || report.type))}</dd></div>
          <div><dt>${t("Quelle", "Source")}</dt><dd>${state.escape(source)}</dd></div>
          ${report.observedAt ? `<div><dt>${t("Zeitpunkt", "Time")}</dt><dd><time datetime="${state.escape(report.observedAt)}">${state.escape(formatTime(report.observedAt))}</time></dd></div>` : ""}
        </dl><p class="compact adapter-review-context">${state.escape(t(report.detail, copy?.detail || report.detail))}</p>
          <div class="service-tools">${portalButton(state, "topology", t("Pfad in Topologie", "Path in topology"),
            `data-layer="${state.escape(link.layer)}" data-topology-focus="${state.escape(link.id)}"`)}</div>`
        : `<p class="compact">${t("Für diese Regel ist keine Verbindungsprüfung erfasst.", "There is no connectivity check recorded for this rule.")}</p>`}
      </div>
    </section>`;
  }

  function currentRule(state, rule) {
    const device = findAsset(state, rule.deviceId);
    return `<section class="panel" aria-label="${t("Konfigurationswirkung", "Configured effect")}">
      <div class="panel-head"><div><h2>${t("Konfigurationswirkung", "Configured effect")}</h2>
        <p>${kindLabel(rule.kind)} · ${t("Beispielkonfiguration", "Sample configuration")}</p></div>
        ${state.badge(effectLabel(rule.effect), rule.effect === "block" ? "warn" : "good")}</div>
      <div class="panel-pad"><dl class="info-list">
        <div><dt>${t("Zuständiges Gerät", "Enforcing device")}</dt><dd>${state.escape(device?.name || t("Offen", "Unknown"))}</dd></div>
        <div><dt>${t("Quelle", "Source")}</dt><dd>${endpoints(state, rule.sourceId, rule.sourceNetworkId)}</dd></div>
        <div><dt>${t("Ziel", "Destination")}</dt><dd>${endpoints(state, rule.targetId, rule.targetNetworkId)}</dd></div>
        <div><dt>${t("Verkehr", "Traffic")}</dt><dd>${state.escape(rule.protocol)} ${state.escape(rule.port)}</dd></div>
        <div><dt>Revision</dt><dd>${state.escape(rule.revision)}</dd></div>
      </dl></div>
    </section>`;
  }

  function pendingChange(state, pending) {
    return `<div class="panel-pad">
      <p class="adapter-review-context">${t("Zur Freigabe vorgemerkt", "Pending approval")} · ${effectLabel(pending.before)} → ${effectLabel(pending.after)}</p>
      <div class="service-tools">${portalButton(state, "changes", t("Auftrag öffnen", "Open job"),
        `id="network-rule-pending-job" data-job="${state.escape(pending.id)}" data-host="${state.escape(pending.host ?? "")}"`)}</div>
    </div>`;
  }

  function editForm(rule, previous) {
    const selected = previous?.after || rule.effect;
    return `<form class="panel-pad" data-network-rule-form>
      <div class="object-setting-fields">
        <label>${t("Wirkung", "Effect")}<select name="effect" id="network-rule-effect">
          ${["allow", "block"].map((effect) => `<option value="${effect}" ${selected === effect ? "selected" : ""}>${effectLabel(effect)}</option>`).join("")}
        </select></label>
      </div>
      <div class="service-tools"><button type="submit" class="button primary">${t("Änderung prüfen", "Preview change")}</button></div>
      <p id="network-rule-result" role="status"></p>
    </form>`;
  }

  function reviewForm(state, rule, preview) {
    const stale = preview.revision !== rule.revision;
    return `<form class="panel-pad" data-network-rule-confirm>
      <h3 id="network-rule-review" tabindex="-1">${t("Regeländerung prüfen", "Review rule change")}</h3>
      <p class="compact adapter-review-context">${t("Ausgangsrevision", "Base revision")} ${state.escape(preview.revision)}</p>
      <dl class="info-list">
        <div><dt>${t("Bisher", "Current")}</dt><dd>${effectLabel(preview.before)}</dd></div>
        <div><dt>${t("Vorgeschlagen", "Proposed")}</dt><dd>${effectLabel(preview.after)}</dd></div>
      </dl>
      <p class="compact adapter-review-context">${t("Die Freigabe erfolgt im Auftrag. Danach benötigt der betroffene Pfad eine erneute Verbindungsprüfung.", "Approve in the job. The affected path then needs a new connectivity check.")}</p>
      <div class="service-tools">
        ${stale ? "" : `<button type="submit" class="button primary" ${saving ? "disabled" : ""}>${t("Zur Freigabe vormerken", "Queue for approval")}</button>`}
        <button type="button" class="button" data-network-rule-edit>${stale ? t("Mit aktueller Revision bearbeiten", "Edit against current revision") : t("Weiter bearbeiten", "Continue editing")}</button>
        <button type="button" class="text-button" data-network-rule-discard>${t("Verwerfen", "Discard")}</button>
      </div>
      <p id="network-rule-result" role="status">${stale ? t("Die Ausgangsrevision wurde geändert. Prüfe die Wirkung erneut.", "The base revision changed. Preview the effect again.") : ""}</p>
    </form>`;
  }

  window.opstendViews["network-rule"] = (state) => {
    const rule = rules.get(state, state.ruleId);
    page = rule && { state, rule };
    if (!rule) return `<header class="page-intro"><h1>${t("Netzwerkregel", "Network rule")}</h1>
      <p>${t("Keine Regel zu dieser Auswahl.", "No rule matches this selection.")}</p></header>
      ${portalButton(state, "network", t("Zum Netzwerk", "Back to network"))}`;
    const active = draft?.id === rule.id && draft.host === state.host ? draft : null;
    return `<header class="page-intro split" data-network-rule-page="${state.escape(rule.id)}" data-network-rule-host="${state.escape(state.host)}"><div><p class="eyebrow">${t("Netzwerk", "Network")} / ${kindLabel(rule.kind)}</p>
      <h1>${state.escape(ruleName(rule))}</h1></div>
      <div class="service-tools">
        ${portalButton(state, "network", t("Zum Netzwerk", "Back to network"))}
        ${portalButton(state, "events", t("Im Protokoll öffnen", "Open event log"), `data-event-subject="rule:${state.escape(rule.id)}"`)}
      </div></header>
      <div class="object-overview">${currentRule(state, rule)}${evidence(state, rule)}</div>
      <section class="panel object-settings" aria-label="${t("Regeländerung", "Rule change")}">
        <div class="panel-head"><h2>${t("Regeländerung", "Rule change")}</h2></div>
        ${rule.pending ? pendingChange(state, rule.pending)
          : !rule.editable ? `<p class="panel-pad compact">${t("Lesend · Für diese Switch-ACL steht in der Demo nur der Konfigurationsbeleg bereit.", "Read-only · This demo provides configuration evidence for this switch ACL.")}</p>`
            : active?.preview ? reviewForm(state, rule, active) : editForm(rule, active)}
      </section>`;
  };

  function refresh(focus) {
    window.dispatchEvent(new CustomEvent("opstend:inventory-changed"));
    document.getElementById(focus)?.focus();
  }

  function setMessage(value) {
    const error = document.getElementById("network-rule-result");
    if (error) error.textContent = value;
  }

  document.addEventListener("change", (event) => {
    if (event.target.id !== "network-rule-effect" || !page) return;
    const { state, rule } = page;
    draft = { id: rule.id, host: state.host, after: event.target.value, preview: false };
  });

  document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!form.matches("[data-network-rule-form], [data-network-rule-confirm]") || !page) return;
    event.preventDefault();
    const { state, rule } = page;
    if (form.hasAttribute("data-network-rule-form")) {
      const after = new FormData(form).get("effect");
      const result = rules.preview(state, rule.id, after, rule.revision);
      if (!result.ok) return setMessage(t(result.error, result.errorEn || result.error));
      if (result.before === result.after) return setMessage(t("Wähle eine andere Wirkung.", "Choose a different effect."));
      draft = { id: rule.id, host: state.host, revision: rule.revision, before: result.before, after: result.after, preview: true };
      refresh("network-rule-review");
      return;
    }
    if (saving || draft?.id !== rule.id || draft.host !== state.host) return;
    const submitted = draft;
    saving = true;
    form.querySelector("button[type=submit]").disabled = true;
    let result;
    const fallback = t("Die Änderung konnte nicht gespeichert werden.", "Could not save the change.");
    try { result = await rules.queue(state, rule.id, submitted.after, submitted.revision); }
    catch { result = { ok: false, error: fallback }; }
    finally { saving = false; }
    if (result.ok && draft === submitted) draft = null;
    const displayed = document.querySelector("[data-network-rule-page]");
    if (displayed?.dataset.networkRulePage !== rule.id || displayed.dataset.networkRuleHost !== state.host) return;
    if (result.ok) {
      document.getElementById("network-rule-pending-job")?.focus();
    } else {
      refresh("network-rule-review");
      setMessage(t(result.error || fallback, result.errorEn || result.error || fallback));
    }
  });

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-network-rule-edit], [data-network-rule-discard]");
    if (!button || saving || !draft) return;
    if (button.hasAttribute("data-network-rule-discard")) draft = null;
    else draft.preview = false;
    refresh("network-rule-effect");
  });

  window.opstendNetworkRuleUi = { section };
})();
