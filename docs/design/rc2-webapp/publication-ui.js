(function () {
  "use strict";

  const { t, ui } = window.opstendLocale;
  const tones = { draft: "warn", approved: "active", applied: "active", verified: "good", failed: "danger" };
  const date = Object.fromEntries([["de", "de-DE"], ["en", "en-GB"]].map(([id, locale]) => [id,
    new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Berlin" }),
  ]));
  const title = () => t("HTTPS-Veröffentlichungen", "HTTPS publications");
  const name = (publication) => t(publication.label, publication.labelEn);

  function status(state, publication) {
    return publication.stale ? state.badge(t("Beleg überholt", "Check outdated"), "warn")
      : state.badge(t(publication.stageLabel, publication.stageLabelEn), tones[publication.stage] || "");
  }

  function isHistorical(publication) {
    return publication.probe?.stale || publication.stale;
  }

  function probeLabel(publication) {
    if (["rejected", "withdrawn"].includes(publication.stage)) return t("Frühere Schritte im Auftragsverlauf", "Earlier steps in job history");
    if (!publication.probe) return t("Externer Prüfbeleg offen", "External evidence pending");
    if (isHistorical(publication)) return t("Historischer Prüfbeleg", "Historical check evidence");
    return publication.probe.result === "pass" ? t("Simulierter Abruf erfolgreich", "Simulated request passed")
      : t("Simulierter Abruf fehlgeschlagen", "Simulated request failed");
  }

  function address(state, publication, withScheme = false) {
    const domain = publication.domain.split(".").map(state.escape).join(".<wbr>");
    return `<span class="mono">${withScheme ? "https://<wbr>" : ""}${domain}</span>`;
  }

  function publicationButton(state, publication) {
    return `<button type="button" class="text-button" data-view="access-detail" data-publication-id="${state.escape(publication.id)}">${state.escape(name(publication))}</button>`;
  }

  function section(state, filters = {}) {
    const { serviceId, linkId } = filters;
    const items = window.opstendPublications.list(state).filter((publication) =>
      (!serviceId || publication.serviceId === serviceId || publication.proxyId === serviceId)
      && (!linkId || publication.linkId === linkId || publication.tunnelId === linkId));
    if (!items.length && (serviceId || linkId)) return "";
    const anchor = serviceId || linkId ? "" : ' id="network-publications" tabindex="-1"';
    const heading = linkId ? `<h3>${title()}</h3>` : `<div class="panel-head"><h2>${title()}</h2></div>`;
    return `<section class="${linkId ? "topology-related" : "panel"}"${anchor} aria-label="${title()}">
      ${heading}
      ${items.length ? `<ul class="${linkId ? "" : "feed"}" role="list">${items.map((publication) => `<li><div>
        <div class="service-tools">${publicationButton(state, publication)}${status(state, publication)}</div>
        <p>${address(state, publication)} · ${probeLabel(publication)}</p>
      </div></li>`).join("")}</ul>`
        : `<p class="panel-pad compact">${t("Keine Veröffentlichungen im gewählten Bereich.", "No publications in the selected scope.")}</p>`}
    </section>`;
  }

  function serviceLink(state, id, host) {
    const service = state.inventory.services.find((item) => item.id === id);
    if (!service) return t("Dienstbeleg offen", "Service evidence pending");
    const label = state.escape(`${service.name} · ${host}`);
    return service.host === host ? `<button type="button" class="text-button" data-view="service" data-service-id="${state.escape(id)}" data-host="${state.escape(host)}">${label}</button>` : label;
  }

  function mapButton(state, linkId, label, host = state.host) {
    if (!state.inventory.links.some((link) => link.id === linkId)) return "";
    return `<button type="button" class="text-button" data-view="topology" data-host="${state.escape(host ?? "")}" data-layer="access" data-topology-focus="${state.escape(linkId)}">${state.escape(label)}</button>`;
  }

  function routePanel(state, publication) {
    const heading = t("Veröffentlichungspfad", "Publication path");
    const tunnel = state.inventory.links.find((link) => link.id === publication.tunnelId);
    const tunnelLabel = tunnel ? window.opstendDemo.linkLabel(tunnel) : "";
    const tunnelLink = tunnel ? mapButton(state, publication.tunnelId, tunnelLabel, publication.proxyHost)
      : t("Tunnelbeleg offen", "Tunnel evidence pending");
    const blocked = publication.error ? state.escape(t(publication.error, publication.errorEn || publication.error)) : "";
    return `<section class="panel" aria-label="${heading}">
      <div class="panel-head"><h2>${heading}</h2>${status(state, publication)}</div>
      <div class="panel-pad"><dl class="info-list">
        <div><dt>${t("Externe Adresse", "External address")}</dt><dd>${address(state, publication, true)}</dd></div>
        <div><dt>HTTPS-Proxy</dt><dd>${serviceLink(state, publication.proxyId, publication.proxyHost)}</dd></div>
        <div><dt>VPN-Tunnel</dt><dd>${tunnelLink}</dd></div>
        <div><dt>${t("Zieldienst", "Target service")}</dt><dd>${serviceLink(state, publication.serviceId, publication.targetHost)}</dd></div>
        <div><dt>${t("TLS-Zertifikat", "TLS certificate")}</dt><dd>${t("Zertifikatsbeleg offen", "Certificate evidence pending")}</dd></div>
        ${publication.jobId ? `<div><dt>${t("Revision", "Revision")}</dt><dd>${state.escape(publication.revision)}</dd></div>` : ""}
      </dl>${blocked ? `<p class="compact adapter-review-context">${blocked}</p>` : ""}</div>
    </section>`;
  }

  function probePanel(state, publication) {
    const heading = t("Externer HTTPS-Abruf", "External HTTPS request");
    const probe = publication.probe;
    const instant = probe && new Date(probe.at);
    const time = instant && Number.isFinite(instant.getTime()) ? date[ui()].format(instant) : "";
    const result = probe?.result === "pass" ? t("Simulierter Abruf erfolgreich", "Simulated request passed")
      : t("Simulierter Abruf fehlgeschlagen", "Simulated request failed");
    return `<section class="panel" aria-label="${heading}"><div class="panel-head"><h2>${heading}</h2></div>
      <div class="panel-pad">${probe ? `<dl class="info-list">
        <div><dt>${t("Ergebnis", "Result")}</dt><dd>${result}</dd></div>
        ${isHistorical(publication) ? `<div><dt>${t("Gültigkeit", "Validity")}</dt><dd>${probeLabel(publication)}</dd></div>` : ""}
        <div><dt>${t("Quelle", "Source")}</dt><dd>${t("Simulierter externer Prüfpunkt", "Simulated external probe")}</dd></div>
        ${time ? `<div><dt>${t("Zeitpunkt", "Time")}</dt><dd><time datetime="${state.escape(probe.at)}">${state.escape(time)}</time> · Europe/Berlin</dd></div>` : ""}
      </dl>` : `<p class="compact">${probeLabel(publication)}.</p>`}</div>
    </section>`;
  }

  function render(state) {
    const publication = window.opstendPublications.get(state, state.publicationId);
    const back = `<button type="button" class="text-button" data-view="network">${t("Zum Netzwerk", "Back to network")}</button>`;
    if (!publication) return `<header class="page-intro"><h1>${title()}</h1>
      <p>${t("Keine Veröffentlichung zu dieser Auswahl.", "No publication matches this selection.")}</p></header>${back}`;
    const map = mapButton(state, publication.linkId, t("Veröffentlichung in Topologie", "Publication in topology"));
    const job = publication.jobId ? `<button type="button" class="button primary" data-view="changes" data-job="${state.escape(publication.jobId)}" data-host="${state.escape(publication.proxyHost)}">${t("Auftrag öffnen", "Open job")}</button>` : "";
    return `<header class="page-intro split" data-publication-page="${state.escape(publication.id)}"><div>
      <p class="eyebrow">${t("Netzwerk", "Network")} / ${title()}</p><h1>${state.escape(name(publication))}</h1>
      <p>${t("Öffentliche Website · Demo", "Public website · Demo")}</p></div>
      <div class="service-tools">${back}${map}${job}</div>
    </header><div class="object-overview">${routePanel(state, publication)}${probePanel(state, publication)}</div>`;
  }

  window.opstendPublicationUi = { section, render };
  window.opstendViews["access-detail"] = render;
})();
