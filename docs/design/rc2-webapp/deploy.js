(function () {
  "use strict";

  const examples = [
    { name: "Sensorik API", url: "https://git.example/werkstatt/sensorik-api.git" },
    { name: "Sensorik Web", url: "https://git.example/werkstatt/sensorik-web.git" },
    { name: "Statusseite", url: "https://git.example/werkstatt/statusseite.git" },
  ];
  const blank = () => ({
    repos: new Set(), custom: [], name: "", host: "", network: "VLAN 20", domain: "",
    ip: "", secret: "", visibility: "intern", storage: "persistente Daten",
    reference: "", updates: false, adapterText: "", approved: false,
    adapterValues: null, adapterVersion: "",
  });
  let draft = blank();
  let stage = "sources";
  let mode = "guided";
  let opened = false;
  let screen = "chat";
  let result = null;
  let problem = "";
  let sourceUrl = "";
  const chats = window.opstendZorecChats;
  const knowledge = window.opstendZorecKnowledge;
  const inspections = window.opstendZorecInspections;
  let sidePanel = "";
  let panelOpener = "";
  let activityTurn = null;
  let state;

  const shellNames = { "admin-read": "Admin Lesen", "admin-edit": "Admin Edit", report: "Bericht" };
  const englishShellNames = { "admin-read": "Admin Read", "admin-edit": "Admin Edit", report: "Report" };
  const editLabels = { draft: "Entwürfe", operate: "Freigegebene Aktionen", full: "Vollzugriff" };
  const englishEditLabels = { draft: "Drafts", operate: "Approved actions", full: "Full access" };
  const ui = (de, en) => window.opstendLocale?.t(de, en) ?? de;
  const responseText = (language) => (de, en) => language === "en" ? en : de;
  const shellName = (shell) => ui(shellNames[shell], englishShellNames[shell]);
  const targetLabel = (target) => ui(target.label, target.englishLabel || target.label);
  const englishFacts = {
    "Gesund": "Healthy", "Wird geprüft": "Check in progress", "Health offen": "Health check pending", "Warnung": "Warning",
    "Ausgefallen": "Offline", "Gestoppt": "Stopped", "Stillgelegt": "Retired", "Container · Podman": "Podman container",
    "Sensorik antwortete nicht": "Sensorik did not respond", "Zorec prüft den Wiederanlauf": "Zorec is checking recovery",
    "Drei Healthchecks sind fehlgeschlagen. Der Dienst wurde neu gestartet.": "Three health checks failed. The service was restarted.",
    "Wiederanlauf nicht bestätigt": "Recovery has yet to be confirmed", "Zorec prüft das neue Ergebnis": "Zorec is checking the new result",
    "Die Health-Nachprüfung nach dem Neustart ist fehlgeschlagen.": "The health recheck after the restart failed.",
    "Du hast eine weitere Health-Prüfung angestoßen.": "You started another health check.",
    "Sensorik erneut prüfen": "Recheck Sensorik", "Deine Entscheidung ist gefragt": "Your decision is needed",
    "Der erlaubte Neustart wurde ausgeführt. Du kannst eine weitere Health-Prüfung anstoßen.": "The approved restart completed. You can start another health check.",
    "Medien extern erreichbar machen": "Publish Medien externally", "Deine Freigabe ist gefragt": "Your approval is needed",
    "Die HTTPS-Adresse würde Webzugriffe von außen zu Medien auf nuc-a leiten.": "The HTTPS address would forward external web traffic to Medien on nuc-a.",
    "Prüfung verfolgen": "Follow check", "Störung ansehen": "View incident", "Nachprüfung entscheiden": "Decide on recheck", "Freigabe prüfen": "Review approval",
  };
  function factText(value, reply) {
    const localized = window.opstendViews.englishJobText(value) ?? (Object.hasOwn(englishFacts, value) ? englishFacts[value] : value);
    return reply(value, localized);
  }
  const activeShell = () => screen === "report" ? "report" : chats.mode;
  const chatGroup = () => screen === "report" ? "report" : "admin";
  const currentChat = () => chats.list(chatGroup())[0];
  function chatDiagram(chat, shell) {
    const entry = chat.diagrams[shell];
    if (!entry || entry.scope !== chats.scope(shell)) return null;
    return entry.value.steps || entry.value.scope === state.host ? entry.value : null;
  }

  function keepDiagram(chat, turn, diagram) {
    const { shell, scope, language, id } = turn;
    chat.diagrams[shell] = { scope, value: { ...diagram, language } };
    turn.diagram = true;
    if (currentChat() === chat && screen === "chat" && activeShell() === shell && chatDiagram(chat, shell)
      && !sidePanel && matchMedia("(min-width: 820px)").matches && document.getElementById("zorec-dialog")?.open) {
      sidePanel = "diagram";
      panelOpener = `[data-diagram-turn="${id}"]`;
    }
  }
  const policy = () => window.opstendZorecPolicy.get();
  const adminEdit = () => screen === "chat" && activeShell() === "admin-edit" && policy()["admin-edit"].enabled;
  const stepNames = { sources: "Quellen", setup: "Einrichtung", review: "Prüfung", done: "Auftrag" };
  const escape = (value) => state.escape(value ?? "");
  const field = (name, label, value = draft[name], extra = "") =>
    `<label class="deploy-field">${label}<input name="${name}" value="${escape(value)}" ${extra}></label>`;
  const options = (items, selected) => items.map(([value, label]) =>
    `<option value="${escape(value)}" ${value === selected ? "selected" : ""}>${escape(label)}</option>`).join("");
  const select = (name, label, items) =>
    `<label class="deploy-field">${label}<select name="${name}">${options(items, draft[name])}</select></label>`;
  const repos = () => [...examples, ...draft.custom];
  const adapterSource = () => ({ repositories: [...draft.repos] });
  const selectedAdapter = () => window.opstendDemo.adapterSettings(adapterSource());

  function updateSources() {
    draft.approved = false;
    if (!selectedAdapter()) {
      draft.adapterValues = null;
      draft.adapterVersion = "";
    }
  }

  function adapterText() {
    if (draft.adapterText) return draft.adapterText;
    const dataPath = draft.storage === "zustandslos" ? "entfällt" : "/var/lib/app";
    return [
      "# Entwurf für den Dienstadapter",
      "dependencies: aus den gebundenen Repository-Quellen prüfen",
      "build: isolierter Build je Komponente",
      "data_path: " + dataPath,
      "api_path: /api",
      "health_path: /healthz",
      "updates: " + (draft.updates ? "validiert im Wartungsfenster" : "manuell freigeben"),
      "rollback: letztes geprüftes Image; Datenmigration vorher bewerten",
    ].join("\n");
  }

  function sourceStep() {
    return `<form data-deploy-submit="sources" class="deploy-form">
      <h3>Repositories für diesen Dienst</h3>
      <div class="deploy-repos">${repos().map((repo) => `
        <label class="deploy-repo"><input type="checkbox" name="repo" value="${escape(repo.url)}" ${draft.repos.has(repo.url) ? "checked" : ""}>
          <span><strong>${escape(repo.name)}</strong><small>${escape(repo.url)}</small></span></label>`).join("")}</div>
      <div class="deploy-add">${field("repo-url", "Weitere HTTPS-Quelle", sourceUrl, 'placeholder="https://git.example/gruppe/repo.git" maxlength="220"')}
        <button type="button" class="button" data-deploy-add>Hinzufügen</button></div>
      <div class="deploy-actions"><button class="button primary" type="submit">Weiter zur Einrichtung</button></div>
    </form>`;
  }

  function setupStep() {
    const inv = state.inventory;
    const adapter = selectedAdapter();
    const hosting = inv.hosts.filter((host) => !host.budgets).map((host) => [host.id, host.name + " · " + host.runtime]);
    const networks = inv.networks.map((network) => [network.name.split(" · ")[0], network.name + " (" + network.cidr + ")"]);
    const references = inv.secretRefs.map((secret) => [secret.id, secret.name]);
    const related = inv.services.filter((item) => item.host === draft.host && item.status === "Gesund").map((item) => [item.id, item.name]);
    const helper = mode === "guided"
      ? `<section class="deploy-question"><h3>Zorecs Einrichtungsvorschlag</h3>
          <p>Das Inventar listet ${escape(draft.host)} als Ziel und ${escape(inv.domains[0]?.name)} als Beispielzone. Die Keystore-Auswahl enthält Referenzen.</p>
          <div class="deploy-fields">${select("visibility", "Wer soll den Dienst erreichen?", [["intern", "Nur intern"], ["öffentlich planen", "Öffentlichen Zugang entwerfen"]])}
          ${select("storage", "Braucht der Dienst dauerhafte Daten?", [["persistente Daten", "Ja, eigener Datenpfad"], ["zustandslos", "Nein, zustandslos"]])}</div>
          <p>Die Antworten bestimmen Veröffentlichung, Datenpfad und Rückweg im Adapterentwurf.</p></section>`
      : `<section class="deploy-ide"><div><h3>Dienstadapter</h3><span class="deploy-file mono">adapter.yml</span></div>
          <label for="deployment-adapter">Build, Abhängigkeiten, Pfade und Wartung</label>
          <textarea id="deployment-adapter" class="mono" name="adapterText" rows="9" spellcheck="false">${escape(adapterText())}</textarea></section>`;
    return `<form data-deploy-submit="setup" class="deploy-form">
      <div class="tabs" role="group" aria-label="Einrichtungsweg">
        <button type="button" data-deploy-mode="guided" aria-pressed="${mode === "guided"}">Mit Zorec einrichten</button>
        <button type="button" data-deploy-mode="manual" aria-pressed="${mode === "manual"}">Manueller Editor</button>
      </div>
      <div class="deploy-fields">
        ${field("name", "Dienstname", draft.name, 'required maxlength="70"')}
        ${select("host", "Zielmaschine", hosting)}
        ${select("network", "Netzwerk", networks)}
        ${field("domain", "Domain", draft.domain, 'maxlength="120"')}
        ${field("ip", "IPv4-Adresse (optional)", draft.ip, 'maxlength="32"')}
        ${select("secret", "Keystore-Referenz", [["", "Keine"], ...references])}
        ${select("reference", "Abhängiger Dienst", [["", "Keine"], ...related])}
      </div>
      ${helper}
      ${adapter ? `<fieldset class="deploy-adapter" data-deploy-adapter-fields>
        <legend>${escape(adapter.title)} · Adapter ${escape(adapter.version)}</legend>
        <div class="object-setting-fields">${window.opstendObjectUi.adapterFields(state, adapter, draft.adapterValues ?? adapter.values)}</div>
      </fieldset>` : ""}
      <label class="deploy-check"><input name="updates" type="checkbox" ${draft.updates ? "checked" : ""}> Geprüfte Git-Updates im Wartungsfenster erlauben</label>
      <div class="deploy-actions"><button type="button" class="button" data-deploy-step="sources">Zurück</button><button class="button primary" type="submit">Entwurf prüfen</button></div>
    </form>`;
  }

  function reviewStep() {
    const adapter = draft.adapterValues && selectedAdapter();
    const showValue = window.opstendObjectUi.adapterValue;
    return `<form data-deploy-submit="review" class="deploy-form">
      <h3>${escape(draft.name)} · Deployment-Entwurf</h3>
      <dl class="info-list">
        <div><dt>Quellen</dt><dd>${[...draft.repos].map(escape).join("<br>")}</dd></div>
        <div><dt>Platzierung</dt><dd>${escape(draft.host)} · ${escape(draft.network)}</dd></div>
        <div><dt>Zugang</dt><dd>${escape(draft.domain || "Ohne Domain")} · ${escape(draft.visibility)}</dd></div>
        <div><dt>Keystore</dt><dd>${escape(draft.secret || "Keine Referenz")}</dd></div>
        <div><dt>Git-Updates</dt><dd>${draft.updates ? "Geprüft im Fenster vorgesehen" : "Manuelle Freigabe"}</dd></div>
      </dl>
      ${adapter ? `<section data-deploy-adapter-review>
        <h3>${escape(adapter.title)} · Adapter ${escape(draft.adapterVersion)}</h3>
        <dl class="info-list">${adapter.fields.map((setting) => {
          const value = draft.adapterValues[setting.id];
          const display = escape(showValue(setting, value));
          const original = value === setting.default ? "Vorgabe" : `Vorgabe ${escape(showValue(setting, setting.default))}`;
          return `<div><dt>${escape(setting.label)}</dt><dd>${display} <small>(${original})</small></dd></div>`;
        }).join("")}</dl>
      </section>` : ""}
      <details><summary>Adapterentwurf ansehen</summary><pre class="deploy-code mono">${escape(adapterText())}</pre></details>
      <p class="compact">Der Auftrag verbindet Quellen, isolierten Build, Validierung, Freigabe und Prüfung des Zielzustands.</p>
      <label class="deploy-check"><input name="approved" type="checkbox" required ${draft.approved ? "checked" : ""}> Diesen Demo-Auftrag bestätigen</label>
      <div class="deploy-actions"><button type="button" class="button" data-deploy-step="setup">Bearbeiten</button><button class="button primary" type="submit">Deployment vormerken</button></div>
    </form>`;
  }

  function chatContext() {
    const [subjectKind, subjectId] = state.view === "events" ? state.eventSubject.split(":") : [];
    const topologyTarget = state.view === "topology" ? state.topologyFocus : "";
    const service = state.inventory.services.find((item) => (state.view === "service" && item.id === state.serviceId)
      || (item.id === topologyTarget && (!state.host || item.host === state.host))
      || (subjectKind === "service" && item.id === subjectId && (!state.host || state.host === item.host)));
    const host = service?.host || state.host;
    const network = state.view === "network-detail" && state.inventory.networks.find((item) => item.id === state.networkId);
    const port = state.view === "network-port" ? window.opstendDemo.portConfiguration(state.portId, state.inventory)
      : subjectKind === "port" ? window.opstendDemo.portConfiguration(subjectId, state.inventory) : null;
    const job = state.view === "changes" && window.opstendViews.selectedJob(state);
    const publication = state.view === "access-detail" && window.opstendPublications.get(state, state.publicationId);
    const pve = state.view === "pve-inventory" && {
      detail: !!state.pveGuest,
      ...(!host || window.opstendPveInventory.referenceFor(host) ? window.opstendPveInventory.read(state.pveGuest || null) : {}),
    };
    return { service, host, job, network, port, publication, pve, topologyTarget, label: service?.name || network?.name || (port && `Port ${port.port}`)
      || (publication && ui(publication.label, publication.labelEn))
      || (pve && ui("Proxmox-Inventar", "Proxmox inventory"))
      || (job && factText(job.title, ui)) || host || ui("Ganze Flotte", "Entire fleet") };
  }

  function offeredInspection(turn) {
    if (turn?.run.status !== "done" || turn.shell === "report" || turn.questionMode === "knowledge") return null;
    const legacyFleet = !turn.host && ["Ganze Flotte", "Entire fleet"].includes(turn.context);
    const id = turn.inspectionOffer?.id || (legacyFleet ? inspections.match(turn.question) : null);
    const action = inspections.action(id);
    return action ? { ...action, host: turn.host, subject: turn.inspectionOffer?.subject || "" } : null;
  }

  function inspectionInScope(action, context) {
    return action.host === (context.host || "") && action.subject === (context.service?.id || "");
  }

  function staleInspection(dialog) {
    problem = ui("Die Auswahl hat sich geändert. Frage Zorec erneut für diesen Bereich.", "The selection changed. Ask Zorec again for this scope.");
    draw(dialog);
  }

  function actionButton(action, waiting) {
    const route = Object.entries(action.route || {}).map(([key, value]) => `data-${key}="${escape(value)}"`).join(" ");
    const attributes = action.field ? `data-chat-field="${escape(action.field.key)}" data-chat-subject="${escape(action.field.subjectId)}"
      data-chat-value="${escape(action.field.value)}" data-chat-version="${escape(action.field.expectedVersion)}" data-chat-revision="${escape(action.field.expectedRevision)}"`
      : action.console ? `data-chat-console="${escape(action.console.targetId)}" data-chat-command="${escape(action.console.command)}"`
      : action.inspection ? `data-chat-inspection="${escape(action.inspection)}" data-inspection-host="${escape(action.host)}"
        data-inspection-subject="${escape(action.subject)}"`
      : action.prepare ? 'data-dialog-action="prepare"'
      : action.wizard ? 'data-dialog-action="new"' : `${route} data-deploy-navigate`;
    return `<button type="button" class="button" ${attributes} ${action.inspection ? waiting : ""}>${escape(action.label)}</button>`;
  }

  function renderWebSources(turn) {
    if (!turn.researchStatus) return "";
    const sources = knowledge.sourceLinks(turn.sources);
    const summary = sources.length ? ui("Webquellen", "Web sources") : ui("Keine Webquellen für diese Antwort", "No web sources for this reply");
    return `<p class="chat-source-status">${summary}</p>${sources.length ? `<ul class="chat-sources" aria-label="${summary}">
      ${sources.map(({ title, url }) => `<li><a href="${escape(url)}" target="_blank" rel="noopener noreferrer">${escape(title)}</a></li>`).join("")}</ul>` : ""}`;
  }

  function answer(question, context, state, shell, reply) {
    const input = question.toLocaleLowerCase("de");
    const edit = shell === "admin-edit";
    if (/keystore|zugangsdaten|schlüssel|passw[öo]rt|credential|password/.test(input)) {
      const details = edit || policy()["admin-read"].data === "full";
      const names = details ? state.inventory.secretRefs.map((ref) => ref.name) : [];
      return {
        ruleOnly: true,
        activity: [ui("Keystore-Freigabe prüfen", "Check keystore access"), details ? ui(`${names.length} freigegebene Referenzen`, `${names.length} approved references`)
          : ui("Referenznamen sind für diesen Leseumfang gesperrt.", "Reference names are restricted in this read scope.")],
        text: details ? reply(`Freigegebene Keystore-Referenzen${names.length ? "\n" + names.join("\n") : " · keine"}`,
          `Approved keystore references${names.length ? "\n" + names.join("\n") : " · none"}`)
          : reply("Referenznamen gehören zu den erweiterten Lesedaten. Die Shell-Berechtigungen zeigen die aktuelle Freigabe.",
            "Reference names require expanded read access. Shell permissions shows the current access level."),
        actions: [{ label: ui("Shell-Berechtigungen öffnen", "Open shell permissions"), route: { view: "settings", "settings-tab": "ai" } }],
      };
    }
    if (context.service && /adapter|rollback|rückweg|version/.test(input)) {
      const demo = window.opstendDemo;
      const adapter = demo.adapterSettings(context.service);
      if (!adapter) return {
        text: reply(`Für ${context.label} ist im Beispiel kein Adapter mit Einstellungen hinterlegt.`, `The demo has no adapter with configurable settings for ${context.service.name}.`), actions: [],
        gesture: "missing-data", activity: [ui("Adapterstand lesen", "Read adapter status"), ui("Kein Adapter mit Einstellungen hinterlegt.", "No configurable adapter is registered.")],
      };
      const upgrade = demo.previewAdapterTransition(context.service, "upgrade");
      const rollback = demo.previewAdapterTransition(context.service, "rollback");
      const next = upgrade.ok ? reply(`Die Vorschau für ${upgrade.to.version} zeigt die Feldmigration.`, `The preview for ${upgrade.to.version} shows the field migration.`)
        : rollback.ok ? reply(`Die Rückweg-Vorschau zeigt die Wiederherstellung von ${rollback.to.version} und der gesicherten Werte.`, `The rollback preview shows how to restore ${rollback.to.version} and the saved values.`)
        : reply("Für diesen Stand ist im Beispiel kein Versionswechsel hinterlegt.", "The demo has no transition configured for this version.");
      return {
        activity: [ui("Adapterstand lesen", "Read adapter status"), `${context.label} · Version ${adapter.version} · Revision ${adapter.revision}`],
        text: reply(`${context.label} verwendet Adapter ${adapter.version} mit Konfigurationsrevision ${adapter.revision}. ${next}`,
          `${context.service.name} uses adapter ${adapter.version} with configuration revision ${adapter.revision}. ${next}`),
        actions: [{ label: ui("Dienst-Einstellungen öffnen", "Open service settings"), route: {
          view: "service", host: context.host, "service-id": context.service.id, "adapter-section": "true",
        } }],
      };
    }
    if (/auslastung|messwert|\bcpu\b|\bram\b|arbeitsspeicher|speicherbelegung|utilization|measurements?/.test(input)) {
      const timeline = window.opstendMonitoringData;
      const monitoring = window.opstendMonitoring;
      const host = context.host || (state.view === "monitoring" ? state.monitorHost : "");
      const metric = /\bram\b|arbeitsspeicher|memory/.test(input) ? "ram" : /speicherbelegung|datenspeicher|storage/.test(input) ? "storage"
        : /\bcpu\b/.test(input) || state.view !== "monitoring" ? "cpu" : state.monitorMetric;
      const period = state.view === "monitoring" ? state.monitorPeriod : "1h";
      const reading = host ? timeline.read(state, host, metric, period) : null;
      const detail = (language) => reading ? `${monitoring.readingNote(reading, language)} · ${monitoring.sourceLabel(reading.source, language)}`
        : monitoring.sourceSummary(state, metric, period, language);
      const language = reply("de", "en");
      return {
        ruleOnly: true,
        text: reading ? `${host} · ${monitoring.metricLabel(metric, language)} · ${monitoring.textValue(reading.latestValue, language)}\n${detail(language)}`
          : reply(`Messstand für ${period} · ${detail(language)}. Die Überwachung zeigt die Werte und Spitzen je Host.`,
            `Readings for ${period} · ${detail(language)}. Monitoring shows the readings and peaks by host.`),
        activity: [ui("Demo-Messstand lesen", "Read demo measurements"), detail()],
        actions: [{ label: ui("Überwachung öffnen", "Open monitoring"), route: { view: "monitoring", host: context.host,
          "monitor-host": host, "monitor-metric": metric, "monitor-period": period } }],
      };
    }
    if (context.job?.id === "sensorik" && /beispielwert|example value|simula|statisch|\bstatic\b|wert ändern/.test(input)) {
      const { host, id, recovery, verification } = context.job;
      const nextStep = recovery?.phase === "failed" ? reply("Im Auftrag kannst du eine erneute Nachprüfung anstoßen.", "You can start a new recheck from the job.")
        : recovery?.phase === "pending" ? reply("Im Auftrag kannst du das Health-Ergebnis simulieren.", "You can simulate the health result in the job.")
          : reply("Der Auftrag zeigt das protokollierte Ergebnis.", "The job shows the recorded result.");
      return {
        ruleOnly: true,
        text: `${reply("Der Neustart ist ein fester Beispielbeleg.", "The restart is a fixed demo event.")} ${nextStep}\n${factText(verification, reply)}.`,
        activity: [ui("Demo-Wirkung am Auftrag prüfen", "Check demo job behavior"), factText(verification, ui)],
        actions: [{ label: ui("Nachprüfung öffnen", "Open recheck"), route: { view: "changes", host, job: id } }],
      };
    }
    if (context.job && /diesen auftrag|this job|nachprüfung|wiederanlauf|recheck|recovery/.test(input)) {
      const { id, title, status, outcome, verification } = context.job;
      const probe = id === "sensorik" && /prüft|prüfschritt|what.*check/.test(input)
        ? reply("Die Nachprüfung prüft, ob Sensorik über den registrierten Health-Pfad antwortet.\n", "The recheck verifies whether Sensorik responds on its registered health endpoint.\n") : "";
      return {
        ruleOnly: true,
        text: `${probe}${factText(title, reply)} · ${factText(status, reply)}\n${factText(outcome, reply)}. ${factText(verification, reply)}.`,
        activity: [ui("Auftragsstand lesen", "Read job status"), factText(title, ui)],
        actions: [{ label: ui("Auftrag ansehen", "View job"), route: { view: "changes", host: context.host, job: id } }],
      };
    }
    if (context.service && /welchen status|what is the status/.test(input)) {
      const { id, name, kind, host, status } = context.service;
      return {
        ruleOnly: true,
        text: `${name} · ${factText(kind, reply)} ${reply("auf", "on")} ${host} · ${factText(status, reply)}`,
        activity: [ui("Dienststand lesen", "Read service status"), factText(status, ui)],
        actions: [{ label: ui("Dienst öffnen", "Open service"), route: { view: "service", host, "service-id": id } }],
      };
    }
    if (/stör|wiederanlauf|prüfung|geprüft|health|status|freigabe|entwarnung|wiederhergestellt|incidents?|approvals?|recovered/.test(input)) {
      const { host } = context;
      const service = context.service || (/sensorik/.test(input) && state.inventory.services.find((item) =>
        item.id === "sensorik" && (!host || host === item.host)));
      const recovery = window.opstendDemo.recoveryFor(service);
      if (recovery?.phase === "healthy") {
        return {
          activity: [ui("Health-Beleg lesen", "Read health evidence"), ui("Der registrierte Prüfpfad antwortet wieder.", "The registered health endpoint is responding again.")],
          text: reply("Sensorik antwortet wieder am registrierten Prüfpfad. Der simulierte Health-Beleg schließt die Störung und steht im Verlauf.",
            "Sensorik is responding again on its registered health endpoint. The simulated health result closes the incident and appears in the log."),
          gesture: "recovered",
          actions: [{ label: ui("Health-Beleg ansehen", "View health evidence"), route: { view: "changes", job: "sensorik", host: service.host } }],
        };
      }
      const open = window.opstendViews.attention({ ...state, host });
      const cases = context.job ? open.filter((job) => job.id === context.job.id) : service
        ? open.filter((job) => job.serviceId === service.id)
        : open;
      const uniqueActions = [...new Map(cases.map((job) => [job.id, job])).values()];
      const failed = cases.some((job) => job.id === "sensorik" && job.attention.kind === "decision");
      const matches = cases.length === 1 ? ui("1 offener Vorgang", "1 open case") : ui(`${cases.length} offene Vorgänge`, `${cases.length} open cases`);
      return {
        activity: [ui("Offene Vorgänge abgleichen", "Review open cases"), `${matches} · ${failed ? ui("Health-Nachprüfung fehlgeschlagen", "Health recheck failed") : ui("Quelle: Betriebsübersicht", "Source: Operations")}`],
        text: cases.length ? cases.map(({ attention }) => `${factText(attention.title, reply)}. ${factText(attention.status, reply)}. ${factText(attention.impact, reply)}`).join("\n")
          : reply(`Für ${context.label} ist im Beispiel kein offener Vorgang sichtbar.`, `The demo shows no open case for ${context.label}.`),
        gesture: failed ? "failed" : cases.some((job) => job.attention.kind === "incident") ? "verifying" : "answered",
        actions: uniqueActions.map((job) => ({
          label: factText(job.attention.action, ui),
          route: { view: "changes", job: job.id, host: context.host || job.host },
        })),
      };
    }
    if (/protokoll|\blogs?\b|verlauf/.test(input)) {
      const subject = context.service ? "service:" + context.service.id : context.port ? "port:" + context.port.id : "";
      return {
        activity: [ui("Protokollbereich bestimmen", "Identify the log scope"), subject
          ? ui("Filter auf das gewählte Objekt angewendet.", "Filter by the selected object.") : ui("Filter auf den aktuellen Geltungsbereich angewendet.", "Filter by the current scope.")],
        text: reply("Das Ereignisprotokoll zeigt ausgeführte Schritte im aktuellen Geltungsbereich. Jeder Eintrag führt zum zugehörigen Auftrag mit seiner Vorgeschichte.",
          "The event log shows completed steps in the current scope. Each entry links to the job and its timeline."),
        actions: [{ label: ui("Ereignisprotokoll öffnen", "Open event log"), route: { view: "events", host: context.host, "event-subject": subject } }],
      };
    }
    if (/netz|network|vlan|\bip\b|topologie|topology/.test(input)) {
      const host = state.hosts[context.host];
      const details = edit || policy()["admin-read"].data === "full";
      if (context.port) {
        const { current, port, id } = context.port;
        const name = state.inventory.networks.find((item) => item.id === current.nativeVlan)?.name || current.nativeVlan;
        return {
          activity: [ui("Port-Zuordnung lesen", "Read port assignment"), `Port ${port} · ${name}`],
          text: reply(`Port ${port} ist als ${current.mode === "trunk" ? "Trunk" : "Access"} mit ${name} als ungetaggtem Netz hinterlegt. Der Linkbeleg und die VLAN-Zuordnung stehen in der Portansicht.`,
            `Port ${port} is configured as ${current.mode === "trunk" ? "a trunk" : "an access port"} with ${name} as the untagged network. Open the port for link evidence and VLAN assignment.`),
          actions: [{ label: ui("Portdetails öffnen", "Open port details"), route: { view: "network-port", "port-id": id } }],
        };
      }
      const networks = state.inventory.networks.map((network) => network.name).join(", ");
      const ip = details ? ` IPv4 ${context.service?.ip || reply("offen", "unassigned")}.` : "";
      return {
        activity: [ui("Netzinventar abfragen", "Read network inventory"), context.network?.name || context.service?.network || host?.name || ui(`${state.inventory.networks.length} Netze erfasst`, `${state.inventory.networks.length} known networks`)],
        text: context.network ? reply(`${context.network.name} verwendet ${context.network.cidr}. In der Netzansicht findest du zugeordnete Hosts, Workloads und beobachtete Verbindungen.`,
          `${context.network.name} uses ${context.network.cidr}. The network view lists associated hosts, workloads and observed connections.`)
          : context.service ? reply(`${context.service.name} läuft auf ${context.host} in ${context.service.network}.${ip}`,
            `${context.service.name} runs on ${context.host} in ${context.service.network}.${ip}`)
          : host ? reply(`${host.name}${details ? ` hat die Verwaltungsadresse ${host.ip}.` : " ist im Netz erfasst."} Die Karte zeigt seine Anschlüsse.`,
            `${host.name}${details ? ` has management address ${host.ip}.` : " is registered in the inventory."} The topology shows its connections.`)
          : reply(`Im Inventar stehen ${networks}.`, `The inventory lists ${networks}.`),
        actions: [{ label: ui("In der Topologie öffnen", "Open in topology"), route: {
          view: "topology", layer: "network", host: context.host, "topology-focus": context.service?.id || context.host,
        } }],
      };
    }
    if (/vorlage|template|\bvm\b|\blxc\b|\bgast\b|\bguest\b/.test(input) && /anlegen|erstellen|vorlage|create|template/.test(input)) {
      return {
        activity: [ui("Gastanlage zuordnen", "Find guest setup"), ui("Vorlagen und Profile werden auf der Zielmaschine ausgewählt.", "Select templates and profiles on the destination host.")],
        text: reply("Bei der Gastanlage bestimmt die Zielmaschine, welche Vorlagen oder Profile angeboten werden. Die Vorschau zeigt Vorlage, Speicherziel, Netz, Zuteilung und Startverhalten.",
          "The destination host determines available guest templates and profiles. The preview shows the template, storage location, network, allocation and startup behavior."),
        actions: [{ label: ui("Gast aus Vorlage anlegen", "Create guest from template"), route: { view: "guest-create", host: context.host } }],
      };
    }
    if (/deploy|einrichten|repositor|anlegen|set up.*service/.test(input)) {
      return edit ? {
        activity: [ui("Deployment-Einstieg wählen", "Find deployment setup"), ui("Admin Edit kann einen Dienstentwurf öffnen.", "Admin Edit can open a service draft.")],
        text: reply("Wähle die Repository-Quellen, die Zielmaschine und das Netz. Zorec führt dich durch den Entwurf. Du kannst den Adapter auch direkt bearbeiten.",
          "Choose the repositories, destination host and network. Zorec guides you through the draft. You can also edit the adapter directly."),
        actions: [{ label: ui("Dienstentwurf vorbereiten", "Prepare service draft"), prepare: true }],
      } : {
        activity: [ui("Deployment-Einstieg wählen", "Find deployment setup"), ui("Zum Einrichtungsdialog weiterleiten.", "Open the setup dialog.")],
        text: reply("Der Einrichtungsdialog zeigt Quellen, Zielmaschine, Netz und die Vorschau. Dort kannst du den Entwurf prüfen und bestätigen.",
          "The setup dialog shows the sources, destination host, network and preview. You can review and confirm the draft there."),
        actions: [{ label: ui("Dienst einrichten", "Set up service"), wizard: true }],
      };
    }
    if (/werkzeug|regel|berechtigung|kannst|permissions?|privileges?|\bshell\b|what can you/.test(input)) {
      return {
        ruleOnly: true,
        activity: [ui("Shell-Profil lesen", "Read shell profile"), shellName(shell)],
        text: edit
          ? reply(`Admin Edit ist hier für ${editLabels[policy()["admin-edit"].access]} konfiguriert. Die Demo zeigt die Einrichtung und lokale Entwürfe.`,
            `Admin Edit is configured for ${englishEditLabels[policy()["admin-edit"].access].toLowerCase()}. The demo shows setup and local drafts.`)
          : reply("Admin Lesen erklärt das Inventar, Health-Belege und den Verlauf. Configuration zeigt die getrennten Shell-Berechtigungen.",
            "Admin Read can explain the inventory, health evidence and event history. Configuration shows permissions for each shell."),
        actions: [{ label: ui("Werkzeugfreigaben öffnen", "Open tool permissions"), route: { view: "settings", "settings-tab": "ai" } }],
      };
    }
    if (/inventar|inventory|host|maschine|machine|laufen|running|dienst|services?/.test(input)) {
      const services = state.inventory.services.filter((service) => !context.host || service.host === context.host);
      const examples = services.length ? " " + services.slice(0, 5).map((service) => service.name).join(", ") + "." : "";
      return {
        activity: [ui("Dienstinventar lesen", "Read service inventory"), ui(`${services.length} Instanzen im gewählten Bereich`, `${services.length} instances in scope`)],
        text: context.service ? `${context.service.name} · ${factText(context.service.kind, reply)} ${reply("auf", "on")} ${context.host} · ${factText(context.service.status, reply)}`
          : reply(`${context.label} hat ${services.length} Dienstinstanzen.${examples}`, `${context.host || "The fleet"} has ${services.length} service instances.${examples}`),
        actions: [{ label: ui("Dienste öffnen", "Open services"), route: { view: "services", host: context.host } }],
      };
    }
    return {
      text: reply("Für diese Frage gibt es in der Demo keine Antwort. Frag nach offenen Störungen, dem Netzwerk oder einem neuen Deployment.",
        "The demo has no answer to this question. Try asking about open incidents, the network or a new deployment."), actions: [],
      gesture: "missing-data", activity: [ui("Anfrage zuordnen", "Identify request"), ui("Für diese Frage ist kein Demo-Ablauf hinterlegt.", "The demo has no workflow for this question.")],
    };
  }

  function reportAnswer(state, reply) {
    const services = state.inventory.services.filter((service) => !state.host || service.host === state.host);
    const cases = window.opstendViews.attention(state);
    const counts = cases.reduce((result, job) => {
      if (job.attention.kind === "incident") result.incidents += 1;
      if (job.attention.kind === "decision") result.decisions += 1;
      return result;
    }, { incidents: 0, decisions: 0 });
    const data = window.opstendZorecPolicy.effectiveReportData();
    const health = services.filter((service) => service.status === "Gesund").length;
    let text = reply(`Demo-Lagebericht\nDienstinstanzen ${services.length} · gesund ${health}\nOffene Störungen ${counts.incidents} · Entscheidungen ${counts.decisions}`,
      `Demo status report\nService instances ${services.length} · healthy ${health}\nOpen incidents ${counts.incidents} · Decisions ${counts.decisions}`);
    if (data !== "reports") {
      const runtimes = new Map();
      for (const service of services) runtimes.set(service.kind, (runtimes.get(service.kind) || 0) + 1);
      const breakdown = [...runtimes].map(([runtime, count]) => `${runtime} ${count}`).join(" · ");
      const hosts = state.inventory.hosts.filter((host) => !state.host || host.id === state.host).length;
      text += `\n${reply("Erfasste Hosts", "Known hosts")} ${hosts}${breakdown ? "\n" + reply("Laufzeiten", "Runtimes") + " " + breakdown : ""}`;
    }
    if (data === "full") text += "\n" + services.map((service) => `${service.name} · ${factText(service.status, reply)}`).join("\n");
    return { text, actions: [], activity: [ui("Lagebericht zusammenstellen", "Compile status report"),
      ui(`${services.length} Dienstinstanzen · ${counts.incidents} offene Störungen · ${counts.decisions} Entscheidungen`,
        `${services.length} service instances · ${counts.incidents} open incidents · ${counts.decisions} decisions`)] };
  }

  function refreshChat(chat) {
    const dialog = document.getElementById("zorec-dialog");
    if (dialog?.open && screen !== "wizard" && currentChat() === chat) refreshConversation(dialog);
  }

  async function navigationAnswer(intent, question, reply, language) {
    const { target, candidates, explicit } = intent;
    if (target) return {
      ruleOnly: true,
      text: reply(`Du findest das unter ${targetLabel(target)}.`, `You can find this under ${targetLabel(target)}.`),
      activity: [ui("Ansicht aus der Navigation auswählen", "Select navigation destination"), targetLabel(target)],
      actions: [{ label: `${ui("Seite ansehen", "View page")} · ${targetLabel(target)}`, route: target.route }],
      ...(explicit ? { navigation: target } : {}),
    };

    let suggested;
    let detail = ui("Das Ziel ist in diesem Geltungsbereich nicht eindeutig.", "The destination is ambiguous in this scope.");
    if (candidates.length && window.opstendViews.demoAiProvider() !== "demo" && (await window.opstendDemoModel.status).configured) {
      const choices = candidates.map(({ id, label, description }) => ({ id, label, description }));
      const match = await window.opstendDemoModel.ask(
        `Wähle nur eine eindeutig passende Ziel-ID aus der Liste. Antworte als JSON-Objekt mit targetId oder null. Nutzerfrage: ${question}`,
        `Erlaubte Ansichten der aktuellen Oberfläche: ${JSON.stringify(choices).slice(0, 2400)}`, [], window.opstendViews.demoAiModel(), language);
      try {
        const raw = match.reply?.trim();
        const id = JSON.parse(raw?.match(/^```(?:json)?\s*\n([\s\S]*?)\n?```$/i)?.[1] || raw)?.targetId;
        suggested = candidates.find((item) => item.id === id);
      } catch {}
      if (suggested) detail = `${ui("Vorschlag", "Suggestion")} · ${targetLabel(suggested)} · cn-0001 · ${match.model}`;
    }
    const choices = suggested ? [suggested] : candidates.slice(0, 3);
    return {
      ruleOnly: true,
      text: suggested ? reply(`Meinst du ${targetLabel(suggested)}? Über den Link kannst du die Ansicht öffnen.`,
        `Did you mean ${targetLabel(suggested)}? Use the link to open that page.`)
        : choices.length ? reply("Welchen dieser Bereiche möchtest du öffnen?", "Which of these pages would you like to open?")
          : reply("Ich finde dafür in diesem Geltungsbereich keine registrierte Ansicht.", "I could not find a registered page for that in this scope."),
      activity: [ui("Navigationsziel prüfen", "Check navigation destination"), detail],
      actions: choices.map((item) => ({ label: `${ui("Seite ansehen", "View page")} · ${targetLabel(item)}`, route: item.route })),
    };
  }

  function modelContext(source, context, result) {
    const nearby = context.service ? [context.service] : source.inventory.services.filter((service) => !context.host || service.host === context.host);
    const cases = window.opstendViews.attention({ ...source, host: context.host });
    const running = cases.filter((job) => job.attention.kind === "incident" && job.tone === "active"
      && (!context.service || job.serviceId === context.service.id));
    const checks = running.map((job) => {
      const target = source.inventory.services.find((service) => service.id === job.serviceId);
      return `${target?.name || job.target} auf ${job.host} (Nachprüfung läuft)`;
    });
    const notes = [`Ansicht ${source.view} · ${context.label}`,
      `Laufende Prüfungen: ${checks.join("; ") || "keine belegt"}.`,
      `Erfasste Dienstzustände: ${nearby.slice(0, 8).map((service) => `${service.name} auf ${service.host} = ${service.status}`).join("; ") || "keine erfasst"}.`,
      `Offene Vorgänge: ${cases.slice(0, 4).map((job) => job.attention.title).join("; ") || "keine erfasst"}.`];
    if (result.gesture !== "missing-data") notes.push(result.text);
    return notes.join("\n").slice(0, 2500);
  }

  function knowledgeAnswer(request, shell, reply) {
    const denied = request.mode === "research" && !policy()[shell].internet;
    return {
      ruleOnly: denied,
      activity: request.mode === "research" ? [ui("Webquellen prüfen", "Check web sources"), denied
        ? ui("Internet-Recherche ist für diese Shell aus.", "Internet research is disabled for this shell.")
        : ui("Öffentliche Suchanfrage", "Public search query")]
        : [ui("Wissensfrage einordnen", "Identify knowledge question"), ui("Allgemeines Wissen", "General knowledge")],
      text: denied ? reply("Für diese Shell ist Internet-Recherche ausgeschaltet. Wähle Allgemeinwissen oder öffne die Recherchefreigabe.",
        "Internet research is disabled for this shell. Choose General knowledge or open the research permission.")
        : reply("Für freie Wissensfragen braucht diese Demo das lokale Modell.", "This demo uses the local model for general knowledge questions."),
      actions: [{ label: denied ? ui("Recherchefreigabe öffnen", "Open research permission") : ui("Modelleinstellungen öffnen", "Open model settings"),
        route: { view: "settings", "settings-tab": "ai" } }],
    };
  }

  function send(dialog, question, quick = false, inspection = "") {
    const text = question.trim().slice(0, 240);
    if (!text) return;
    const shell = activeShell();
    const language = window.opstendLocale?.zorec() === "en" ? "en" : "de";
    const reply = responseText(language);
    const group = chatGroup();
    const chat = currentChat();
    const scope = chats.scope(shell);
    const conversation = chat.turns;
    if (conversation.at(-1)?.run.status === "running" || (shell === "admin-edit" && !adminEdit())) return;
    const source = state;
    const report = shell === "report";
    const context = report ? { label: ui("Berichtsvorschau", "Report preview") } : chatContext();
    const questionMode = chat.questionMode || "auto";
    const systemQuestion = !report && ["auto", "system"].includes(questionMode);
    const last = conversation.at(-1);
    if (!inspection && systemQuestion && last?.shell === shell && last.scope === scope && inspections.isConfirmation(text)) {
      const offered = offeredInspection(last);
      if (offered) {
        if (!inspectionInScope(offered, context)) return staleInspection(dialog);
        inspection = offered.inspection;
      }
    }
    problem = "";
    const navigation = report || inspection ? null : window.opstendZorecNavigation.resolve(text, source);
    const existingDiagram = chatDiagram(chat, shell);
    const proposal = systemQuestion && !inspection ? inspections.resolve(text, context, source, reply) : null;
    const request = report || quick || proposal || inspection ? null : knowledge.resolve(text, source, questionMode, navigation, existingDiagram);
    if (request) Object.assign(context, { label: ui("Allgemeines Wissen", "General knowledge"), host: "" });
    const run = {
      shellLabel: shellName(shell), context: context.label, gesture: "thinking", status: "running",
      steps: [
        { state: "done", label: ui("Geltungsbereich zugeordnet", "Scope identified") },
        { state: "active", label: ui("Demo-Daten abgleichen", "Review demo data") },
        { state: "pending", label: ui("Antwort bereitstellen", "Prepare reply") },
      ],
    };
    const host = context.host || "";
    const turn = { id: (conversation.at(-1)?.id || 0) + 1, shell, scope, language, questionMode: request ? "knowledge" : "system", question: text,
      context: context.label, host, text: "", actions: [], run };
    const history = conversation.filter(entry => entry.run.status === "done" && entry.text.trim()
      && (entry.shell === shell || (shell === "admin-edit" && entry.shell === "admin-read"))
      && entry.scope === chats.scope(entry.shell) && (entry.questionMode || "system") === turn.questionMode
      && (request || (entry.context === context.label && entry.host === host))).slice(-3)
      .map((entry) => ({ question: entry.question, answer: entry.text.slice(0, 1200) }));
    conversation.push(turn);
    if (conversation.length > 24) conversation.shift();
    chats.save();
    const pending = () => chats.contains(group, chat) && conversation.includes(turn) && scope === chats.scope(shell);
    activityTurn = null;
    chat.prompt = "";
    draw(dialog, !matchMedia("(pointer: coarse)").matches);
    requestAnimationFrame(() => requestAnimationFrame(async () => {
      if (!pending()) return;
      try {
        const tool = report || request || inspection || proposal || navigation?.explicit ? null : window.opstendZorecContextTools.answer(
          text.toLocaleLowerCase("de"), context, source, shell, existingDiagram?.steps ? null : existingDiagram, reply);
        const result = report ? reportAnswer(source, reply)
          : inspection ? inspections.run(inspection, context, source, reply)
            : proposal || (request ? knowledgeAnswer(request, shell, reply)
              : tool || (navigation ? await navigationAnswer(navigation, text, reply, language) : answer(text, context, source, shell, reply)));
        if (!pending()) return;
        if (result.diagram) keepDiagram(chat, turn, result.diagram);
        const [label, detail] = result.activity;
        run.steps[1] = { state: "done", label, detail };
        const provider = window.opstendViews.demoAiProvider();
        const useModel = !report && !quick && !result.ruleOnly && provider !== "demo"
          && (provider === "local" || (await window.opstendDemoModel.status).configured);
        if (!pending()) return;
        const offer = result.actions.find(action => action.inspection);
        if (offer) turn.inspectionOffer = { id: offer.inspection, subject: context.service?.id || "" };
        turn.actions = result.actions.filter(action => !action.inspection);
        run.gesture = result.gesture || "answered";
        run.status = "done";
        if (useModel) {
          turn.pending = reply("Lokales Modell antwortet …", "The local model is responding…");
          run.gesture = "thinking";
          run.status = "running";
          run.steps.splice(2, 0, { state: "active", label: ui("Lokales Modell anfragen", "Ask local model"), detail: "cn-0001" });
          refreshChat(chat);
          const response = await window.opstendDemoModel.ask(text, request ? "" : modelContext(source, context, result),
            history, window.opstendViews.demoAiModel(), language, request || undefined);
          if (!pending()) return;
          if (request && !response.error) {
            turn.actions = [];
            turn.sources = knowledge.sourceLinks(response.sources);
            if (request.mode === "research") {
              turn.researchStatus = response.researchStatus || "unavailable";
              const count = turn.sources.length;
              run.steps[1].detail = count ? ui(`${count} öffentliche Quellen abgerufen`, `${count} public sources retrieved`)
                : ui("Keine Webquellen für diese Antwort", "No web sources for this reply");
            }
            if (request.diagram) {
              const diagram = knowledge.diagramDraft(response.diagram, existingDiagram);
              if (diagram) keepDiagram(chat, turn, diagram);
            }
          }
          run.steps[2] = response.error ? { state: "error", label: ui("Modellantwort offen", "Model reply unavailable"), detail: response.error }
            : { state: "done", label: ui("Lokale Modellantwort erhalten", "Local model reply received"), detail: `cn-0001 · ${response.model}` };
          run.gesture = response.error ? "offline" : "answered";
          run.status = response.error ? "error" : "done";
          turn.text = response.error || response.reply;
          turn.model = response.model;
        } else turn.text = result.text;
        const offeredActions = offer ? [offer, ...turn.actions] : turn.actions;
        run.steps[run.steps.length - 1] = { state: run.status === "error" ? "pending" : "done", label: ui("Antwort bereitgestellt", "Reply ready"),
          detail: offeredActions.length ? `${ui("Angeboten", "Offered")} · ${offeredActions.map((action) => action.label).join(" · ")}` : ui("Antwort im Chat verfügbar.", "Reply available in chat.") };
        if (result.navigation && source === state && currentChat() === chat
          && screen !== "wizard" && activeShell() === shell && document.getElementById("zorec-dialog")?.open) {
          const destination = result.navigation;
          const routed = !window.dispatchEvent(new CustomEvent("opstend:zorec-navigate", { detail: { id: destination.id }, cancelable: true }));
          if (routed) {
            turn.text = reply(`Ich habe ${targetLabel(destination)} geöffnet.`, `I opened ${targetLabel(destination)}.`);
            run.steps[1] = { state: "done", label: ui("Ansicht geöffnet", "Page opened"), detail: targetLabel(destination) };
          }
        }
      } catch {
        if (!pending()) return;
        turn.text = reply("Beim Auswerten deiner Anfrage ist mir ein Fehler passiert.", "I hit an error while processing your request.");
        run.status = "error";
        run.gesture = "embarrassed";
        run.steps[1] = { state: "error", label: ui("Abgleich fehlgeschlagen", "Review failed"), detail: ui("Die Demo-Daten konnten nicht ausgewertet werden.", "The demo data could not be reviewed.") };
      }
      chats.save();
      refreshChat(chat);
    }));
  }

  function shellBar() {
    const shell = activeShell();
    const current = policy()[shell];
    const internet = current.internet ? `<span class="zorec-shell-warning">${ui("Internet erlaubt · Standard aus", "Internet allowed · Off by default")}</span>` : ui("Internet aus", "Internet off");
    if (shell === "report") {
      const dataLabel = { reports: ui("Berichtsdaten", "Report data"), basic: ui("Betriebsdaten", "Operations data"), full: ui("Freigegebene Lesedaten", "Approved read data") };
      const data = window.opstendZorecPolicy.effectiveReportData();
      return `<div class="zorec-shell-bar"><p class="zorec-shell-summary" role="status">
        ${dataLabel[data]} · ${internet} · ${ui("lokale Demo-Quellen", "local demo sources")}</p></div>`;
    }
    return `<div class="zorec-shell-bar">
      <div class="zorec-shell-controls">
        <div class="tabs" role="group" aria-label="${ui("Zorec-Shell", "Zorec shell")}">
          <button type="button" data-zorec-shell="admin-read" aria-pressed="${shell === "admin-read"}">${shellName("admin-read")}</button>
          <button type="button" data-zorec-shell="admin-edit" aria-pressed="${shell === "admin-edit"}"
            ${policy()["admin-edit"].enabled ? "" : "disabled"}>Admin Edit</button>
        </div>
        <button type="button" class="text-button" data-view="settings" data-settings-tab="ai" data-deploy-navigate>${ui("Shell-Berechtigungen", "Shell permissions")}</button>
      </div>
      <p class="zorec-shell-summary" role="status">${shell === "admin-edit"
        ? `<span class="zorec-shell-warning">${ui(editLabels[current.access], englishEditLabels[current.access])} · ${ui("Standard aus", "Off by default")}</span>`
        : current.data === "full" ? ui("Alle freigegebenen Lesewerkzeuge", "All approved read tools") : ui("Inventar und Betriebsstatus", "Inventory and operations status")}
        · ${internet} · ${ui("lokale Demo-Quellen", "local demo sources")}</p>
    </div>`;
  }

  function chatMenu() {
    const older = chats.list(chatGroup()).slice(1);
    return `<details class="zorec-chat-menu" data-chat-menu="history">
      <summary class="text-button">Chats</summary>
      <div class="zorec-chat-menu-panel">
        <button type="button" class="text-button" data-chat-start>${ui("Neuer Chat", "New chat")}</button>
        ${older.length ? `<ul aria-label="${ui("Frühere Chats", "Previous chats")}">
          ${older.map(entry => `<li><button type="button" class="text-button" data-chat-restore="${entry.id}">
            ${escape(entry.turns[0]?.question.slice(0, 70) || ui("Neuer Chat", "New chat"))}
          </button></li>`).join("")}
        </ul>` : ""}
      </div>
    </details>`;
  }

  function chatStep(prompt, selected, diagram) {
    const report = screen === "report";
    const shell = activeShell();
    const chat = currentChat();
    const conversation = chat.turns;
    const waiting = conversation.at(-1)?.run.status === "running" ? "disabled" : "";
    const suggestions = report ? [] : window.opstendZorecContextTools.suggestions(state, chatContext(), shell);
    return `<div class="zorec-chat-workspace"><div class="zorec-chat">
      ${shellBar()}
      ${chats.storageError ? `<p class="deploy-error" role="status">${ui("Der Chatverlauf konnte in diesem Browser nicht gespeichert werden.", "Chat history could not be saved in this browser.")}</p>` : ""}
      <div class="zorec-transcript" role="log" aria-label="${report ? ui("Berichtsvorschau", "Report preview") : ui("Gespräch mit Zorec", "Conversation with Zorec")}">
        ${conversation.length ? conversation.map((turn) => {
          const inspection = offeredInspection(turn);
          const actions = inspection ? [inspection, ...turn.actions] : turn.actions;
          return `<div class="zorec-exchange">
          <p class="chat-user"><span class="chat-scope">${shellName(turn.shell)} · ${escape(turn.context)}</span>${escape(turn.question)}</p>
          <div class="chat-answer"><strong class="chat-author">Zorec</strong>
            <p lang="${turn.language === "en" ? "en" : "de"}">${escape(turn.text || turn.pending
              || responseText(turn.language)("Demo-Daten werden abgeglichen …", "Reviewing demo data…"))}</p>
            ${renderWebSources(turn)}
            ${turn.shell === shell && actions.length ? `<div class="chat-actions">${actions.map(action => actionButton(action, waiting)).join("")}</div>` : ""}
            <div class="zorec-turn-tools">
              <button type="button" class="text-button" data-activity-turn="${turn.id}" aria-controls="zorec-activity"
                aria-expanded="${sidePanel === "activity" && selected === turn}">${ui("Ablauf ansehen", "View activity")}</button>
              ${turn.diagram && turn.shell === shell && diagram ? `<button type="button" class="text-button" data-diagram-turn="${turn.id}"
                aria-controls="zorec-diagram" aria-expanded="${sidePanel === "diagram"}">${ui("Diagramm ansehen", "View diagram")}</button>` : ""}
            </div>
          </div></div>`;
        }).join("") : `<p class="chat-intro">${report ? ui("Frage nach einem Lagebericht.", "Ask for a status report.") : ui("Was möchtest du zum aktuellen Betrieb wissen?", "What would you like to know about current operations?")}</p>`}
      </div>
      <div class="chat-compose">
        <div class="chat-actions">
          ${report ? `<button type="button" class="button" data-chat-question="${ui("Wie ist die Betriebslage?", "What is the current operations status?")}" ${waiting}>${ui("Lagebericht", "Status report")}</button>` : `
            <button type="button" class="button" data-chat-question="${ui("Welche Störungen und Freigaben sind offen?", "Which incidents and approvals are open?")}" ${waiting}>${ui("Offene Vorgänge", "Open cases")}</button>
            <button type="button" class="button" data-chat-question="${ui("Wie ist das Netzwerk verbunden?", "How is the network connected?")}" ${waiting}>${ui("Netzwerk", "Network")}</button>
            ${adminEdit() ? `<button type="button" class="button" data-dialog-action="prepare">${ui("Dienstentwurf vorbereiten", "Prepare service draft")}</button>`
              : `<button type="button" class="button" data-dialog-action="new">${ui("Dienst einrichten", "Set up service")}</button>`}`}
        </div>
        ${suggestions.length ? `<div class="chat-actions chat-context-actions" role="group" aria-label="${ui("Auf dieser Seite", "On this page")}">
          <span>${ui("Auf dieser Seite", "On this page")}</span>${suggestions.map(([label, question]) => `<button type="button" class="button"
            data-chat-question="${escape(question)}" ${waiting}>${escape(label)}</button>`).join("")}
        </div>` : ""}
        <form data-deploy-submit="chat" class="deploy-add">
          ${report ? "" : knowledge.renderMode(chat.questionMode || "auto")}
          ${field("question", ui("Frage an Zorec", "Question for Zorec"), prompt, `required maxlength="240" placeholder="${report ? ui("Frage zum Bericht", "Question about the report") : ui("Nach einem Dienst oder Vorgang fragen", "Ask about a service or case")}"`)}
          <button class="button primary" type="submit" ${waiting}>${ui("Senden", "Send")}</button>
        </form>
      </div>
    </div>${window.opstendActivity.render(state, { open: sidePanel === "activity", run: selected?.run })}
      ${window.opstendZorecDiagram.render(state, sidePanel === "diagram" ? diagram : null)}</div>`;
  }

  function draw(dialog, focus = false) {
    const forms = { sources: sourceStep, setup: setupStep, review: reviewStep, done: () => `
      <div class="deploy-form">
        <h3>Deployment in der Demo vorgemerkt</h3>
        <p class="compact" role="status">${escape(draft.name)} erscheint im Inventar, in der Topologie und im Auftragsverlauf.</p>
        <button type="button" class="button primary" data-view="changes" data-host="${escape(draft.host)}" data-job="service-${escape(result.id)}" data-deploy-navigate>Auftrag ansehen</button>
      </div>` };
    const chat = screen !== "wizard";
    const report = screen === "report";
    const shell = activeShell();
    const chatRecord = currentChat();
    const conversation = chatRecord.turns;
    const diagram = chatDiagram(chatRecord, shell);
    if (sidePanel === "diagram" && !diagram) sidePanel = "";
    const selected = conversation.find((turn) => turn.id === activityTurn) || conversation.at(-1);
    const prompt = chat ? chatRecord.prompt || "" : "";
    const gesture = chat ? (conversation.at(-1)?.run.gesture || "listening")
      : stage === "review" ? "verifying" : stage === "done" ? "answered" : "setup";
    dialog.classList.toggle("chat-open", chat);
    dialog.classList.toggle("zorec-side-open", chat && !!sidePanel);
    dialog.dataset.shell = chat ? shell : "deployment";
    dialog.dataset.chatId = chat ? chatRecord.id : "";
    dialog.innerHTML = `<header class="deploy-heading">
      ${window.opstendMascot.render(gesture, { idle: chat })}
      <div><h2 id="deploy-title">${report ? ui("Zorec · Berichtsvorschau", "Zorec · Report preview") : chat ? "Zorec" : ui("Neuer Dienst", "New service")}</h2>
        <p>${report ? ui("Bericht · Demo", "Report · Demo") : chat ? `${escape(chatContext().label)} · Demo` : stepNames[stage]}</p></div>
      <div class="deploy-heading-actions">${chat ? `${chatMenu()}<button type="button" class="button" data-activity-toggle
        aria-controls="zorec-activity" aria-expanded="${sidePanel === "activity"}">${ui("Aktivität", "Activity")}</button>
        ${diagram ? `<button type="button" class="button" data-diagram-toggle aria-controls="zorec-diagram"
          aria-expanded="${sidePanel === "diagram"}">${ui("Diagramm", "Diagram")}</button>` : ""}`
        : '<button class="button" type="button" data-dialog-action="chat">Chat</button>'}
        <button class="button" type="button" data-dialog-action="close" aria-label="${ui("Zorec schließen", "Close Zorec")}">×</button></div>
    </header>
    ${problem ? `<p role="alert" class="deploy-error">${escape(problem)}</p>` : ""}
    ${chat ? chatStep(prompt, selected, diagram) : `<div class="deploy-body">${forms[stage]()}</div>`}`;
    const transcript = dialog.querySelector(".zorec-transcript");
    if (transcript) transcript.scrollTop = transcript.scrollHeight;
    window.opstendZorecDiagram.mount(dialog, state, chat && sidePanel === "diagram" ? diagram : null);
    if (focus) focusInput(dialog);
  }

  function refreshConversation(dialog) {
    const active = document.activeElement;
    const stableControls = ['input[name="question"]', '[data-activity-toggle]', '[data-activity-close]',
      '[data-diagram-toggle]', '[data-diagram-close]', '#zorec-diagram-title', '[data-zorec-diagram-kind]',
      '#zorec-activity-title', '[data-dialog-action="close"]', '[data-zorec-shell][aria-pressed="true"]',
      '[data-chat-menu="history"] summary', '[data-chat-menu="scope"] summary', '[data-chat-start]'];
    const focus = stableControls.find((selector) => active?.matches(selector));
    const selection = focus === stableControls[0] ? [active.selectionStart, active.selectionEnd] : null;
    const bodySelector = ".zorec-activity-body, .zorec-diagram-body";
    const top = dialog.querySelector(bodySelector)?.scrollTop || 0;
    const menuOpen = dialog.querySelector("[data-chat-menu][open]")?.dataset.chatMenu;
    const entry = active?.dataset.chatRestore || active?.dataset.questionMode;
    draw(dialog);
    const currentBody = dialog.querySelector(bodySelector);
    if (currentBody) currentBody.scrollTop = top;
    const menu = menuOpen && dialog.querySelector(`[data-chat-menu="${menuOpen}"]`);
    if (menu) menu.open = true;
    const restored = entry && menu
      ? Array.from(menu.querySelectorAll("[data-chat-restore], [data-question-mode]"))
        .find(button => (button.dataset.chatRestore || button.dataset.questionMode) === entry)
        || menu.querySelector("summary")
      : focus && dialog.querySelector(focus);
    restored?.focus({ preventScroll: true });
    if (selection) restored?.setSelectionRange(...selection);
  }

  function showPanel(dialog, panel, turn = null, opener = "") {
    const previous = panelOpener;
    sidePanel = panel;
    panelOpener = opener;
    activityTurn = turn;
    draw(dialog);
    const focus = panel ? dialog.querySelector(`#zorec-${panel}-title`) : previous && dialog.querySelector(previous);
    (focus || dialog.querySelector("[data-activity-toggle]"))?.focus({ preventScroll: true });
  }

  function showChat(dialog) {
    sidePanel = "";
    panelOpener = "";
    activityTurn = null;
    problem = "";
    draw(dialog, true);
  }

  function applyContextAction(dialog, data) {
    if (data.chatField) {
      const proposal = adminEdit() ? window.opstendZorecFields.propose({
        key: data.chatField, value: Number(data.chatValue), subjectId: data.chatSubject,
        expectedVersion: data.chatVersion, expectedRevision: Number(data.chatRevision),
      }) : { ok: false, error: "Für Feldvorschläge braucht Zorec Admin Edit." };
      if (!proposal.ok) {
        problem = proposal.error;
        draw(dialog, true);
        return;
      }
    }
    opened = false;
    dialog.close();
    if (data.chatConsole) window.opstendZorecConsole.prepare({ targetId: data.chatConsole, command: data.chatCommand });
  }

  function focusInput(dialog) {
    const input = dialog.querySelector('input[name="question"], .deploy-form input, .deploy-form button')
      || dialog.querySelector("[data-dialog-action='close']");
    input?.focus();
  }

  function open(dialog, next, prepared = false) {
    if (!opened || screen !== next) {
      sidePanel = "";
      panelOpener = "";
      activityTurn = null;
    }
    opened = true;
    screen = next;
    problem = "";
    if (stage === "done" && next === "wizard") {
      draft = blank();
      stage = "sources";
      mode = "guided";
      sourceUrl = "";
    }
    if (next === "wizard") {
      if (!draft.host || (prepared && !draft.repos.size && !draft.name)) {
        const host = chatContext().host;
        draft.host = host && !state.hosts[host]?.budgets ? host : "host-b";
      }
      if (!draft.domain) draft.domain = "dienst." + (state.inventory.domains[0]?.name || "example");
    }
    draw(dialog);
    if (!dialog.open) dialog.showModal();
    window.opstendZorecStatus.refresh();
    if (!matchMedia("(pointer: coarse)").matches) focusInput(dialog);
  }

  function addRepository(dialog) {
    const input = dialog.querySelector('[name="repo-url"]');
    try {
      const url = new URL(input.value.trim());
      if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search) throw new Error();
      if (!repos().some((item) => item.url === url.href)) {
        if (draft.custom.length >= 5) throw new Error();
        draft.custom.push({ name: url.pathname.split("/").filter(Boolean).at(-1) || url.hostname, url: url.href });
      }
      draft.repos.add(url.href);
      updateSources();
      sourceUrl = "";
      problem = "";
    } catch {
      problem = "Gib eine HTTPS-Repository-URL ohne Zugangsdaten ein. Bis zu fünf eigene Quellen sind möglich.";
    }
    draw(dialog);
    dialog.querySelector('[name="repo-url"]').focus();
  }

  function submit(dialog, form) {
    const step = form.dataset.deploySubmit;
    if (screen === "report" && step !== "chat") return;
    const values = new FormData(form);
    problem = "";
    if (step === "chat") {
      send(dialog, String(values.get("question")));
      return;
    } else if (step === "sources") {
      if (sourceUrl.trim()) return addRepository(dialog);
      if (draft.repos.size) stage = "setup";
      else problem = "Wähle mindestens ein Repository.";
    } else if (step === "setup") {
      const adapterFields = form.querySelector("[data-deploy-adapter-fields]");
      if (!draft.name.trim()) {
        problem = "Gib dem Dienst einen Namen.";
      } else if (adapterFields) {
        draft.adapterValues = window.opstendObjectUi.adapterFieldValues(adapterFields);
        const preview = window.opstendDemo.previewAdapterSettings(adapterSource(), draft.adapterValues);
        if (preview.ok) {
          draft.adapterValues = preview.values;
          draft.adapterVersion = preview.adapter.version;
          stage = "review";
        } else {
          problem = preview.error;
        }
      } else {
        stage = "review";
      }
    } else if (step === "review") {
      result = window.opstendDemo.createService({
        name: draft.name, host: draft.host, network: draft.network, ip: draft.ip,
        kind: state.hosts[draft.host]?.type === "PVE" ? "LXC" : "Container · Podman",
        repositories: [...draft.repos], updates: draft.updates,
        adapter: { domain: draft.domain, secretRef: draft.secret, visibility: draft.visibility, dependsOn: draft.reference, body: adapterText() },
        ...(draft.adapterValues ? { adapterValues: draft.adapterValues, adapterVersion: draft.adapterVersion } : {}),
      });
      if (result.ok) stage = "done";
      else problem = result.error;
    }
    draw(dialog, true);
  }

  window.opstendDeploy = {
    render() {
      return '<dialog id="zorec-dialog" class="deploy-dialog" aria-labelledby="deploy-title"></dialog>';
    },
    selectTopologyTarget(topologyFocus) {
      if (state?.view !== "topology" || state.topologyFocus === topologyFocus) return;
      state = { ...state, topologyFocus };
      if (screen === "chat") refreshChat(currentChat());
    },
    mount(current) {
      state = current;
      window.opstendMascot.mount();
      const dialog = document.getElementById("zorec-dialog");
      window.opstendZorecStatus.mount(current);
      let backdropPressed = false;
      function onBackdrop(event) {
        if (event.target !== dialog) return false;
        const { left, top, right, bottom } = dialog.getBoundingClientRect();
        return event.clientX < left || event.clientX >= right || event.clientY < top || event.clientY >= bottom;
      }
      dialog.addEventListener("pointerdown", (event) => {
        backdropPressed = event.isPrimary && event.button === 0 && onBackdrop(event);
      });
      dialog.addEventListener("pointercancel", () => { backdropPressed = false; });
      dialog.addEventListener("cancel", (event) => {
        const menu = dialog.querySelector("[data-chat-menu][open]");
        if (menu) {
          event.preventDefault();
          menu.open = false;
          menu.querySelector("summary").focus();
          return;
        }
        if (sidePanel && screen !== "wizard") {
          event.preventDefault();
          showPanel(dialog, "");
        } else {
          opened = false;
        }
      });
      dialog.addEventListener("close", () => {
        opened = false;
        window.opstendZorecStatus.refresh();
      });
      dialog.addEventListener("input", (event) => {
        const { name, type, value, checked } = event.target;
        if (name === "question") {
          currentChat().prompt = value.slice(0, 240);
        } else if (name === "repo") {
          if (checked) draft.repos.add(value);
          else draft.repos.delete(value);
          updateSources();
        } else if (event.target.hasAttribute("data-adapter-field")) {
          draft.adapterValues = window.opstendObjectUi.adapterFieldValues(event.target.closest("[data-deploy-adapter-fields]"));
          draft.approved = false;
        } else if (name === "repo-url") {
          sourceUrl = value;
        } else if (Object.hasOwn(draft, name) && name !== "repos" && name !== "custom") {
          draft[name] = type === "checkbox" ? checked : value.slice(0, 12000);
          if (name !== "approved") draft.approved = false;
        }
      });
      dialog.addEventListener("opstend:zorec-diagram-kind", (event) => {
        const diagram = chatDiagram(currentChat(), activeShell());
        if (diagram?.revision === event.detail.revision) diagram.kind = event.detail.kind;
      });
      dialog.addEventListener("change", (event) => {
        if (event.target.name !== "host") return;
        draft.reference = "";
        draw(dialog);
        dialog.querySelector('select[name="host"]').focus();
      });
      dialog.addEventListener("click", (event) => {
        const minimize = backdropPressed && onBackdrop(event) && screen !== "wizard";
        backdropPressed = false;
        if (minimize) {
          opened = false;
          dialog.close();
          document.querySelector("[data-open-zorec]")?.focus({ preventScroll: true });
          return;
        }
        const menu = dialog.querySelector("[data-chat-menu][open]");
        if (menu && !menu.contains(event.target)) menu.open = false;
        const button = event.target.closest("button");
        if (!button) return;
        const data = button.dataset;
        if (screen === "chat" && knowledge.modeIds.has(data.questionMode)) {
          currentChat().questionMode = data.questionMode;
          draw(dialog, true);
          return;
        }
        if (screen !== "wizard" && ("chatStart" in data || data.chatRestore)) {
          if (data.chatRestore) chats.restore(chatGroup(), data.chatRestore);
          else chats.start(chatGroup());
          showChat(dialog);
          return;
        }
        if (screen !== "wizard") {
          if ("activityClose" in data || "diagramClose" in data) return showPanel(dialog, "");
          if ("activityToggle" in data || data.activityTurn) {
            const turn = data.activityTurn ? Number(data.activityTurn) : null;
            const selected = activityTurn ?? currentChat().turns.at(-1)?.id;
            const hide = sidePanel === "activity" && (turn === null || turn === selected);
            const opener = turn === null ? "[data-activity-toggle]" : `[data-activity-turn="${turn}"]`;
            return showPanel(dialog, hide ? "" : "activity", hide ? null : turn, hide ? "" : opener);
          }
          if ("diagramToggle" in data || data.diagramTurn) {
            const opener = data.diagramTurn ? `[data-diagram-turn="${CSS.escape(data.diagramTurn)}"]` : "[data-diagram-toggle]";
            return sidePanel === "diagram" ? showPanel(dialog, "") : showPanel(dialog, "diagram", null, opener);
          }
        }
        if (screen === "report" && data.dialogAction !== "close" && !data.chatQuestion) return;
        if (data.chatInspection) {
          if (!inspections.action(data.chatInspection)) return;
          if (!inspectionInScope({ host: data.inspectionHost, subject: data.inspectionSubject }, chatContext())) return staleInspection(dialog);
          send(dialog, button.textContent.trim(), true, data.chatInspection);
        } else if (data.chatField || data.chatConsole) {
          applyContextAction(dialog, data);
        } else if (data.dialogAction === "close" || "deployNavigate" in data) {
          opened = false;
          dialog.close();
        } else if (data.zorecShell && screen === "chat") {
          chats.setMode(data.zorecShell);
          draw(dialog);
          dialog.querySelector(`[data-zorec-shell="${activeShell()}"]`)?.focus();
        } else if (data.dialogAction === "prepare" && adminEdit()) {
          open(dialog, "wizard", true);
        } else if (data.dialogAction === "new") {
          open(dialog, "wizard");
        } else if (data.dialogAction === "chat") {
          open(dialog, "chat");
        } else if (data.chatQuestion) {
          send(dialog, data.chatQuestion, true);
        } else if ("deployAdd" in data) {
          addRepository(dialog);
        } else if (data.deployMode || data.deployStep) {
          if (data.deployMode) mode = data.deployMode;
          if (data.deployStep) stage = data.deployStep;
          problem = "";
          draw(dialog, true);
        }
      });
      dialog.addEventListener("submit", (event) => {
        event.preventDefault();
        submit(dialog, event.target);
      });
      if (opened) open(dialog, screen);
    },
  };

  window.addEventListener("opstend:zorec-policy-changed", () => {
    chats.invalidate();
    const dialog = document.getElementById("zorec-dialog");
    if (dialog?.open && screen !== "wizard") refreshConversation(dialog);
  });

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-new-service], [data-open-zorec], [data-open-zorec-report]");
    if (!trigger) return;
    const next = trigger.hasAttribute("data-open-zorec-report") ? "report" : trigger.hasAttribute("data-new-service") ? "wizard" : "chat";
    open(document.getElementById("zorec-dialog"), next);
  });
})();
