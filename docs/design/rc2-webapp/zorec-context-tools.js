(function () {
  "use strict";

  const ui = (de, en) => window.opstendLocale?.t(de, en) ?? de;

  function explain(input, context, state, existing, reply) {
    const revise = existing && existing.scope === state.host && /ergänz|änder|hinzu|wechs|hervor|wegla|\badd\b|change|switch|highlight|remove/.test(input);
    const kind = /sequenz|sequence/.test(input) ? "sequence" : /komponent|component/.test(input) ? "component"
      : /aktivität|ablaufdiagramm|activity/.test(input) ? "activity" : /deployment|platzierung/.test(input) ? "deployment" : existing?.kind || "sequence";
    const assets = [...state.inventory.hosts, ...state.inventory.services, ...state.inventory.devices];
    const link = state.inventory.links.find((item) => item.id === context.topologyTarget
      && (!state.host || assets.some((asset) => (asset.id === item.from || asset.id === item.to)
        && (asset.id === state.host || asset.host === state.host))));
    const linked = link && assets.find((item) => item.id === link.to);
    const target = linked || context.service || state.hosts[context.host];
    const sourceName = (link && assets.find((item) => item.id === link.from)?.name) || reply("Anfrager", "Client");
    const showCheck = /health|prüfschritt|nachprüfung|recheck/.test(input);
    const omitCheck = /ohne|entferne|wegla|without|remove/.test(input);
    const focus = /ziel|hervor|markier|target|highlight/.test(input) ? "target" : "path";
    const draft = revise ? { ...existing } : {
      scope: state.host, title: reply("Erklärdiagramm", "Diagram") + " · " + (target?.name || reply("Anfrage und Ziel", "Request and destination")), sourceName,
      targetName: target?.name || reply("Dienst", "Service"), hostName: target?.host || context.host || "Host", includeCheck: false,
    };
    Object.assign(draft, { kind, focus, revision: revise ? existing.revision + 1 : 1, expanded: true,
      includeCheck: showCheck ? !omitCheck : draft.includeCheck });
    return {
      text: revise ? reply(`Ich habe das Diagramm auf Version ${draft.revision} aktualisiert.`, `I updated the diagram to version ${draft.revision}.`)
        : reply("Das Diagramm zeigt den Weg der Anfrage und die Platzierung des Ziels. Du kannst die Elemente auswählen und den Diagrammtyp wechseln.",
          "The diagram shows where the request goes and where the destination runs. You can select its elements and change the diagram type."),
      diagram: draft, ruleOnly: true, activity: [ui("Erklärdiagramm aktualisieren", "Update diagram"), `${draft.targetName} · Version ${draft.revision}`], actions: [],
    };
  }

  function mark(input, context, state, reply) {
    const scoped = [...state.inventory.hosts, ...state.inventory.services, ...state.inventory.devices]
      .filter((item) => !state.host || item.id === state.host || item.host === state.host);
    const ids = new Set(scoped.map((item) => item.id));
    const candidates = [...scoped, ...state.inventory.links.filter((link) => !state.host || ids.has(link.from) || ids.has(link.to))];
    const target = candidates.find((item) => input.includes((item.name || item.label).toLocaleLowerCase("de")))
      || candidates.find((item) => item.id === context.topologyTarget || item.id === (context.service?.id || context.host));
    const name = target?.name || target?.label;
    return {
      ruleOnly: true, text: target ? reply(`${name} kann ich auf der Topologie markieren.`, `I can highlight ${name} in the topology.`)
        : reply("Nenne den Namen eines Hosts, Dienstes oder einer Verbindung oder öffne das Objekt zuerst.", "Name a host, service or connection, or open it first."),
      activity: [ui("Kartenobjekt zuordnen", "Find map object"), name || ui("Kein eindeutiges Objekt im Geltungsbereich.", "No unique object in scope.")],
      actions: target ? [{ label: ui("In Topologie markieren", "Highlight in topology"), route: { view: "topology", layer: target.layer || "placement",
        "topology-focus": target.id, "topology-mark": target.id } }] : [],
    };
  }

  function field(input, context, state, shell, reply) {
    const adapter = context.service && state.view === "service" && window.opstendDemo.adapterSettings(context.service);
    const value = Number(input.match(/\b(\d{1,7})\s*(?:sekunden|sek\.?|seconds?|sec\.?|s\b)/)?.[1]);
    const preview = adapter && Number.isInteger(value) && window.opstendDemo.previewAdapterSettings(context.service, { ...adapter.values, intervalSeconds: value });
    const permitted = shell === "admin-edit" && context.service?.id === "sensorik" && preview?.ok;
    return {
      ruleOnly: true, text: permitted ? reply(`Vorschlag für ${context.service.name} · Messintervall ${value} Sekunden. Du kannst den Wert im Formular bearbeiten und prüfen.`,
        `Suggested measurement interval for ${context.service.name}: ${value} seconds. You can edit and review the value in the form.`)
        : shell !== "admin-edit" ? reply("Wechsle zu Admin Edit, um einen Wert ins Formular vorzuschlagen.", "Switch to Admin Edit to suggest a value in the form.")
          : preview?.error ? reply(preview.error, "The proposed interval is outside the limits shown in the settings form.")
            : reply("Öffne den Dienst Sensorik und nenne ein Messintervall in Sekunden.", "Open Sensorik and specify a measurement interval in seconds."),
      activity: [ui("Registriertes Formularfeld prüfen", "Check registered form field"), permitted
        ? ui("Sensorik · Messintervall", "Sensorik · Measurement interval") : ui("Kein Feldentwurf erstellt.", "No field draft created.")],
      actions: permitted ? [{ label: ui("Vorschlag ins Feld", "Fill in suggested value"), field: { key: "service.adapter.intervalSeconds", value,
        subjectId: context.service.id, expectedVersion: adapter.version, expectedRevision: adapter.revision } }] : [],
    };
  }

  function consoleDraft(input, context, state, reply) {
    const targetId = state.view === "service" && context.service ? `service:${context.service.id}`
      : state.view === "host" && state.hostTab === "overview" && context.host ? `host:${context.host}` : "";
    const command = /hostname|rechnername/.test(input) ? "hostname" : /adresse|address|\bip\b/.test(input) ? "ip -brief address" : "status";
    return {
      ruleOnly: true, text: targetId ? reply(`Ich kann „${command}“ in der Konsole von ${context.label} vorbereiten. Die Befehlszeile bleibt bearbeitbar.`,
        `I can prepare “${command}” in the ${context.label} console. You can edit the command before sending it.`)
        : reply("Öffne die Konsole in der Übersicht des Hosts oder Dienstes. Dort kannst du auch direkt @Zorec oder @chat schreiben.",
          "Open the console in the host or service overview. You can also type @Zorec or @chat there."),
      activity: [ui("Konsolenziel prüfen", "Check console target"), targetId ? context.label : ui("Keine offene Host- oder Dienstkonsole im Kontext.", "No host or service console in scope.")],
      actions: targetId ? [{ label: ui("In Konsole vorbereiten", "Prepare in console"), console: { targetId, command } }] : [],
    };
  }

  function answer(input, context, state, shell, diagram, reply) {
    if (context.pve && /proxmox|inventar|beleg|lesebereich|token|evidence|scope/.test(input)) {
      const { snapshot, pending, detail } = context.pve;
      let evidence;
      if (snapshot?.status === "observed" && snapshot.guest) {
        evidence = reply(`Der Gast ${snapshot.guest.name || snapshot.guest.kind.toUpperCase()} ist im Token-Berechtigungsumfang sichtbar. Netz, Messwerte und native Tasks haben jeweils eigene Belege.`,
          `The guest ${snapshot.guest.name || snapshot.guest.kind.toUpperCase()} is visible within the token scope. Networking, measurements, and native tasks have separate evidence.`);
      } else if (snapshot?.status === "observed" && !detail) {
        evidence = reply(`Im Token-Berechtigungsumfang sind ${snapshot.nodes.length} Knoten und ${snapshot.guests.length} Gäste sichtbar.`,
          `The token scope shows ${snapshot.nodes.length} nodes and ${snapshot.guests.length} guests.`);
      } else if (snapshot?.status === "restricted" && detail) {
        evidence = reply("Der Gast ist im Lesebereich nicht verfügbar.", "The guest is unavailable in the read scope.");
      } else if (snapshot?.status === "stale") {
        evidence = reply("Der Inventarstand ist veraltet. Für die aktuelle Ansicht wartet die Demo auf einen frischen Abruf.",
          "The inventory snapshot is stale. This demo view needs a fresh response.");
      } else if (snapshot?.status === "absent") {
        evidence = reply("Im sichtbaren Lesebereich wurden keine Proxmox-Ressourcen gefunden.", "The visible read scope returned no Proxmox resources.");
      } else {
        evidence = pending ? reply("Der Leseabruf läuft.", "The read request is in progress.")
          : reply("Für diese Auswahl ist kein Proxmox-Inventarbeleg verfügbar.", "No Proxmox inventory evidence is available for this selection.");
      }
      return { ruleOnly: true, text: evidence,
        activity: [ui("Proxmox-Lesebeleg lesen", "Read Proxmox evidence"), snapshot?.observed_at || ui("Aktueller Seitenkontext", "Current page context")], actions: [] };
    }
    if (context.publication && /freigab|zugang|erreich|https|vpn|veröffentlich|access|publication|reachable/.test(input)) {
      const publication = context.publication;
      const service = state.inventory.services.find(({ id }) => id === publication.serviceId);
      const path = `${publication.domain} → ${publication.proxyHost} → ${service?.name || publication.serviceId} (${publication.targetHost})`;
      const status = publication.stale ? reply("Beleg überholt", "Outdated evidence") : reply(publication.stageLabel, publication.stageLabelEn);
      const proof = publication.error ? reply(publication.error, publication.errorEn)
        : publication.probe?.result === "pass" ? reply("Der externe Beispielabruf war erfolgreich.", "The simulated external request passed.")
          : publication.probe ? reply("Der externe Beispielabruf ist fehlgeschlagen.", "The simulated external request failed.")
            : ["rejected", "withdrawn"].includes(publication.stage)
              ? reply("Frühere Schritte stehen im Auftragsverlauf.", "Earlier steps are available in the job history.")
              : reply("Der externe Abrufbeleg steht aus.", "External request evidence is pending.");
      const actions = publication.jobId ? [{ label: ui("Auftrag öffnen", "Open job"), route: {
        view: "changes", host: publication.proxyHost, job: publication.jobId,
      } }] : [];
      return { ruleOnly: true, text: `${path}\n${status}. ${proof}`,
        activity: [ui("Veröffentlichungspfad lesen", "Read publication path"), status], actions };
    }
    if (context.job && /zorecs? entscheidung|autonom|what did zorec decide|zorec.s decision/.test(input)) {
      const run = window.opstendAutonomy.decisionFor(context.job.id, context.job.host);
      if (run) {
        const explain = (field) => Array.isArray(field) ? reply(...field) : field;
        return { ruleOnly: true,
          text: [run.context, run.reason, run.readback].filter(Boolean).map(explain).join("\n"),
          activity: [ui("Entscheidungsbeleg lesen", "Read decision evidence"), explain(run.source) || context.job.title],
          actions: [],
        };
      }
    }
    if (context.host && ["host", "host-maintenance"].includes(state.view) && /wartung|maintenance/.test(input)) {
      const maintenance = window.opstendHostMaintenance;
      const record = maintenance.latest(state, context.host);
      const open = record && !["finished", "rejected"].includes(record.stage);
      const plan = open ? record : maintenance.preview(state, context.host);
      const workloads = plan.workloads.filter(({ handling }) => handling === "restart").map(({ name }) => name).join(", ");
      const affected = workloads ? reply(`Ein lokaler Neustart unterbricht ${workloads}.`, `A local restart interrupts ${workloads}.`)
        : reply("Kein laufender Dienst ist für einen Neustart eingeplant.", "No running service is scheduled to restart.");
      return { ruleOnly: true, text: `${reply(plan.window.label, plan.window.labelEn)} · ${context.host}. ${affected}${plan.error ? ` ${reply(plan.error, plan.errorEn)}` : ""}`,
        activity: [ui("Wartungsvorschau lesen", "Read maintenance preview"), plan.window.source && ui(plan.window.source, plan.window.sourceEn)],
        actions: [{ label: open ? ui("Wartungsauftrag öffnen", "Open maintenance job") : ui("Hostwartung öffnen", "Open host maintenance"),
          route: open ? { view: "changes", host: context.host, job: record.id } : { view: "host-maintenance", host: context.host } }] };
    }
    if (state.view === "network-rule" && /regel|verbindung|beleg|firewall|\bacl\b|\brule\b|connection|evidence/.test(input)) {
      const rule = window.opstendNetworkRules?.get(state, state.ruleId);
      if (!rule) return null;
      const link = state.inventory.links.find(item => item.id === rule.linkId);
      const proof = link && window.opstendDemo.linkEvidence(link);
      const effect = rule.effect === "allow" ? reply("Erlauben", "Allow") : reply("Blockieren", "Block");
      const status = rule.pending
        ? reply("Eine Änderung wartet auf Freigabe. Die aktive Regelwirkung gilt weiter.", "A change is awaiting approval. The active rule effect still applies.") : "";
      const evidence = proof ? reply(proof.detail, proof.detailEn || proof.detail) : reply("Für diese Regel liegt ein Konfigurationsbeleg vor.", "This rule has configuration evidence.");
      return { ruleOnly: true,
        text: `${reply(rule.name, rule.nameEn)} · ${effect} · ${rule.protocol} ${rule.port}. ${status ? `${status} ` : ""}${evidence}`,
        activity: [ui("Regelstand lesen", "Read rule revision"), `${ui("Revision", "Revision")} ${rule.revision}`],
        actions: rule.pending ? [{ label: ui("Auftrag öffnen", "Open job"), route: { view: "changes", host: rule.pending.host, job: rule.pending.id } }]
          : link ? [{ label: ui("Pfad in Topologie", "Path in topology"), route: { view: "topology", host: state.host, layer: link.layer, "topology-focus": link.id } }] : [],
      };
    }
    if (state.view === "settings" && state.settingsTab === "language" && /sprache|language/.test(input)) {
      return { ruleOnly: true,
        text: reply("Das globale Konto gibt die Sprache für die Oberfläche und für meine Antworten vor. Persönliche Profile können jeden der beiden Werte unabhängig übernehmen oder überschreiben.",
          "The global account provides separate defaults for the interface and my replies. Personal profiles can inherit or override each setting independently."),
        activity: [ui("Spracheinstellungen erklären", "Explain language preferences"), ui("Globale Vorgaben und persönliche Präferenzen", "Global defaults and personal preferences")], actions: [] };
    }
    if (/hostaufnahme erklären|was.*bestandsaufnahme|host enrollment/.test(input) && state.view === "settings" && state.settingsTab === "hosts") {
      const { candidate } = window.opstendHostEnrollment;
      const intake = window.opstendHostEnrollment.read();
      return { ruleOnly: true,
        text: reply(`Die Bestandsaufnahme für ${candidate.name} zeigt Hardware und vorhandene Dienste. Danach legst du die Zuständigkeit pro Dienst und die Ressourcenfreigaben fest. Die Vorschau zeigt den Stand vor der Bestätigung.`,
          `Discovery for ${candidate.name} shows its hardware and existing services. Choose who manages each service and which resources OpsTend may use, then review the preview before confirming.`),
        activity: [ui("Hostaufnahme im Seitenkontext lesen", "Read host enrollment"), ui(`${candidate.name} · ${intake.services.length} Dienste vor Ort`, `${candidate.name} · ${intake.services.length} local services`)], actions: [] };
    }
    if (/eigenupdate|opstend.{0,30}update|patch.abgleich|patch reconciliation|self-update/.test(input)) {
      const update = window.opstendSelfUpdateView.jobs(state)[0];
      const host = update?.host || context.host || "nuc-a";
      return { ruleOnly: true, text: update ? reply(`${update.title} · ${update.status}. ${update.verification}.`, `OpsTend has an update job for ${host}. Open the job to see its current verification result.`)
        : reply("Unter OpsTend-Updates kannst du die Richtlinie und den Patchstand je Installation prüfen.", "OpsTend updates shows the policy and patch status for each installation."),
        activity: [ui("Eigenupdate-Auftrag lesen", "Read self-update job"), update?.status || ui("Für diesen Bereich gibt es noch keinen Demo-Auftrag.", "No demo job exists in this scope yet.")],
        actions: [{ label: ui("OpsTend-Updates öffnen", "Open OpsTend updates"), route: { view: "settings", host, "settings-tab": "updates" } }] };
    }
    if (/diagram|excaliplant|plantuml/.test(input) || (diagram && /prüfschritt|nachprüfung ergänz|add.*recheck/.test(input))) return explain(input, context, state, diagram, reply);
    if (/markier|hervorheb|highlight/.test(input)) return mark(input, context, state, reply);
    if (/interval/.test(input) && /sekunden|seconds| ändern| setzen| einstellen| eintrag|\bset\b/.test(input)) return field(input, context, state, shell, reply);
    if (/konsole|befehl|kommando|console|command/.test(input) && /vorbereit|eintrag|eingeb|hostname|ip |status|prepare|draft/.test(input)) return consoleDraft(input, context, state, reply);
    return null;
  }

  function suggestions(state, context, shell) {
    if (shell === "report") return [];
    const pick = (de, en, question, englishQuestion) => [ui(de, en), ui(question, englishQuestion)];
    if (context.pve) return [pick("Proxmox-Belege erklären", "Explain Proxmox evidence", "Welche Proxmox-Belege sind im Lesebereich sichtbar?",
      "What Proxmox evidence is visible in the read scope?")];
    if (context.publication) return [pick("Zugang erklären", "Explain access", "Wie ist dieser HTTPS-Zugang in der Demo geschaltet?",
      "How is this HTTPS publication configured in the demo?")];
    if (state.view === "service" && context.service) {
      const service = context.service;
      return [
        pick("Dienststatus erklären", "Explain service status", `Welchen Status hat ${service.name}?`, `What is the status of ${service.name}?`),
        service.id === "sensorik" && shell === "admin-edit"
          ? pick("Messintervall als Entwurf", "Draft a measurement interval", "Bereite 90 Sekunden für das Messintervall vor.", "Suggest a measurement interval of 90 seconds.")
          : pick("Platzierung als Diagramm", "Diagram the placement", `Zeige ${service.name} als Deployment-Diagramm.`, `Show ${service.name} in a deployment diagram.`),
      ];
    }
    if (state.view === "host" && context.host) return [
      pick("CPU-Auslastung", "CPU utilization", `Wie hoch ist die CPU-Auslastung auf ${context.host}?`, `What is the CPU utilization on ${context.host}?`),
      pick("Host auf der Karte markieren", "Highlight host on the map", `Markiere ${context.host} in der Topologie.`, `Highlight ${context.host} in the topology.`),
    ];
    if (state.view === "host-maintenance" && context.host) return [pick("Auswirkungen erklären", "Explain the impact",
      "Welche Dienste sind von dieser Wartung betroffen?", "Which services are affected by this maintenance?")];
    if (state.view === "changes" && context.job?.id === "sensorik") return [
      pick("Nachprüfung erklären", "Explain the recheck", "Was prüft Zorec beim Wiederanlauf von Sensorik?", "What does Zorec check during Sensorik recovery?"),
      window.opstendAutonomy.decisionFor(context.job.id, context.job.host)
        ? pick("Zorecs Entscheidung erklären", "Explain Zorec's decision", "Was war Zorecs Entscheidung zu Sensorik?", "What did Zorec decide about Sensorik?")
        : pick("Beispielwerte einordnen", "Explain the demo values", "Sind die Werte zum Neustart statisch oder in der Demo veränderbar?", "Are the restart values static or can I simulate a result?"),
    ];
    if (state.view === "changes" && context.job) return [pick("Auftrag erklären", "Explain this job", "Erkläre mir diesen Auftrag.", "Explain this job.")];
    if (state.view === "overview" || state.view === "inventory") return [pick("Topologie öffnen", "Open topology", "Öffne die Topologie.", "Open the topology.")];
    if (state.view === "services") return [pick("Dienstbestand zusammenfassen", "Summarize services", "Welche Dienstinstanzen laufen hier?", "Which services are running here?")];
    if (state.view === "network") return [pick("Erfasste Netze zeigen", "List known networks", "Welche Netze sind im Inventar erfasst?", "Which networks are registered in the inventory?")];
    if (state.view === "monitoring") return [pick("Messstand erklären", "Explain the readings", "Welche Messwerte sind im gewählten Bereich belegt?", "What measurements are available in the current scope?")];
    if (state.view === "events") return [pick("Dieses Protokoll erklären", "Explain this log", "Was zeigt dieses Ereignisprotokoll?", "What does this event log show?")];
    if (state.view === "topology" && context.topologyTarget) return [
      pick("Auswahl markieren", "Highlight selection", "Markiere die aktuelle Auswahl.", "Highlight the current selection."),
      pick("Auswahl als Diagramm", "Diagram the selection", "Zeige die Auswahl als Sequenzdiagramm.", "Show the selection in a sequence diagram."),
    ];
    if (state.view === "network-rule") return [pick("Regelwirkung erklären", "Explain the rule effect", "Welche Wirkung hat diese Regel?", "What is the effect of this rule?")];
    if (state.view === "network-detail" || state.view === "network-port") return [pick("Verbindung erklären", "Explain the connection", "Wie ist das ausgewählte Netz verbunden?", "How is the selected network connected?")];
    if (state.view !== "settings") return [];
    if (state.settingsTab === "ai") return [pick("Aktive Shell erklären", "Explain active shell", "Welche Berechtigungen hat deine aktuelle Shell?", "What permissions does your current shell have?")];
    if (state.settingsTab === "language") return [pick("Sprachvorgaben erklären", "Explain language defaults", "Wie werden die Sprachen ausgewählt?", "How are the language preferences selected?")];
    if (state.settingsTab === "hosts") return [pick("Hostaufnahme erklären", "Explain host enrollment", "Kannst du die Hostaufnahme erklären?", "How does host enrollment work?")];
    if (state.settingsTab === "updates") return [pick("Patch-Abgleich erklären", "Explain patch reconciliation", "Was zeigt der Patch-Abgleich für das Eigenupdate?", "What does patch reconciliation show for self-updates?")];
    return [];
  }

  window.opstendZorecContextTools = { answer, suggestions };
})();
