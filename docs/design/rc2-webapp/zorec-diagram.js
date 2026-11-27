(function () {
  "use strict";

  const kinds = {
    sequence: ["Sequenz", "Sequence"],
    component: ["Komponenten", "Component"],
    activity: ["Aktivität", "Activity"],
    deployment: ["Deployment", "Deployment"],
  };
  const t = window.opstendLocale.t;
  let cleanup = () => {};

  function diagramLabel(value, fallback) {
    return String(value ?? "").normalize("NFKC")
      .replace(/[^\p{L}\p{N} .,_()/+\-]/gu, " ").replace(/\s+/g, " ").trim().slice(0, 64) || fallback;
  }

  function normalize(draft) {
    const language = draft.language === "en" ? "en" : "de";
    return {
      kind: Object.hasOwn(kinds, draft.kind) ? draft.kind : "sequence",
      revision: Number.isSafeInteger(draft.revision) && draft.revision > 0 ? draft.revision : 1,
      title: String(draft.title || "Erklärdiagramm").slice(0, 100),
      sourceName: diagramLabel(draft.sourceName, "Aufrufer"),
      targetName: diagramLabel(draft.targetName, "Ziel"),
      hostName: diagramLabel(draft.hostName, "Host"),
      focus: draft.focus === "target" ? "target" : "path",
      includeCheck: draft.includeCheck === true,
      language,
      steps: draft.steps?.map(step => diagramLabel(step, "…")),
    };
  }

  function points(draft) {
    const { sourceName, targetName, hostName, includeCheck, language } = draft;
    const text = (de, en) => language === "en" ? en : de;
    if (draft.steps) return Object.fromEntries(draft.steps.map((detail, index) => [`step_${index + 1}`, {
      label: text(`Schritt ${index + 1}`, `Step ${index + 1}`), detail,
    }]));
    return {
      path: { label: text("Pfad", "Path"), detail: text(`Der dargestellte Pfad führt von ${sourceName} zu ${targetName}.`, `The path runs from ${sourceName} to ${targetName}.`) },
      source: { label: text("Quelle", "Source"), detail: text(`${sourceName} ist der Ausgangspunkt der Erklärung.`, `${sourceName} is the starting point.`) },
      target: { label: text("Ziel", "Target"), detail: text(`${targetName} ist das Ziel der dargestellten Anfrage.`, `${targetName} is the destination of this request.`) },
      host: { label: "Host", detail: text(`${hostName} ist die Maschine im Kontext dieser Erklärung.`, `${hostName} is the machine involved in this explanation.`) },
      ...(includeCheck ? { check: { label: text("Prüfung", "Check"), detail: text("Die dargestellte Health-Prüfung folgt auf die Anfrage zum Ziel.", "The health check follows the request to the target.") } } : {}),
    };
  }

  function render(state, draft) {
    if (!draft) return '<section id="zorec-diagram" hidden></section>';
    const diagram = normalize(draft);
    const escape = state.escape;
    const items = points(diagram);
    const focus = diagram.steps ? "step_1" : diagram.focus;
    return `<section class="zorec-diagram" id="zorec-diagram" data-zorec-diagram aria-labelledby="zorec-diagram-title">
      <header class="zorec-activity-head">
        <div class="zorec-activity-heading">${window.opstendMascot.render("answered")}
          <div><h3 id="zorec-diagram-title" tabindex="-1">${t("Diagramm", "Diagram")}</h3>
            <p lang="${diagram.language}">${escape(diagram.title)}</p></div>
        </div>
        <button type="button" class="button zorec-activity-close" data-diagram-close aria-label="${t("Diagramm schließen", "Close diagram")}">×</button>
      </header>
      <div class="zorec-diagram-body">
        ${diagram.steps ? "" : `<label class="zorec-diagram-kind">${t("Diagrammtyp", "Diagram type")}
          <select data-zorec-diagram-kind>${Object.entries(kinds).map(([kind, label]) =>
            `<option value="${kind}" ${kind === diagram.kind ? "selected" : ""}>${t(...label)}</option>`).join("")}</select>
        </label>`}
        <div class="zorec-diagram-viewport" data-zorec-diagram-viewport tabindex="0" aria-label="${t("Interaktives Diagramm", "Interactive diagram")}"></div>
        <p class="zorec-diagram-status" data-zorec-diagram-status role="status"></p>
        <div class="zorec-diagram-points" role="group" aria-label="${t("Diagrammelemente", "Diagram elements")}">${Object.entries(items).map(([id, item]) =>
          `<button type="button" class="button" lang="${diagram.language}" data-zorec-diagram-point="${id}" aria-pressed="${id === focus}">${item.label}</button>`).join("")}</div>
        <p class="zorec-diagram-detail" lang="${diagram.language}" data-zorec-diagram-detail aria-live="polite">${escape(items[focus].detail)}</p>
      </div>
    </section>`;
  }

  function diagramBody(draft) {
    const { kind, sourceName, targetName, hostName, includeCheck, language } = draft;
    const text = (de, en) => language === "en" ? en : de;
    const request = text("Anfrage", "Request");
    const health = text("Health-Prüfung", "Health check");
    const placementText = text("Platzierung", "Placement");
    if (kind === "activity") {
      const labels = draft.steps ? Object.fromEntries(draft.steps.map((step, index) => [`step_${index + 1}`, `${index + 1}. ${step}`])) : {
        source: text(`Anfrage von ${sourceName}`, `Request from ${sourceName}`),
        target: text(`Anfrage an ${targetName}`, `Request to ${targetName}`),
        host: text(`Ziel auf ${hostName} zuordnen`, `Place target on ${hostName}`),
        ...(includeCheck ? { check: text("Health-Prüfung vorsehen", "Schedule a health check") } : {}),
      };
      return { labels, lines: ["start", ...Object.values(labels).map((label) => `:${label};`), "stop"] };
    }
    if (kind === "sequence") return { lines: [
      `participant "${sourceName}" as source`, `participant "${targetName}" as target`,
      `participant "${hostName}" as host`,
      ...(includeCheck ? [`participant "${health}" as check`] : []),
      `source -> target: ${request}`, `note over target, host: ${text("Platzierung des Dienstes", "Service placement")}`,
      ...(includeCheck ? [`check -> target: ${health}`] : []),
    ] };
    const deployment = kind === "deployment";
    const placement = deployment ? [
      `node "${hostName}" as host {`, `  artifact "${targetName}" as target`, "}",
    ] : [
      `component "${targetName}" as target`, `component "${hostName}" as host`, `target ..> host : ${placementText}`,
    ];
    return { lines: [
      "left to right direction", `${deployment ? "cloud" : "component"} "${sourceName}" as source`, ...placement,
      `source --> target : ${request}`,
      ...(includeCheck ? [`${deployment ? "artifact" : "component"} "${health}" as check`, `check ..> target : ${text("Prüfschritt", "Check step")}`] : []),
    ] };
  }

  function activityHooks(elements, labels) {
    const unwrapped = (text) => text.replace(/\s+/g, " ").trim();
    return Object.entries(labels).map(([id, label]) => {
      const text = elements.find((item) => item.type === "text" && unwrapped(item.text) === unwrapped(label));
      const group = text?.groupIds?.[0];
      const shape = group && elements.find((item) => item.type === "rectangle" && item.groupIds?.includes(group));
      if (!shape) throw new Error("Die Aktivität konnte nicht dem Diagrammelement zugeordnet werden.");
      return `@hook #${id} element:${shape.id} .point click-mode:button`;
    });
  }

  async function makeSvg(draft, theme, itemIds) {
    const { render: renderPlantUml } = window.opstendExcaliplant;
    const options = { strict: true, theme: `transparent-${theme === "dark" ? "dark" : "light"}`, sketch: false, seed: "opstend-zorec" };
    const diagram = diagramBody(draft);
    const source = (hooks) => ["@startuml", ...hooks, ...diagram.lines, "@enduml"].join("\n");
    const ids = itemIds.filter((id) => id !== "path");
    const hooks = diagram.labels
      ? activityHooks((await renderPlantUml(source([]), options)).excalidraw.elements, diagram.labels)
      : ids.map((id) => `@hook #${id} alias:${id} .point click-mode:button`);
    const rendered = await renderPlantUml(source(hooks), options);
    if (rendered.kind !== draft.kind) throw new Error("Der gewünschte Diagrammtyp konnte nicht gerendert werden.");
    const markup = await rendered.toSvg({ interactive: true, embedFont: false });
    return window.opstendTopology.importSvg(markup, `${kinds[draft.kind][draft.language === "en" ? 1 : 0]} · ${draft.title}`);
  }

  function mount(dialog, state, draft) {
    cleanup();
    cleanup = () => {};
    const panel = dialog.querySelector("[data-zorec-diagram]");
    if (!panel || !draft) return;
    const events = new AbortController();
    const { signal } = events;
    const viewport = panel.querySelector("[data-zorec-diagram-viewport]");
    const status = panel.querySelector("[data-zorec-diagram-status]");
    const detail = panel.querySelector("[data-zorec-diagram-detail]");
    const preview = normalize(draft);
    const items = points(preview);
    let selected = preview.steps ? "step_1" : preview.focus;
    let request = 0;
    let unbind = () => {};
    cleanup = () => { events.abort(); unbind(); };

    function select(id) {
      if (!Object.hasOwn(items, id)) return;
      selected = id;
      detail.textContent = items[id].detail;
      for (const button of panel.querySelectorAll("[data-zorec-diagram-point]")) {
        button.setAttribute("aria-pressed", String(button.dataset.zorecDiagramPoint === id));
      }
      for (const target of viewport.querySelectorAll("[data-excaliplant-hook-id]")) {
        const item = target.getAttribute("data-excaliplant-hook-id");
        const highlighted = id === item || (id === "path" && ["source", "target"].includes(item));
        target.toggleAttribute("data-zorec-diagram-highlight", highlighted);
        if (target.getAttribute("tabindex") === "0") {
          target.setAttribute("aria-pressed", String(highlighted));
        }
      }
    }

    async function refresh() {
      const generation = ++request;
      unbind();
      viewport.replaceChildren();
      status.textContent = t("Diagramm wird gerendert …", "Rendering diagram …");
      try {
        const kind = preview.kind;
        const svg = await makeSvg(preview, state.theme, Object.keys(items));
        if (signal.aborted || generation !== request || !panel.isConnected) return;
        viewport.replaceChildren(svg);
        const unbindHooks = window.opstendExcaliplant.bindHooks(svg);
        const onHook = (event) => {
          if (event.detail.type === "click") select(event.detail.id);
        };
        svg.addEventListener("excaliplant:hook", onHook);
        unbind = () => {
          svg.removeEventListener("excaliplant:hook", onHook);
          unbindHooks();
        };
        for (const control of svg.querySelectorAll('[data-excaliplant-hook-id][tabindex="0"]')) {
          const item = items[control.getAttribute("data-excaliplant-hook-id")];
          if (item) control.setAttribute("aria-label", preview.language === "en" ? `${item.label} in diagram` : `${item.label} im Diagramm`);
        }
        select(selected);
        status.textContent = `${t(...kinds[kind])} · Version ${preview.revision}`;
      } catch {
        if (signal.aborted || generation !== request || !panel.isConnected) return;
        viewport.replaceChildren();
        status.textContent = t("Diagramm nicht verfügbar. Die Erläuterungen bleiben auswählbar.", "The diagram is unavailable. You can still select the explanations.");
      }
    }

    panel.addEventListener("click", (event) => {
      const point = event.target.closest("[data-zorec-diagram-point]");
      if (point) select(point.dataset.zorecDiagramPoint);
    }, { signal });
    panel.querySelector("[data-zorec-diagram-kind]")?.addEventListener("change", (event) => {
      const kind = event.target.value;
      if (!Object.hasOwn(kinds, kind)) return;
      preview.kind = kind;
      void refresh();
      panel.dispatchEvent(new CustomEvent("opstend:zorec-diagram-kind", { detail: { kind, revision: preview.revision }, bubbles: true }));
    }, { signal });
    dialog.addEventListener("close", () => { if (!dialog.open) cleanup(); }, { signal });
    void refresh();
  }

  window.opstendZorecDiagram = { render, mount };
})();
