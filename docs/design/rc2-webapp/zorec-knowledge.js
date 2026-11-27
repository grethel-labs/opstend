(function () {
  "use strict";

  const t = window.opstendLocale.t;
  const modes = [
    ["auto", "Automatisch", "Automatic"], ["system", "Dieses System", "This system"],
    ["knowledge", "Allgemeinwissen", "General knowledge"], ["research", "Webquellen", "Web sources"],
  ];
  const modeIds = new Set(modes.map(([id]) => id));
  const diagramWords = /diagramm|diagram|grafik|visualisier|visualiz|schaubild|flussbild|flowchart/iu;
  const webRequest = /(?:\b(?:im internet|im web|online|im netz|the web|online sources)\b.{0,30}\b(?:such\w*|recherchier\w*|nachschlag\w*|search|look up)\b|\b(?:such\w*|recherchier\w*|nachschlag\w*|search|look up)\b.{0,45}\b(?:im internet|im web|online|im netz|the web|online sources)\b|\b(?:mit webquellen|with web sources)\b)/iu;
  const systemReference = /\b(?:opstend|zorecs?|demo|unser\w*|our|dies(?:e|er|em|en)\s+(?:ansicht|system|instanz|regel|verbindung)|this\s+(?:system|instance|page|rule|connection)|hier|current scope|geltungsbereich|offene vorgänge|open cases)\b/iu;
  const generalQuestion = /^(?:was |wie (?:funktioniert|entsteht|berechne|entwickelt)|warum |welch\w* |wer |woher |wann |wieso |wie viele |what |how (?:does|do|is|are|can|many)|why |which |who |when |explain |describe |compare |erklär\w* |beschreib\w* |vergleich\w* |zeig\w* .*diagramm)/iu;
  const normalize = value => String(value).normalize("NFKC").toLocaleLowerCase("de").replace(/[^\p{L}\p{N}]+/gu, " ").trim();

  function resolve(question, state, selected, localIntent, currentDiagram) {
    const input = question.trim();
    const diagram = diagramWords.test(input);
    if (selected === "system") return null;
    if (selected === "research" || webRequest.test(input)) return { mode: "research", diagram };
    if (selected === "knowledge") return { mode: "knowledge", diagram };
    const editingDiagram = diagram && /ergänz|füg|änder|aktualisier|add |update|revise|change/iu.test(input);
    if (editingDiagram && currentDiagram) return currentDiagram.steps ? { mode: "knowledge", diagram: true } : null;
    if (localIntent || systemReference.test(input)) return null;
    const text = ` ${normalize(input)} `;
    const assets = [...state.inventory.hosts, ...state.inventory.services, ...state.inventory.devices];
    if (assets.some(({ id, name }) => [id, name].some(value => value && normalize(value).length > 2 && text.includes(` ${normalize(value)} `)))) return null;
    return generalQuestion.test(input) ? { mode: "knowledge", diagram } : null;
  }

  function renderMode(selected) {
    const [mode, de, en] = modes.find(([id]) => id === selected) || modes[0];
    const label = t("Fragebereich", "Question scope");
    const title = `${label} · ${t(de, en)}`;
    return `<details class="chat-question-mode" data-chat-menu="scope">
      <summary class="button" aria-label="${title}" title="${title}" data-selected="${mode !== "auto"}">
        <span aria-hidden="true">+</span>
      </summary>
      <div class="zorec-chat-menu-panel" role="group" aria-label="${label}">
        <p class="chat-question-mode-label">${label}</p>
        ${modes.map(([id, german, english]) => `<button type="button" class="text-button"
          data-question-mode="${id}" aria-pressed="${id === mode}">${t(german, english)}</button>`).join("")}
      </div>
    </details>`;
  }

  function sourceLinks(items) {
    if (!Array.isArray(items)) return [];
    return items.flatMap(item => {
      if (typeof item?.title !== "string" || !item.title.trim() || typeof item.url !== "string") return [];
      try {
        const url = new URL(item.url);
        if (url.protocol !== "https:" || !["de.wikipedia.org", "en.wikipedia.org"].includes(url.host)
          || !url.pathname.startsWith("/wiki/") || url.username || url.password || url.search || url.hash) return [];
        return [{ title: item.title.slice(0, 100), url: url.href }];
      } catch { return []; }
    }).slice(0, 3);
  }

  function diagramDraft(result, previous) {
    if (typeof result?.title !== "string" || !result.title.trim() || !Array.isArray(result.steps)
      || result.steps.length < 3 || result.steps.length > 6 || result.steps.some(step => typeof step !== "string" || !step.trim())) return null;
    return { kind: "activity", title: result.title.slice(0, 100), steps: result.steps.map(step => step.slice(0, 64)),
      revision: (previous?.steps ? previous.revision : 0) + 1 };
  }

  window.opstendZorecKnowledge = { resolve, renderMode, modeIds, sourceLinks, diagramDraft };
})();
