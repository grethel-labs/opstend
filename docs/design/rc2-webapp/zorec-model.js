(function () {
  "use strict";

  let config = { configured: false, model: null, research: false };
  const hosted = location.protocol === "http:" || location.protocol === "https:";
  const status = hosted ? fetch("/api/v1/demo/model").then(async (response) => {
    if (!response.ok) return config;
    const payload = await response.json();
    if (payload.configured === true && typeof payload.model === "string") config = payload;
    window.dispatchEvent(new Event("opstend:demo-model-config"));
    return config;
  }).catch(() => config) : Promise.resolve(config);

  const label = () => config.configured ? `cn-0001 · ${config.model}` : "Demo-Assistent verfügbar";

  async function discover() {
    const current = await status;
    const error = "Die Modell-API konnte gerade nicht verifiziert werden.";
    try {
      const response = await fetch("/api/v1/demo/models", { headers: { "X-OpsTend-Demo": "1" } });
      if (response.ok) return await response.json();
    } catch {}
    return { models: [], activeModel: current.model, error };
  }

  async function ask(question, context, history, model, language = "de", { mode = "context", diagram = false } = {}) {
    const message = (de, en) => language === "en" ? en : de;
    const current = await status;
    if (!current.configured) return { error: message("Das lokale Modell ist in dieser Demo-Instanz nicht verbunden.", "This demo instance has no connection to the local model.") };
    try {
      const response = await fetch("/api/v1/demo/ask", {
        method: "POST", headers: { "Content-Type": "application/json", "X-OpsTend-Demo": "1" },
        body: JSON.stringify({ question, language, mode, diagram, ...(model ? { model } : {}),
          ...(mode === "context" ? { context, history } : mode === "knowledge" ? { history } : {}) }),
      });
      if (response.status === 429) return { error: message("Das lokale Modell bearbeitet gerade eine andere Anfrage.", "The local model is processing another request.") };
      if (!response.ok) return { error: message("Das lokale Modell konnte gerade keine Antwort liefern.", "The local model could not provide an answer.") };
      const result = await response.json();
      return { reply: result.reply, model: result.model, diagram: result.diagram,
        sources: result.sources, researchStatus: result.researchStatus };
    } catch {
      return { error: message("Die Verbindung zum lokalen Modell ist unterbrochen.", "The connection to the local model was interrupted.") };
    }
  }

  window.opstendDemoModel = { status, label, ask, discover };
})();
