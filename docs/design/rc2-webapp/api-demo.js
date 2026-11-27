(function () {
  "use strict";

  const shells = { "admin-read": "Admin Lesen", "admin-edit": "Admin Edit", report: "Berichte" };
  const roles = { "admin-read": "operator", "admin-edit": "operator-edit", report: "report" };
  const base = "/api/v1";
  const action = "sensorik.health-check";
  let shell = "admin-read";
  let session = null;
  let directToken = "";
  let source = "direct";
  const runs = { direct: {}, chat: {} };
  let response = null;
  let busy = false;
  let generation = 0;

  function canEdit() {
    return window.opstendZorecPolicy.get()["admin-edit"].enabled;
  }

  function render(state) {
    const esc = state.escape;
    const hosted = location.protocol === "http:" || location.protocol === "https:";
    const available = hosted && !busy;
    const gate = (condition) => condition ? "" : "disabled";
    const responseText = response?.payload ? JSON.stringify(response.payload, null, 2) : "";
    const selectedRun = runs[source];
    const viaChat = source === "chat";
    return `<div class="api-demo" data-api-demo>
      <div class="api-demo-layout">
        <section class="panel" aria-labelledby="api-demo-chat">
          <div class="panel-head"><div><h2 id="api-demo-chat">Chat und Shell</h2><p>Lokale API-Testidentitäten</p></div></div>
          <form class="api-demo-form" data-api-form="start">
            <label for="api-demo-shell">Shell</label>
            <select id="api-demo-shell" name="shell" ${gate(available)}>${Object.entries(shells).map(([id, title]) =>
              `<option value="${id}" ${shell === id ? "selected" : ""} ${id === "admin-edit" && !canEdit() ? "disabled" : ""}>${title}</option>`).join("")}</select>
            <button type="submit" class="button primary" ${gate(available)}>Chat öffnen</button>
            ${!canEdit() ? '<p class="compact">Admin Edit lässt sich unter Zorec und KI aktivieren.</p>' : ""}
          </form>
          ${session ? `<div class="api-demo-identity">
            <dl class="info-list"><div><dt>Chat-ID</dt><dd class="mono">${esc(session.chatId)}</dd></div>
              <div><dt>Gebundene Shell</dt><dd>${esc(shells[session.shell])}</dd></div></dl>
            <form class="api-demo-form api-message" data-api-form="message">
              <label for="api-demo-message">Nachricht</label>
              <input id="api-demo-message" name="text" placeholder="Wie ist der Betriebsstatus?" maxlength="240" required>
              <div class="service-tools">
                <button type="submit" class="button primary" ${gate(available)}>Senden</button>
                <button type="button" class="button" data-api-action="chat-events" ${gate(available)}>Chat-Ereignisse laden</button>
              </div>
            </form>
          </div>` : ""}
        </section>
        <section class="panel" aria-labelledby="api-demo-action">
          <div class="panel-head"><div><h2 id="api-demo-action">Feste Systemaktion</h2><p>Sensorik · Health-Prüfung</p></div></div>
          <div class="panel-pad">
            <div class="tabs" role="group" aria-label="Aufrufweg">
              <button type="button" data-api-source="direct" aria-pressed="${!viaChat}" ${gate(available)}>Direkt per API</button>
              <button type="button" data-api-source="chat" aria-pressed="${viaChat}" ${gate(available)}>Mit Zorec-Chat</button>
            </div>
            <p class="compact api-demo-source">${viaChat
              ? session ? `${esc(shells[session.shell])} · ${session.shell === "admin-edit" ? "Diese Chat-ID kann einen Plan anlegen." : "Die API lehnt Aktionspläne für diese Shell ab."}`
                : "Öffne zuerst einen Chat. Aktionspläne erfordern Admin Edit."
              : "Ein eigenes Testkonto darf diese Systemaktion ohne Chat-ID aufrufen."}</p>
            ${selectedRun.planId ? `<dl class="info-list api-plan-preview"><div><dt>${selectedRun.jobId ? "Auftrag simuliert" : "Plan zur Bestätigung"}</dt>
              <dd class="mono">${esc(selectedRun.jobId || selectedRun.planId)}</dd></div></dl>` : ""}
            <div class="service-tools api-demo-actions">
              <button type="button" class="button" data-api-action="plan" ${gate(available && (!viaChat || session))}>Health-Prüfung planen</button>
              ${selectedRun.planId ? `<button type="button" class="button primary" data-api-action="confirm" ${gate(available)}>Plan bestätigen</button>` : ""}
              ${selectedRun.jobId ? `<button type="button" class="button" data-api-action="job" ${gate(available)}>Auftrag abrufen</button>` : ""}
            </div>
          </div>
        </section>
      </div>
      <section class="panel api-response" aria-labelledby="api-demo-response">
        <div class="panel-head"><div><h2 id="api-demo-response" tabindex="-1">HTTP-Antwort</h2>
          <p role="status">${!hosted ? "Die Testanfragen sind im lokalen Demo-Server verfügbar."
            : busy ? "Anfrage läuft …" : response ? `${esc(response.method)} ${esc(response.path)} · HTTP ${esc(response.status)}`
            : "Noch keine Anfrage angezeigt."}</p></div></div>
        ${responseText ? `<pre tabindex="0" aria-label="JSON-Antwort">${esc(responseText)}</pre>` : ""}
      </section>
    </div>`;
  }

  async function request(path, { method = "GET", body, token, bootstrap = false } = {}, current, scope) {
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (token) headers.Authorization = "Bearer " + token;
    if (bootstrap) headers["X-OpsTend-Demo"] = "1";
    const result = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const payload = await result.json();
    if (!current()) return null;
    if (!bootstrap || !result.ok) response = { path: base + path, method, status: result.status, payload, scope };
    if (scope === "direct" && result.status === 401) {
      directToken = "";
      runs.direct = {};
    }
    return result.ok ? payload : null;
  }

  function refresh() {
    if (document.querySelector("[data-api-demo]")) window.dispatchEvent(new CustomEvent("opstend:inventory-changed"));
  }

  async function run(scope, operation, nextSelector) {
    if (busy) return;
    const started = generation;
    const current = () => scope === "direct" || started === generation;
    busy = true;
    response = null;
    refresh();
    try {
      await operation((path, options) => request(path, options, current, scope));
    } catch {
      if (current()) {
        response = { method: "API", path: base, status: "offen", scope, payload: { error: "Die lokale Demo-API ist gerade nicht erreichbar." } };
      }
    } finally {
      busy = false;
      refresh();
      const next = response?.status < 400 && nextSelector ? document.querySelector(nextSelector) : null;
      (next || document.getElementById("api-demo-response"))?.focus();
    }
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    const kind = form.dataset.apiForm;
    if (!kind) return;
    event.preventDefault();
    const fields = new FormData(form);
    if (kind === "start") {
      const chosen = fields.get("shell");
      if (!Object.hasOwn(shells, chosen) || (chosen === "admin-edit" && !canEdit())) return;
      shell = chosen;
      session = null;
      runs.chat = {};
      void run("chat", async (request) => {
        const credentials = await request("/demo/sessions", { method: "POST", body: { role: roles[chosen] }, bootstrap: true });
        if (!credentials || (chosen === "admin-edit" && !canEdit())) return;
        const chat = await request("/chats", { method: "POST", body: { shell: chosen }, token: credentials.token });
        if (chat && (chosen !== "admin-edit" || canEdit())) session = { ...chat, token: credentials.token };
      }, "#api-demo-message");
    } else if (kind === "message" && session) {
      const { chatId, token } = session;
      const text = String(fields.get("text") || "").trim();
      if (text) void run("chat", (request) => request(`/chats/${chatId}/messages`, {
        method: "POST", body: { messageId: crypto.randomUUID(), text }, token,
      }));
    }
  });

  document.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-api-source], button[data-api-action]");
    if (!button || busy) return;
    if (button.dataset.apiSource) {
      source = button.dataset.apiSource;
      if (response?.scope !== source) response = null;
      refresh();
      document.querySelector(`[data-api-source="${source}"]`)?.focus();
      return;
    }
    const step = button.dataset.apiAction;
    if (step === "chat-events") {
      if (!session) return;
      const { chatId, token } = session;
      void run("chat", (request) => request(`/chats/${chatId}/events`, { token }));
      return;
    }
    const viaChat = source === "chat";
    if (viaChat && !session) return;
    const selectedRun = runs[source];
    const token = viaChat ? session.token : directToken;
    if (step === "plan") void run(source, async (request) => {
      const selection = {};
      runs[source] = selection;
      if (!viaChat && !directToken) {
        const credentials = await request("/demo/sessions", { method: "POST", body: { role: "automation" }, bootstrap: true });
        if (!credentials) return;
        directToken = credentials.token;
      }
      const body = { target: "sensorik" };
      if (viaChat) body.chatId = session.chatId;
      const plan = await request(`/actions/${action}/plans`, { token: viaChat ? token : directToken, method: "POST", body });
      if (plan) selection.planId = plan.planId;
    }, '[data-api-action="confirm"]');
    if (step === "confirm" && selectedRun.planId) void run(source, async (request) => {
      const job = await request(`/plans/${selectedRun.planId}/confirm`, { token, method: "POST", body: {} });
      if (job) selectedRun.jobId = job.jobId;
    }, '[data-api-action="job"]');
    if (step === "job" && selectedRun.jobId) void run(source, (request) => request(`/jobs/${selectedRun.jobId}`, { token }));
  });

  window.addEventListener("opstend:zorec-policy-changed", () => {
    if (shell === "admin-edit" && !canEdit()) {
      generation += 1;
      shell = "admin-read";
      session = null;
      runs.chat = {};
      if (response?.scope === "chat") response = null;
    }
    refresh();
  });

  window.opstendApiDemo = { render };
})();
