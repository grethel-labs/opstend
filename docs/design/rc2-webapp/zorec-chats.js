(function () {
  "use strict";

  const key = "opstend-rc2-zorec-chats-v1";
  const defaultLimit = 10;
  const maxLimit = 50;
  const turnLimit = 24;
  const groups = ["admin", "report"];
  const shells = ["admin-read", "admin-edit", "report"];
  const blank = mode => ({ id: crypto.randomUUID(), mode, turns: [], diagrams: {} });
  const text = (value, limit) => typeof value === "string" ? value.slice(0, limit) : "";

  function scope(shell, policy = window.opstendZorecPolicy.get()) {
    if (shell === "report") {
      return JSON.stringify([window.opstendZorecPolicy.effectiveReportData(policy), policy.report.internet]);
    }
    if (shell === "admin-edit" && !policy[shell].enabled) return null;
    return JSON.stringify(policy[shell]);
  }

  function scopes() {
    const policy = window.opstendZorecPolicy.get();
    return Object.fromEntries(shells.map(shell => [shell, scope(shell, policy)]));
  }

  function validTurn(turn, group, access) {
    return shells.includes(turn?.shell) && (turn.shell === "report") === (group === "report")
      && typeof turn.scope === "string" && turn.scope === access[turn.shell];
  }

  function transcriptTurn(turn) {
    const interrupted = turn.run?.status === "running";
    const language = turn.language === "en" ? "en" : "de";
    return {
      id: turn.id,
      shell: turn.shell,
      scope: turn.scope,
      language,
      question: text(turn.question, 240),
      questionMode: turn.questionMode === "knowledge" ? "knowledge" : "system",
      researchStatus: text(turn.researchStatus, 20),
      sources: Array.isArray(turn.sources) ? turn.sources.slice(0, 3).filter(Boolean)
        .map(({ title, url }) => ({ title: text(title, 100), url: text(url, 300) })) : [],
      context: text(turn.context, 160),
      host: text(turn.host, 80),
      ...(window.opstendZorecInspections.action(turn.inspectionOffer?.id) ? {
        inspectionOffer: { id: turn.inspectionOffer.id, subject: text(turn.inspectionOffer.subject, 80) },
      } : {}),
      text: interrupted ? (language === "en" ? "This reply was interrupted." : "Diese Antwort wurde unterbrochen.") : text(turn.text, 2400),
      run: {
        status: interrupted || turn.run?.status === "error" ? "error" : "done",
        gesture: interrupted ? "neutral" : text(turn.run?.gesture, 32),
        shellLabel: text(turn.run?.shellLabel, 32),
        context: text(turn.context, 160),
        steps: Array.isArray(turn.run?.steps) && !interrupted
          ? turn.run.steps.slice(0, 6).filter(Boolean).map(step => ({
            state: text(step.state, 12), label: text(step.label, 120), detail: text(step.detail, 400),
          })) : [],
      },
    };
  }

  function load() {
    try { return JSON.parse(localStorage.getItem(key) || "null"); }
    catch { return null; }
  }

  const saved = load();
  const initialAccess = scopes();
  const allowedMode = (value, access) => value === "admin-edit" && access["admin-edit"] !== null
    ? "admin-edit" : "admin-read";
  let limit = Number.isInteger(saved?.limit) && saved.limit >= 0 && saved.limit <= maxLimit ? saved.limit : defaultLimit;
  let storageError = false;
  const chats = Object.fromEntries(groups.map(group => {
    const ids = new Set();
    const entries = Array.isArray(saved?.[group]) ? saved[group].slice(0, limit + 1) : [];
    const restored = entries.filter(entry => {
      if (!/^[a-f0-9-]{36}$/.test(entry?.id) || ids.has(entry.id)) return false;
      ids.add(entry.id);
      return true;
    }).map(entry => ({
      id: entry.id, mode: group === "admin" ? allowedMode(entry.mode, initialAccess) : "report", diagrams: {},
      turns: Array.isArray(entry.turns) ? entry.turns.slice(-turnLimit)
        .filter(turn => Number.isSafeInteger(turn?.id) && turn.id > 0 && validTurn(turn, group, initialAccess))
        .map(turn => ({ ...transcriptTurn(turn), actions: [] })) : [],
    }));
    return [group, restored.length ? restored : [blank(group === "admin" ? "admin-read" : "report")]];
  }));

  function save() {
    const data = { limit };
    const access = scopes();
    for (const group of groups) {
      const [current, ...older] = chats[group];
      chats[group] = [current, ...older.filter(chat => chat.turns.length)].slice(0, limit + 1);
      data[group] = chats[group].map(chat => ({
        id: chat.id, mode: chat.mode, turns: chat.turns.filter(turn => validTurn(turn, group, access)).map(transcriptTurn),
      }));
    }
    try {
      localStorage.setItem(key, JSON.stringify(data));
      storageError = false;
    } catch { storageError = true; }
  }

  function select(group, chat) {
    chats[group] = [chat, ...chats[group].filter(entry => entry !== chat)];
    if (group === "admin") chat.mode = allowedMode(chat.mode, scopes());
    save();
  }

  function invalidate() {
    const access = scopes();
    for (const group of groups) {
      for (const chat of chats[group]) {
        if (group === "admin") chat.mode = allowedMode(chat.mode, access);
        chat.turns.splice(0, chat.turns.length, ...chat.turns.filter(turn => validTurn(turn, group, access)));
        for (const shell of shells) {
          if (chat.diagrams[shell]?.scope !== access[shell]) delete chat.diagrams[shell];
        }
      }
    }
    save();
  }

  window.opstendZorecChats = {
    get limit() { return limit; },
    get mode() { return chats.admin[0].mode; },
    get storageError() { return storageError; },
    maxLimit,
    scope,
    save,
    invalidate,
    list: group => chats[group],
    contains: (group, chat) => chats[group].includes(chat),
    start: group => select(group, blank(chats[group][0].mode)),
    restore(group, id) {
      const chat = chats[group].find(entry => entry.id === id);
      if (chat) select(group, chat);
    },
    setMode(shell) {
      if (shell !== "admin-read" && (shell !== "admin-edit" || scope(shell) === null)) return;
      chats.admin[0].mode = shell;
      save();
    },
    setLimit(value) {
      if (!Number.isInteger(value) || value < 0 || value > maxLimit) return;
      limit = value;
      save();
    },
  };
})();
