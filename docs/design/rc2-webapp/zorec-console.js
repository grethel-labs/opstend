(function () {
  "use strict";

  const consoles = new Map();
  const commands = {
    hostname: (target) => target.name,
    "ip -brief address": (target) => target.ip ? `IPv4 · ${target.ip}` : "IPv4-Adresse im Demo-Inventar offen.",
    status: (target) => target.status,
  };
  const mention = /^@(zorec|chat)(?:\s+|:\s*|$)/i;
  const inputSelector = "[data-zorec-console-input]";

  function targetId(state, config) {
    return state.view === "service" ? `service:${state.serviceId}` : `host:${state.host || config.name}`;
  }

  function render(state, config, id) {
    const [kind, key] = id.split(":");
    const objects = kind === "service" ? state.inventory.services : state.inventory.hosts;
    const item = objects.find((object) => object.id === key);
    if (!item) return "";

    const record = consoles.get(id) || { value: "", prepared: false, history: [], notice: "" };
    record.target = { name: config.name, ip: item.ip, status: item.status || state.hosts?.[key]?.status || "Im Inventar erfasst" };
    record.lines = config.lines;
    consoles.set(id, record);
    const esc = state.escape;
    return `<pre tabindex="0" data-zorec-console-log aria-label="Demo-Konsolenausgabe">${esc(output(record))}</pre>
      <form class="zorec-console-form" data-zorec-console-form>
        <label>Befehlszeile <input type="text" name="console-line" value="${esc(record.value)}" data-zorec-console-input
          ${record.prepared ? "data-zorec-console-prepared" : ""} maxlength="160" placeholder="@zorec Wie ist die IP?" autocomplete="off" spellcheck="false"></label>
        <button type="submit" class="button">In Demo senden</button>
      </form>
      <p class="zorec-console-notice" role="status" data-zorec-console-notice>${esc(record.notice || "@zorec oder @chat für Hilfe auf diesem Ziel")}</p>`;
  }

  function output(record) {
    return [...record.lines, ...record.history].join("\n");
  }

  function cardFor(id) {
    return [...document.querySelectorAll("[data-console-target]")].find((card) => card.dataset.consoleTarget === id);
  }

  function redraw(card, record) {
    for (const input of card.querySelectorAll(inputSelector)) {
      if (input.value !== record.value) input.value = record.value;
      input.toggleAttribute("data-zorec-console-prepared", record.prepared);
    }
    const contents = output(record);
    for (const log of card.querySelectorAll("[data-zorec-console-log]")) {
      if (log.textContent !== contents) {
        log.textContent = contents;
        log.scrollTop = log.scrollHeight;
      }
    }
    const message = record.notice || "@zorec oder @chat für Hilfe auf diesem Ziel";
    for (const notice of card.querySelectorAll("[data-zorec-console-notice]")) {
      if (notice.textContent !== message) notice.textContent = message;
    }
  }

  function stage(record, command) {
    record.value = command;
    record.prepared = true;
    record.notice = "Von Zorec vorbereitet. Du kannst die Zeile bearbeiten und in der Demo senden.";
  }

  function prepare({ targetId, command }) {
    if (!Object.hasOwn(commands, command)) return false;
    const card = cardFor(targetId);
    const record = consoles.get(targetId);
    if (!card || !record) return false;

    window.opstendObjectUi.setConsoleMode(card, "terminal");
    if (record.value.trim() && record.value !== command) {
      record.notice = "In dieser Konsole ist bereits eine Zeile offen.";
      redraw(card, record);
      return false;
    }
    stage(record, command);
    redraw(card, record);
    const current = card.querySelector("dialog[open]") || card;
    current.querySelector(inputSelector)?.focus();
    return true;
  }

  function help(question) {
    if (/\bip\b|ipv4|netz|adresse/i.test(question)) return "ip -brief address";
    if (/hostname|rechnername/i.test(question)) return "hostname";
    if (/status|health|zustand/i.test(question)) return "status";
    return "";
  }

  document.addEventListener("input", (event) => {
    if (!event.target.matches(inputSelector)) return;
    const card = event.target.closest("[data-console-target]");
    const record = consoles.get(card.dataset.consoleTarget);
    record.value = event.target.value;
    if (!record.value) {
      record.prepared = false;
      record.notice = "";
    }
    redraw(card, record);
  });

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!form.hasAttribute("data-zorec-console-form")) return;
    event.preventDefault();
    const card = form.closest("[data-console-target]");
    const record = consoles.get(card.dataset.consoleTarget);
    const input = form.querySelector(inputSelector);
    const value = input.value.trim();
    if (!value) return;

    record.value = "";
    record.prepared = false;
    if (mention.test(value)) {
      const suggestion = help(value.replace(mention, ""));
      record.history.push(suggestion ? `Zorec · ${record.target.name} · ${suggestion} vorbereitet.`
        : `Zorec · ${record.target.name} · Frag nach IP, Hostname oder Status.`);
      if (suggestion) stage(record, suggestion);
      else record.notice = "Zorec hat im Konsolenverlauf geantwortet.";
    } else if (Object.hasOwn(commands, value)) {
      record.history.push(`> ${value}\nDemo-Ausgabe · ${commands[value](record.target)}`);
      record.notice = "Demo-Ausgabe im Verlauf ergänzt.";
    } else {
      record.notice = "Für diese Zeile gibt es keine Demo-Ausgabe. Frag @zorec nach passenden Beispielen.";
    }
    record.history = record.history.slice(-12);
    redraw(card, record);
    input.focus();
  });

  window.opstendZorecConsole = { targetId, render, prepare };
})();
