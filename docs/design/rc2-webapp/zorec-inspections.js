(function () {
  "use strict";

  const timeSync = "service.time-sync";
  const maxOffsetMs = 100;
  const probeResults = new Map([
    ["medien", { host: "nuc-a", source: "guest", synchronized: true, offsetMs: 12 }],
    ["entwicklung", { host: "nuc-a", source: "guest", synchronized: false, offsetMs: 426 }],
    ["sensorik", { host: "host-b", source: "host", synchronized: true, offsetMs: 4 }],
    ["zeitdienst", { host: "host-b", source: "host", synchronized: true, offsetMs: 4 }],
    ["https-proxy", { host: "edge-01", source: "host", synchronized: false, offsetMs: 267 }],
    ["control-b", { host: "host-b", source: "host", synchronized: true, offsetMs: 4 }],
    ["control-c", { host: "nuc-c", source: "host" }],
    ["web", { host: "nuc-c", source: "host", synchronized: true, offsetMs: -8 }],
    ["zorec", { host: "host-b", source: "host", synchronized: true, offsetMs: 4 }],
    ["ipa", { host: "nuc-a", source: "host" }],
  ]);

  function selectedServices(context, state) {
    return state.inventory.services.filter(service => (!state.host || service.host === state.host)
      && (!context.host || service.host === context.host) && (!context.service || service.id === context.service.id));
  }

  function normalize(question) {
    return String(question).normalize("NFKC").toLocaleLowerCase("de").replace(/[^\p{L}\p{N}]+/gu, " ").trim();
  }

  function match(question) {
    const input = normalize(question);
    const explanatory = /^(?:was bedeutet|was heißt|wie funktioniert|wie viel zeit|what does .* mean|how does|how much time|explain|erklär\p{L}*)\b/u.test(input);
    const localReference = /\b(?:hier|aktuell\p{L}*|unser\p{L}*|our|current|here|auf (?:diesem|diesen|allen)|on (?:this|these|all))\b/u.test(input);
    const generallyAsked = /^(?:was ist|what is|warum|wozu|why|wie kann (?:ich|man)|how (?:can i|do i|to))\b/.test(input);
    if (explanatory || (generallyAsked && !localReference)) return null;
    const target = /\b(?:dienst(?:en?)?|services?|hosts?|maschinen?|containers?|vms?|system(?:en?)?|servers?|nodes?|gästen?|guests?|flotte|fleet|knoten)\b/.test(input);
    const check = /\b(?:\p{L}*pr(?:ü|ue)f\p{L}*|kontrollier\p{L}*|verifiz\p{L}*|ausles\p{L}*|check\p{L}*|verify|inspect|test|show)\b/u.test(input);
    const statusQuestion = /^(?:ist|sind|haben|hat|gehen|geht|stimmen|stimmt|laufen|läuft|gleich(?:t|en)|is|are|do|does|was (?:sagt|meldet)|wie (?:steht|groß)|how (?:well|far))\b/.test(input)
      || /\b(?:status|abweichung|offsets?)\b/.test(input);
    const namedCheck = /zeitsync|zeitabgleich|zeitversatz|zeitabweich|zeitdrift|time sync|clock sync|clock drift|clock offset|\b(?:ntp|chrony)\b/.test(input);
    const clock = /\b(?:(?:system|uhr)?zeit(?:en|lich)?|(?:system)?uhr(?:en)?|times?|clocks?)\b/.test(input);
    const sync = /(?:^| )(?:gesync\p{L}*|sync\p{L}*|gleich|überein|auseinander|agree|aligned)(?: |$)/u.test(input);
    const sameClock = /\b(?:gleiche[nr]?|dieselbe[nr]?|same) (?:system )?(?:(?:system|uhr)zeit(?:en)?|(?:system)?uhr(?:en)?|clocks?)\b/.test(input);
    const alignsClock = /\bgleich(?:t|en)\b.*\bab\b/.test(input);
    return (target || check || statusQuestion || localReference) && (namedCheck || sameClock || clock && (sync || alignsClock)) ? timeSync : null;
  }

  function isConfirmation(question) {
    const input = normalize(question);
    return /^(?:ja )?(?:bitte )?(?:(?:über|nach)?pr(?:ü|ue)f(?:e|en)?|kontrollier(?:e|en)?|untersuch(?:e|en)?)(?: (?:das|es|sie))?(?: bitte)?$/u.test(input)
      || /^(?:kannst du|könntest du) (?:das|es|sie) (?:bitte )?(?:über|nach)?pr(?:ü|ue)fen$/u.test(input)
      || /^(?:yes )?(?:please )?(?:check|verify|inspect)(?: (?:it|that|them|the clocks?))?(?: please)?$/.test(input);
  }

  function action(id) {
    if (id !== timeSync) return null;
    const ui = window.opstendLocale.t;
    return { label: ui("Zeitsynchronisation prüfen", "Check time synchronization"), inspection: id };
  }

  function readProbe(service, reply) {
    const probe = probeResults.get(service.id);
    if (!probe || probe.host !== service.host) {
      return { state: "unsupported", text: reply("Für diese Platzierung ist keine Zeitprobe registriert.", "No clock probe is registered for this placement.") };
    }
    const source = probe.source === "guest" ? reply("chrony im Gast", "chrony in the guest") : reply("chrony · Hostuhr", "chrony · host clock");
    if (window.opstendDemo.serviceRuntime(service) !== "running" || !Number.isFinite(probe.offsetMs)) {
      return { state: "unknown", text: `${reply("Kein Messwert verfügbar", "No reading available")} · ${source}` };
    }
    const passed = probe.synchronized && Math.abs(probe.offsetMs) <= maxOffsetMs;
    const status = passed ? reply("Synchronisiert", "Synchronized") : reply("Abweichung", "Out of sync");
    const offset = `${probe.offsetMs > 0 ? "+" : ""}${probe.offsetMs} ms`;
    return { state: passed ? "synced" : "drift", text: `${status} · ${offset} · ${source}` };
  }

  function resolve(question, context, state, reply) {
    const id = match(question);
    if (!id) return null;
    const ui = window.opstendLocale.t;
    const count = selectedServices(context, state).length;
    const host = context.host || state.host;
    const describeTarget = translate => {
      if (context.service) return `${context.service.name} (${context.service.host})`;
      const de = `${count} ${count === 1 ? "Dienst" : "Dienste"}`;
      const en = `${count} ${count === 1 ? "service" : "services"}`;
      return host ? translate(`${de} auf ${host}`, `${en} on ${host}`) : translate(`${de} in der Flotte`, `${en} in the fleet`);
    };
    const target = describeTarget(reply);
    return {
      ruleOnly: true,
      text: count ? reply(`Im aktuellen Dienststatus fehlen Zeitmesswerte. Soll ich die simulierten Zeitproben für ${target} auswerten?`,
        `The current service status is missing clock readings. Should I review the simulated clock probes for ${target}?`)
        : reply("Im ausgewählten Bereich sind keine Dienste erfasst.", "No services are registered in the selected scope."),
      activity: [ui("Zeitbelege einordnen", "Identify clock evidence"), count ? describeTarget(ui) : context.label],
      actions: count ? [action(id)] : [],
    };
  }

  function run(id, context, state, reply) {
    if (id !== timeSync) return null;
    const ui = window.opstendLocale.t;
    const counts = { synced: 0, drift: 0, unknown: 0, unsupported: 0 };
    const rows = selectedServices(context, state).map(service => {
      const result = readProbe(service, reply);
      counts[result.state] += 1;
      return `${service.name} (${service.host}) · ${result.text}`;
    });
    const { synced, drift, unknown, unsupported } = counts;
    const summary = reply(`${synced} synchronisiert · ${drift} mit Abweichung · ${unknown} ohne Messwert · ${unsupported} ohne registrierte Probe`,
      `${synced} synchronized · ${drift} out of sync · ${unknown} without readings · ${unsupported} without registered probes`);
    const verdict = drift ? reply("Die Probe zeigt Zeitabweichungen.", "The check found clock drift.")
      : unknown + unsupported ? reply("Die Zeitsynchronisation ist teilweise unbelegt.", "Time synchronization is only partly verified.")
        : reply("Alle ausgewählten Dienste sind im Beispiel synchronisiert.", "All selected services are synchronized in the sample.");
    return {
      ruleOnly: true,
      text: rows.length ? [verdict, summary, reply(`Simulierte Zeitproben mit einer Toleranz von ±${maxOffsetMs} ms.`,
        `Simulated clock probes with a tolerance of ±${maxOffsetMs} ms.`), "", ...rows].join("\n")
        : reply("Im ausgewählten Bereich sind keine Dienste erfasst.", "No services are registered in the selected scope."),
      activity: [ui("Zeitproben auslesen", "Read clock probes"), ui(`${rows.length} Dienste · simulierte Leseprüfung`, `${rows.length} services · simulated read-only check`)],
      actions: [],
    };
  }

  window.opstendZorecInspections = { action, isConfirmation, match, resolve, run };
})();
