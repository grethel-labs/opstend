(function () {
  "use strict";

  const sleepAfter = 45_000;
  const recoveryDuration = 15_000;
  const offlineStates = new Set(["Offline", "Ausgefallen", "Nicht erreichbar"]);
  const t = window.opstendLocale.t;
  let state;
  let quietSince = null;
  let previousRecovery = null;
  let recoveryUntil = 0;
  let timer = 0;

  function statusFor(snapshot, now) {
    const hosts = snapshot.inventory.hosts.filter((host) => !snapshot.host || host.id === snapshot.host);
    const services = snapshot.inventory.services.filter((service) => !snapshot.host || service.host === snapshot.host);
    const attention = window.opstendViews.attention(snapshot);
    const sensor = services.find((service) => service.id === "sensorik");
    const recovery = window.opstendDemo.recoveryFor(sensor);
    if (recovery?.phase === "healthy" && previousRecovery?.phase === "pending") {
      const observedAt = Date.parse(recovery.events.at(-1)?.at);
      if (Number.isFinite(observedAt)) recoveryUntil = observedAt + recoveryDuration;
    }
    previousRecovery = recovery;
    if (recovery?.phase !== "healthy") recoveryUntil = 0;

    const faults = new Map();
    for (const host of hosts) {
      if (offlineStates.has(host.status)) faults.set(`host:${host.id}`, "offline");
      else if (host.status === "Warnung") faults.set(`host:${host.id}`, "warning");
    }
    for (const service of services) {
      if (offlineStates.has(service.status)) faults.set(`service:${service.id}`, "offline");
      else if (service.status === "Warnung") faults.set(`service:${service.id}`, "warning");
    }
    const incidents = attention.filter((job) => job.attention.kind === "incident");
    for (const job of incidents) {
      if (job.tone === "active") continue;
      const key = job.serviceId ? `service:${job.serviceId}` : `job:${job.id}`;
      if (!faults.has(key)) faults.set(key, "warning");
    }

    if (faults.size > 1) return { mood: "critical", label: t(`${faults.size} Störungen offen`, `${faults.size} open incidents`) };
    if (faults.size === 1) {
      if (faults.values().next().value === "offline") return { mood: "offline", label: t("1 Ziel offline", "1 target offline") };
      return { mood: "warning", label: t("1 Störung offen", "1 open incident") };
    }
    if (incidents.some((job) => job.tone === "active")) return { mood: "working", label: t("Prüfung läuft", "Check in progress") };
    if (attention.some((job) => job.attention.kind === "decision")) return { mood: "approval", label: t("Entscheidung offen", "Decision pending") };
    if (hosts.some((host) => host.status === "Wartung")) return { mood: "maintenance", label: t("Wartung aktiv", "Maintenance active") };
    if (recoveryUntil > now) return { mood: "recovered", label: t("Wiederhergestellt", "Recovered"), refreshAt: recoveryUntil };
    return { mood: "quiet", label: t("Ruhiger Betrieb", "Normal operation") };
  }

  function refresh() {
    if (!state) return;
    const launcher = document.querySelector(".zorec-launcher");
    clearTimeout(timer);
    const now = Date.now();
    let next = statusFor(state, now);
    if (next.mood !== "quiet" || document.getElementById("zorec-dialog")?.open) {
      quietSince = null;
    } else {
      quietSince ??= now;
      const sleepAt = quietSince + sleepAfter;
      next = sleepAt <= now ? { ...next, mood: "sleepy" } : { ...next, refreshAt: sleepAt };
    }
    launcher.dataset.mood = next.mood;
    launcher.querySelector(".zorec-mascot").dataset.mood = next.mood;
    const caption = launcher.querySelector("#zorec-launcher-status");
    if (caption.textContent !== next.label) caption.textContent = next.label;
    launcher.title = `${state.host || t("Ganze Flotte", "Entire fleet")} · ${next.label}`;
    if (next.refreshAt) timer = setTimeout(refresh, Math.max(1, next.refreshAt - now));
  }

  function mount(current) {
    const root = document.getElementById("zorec-launcher-root");
    if (!root.firstChild) {
      root.innerHTML = `<button type="button" class="zorec-launcher" data-open-zorec
        aria-haspopup="dialog" aria-describedby="zorec-launcher-status">
        ${window.opstendMascot.render("neutral", { follow: true, mood: "quiet" })}
        <span class="zorec-launcher-copy"><strong></strong><small id="zorec-launcher-status"></small></span>
      </button>`;
    }
    const label = t("Zorec fragen", "Ask Zorec");
    root.firstElementChild.setAttribute("aria-label", label);
    root.querySelector(".zorec-launcher-copy strong").textContent = label;
    if (state?.host !== current.host) {
      quietSince = null;
      previousRecovery = null;
      recoveryUntil = 0;
    }
    state = current;
    refresh();
  }

  window.opstendZorecStatus = { mount, refresh };
})();
