(function () {
  "use strict";

  const { t, ui } = window.opstendLocale;
  const autonomy = window.opstendAutonomy;
  const formats = Object.fromEntries([["de", "de-DE"], ["en", "en-GB"]].map(([id, locale]) => [id,
    new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Berlin" }),
  ]));
  const outcomes = {
    approved: ["Autonom freigegeben", "Approved automatically", "good"],
    started: ["Health-Nachprüfung angestoßen", "Health recheck started", "active"],
    review: ["Entscheidung offen", "Decision pending", "warn"],
    blocked: ["Gesperrt", "Blocked", "danger"],
  };
  let pending = false;
  let feedback = null;

  const localized = (value) => Array.isArray(value) ? t(value[0], value[1]) : value;

  function modeLabel({ enabled, effective }) {
    if (effective) return t("Wirksam · aktiv", "Effective · on");
    return enabled ? t("Wirksam · Berechtigung fehlt", "Effective · permission required") : t("Wirksam · aus", "Effective · off");
  }

  function modeState() {
    return { enabled: autonomy.get().enabled, eligible: autonomy.eligible(), effective: autonomy.effective() };
  }

  function instant(state, value) {
    const date = new Date(value);
    if (!value || !Number.isFinite(date.getTime())) return "";
    return `<time datetime="${state.escape(value)}">${state.escape(formats[ui()].format(date))}</time>`;
  }

  function notices(state, notice) {
    if (!notice) return "";
    const start = instant(state, notice.startAt);
    const end = instant(state, notice.endAt);
    if (!start || !end) return "";
    return `<div><dt>${t("Angekündigtes Wartungsfenster", "Announced maintenance window")}</dt><dd>${start} – ${end} · Europe/Berlin</dd></div>`;
  }

  function decisionBadge(state, run) {
    const [de, en, tone] = outcomes[run.outcome];
    return state.badge(t(de, en), tone);
  }

  function decisionDetails(state, run) {
    const entries = [
      [t("Ausgangslage", "Context"), run.context],
      [t("Auswirkung", "Impact"), run.impact],
      [t("Begründung", "Reason"), run.reason],
      [t("Quelle", "Source"), run.source],
      [t("Recherche", "Research"), run.research],
      [t("Nachweis", "Readback"), run.readback],
    ];
    return `<dl class="info-list">${entries.map(([label, value]) => {
      const detail = localized(value);
      return detail ? `<div><dt>${label}</dt><dd>${state.escape(detail)}</dd></div>` : "";
    }).join("")}${notices(state, run.notice)}</dl>`;
  }

  function recentDecisions(state, runs) {
    const recent = runs.toSorted((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, 8);
    return `<section class="panel" aria-labelledby="zorec-autonomy-history-title">
      <div class="panel-head"><h2 id="zorec-autonomy-history-title">${t("Letzte autonome Entscheidungen", "Recent autonomous decisions")}</h2></div>
      ${recent.length ? `<ul class="feed" role="list">${recent.map((run) => `<li><div><div class="service-tools">
          <strong>${state.escape(localized(run.title))}</strong>${decisionBadge(state, run)}</div>
          <p>${state.escape(run.host)} · ${instant(state, run.at)}</p>
          ${decisionDetails(state, run)}
          ${run.jobId ? `<div class="service-tools adapter-review-context"><button type="button" class="text-button" data-view="changes"
            data-host="${state.escape(run.host)}" data-job="${state.escape(run.jobId)}">${t("Auftrag öffnen", "Open job")}</button></div>` : ""}
        </div></li>`).join("")}</ul>` : `<p class="panel-pad compact">${t("In dieser Demo sind noch keine Entscheidungen erfasst.", "No decisions have been recorded in this demo yet.")}</p>`}
    </section>`;
  }

  function renderJob(state, job) {
    const run = autonomy.get().runs.find(({ jobId, host }) => jobId === job.id && host === job.host);
    if (!run) return "";
    return `<section class="manage-decision" aria-labelledby="zorec-autonomy-job-title">
      <h3 id="zorec-autonomy-job-title">${t("Zorecs Entscheidung", "Zorec’s decision")}</h3>
      <div class="service-tools">${decisionBadge(state, run)} ${instant(state, run.at)}</div>
      ${decisionDetails(state, run)}
    </section>`;
  }

  function render(state) {
    const mode = modeState();
    const title = t("Vollautonomer Modus", "Fully autonomous mode");
    return `<section class="panel manage-scope-detail" aria-labelledby="zorec-autonomy-title">
      <div class="manage-panel-heading"><div><h2 id="zorec-autonomy-title">${title}</h2>
        <p>${t("Flottenweite Einstellung · Standard aus", "Fleet-wide setting · Off by default")}</p></div></div>
      <div class="manage-form">
        <div class="zorec-shell-option"><label for="zorec-autonomy-enabled">
          <input type="checkbox" role="switch" id="zorec-autonomy-enabled" ${mode.enabled ? "checked" : ""}
            ${pending || !mode.eligible && !mode.enabled ? "disabled" : ""} aria-describedby="zorec-autonomy-mode zorec-autonomy-description zorec-autonomy-requirements">
          ${title}</label></div>
        <p id="zorec-autonomy-mode">${modeLabel(mode)}</p>
        <p id="zorec-autonomy-description">${t("Zorec prüft offene Vorgänge, solange die Demo geöffnet ist. Die Demo-Regeln erlauben die Freigabe einer vorgemerkten Hostwartung und eine einmalige Health-Nachprüfung für Sensorik. Offene Fälle stehen mit einer Begründung im Auftrag.",
          "Zorec checks open cases while the demo is open. The demo rules allow approval of planned host maintenance and one health recheck for Sensorik. Open cases show their reasoning in the job details.")}</p>
        <div id="zorec-autonomy-requirements" ${mode.eligible ? "hidden" : ""}>
          <p>${t("Aktiviere Admin Edit und „Für KI-Automationen zulassen“. Wähle beim Schreibumfang mindestens „Betriebsaktionen freigeben“.",
            "Enable Admin Edit and allow AI automation. Set write access to at least “Approve operations”.")}</p>
          <button type="button" class="text-button" data-autonomy-focus-edit>${t("Zu Admin Edit", "Go to Admin Edit")}</button>
        </div>
        <p id="zorec-autonomy-result" role="status">${state.escape(localized(feedback) || "")}</p>
      </div>
    </section>
    ${recentDecisions(state, autonomy.get().runs)}`;
  }

  function refreshControl(focus = false) {
    const control = document.getElementById("zorec-autonomy-enabled");
    if (!control) return;
    const mode = modeState();
    control.checked = mode.enabled;
    control.disabled = pending || !mode.eligible && !mode.enabled;
    document.getElementById("zorec-autonomy-mode").textContent = modeLabel(mode);
    const requirements = document.getElementById("zorec-autonomy-requirements");
    requirements.hidden = mode.eligible;
    document.getElementById("zorec-autonomy-result").textContent = localized(feedback) || "";
    if (focus) (control.disabled ? requirements.querySelector("button") : control)?.focus({ preventScroll: true });
  }

  document.addEventListener("change", async (event) => {
    const control = event.target;
    if (control.id !== "zorec-autonomy-enabled" || pending) return;
    const enabled = control.checked;
    pending = true;
    control.disabled = true;
    try {
      const result = await autonomy.setEnabled(enabled);
      feedback = result.ok ? ["Einstellung gespeichert.", "Setting saved."] : result.error;
    } catch {
      feedback = ["Die Einstellung konnte nicht gespeichert werden.", "The setting could not be saved."];
    } finally {
      pending = false;
      refreshControl(true);
    }
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest("[data-autonomy-focus-edit]")) return;
    const control = document.getElementById("zorec-admin-edit-enabled");
    control?.scrollIntoView({ block: "center" });
    control?.focus({ preventScroll: true });
  });

  window.addEventListener("opstend:zorec-policy-changed", () => {
    feedback = null;
    refreshControl();
  });

  window.opstendAutonomyUI = { render, renderJob };
})();
