(function () {
  "use strict";

  const t = window.opstendLocale.t;
  const results = { running: ["Läuft", "Running"], done: ["Abgeschlossen", "Complete"], error: ["Fehlgeschlagen", "Failed"] };
  const stepStates = {
    pending: { mark: "·", label: ["Ausstehend", "Pending"] },
    active: { mark: "›", label: ["Läuft", "Running"] },
    done: { mark: "✓", label: ["Erledigt", "Done"] },
    error: { mark: "!", label: ["Fehler", "Error"] },
  };

  function stepRow(step, escape) {
    const status = Object.hasOwn(stepStates, step.state) ? step.state : "pending";
    const { mark, label } = stepStates[status];
    return `<li data-step-status="${status}">
      <span class="zorec-step-mark" aria-hidden="true">${mark}</span>
      <div class="zorec-step-text"><strong>${escape(step.label)}</strong>
        ${step.detail ? `<p>${escape(step.detail)}</p>` : ""}</div>
      <span class="zorec-step-status">${t(...label)}</span>
    </li>`;
  }

  function render(state, { open, run }) {
    if (!open) return '<section id="zorec-activity" hidden></section>';

    const escape = state.escape;
    const status = run && Object.hasOwn(results, run.status) ? run.status : "";
    const mascot = window.opstendMascot.render(run?.gesture || "listening");
    return `<section class="zorec-activity" id="zorec-activity" aria-labelledby="zorec-activity-title">
      <header class="zorec-activity-head">
        <div class="zorec-activity-heading">${mascot}
          <div><h3 id="zorec-activity-title" tabindex="-1">${t("Aktivitätskonsole", "Activity console")}</h3>
            <p>${t("Lokale Demo", "Local demo")}</p></div>
        </div>
        <button type="button" class="button zorec-activity-close" data-activity-close aria-label="${t("Aktivitätskonsole schließen", "Close activity console")}">×</button>
      </header>
      <div class="zorec-activity-body" tabindex="0" role="group" aria-label="${t("Ablaufdetails", "Run details")}">
        ${run ? `<div class="zorec-activity-run">
          <dl class="zorec-activity-context">
            <div><dt>Shell</dt><dd>${escape(run.shellLabel)}</dd></div>
            <div><dt>${t("Kontext", "Context")}</dt><dd>${escape(run.context)}</dd></div>
          </dl>
          ${status ? `<p class="zorec-run-status" data-run-status="${status}" role="status">${t(...results[status])}</p>` : ""}
        </div>
        <ol class="zorec-activity-steps" role="list" aria-label="${t("Ablaufschritte", "Run steps")}">
          ${run.steps.map((step) => stepRow(step, escape)).join("")}
        </ol>` : `<p class="zorec-activity-empty">${t("Hier erscheint der Ablauf, sobald Zorec eine Anfrage bearbeitet.", "Steps appear here when Zorec processes a request.")}</p>`}
      </div>
    </section>`;
  }

  window.opstendActivity = { render };
})();
