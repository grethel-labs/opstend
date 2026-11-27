(function () {
  "use strict";

  const fields = Object.freeze({ "service.adapter.intervalSeconds": "intervalSeconds" });
  const proposalEvent = "opstend:zorec-field-proposed";
  const failure = (error) => ({ ok: false, error });

  function propose({ key, value, subjectId, expectedVersion, expectedRevision } = {}) {
    if (!window.opstendZorecPolicy.get()["admin-edit"].enabled) {
      return failure("Für Feldvorschläge braucht Zorec die Shell Admin Edit.");
    }
    if (!Object.hasOwn(fields, key) || typeof subjectId !== "string" || !subjectId) {
      return failure("Dieses Feld ist für Zorec nicht freigegeben.");
    }

    const form = document.querySelector(`[data-zorec-adapter][data-adapter-settings="${CSS.escape(subjectId)}"]`);
    const name = fields[key];
    const input = form?.elements.namedItem(name);
    if (!(input instanceof HTMLInputElement) || !input.hasAttribute("data-adapter-field")
      || input.type !== "number" || input.disabled || input.readOnly) {
      return failure("Öffne das bearbeitbare Einstellungsformular dieses Dienstes.");
    }

    const demo = window.opstendDemo;
    const service = demo.getInventory().services.find((item) => item.id === subjectId);
    const adapter = demo.adapterSettings(service);
    if (!adapter || form.hasAttribute("data-zorec-proposal-stale")
      || form.dataset.adapterVersion !== adapter.version || Number(form.dataset.adapterRevision) !== adapter.revision
      || (expectedVersion !== undefined && expectedVersion !== adapter.version)
      || (expectedRevision !== undefined && expectedRevision !== adapter.revision)) {
      return failure("Die Adaptereinstellungen haben sich geändert. Bitte Zorec um einen neuen Vorschlag.");
    }

    const preview = demo.previewAdapterSettings(service, { ...adapter.values, [name]: value });
    if (!preview.ok) return failure(preview.error);
    const proposed = String(preview.values[name]);
    if (input.value === proposed) return { ok: true, changed: false };
    if (input.value !== String(adapter.values[name]) && input.value !== form.dataset.zorecDraftValue) {
      return failure("In diesem Feld stehen bereits eigene Eingaben. Prüfe sie im Formular.");
    }

    input.value = proposed;
    form.dispatchEvent(new CustomEvent(proposalEvent, { bubbles: true, detail: { name, value: proposed } }));
    input.dispatchEvent(new Event("input", { bubbles: true }));
    queueMicrotask(() => {
      if (!input.isConnected || document.querySelector("dialog[open]")) return;
      input.scrollIntoView({ block: "center" });
      input.focus({ preventScroll: true });
    });
    return { ok: true, changed: true };
  }

  function note(proposal, values) {
    const description = `Zorec-Vorschlag · ${proposal.value} Sekunden`;
    return String(values[proposal.name]) === proposal.value ? description : `${description} · von dir bearbeitet`;
  }

  window.opstendZorecFields = { propose, note };
})();
