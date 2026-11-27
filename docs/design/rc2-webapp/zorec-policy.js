(function () {
  "use strict";

  const storageKey = "opstend-rc2-zorec-shells-v1";
  const changed = "opstend:zorec-policy-changed";
  const dataLevels = ["reports", "basic", "full"];
  const defaults = {
    "admin-read": { data: "basic", internet: false },
    "admin-edit": { enabled: false, access: "draft", internet: false, automation: false },
    report: { data: "reports", internet: false },
  };

  function hasFields(value, fields) {
    return value !== null && typeof value === "object" && !Array.isArray(value)
      && Object.keys(value).length === fields.length
      && fields.every((field) => Object.hasOwn(value, field));
  }

  function valid(policy) {
    if (!hasFields(policy, ["admin-read", "admin-edit", "report"])) return false;
    const read = policy["admin-read"];
    const edit = policy["admin-edit"];
    const report = policy.report;
    return hasFields(read, ["data", "internet"])
      && ["basic", "full"].includes(read.data) && typeof read.internet === "boolean"
      && hasFields(edit, ["enabled", "access", "internet", "automation"])
      && ["draft", "operate", "full"].includes(edit.access)
      && [edit.enabled, edit.internet, edit.automation].every((value) => typeof value === "boolean")
      && hasFields(report, ["data", "internet"])
      && dataLevels.includes(report.data) && typeof report.internet === "boolean";
  }

  function get() {
    try {
      const policy = JSON.parse(localStorage.getItem(storageKey) || "null");
      if (valid(policy)) return policy;
    } catch {}
    return structuredClone(defaults);
  }

  function effectiveReportData(policy = get()) {
    if (!valid(policy)) return defaults.report.data;
    const readLevel = dataLevels.indexOf(policy["admin-read"].data);
    const reportLevel = dataLevels.indexOf(policy.report.data);
    return dataLevels[Math.min(readLevel, reportLevel)];
  }

  function notifyChange() {
    window.dispatchEvent(new CustomEvent(changed));
  }

  function save(policy) {
    if (!valid(policy)) return "Prüfe die Berechtigungen der drei Zorec-Shells.";
    try {
      localStorage.setItem(storageKey, JSON.stringify(policy));
    } catch {
      return "Die Shell-Einstellungen konnten in diesem Browser nicht gespeichert werden.";
    }
    queueMicrotask(notifyChange);
    return true;
  }

  window.addEventListener("storage", (event) => {
    if (event.key === storageKey || event.key === null) notifyChange();
  });

  window.opstendZorecPolicy = { get, save, effectiveReportData };
})();
