(() => {
  "use strict";

  const preferenceKey = "opstend-rc2-language-v1";
  const profileKey = "opstend-rc2-language-profile-v1";
  const profiles = ["shared", "oidc", "local"];
  const languages = ["de", "en"];

  function languagePair(value, fallback) {
    const allowed = fallback === "inherit" ? [...languages, "inherit"] : languages;
    return {
      ui: allowed.includes(value?.ui) ? value.ui : fallback,
      zorec: allowed.includes(value?.zorec) ? value.zorec : fallback,
    };
  }

  function readPreferences() {
    let saved;
    try { saved = JSON.parse(localStorage.getItem(preferenceKey)); } catch {}
    return Object.fromEntries(profiles.map((profile) => [profile,
      languagePair(saved?.[profile], profile === "shared" ? "de" : "inherit"),
    ]));
  }

  function readProfile() {
    let saved;
    try { saved = sessionStorage.getItem(profileKey); } catch {}
    return profiles.includes(saved) ? saved : "shared";
  }

  let preferences = readPreferences();
  let activeProfile = readProfile();

  function effective(field) {
    const choice = preferences[activeProfile][field];
    return choice === "inherit" ? preferences.shared[field] : choice;
  }

  function visibleState() {
    return JSON.stringify([activeProfile, preferences.shared, preferences[activeProfile]]);
  }

  function notify(previous) {
    if (visibleState() === previous) return;
    window.dispatchEvent(new CustomEvent("opstend:locale-changed", {
      detail: { profile: activeProfile, ui: effective("ui"), zorec: effective("zorec") },
    }));
  }

  function selectProfile(profile) {
    if (!profiles.includes(profile) || profile === activeProfile) return;
    const previous = visibleState();
    activeProfile = profile;
    try { sessionStorage.setItem(profileKey, profile); } catch {}
    notify(previous);
  }

  function save(value) {
    const next = languagePair(value, activeProfile === "shared" ? "de" : "inherit");
    if (next.ui !== value?.ui || next.zorec !== value?.zorec) return false;

    const previous = visibleState();
    const latest = readPreferences();
    const current = latest[activeProfile];
    if (next.ui !== current.ui || next.zorec !== current.zorec) {
      latest[activeProfile] = next;
      try { localStorage.setItem(preferenceKey, JSON.stringify(latest)); } catch { return false; }
    }
    preferences = latest;
    notify(previous);
    return true;
  }

  window.addEventListener("storage", (event) => {
    if (event.storageArea !== localStorage || (event.key !== preferenceKey && event.key !== null)) return;
    const previous = visibleState();
    preferences = readPreferences();
    notify(previous);
  });

  window.opstendLocale = {
    profile: () => activeProfile,
    choices: () => ({ ...preferences[activeProfile] }),
    defaults: () => ({ ...preferences.shared }),
    ui: () => effective("ui"),
    zorec: () => effective("zorec"),
    t: (german, english) => effective("ui") === "en" ? english : german,
    selectProfile,
    save,
  };
})();
