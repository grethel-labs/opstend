import { useState } from "react";
import { api } from "../api";
import { useT } from "../lib";

export function Login({ setup, onDone }: { setup: boolean; onDone: () => void }) {
  const t = useT();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  async function submit() {
    setError(null);
    try {
      await api.post(setup ? "/api/setup" : "/api/session", { username, password });
      onDone();
    } catch (e) {
      setError(String((e as Error).message));
    }
  }
  return (
    <main style={{ display: "grid", placeItems: "center", minHeight: "100%", padding: 16 }}>
      <form className="card" style={{ width: "min(400px, 100%)", padding: 24, display: "grid", gap: 14 }} onSubmit={(e) => { e.preventDefault(); submit(); }}>
        <div className="row"><img src="/brand/opstend.svg" alt="" width={40} /><h1 style={{ fontSize: "1.4rem" }}>OpsTend</h1></div>
        <p className="muted">{setup ? t("Lege das erste Administratorkonto an.", "Create the first administrator account.") : t("Melde dich an.", "Sign in.")}</p>
        <label className="lbl">{t("Benutzername", "User name")}<input className="field" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} /></label>
        <label className="lbl">{t("Passwort", "Password")}{setup && <span className="help">{t("Mindestens 12 Zeichen", "At least 12 characters")}</span>}
          <input className="field" type="password" autoComplete={setup ? "new-password" : "current-password"} value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        {error && <div className="banner warn">{error}</div>}
        <button className="btn primary" disabled={!username || !password}>{setup ? t("Konto anlegen", "Create account") : t("Anmelden", "Sign in")}</button>
      </form>
    </main>
  );
}
