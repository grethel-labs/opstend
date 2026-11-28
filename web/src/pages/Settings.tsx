import { useEffect, useState } from "react";
import { api, type Session } from "../api";
import { Card, Loading } from "../components/ui";
import { useCan, useData, useLang, useSession, useT, type Theme } from "../lib";

type Policy = {
  autonomy: Record<string, "observe" | "propose" | "auto">;
  budget: { max_actions: number; per_minutes: number; cooldown_minutes: number };
  window: { name: string; days: string[]; start: string; duration_minutes: number; timezone: string };
  kill_switch: boolean;
  require_backup_before_disruptive: boolean;
};

const DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

export function Settings({ theme, setTheme }: { theme: Theme; setTheme: (t: Theme) => void }) {
  const t = useT();
  const lang = useLang();
  const { refresh } = useSession();
  const isAdmin = useCan("admin");
  const { data } = useData<Policy>("/api/policy", []);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  useEffect(() => setPolicy(data), [data]);
  if (!policy) return <Loading />;

  const cats: [string, string, string][] = [
    ["restart", "Dienste neu starten", "Restart services"],
    ["reschedule", "Rollen und Workloads verlagern", "Move roles and workloads"],
    ["patch", "Sicherheitsupdates", "Security updates"],
    ["upgrade", "Funktionsupdates und Firmware", "Feature updates and firmware"],
    ["quarantine", "Gefährdete Dienste vom Netz nehmen", "Take exposed services offline"],
    ["network", "Netzwerkänderungen", "Network changes"],
    ["deploy", "Dienste anlegen und ändern", "Create and change services"],
    ["backup", "Sicherungen", "Backups"],
    ["power", "Ein- und Ausschalten", "Power actions"],
  ];
  const dayNames = lang === "de" ? ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"] : ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

  async function save(next: Policy) {
    setPolicy(next);
    try {
      await api.put("/api/policy", next);
      setSaved(t("Gespeichert", "Saved"));
    } catch (e) {
      setSaved(String((e as Error).message));
    }
    window.setTimeout(() => setSaved(null), 2500);
  }

  return (
    <>
      <div className="page-head">
        <div><h1>{t("Einstellungen", "Settings")}</h1></div>
        {saved && <span className="pill ok">{saved}</span>}
      </div>
      <Card title={t("Not-Aus für Automatik", "Automation kill switch")} sub={t("Pausiert alle automatischen Änderungen. Beobachtung und Hinweise laufen weiter.", "Pauses all automatic changes. Observation and insights continue.")}>
        <label className="chk"><input type="checkbox" disabled={!isAdmin} checked={policy.kill_switch} onChange={(e) => save({ ...policy, kill_switch: e.target.checked })} />
          {policy.kill_switch ? t("Automatik ist pausiert", "Automation is paused") : t("Automatik ist aktiv", "Automation is active")}</label>
      </Card>
      <Card title={t("Was OpsTend selbst tun darf", "What OpsTend may do on its own")} flush>
        <div className="table-wrap"><table>
          <thead><tr><th>{t("Bereich", "Area")}</th><th>{t("Verhalten", "Behavior")}</th></tr></thead>
          <tbody>{cats.map(([k, de, en]) => (
            <tr key={k}><td>{t(de, en)}</td><td>
              <div className="seg" role="group" aria-label={t(de, en)}>
                {(["observe", "propose", "auto"] as const).map((lvl) => (
                  <button key={lvl} disabled={!isAdmin} aria-pressed={policy.autonomy[k] === lvl} onClick={() => save({ ...policy, autonomy: { ...policy.autonomy, [k]: lvl } })}>
                    {{ observe: t("Nur melden", "Report only"), propose: t("Vorschlagen", "Propose"), auto: t("Selbst erledigen", "Do it") }[lvl]}
                  </button>
                ))}
              </div>
            </td></tr>
          ))}</tbody>
        </table></div>
      </Card>
      <div className="grid cols-2">
        <Card title={t("Wartungsfenster", "Maintenance window")} sub={t("Neustarts und Updates beginnen nur hier – außer bei akuter Gefahr.", "Reboots and updates start only here – except for acute risk.")}>
          <div className="stack">
            <div className="row">{DAYS.map((d, i) => (
              <label key={d} className="chk"><input type="checkbox" disabled={!isAdmin} checked={policy.window.days.includes(d)} onChange={(e) => {
                const days = e.target.checked ? [...policy.window.days, d] : policy.window.days.filter((x) => x !== d);
                if (days.length) save({ ...policy, window: { ...policy.window, days } });
              }} />{dayNames[i]}</label>
            ))}</div>
            <div className="row">
              <label className="lbl">{t("Beginn", "Start")}<input className="field" type="time" disabled={!isAdmin} value={policy.window.start.slice(0, 5)} onChange={(e) => save({ ...policy, window: { ...policy.window, start: e.target.value } })} /></label>
              <label className="lbl">{t("Dauer (Minuten)", "Duration (minutes)")}<input className="field" type="number" min={15} max={720} step={15} disabled={!isAdmin} value={policy.window.duration_minutes} onChange={(e) => save({ ...policy, window: { ...policy.window, duration_minutes: Number(e.target.value) } })} /></label>
            </div>
            <span className="muted small">{policy.window.timezone}</span>
          </div>
        </Card>
        <Card title={t("Grenzen gegen Schleifen", "Loop limits")} sub={t("Wie oft OpsTend dasselbe Ziel anfassen darf, bevor es dich fragt.", "How often OpsTend may touch the same target before it asks you.")}>
          <div className="row">
            <label className="lbl">{t("Höchstens", "At most")}<input className="field" type="number" min={1} max={10} disabled={!isAdmin} value={policy.budget.max_actions} onChange={(e) => save({ ...policy, budget: { ...policy.budget, max_actions: Number(e.target.value) } })} /></label>
            <label className="lbl">{t("pro Minuten", "per minutes")}<input className="field" type="number" min={10} max={1440} disabled={!isAdmin} value={policy.budget.per_minutes} onChange={(e) => save({ ...policy, budget: { ...policy.budget, per_minutes: Number(e.target.value) } })} /></label>
            <label className="lbl">{t("Pause danach (Min.)", "Cooldown (min)")}<input className="field" type="number" min={0} max={240} disabled={!isAdmin} value={policy.budget.cooldown_minutes} onChange={(e) => save({ ...policy, budget: { ...policy.budget, cooldown_minutes: Number(e.target.value) } })} /></label>
          </div>
        </Card>
      </div>
      <Card title={t("Darstellung und Sprache", "Appearance and language")}>
        <div className="row">
          <div className="seg" role="group" aria-label={t("Darstellung", "Theme")}>
            {(["system", "light", "dark"] as Theme[]).map((x) => <button key={x} aria-pressed={theme === x} onClick={() => setTheme(x)}>{{ system: "System", light: t("Hell", "Light"), dark: t("Dunkel", "Dark") }[x]}</button>)}
          </div>
          <div className="seg" role="group" aria-label={t("Sprache", "Language")}>
            {(["de", "en"] as const).map((l) => <button key={l} aria-pressed={lang === l} onClick={() => api.put<Session>("/api/session/lang", { lang: l }).then(refresh)}>{l === "de" ? "Deutsch" : "English"}</button>)}
          </div>
          <button className="btn ghost" onClick={() => api.del("/api/session").then(refresh)}>{t("Abmelden", "Sign out")}</button>
        </div>
      </Card>
    </>
  );
}
