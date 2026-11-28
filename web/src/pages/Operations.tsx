import { api, type AuditEntry, type Insight, type Job, type Service } from "../api";
import { Icon } from "../components/Icon";
import { Card, Empty, Kpi, Loading, Meter, Pill, useJobFlow } from "../components/ui";
import { clock, gb, go, href, useCan, useData, useLang, useSession, useT } from "../lib";

type Incident = { id: string; target: string; title: string; detail: string; severity: string; state: string; job_id: string | null };
type Overview = {
  incidents: Incident[]; unhealthy: Service[]; decisions: Job[]; working: Job[];
  counts: Record<string, number>;
  capacity: { cpu_cores: number; memory_mb: number; memory_used_mb: number; disk_gb: number; disk_used_gb: number; measured: number };
  sites: { name: string; hosts: number; ok: number; workloads: number; stale: number }[];
  insights: Insight[]; activity: AuditEntry[];
  cluster: { role: string; term: number; leader: string | null; voters: string[]; nodes: number };
};

export function Operations() {
  const t = useT();
  const lang = useLang();
  const { session } = useSession();
  const canAct = useCan("operator");
  const { data } = useData<Overview>("/api/overview");
  const flow = useJobFlow();
  if (!data) return <Loading />;
  const c = data.counts;
  const incidents = data.incidents.filter((i) => i.state !== "resolved");

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">{session.site} · {t("ganze Flotte", "whole fleet")}</div>
          <h1>{t("Betrieb", "Operations")}</h1>
        </div>
        <div className="row">
          {session.demo && <span className="pill info plain">{t("Demo mit Beispieldaten", "Demo with example data")}</span>}
          <a className="btn" href={href("/network/topology")}><Icon name="map" />{t("Topologie öffnen", "Open topology")}</a>
        </div>
      </div>

      <div className="grid cols-2">
        <Card title={<span className="row"><Icon name="alert" />{t("Störungen", "Incidents")}</span>} action={<span className="pill plain">{incidents.length + data.unhealthy.length}</span>} flush>
          {incidents.length === 0 && data.unhealthy.length === 0 && <Empty>{t("Keine Störungen. Alles läuft.", "No incidents. Everything runs.")}</Empty>}
          {incidents.map((i) => (
            <div key={i.id} className={`item sev-stripe ${i.severity}`}>
              <div className="row between">
                <span className="title">{i.title}</span>
                <Pill state={i.state} />
              </div>
              <div className="muted small">{i.detail}</div>
              {i.job_id && <div><a className="btn small" href={href(`/jobs/${i.job_id}`)}>{t("Prüfung verfolgen", "Follow the check")}<Icon name="arrow" size={14} /></a></div>}
            </div>
          ))}
          {data.unhealthy.filter((s) => !incidents.some((i) => i.target === `service/${s.id}`)).map((s) => (
            <div key={s.id} className="item sev-stripe high">
              <div className="row between"><span className="title">{s.name}</span><Pill state={s.health} /></div>
              <div className="muted small">{s.description}</div>
            </div>
          ))}
        </Card>

        <Card title={<span className="row"><Icon name="shield" />{t("Anstehende Entscheidungen", "Pending decisions")}</span>} action={<span className="pill plain">{data.decisions.length}</span>} flush>
          {data.decisions.length === 0 && <Empty>{t("Nichts wartet auf dich.", "Nothing is waiting for you.")}</Empty>}
          {data.decisions.map((j) => (
            <div key={j.id} className="item">
              <div className="row between">
                <span className="title">{j.title}</span>
                <span className="pill warn">{j.requested_by === "zorec" ? t("Vorschlag von Zorec", "Suggested by Zorec") : t("Deine Freigabe", "Your approval")}</span>
              </div>
              {j.reason && <div className="muted small">{j.reason}</div>}
              <div className="row">
                <a className="btn small" href={href(`/jobs/${j.id}`)}>{t("Details prüfen", "Review details")}</a>
                {canAct && (
                  <button className="btn small primary" onClick={() => flow.start(async () => j)}>
                    <Icon name="check" size={14} />{t("Freigeben …", "Approve …")}
                  </button>
                )}
              </div>
            </div>
          ))}
        </Card>
      </div>

      {data.working.length > 0 && (
        <Card title={<span className="row"><img src="/brand/zorec.svg" alt="" width={22} />{t("Zorec arbeitet daran", "Zorec is working on")}</span>} flush>
          {data.working.map((j) => (
            <a key={j.id} className="item" href={href(`/jobs/${j.id}`)} style={{ color: "inherit" }}>
              <div className="row between"><span className="title">{j.title}</span><Pill state={j.state} /></div>
              <div className="muted small">{j.not_before ? t(`Startet im Wartungsfenster ${new Date(j.not_before).toLocaleString(lang)}`, `Starts in the maintenance window ${new Date(j.not_before).toLocaleString(lang)}`) : j.reason}</div>
            </a>
          ))}
        </Card>
      )}

      <div className="grid cols-4">
        <Kpi label="Hosts" value={c.hosts} hint={t(`${c.hosts_ok} gesund`, `${c.hosts_ok} healthy`)} onClick={() => go("/infra")} />
        <Kpi label={t("Gäste und Container", "Guests and containers")} value={c.guests} hint={t(`${c.guests_running} laufen`, `${c.guests_running} running`)} onClick={() => go("/infra?tab=guests")} />
        <Kpi label={t("Sicherheit", "Security")} value={c.findings_high} hint={t("wichtige Befunde", "important findings")} onClick={() => go("/security")} />
        <Kpi label="Updates" value={c.updates} hint={t(`${c.updates_security} sicherheitsrelevant`, `${c.updates_security} security`)} onClick={() => go("/updates")} />
      </div>

      <div className="grid split">
        <div className="grid">
          <Card title={t("Standorte", "Sites")} sub={t("Erreichbarkeit und Arbeitslast", "Reachability and workload")} flush>
            <div className="table-wrap">
              <table>
                <thead><tr><th>{t("Standort", "Site")}</th><th>Hosts</th><th>{t("Workloads", "Workloads")}</th><th>{t("Zustand", "State")}</th></tr></thead>
                <tbody>
                  {data.sites.map((s) => (
                    <tr key={s.name} className="link" onClick={() => go(`/infra?site=${encodeURIComponent(s.name)}`)}>
                      <td><b>{s.name}</b></td>
                      <td className="num">{s.ok} / {s.hosts} {t("erreichbar", "reachable")}{s.stale > 0 && <span className="sub">{t(`${s.stale} mit veralteten Daten`, `${s.stale} with stale data`)}</span>}</td>
                      <td className="num">{s.workloads}</td>
                      <td><Pill state={s.ok === s.hosts && !s.stale ? "ok" : "warning"} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <Card title={t("Netzwerk-Hinweise", "Network insights")} sub={t("Über UniFi, Proxmox und Linux hinweg erkannt", "Found across UniFi, Proxmox and Linux")}
            action={<a href={href("/network")} className="small">{t("Alle ansehen", "See all")}</a>} flush>
            {data.insights.length === 0 && <Empty>{t("Keine Auffälligkeiten.", "Nothing unusual.")}</Empty>}
            {data.insights.map((i) => (
              <div key={i.id} className={`item sev-stripe ${i.severity}`}>
                <div className="row between"><span className="title">{i.title}</span><Pill state={i.severity} /></div>
                <div className="muted small">{i.detail}</div>
                {i.fix && canAct && (
                  <div><button className="btn small" onClick={() => flow.start(() => api.post<Job>(`/api/network/insights/${i.id}/fix`))}>{i.fix.summary}</button></div>
                )}
              </div>
            ))}
          </Card>
        </div>

        <div className="grid">
          <Card title={t("Kapazität", "Capacity")} sub={t(`${data.capacity.measured} Hosts mit aktuellen Messwerten`, `${data.capacity.measured} hosts with current measurements`)}>
            <div className="stack">
              <div className="row between"><span>{t("Arbeitsspeicher", "Memory")}</span><b className="num">{gb(data.capacity.memory_used_mb)} / {gb(data.capacity.memory_mb)}</b></div>
              <Meter value={data.capacity.memory_used_mb} max={data.capacity.memory_mb} label={t("Arbeitsspeicher", "Memory")} />
              <div className="row between" style={{ marginTop: 10 }}><span>{t("Lokaler Speicher", "Local storage")}</span><b className="num">{data.capacity.disk_used_gb} / {data.capacity.disk_gb} GB</b></div>
              <Meter value={data.capacity.disk_used_gb} max={data.capacity.disk_gb} label={t("Speicher", "Storage")} />
              <div className="muted small" style={{ marginTop: 6 }}>{data.capacity.cpu_cores} {t("CPU-Kerne insgesamt", "CPU cores in total")}</div>
            </div>
          </Card>
          <Card title={t("Steuerung", "Control plane")}>
            <div className="stack small">
              <div className="row between"><span>{t("Rolle dieses Knotens", "This node")}</span><Pill state={data.cluster.role === "leader" ? "ok" : "unknown"}>{data.cluster.role}</Pill></div>
              <div className="row between"><span>Voter</span><b className="num">{data.cluster.voters.length}</b></div>
              <div className="row between"><span>{t("Knoten", "Nodes")}</span><b className="num">{data.cluster.nodes}</b></div>
              <a href={href("/cluster")}>{t("Rollen und Ausfallsicherheit ansehen", "View roles and failover")}</a>
            </div>
          </Card>
          <Card title={t("Letzte Aktivität", "Recent activity")} action={<a className="small" href={href("/jobs?tab=log")}>{t("Protokoll", "Log")}</a>} flush>
            {data.activity.length === 0 && <Empty>{t("Noch keine Einträge.", "No entries yet.")}</Empty>}
            {data.activity.map((e) => (
              <div key={e.seq} className="item small">
                <div className="row between"><b>{String(e.detail.title ?? e.detail.effect ?? e.action)}</b><span className="muted num">{clock(e.at, lang)}</span></div>
                <span className="muted">{e.actor} · {e.target}{e.outcome !== "ok" ? ` · ${e.outcome}` : ""}</span>
              </div>
            ))}
          </Card>
        </div>
      </div>
      {flow.dialog}
    </>
  );
}
