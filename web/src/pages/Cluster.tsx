import { Card, Empty, Loading, Pill } from "../components/ui";
import { gb, useData, useLang, useT, when } from "../lib";

type Node = { id: string; name: string; address: string; version: string; state: string; voter: boolean; site: string; labels: Record<string, string>; last_seen: string; capacity: { cpu_cores: number; memory_mb: number }; usage: { cpu_pct: number | null; memory_mb: number | null } };
type Data = {
  raft: { id: string; role: string; term: number; leader: string | null; voters: string[]; commit_index: number };
  nodes: Node[];
  placement: { assignments?: Record<string, string[]>; reasons?: Record<string, string>; unplaced?: Record<string, string> };
  roles: { name: string; description: string }[];
  candidates: { address: string; kind: string; name: string | null; detail: Record<string, string> }[];
};

export function Cluster() {
  const t = useT();
  const lang = useLang();
  const { data } = useData<Data>("/api/cluster");
  if (!data) return <Loading />;
  const names = Object.fromEntries(data.nodes.map((n) => [n.id, n.name]));
  const a = data.placement.assignments ?? {};
  const roleDe: Record<string, string> = {
    controller: "Steuerzustand (Raft-Voter)", web: "Web-App und API", collector: "Liest Proxmox, UniFi und Linux eines Standorts",
    discovery: "Findet neue Knoten und Geräte", scanner: "Sicherheitsscans und Bedrohungsdaten", backup: "Sicherungen und Restore-Tests",
    zorec: "Zorec mit optionalem lokalem Modell",
  };
  return (
    <>
      <div className="page-head">
        <div>
          <h1>{t("Cluster und Rollen", "Cluster and roles")}</h1>
          <p className="muted">{t("Nicht jeder Knoten macht alles. OpsTend verteilt die Rollen nach Leistung, Standort und Merkmalen. Fällt ein Knoten aus, wählen die übrigen Voter in Sekunden eine neue Steuerung und verlagern seine Rollen.",
            "Not every node runs everything. OpsTend spreads roles by capacity, site and labels. If a node fails, the remaining voters elect a new leader within seconds and move its roles.")}</p>
        </div>
      </div>
      <div className="grid cols-4">
        <Card title={t("Steuerung", "Leader")}><b>{names[data.raft.leader ?? ""] ?? data.raft.leader ?? "–"}</b><div className="muted small">Term {data.raft.term}</div></Card>
        <Card title="Voter"><b className="num">{data.raft.voters.length}</b><div className="muted small">{t(`Mehrheit: ${Math.floor(data.raft.voters.length / 2) + 1}`, `Majority: ${Math.floor(data.raft.voters.length / 2) + 1}`)}</div></Card>
        <Card title={t("Knoten", "Nodes")}><b className="num">{data.nodes.length}</b><div className="muted small">{data.nodes.filter((n) => n.state === "healthy").length} {t("gesund", "healthy")}</div></Card>
        <Card title={t("Neu gefunden", "Discovered")}><b className="num">{data.candidates.length}</b><div className="muted small">{t("warten auf Aufnahme", "waiting to join")}</div></Card>
      </div>
      <Card title={t("Knoten", "Nodes")} flush>
        <div className="table-wrap"><table>
          <thead><tr><th>{t("Knoten", "Node")}</th><th>{t("Rollen", "Roles")}</th><th className="hide-sm">{t("Architektur", "Architecture")}</th><th className="hide-sm">{t("Ressourcen", "Resources")}</th><th>Version</th><th>{t("Zustand", "State")}</th></tr></thead>
          <tbody>{data.nodes.map((n) => (
            <tr key={n.id}>
              <td><b>{n.name}</b>{n.voter && <span className="pill info plain" style={{ marginLeft: 6 }}>Voter</span>}<span className="sub">{n.address} · {n.site}</span></td>
              <td className="small">{Object.entries(a).filter(([, ids]) => ids.includes(n.id)).map(([r]) => r).join(", ") || "–"}</td>
              <td className="hide-sm">{n.labels.arch ?? "–"}</td>
              <td className="hide-sm num small">{n.capacity.cpu_cores} CPU · {gb(n.capacity.memory_mb)}</td>
              <td className="num">{n.version}</td>
              <td><Pill state={n.state} /><span className="sub">{when(n.last_seen, lang)}</span></td>
            </tr>
          ))}</tbody>
        </table></div>
      </Card>
      <Card title={t("Rollenverteilung", "Role placement")} flush>
        {data.roles.map((r) => (
          <div key={r.name} className="item">
            <div className="row between"><b>{r.name}</b><span className="small">{(a[r.name] ?? []).map((id) => names[id] ?? id).join(", ") || <span className="pill bad plain">{t("nicht platziert", "not placed")}</span>}</span></div>
            <span className="muted small">{t(roleDe[r.name] ?? r.description, r.description)} · {data.placement.reasons?.[r.name] ?? ""}</span>
          </div>
        ))}
      </Card>
      <Card title={t("Neue Knoten und Systeme", "New nodes and systems")} sub={t("Gefunden über Beacons und Scans privater Netze", "Found through beacons and scans of private networks")} flush>
        {data.candidates.length === 0 ? (
          <Empty>
            {t("Keine neuen Systeme gefunden. Neue Knoten erscheinen hier automatisch, sobald der OpsTend-Agent dort läuft.", "No new systems found. New nodes appear here as soon as the OpsTend agent runs there.")}
            <div className="mono small" style={{ marginTop: 8 }}>curl -fsSL https://github.com/grethel-labs/opstend/releases/latest/download/install.sh | sudo sh</div>
          </Empty>
        ) : data.candidates.map((c) => (
          <div key={c.address + c.kind} className="item"><b>{c.name ?? c.address}</b><span className="muted small">{c.kind} · {c.address}</span></div>
        ))}
      </Card>
    </>
  );
}
