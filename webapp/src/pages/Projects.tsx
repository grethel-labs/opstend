import { useState } from "react";
import type { PageProps } from "../App";
import { ApiError, api } from "../api";
import { Badge, Problem, useLoad } from "../hooks";

export function ProjectsPage({ onAuthLost }: PageProps) {
  const status = useLoad(() => api.status(), onAuthLost, 15000);
  const config = useLoad(() => api.config(), onAuthLost);
  const [notice, setNotice] = useState("");
  const live = status.data?.status?.projects ?? {};
  const projects = config.data?.config?.projects ?? [];

  async function restart(id: string) {
    setNotice("");
    try {
      const job = await api.restart(id);
      setNotice(`Restart of ${id} queued as job ${job.id.slice(0, 12)}. See Jobs for the result.`);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onAuthLost();
      else setNotice(err instanceof Error ? err.message : "request failed");
    }
  }

  return (
    <>
      <Problem loaded={config} />
      {notice && <p className="banner info" role="status">{notice}</p>}
      {config.data?.pending && (
        <p className="banner warn">
          The table shows the head revision. It differs from the applied revision until the next deployment.
        </p>
      )}
      <table>
        <thead>
          <tr>
            <th>Project</th>
            <th>Desired</th>
            <th>Service</th>
            <th>Health</th>
            <th>Isolation</th>
            <th>Limits</th>
            <th>Egress</th>
            <th>Routes</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {projects.map((raw) => {
            const project = raw as {
              id: string;
              manage: boolean;
              deploy: boolean;
              resources: { memory_mb: number; cpus: number; pids: number };
              egress: { mode: string };
              routes: Array<{ host: string }>;
            };
            const state = live[project.id];
            return (
              <tr key={project.id}>
                <td>
                  <strong>{project.id}</strong>
                </td>
                <td>{!project.manage ? "unmanaged" : project.deploy ? "running" : "stopped, data kept"}</td>
                <td>
                  {state ? (
                    <Badge tone={state.unit.active === "active" ? "ok" : project.deploy ? "bad" : "info"}>
                      {state.unit.active}
                    </Badge>
                  ) : (
                    <span className="muted">no data</span>
                  )}
                </td>
                <td>
                  {state?.health ? (
                    <Badge tone={state.health.ok ? "ok" : "bad"}>
                      {state.health.ok ? "ok" : `failed (${state.health.status ?? state.health.error})`}
                    </Badge>
                  ) : (
                    <span className="muted">–</span>
                  )}
                </td>
                <td>
                  {state?.hardening ? (
                    state.hardening.violations.length === 0 ? (
                      <Badge tone="ok">verified</Badge>
                    ) : (
                      <Badge tone="bad">{state.hardening.violations.join(", ")}</Badge>
                    )
                  ) : (
                    <span className="muted">–</span>
                  )}
                </td>
                <td>
                  {project.resources.memory_mb} MB · {project.resources.cpus} CPU · {project.resources.pids} PIDs
                </td>
                <td>{project.egress.mode}</td>
                <td>{project.routes.length ? project.routes.map((r) => r.host).join(", ") : "not exposed"}</td>
                <td>
                  <button
                    className="secondary"
                    disabled={!state?.deploy}
                    title={state?.allow_restart ? "" : "Needs maintenance.allow_restart; the executor will refuse otherwise"}
                    onClick={() => restart(project.id)}
                  >
                    Restart
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {projects.length === 0 && !config.loading && <p>No projects configured.</p>}
    </>
  );
}
