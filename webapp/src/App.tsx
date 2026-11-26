import { type FormEvent, useCallback, useEffect, useState } from "react";
import { ApiError, api, setCsrf } from "./api";
import { AuditPage } from "./pages/Audit";
import { BackupsPage } from "./pages/Backups";
import { ConfigPage } from "./pages/Config";
import { EventsPage } from "./pages/Events";
import { JobsPage } from "./pages/Jobs";
import { AiPage } from "./pages/Ai";
import { OverviewPage } from "./pages/Overview";
import { ProjectsPage } from "./pages/Projects";
import { ScansPage } from "./pages/Scans";

const PAGES = {
  overview: { title: "Overview", component: OverviewPage },
  projects: { title: "Projects", component: ProjectsPage },
  backups: { title: "Backups", component: BackupsPage },
  config: { title: "Configuration", component: ConfigPage },
  events: { title: "Events", component: EventsPage },
  scans: { title: "Vulnerabilities", component: ScansPage },
  jobs: { title: "Jobs", component: JobsPage },
  ai: { title: "AI", component: AiPage },
  audit: { title: "Audit", component: AuditPage },
} as const;
type PageId = keyof typeof PAGES;

export interface PageProps {
  onAuthLost: () => void;
}

function pageFromHash(): PageId {
  const id = window.location.hash.replace(/^#\/?/, "");
  return id in PAGES ? (id as PageId) : "overview";
}

function Login({ onDone }: { onDone: () => void }) {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await api.login(token);
      setCsrf(result.csrf);
      setToken("");
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <form onSubmit={submit} className="card">
        <h1>steward</h1>
        <p className="muted">Sign in with the admin token of this server.</p>
        <label htmlFor="token">Admin token</label>
        <input
          id="token"
          type="password"
          autoComplete="off"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          required
          autoFocus
        />
        {error && <p className="error" role="alert">{error}</p>}
        <button type="submit" disabled={busy || !token}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}

export function App() {
  const [auth, setAuth] = useState<"unknown" | "yes" | "no">("unknown");
  const [version, setVersion] = useState("");
  const [page, setPage] = useState<PageId>(pageFromHash);

  const check = useCallback(async () => {
    try {
      const session = await api.session();
      setCsrf(session.csrf);
      setVersion(session.version);
      setAuth("yes");
    } catch {
      setAuth("no");
    }
  }, []);

  useEffect(() => {
    void check();
    const onHash = () => setPage(pageFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [check]);

  if (auth === "unknown") return <main className="login muted">Loading…</main>;
  if (auth === "no") return <Login onDone={check} />;

  const Page = PAGES[page].component;
  return (
    <div className="shell">
      <header>
        <strong>steward</strong>
        <nav aria-label="Sections">
          {(Object.keys(PAGES) as PageId[]).map((id) => (
            <a key={id} href={`#/${id}`} aria-current={id === page ? "page" : undefined}>
              {PAGES[id].title}
            </a>
          ))}
        </nav>
        <span className="muted">v{version}</span>
        <button
          className="secondary"
          onClick={async () => {
            await api.logout().catch(() => undefined);
            setCsrf("");
            setAuth("no");
          }}
        >
          Sign out
        </button>
      </header>
      <main>
        <h1>{PAGES[page].title}</h1>
        <Page onAuthLost={() => setAuth("no")} />
      </main>
    </div>
  );
}
