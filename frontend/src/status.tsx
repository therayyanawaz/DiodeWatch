import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import Clock from "./components/Clock";
import StatusBoard from "./components/StatusBoard";
import ThemeToggle from "./components/ThemeToggle";
import { useStatus } from "./useStatus";

/* The wall's status board. It is emitted as a second page of the same build,
   so `server.py` serves it at /status off the existing static mount and no
   route is invented for it. */
function StatusApp() {
  const { st, refresh, verify } = useStatus();

  return (
    <div className="shell">
      <header className="topbar">
        <a className="brand" href="/">
          <svg className="brand-mark tri" aria-hidden="true"><use href="#i-tri" /></svg>
          <span>DiodeWatch</span>
        </a>
        <nav className="pillnav" aria-label="Sections">
          <a href="/" className="pill">Dashboard</a>
          <a href="/status" className="pill is-active" aria-current="page">Status</a>
        </nav>
        <div className="top-right">
          <Clock />
          <ThemeToggle />
        </div>
      </header>

      <main className="content">
        <section className="greeting">
          <h1>System status</h1>
          <p>Every service, component, and detector channel, what is on, what is
            degraded, what is off.</p>
        </section>

        <StatusBoard st={st} onVerify={verify} onRefresh={refresh} />

        <footer className="foot">
          <span>DiodeWatch · Passive threat detection for one-way network links</span>
          <span className="foot-sep">·</span>
          <span>offline, zero external calls</span>
        </footer>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <StatusApp />
  </StrictMode>,
);
