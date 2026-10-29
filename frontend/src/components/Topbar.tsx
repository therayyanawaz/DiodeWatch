import { useEffect, useState } from "react";
import type { MouseEvent as ReactMouseEvent } from "react";
import Clock from "./Clock";
import ThemeToggle from "./ThemeToggle";

/* The pill tracks the section you are actually looking at, so a scroll never
   leaves "Overview" lit while the feed is on screen. */
const SECTIONS = [
  { nav: "overview", label: "Overview" },
  { nav: "activity", label: "Activity" },
  { nav: "metrics", label: "Metrics" },
  { nav: "diode", label: "Diode Proof" },
];

export default function Topbar({ onReset }: { onReset: () => void }) {
  const [active, setActive] = useState("overview");

  useEffect(() => {
    const spy = new IntersectionObserver((entries) => {
      for (const en of entries) if (en.isIntersecting) setActive(en.target.id);
    }, { rootMargin: "-20% 0px -70% 0px" });
    for (const s of SECTIONS) {
      const el = document.getElementById(s.nav);
      if (el) spy.observe(el);
    }
    return () => spy.disconnect();
  }, []);

  const jump = (nav: string) => (e: ReactMouseEvent) => {
    e.preventDefault();
    document.querySelector(`#${nav}`)?.scrollIntoView({ behavior: "smooth" });
    setActive(nav);
  };

  return (
    <header className="topbar">
      <a className="brand" href="#overview" onClick={jump("overview")}>
        <svg className="brand-mark tri" aria-hidden="true"><use href="#i-tri" /></svg>
        <span>DiodeWatch</span>
      </a>
      <nav className="pillnav" aria-label="Sections">
        {SECTIONS.map((s) => (
          <a key={s.nav} href={`#${s.nav}`} onClick={jump(s.nav)}
             className={`pill${active === s.nav ? " is-active" : ""}`}>
            {s.label}
          </a>
        ))}
        <a href="/status" className="pill">Status</a>
      </nav>
      <div className="top-right">
        <Clock />
        <button className="iconbtn" title="Demo script — docs/demo_script.md"
                aria-label="Open demo script"
                onClick={() => window.open("/api/demo_script", "_blank", "noopener")}>
          <svg aria-hidden="true"><use href="#i-help" /></svg>
        </button>
        <button className="iconbtn" title="Reset session" aria-label="Reset session"
                onClick={onReset}>
          <svg aria-hidden="true"><use href="#i-power" /></svg>
        </button>
        <ThemeToggle />
        <button className="iconbtn" title="Alerts" aria-label="Jump to alert feed"
                onClick={jump("activity")}>
          <svg aria-hidden="true"><use href="#i-bell" /></svg>
        </button>
      </div>
    </header>
  );
}
