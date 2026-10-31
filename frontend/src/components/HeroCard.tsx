import { useEffect, useState } from "react";
import { api } from "../api";
import { fmt } from "../format";
import type { Kpi } from "../useEased";
import type { Metrics, Params, Source } from "../types";
import Help from "./Help";
import { MiniSelect, SourcePicker } from "./Listbox";

const TL_CSS: Record<string, string> = {
  critical: "tl--critical",
  high: "tl--elevated",
  medium: "tl--guarded",
};

type Props = {
  sessionState: string;
  progress: number | null;
  metrics: Metrics;
  kpi: Kpi;
  defaults: Params;
  levelWord: (sev: string | null | undefined) => string;
  launch: (p: Params) => void;
  togglePause: (paused: boolean) => void;
  reset: () => void;
};

export default function HeroCard({
  sessionState, progress, metrics, kpi, defaults, levelWord,
  launch, togglePause, reset,
}: Props) {
  const [sources, setSources] = useState<Source[]>([]);
  const [params, setParams] = useState<Params>(defaults);

  useEffect(() => {
    api.sources().then(setSources).catch(() => setSources([]));
  }, []);

  // A snapshot arrives on (re)connect and carries the session the shared wall
  // is actually running; the pickers must not keep offering a stale choice.
  useEffect(() => {
    setParams(defaults);
  }, [defaults.source, defaults.window_s, defaults.tick_ms]);

  const busy = sessionState === "running" || sessionState === "loading"
    || sessionState === "paused";
  const paused = sessionState === "paused";
  const sev = metrics.max_severity ?? null;
  const pct = sessionState === "finished" ? 100
    : Math.round((progress ?? 0) * 100);

  return (
    <section
      className={`card hero-card${sessionState === "running" || sessionState === "loading" ? " live" : ""}`}
    >
      <div className="card-top">
        <span className="card-label">Threat Level{" "}
          <Help about="Threat Level">Session roll-up from alert severities: CALM with no
            alerts, then GUARDED, ELEVATED or CRITICAL as the worst severity
            climbs. Counts alerts, not traffic.</Help>
        </span>
        <SourcePicker
          sources={sources}
          value={params.source}
          onChange={(source) => setParams({ ...params, source })}
        />
      </div>

      <div className={`hero-value ${TL_CSS[sev ?? ""] || "tl--calm"}`}>
        <span>{levelWord(sev)}</span>
      </div>
      <div className="hero-sub">
        {/* A threat count carries no direction: green-as-growth on alerts is a lie. */}
        <span className="delta">{fmt(metrics.alerts)} alerts</span>
        <span className="muted">· {fmt(kpi.flows)} flows evaluated</span>
      </div>

      <div className="progress replay-progress" title="Replay progress">
        <i style={{ width: `${pct}%` }} />
      </div>

      <div className="btnrow">
        <button className="btn-dark" disabled={busy} onClick={() => launch(params)}>
          <svg className="sm" aria-hidden="true"><use href="#i-send" /></svg>
          <span>Launch Replay</span>
        </button>
        <button
          className="btn-outline"
          disabled={!(sessionState === "running" || paused)}
          onClick={() => togglePause(paused)}
        >
          <svg className="sm" aria-hidden="true">
            <use href={paused ? "#i-play" : "#i-pause"} />
          </svg>
          <span>{paused ? "Resume" : "Pause"}</span>
        </button>
        <button className="btn-outline" onClick={reset}>
          <svg className="sm" aria-hidden="true"><use href="#i-rotate" /></svg>
          Reset
        </button>
      </div>

      <div className="minirow">
        <div className="miniselect">
          <span>WINDOW</span>
          <MiniSelect
            label="Detection window seconds"
            value={String(params.window_s)}
            options={[5, 10, 20, 30].map((v) => ({ value: String(v), text: `${v} s` }))}
            onChange={(v) => setParams({ ...params, window_s: Number(v) })}
          />
        </div>
        <div className="miniselect">
          <span>CADENCE</span>
          <MiniSelect
            label="Replay tick cadence"
            value={String(params.tick_ms)}
            options={[500, 1000, 2000].map((v) => ({ value: String(v), text: `${v / 1000} s` }))}
            onChange={(v) => setParams({ ...params, tick_ms: Number(v) })}
          />
        </div>
      </div>
    </section>
  );
}
