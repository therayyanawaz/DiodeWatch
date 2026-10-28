import { useEffect, useState } from "react";
import AlertFeed from "./components/AlertFeed";
import CapacityCard from "./components/CapacityCard";
import ClassTiles from "./components/ClassTiles";
import DetectorsGrid from "./components/DetectorsGrid";
import DiodeProof from "./components/DiodeProof";
import EvidenceDrawer from "./components/EvidenceDrawer";
import HeroCard from "./components/HeroCard";
import QualityPanel from "./components/QualityPanel";
import StatRow from "./components/StatRow";
import TimelineChart from "./components/TimelineChart";
import Toast from "./components/Toast";
import Topbar from "./components/Topbar";
import { useEased } from "./useEased";
import { useWall } from "./useWall";

/* The wall's own time-of-day greeting, and it rolls over at noon and 18:00
   without a reload for the same reason the shipped one does. */
const greeting = () => {
  const h = new Date().getHours();
  return `${h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening"}, Analyst`;
};

export default function App() {
  const { wall, launch, togglePause, reset, classLabel, levelWord } = useWall();
  const [selected, setSelected] = useState<string | null>(null);
  const [greet, setGreet] = useState(greeting);

  useEffect(() => {
    const id = window.setInterval(() => setGreet(greeting()), 60000);
    return () => window.clearInterval(id);
  }, []);

  /* One eased object for every animated figure, so the tiles, the capacity bar
     and the hero cannot print three versions of the same flow rate. */
  const kpi = useEased({
    replay: wall.metrics.replay_fps || 0,
    alertRate: wall.metrics.alerts_per_sec || 0,
    p95: wall.metrics.p95_eval_ms || 0,
    p50: wall.metrics.p50_eval_ms || 0,
    cap: wall.metrics.sustained_fps || 0,
    flows: wall.metrics.flows || 0,
    alerts: wall.metrics.alerts || 0,
    suppressed: wall.metrics.alerts_suppressed || 0,
  });

  return (
    <div className="shell">
      <Topbar onReset={reset} />
      <main className="content">
        <section className="greeting" id="overview">
          <h1>{greet}</h1>
          <p>Passive by design · one-way by enforcement · evidence by default
            — track the live replay, capacity, and every alert.</p>
          {!wall.connected && (
            <p className="quality-note warn-text">
              Push channel down — /ws/live is not connected, so nothing below is live.
            </p>
          )}
        </section>

        <div className="cols">
          <div className="col-left">
            <HeroCard
              sessionState={wall.sessionState}
              progress={wall.progress}
              metrics={wall.metrics}
              kpi={kpi}
              defaults={wall.params}
              levelWord={levelWord}
              launch={launch}
              togglePause={togglePause}
              reset={reset}
            />
            <DetectorsGrid />
            <ClassTiles classStats={wall.classStats} classLabel={classLabel} />
          </div>
          <div className="col-right">
            <StatRow k={kpi} />
            <CapacityCard k={kpi} />
            <TimelineChart timeline={wall.timeline} />
            <AlertFeed
              alerts={wall.alerts}
              classStats={wall.classStats}
              custody={wall.custody}
              sessionState={wall.sessionState}
              sessionTotal={wall.metrics.alerts ?? 0}
              classLabel={classLabel}
              onSelect={setSelected}
            />
          </div>
        </div>

        <div className="below">
          <DiodeProof />
          <QualityPanel />
        </div>

        <footer className="foot">
          <span>DiodeWatch · Passive threat detection for one-way network links</span>
          <span className="foot-sep">·</span>
          <span>offline, zero external calls</span>
        </footer>
      </main>

      <EvidenceDrawer
        alertId={selected}
        classLabel={classLabel}
        onClose={() => setSelected(null)}
      />
      <Toast
        message={wall.error || (wall.sessionState === "finished"
          ? "Replay complete — all windows evaluated" : "")}
        isError={Boolean(wall.error)}
      />
    </div>
  );
}
