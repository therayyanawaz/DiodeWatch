import Help from "./Help";
import Radar from "./Radar";
import { fmt } from "../format";
import type { ClassStat } from "../types";

/* The wall's own icon table. No axis for slowdos: SlowDoSRule reports threat_class
   "ddos" (src/detectors/slowdos.py), so a slowdos icon could never be reached. */
const CLASS_ICON: Record<string, string> = {
  ddos: "i-bolt", scan: "i-radar", exfil: "i-send",
  beacon: "i-radio", dga: "i-dna", bot: "i-bell",
  tls_anomaly: "i-lock", bruteforce: "i-bolt", webattack: "i-bolt",
  infiltration: "i-send",
};

const SLOTS = [0, 1, 2, 3];

export default function ClassTiles({ classStats, classLabel }: {
  classStats: Record<string, ClassStat>;
  classLabel: (tc: string) => string;
}) {
  const top = Object.entries(classStats)
    .sort((a, b) => b[1].count - a[1].count).slice(0, 4);

  return (
    <section className="card">
      <div className="card-head">
        <b>Threat Classes</b>
        {" "}<Help about="Threat Classes">Top 4 alert classes in this session by count;
          the radar maps their shape against each other.</Help>
        <span className="muted">top 4 by count</span>
      </div>
      <div className="tilegrid">
        {SLOTS.map((i) => {
          const entry = top[i];
          const tc = entry ? entry[0] : null;
          const info = entry ? entry[1] : null;
          return (
            <div className={`tile tile-${i}` + (tc ? "" : " tile-empty")} key={i}>
              <div className="tile-top">
                <span className="tile-name">{tc ? classLabel(tc) : " -"}</span>
                <svg aria-hidden="true">
                  <use href={`#${tc ? (CLASS_ICON[tc] || "i-pulse") : "i-pulse"}`} />
                </svg>
              </div>
              <div className="tile-count">{tc ? fmt(info?.count ?? 0) : " -"}</div>
              <div className="tile-bottom">
                <span className="tile-attack">{tc ? (info?.attack || " -") : "AWAITING"}</span>
                <span className="tile-sev">{tc ? (info?.severity || " -").toUpperCase() : "SIGNAL"}</span>
              </div>
            </div>
          );
        })}
      </div>
      <Radar classStats={classStats} classLabel={classLabel} />
    </section>
  );
}
