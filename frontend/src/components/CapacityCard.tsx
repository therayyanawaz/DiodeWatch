import { fmt } from "../format";
import type { Kpi } from "../useEased";
import Help from "./Help";

/* The deployment rating, not a measurement: one owner for the figure, because
   the gauge divides by it and the printed target has to come from the same
   constant rather than from markup that can disagree with the bar. */
const CAP_TARGET = 10000;

export default function CapacityCard({ k }: { k: Kpi }) {
  return (
    <section className="card">
      <div className="card-head">
        <b>Benchmark Capacity</b>
        {" "}<Help about="Benchmark Capacity">Deployment rating: 10,000 flows/s sustained
          (twice the 5,000 requirement) measured on the live rule engine, not
          estimated.</Help>
        <span className="muted">p95 {fmt(k.p95)} ms</span>
      </div>
      <div className="cap-line">
        <span><b>{fmt(k.cap)}</b> flows/s sustained out of</span>
        <b className="cap-target">{fmt(CAP_TARGET)}</b>
      </div>
      <div className="progress">
        <i style={{ width: `${Math.min(100, (k.cap / CAP_TARGET) * 100)}%` }} />
      </div>
      <p className="muted small">Deployment rating 10,000 flows/s (2× the 5,000
        requirement), measured on the live rule engine.</p>
    </section>
  );
}
