import { fmt } from "../format";
import type { Kpi } from "../useEased";
import Help from "./Help";

export default function StatRow({ k }: { k: Kpi }) {
  return (
    <div className="statrow">
      <div className="card stat stat--accent">
        <span className="card-label">Flows / sec{" "}
          <Help about="Flows per second">Replayed capture throughput: flows evaluated per
            second on this machine.</Help>
        </span>
        <b>{fmt(k.replay, 1)}</b>
        <span className="delta">flows evaluated per second</span>
      </div>
      <div className="card stat">
        <span className="card-label">Alerts / sec{" "}
          <Help about="Alerts per second">Alert rate for the current replay session.</Help>
        </span>
        <b>{fmt(k.alertRate, 2)}</b>
        <span className="delta">
          {k.suppressed > 0
            ? `${fmt(k.alerts)} alerts · ${fmt(k.suppressed)} re-detections collapsed`
            : `${fmt(k.alerts)} alerts`}
        </span>
      </div>
      <div className="card stat">
        <span className="card-label">Sustained Capacity{" "}
          <Help edge about="Sustained Capacity">Highest flows per second this machine
            sustained (flows divided by window eval time); p95 window-eval latency
            below.</Help>
        </span>
        <b>{fmt(k.cap)}</b>
        <span className="delta">p95 {fmt(k.p95)} ms · p50 {fmt(k.p50)} ms</span>
      </div>
    </div>
  );
}
