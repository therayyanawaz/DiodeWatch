import Help from "./Help";

const CHANNELS = [
  { icon: "i-bolt", name: "Rule Engine", sub: "tumbling windows" },
  { icon: "i-dna", name: "ML Channels", sub: "beacon · dga" },
  { icon: "i-lock", name: "Diode Monitor", sub: "kernel egress" },
];

/* Static by design: the shipped wall never touches these three ids either, so
   this card names the channels without pretending to monitor them. */
export default function DetectorsGrid() {
  return (
    <section className="card">
      <div className="card-head">
        <b>Detectors</b>
        {" "}<Help about="Detectors">The three live channels evaluated on every closed
          window: the Rule Engine (deterministic 10-second-window rules), ML
          Channels (C2-beacon and DGA sidecars) and the Diode Monitor (egress
          proof).</Help>
        <span className="muted">3 channels</span>
      </div>
      <div className="grid3">
        {CHANNELS.map((c) => (
          <div className="mini-card" key={c.name}>
            <span className="mc-icon">
              <svg aria-hidden="true"><use href={`#${c.icon}`} /></svg>
            </span>
            <b>{c.name}</b><span className="mc-sub">{c.sub}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
