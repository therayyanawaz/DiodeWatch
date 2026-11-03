import { useEffect, useState } from "react";
import { api } from "../api";
import { fmt } from "../format";
import type { Diode } from "../types";
import Help from "./Help";

type Cell = { text: string; cls: string };

/* Everything a claim on this panel rests on is decided here, from the server's
   own verdict object. `data/diode_status.json` is written by the host whose
   innocence it attests, so its counters are allegations; only /api/diode knows
   the heartbeat's age. A client that re-derived a verdict from the raw fields
   could call a dead monitor a clean one. */
function view(d: Diode) {
  const p = d.proof || {};
  const proof = p.proof || "unknown";
  const verdict = p.verdict || "NO-STATUS";
  const ob = d.outbound_bytes;

  if (!d.available) {
    const dash: Cell = { text: "—", cls: "dcell-value" };
    return {
      link: "offline",
      bytes: dash,
      conns: dash,
      viol: dash,
      drop: dash,
      note: {
        text: "Egress monitor is not running — these counters come from the "
          + "Linux kernel (nftables + /proc/net), so they need a Linux host "
          + "with root: python -m src.diode.cli monitor",
        cls: "quality-note warn-text",
      },
    };
  }

  // A tick from a host with no readable kernel socket table observed nothing,
  // so its counters describe the absent observer, not an absent egress. This
  // rule is not conditional on the verdict: when the proof is "unknown" the
  // bytes cell reads "not observed" and these must not contradict it.
  const seen = d.monitor_available === true;
  const nv = d.violations_total || 0;
  const conns: Cell = {
    text: seen ? fmt(d.outbound_connections || 0) : "—",
    cls: "dcell-value",
  };
  const viol: Cell = {
    text: seen ? fmt(nv) : "—",
    cls: "dcell-value" + (seen && nv > 0 ? " warn" : ""),
  };
  const drop: Cell = {
    text: d.dropped_packets == null ? "n/a" : fmt(d.dropped_packets),
    cls: "dcell-value",
  };

  if (proof === "unknown") {
    return {
      link: "offline",
      bytes: { text: "not observed", cls: "dcell-value warn" },
      conns,
      viol,
      drop,
      note: {
        text: `Diode proof ${verdict}: ${(p.reasons || ["no verdict from server"])[0]}`,
        cls: "quality-note warn-text",
      },
    };
  }

  return {
    link: verdict === "ENFORCED-VERIFIED" ? "enforced"
      : verdict === "ENFORCED-UNVERIFIED" ? "unverified" : "monitor",
    bytes: ob === 0
      ? { text: "0", cls: "dcell-value" }
      : { text: fmt(ob), cls: "dcell-value bad" },
    conns,
    viol,
    drop,
    note: null,
  };
}

export default function DiodeProof() {
  const [status, setStatus] = useState<Diode | null>(null);

  const head = (
    <div className="card-head">
      <b>Diode Proof</b>
      {" "}<Help about="Diode Proof">Live egress counters behind the one-way claim: bytes
        and connections stay zero when they are measured, and kernel drops count
        enforced denials. Monitor-only hosts and unmeasured ticks say so
        explicitly.</Help>
    </div>
  );

  useEffect(() => {
    let gone = false;
    const pull = () => {
      api.diode()
        .then((d) => { if (!gone) setStatus(d); })
        .catch(() => { if (!gone) setStatus(null); });
    };
    pull();
    const id = window.setInterval(pull, 2000);
    return () => {
      gone = true;
      window.clearInterval(id);
    };
  }, []);

  if (!status) {
    return (
      <section className="card diodepanel" id="diode">
        {head}
        <div className="diode-link" data-state="offline" role="img"
             aria-label="One-way link diagram: the egress counters are unavailable">
          <svg viewBox="0 0 340 74" aria-hidden="true">
            <text className="dl-label" x="8" y="12">NET</text>
            <text className="dl-label" x="322" y="12" textAnchor="end">ENCLAVE</text>
            <path className="dl-wire" d="M20 30 H320" />
            <path className="dl-gate" d="M150 18 L178 30 L150 42 Z" />
            <line className="dl-gate" x1="178" y1="16" x2="178" y2="44" />
          </svg>
        </div>
        <p className="quality-note warn-text">
          Egress status unavailable — /api/diode did not answer.
        </p>
      </section>
    );
  }

  const v = view(status);
  const cells: Array<{ label: string; cell: Cell; hero?: boolean }> = [
    { label: "OUTBOUND BYTES", cell: v.bytes, hero: true },
    { label: "CONNECTIONS", cell: v.conns },
    { label: "VIOLATIONS", cell: v.viol },
    { label: "KERNEL DROPS", cell: v.drop },
  ];

  return (
    <section className="card diodepanel" id="diode">
      {head}
      <div className="diode-link" data-state={v.link} role="img"
           aria-label="One-way link diagram: traffic flows toward the enclave through the diode gate; the return path is physically blocked">
        <svg viewBox="0 0 340 74" aria-hidden="true">
          <text className="dl-label" x="8" y="12">NET</text>
          <text className="dl-label" x="322" y="12" textAnchor="end">ENCLAVE</text>
          <path className="dl-wire" d="M20 30 H320" />
          <path className="dl-flow" d="M20 30 H145" />
          <path className="dl-flow" d="M183 30 H320" />
          <path className="dl-gate" d="M150 18 L178 30 L150 42 Z" />
          <line className="dl-gate" x1="178" y1="16" x2="178" y2="44" />
          <path className="dl-wire" d="M296 56 H170" strokeDasharray="3 5" opacity="0.55" />
          <path className="dl-blocked" d="M158 48 L170 60 M170 48 L158 60" />
          <line className="dl-blocked" x1="152" y1="54" x2="176" y2="54" />
          <text className="dl-no" x="288" y="48" textAnchor="end">NO RETURN PATH</text>
        </svg>
      </div>
      <div className="diode-grid">
        {cells.map(({ label, cell, hero }) => (
          <div key={label} className={`dcell${hero ? " dcell--hero" : ""}`}>
            <div className={cell.cls}>{cell.text}</div>
            <div className="dcell-label">{label}</div>
          </div>
        ))}
      </div>
      {v.note && <p className={v.note.cls}>{v.note.text}</p>}
    </section>
  );
}
