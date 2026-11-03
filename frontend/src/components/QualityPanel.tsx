import { useEffect, useState } from "react";
import { api } from "../api";
import { fmt } from "../format";
import type { MlMetrics } from "../types";
import Help from "./Help";

type Row = { det: string; cls: string; p?: number | null; r?: number | null;
  f?: number | null; s?: number | null };

const n3 = (v: number | null | undefined) => (v == null ? "—" : Number(v).toFixed(3));
const nPct = (v: number | null | undefined) =>
  (v == null ? "—" : `${(Number(v) * 100).toFixed(1)}%`);

/* Ported from the shipped wall's loadQuality(): the table only scores channels
   gated on precision/recall/F1 by class, and the three sidecars that are gated
   on their own protocols (ROC-AUC, family holdout, synthetic plant) get their
   real numbers underneath rather than being silently dropped. */
export default function QualityPanel() {
  const [ml, setMl] = useState<MlMetrics | null>(null);

  useEffect(() => {
    let gone = false;
    api.mlMetrics().then((m) => { if (!gone) setMl(m); }).catch(() => {});
    return () => { gone = true; };
  }, []);

  const head = (
    <div className="card-head">
      <b>Detection Quality</b>
      {" "}<Help edge about="Detection Quality">Held-out scores per detector from the
        committed evaluation runs — out-of-sample only. Protocols differ by
        channel (per-class holdout, leave-one-scenario-out, family holdout,
        synthetic plant) and are stated inline.</Help>
      <span className="muted">held-out evaluation</span>
    </div>
  );

  if (!ml) {
    return (
      <section className="card qualitypanel" id="metrics">
        {head}
        <p className="quality-note">Loading /api/ml_metrics…</p>
      </section>
    );
  }

  const win = ml.window || {};
  const rows: Row[] = [];
  const disabled: string[] = [];
  for (const cls of Object.keys(win.per_class || {})) {
    const pc = win.per_class?.[cls] || {};
    // threshold=null means the tuning slice could not reach the precision gate,
    // so the class is rank-only (never alerts). Listing its 0.000 hold-out row
    // would read as measured failure rather than a disabled channel; name it in
    // the note instead of scoring it.
    if (pc.threshold == null) { disabled.push(cls); continue; }
    rows.push({ det: "ml.flowctx", cls, p: pc.precision, r: pc.recall,
      f: pc.f1, s: pc.support });
  }
  for (const cls of Object.keys(ml.supervised?.per_class || {})) {
    const pc = ml.supervised?.per_class?.[cls] || {};
    rows.push({ det: "ml.supervised (ref)", cls, p: pc.precision, r: pc.recall,
      f: pc.f1, s: pc.support });
  }
  rows.sort((a, b) => (a.det + a.cls).localeCompare(b.det + b.cls));

  const fpd = win.benign_false_positives_per_day || {};
  const totalFp = Object.values(fpd).reduce((a, b) => a + b, 0);
  const note = rows.length
    ? `protocol A: stratified per-day holdout · benign false positives: ${fmt(totalFp)} across `
      + `${Object.keys(fpd).length} held-out days (0 required) · gate: F1 ≥ 0.95 where data allows`
      + (disabled.length
        ? ` · ml.flowctx disabled by the precision gate: ${disabled.join(", ")} (rank-only, never alerts)`
        : "")
    : "results/ml/*.json not found — run: python scripts/checks/check_ml.py train-windows";

  const channels = [
    ml.beacon
      ? { name: "ml.beacon", text: `ROC-AUC ${n3(ml.beacon.roc_auc_macro)} macro (LOSO)`
          + ` · P ${n3(ml.beacon.precision)} / R ${n3(ml.beacon.recall)} @ ${n3(ml.beacon.threshold)}`
          + ` · CTU-13 ${fmt(ml.beacon.positives || 0)} positive pairs`, missing: false }
      : { name: "ml.beacon", text: "no metrics file", missing: true },
    ml.dga
      ? { name: "ml.dga", text: `F1 ${n3(ml.dga.f1)} · P ${n3(ml.dga.precision)} / R ${n3(ml.dga.recall)}`
          + ` · ${ml.dga.families ?? "—"} families held out · Umbrella FPR ${nPct(ml.dga.umbrella_fpr_at_threshold)}`,
        missing: false }
      : { name: "ml.dga", text: "no metrics file", missing: true },
    ml.tls
      ? { name: "ml.tls", text: tlsText(ml.tls), missing: false }
      : { name: "ml.tls", text: "no metrics file", missing: true },
  ];

  return (
    <section className="card qualitypanel" id="metrics">
      {head}
      {rows.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Detector</th><th>Class</th><th>P</th><th>R</th><th>F1</th><th>Support</th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.det + r.cls}>
                  <td>{r.det}</td><td>{r.cls}</td>
                  <td>{(r.p ?? 0).toFixed(3)}</td><td>{(r.r ?? 0).toFixed(3)}</td>
                  <td className={r.f != null && r.f >= 0.95 ? "f1-hi"
                    : r.f != null && r.f >= 0.75 ? "f1-mid" : ""}>{(r.f ?? 0).toFixed(3)}</td>
                  <td>{fmt(r.s || 0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="quality-note">{note}</p>
      {rows.length > 0 && (
        <div className="chan-list">
          <div className="chan-title">Other channels — each gated on its own protocol</div>
          {channels.map((c) => (
            <div className={`chan-row${c.missing ? " missing" : ""}`} key={c.name}>
              <b>{c.name}</b><span>{c.text}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function tlsText(t: NonNullable<MlMetrics["tls"]>): string {
  const plant = t.synthetic_plant_eval;
  const wl = plant?.watchlist_only;
  const nov = plant?.novelty_only;
  return (plant
    ? `synthetic plant P/R/F1 ${n3(plant.precision)}/${n3(plant.recall)}/${n3(plant.f1)}`
      + ` (n=${fmt((plant.tp || 0) + (plant.fn || 0))}, planted)`
      + (wl && nov ? ` — detections: watchlist ${fmt(wl.tp)}, novelty ${fmt(nov.tp)}` : "")
    : "no plant evaluation")
    + ` · ${t.watchlist_size ?? "—"} JA3 watchlist · novelty layer `
    + (t.novelty_available
      ? `active, flags ${nPct(t.baseline_flag_rate_on_real_eval)} of benign`
      : "disabled (fit baseline has no spread)");
}
