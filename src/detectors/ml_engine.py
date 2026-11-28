"""Unified ML detection engine: feature vectors -> alerts.

One entry point for every ML detector; output alerts use the exact same
envelope as the rule engine (alerts.schema.Alert), so the alert store, UI and
exports cannot tell rules and ML apart.

    python -m src.detectors.ml_engine --input data/slices/features.parquet \
                                      --out data/slices/ml_alerts.jsonl

Detectors wired in:
  * flow+window-context LightGBM (default)  per-flow threat alerts with the
                            window aggregates as context features;
  * reference flow-level model (fallback)   frozen 38-feature matrix;
  * beacon       --beacon-flows <ctu-netflow.csv>   pair-level periodicity;
  * dga          --dga-domains <domains.txt>        lexical DGA/DNS-tunnel;
  * tls          --tls-ssl-log <zeek ssl.log>       JA3 watchlist + novelty.

Models load from --model-dir (default models/). The supervised model trains
on demand when --train-input features parquets are given; the other detectors
fall back to their documented heuristic mode when their artifact is missing.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.alerts.calibration import CalibrationPolicy
from src.alerts.schema import Alert, validate_alert

from .ml import beacon as beacon_mod
from .ml import dga as dga_mod
from .ml import tls_ja3 as tls_mod
from .ml.features import load_features
from .ml.supervised import SupervisedModel, metrics_summary, train_supervised
from .ml.supervised_windows import FlowContextModel


def _write_alerts(alerts: list[Alert], out_path: str | Path) -> int:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    bad = 0
    with p.open("w", encoding="utf-8") as fh:
        for a in alerts:
            problems = validate_alert(a)
            if problems:
                bad += 1
                print(f"[warn] invalid alert ({'; '.join(problems)})", file=sys.stderr)
            fh.write(json.dumps(a.to_dict(), ensure_ascii=False) + "\n")
    return bad


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m src.detectors.ml_engine",
        description="Unified ML detection engine: features -> alerts.",
    )
    ap.add_argument("--input", required=True,
                    help="features parquet (src.features.pipeline output)")
    ap.add_argument("--out", required=True, help="output NDJSON alert file")
    ap.add_argument("--model-dir", default="models")
    ap.add_argument("--threshold", type=float, default=0.9,
                    help="min predicted threat probability to alert")
    ap.add_argument("--limit", type=int, default=None, help="score only N rows")
    ap.add_argument("--train-input", nargs="*", default=None,
                    help="features parquets used to train the supervised model "
                         "when no model artifact exists yet")
    ap.add_argument("--beacon-flows",
                    help="CTU-style labeled NetFlow CSV for the beacon detector")
    ap.add_argument("--dga-domains",
                    help="text file with one queried domain per line")
    ap.add_argument("--tls-ssl-log",
                    help="Zeek ssl.log or tls_metadata JSON-lines for the "
                         "JA3/JA4 detector")
    ap.add_argument("--calibration", default=None,
                    help="calibration artifact (default: <model-dir>/calibration.json)")
    ap.add_argument("--no-calibration", action="store_true",
                    help="write raw detector scores, ignoring the calibration artifact")
    args = ap.parse_args(argv)

    df = load_features(args.input)
    if args.limit:
        df = df.head(args.limit)
    print(f"[ml_engine] scoring {len(df):,} flows from {args.input}", file=sys.stderr)

    alerts: list[Alert] = []

    # ---- supervised (core path) ------------------------------------------
    # Primary: the flow+window-context model (scripts/checks/check_ml.py train-windows).
    # Fallbacks: the reference flow-level model, or on-demand training from
    # --train-input when no artifact exists (never silent).
    model_dir = Path(args.model_dir)
    used = None
    try:
        flowctx = FlowContextModel.load(model_dir)
        # No --threshold here: flowctx alerts on its tuned per-class values,
        # which is what the precision gate validated. --threshold applies to
        # the fallback supervised model below.
        alerts.extend(flowctx.score(df))
        proba = flowctx.predict_proba(df.head(min(len(df), 50_000)))
        used = "ml.flowctx (flow + window context)"
        classes = flowctx.classes
    except (FileNotFoundError, ValueError):
        try:
            sup = SupervisedModel.load(model_dir)
        except FileNotFoundError:
            if not args.train_input:
                print("[error] no trained model in models/, run "
                      "scripts/checks/check_ml.py train-windows (or pass --train-input "
                      "with features parquets to train the reference model)",
                      file=sys.stderr)
                return 1
            print("[ml_engine] training reference supervised model ...",
                  file=sys.stderr)
            sup, metrics = train_supervised(args.train_input, model_dir=model_dir)
            print(metrics_summary(metrics), file=sys.stderr)
        alerts.extend(sup.score(df, threshold=args.threshold))
        proba = sup.predict_proba(df.head(min(len(df), 50_000)))
        used = "ml.supervised (flow-level reference)"
        classes = sup.classes

    pmax = proba.max(axis=1)
    hit = pmax >= args.threshold
    top_classes = sorted({classes[int(k)] for k, h in zip(proba.argmax(axis=1), hit)
                          if h and classes[int(k)] != "benign"})
    print(f"[ml_engine] supervised via {used}: {int((pmax >= args.threshold).sum()):,} "
          f"flows >= {args.threshold} in sample (top classes: {top_classes})",
          file=sys.stderr)

    # ---- optional detectors ----------------------------------------------
    if args.beacon_flows:
        flows = beacon_mod.load_ctu(args.beacon_flows)
        pairs = beacon_mod.pair_series(flows)
        bm = beacon_mod.BeaconModel.load(model_dir)
        scores = bm.predict_score(pairs)
        got = beacon_mod.emit_alerts(pairs, scores, threshold=bm.threshold)
        alerts.extend(got)
        print(f"[ml_engine] beacon: {len(got)} pair alerts "
              f"(model={'lgbm' if bm.booster is not None else 'fallback rule'}, "
              f"thr={bm.threshold:.3f})", file=sys.stderr)

    if args.dga_domains:
        domains = pd_read_domains(args.dga_domains)
        try:
            dm = dga_mod.DgaModel.load(model_dir)
        except FileNotFoundError:
            print("[ml_engine] dga: no model artifact, falling back to the "
                  "transparent lexical rule", file=sys.stderr)
            dm = dga_mod.DgaModel.fallback()
        s = dm.score_domains(domains)
        got = dm.emit_alerts(domains, s, threshold=dm.threshold)
        alerts.extend(got)
        print(f"[ml_engine] dga: {len(got)} domain alerts (thr={dm.threshold:.3f})",
              file=sys.stderr)

    if args.tls_ssl_log:
        frame = tls_mod.load_ssl_log(args.tls_ssl_log)
        tm = tls_mod.TlsModel.load(model_dir)
        flagged = tm.flag(frame)
        got = tls_mod.emit_alerts(flagged)
        alerts.extend(got)
        print(f"[ml_engine] tls: {len(got)} client alerts "
              f"(watchlist={len(tm.watchlist)} hashes, "
              f"novelty={'on' if tm.iso is not None else 'unavailable'})",
              file=sys.stderr)

    if not args.no_calibration:
        cal_path = (Path(args.calibration) if args.calibration
                    else model_dir / "calibration.json")
        if args.calibration and not cal_path.exists():
            print(f"[ml_engine] calibration: explicit artifact not found: "
                  f"{cal_path}", file=sys.stderr)
            return 2
        try:
            policy = CalibrationPolicy.load(cal_path)
        except FileNotFoundError:
            print(f"[ml_engine] calibration: no artifact at {cal_path}; "
                  "writing raw detector scores", file=sys.stderr)
        except (OSError, ValueError, TypeError, KeyError) as e:
            print(f"[ml_engine] calibration: unreadable artifact {cal_path}: "
                  f"{e}; writing raw detector scores", file=sys.stderr)
        else:
            report = policy.apply(alerts)
            alerts = report.accepted
            print(f"[ml_engine] calibration: {report.calibrated:,} scored, "
                  f"{report.abstained:,} abstained -> {len(alerts):,} kept",
                  file=sys.stderr)

    bad = _write_alerts(alerts, args.out)
    print(f"[ml_engine] wrote {len(alerts):,} alerts -> {args.out}"
          + (f" ({bad} invalid)" if bad else ""), file=sys.stderr)
    return 0


def pd_read_domains(path: str | Path):
    import pandas as pd

    lines = [ln.strip() for ln in Path(path).read_text(encoding="utf-8").splitlines()]
    return pd.Series([ln for ln in lines if ln and not ln.startswith("#")],
                     dtype="string")


if __name__ == "__main__":
    raise SystemExit(main())
