#!/usr/bin/env python3
"""Throughput & latency benchmark.

    python scripts/benchmarks/bench_throughput.py [--rates 1000,2500,5000,7500,10000]
                                       [--reps 10] [--out results/benchmarks]

Three measurements, all on this machine, all reproducible:

  1. Windowed rule-engine ladder (the streaming path the dashboard replays):
     for each offered rate R (flows/sec), bootstrap 10 windows of R*window_s
     canonical flows from the CIC-IDS2017 Wednesday slice and time the full
     window build + rule evaluation. A rate is SUSTAINABLE when evaluation
     finishes inside the window it must fill (headroom = window_s / eval_s);
     we report the max rate with headroom >= 2 as the deployment rating.

  2. Batch ML scoring: the flow+window-context model scoring feature rows
     from the full Wednesday corpus day (chunked predict_proba).

  3. Alert-store ingest: alerts/second into SQLite.

Writes results/benchmarks/throughput.json and prints a summary table.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from src.detectors.rules import run_rules

SLICE = REPO / "data/slices/flows.ndjson"
WED_FEATURES = (REPO / "data/slices/ml/"
                "features__Wednesday-workingHours.pcap_ISCX.csv.parquet")
OUT_DIR = REPO / "results/benchmarks"
WINDOW_S = 10


def _percentile(sorted_vals: list[float], q: float) -> float:
    """Nearest-rank percentile on a pre-sorted list."""
    if not sorted_vals:
        return 0.0
    k = min(len(sorted_vals) - 1, max(0, round(q * (len(sorted_vals) - 1))))
    return sorted_vals[k]


def load_slice() -> list[dict]:
    with SLICE.open(encoding="utf-8") as fh:
        recs = [json.loads(line) for line in fh if line.strip()]
    print(f"[bench] corpus slice: {len(recs):,} canonical flows "
          f"({SLICE.name}, CIC-IDS2017 Wednesday)", flush=True)
    return recs


def _dense_window(recs: list[dict], rate: int, rng) -> list[dict]:
    """One streaming-shaped window: R flows/s of real corpus traffic.

    Rows are bootstrapped from the corpus (byte-accurate flow shapes), then
    re-timed into a single dense 10 s window at exactly the offered rate -
    the shape a live stream at R flows/s actually delivers, unlike sparse
    random timestamps which fragment into thousands of near-empty windows.
    """
    n = rate * WINDOW_S
    idx = rng.choice(len(recs), size=n, replace=True)
    win = [dict(recs[i]) for i in idx]
    start = 1_500_000_000.0
    for i, w in enumerate(win):
        w["ts_epoch"] = start + i / rate
        w["timestamp"] = pd.Timestamp(start + i / rate, unit="s", tz="UTC") \
            .strftime("%Y-%m-%dT%H:%M:%S")
    return win


def ladder(recs: list[dict], rates: list[int], reps: int) -> dict:
    """Offered-rate ladder: R flows/s -> one dense R*10-row window per rep."""
    import numpy as np

    rng = np.random.default_rng(42)
    results = {}
    for rate in rates:
        n = rate * WINDOW_S
        evals_ms, alerts_seen = [], 0
        for _ in range(reps):
            win = _dense_window(recs, rate, rng)
            t0 = time.perf_counter()
            alerts = run_rules(pd.DataFrame(win), window_s=WINDOW_S)
            evals_ms.append((time.perf_counter() - t0) * 1000.0)
            alerts_seen += len(alerts)
        s = sorted(evals_ms)
        med = statistics.median(s)
        headroom = WINDOW_S / (med / 1000.0)
        per_flow = sorted(ms / n for ms in evals_ms)
        results[rate] = {
            "n_per_window": n,
            "reps": reps,
            "eval_ms_median": round(med, 1),
            "eval_ms_p95": round(_percentile(s, 0.95), 1),
            "eval_ms_p99": round(_percentile(s, 0.99), 1),
            "per_flow_ms_p95": round(_percentile(per_flow, 0.95), 4),
            "sustained_fps_at_rate": round(n / (med / 1000.0), 1),
            "headroom_x": round(headroom, 2),
            "sustainable": headroom >= 1.0,
            "alerts_per_window_median": alerts_seen // reps,
        }
        r = results[rate]
        print(f"  {rate:>6,} flows/s x {WINDOW_S}s = {n:>7,} rows/window: "
              f"eval {r['eval_ms_median']:>8,.1f} ms "
              f"(p95 {r['eval_ms_p95']:>8,.1f})  "
              f"headroom {r['headroom_x']:>5.1f}x  "
              f"{'OK' if r['sustainable'] else 'OVERLOAD'}", flush=True)
    ok_rates = [r for r, v in results.items() if v["sustainable"] and
                v["headroom_x"] >= 2.0]
    rating = max(ok_rates) if ok_rates else 0
    print(f"[bench] deployment rating (headroom >= 2x): "
          f"{rating:,} flows/s", flush=True)
    return {
        "rates": results,
        "rating_headroom2x": rating,
        "methodology": ("bootstrap-resampled corpus flows re-timed into one "
                        "dense window at the offered rate; sustainable when "
                        "evaluation finishes inside the 10 s it must fill"),
    }


def replay_end_to_end(recs: list[dict], max_rows: int) -> dict:
    """Sanity pass through the real replay engine (windowing included).

    Capped to `max_rows` corpus flows by default: a contiguous, time-sorted
    block of the slice (a capture-shaped replay). An unsorted sample scatters
    rows across thousands of tiny windows, which is window-COUNT bound
    (per-window pandas overhead) and measures nothing about flow rate, the
    ladder above is the throughput measurement, this is the latency one.
    """
    from src.alerts.watch import replay_flows

    ordered = sorted(recs, key=lambda r: float(r.get("ts_epoch") or 0.0))
    if len(ordered) > max_rows:
        start = len(ordered) // 4  # fixed, deterministic mid-capture block
        ordered = ordered[start:start + max_rows]
    recs = ordered
    windows, alerts, flows = 0, 0, 0
    t0 = time.perf_counter()
    evals = []
    for w in replay_flows(recs, window_s=WINDOW_S):
        windows += 1
        flows += w.n_flows
        alerts += len(w.alerts)
        evals.append(w.eval_ms)
    wall = time.perf_counter() - t0
    s = sorted(evals)
    out = {
        "flows": flows, "windows": windows, "alerts": alerts,
        "wall_s": round(wall, 1),
        "eval_ms_p50": round(_percentile(s, 0.50), 1),
        "eval_ms_p95": round(_percentile(s, 0.95), 1),
        "eval_ms_p99": round(_percentile(s, 0.99), 1),
        "n_windows_timed": len(s),
        "note": ("slice replay is window-count bound (tiny windows from "
                 "sparse capture times); use the ladder for rate ratings"),
    }
    print(f"[bench] end-to-end replay ({flows:,} flows / {windows:,} windows): "
          f"p95 window eval {out['eval_ms_p95']:,.1f} ms", flush=True)
    return out


def batch_ml(max_rows: int) -> dict:
    """Flow-context model batch scoring on the Wednesday corpus day."""
    from src.detectors.ml.features import load_features
    from src.detectors.ml.supervised_windows import FlowContextModel

    if not WED_FEATURES.exists():
        print(f"[bench] skip ML batch: {WED_FEATURES.name} missing")
        return {}
    df = load_features(WED_FEATURES)
    total = len(df)
    if max_rows and total > max_rows:
        df = df.head(max_rows)
    model = FlowContextModel.load(REPO / "models")
    chunk = 50_000
    rates, lat = [], []
    for start in range(0, len(df), chunk):
        part = df.iloc[start:start + chunk]
        t0 = time.perf_counter()
        model.predict_proba(part)
        dt = time.perf_counter() - t0
        rates.append(len(part) / dt)
        lat.append(dt * 1000.0)
    out = {
        "model": "ml.flowctx (flow + window context LightGBM)",
        "rows_scored": len(df),
        "corpus_rows_total": int(total),
        "chunk_rows": chunk,
        "scoring_fps_min": round(min(rates), 1),
        "scoring_fps_median": round(statistics.median(rates), 1),
        "scoring_fps_max": round(max(rates), 1),
        "chunk_latency_ms_p95": round(_percentile(sorted(lat), 0.95), 1),
    }
    print(f"[bench] ML batch scoring: {out['scoring_fps_median']:,.0f} flows/s "
          f"median over {out['rows_scored']:,} rows (min "
          f"{out['scoring_fps_min']:,.0f})", flush=True)
    return out


def store_ingest() -> dict:
    """Alert-store ingest rate: 20k alerts through insert_many."""
    import tempfile

    from src.alerts.schema import alert_from_dict
    from src.alerts.store import AlertStore, iter_jsonl

    src = REPO / "data/slices/ml_alerts__Wednesday.jsonl"
    if not src.exists():
        print("[bench] skip store ingest: ml_alerts__Wednesday.jsonl missing")
        return {}
    alerts = [alert_from_dict(d) for _, d in
              zip(range(20_000), iter_jsonl(src))]
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db = Path(tf.name)
    try:
        with AlertStore(db) as store:
            t0 = time.perf_counter()
            inserted, _, _ = store.insert_many(alerts)
            dt = time.perf_counter() - t0
            t1 = time.perf_counter()
            store.recent(limit=20)
            q_ms = (time.perf_counter() - t1) * 1000.0
        out = {
            "alerts_inserted": inserted,
            "insert_s": round(dt, 2),
            "inserts_per_s": round(inserted / dt, 1),
            "recent20_query_ms": round(q_ms, 2),
        }
        print(f"[bench] store ingest: {out['inserts_per_s']:,.0f} alerts/s "
              f"({inserted:,} in {out['insert_s']} s), "
              f"recent(20) {out['recent20_query_ms']} ms", flush=True)
        return out
    finally:
        db.unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rates", default="1000,2500,5000,7500,10000")
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--replay-rows", type=int, default=40_000,
                    help="cap for the end-to-end replay latency pass")
    ap.add_argument("--ml-rows", type=int, default=200_000,
                    help="cap for batch ML scoring rows")
    ap.add_argument("--skip-ladder", action="store_true")
    ap.add_argument("--skip-replay", action="store_true")
    args = ap.parse_args()
    rates = [int(r) for r in args.rates.split(",")]

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "throughput.json"
    result = {
        "machine_note": "single developer workstation; timings are this host",
        "window_s": WINDOW_S,
    }

    def save() -> None:
        out.write_text(json.dumps(result, indent=2))

    recs = load_slice()
    if not args.skip_ladder:
        print(f"[bench] offered-rate ladder ({args.reps} reps/rate):", flush=True)
        result["ladder"] = ladder(recs, rates, args.reps)
        save()
    if not args.skip_replay:
        result["replay_end_to_end"] = replay_end_to_end(recs, args.replay_rows)
        save()
    result["ml_batch"] = batch_ml(args.ml_rows)
    save()
    result["store_ingest"] = store_ingest()
    save()
    print(f"[bench] wrote {out.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
