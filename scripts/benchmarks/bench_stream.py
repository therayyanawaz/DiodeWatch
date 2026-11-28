#!/usr/bin/env python3
"""Paced backlog and ingest-to-alert benchmark.

    python scripts/benchmarks/bench_stream.py
    python scripts/benchmarks/bench_stream.py --rates 5000,10000,50000 \
        --windows 6 --out results/benchmarks/stream.json

Each rate is a closed-loop replay: a producer emits real CIC-IDS2017
Wednesday flow shapes at the offered rate, a bounded queue blocks when full,
and the same windowed rule engine evaluates each 10 s window. Unlike
`bench_throughput.py` (which times evaluation only), the clock here starts
when a flow is offered to the queue and stops when its window's alerts exist.
The upstream capture-to-flow-export step is not in this clock.
"""
from __future__ import annotations

import argparse
import gc
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from src.alerts.stream import PacedStream

SLICE = REPO / "data/slices/flows.ndjson"
OUT_DIR = REPO / "results/benchmarks"
WINDOW_S = 10.0


def load_slice() -> list[dict]:
    with SLICE.open(encoding="utf-8") as fh:
        recs = [json.loads(line) for line in fh if line.strip()]
    print(f"[stream] corpus slice: {len(recs):,} canonical flows "
          f"({SLICE.name})", flush=True)
    return recs


def dense_stream(recs: list[dict], rate: int, windows: int):
    """Retimed CIC flows at exactly `rate` per second for `windows` windows."""
    n = int(rate * WINDOW_S * windows)
    start = 1_500_000_000.0
    for i in range(n):
        rec = dict(recs[i % len(recs)])
        rec["ts_epoch"] = start + i / rate
        yield rec


def warm_up(recs: list[dict]) -> None:
    """Pay pandas' first-call cost before the first measured window."""
    import pandas as pd

    from src.detectors.rules import run_rules

    start = 1_500_000_000.0
    flows = []
    for i in range(5_000):
        rec = dict(recs[i % len(recs)])
        rec["ts_epoch"] = start + i / 500.0
        flows.append(rec)
    run_rules(pd.DataFrame(flows), window_s=10)
    print("[stream] warm-up window complete", flush=True)


def window_rows(run) -> list[dict]:
    rows = []
    for w in run.windows:
        rows.append({
            "win_idx": w.win_idx,
            "n_flows": w.n_flows,
            "alerts": len(w.alerts),
            "fill_ms": w.fill_ms,
            "queue_ms": w.queue_ms,
            "alert_ms": w.alert_ms,
            "ingest_to_alert_ms": w.ingest_to_alert_ms,
            "eval_ms": w.eval_ms,
        })
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rates", default="5000,10000,50000")
    ap.add_argument("--windows", type=int, default=6,
                    help="10 s windows to replay per rate")
    ap.add_argument("--out", default=str(OUT_DIR / "stream.json"))
    args = ap.parse_args()
    rates = [int(r) for r in args.rates.split(",")]
    if args.windows < 1:
        ap.error("--windows must be >= 1")

    recs = load_slice()
    out = Path(args.out)
    if not out.is_absolute():
        out = REPO / out
    out.parent.mkdir(parents=True, exist_ok=True)
    result = {
        "machine_note": "single developer workstation; timings are this host",
        "window_s": WINDOW_S,
        "windows_per_rate": args.windows,
        "queue_policy": "blocking put; capacity = 2 s of offered traffic",
        "clock": "first offered canonical flow -> alert emitted",
        "rates": {},
    }
    warm_up(recs)
    started = time.perf_counter()
    for rate in rates:
        gc.collect()
        print(f"[stream] {rate:,} flows/s x {args.windows} windows ...",
              flush=True)
        run = PacedStream(dense_stream(recs, rate, args.windows), rate=rate,
                          window_s=WINDOW_S).run()
        summary = run.summary()
        summary["target_fps"] = float(rate)
        summary["headroom"] = (WINDOW_S / (summary["p95_window_ms"] / 1000.0)
                               if summary["p95_window_ms"] else 0.0)
        summary["backpressured"] = summary["blocked_puts"] > 0
        summary["sustained"] = (summary["p95_window_ms"] / 1000.0) < WINDOW_S
        summary["windows_detail"] = window_rows(run)
        result["rates"][str(rate)] = summary
        print(
            f"[stream]   arrivals {summary['arrival_fps']:,.0f}/s, "
            f"p95 window {summary['p95_window_ms']:,.0f} ms, "
            f"p95 alert {summary['p95_alert_ms']:,.0f} ms, "
            f"p95 ingest->alert {summary['p95_ingest_to_alert_ms']:,.0f} ms, "
            f"blocked {summary['blocked_puts']:.0f} puts/"
            f"{summary['blocked_ms'] / 1000.0:,.1f} s, "
            f"queue peak {summary['high_water']:.0f}/"
            f"{summary['capacity']:.0f}", flush=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    result["wall_s"] = time.perf_counter() - started
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    try:
        shown = out.relative_to(REPO)
    except ValueError:
        shown = out
    print(f"[stream] wrote {shown}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
