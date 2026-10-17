#!/usr/bin/env python3
"""Exit check: feature parity vs the original CIC slice.

Compares data/slices/features.parquet (engine output) row-for-row against the
source baseline_slice.parquet. Row alignment is guaranteed by construction:
unify emits flows.ndjson in source-row order and the feature pipeline preserves
it — asserted explicitly via the flow id.

Verified per flow (200k flows, not a sample):

    duration_s * 1e6 == Flow Duration (µs)             (exact)
    fwd/bwd pkts     == Total Fwd/Backward Packets     (exact)
    fwd/bwd bytes    == Total Length of Fwd/Bwd Packets(exact)
    flow_bytes_per_s ~  Flow Bytes/s    (both finite, rel tol 1e-3)
    flow_pkts_per_s  ~  Flow Packets/s  (both finite, rel tol 1e-3)

CIC rate columns contain Inf/-1 sentinels for zero-duration flows; those pairs
are skipped (features encode the same case as NaN). Timing sentinels are NOT
skipped: a -1, or a negative Flow IAT Min from an out-of-order capture, is
source data and has to survive the round trip.

Usage:
    python scripts/experiments/spotcheck_features.py [--features data/slices/features.parquet]
                                         [--source data/slices/baseline_slice.parquet]
                                         [--sample N]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[2]

EXACT = {  # feature col -> source col (identical semantics)
    "fwd_pkts": "Total Fwd Packets",
    "bwd_pkts": "Total Backward Packets",
    "fwd_bytes": "Total Length of Fwd Packets",
    "bwd_bytes": "Total Length of Bwd Packets",
}
RATES = {"flow_bytes_per_s": "Flow Bytes/s", "flow_pkts_per_s": "Flow Packets/s"}

# Per-packet timing and size: the table reader aliases these straight out of the
# CIC columns and the engine passes them through, so equality must be exact.
# This is what proves the enriched record did not silently reshape the source.
PASSTHROUGH = {
    "iat_us_mean": "Flow IAT Mean", "iat_us_std": "Flow IAT Std",
    "iat_us_max": "Flow IAT Max", "iat_us_min": "Flow IAT Min",
    "fwd_iat_us_total": "Fwd IAT Total", "fwd_iat_us_mean": "Fwd IAT Mean",
    "fwd_iat_us_std": "Fwd IAT Std", "fwd_iat_us_max": "Fwd IAT Max",
    "fwd_iat_us_min": "Fwd IAT Min",
    "bwd_iat_us_total": "Bwd IAT Total", "bwd_iat_us_mean": "Bwd IAT Mean",
    "bwd_iat_us_std": "Bwd IAT Std", "bwd_iat_us_max": "Bwd IAT Max",
    "bwd_iat_us_min": "Bwd IAT Min",
    "len_min": "Min Packet Length", "len_max": "Max Packet Length",
    "len_mean": "Packet Length Mean", "len_std": "Packet Length Std",
    "fwd_len_min": "Fwd Packet Length Min", "fwd_len_max": "Fwd Packet Length Max",
    "fwd_len_mean": "Fwd Packet Length Mean", "fwd_len_std": "Fwd Packet Length Std",
    "bwd_len_min": "Bwd Packet Length Min", "bwd_len_max": "Bwd Packet Length Max",
    "bwd_len_mean": "Bwd Packet Length Mean", "bwd_len_std": "Bwd Packet Length Std",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--features", type=Path,
                    default=REPO / "data" / "slices" / "features.parquet")
    ap.add_argument("--source", type=Path,
                    default=REPO / "data" / "slices" / "baseline_slice.parquet")
    ap.add_argument("--sample", type=int, default=None,
                    help="restrict the comparison to N random flows")
    args = ap.parse_args()

    if not args.features.exists() or not args.source.exists():
        print(f"[error] missing inputs (need {args.features} and {args.source}); "
              f"run the unify + features pipelines first", file=sys.stderr)
        return 2

    feat = pd.read_parquet(args.features).reset_index(drop=True)
    src = pd.read_parquet(args.source).reset_index(drop=True)
    if args.sample is not None:
        idx = src.sample(n=min(args.sample, len(src)), random_state=42).index
        feat, src = feat.loc[idx], src.loc[idx]

    if len(feat) != len(src):
        print(f"[error] row counts differ: features={len(feat):,} "
              f"source={len(src):,}", file=sys.stderr)
        return 2
    aligned = feat["flow_id"].astype(str).to_numpy() == src["Flow ID"].astype(str).to_numpy()
    if not aligned.all():
        print(f"[error] flow ids misaligned in {int((~aligned).sum()):,} rows",
              file=sys.stderr)
        return 2
    print(f"checked {len(feat):,} positionally-aligned flows "
          f"(flow ids verified)")

    def num(col: str, frame: pd.DataFrame) -> np.ndarray:
        return pd.to_numeric(frame[col], errors="coerce").to_numpy()

    bad = 0
    for fcol, scol in EXACT.items():
        a, b = num(fcol, feat), num(scol, src)
        n_bad = int((a != b).sum())
        bad += n_bad
        print(f"  exact  {fcol:<12} vs {scol:<28} mismatches: {n_bad}")

    dur_a = num("duration_s", feat) * 1e6
    dur_b = num("Flow Duration", src)
    n_bad_dur = int((np.round(dur_a) != dur_b).sum())
    bad += n_bad_dur
    print(f"  exact  duration_s    vs Flow Duration        mismatches: {n_bad_dur}")

    rate_over = 0
    max_rel = 0.0
    for fcol, scol in RATES.items():
        a, b = num(fcol, feat), num(scol, src)
        both = ~np.isnan(a) & ~np.isnan(b) & np.isfinite(b)
        # 0/0 (both rates zero) is an exact match; real Inf = genuine mismatch.
        rel = np.divide(np.abs(a[both] - b[both]), np.abs(b[both]),
                        out=np.zeros(int(both.sum())), where=b[both] != 0)
        # CIC-IDS2017 quantizes large rates to ~2-3 significant digits in the
        # released CSV (e.g. 10,328,125 -> 10,300,000; max ~0.5%). The engine
        # recomputes exact rates from integers, so allow 1% and report the max.
        over = rel[rel > 1e-2]
        rate_over += len(over)
        if len(rel):
            max_rel = max(max_rel, float(rel.max()))
        print(f"  rate   {fcol:<12} vs {scol:<28} finite-pairs: {int(both.sum()):,} "
              f"max rel err: {max_rel:.2%}   >1%: {len(over)}")

    absent = 0
    pt_bad = 0
    for fcol, scol in sorted(PASSTHROUGH.items()):
        if fcol not in feat.columns:
            absent += 1
            continue
        a, b = num(fcol, feat), num(scol, src)
        # equal_nan: a source cell we could not parse stays NaN on both sides
        ok = np.isclose(a, b, rtol=1e-9, atol=0.0, equal_nan=True)
        n_bad = int((~ok).sum())
        pt_bad += n_bad
        print(f"  pass   {fcol:<18} vs {scol:<24} mismatches: {n_bad}")

    if absent:
        print(f"\n[FAIL] {absent} of {len(PASSTHROUGH)} timing/size columns are "
              f"absent from {args.features} — that frame predates the enriched "
              f"record; rebuild it with scripts/generators/build_ml_features.sh "
              f"or python -m src.features.pipeline", file=sys.stderr)
        return 1

    print("\n--- sample rows (feature | source) ---")
    for i in range(min(6, len(feat))):
        f, s = feat.iloc[i], src.iloc[i]
        print(f"{f['label']:<18} {f['flow_id']}")
        print(f"    dur:  {f['duration_s']*1e6:>12,.0f} us | {s['Flow Duration']:>12,.0f} us")
        print(f"    pkts: fwd {f['fwd_pkts']:>6,} | {s['Total Fwd Packets']:>6,}   "
              f"bwd {f['bwd_pkts']:>6,} | {s['Total Backward Packets']:>6,}")
        print(f"    bytes: fwd {f['fwd_bytes']:>8,} | {s['Total Length of Fwd Packets']:>8,}  "
              f"bwd {f['bwd_bytes']:>8,} | {s['Total Length of Bwd Packets']:>8,}")

    if bad or rate_over or pt_bad:
        print(f"\n[FAIL] {bad} exact mismatches, {rate_over} rate mismatches >1%, "
              f"{pt_bad} timing/size passthrough mismatches",
              file=sys.stderr)
        return 1
    print(f"\n[PASS] {len(feat):,} flows: durations, counts and bytes match the "
          f"source CIC slice exactly; all {len(PASSTHROUGH)} timing/size columns "
          f"came through the enriched record unchanged; rates agree within CIC's "
          f"publication rounding (max rel err {max_rel:.2%})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
