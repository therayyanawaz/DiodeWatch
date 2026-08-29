"""Feature pipeline CLI: canonical flow records -> frozen feature parquet.

    python -m src.features.pipeline --input data/slices/flows.ndjson \
                                    --out data/slices/features.parquet

Reads the unify NDJSON (one canonical flow record per line), computes the
feature frame declared in specs.FEATURES (see `python -m src.features.pipeline
--describe`), and writes a parquet whose column list is exactly the active
registry in order.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import pandas as pd

from . import __version__
from .engine import build_features
from .specs import ACTIVE_NAMES, FEATURES, describe


def read_flows(path: Path, limit: int | None = None) -> pd.DataFrame:
    """Load canonical flow NDJSON (streamed line-array to keep dtypes honest)."""
    import json

    recs: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            recs.append(json.loads(line))
            if limit is not None and len(recs) >= limit:
                break
    df = pd.DataFrame(recs)
    if df.empty:
        raise ValueError(f"no records found in {path}")
    return df


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m src.features.pipeline",
        description="Turn canonical flow NDJSON into the frozen features parquet.",
    )
    ap.add_argument("--input", help="canonical flow NDJSON from src.ingest.unify")
    ap.add_argument("--out", help="output .parquet path")
    ap.add_argument("--limit", type=int, default=None,
                    help="process only the first N flows (smoke runs)")
    ap.add_argument("--describe", action="store_true",
                    help="print the feature registry and exit")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    if args.describe:
        print(describe())
        return 0
    if not args.input or not args.out:
        ap.error("--input and --out are required unless --describe is given")

    t0 = time.perf_counter()
    flows = read_flows(Path(args.input), limit=args.limit)
    features = build_features(flows)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    features.to_parquet(args.out, index=False)

    elapsed = time.perf_counter() - t0
    print(f"[features] {len(features):,} flows x {len(ACTIVE_NAMES)} features "
          f"-> {args.out} ({elapsed:.1f}s)", file=sys.stderr)
    fam: dict[str, int] = {}
    by_name = {f["name"]: f["family"] for f in FEATURES}
    for name in ACTIVE_NAMES:
        fam[by_name[name]] = fam.get(by_name[name], 0) + 1
    print(f"[features] columns by family: {fam}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
