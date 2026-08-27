"""Unify raw traffic into canonical one-flow-per-line NDJSON.

    python -m src.ingest.unify --input data/raw/wednesday.parquet --out data/slices/flows.ndjson
    python -m src.ingest.unify --input data/pcaps/ --format pcap --out data/slices/flows.ndjson

Two sources, one output schema (src/ingest/schema.py::FLOW_FIELDS):

  * table (CICFlowMeter-style .csv/.parquet) — one row per flow, standardized;
  * pcap (.pcap/.pcapng) — packets aggregated to timeout-based bidirectional flows.

`--input` may be a single file or a directory (every supported file is
processed in sorted order and the records concatenated).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from contextlib import ExitStack
from pathlib import Path

from . import __version__
from .pcap_reader import PCAP_SUFFIXES, stream_flows
from .table_reader import TABLE_SUFFIXES, stream_records

SUPPORTED = TABLE_SUFFIXES | PCAP_SUFFIXES


def _classify(path: Path) -> str | None:
    if path.suffix.lower() in TABLE_SUFFIXES:
        return "table"
    if path.suffix.lower() in PCAP_SUFFIXES:
        return "pcap"
    return None


def _collect_inputs(raw: str) -> list[tuple[Path, str]]:
    p = Path(raw)
    if p.is_dir():
        files = sorted(p.rglob("*"))
        jobs = [(f, _classify(f)) for f in files if _classify(f)]
        if not jobs:
            raise SystemExit(f"[error] no supported files under {p} "
                             f"(wanted {sorted(SUPPORTED)})")
        return jobs
    kind = _classify(p)
    if kind is None:
        raise SystemExit(f"[error] unsupported input {p} (wanted {sorted(SUPPORTED)})")
    return [(p, kind)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m src.ingest.unify",
        description="Unify CICFlowMeter tables or pcap captures into canonical flow NDJSON.",
    )
    ap.add_argument("--input", required=True,
                    help="file or directory of .csv/.parquet/.pcap/.pcapng captures")
    ap.add_argument("--out", required=True,
                    help="output .ndjson path (use '-' for stdout)")
    ap.add_argument("--format", choices=["auto", "table", "pcap"], default="auto",
                    help="force a source kind instead of inferring from file suffix")
    ap.add_argument("--limit", type=int, default=None,
                    help="stop after N records (smoke runs)")
    ap.add_argument("--flow-timeout", type=float, default=120.0,
                    help="pcap idle-flow timeout in seconds (default 120)")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    jobs = _collect_inputs(args.input)
    if args.format != "auto":
        jobs = [(p, args.format) for p, _ in jobs]

    n_out = 0
    labels: Counter = Counter()
    with ExitStack() as stack:
        out_fh = (sys.stdout if args.out == "-"
                  else stack.enter_context(open(args.out, "w", encoding="utf-8")))
        for path, kind in jobs:
            print(f"[unify] {kind:>5}  {path}", file=sys.stderr)
            if kind == "table":
                if args.limit is not None and n_out >= args.limit:
                    break
                for rec in stream_records(path, limit=args.limit, batch_size=100_000):
                    out_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    n_out += 1
                    if rec["label"]:
                        labels[rec["label"]] += 1
                    if args.limit is not None and n_out >= args.limit:
                        break
            else:  # pcap
                stats: dict = {}
                if args.limit is not None and n_out >= args.limit:
                    break
                for rec in stream_flows(path, flow_timeout=args.flow_timeout,
                                        stats=stats):
                    out_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    n_out += 1
                    if args.limit is not None and n_out >= args.limit:
                        break
                print(f"      packets={stats.get('pkts', 0):,} "
                      f"ip={stats.get('ip_pkts', 0):,} "
                      f"skipped={stats.get('skipped', 0):,} "
                      f"idle-timeouts={stats.get('timeouts', 0):,} "
                      f"open-at-eof={stats.get('at_eof', 0):,}",
                      file=sys.stderr)

    print(f"[unify] wrote {n_out:,} flow records -> {args.out}", file=sys.stderr)
    if labels:
        for label, n in labels.most_common():
            print(f"    {label:<22} {n:>10,}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
