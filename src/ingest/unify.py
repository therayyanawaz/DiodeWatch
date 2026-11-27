"""Unify raw traffic into canonical one-flow-per-line NDJSON.

    python -m src.ingest.unify --input data/raw/wednesday.parquet --out data/slices/flows.ndjson
    python -m src.ingest.unify --input data/pcaps/ --format pcap --out data/slices/flows.ndjson
    python -m src.ingest.unify --input data/raw/ctu13/ --format argus --out data/slices/ctu13.ndjson
    python -m src.ingest.unify --input flows.jsonl --format goflow2 --out data/slices/flows.ndjson

Five sources, one output schema (src/ingest/schema.py::FLOW_FIELDS):

  * table (CICFlowMeter-style .csv/.parquet), one row per flow, standardized;
  * pcap (.pcap/.pcapng), packets aggregated to timeout-based bidirectional flows;
  * Argus CSV (ra -c ,), including CTU-13 .binetflow exports;
  * nfdump CSV (nfdump -o csv), with or without its header row;
  * goflow2 JSON (one object per line, or a top-level array).

A .csv is sniffed by its header: Argus starts with StartTime/SrcAddr, nfdump
with ts/te/td, and anything else is treated as a CICFlowMeter table. Explicit
--format skips the sniff when a producer emits an ambiguous header.

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
from .flow_reader import (
    FLOW_SUFFIXES,
    detect_format,
    stream_argus,
    stream_goflow2,
    stream_nfdump,
)
from .pcap_reader import PCAP_SUFFIXES, stream_flows
from .table_reader import TABLE_SUFFIXES, stream_records

SUPPORTED = TABLE_SUFFIXES | PCAP_SUFFIXES | FLOW_SUFFIXES
FORMATS = ("auto", "table", "pcap", "argus", "nfdump", "goflow2")
FLOW_STREAMERS = {
    "argus": stream_argus,
    "nfdump": stream_nfdump,
    "goflow2": stream_goflow2,
}


def _classify(path: Path) -> str | None:
    return detect_format(path)


def _collect_inputs(raw: str, forced: str | None = None) -> list[tuple[Path, str]]:
    p = Path(raw)
    if p.is_dir():
        jobs = []
        for f in sorted(p.rglob("*")):
            if f.suffix.lower() not in SUPPORTED:
                continue
            kind = forced or _classify(f)
            if kind:
                jobs.append((f, kind))
        if not jobs:
            raise SystemExit(f"[error] no supported files under {p} "
                             f"(wanted {sorted(SUPPORTED)})")
        return jobs
    if p.suffix.lower() not in SUPPORTED:
        raise SystemExit(f"[error] unsupported input {p} (wanted {sorted(SUPPORTED)})")
    kind = forced or _classify(p)
    if kind is None:
        raise SystemExit(f"[error] could not identify {p}; pass --format")
    return [(p, kind)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m src.ingest.unify",
        description="Unify tables, captures and flow exports into canonical flow NDJSON.",
    )
    ap.add_argument("--input", required=True,
                    help="file or directory of .csv/.binetflow/.parquet/"
                         ".pcap/.pcapng/.json(l) captures")
    ap.add_argument("--out", required=True,
                    help="output .ndjson path (use '-' for stdout)")
    ap.add_argument("--format", choices=FORMATS, default="auto",
                    help="force a source kind instead of inferring it")
    ap.add_argument("--limit", type=int, default=None,
                    help="stop after N records (smoke runs)")
    ap.add_argument("--flow-timeout", type=float, default=120.0,
                    help="pcap idle-flow timeout in seconds (default 120)")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    jobs = _collect_inputs(args.input, None if args.format == "auto" else args.format)

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
            elif kind == "pcap":
                stats: dict = {}
                if args.limit is not None and n_out >= args.limit:
                    break
                for rec in stream_flows(path, flow_timeout=args.flow_timeout,
                                        stats=stats):
                    out_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    n_out += 1
                    if rec["label"]:
                        labels[rec["label"]] += 1
                    if args.limit is not None and n_out >= args.limit:
                        break
                print(f"      packets={stats.get('pkts', 0):,} "
                      f"ip={stats.get('ip_pkts', 0):,} "
                      f"skipped={stats.get('skipped', 0):,} "
                      f"idle-timeouts={stats.get('timeouts', 0):,} "
                      f"open-at-eof={stats.get('at_eof', 0):,}",
                      file=sys.stderr)
            else:
                stats = {}
                before = n_out
                if args.limit is not None and n_out >= args.limit:
                    break
                for rec in FLOW_STREAMERS[kind](path, limit=args.limit, stats=stats):
                    out_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    n_out += 1
                    if rec["label"]:
                        labels[rec["label"]] += 1
                    if args.limit is not None and n_out >= args.limit:
                        break
                print(f"      rows={stats.get('rows', 0):,} "
                      f"emitted={n_out - before:,} "
                      f"skipped={stats.get('skipped', 0):,}",
                      file=sys.stderr)

    print(f"[unify] wrote {n_out:,} flow records -> {args.out}", file=sys.stderr)
    if labels:
        for label, n in labels.most_common():
            print(f"    {label:<22} {n:>10,}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
