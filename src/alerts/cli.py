"""Command line entry points for the alert evidence store and exports.

    python -m src.alerts.cli store   --alerts alerts.ndjson --db alerts.db \
                                    [--jsonl out.ndjson] [--limit N]
    python -m src.alerts.cli recent  --db alerts.db [--limit N] \
                                    [--class ddos] [--severity high]
    python -m src.alerts.cli report  (--alerts file.ndjson | --db alerts.db
                                     [--window-start T --window-end T])
                                    --out incident.html [--title T]
    python -m src.alerts.cli stix    --alerts alerts.ndjson --out bundle.json
                                    [--limit N]
    python -m src.alerts.cli stats   --db alerts.db
    python -m src.alerts.cli verify-chain --db alerts.db
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .export_stix import write_stix
from .report import write_report
from .schema import alert_from_dict
from .store import AlertStore, verify_chain, write_jsonl
from .triage_store import join_verdicts, record_verdicts


def _print_summary(tag: str, counts: tuple[int, int, int]) -> None:
    inserted, dup, invalid = counts
    print(f"[store] {tag}: inserted={inserted:,} duplicates={dup:,} "
          f"invalid={invalid:,}", file=sys.stderr)


def _load_alerts(path: Path, limit: int | None = None) -> list:
    from .store import iter_jsonl
    return [alert_from_dict(d) for d in iter_jsonl(path, limit=limit)]


def cmd_store(args) -> int:
    alerts = _load_alerts(args.alerts, limit=args.limit)
    with AlertStore(args.db) as store:
        counts = store.insert_many(alerts)
    _print_summary(f"{args.alerts} -> {args.db}", counts)
    # Advisory triage belongs beside the chain, never inside it: the payload
    # hash covers what the detector saw, so a re-triage must not re-hash
    # history. Without this the verdicts die with the NDJSON file and
    # `triage_store counts` inspects a table nothing ever wrote.
    recorded = record_verdicts(alerts, args.db)
    if recorded:
        print(f"[triage] recorded {recorded:,} advisory verdicts "
              f"-> {args.db}", file=sys.stderr)
    if args.jsonl:
        write_jsonl(alerts, args.jsonl)
        print(f"[jsonl] wrote {len(alerts):,} alerts -> {args.jsonl}",
              file=sys.stderr)
    return 0


def cmd_recent(args) -> int:
    with AlertStore(args.db) as store:
        alerts = store.recent(limit=args.limit, threat_class=args.cls,
                              severity=args.severity)
    for a in alerts:
        print(json.dumps(a.to_dict()))
    print(f"[recent] {len(alerts)} alerts", file=sys.stderr)
    return 0


def cmd_report(args) -> int:
    if args.alerts:
        alerts = _load_alerts(args.alerts, limit=args.limit)
    else:
        with AlertStore(args.db) as store:
            if args.window_start and args.window_end:
                alerts = store.between(args.window_start, args.window_end)
            else:
                alerts = store.recent(limit=args.limit or 50)
    if args.db:
        # advisory only; the report labels it so
        alerts = join_verdicts(alerts, args.db)
    out = write_report(alerts, args.out, title=args.title or "DiodeWatch incident report")
    print(f"[report] {len(alerts)} alerts -> {out}", file=sys.stderr)
    return 0


def cmd_stix(args) -> int:
    alerts = _load_alerts(args.alerts, limit=args.limit)
    bundle, problems = write_stix(alerts, args.out)
    if problems:
        print(f"[stix] WARNING validation problems: {problems}", file=sys.stderr)
    n_objects = len(bundle["objects"])
    print(f"[stix] {len(alerts)} alerts -> {args.out} "
          f"({n_objects} objects, validation "
          f"{'clean' if not problems else 'WARNINGS'})", file=sys.stderr)
    return 0 if not problems else 2


def cmd_stats(args) -> int:
    with AlertStore(args.db) as store:
        print(json.dumps(store.stats(), indent=2))
    return 0


def cmd_verify_chain(args) -> int:
    result = verify_chain(args.db)
    print(json.dumps(result, indent=2))
    if result["ok"]:
        head = result["head"] or {}
        # the words both UIs use: re-hashing proves the rows agree with each
        # other, only the append-only ledger beside the db proves nobody rewrote
        # them, so PASS on its own overstates a chain with no anchor
        claim = ("RE-VERIFIED · ANCHORED" if result["anchored"]
                 else "RE-VERIFIED (no anchor)")
        print(f"[chain] {claim} · {result['links']:,} links · head "
              f"{head.get('chain_hash', ' -')[:16]}…", file=sys.stderr)
        return 0
    print(f"[chain] BREAK DETECTED · {result['error']}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m src.alerts.cli",
        description="Alert evidence store, STIX 2.1 export, incident reports.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("store", help="ingest alert JSONL into SQLite")
    p.add_argument("--alerts", required=True, type=Path)
    p.add_argument("--db", required=True)
    p.add_argument("--jsonl", type=Path, default=None)
    p.add_argument("--limit", type=int, default=None)
    p.set_defaults(fn=cmd_store)

    p = sub.add_parser("recent", help="newest alerts")
    p.add_argument("--db", required=True)
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--class", dest="cls", default=None)
    p.add_argument("--severity", default=None)
    p.set_defaults(fn=cmd_recent)

    p = sub.add_parser("report", help="render an incident report (HTML)")
    p.add_argument("--alerts", type=Path, default=None)
    p.add_argument("--db", default=None)
    p.add_argument("--window-start", default=None)
    p.add_argument("--window-end", default=None)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--title", default=None)
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("stix", help="export a STIX 2.1 bundle")
    p.add_argument("--alerts", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--limit", type=int, default=None)
    p.set_defaults(fn=cmd_stix)

    p = sub.add_parser("stats", help="store statistics")
    p.add_argument("--db", required=True)
    p.set_defaults(fn=cmd_stats)

    p = sub.add_parser("verify-chain",
                       help="recompute the tamper-evident evidence chain")
    p.add_argument("--db", required=True)
    p.set_defaults(fn=cmd_verify_chain)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
