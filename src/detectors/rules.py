"""Rule engine: registry + batch evaluation over canonical flow records.

    python -m src.detectors.rules --input data/slices/flows.ndjson \
                                  --out alerts/rules_alerts.ndjson

`run_rules(flows)` is the one-call API the streaming/alert pipeline will use:
canonical records in, fully-populated Alert objects out (each with timestamp,
flow_id, threat_class, confidence, and value-vs-threshold evidence).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd

from src.alerts.schema import Alert

from .base import Rule
from .ddos import DDoSRule
from .exfil import ExfilRule
from .scan import ScanRule
from .slowdos import SlowDoSRule
from .window import build_windows

#: default rule set, in evaluation order
DEFAULT_RULES: tuple[type[Rule], ...] = (DDoSRule, SlowDoSRule, ScanRule, ExfilRule)


def make_rules(per_rule_params: dict[str, dict] | None = None) -> list[Rule]:
    """Instantiate the default rule set, optionally with per-rule overrides."""
    per_rule_params = per_rule_params or {}
    return [cls(params=per_rule_params.get(cls.name)) for cls in DEFAULT_RULES]


def run_rules(flows: pd.DataFrame, rules: list[Rule] | None = None,
              window_s: int = 10) -> list[Alert]:
    """Evaluate the rule set over one batch of canonical flow records."""
    rules = rules if rules is not None else make_rules()
    wf = build_windows(flows, window_s=window_s)
    alerts: list[Alert] = []
    for rule in rules:
        alerts.extend(rule.evaluate(wf))
    alerts.sort(key=lambda a: (a.timestamp or "", a.threat_class, a.key or ""))
    return alerts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m src.detectors.rules",
        description="Run rule-based detectors over canonical flow NDJSON.",
    )
    ap.add_argument("--input", help="canonical flow NDJSON (unify output)")
    ap.add_argument("--out", help="output alerts NDJSON path")
    ap.add_argument("--window", type=int, default=10,
                    help="tumbling window seconds (default 10)")
    ap.add_argument("--limit", type=int, default=None,
                    help="read only the first N flows (smoke runs)")
    args = ap.parse_args(argv)
    if not args.input or not args.out:
        ap.error("--input and --out are required")

    from src.features.pipeline import read_flows

    t0 = time.perf_counter()
    flows = read_flows(Path(args.input), limit=args.limit)
    alerts = run_rules(flows, window_s=args.window)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(a.to_dict()) + "\n" for a in alerts)

    elapsed = time.perf_counter() - t0
    by_class: dict[str, int] = {}
    for a in alerts:
        by_class[a.threat_class] = by_class.get(a.threat_class, 0) + 1
    print(f"[rules] {len(flows):,} flows -> {len(alerts):,} alerts "
          f"({by_class}) in {elapsed:.1f}s -> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
