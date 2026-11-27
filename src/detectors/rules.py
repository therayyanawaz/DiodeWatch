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
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from src.alerts.schema import Alert

from .base import Rule
from .ddos import DDoSRule
from .exfil import ExfilRule
from .scan import ScanRule
from .slowdos import STRONG_HELD_CONNS, STRONG_MIN_FLOWS, SlowDoSRule
from .window import build_windows


def _alert_window_index(alert, window_s: int) -> int | None:
    """Window bucket of an alert start, or None when it has no usable clock."""
    start = getattr(alert, "window_start", None)
    if not start:
        return None
    try:
        dt = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() // window_s)


def arbitrate_alerts(flows: pd.DataFrame, alerts: list[Alert],
                     window_s: int = 10) -> list[Alert]:
    """Drop scan claims that are a side effect of a DDoS flood.

    A SYN flood and a port sweep share the same observable shape: one source
    sends many tiny unanswered flows to many ports on the victim. The scan rule
    cannot tell those apart in a single window, so when the same source also
    sends to a destination that already has a DDoS alert in that window, the
    victim alert owns the traffic and the scan claim is suppressed. This is a
    class-precedence rule over the same window, not a threshold change: it
    removes double-counting without hiding the flood.

    A scan that does not touch a DDoS victim in the same window is untouched,
    and an empty alert list returns immediately. A `slowdos` claim that
    duplicates a `ddos` alert on the same `(window, key)` is also dropped:
    the fast-volume class owns that incident.
    """
    if not alerts:
        return alerts
    volume = {
        (_alert_window_index(a, window_s), str(a.key))
        for a in alerts
        if a.threat_class == "ddos" and getattr(a, "key", None)
        and getattr(a, "window_start", None)
    }
    if volume:
        alerts = [
            a for a in alerts
            if not (a.threat_class == "slowdos"
                    and (_alert_window_index(a, window_s), str(a.key)) in volume)
        ]
    ddos = [a for a in alerts
            if a.threat_class in ("ddos", "slowdos")
            and getattr(a, "dst_ip", None)
            and getattr(a, "window_start", None)]
    scans = [(i, a) for i, a in enumerate(alerts)
             if a.threat_class == "scan" and getattr(a, "key", None)
             and getattr(a, "window_start", None)]
    if not ddos or not scans:
        return alerts
    if "ts_epoch" not in flows.columns or "src_ip" not in flows.columns \
            or "dst_ip" not in flows.columns:
        return alerts

    ts = pd.to_numeric(flows["ts_epoch"], errors="coerce").to_numpy(
        dtype="float64")
    keep = np.isfinite(ts)
    if not keep.any():
        return alerts
    flow_windows = pd.DataFrame({
        "_win": (ts[keep] // window_s).astype("int64"),
        "src_ip": flows["src_ip"].to_numpy()[keep].astype(str),
        "dst_ip": flows["dst_ip"].to_numpy()[keep].astype(str),
    })

    claims = pd.DataFrame(
        [{"_alert": i, "_win": _alert_window_index(a, window_s),
          "src_ip": str(a.key)} for i, a in scans],
        columns=["_alert", "_win", "src_ip"])
    claims = claims[claims["_win"].notna()].astype(
        {"_alert": "int64", "_win": "int64"})
    if claims.empty:
        return alerts
    victims = pd.DataFrame(
        [{"_win": _alert_window_index(a, window_s), "dst_ip": str(a.dst_ip)}
         for a in ddos],
        columns=["_win", "dst_ip"])
    victims = victims[victims["_win"].notna()].astype({"_win": "int64"})
    if victims.empty:
        return alerts

    relevant = flow_windows[flow_windows["src_ip"].isin(
        set(claims["src_ip"]))]
    if relevant.empty:
        return alerts
    links = claims.merge(relevant, on=["_win", "src_ip"], how="inner")
    if links.empty:
        return alerts
    links = links.merge(victims.drop_duplicates(), on=["_win", "dst_ip"],
                        how="inner")
    if links.empty:
        return alerts
    dropped = set(links["_alert"].astype(int).tolist())
    return [a for i, a in enumerate(alerts) if i not in dropped]


def _strong_slow_window(alert: Alert) -> bool:
    """True when one window alone carries the starvation-scale pressure.

    The rule has already proved the tiny, one-sided packet shape. At 100
    flows and 100 connections still open past the window, the remaining
    benign explanation is a backup or poller with long-lived connections,
    which would not keep a forward/reverse packet ratio above 2 with
    header-sized requests. This threshold is used only to keep a strong
    first window that corroboration would otherwise discard.
    """
    observed: dict[str, object] = {}
    for item in getattr(alert, "evidence", ()) or ():
        condition = getattr(item, "condition", None)
        if condition:
            observed[str(condition)] = getattr(item, "observed", None)
    try:
        flows = float(observed.get("flow_count", 0) or 0)
        held = float(observed.get("held_connections", 0) or 0)
    except (TypeError, ValueError):
        return False
    return flows >= STRONG_MIN_FLOWS and held >= STRONG_HELD_CONNS


def _corroborate_slowdos(alerts: list[Alert], flows: pd.DataFrame,
                         window_s: int) -> list[Alert]:
    """Keep a slow-DoS claim only when it is sustained or rate-corroborated.

    A single window of held, tiny connections is also what a benign backup or
    polling client looks like. A slow-DoS incident lasts, so keep the claim
    when the same destination has the shape in a prior window within 60 s,
    when a volumetric DDoS alert already owns that window, or when one window
    alone shows at least 100 flows and 100 held connections. The last case
    preserves the first window of a strong run; the first window of a weaker
    run is still dropped, and every later window is kept.

    A batch that spans fewer than two windows cannot show persistence, so its
    claims are left alone rather than judged on missing context.
    """
    slow = [(i, a) for i, a in enumerate(alerts)
            if getattr(a, "detector", None) == "slowdos"
            and getattr(a, "key", None) and getattr(a, "window_start", None)]
    if not slow or "ts_epoch" not in flows.columns:
        return alerts
    ts = pd.to_numeric(flows["ts_epoch"], errors="coerce").to_numpy(
        dtype="float64")
    ts = ts[np.isfinite(ts)]
    if ts.size and np.unique((ts // window_s).astype("int64")).size < 2:
        return alerts
    volume = {
        (_alert_window_index(a, window_s), str(a.key))
        for a in alerts
        if getattr(a, "detector", None) == "ddos"
        and getattr(a, "threat_class", None) == "ddos"
        and getattr(a, "key", None)
    }
    slow_windows = {_alert_window_index(a, window_s) for _, a in slow}
    if len(slow_windows - {None}) <= 1:
        # Every slow claim sits in one window, so persistence is not
        # observable in this batch. Keep them instead of judging on silence.
        return alerts
    max_gap = round(60.0 / window_s)
    previous: dict[str, int] = {}
    keep: set[int] = set()
    for i, a in sorted(slow, key=lambda item: (
            str(item[1].key), item[1].window_start or "")):
        win = _alert_window_index(a, window_s)
        if win is None:
            keep.add(i)
            continue
        key = str(a.key)
        prior = previous.get(key)
        if (win, key) in volume or _strong_slow_window(a) or (
                prior is not None and 0 < win - prior <= max_gap):
            keep.add(i)
        previous[key] = win
    return [a for i, a in enumerate(alerts)
            if not any(i == j for j, _ in slow) or i in keep]


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
    alerts = arbitrate_alerts(flows, alerts, window_s=window_s)
    alerts = _corroborate_slowdos(alerts, flows, window_s=window_s)
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
