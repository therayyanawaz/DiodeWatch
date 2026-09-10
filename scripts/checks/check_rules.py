#!/usr/bin/env python3
"""Exit check: rule-based detectors on labelled slices + synthetic scenarios.

Runs the default rule set over

  1. the CIC-IDS2017 Wednesday slice flows (data/slices/flows.ndjson), the
     acceptance check: DDoS/scan alerts land on attack-labelled windows,
     benign-labelled windows stay quiet;
  2. three built-in synthetic scenarios (volumetric DDoS, port sweep, bulk
     exfil) with known ground truth by construction.

Exit code 0 = acceptance criteria met.

Usage:
    python scripts/checks/check_rules.py [--flows data/slices/flows.ndjson]
                                  [--skip-slice] [--window 10]
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from src.detectors.rules import run_rules

DEFAULT_FLOWS = REPO / "data" / "slices" / "flows.ndjson"
BASE_TS = 1_499_268_000.0


def _rec(i, *, src, dst, sport, dport=80, proto=6, ts=None, dur=1.0,
         fwd_pkts=4, bwd_pkts=4, fwd_bytes=800, bwd_bytes=2000,
         syn_flags=0, label=None):
    return {
        "flow_id": f"{src}-{dst}-{sport}-{dport}-{proto}",
        "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport,
        "protocol": proto,
        "proto": {6: "tcp", 17: "udp"}.get(proto),
        "timestamp": pd.Timestamp(ts, unit="s", tz="UTC").strftime("%Y-%m-%dT%H:%M:%S"),
        "ts_epoch": ts, "duration_us": int(dur * 1e6),
        "fwd_pkts": fwd_pkts, "bwd_pkts": bwd_pkts,
        "fwd_bytes": fwd_bytes, "bwd_bytes": bwd_bytes,
        "fin_flags": 0, "syn_flags": syn_flags, "rst_flags": 0,
        "psh_flags": 0, "ack_flags": 0, "urg_flags": 0, "label": label,
    }


def synth_scenarios() -> tuple[pd.DataFrame, dict[str, set[str]]]:
    """Synthetic benign + attack replay; returns (flows, expected alerts)."""
    flows: list[dict] = []
    # benign web mix over 40 s
    for i in range(40):
        flows.append(_rec(i, src=f"10.0.1.{i % 5}", dst=f"93.184.0.{10 + i % 4}",
                          sport=40000 + i, ts=BASE_TS + i,
                          fwd_bytes=1500, bwd_bytes=9000, label="BENIGN"))
    expected: dict[str, set[str]] = {"ddos": set(), "scan": set(), "exfil": set()}

    # volumetric DDoS: ~120 flows/s to one target from 100 hosts
    for i in range(1200):
        flows.append(_rec(i, src=f"10.1.0.{i % 100}", dst="10.9.9.9",
                          sport=20000 + i, ts=BASE_TS + i * 0.008, dur=0.05,
                          fwd_pkts=3, bwd_pkts=1, fwd_bytes=120, bwd_bytes=60,
                          label="DoS Hulk"))
    expected["ddos"].add("10.9.9.9")

    # port sweep: 60 unanswered probes to 60 ports
    for i in range(60):
        flows.append(_rec(i, src="10.5.0.7", dst=f"10.60.0.{i % 3}",
                          sport=35000 + i, dport=1000 + i, ts=BASE_TS + i * 0.05,
                          dur=0.0, fwd_pkts=1, bwd_pkts=0, fwd_bytes=60,
                          bwd_bytes=0, label=None))
    expected["scan"].add("10.5.0.7")

    # bulk exfil: 8 MB uploaded in one window to an external host
    for i in range(40):
        flows.append(_rec(i, src="10.20.0.9", dst="93.184.200.9",
                          sport=46000 + i, ts=BASE_TS + 60 + i * 0.1, dur=8.0,
                          fwd_pkts=300, bwd_pkts=300, fwd_bytes=200_000,
                          bwd_bytes=200_000, label=None))
    expected["exfil"].add("10.20.0.9")
    return pd.DataFrame(flows), expected


def check_slice(flows_path: Path, window_s: int) -> bool:
    print(f"\n=== labelled slice: {flows_path}")
    import json

    with flows_path.open(encoding="utf-8") as fh:
        recs = [json.loads(l) for l in fh if l.strip()]
    flows = pd.DataFrame(recs)
    alerts = run_rules(flows, window_s=window_s)

    by_class = Counter(a.threat_class for a in alerts)
    print(f"flows: {len(flows):,}  window: {window_s}s  alerts: {len(alerts):,} {dict(by_class)}")

    ok = True
    ddos = [a for a in alerts if a.threat_class == "ddos"]
    if not ddos:
        print("  [FAIL] no DDoS alerts on the DDoS portion of the slice")
        ok = False
    else:
        keys = sorted({a.key for a in ddos})
        labels = Counter(a.label for a in ddos)
        print(f"  ddos : {len(ddos):,} alerts on {keys} labels={dict(labels)}")
        bad = [a for a in ddos if a.label == "BENIGN"]
        if bad:
            print(f"  [FAIL] {len(bad)} DDoS alerts on benign-labelled windows")
            ok = False

    benign_alerts = [a for a in alerts if a.label == "BENIGN"]
    for a in benign_alerts[:10]:
        conds = ", ".join(e.condition for e in a.evidence)
        print(f"  benign-alert {a.timestamp} {a.detector:<8} {a.key} "
              f"conf={a.confidence:.2f} [{conds}]")
    if len(benign_alerts) > 2:
        print(f"  [FAIL] {len(benign_alerts)} alerts on benign-labelled windows "
              f"(target: <= 2)")
        ok = False
    else:
        print(f"  benign: {len(benign_alerts)} alerts on benign-labelled windows (target <= 2)")

    for a in alerts:
        conf = a.confidence
        if not 0.0 <= conf <= 1.0:
            print(f"  [FAIL] confidence out of range: {conf}")
            ok = False
    return ok


def check_synthetic() -> bool:
    print("\n=== synthetic scenarios")
    flows, expected = synth_scenarios()
    alerts = run_rules(flows)
    ok = True
    for cls, keys in expected.items():
        got = {a.key for a in alerts if a.threat_class == cls}
        missed = keys - got
        if missed:
            print(f"  [FAIL] {cls}: expected alerts on {sorted(missed)}")
            ok = False
        else:
            print(f"  {cls:<6}: fired on {sorted(got)} as expected")
    fp = [a for a in alerts if a.label == "BENIGN"]
    if fp:
        print(f"  [FAIL] {len(fp)} alerts on synthetic benign flows")
        ok = False
    else:
        print("  benign: no alerts (as expected)")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--flows", type=Path, default=DEFAULT_FLOWS)
    ap.add_argument("--skip-slice", action="store_true")
    ap.add_argument("--window", type=int, default=10)
    args = ap.parse_args()

    ok = check_synthetic()
    if not args.skip_slice:
        if args.flows.exists():
            ok = check_slice(args.flows, args.window) and ok
        else:
            print(f"\n[skip] {args.flows} not present; slice check skipped")
    print("\n[PASS] Rule-detector acceptance criteria met" if ok
          else "\n[FAIL] acceptance criteria NOT met", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
