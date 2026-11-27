#!/usr/bin/env python3
"""Exit check: re-derive every rule-threshold calibration number from data.

The rule thresholds in src/detectors/ are justified by numbers quoted in the
module docstrings and in docs/rules.md ("benign max 48.8 flows/s", "38 benign
windows > 30 ports", "zero benign false positives"). Those numbers are only
worth anything if a reader can reproduce them. This script recomputes each one
from the pinned corpus and compares it against the value the documentation
claims.

Exit codes:
    0  every claim reproduced (within tolerance)
    1  at least one documented number no longer matches the data
    2  corpus unavailable, nothing verified (a distinct, honest failure:
       never report "calibration verified" when no data was read)

Usage:
    python scripts/checks/check_thresholds.py
    python scripts/checks/check_thresholds.py --corpus path/to/slice.parquet
    python scripts/checks/check_thresholds.py --print-only
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from src.detectors.rules import run_rules
from src.detectors.window import build_windows

#: Pinned CIC-IDS2017 working-hours table used for every calibration figure.
DEFAULT_CORPUS = (REPO / "data" / "raw" / "cic2017" /
                  "Wednesday-workingHours.pcap_ISCX.csv.parquet")


@dataclass
class Claim:
    """One documented calibration number, and how it was measured."""
    key: str
    what: str
    documented: float
    measured: float
    op: str = "=="          # "==" | "<=" | ">=" | "<" | ">"
    tol: float = 0.0
    detail: str = ""

    @property
    def ok(self) -> bool:
        a, b = self.measured, self.documented
        if self.op == "==":
            return abs(a - b) <= (self.tol if self.tol else 0.5)
        if self.op == "<=":
            return a <= b + self.tol
        if self.op == ">=":
            return a >= b - self.tol
        if self.op == "<":
            return a < b
        if self.op == ">":
            return a > b
        raise ValueError(self.op)


def load_flows(corpus: Path) -> pd.DataFrame:
    """Canonical flow records from a raw table via the project's own reader."""
    from src.ingest.table_reader import stream_records
    return pd.DataFrame(list(stream_records(corpus)))


def measure(df: pd.DataFrame, window_s: int) -> tuple[dict[str, float], list]:
    """Recompute every calibration quantity; return (numbers, rule alerts)."""
    wf = build_windows(df, window_s=window_s)
    dst, src = wf.dst, wf.src
    ben_d = dst[dst["label"] == "BENIGN"]
    ben_s = src[src["label"] == "BENIGN"]

    alerts = run_rules(df, window_s=window_s)
    benign_alerts = [a for a in alerts if a.label == "BENIGN"]

    n = {
        "flows": float(len(df)),
        "benign_flows": float((df["label"] == "BENIGN").sum()),
        "benign_dst_windows": float(len(ben_d)),
        "benign_src_windows": float(len(ben_s)),
        # ddos
        "ddos_benign_max_flows_per_sec": float(ben_d["flows_per_sec"].max()),
        "ddos_benign_windows_ge_50fps": float((ben_d["flows_per_sec"] >= 50).sum()),
        "ddos_benign_max_n_src": float(ben_d["n_src"].max()),
        # ddos fan-in conjunction
        "ddos_fanin_benign_candidates": float(
            ((ben_d["n_src"] >= 50) & (ben_d["src_conc"] <= 0.3)).sum()),
        # scan
        "scan_benign_windows_gt_30_ports": float((ben_s["n_dports"] > 30).sum()),
        "scan_benign_bytes_per_flow_median": float(
            ben_s[ben_s["n_dports"] > 30]["bytes_per_flow"].median()),
        "scan_benign_resp_share_p50": float(ben_s["resp_share"].median()),
        "scan_server_share_survivors": float(
            (ben_s[ben_s["n_dports"] > 30]["server_share"] <= 0.2).sum()),
        "scan_conjunction_benign_survivors": float((
            (ben_s["server_share"] <= 0.2)
            & (ben_s["resp_share"] <= 0.5)
            & (ben_s["bytes_per_flow"] <= 600)
            & (ben_s["n_dports"] >= 30)).sum()),
        # exfil
        "exfil_benign_max_upload_kb": float(ben_s["fwd_bytes"].max() / 1000.0),
        "exfil_benign_windows_ge_5mb": float((ben_s["fwd_bytes"] >= 5_000_000).sum()),
        # end-to-end
        "rule_alerts_total": float(len(alerts)),
        "rule_alerts_on_benign": float(len(benign_alerts)),
    }
    return n, alerts


#: The claims as written in src/detectors/*.py and docs/rules.md.
#: `documented` is what the docs say; `measured` is filled in by main().
#: Values below were re-derived from the pinned corpus on 2026-09-10; the
#: earlier prose figures (48.8 flows/s, 38 windows > 30 ports, >1 kB/flow,
#: 968 kB, "zero benign false positives") did NOT reproduce and were
#: corrected rather than kept. Re-run this script after any threshold edit.
def build_claims(m: dict[str, float]) -> list[Claim]:
    return [
        Claim("benign_flows", "BENIGN flow rows in the slice",
              440_031, m["benign_flows"], detail="README denominator"),
        Claim("ddos_benign_max_flows_per_sec",
              "highest flows/s any single benign destination reached",
              210.9, m["ddos_benign_max_flows_per_sec"], tol=0.5,
              detail="ddos.py 'volumetric_rate' rationale"),
        Claim("ddos_benign_windows_ge_50fps",
              "benign windows at or above the 50 flows/s threshold",
              77, m["ddos_benign_windows_ge_50fps"],
              detail="74 of the 77 are one destination (192.168.10.3); "
                     "this is why volumetric_rate needs the fan-in/SYN "
                     "branches, or a per-destination baseline, to be clean"),
        Claim("ddos_fanin_benign_candidates",
              "benign windows with n_src>=50 AND src_conc<=0.3",
              2, m["ddos_fanin_benign_candidates"],
              detail="fan-in conjunction is near-clean: 73 benign windows "
                     "reach 50 sources, only 2 are also concentrated"),
        Claim("scan_benign_windows_gt_30_ports",
              "benign source windows touching more than 30 ports",
              66, m["scan_benign_windows_gt_30_ports"],
              detail="scan.py cardinality rationale"),
        Claim("scan_server_share_survivors",
              "of those, how many also pass server_share<=0.2",
              1, m["scan_server_share_survivors"],
              detail="server_share is the decisive scan gate: it removes 65 "
                     "of the 66 high-cardinality benign windows"),
        Claim("scan_benign_bytes_per_flow_median",
              "median bytes per flow, benign windows with >30 ports",
              285.3, m["scan_benign_bytes_per_flow_median"], tol=1.0,
              detail="scan.py bytes_per_flow rationale (was wrongly quoted "
                     "as '> 1 kB'; overall benign median is 12 B)"),
        Claim("scan_benign_resp_share_p50",
              "median share of benign flows that got any reply",
              0.965, m["scan_benign_resp_share_p50"], tol=0.002,
              detail="scan.py resp_share rationale"),
        Claim("scan_conjunction_benign_survivors",
              "benign source windows passing the four plain scan gates",
              0, m["scan_conjunction_benign_survivors"],
              detail="the host-sweep branch was removed 2026-11-27; on the "
                     "Wednesday table the remaining port-scan conjunction is "
                     "zero, and the two full-corpus benign alerts are Thursday "
                     "sweeps (one reset-closed over 2 hosts, one no-reply "
                     "sweep over 3 hosts)"),
        Claim("ddos_benign_max_n_src",
              "most distinct source IPs any benign destination saw",
              136, m["ddos_benign_max_n_src"],
              detail="docs/rules.md fan_in rationale (was 'benign max 23')"),
        Claim("exfil_benign_max_upload_kb",
              "largest upload (kB) by one source in a benign window",
              4369.8, m["exfil_benign_max_upload_kb"], tol=1.0,
              detail="exfil.py bulk rationale (was '968 kB')"),
        Claim("exfil_benign_windows_ge_5mb",
              "benign windows at or above the 5 MB bulk threshold",
              0, m["exfil_benign_windows_ge_5mb"],
              detail="the 5 MB bulk gate holds with ~0.6 MB of headroom over "
                     "the worst benign window (4,369.8 kB)"),
        Claim("rule_alerts_on_benign",
              "rule alerts landing on benign-labelled windows",
              3, m["rule_alerts_on_benign"],
              detail="ddos 3 on Wednesday; the old 15 was ddos 3 / exfil 9 / "
                     "scan 3, and the 500 kB exfil floor plus host-sweep "
                     "removal took the other 12; see docs/rules.md"),
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS,
                    help="pinned CIC table to recalibrate against")
    ap.add_argument("--window", type=int, default=10)
    ap.add_argument("--print-only", action="store_true",
                    help="print measured numbers; never fail")
    args = ap.parse_args(argv)

    if not args.corpus.exists():
        print(f"[SKIP] corpus not present: {args.corpus}\n"
              f"       calibration NOT verified, fetch the pinned "
              f"CIC-IDS2017 table first:\n"
              f"         python scripts/fetch/download_ml_corpora.py --only cic2017\n"
              f"       then re-run this check.",
              file=sys.stderr)
        return 2

    print(f"=== recalibrating rule thresholds from {args.corpus}")
    df = load_flows(args.corpus)
    m, alerts = measure(df, args.window)
    claims = build_claims(m)

    print(f"\ncorpus: {m['flows']:,.0f} flows | "
          f"{m['benign_flows']:,.0f} BENIGN | "
          f"{m['benign_dst_windows']:,.0f} benign dst windows | "
          f"{m['benign_src_windows']:,.0f} benign src windows")
    print(f"rule engine: {m['rule_alerts_total']:,.0f} alerts, "
          f"{m['rule_alerts_on_benign']:,.0f} on benign-labelled windows "
          f"{dict(Counter(a.threat_class for a in alerts))}")

    print(f"\n{'claim':<34} {'documented':>12} {'measured':>12}  result")
    print("-" * 74)
    failed: list[Claim] = []
    for c in claims:
        res = "OK" if c.ok else "DRIFT"
        print(f"{c.key:<34} {c.documented:>12,.4g} {c.measured:>12,.4g}  {res}")
        if not c.ok:
            failed.append(c)

    if failed:
        print(f"\n[DRIFT] {len(failed)}/{len(claims)} documented calibration "
              f"numbers no longer hold on this corpus:")
        for c in failed:
            print(f"  * {c.key}: documented {c.documented:,.4g} "
                  f"{c.op} measured {c.measured:,.4g}")
            print(f"      {c.what}, {c.detail}")
        print("\n  The thresholds themselves may still be correct; the "
              "DOCUMENTED\n  justification is what drifted. Either "
              "re-derive the numbers or\n  re-tune, then update the matching "
              "docstrings and docs/rules.md.")

    benign_alerts = [a for a in alerts if a.label == "BENIGN"]
    if benign_alerts:
        print(f"\ntop benign-alert sources (n={len(benign_alerts)}):")
        for (det, key), cnt in Counter(
                (a.detector, a.key) for a in benign_alerts).most_common(5):
            print(f"  {det:<9} {key:<16} x{cnt}")

    if args.print_only:
        print("\n[PRINT-ONLY] not enforcing")
        return 0
    if failed:
        print("\n[FAIL] documented calibration does not reproduce", file=sys.stderr)
        return 1
    print("\n[PASS] every documented calibration number reproduced", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
