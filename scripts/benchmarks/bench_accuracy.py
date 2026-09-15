#!/usr/bin/env python3
"""Accuracy benchmark: consolidate the out-of-sample metrics.

Every number here is produced by the training/eval harness
(scripts/checks/check_ml.py) and stored in results/ml/*.json. This script does NOT
recompute metrics — it gathers the already-measured values into one file
(results/benchmarks/accuracy.json) and re-asserts the documented gates so the
benchmarks document can cite a single source of truth:

  * window ensemble (ddos/scan)     stratified per-day holdout
  * supervised reference model      stratified per-day holdout
  * beacon pair model               leave-one-scenario-out (CTU-13)
  * DGA lexical model               family-holdout CV + Umbrella-1m holdout
  * TLS novelty channel             synthetic-plant (labelled as such)
  * rule-layer FPR                  benign windows on the labelled slice

Usage:
    python scripts/benchmarks/bench_accuracy.py            # gather + gate-check
    python scripts/benchmarks/bench_accuracy.py --rules    # + live rule-slice FPR pass
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

RESULTS = REPO / "results" / "ml"
OUT = REPO / "results" / "benchmarks" / "accuracy.json"

GATES = {
    "windows_ddos_f1": 0.90,
    "windows_scan_f1": 0.90,
    "beacon_roc_auc": 0.85,
    "dga_precision": 0.90,
    "dga_roc_auc": 0.90,
    "dga_umbrella_fpr_max": 0.15,
    "tls_plant_f1": 0.90,
}


def _load(name: str) -> dict:
    return json.loads((RESULTS / f"{name}_metrics.json").read_text())


def gather() -> dict:
    win = _load("window")
    sup = _load("supervised")
    bc = _load("beacon")
    dga = _load("dga")
    tls = _load("tls")

    out = {
        "methodology": {
            "windows": "stratified per-day holdout (out-of-sample)",
            "supervised": "stratified per-day holdout (reference model)",
            "beacon": "leave-one-scenario-out over CTU-13 scenarios",
            "dga": "family-holdout CV; Umbrella top-1m as untouched benign holdout",
            "tls": "synthetic-plant experiment (labelled as such; no real TLS pcap)",
        },
        "window_ensemble": {
            "ddos_f1": win["ddos"]["f1"],
            "ddos_precision": win["ddos"]["precision"],
            "ddos_recall": win["ddos"]["recall"],
            "scan_f1": win["scan"]["f1"],
            "scan_precision": win["scan"]["precision"],
            "scan_recall": win["scan"]["recall"],
            "benign_false_positives_per_day": win.get(
                "benign_false_positives_per_day", {}),
            "macro_f1": win.get("macro_f1"),
        },
        "supervised_reference": {
            "macro_f1": sup["macro_f1"],
            "accuracy": sup.get("accuracy"),
            "note": "documented plateau (~0.30 macro-F1) — see docs/ml.md",
        },
        "beacon": {
            "roc_auc_macro": bc.get("roc_auc_macro", bc.get("roc_auc")),
            "pooled_roc_auc": bc.get("roc_auc"),
            "pr_auc": bc.get("pr_auc"),
            "f1_at_threshold": bc.get("f1"),
            "threshold": bc.get("threshold"),
            "pairs_evaluated": bc.get("n_pairs"),
        },
        "dga": {
            "precision_known_corpus": dga.get("known_precision",
                                              dga["precision"]),
            "recall": dga.get("recall"),
            "roc_auc": dga.get("roc_auc"),
            "pr_auc": dga.get("pr_auc"),
            "umbrella_fpr_at_threshold": dga.get("umbrella_fpr_at_threshold"),
            "families": dga.get("families"),
        },
        "tls": {
            "plant_f1": tls["synthetic_plant_eval"]["f1"],
            "plant_precision": tls["synthetic_plant_eval"]["precision"],
            "watchlist_size": tls.get("watchlist_size"),
            "honesty_note": "synthetic baseline (no real TLS pcap in the lab)",
        },
    }
    fpr = rule_slice_fpr() if "--rules" in sys.argv else None
    if fpr:
        out["rule_layer"] = fpr
    return out


def rule_slice_fpr() -> dict | None:
    """Live rule pass over the labelled Wednesday slice: benign FPR."""
    slice_path = REPO / "data/slices/flows.ndjson"
    if not slice_path.exists():
        return None
    from src.detectors.rules import run_rules

    with slice_path.open(encoding="utf-8") as fh:
        recs = [json.loads(l) for l in fh if l.strip()]
    flows = __import__("pandas").DataFrame(recs)
    alerts = run_rules(flows, window_s=10)
    benign = [a for a in alerts if a.label == "BENIGN"]
    benign_windows = int((flows.label == "BENIGN").sum())
    return {
        "slice_flows": len(flows),
        "alerts_total": len(alerts),
        "alerts_on_benign_windows": len(benign),
        "benign_fpr_note": (f"{len(benign)} alerts on benign-labelled windows "
                            f"of {benign_windows:,} benign-labelled flows "
                            f"(target: <= 2)"),
        "passes_rule_fpr_gate": len(benign) <= 2,
    }


def gate_check(doc: dict) -> bool:
    ok = True

    def check(name: str, cond: bool, detail: str) -> None:
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}: {detail}")
        ok = ok and cond

    print("[gates] documented accuracy targets (out-of-sample)")
    we = doc["window_ensemble"]
    check("windows ddos F1", we["ddos_f1"] >= GATES["windows_ddos_f1"],
          f"{we['ddos_f1']} >= {GATES['windows_ddos_f1']}")
    check("windows scan F1", we["scan_f1"] >= GATES["windows_scan_f1"],
          f"{we['scan_f1']} >= {GATES['windows_scan_f1']}")
    bc = doc["beacon"]
    check("beacon ROC-AUC (macro LOSO)",
          bc["roc_auc_macro"] >= GATES["beacon_roc_auc"],
          f"{bc['roc_auc_macro']} >= {GATES['beacon_roc_auc']}")
    dg = doc["dga"]
    check("dga precision", dg["precision_known_corpus"] >= GATES["dga_precision"],
          f"{dg['precision_known_corpus']} >= {GATES['dga_precision']}")
    check("dga ROC-AUC", dg["roc_auc"] >= GATES["dga_roc_auc"],
          f"{dg['roc_auc']} >= {GATES['dga_roc_auc']}")
    check("dga umbrella FPR",
          dg["umbrella_fpr_at_threshold"] <= GATES["dga_umbrella_fpr_max"],
          f"{dg['umbrella_fpr_at_threshold']} <= {GATES['dga_umbrella_fpr_max']}")
    tls = doc["tls"]
    check("tls plant F1", tls["plant_f1"] >= GATES["tls_plant_f1"],
          f"{tls['plant_f1']} >= {GATES['tls_plant_f1']} (synthetic)")
    if "rule_layer" in doc:
        check("rule layer benign FPR (gate)",
              doc["rule_layer"]["passes_rule_fpr_gate"],
              doc["rule_layer"]["benign_fpr_note"])
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rules", action="store_true",
                    help="also run the live rule-slice FPR pass")
    args = ap.parse_args()
    if args.rules:
        sys.argv.append("--rules")  # gather() peeks at argv

    doc = gather()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=2))
    print(f"[accuracy] wrote {OUT.relative_to(REPO)}")
    ok = gate_check(doc)
    print("[accuracy] all gates PASS" if ok else "[accuracy] GATE FAILURE",
          file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
