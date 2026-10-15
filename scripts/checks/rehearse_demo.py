#!/usr/bin/env python3
"""Full demo rehearsal (headless, ~1 minute, exit 0 = success).

Exercises exactly what the 5-minute narrated demo shows, without the UI:

  1. demo pack present and manifest-consistent (regenerates if missing);
  2. every pcap replays through the real ingest + rule engine and fires its
     expected detector on the expected entity (ddos / scan / exfil);
  3. the C2 pcap's NetFlow sidecar fires the trained beacon model;
  4. the DGA sidecar fires the trained lexical model, benign names stay quiet;
  5. alerts carry the SOC-ready schema (severity, alert_id, evidence, 5-tuple);
  6. the evidence store ingests the session; recent() answers fast;
  7. a STIX 2.1 bundle and an HTML incident report are produced and valid;
  8. the diode monitor answers (monitor-only on a dev host is a PASS there).

Run it twice back-to-back before a demo: two green rehearsals = go.

    python scripts/checks/rehearse_demo.py [--db data/demo_rehearsal.db]
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

PACK = REPO / "data" / "pcaps" / "pack"
OUT_DIR = REPO / "results" / "demo"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", type=Path,
                    default=REPO / "data" / "demo_rehearsal.db")
    args = ap.parse_args()

    ok = True
    t_start = time.perf_counter()

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f", {detail}" if detail else ""))
        ok = ok and cond

    # ---- 1. pack -----------------------------------------------------------
    print("[1/7] demo pack")
    man_path = PACK / "pack_manifest.json"
    if not man_path.exists():
        print("  (manifest missing, regenerating pack)")
        import subprocess
        rc = subprocess.run([sys.executable,
                             str(REPO / "scripts" / "generators"
                                 / "make_demo_pack.py")],
                            cwd=REPO, capture_output=True, text=True,
                            check=False)
        if rc.returncode != 0:
            print(rc.stdout, rc.stderr)
            print("  [FAIL] pack regeneration failed")
            return 1
    man = json.loads(man_path.read_text())
    check("manifest lists 6 scenarios", len(man["pack"]) == 6,
          f"{[p['pcap'] for p in man['pack']]}")
    for item in man["pack"]:
        p = PACK / item["pcap"]
        check(f"{item['pcap']} exists", p.exists(), f"{p.stat().st_size / 1e6:.2f} MB")

    # ---- 2. rule scenarios fire -------------------------------------------
    print("[2/7] replay every scenario pcap through ingest + rules")
    from src.detectors.rules import run_rules
    from src.ingest.pcap_reader import stream_flows

    session_alerts = []
    for item in man["pack"]:
        expected = (item.get("expected") or {}).get("rule_expected") or []
        if not expected:
            continue
        flows = pd.DataFrame(list(stream_flows(PACK / item["pcap"])))
        alerts = run_rules(flows, window_s=10)
        session_alerts.extend(alerts)
        got = {a.threat_class for a in alerts}
        missing = [c for c in expected if c not in got]
        check(f"{item['pcap']} fires {expected}", not missing,
              f"got {sorted(got)}" if not missing else f"MISSING {missing}")
        benign_hits = [a for a in alerts if a.label == "BENIGN"]
        check(f"{item['pcap']} zero benign false alarms", not benign_hits,
              f"{len(benign_hits)} on benign windows" if benign_hits else "clean")

    # ---- 3. beacon channel --------------------------------------------------
    print("[3/7] C2 beacon channel (NetFlow sidecar -> trained model)")
    from src.detectors.ml import beacon as beacon_mod

    flows2 = beacon_mod.load_ctu(PACK / "02_c2_beacon_netflow.csv")
    pairs = beacon_mod.pair_series(flows2)
    bm = beacon_mod.BeaconModel.load(REPO / "models")
    scores = bm.predict_score(pairs)
    fired = [(str(src), round(float(sc), 3)) for src, sc in
             zip(pairs["src_ip"], scores) if sc >= bm.threshold]
    check("trained beacon model fires on the C2 pair", bool(fired),
          f"{fired[:2]} thr={bm.threshold:.3f}")
    benign_pairs = pairs[~pairs["src_ip"].isin(("10.30.0.9", "10.30.0.8"))]
    b_scores = bm.predict_score(benign_pairs)
    check("no beacon alerts on benign pairs",
          bool((b_scores < bm.threshold).all()),
          f"max benign score {float(b_scores.max()):.3f}")

    # ---- 4. DGA channel -----------------------------------------------------
    print("[4/7] DGA / DNS-tunnel channel (domains sidecar -> trained model)")
    from src.detectors.ml.dga import DgaModel

    dm = DgaModel.load(REPO / "models")
    doms = pd.Series([l.strip() for l in
                      (PACK / "03_dga_domains.txt").read_text().splitlines()
                      if l.strip()])
    s = dm.score_domains(doms)
    fired_n = int((s >= dm.threshold).sum())
    check("DGA model flags the tunnel domains", fired_n == len(doms),
          f"{fired_n}/{len(doms)} min score {float(s.min()):.3f}")
    benign = pd.Series(["www.example.com", "mail.google.com",
                        "updates.microsoft.com", "cdn.assets.example.org",
                        "host17.example.com"])
    sb = dm.score_domains(benign)
    check("DGA model stays quiet on benign names",
          bool((sb < dm.threshold).all()),
          f"max benign score {float(sb.max()):.3f}")

    # ---- 5. alert schema ------------------------------------------------------
    print("[5/7] SOC-ready alert schema on every session alert")
    from src.alerts.schema import validate_alert

    check("session produced alerts", len(session_alerts) >= 4,
          f"{len(session_alerts)} alerts")
    problems = [p for a in session_alerts for p in validate_alert(a)]
    check("all alerts schema-valid", not problems, f"{len(problems)} problems")
    sample = session_alerts[-1]
    # rule alerts aggregate per-side, so exactly the entity side is set
    # (ddos/slowdos -> dst, scan/exfil -> src); ML flow alerts carry both
    check("alert carries severity + alert_id + evidence + entity endpoint",
          bool(sample.severity and sample.alert_id and sample.evidence
               and (sample.src_ip or sample.dst_ip)),
          f"{sample.threat_class}/{sample.severity} "
          f"{sample.src_ip or '-'}->{sample.dst_ip or '-'}")

    # ---- 6. evidence store ---------------------------------------------------
    print("[6/7] evidence store ingest + query")
    from src.alerts.schema import alert_from_dict
    from src.alerts.store import AlertStore, iter_jsonl, write_jsonl

    jsonl = OUT_DIR / "rehearsal_alerts.jsonl"
    write_jsonl(session_alerts, jsonl)
    n_jsonl = sum(1 for _ in iter_jsonl(jsonl))
    check("JSONL round-trip", n_jsonl == len(session_alerts),
          f"{n_jsonl} alerts")
    args.db.unlink(missing_ok=True)
    with AlertStore(args.db) as store:
        ins, dup, inv = store.insert_many(
            alert_from_dict(d) for d in iter_jsonl(jsonl))
        check("store ingest clean", inv == 0 and ins == n_jsonl,
              f"inserted={ins} dup={dup} invalid={inv}")
        t0 = time.perf_counter()
        recent = store.recent(limit=20)
        q_ms = (time.perf_counter() - t0) * 1000
        check("recent(20) query", len(recent) > 0 and q_ms < 250,
              f"{len(recent)} rows in {q_ms:.1f} ms")

    # ---- 7. exports + diode ---------------------------------------------------
    print("[7/7] STIX + incident report + diode monitor")
    from src.alerts.export_stix import write_stix
    from src.alerts.report import write_report

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    bundle, problems = write_stix(session_alerts, OUT_DIR / "rehearsal_stix.json")
    check("STIX 2.1 bundle valid", not problems and
          bundle.get("type") == "bundle",
          f"{len(bundle.get('objects', []))} objects")
    report = write_report(session_alerts, OUT_DIR / "rehearsal_report.html")
    check("incident report written", report.exists(),
          f"{report.stat().st_size / 1024:.0f} kB")
    # diode monitor: one-shot status snapshot into a temp status file
    with tempfile.TemporaryDirectory() as td:
        import subprocess
        rc = subprocess.run(
            [sys.executable, "-m", "src.diode.cli", "status",
             "--status-file", str(Path(td) / "diode_status.json")],
            cwd=REPO, capture_output=True, text=True, check=False)
        st = {}
        try:
            st = json.loads((Path(td) / "diode_status.json").read_text())
        except (OSError, ValueError):
            pass
        check("diode status snapshot works (monitor-only on dev host)",
              rc.returncode == 0 and bool(st),
              f"mode={st.get('mode', '?')} outbound_conn={st.get('outbound_connections', '?')}")

    dt = time.perf_counter() - t_start
    print(f"\n[{'PASS' if ok else 'FAIL'}] rehearsal finished in {dt:.1f} s, "
          f"{'demo is GO' if ok else 'fix failures before demoing'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
