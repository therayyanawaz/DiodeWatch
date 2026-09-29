#!/usr/bin/env python3
"""Laya triage acceptance gate: offline checks that pass WITHOUT the 1.7 GB
weights, plus an end-to-end inference check when the bundle is present.

    python scripts/checks/check_laya.py          # port parity + degradation contract
    python scripts/checks/check_laya.py --infer  # also run real triage (needs bundle)

Mirrors scripts/checks/check_diode.py's shape: every check prints PASS/FAIL and the
script exits non-zero if any gate fails.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from src.alerts.schema import Alert, EvidenceItem, validate_alert
from src.triage import laya_runtime as lr
from src.triage import questions as Q
from src.triage.engine import LayaTriage, attach_evidence

PASS = 0
FAIL = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" — {detail}" if detail else ""))
    PASS += ok
    FAIL += not ok


def make_alert(cls: str = "ddos") -> Alert:
    return Alert(
        timestamp="2026-09-04T00:00:00", threat_class=cls, confidence=0.9,
        evidence=[EvidenceItem("flows_per_sec", ">=", 695.4, 50.0,
                               "695.4 flows/s to one dst", "flows/s"),
                  EvidenceItem("pkt_size_entropy", "<=", 3.1, 4.5,
                               "low packet-size entropy", "bits")],
        flow_id="f0", key="10.0.0.9", detector="ddos",
        src_ip="10.0.0.9", dst_ip="93.184.216.34", dst_port=443, proto="tcp")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--infer", action="store_true",
                    help="run real triage too (requires models/laya-onnx)")
    args = ap.parse_args(argv)

    print("Laya triage acceptance — port parity (no weights needed)")
    dump = lr.py_json_dumps({"b": 1, "a": "é", "l": [1, None, True]})
    check("state serialization matches python json.dumps(ensure_ascii=False)",
          dump == '{"b": 1, "a": "é", "l": [1, null, true]}', dump)
    noul = lr.Question("noul", "holds?", None)
    check("noul renders [false, true] so p[1] == P(true)",
          lr.render_options(noul)[1].startswith("true:"))
    check("temperature buckets",
          lr.temp_bucket(2, 2) == "noul:2"
          and lr.temp_bucket(0, 7) == "choice:6-10")
    check("confidence = 1 - normalized entropy",
          abs(lr.confidence_from_probs([0.5, 0.5])) < 1e-9
          and abs(lr.confidence_from_probs([1.0, 0.0]) - 1.0) < 1e-9)

    ids_map = {"cls": 1, "sep": 2, "mask": 3, "pad": 0}
    q = lr.Question("choice", "pick", {"a": None, "b": None})
    ids, markers = lr.build_sequence(lambda t: [7] * len(t.split()),
                                     ids_map, {"k": 1}, q, 512, 192)
    check("sequence layout [CLS] head [SEP] [MASK] opts [SEP] state [SEP]",
          ids[0] == 1 and ids[markers[0]] == 3 and ids[-1] == 2
          and len(markers) == 2)

    print("\nLaya triage acceptance — degradation contract")
    eng = LayaTriage(REPO / "models" / "laya-onnx")
    a = make_alert()
    st = eng.status()
    if st["available"]:
        check("bundle present, channel available", True, st["model_dir"])
    else:
        check("missing bundle degrades loudly (never silent-junk)",
              "fetch_laya" in st.get("reason", ""), st.get("reason", "")[:80])
        check("quiet triage returns None with remembered reason",
              eng.triage_quiet(a) is None and eng.status_reason() is not None)

    print("\nLaya triage acceptance — question mapping")
    qs = Q.triage_questions(a)
    check("three typed questions: choice/score/noul",
          [x.type for x in qs.values()] == ["choice", "score", "noul"])
    state = Q.state_of(a)
    check("state carries evidence, drops bookkeeping",
          len(state["evidence"]) == 2 and "alert_id" not in state)
    summary = {"recommended": "investigate", "p_false_positive": 0.08,
               "urgency": 1.7, "corroborates_class": 0.77}
    before = (a.confidence, a.severity, a.alert_id)
    attach_evidence(a, summary)
    check("verdict attaches as advisory evidence; detection fields intact",
          a.evidence[-1].condition == "triage.disposition"
          and (a.confidence, a.severity, a.alert_id) == before
          and validate_alert(a) == [])

    if args.infer:
        print("\nLaya triage acceptance — real inference (bundle required)")
        if not st["available"]:
            check("inference skipped — bundle unavailable", False,
                  st.get("reason", "")[:80])
        else:
            import time
            t0 = time.perf_counter()
            s = eng.triage(make_alert())
            dt = (time.perf_counter() - t0) * 1000.0
            check("triage returns calibrated summary", "recommended" in s,
                  f"recommended={s.get('recommended')} "
                  f"urgency={s.get('urgency')} "
                  f"p_fp={s.get('p_false_positive')} ({dt:.0f} ms)")
            s2 = eng.triage(make_alert("scan"))
            check("second triage batched session stays warm",
                  "recommended" in s2)
            stat = eng.status()
            check("latency recorded", (stat.get("avg_ms") or 0) > 0,
                  f"avg {stat.get('avg_ms'):.0f} ms/alert")

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
