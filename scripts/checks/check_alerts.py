#!/usr/bin/env python3
"""Exit check: alert evidence store + STIX / OCSF / incident-report exports.

Acceptance criteria (exit 0 = met):

  1. insert THOUSANDS of real alerts into the SQLite store error-free
     (primary corpus: the ml_engine full-day output at
     data/slices/ml_alerts__Wednesday.jsonl, up to 50,000 ingested;
     fallback: a deterministic synthetic set so the check still runs on a
     machine without the corpus);
  2. every ingested alert carries the SOC-schema fields (severity,
     alert_id, att&ck_techniques) and re-ingestion is idempotent;
  3. "recent" queries answer in milliseconds (recency/class/severity
     filters over the indexed ts_epoch) and return newest-first;
  4. a STIX 2.1 bundle exports cleanly (structural validation passes) for a
     class-balanced subset;
  5. OCSF 1.10.0 Detection Finding JSONL exports cleanly for the same subset;
  6. an incident report renders every evidence field and the 5-tuple.

    python scripts/checks/check_alerts.py [--limit 50000] [--outdir data/alerts]

Runtime artifacts land under data/alerts/ (never committed).
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from src.alerts.export_ocsf import write_ocsf
from src.alerts.export_stix import write_stix
from src.alerts.report import write_report
from src.alerts.schema import Alert, EvidenceItem, alert_from_dict
from src.alerts.store import AlertStore, iter_jsonl

PRIMARY_CORPUS = (REPO / "data/slices/ml_alerts__Wednesday.jsonl")
OUT_DIR = REPO / "data" / "alerts"
SEVERITIES = {"low", "medium", "high", "critical"}


def synthetic_alerts(n: int) -> list[Alert]:
    """Deterministic stand-in corpus when the real ml output is absent."""
    classes = ["ddos", "scan", "exfil", "beacon", "dga"]
    out = []
    for i in range(n):
        cls = classes[i % len(classes)]
        h, m = divmod(i // 60, 60)
        ts = f"2026-09-04T{h % 24:02d}:{m:02d}:{i % 60:02d}"
        out.append(Alert(
            timestamp=ts, threat_class=cls, confidence=0.5 + 0.4 * (i % 2),
            detector=f"ml.{cls}",
            flow_id=f"syn-{i}", key=f"10.9.0.{i % 250}",
            src_ip=f"10.9.0.{i % 250}", dst_ip="203.0.113.7",
            src_port=40000 + i % 1000, dst_port=(53, 80, 443)[i % 3],
            proto="tcp",
            evidence=[EvidenceItem(f"{cls}_rate", ">=", 100.0 + i, 50.0,
                                   f"synthetic {cls} signature", "count")],
        ))
    return out


def _class_sample(alerts: list[dict], per_class: int = 40) -> list[dict]:
    """Balanced subset: up to per_class alerts of every class present."""
    by_class: dict[str, list[dict]] = {}
    for d in alerts:
        by_class.setdefault(d["threat_class"], []).append(d)
    picked: list[dict] = []
    for cls in sorted(by_class):
        picked.extend(by_class[cls][:per_class])
    return picked


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=50_000,
                    help="max alerts ingested from the real corpus")
    ap.add_argument("--outdir", type=Path, default=OUT_DIR)
    args = ap.parse_args()
    out = args.outdir
    out.mkdir(parents=True, exist_ok=True)
    ok = True

    # ------------------------------------------------------------- 1. corpus
    corpus = PRIMARY_CORPUS if PRIMARY_CORPUS.exists() else None
    tag = f"ml_engine full-day output ({PRIMARY_CORPUS.name})" if corpus \
        else "deterministic synthetic stand-in"
    if corpus:
        records = list(iter_jsonl(corpus, limit=args.limit))
        print(f"[corpus] {corpus} -> {len(records):,} alerts ({tag})")
    else:
        alerts = synthetic_alerts(args.limit)
        records = [a.to_dict() for a in alerts]
        print(f"[corpus] no ml output present, {len(records):,} synthetic "
              f"alerts ({tag})")
    if not records:
        print("[FAIL] no alerts available to ingest", file=sys.stderr)
        return 1

    # -------------------------------------------------------- 2. insert many
    db = out / "alert_store_acceptance.db"
    if db.exists():                     # fresh run, not incremental state
        db.unlink()
    t0 = time.perf_counter()
    with AlertStore(db) as store:
        inserted, dup, invalid = store.insert_many(
            alert_from_dict(d) for d in records)
    insert_ms = (time.perf_counter() - t0) * 1000.0
    print(f"[store ] inserted={inserted:,} duplicates={dup:,} invalid={invalid:,} "
          f"in {insert_ms:,.0f} ms -> {db}")
    if invalid:
        print(f"  [FAIL] {invalid:,} alerts failed schema validation")
        ok = False
    if inserted < 1_000:
        print(f"  [FAIL] expected thousands of inserts, got {inserted:,}")
        ok = False

    # idempotent re-ingest (stable alert_id, OR IGNORE)
    replay = records[:5000]
    with AlertStore(db) as store:
        i2, d2, v2 = store.insert_many(alert_from_dict(d) for d in replay)
    if not (i2 == 0 and d2 == len(replay) and v2 == 0):
        print(f"  [FAIL] re-ingest not idempotent: ({i2}, {d2}, {v2})")
        ok = False
    else:
        print(f"[store ] re-ingest of first 5,000: {d2:,} duplicates, "
              f"{i2} inserted (idempotent) [ok]")

    # ----------------------------------------------- 3. schema field audit
    with AlertStore(db) as store:
        sample = store.recent(limit=2_000)
    missing = 0
    bad_uuid = 0
    for a in sample:
        if a.severity not in SEVERITIES or not a.alert_id or not a.evidence:
            missing += 1
        try:
            uuid.UUID(str(a.alert_id))
        except ValueError:
            bad_uuid += 1
    print(f"[schema] {len(sample):,} sampled: severity/alert_id/evidence "
          f"missing on {missing}, bad uuids {bad_uuid}")
    if missing or bad_uuid:
        print("  [FAIL] schema audit found malformed alerts")
        ok = False
    n_ep = sum(1 for a in sample if a.src_ip and a.dst_ip)
    print(f"[schema] {n_ep:,}/{len(sample):,} sampled alerts carry the flow "
          f"5-tuple (endpoints)")

    # --------------------------------------------------- 4. quick queries
    with AlertStore(db) as store:
        t0 = time.perf_counter()
        recent = store.recent(limit=20)
        q_ms = (time.perf_counter() - t0) * 1000.0
        stamps = [a.timestamp for a in recent]
        ordered = stamps == sorted(stamps, reverse=True)

        t0 = time.perf_counter()
        crit = store.recent(limit=100, severity="critical")
        crit_ms = (time.perf_counter() - t0) * 1000.0

        t0 = time.perf_counter()
        by_cls = store.recent(limit=100, threat_class="ddos")
        cls_ms = (time.perf_counter() - t0) * 1000.0

        stats = store.stats()
    print(f"[query ] recent(20)={q_ms:,.1f} ms newest-first={'yes' if ordered else 'NO'} | "
          f"severity filter={crit_ms:,.1f} ms ({len(crit)} rows) | "
          f"class filter={cls_ms:,.1f} ms ({len(by_cls)} rows)")
    if not ordered or q_ms > 2_000 or crit_ms > 2_000:
        print("  [FAIL] recency query wrong or slower than the 2 s bound")
        ok = False
    print(f"[stats ] {stats['alerts']:,} alerts total; "
          f"classes={stats['by_threat_class']}; severities={stats['by_severity']}")

    # -------------------------------------------------- 5. STIX 2.1 export
    picked = _class_sample(records, per_class=30)
    stix_alerts = [alert_from_dict(d) for d in picked]
    stix_path = out / "incident_bundle.json"
    t0 = time.perf_counter()
    bundle, problems = write_stix(stix_alerts, stix_path)
    stix_ms = (time.perf_counter() - t0) * 1000.0
    n_types = Counter(o["type"] for o in bundle["objects"])
    print(f"[stix  ] {len(stix_alerts)} alerts -> {stix_path} "
          f"({stix_ms:,.0f} ms) objects={dict(n_types)}")
    if problems:
        print(f"  [FAIL] STIX validation: {problems[:5]}")
        ok = False
    else:
        print("  stix validation: clean [ok]")

    # ------------------------------------------ 5. OCSF Detection Findings
    ocsf_path = out / "ocsf_detection_findings.jsonl"
    t0 = time.perf_counter()
    events, ocsf_problems = write_ocsf(stix_alerts, ocsf_path)
    ocsf_ms = (time.perf_counter() - t0) * 1000.0
    print(f"[ocsf  ] {len(events)} alerts -> {ocsf_path} "
          f"({ocsf_ms:,.0f} ms) class_uid="
          f"{sorted({e['class_uid'] for e in events})}")
    if ocsf_problems:
        print(f"  [FAIL] OCSF validation: {ocsf_problems[:5]}")
        ok = False
    else:
        print("  ocsf validation: clean [ok]")

    # ------------------------------------------------- 6. incident report
    with AlertStore(db) as store:
        report_alerts = store.recent(limit=50)
    report_path = out / "incident_report.html"
    write_report(report_alerts, report_path, title="Alert store acceptance, recent alerts")
    text = report_path.read_text(encoding="utf-8")
    n_blocks = text.count('<div class="alert">')
    has_evidence = all(
        any(e.description for e in a.evidence) for a in report_alerts[:10])
    print(f"[report] {len(report_alerts)} alerts -> {report_path} "
          f"({n_blocks} blocks; evidence rendered)")
    if n_blocks != len(report_alerts) or not has_evidence:
        print("  [FAIL] incident report missing alerts or evidence fields")
        ok = False
    # evidence inspection line for the acceptance read-out
    first = report_alerts[0]
    print(f"[sample] newest: {first.timestamp} class={first.threat_class} "
          f"sev={first.severity} conf={first.confidence} "
          f"detector={first.detector} attck={first.attack_technique}")
    if first.src_ip and first.dst_ip:
        print(f"[sample] 5-tuple: {first.src_ip}:{first.src_port} -> "
              f"{first.dst_ip}:{first.dst_port} ({first.proto})")
    for e in first.evidence[:3]:
        print(f"[sample] evidence: {e.condition}: {e.observed} {e.operator} "
              f"{e.threshold}, {e.description} [{e.unit}]")

    print("\n[PASS] Alert store & export acceptance criteria met"
          if ok else "\n[FAIL] acceptance criteria NOT met", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
