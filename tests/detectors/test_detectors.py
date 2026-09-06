"""Rule-detector tests: alert envelope, window engine, and rule-based detectors.

Detector tests use hand-built synthetic scenarios with known ground truth
(attack slices must alert, benign slices must stay silent), plus a slice
regression block that runs the real CIC flows.ndjson when present.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from src.alerts.schema import ATTACK_MAP, Alert, EvidenceItem, validate_alert
from src.detectors.rules import DEFAULT_RULES, make_rules, run_rules
from src.detectors.window import build_windows

REPO = Path(__file__).resolve().parents[2]
FLOWS_NDJSON = REPO / "data" / "slices" / "flows.ndjson"

BASE_TS = 1_499_268_000.0  # 2017-07-05T12:20:00Z; arbitrary fixed epoch


# --------------------------------------------------------------------------- #
# canonical record helper
# --------------------------------------------------------------------------- #

def rec(i=0, *, src="10.0.0.1", dst="10.0.0.99", sport=None, dport=80,
        proto=6, ts=None, dur=1.0, fwd_pkts=4, bwd_pkts=4, fwd_bytes=800,
        bwd_bytes=2000, label=None, **flags) -> dict:
    """One canonical flow record with TCP-normal defaults."""
    ts = BASE_TS + i * 0.01 if ts is None else ts
    base = {
        "flow_id": f"{src}-{dst}-{sport or 40000 + i}-{dport}-{proto}",
        "src_ip": src, "src_port": sport if sport is not None else 40000 + i,
        "dst_ip": dst, "dst_port": dport, "protocol": proto,
        "proto": {6: "tcp", 17: "udp", 1: "icmp"}.get(proto),
        "timestamp": pd.Timestamp(ts, unit="s", tz="UTC").strftime("%Y-%m-%dT%H:%M:%S"),
        "ts_epoch": ts, "duration_us": int(dur * 1e6),
        "fwd_pkts": fwd_pkts, "bwd_pkts": bwd_pkts,
        "fwd_bytes": fwd_bytes, "bwd_bytes": bwd_bytes,
        "fin_flags": 0, "syn_flags": 0, "rst_flags": 0,
        "psh_flags": 0, "ack_flags": 0, "urg_flags": 0,
        "label": label,
    }
    base.update(flags)
    return base


# --------------------------------------------------------------------------- #
# alert envelope
# --------------------------------------------------------------------------- #

def test_alert_envelope_roundtrip_and_validation():
    a = Alert(timestamp="2026-09-04T00:00:00", threat_class="ddos",
              confidence=0.67,
              evidence=[EvidenceItem("volumetric_rate", ">=", 695.4, 50,
                                     "695.4 flows/s to one dst", "flows/s")],
              flow_id="10.0.0.99/*", key="10.0.0.99")
    d = a.to_dict()
    assert d["threat_class"] == "ddos"
    assert d["confidence"] == 0.67
    assert d["attack_technique"] == ATTACK_MAP["ddos"][0]
    ev = d["evidence"][0]
    assert ev["condition"] == "volumetric_rate" and ev["observed"] == 695.4
    assert validate_alert(a) == []

    json.dumps(d)  # must be JSON-serializable


def test_validate_alert_flags_problems():
    bad = Alert(timestamp="", threat_class="martian", confidence=1.5,
                evidence=[])
    problems = validate_alert(bad)
    assert any("timestamp" in p for p in problems)
    assert any("threat_class" in p for p in problems)
    assert any("confidence" in p for p in problems)
    assert any("evidence" in p for p in problems)


# --------------------------------------------------------------------------- #
# window engine
# --------------------------------------------------------------------------- #

def test_build_windows_groups_and_rates():
    flows = pd.DataFrame([
        rec(0, src="10.0.0.1", dst="10.0.0.99", ts=BASE_TS),
        rec(1, src="10.0.0.2", dst="10.0.0.99", ts=BASE_TS + 1),
        rec(2, src="10.0.0.1", dst="10.0.0.98", ts=BASE_TS + 2),
        rec(3, src="10.0.0.1", dst="10.0.0.50", dport=53, proto=17,
            ts=BASE_TS + 3),
    ])
    wf = build_windows(flows, window_s=10)
    assert wf.n_flows == 4 and wf.n_dropped_ts == 0

    d = wf.dst
    row = d.loc[(d.index.get_level_values("dst_ip") == "10.0.0.99")].iloc[0]
    assert row["flows"] == 2
    assert row["n_src"] == 2
    assert row["flows_per_sec"] == pytest.approx(0.2)

    s = wf.src
    row1 = s.loc[(s.index.get_level_values("src_ip") == "10.0.0.1")].iloc[0]
    assert row1["flows"] == 3
    assert row1["n_dports"] == 2          # {80, 53}
    assert row1["n_dips"] == 3


def test_build_windows_drops_bad_timestamps_and_rejects_junk():
    flows = pd.DataFrame([rec(0), rec(1), rec(2, ts=None)])
    flows.loc[2, "ts_epoch"] = float("nan")
    wf = build_windows(flows, window_s=10)
    assert wf.n_flows == 2 and wf.n_dropped_ts == 1

    with pytest.raises(ValueError, match="canonical"):
        build_windows(flows.drop(columns=["fwd_pkts"]))
    with pytest.raises(ValueError, match="window_s"):
        build_windows(flows, window_s=0)


def test_sentinel_duration_excluded_from_held_conns():
    # CIC quirk: duration_us = -1 must not count as a held connection
    flows = pd.DataFrame([rec(0, dur=-1e-6), rec(1, dur=60.0)])
    wf = build_windows(flows, window_s=10)
    assert wf.dst["held_conns"].sum() == 1.0


# --------------------------------------------------------------------------- #
# synthetic threat scenarios (ground truth known by construction)
# --------------------------------------------------------------------------- #

def benign_mix(n=40) -> list[dict]:
    """Unremarkable web traffic spread over clients, servers and 40 s."""
    out = []
    for i in range(n):
        out.append(rec(i, src=f"10.0.1.{i % 5}", dst=f"93.184.0.{10 + i % 4}",
                       ts=BASE_TS + (i % 40) * 1.0, dur=2.0,
                       fwd_pkts=8, bwd_pkts=10,
                       fwd_bytes=1500, bwd_bytes=9000, label="BENIGN"))
    return out


def test_benign_traffic_produces_no_alerts():
    alerts = run_rules(pd.DataFrame(benign_mix()))
    assert alerts == []


def test_volumetric_ddos_fires_and_benign_does_not():
    # 100 distinct sources, ~150 flows/s of tiny flows to one dst over ~10 s
    atk = [rec(i, src=f"10.1.0.{i % 100}", dst="10.9.9.9", sport=20000 + i,
               ts=BASE_TS + i * 0.006, dur=0.05, fwd_pkts=3, bwd_pkts=1,
               fwd_bytes=120, bwd_bytes=60, label="DoS Hulk")
           for i in range(1500)]
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + atk))
              if a.detector == "ddos" and a.key == "10.9.9.9"]
    assert alerts, "volumetric flood must alert"
    top = max(alerts, key=lambda a: a.confidence)
    conds = {e.condition for e in top.evidence}
    assert "volumetric_rate" in conds
    assert top.confidence <= 1.0 and top.evidence


def test_fanin_and_synflood_signatures_fire():
    # 60 sources SYN-flooding one dst: no replies at all (240 flows -> conc 0.25)
    atk = [rec(i, src=f"10.2.0.{i % 60}", dst="10.8.8.8", sport=30000 + i,
               ts=BASE_TS + i * 0.02, dur=0.0, fwd_pkts=2, bwd_pkts=0,
               fwd_bytes=80, bwd_bytes=0, syn_flags=2, label="DoS Hulk")
           for i in range(240)]
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + atk))
              if a.threat_class == "ddos" and a.key == "10.8.8.8"]
    assert alerts, "fan-in SYN flood must alert"
    conds = {e.condition for a in alerts for e in a.evidence}
    assert "fan_in_distinct_sources" in conds
    assert "syn_flood_half_open" in conds


def test_slowdos_fires_on_slowloris_shape_only():
    # 30 flows from one source, tiny requests, connections held across windows
    atk = [rec(i, src="10.3.0.7", dst="10.7.7.7", sport=40000 + i,
               ts=BASE_TS + i * 0.1, dur=45.0, fwd_pkts=6, bwd_pkts=2,
               fwd_bytes=90, bwd_bytes=120, label="DoS slowloris")
           for i in range(35)]
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + atk))
              if a.detector == "slowdos" and a.key == "10.7.7.7"]
    assert alerts, "slowloris shape must alert"
    conds = {e.condition for a in alerts for e in a.evidence}
    assert {"flow_count", "fwd_bwd_pkt_ratio", "mean_fwd_pkt_size",
            "held_connections"} <= conds

    # same shape but connections NOT held (fast tiny poller) must stay silent
    benign_poller = [rec(i, src="10.4.0.7", dst="10.6.6.6", sport=41000 + i,
                         ts=BASE_TS + i * 0.1, dur=0.05, fwd_pkts=6, bwd_pkts=2,
                         fwd_bytes=90, bwd_bytes=120, label="BENIGN")
                     for i in range(35)]
    alerts2 = [a for a in run_rules(pd.DataFrame(benign_mix() + benign_poller))
               if a.detector == "slowdos" and a.key == "10.6.6.6"]
    assert alerts2 == []


def test_scan_fires_on_port_sweep_only():
    # 60 probe flows from one source to 60 distinct ports, mostly unanswered
    atk = [rec(i, src="10.5.0.7", dst=f"10.60.0.{i % 3}", sport=35000 + i,
               dport=1000 + i, ts=BASE_TS + i * 0.05, dur=0.0,
               fwd_pkts=1, bwd_pkts=0, fwd_bytes=60, bwd_bytes=0,
               rst_flags=1 if i % 3 else 0, label=None)
           for i in range(60)]
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + atk))
              if a.threat_class == "scan" and a.key == "10.5.0.7"]
    assert alerts, "port sweep must alert"
    conds = {e.condition for a in alerts for e in a.evidence}
    assert "cardinality" in conds and "bytes_per_flow" in conds

    # a chatty-but-legit high-cardinality client (real sessions, replies) stays silent
    chatty = [rec(i, src="10.5.0.9", dst=f"93.184.1.{i}", sport=36000 + i,
                  dport=443, ts=BASE_TS + i * 0.05, dur=5.0,
                  fwd_pkts=20, bwd_pkts=40, fwd_bytes=4000, bwd_bytes=60000,
                  label="BENIGN")
              for i in range(35)]
    alerts2 = [a for a in run_rules(pd.DataFrame(benign_mix() + chatty))
               if a.threat_class == "scan" and a.key == "10.5.0.9"]
    assert alerts2 == []


def test_exfil_ratio_and_bulk_signatures_fire():
    # ratio signature: 25 sustained upload-heavy flows to an external host
    ratio = [rec(i, src="10.20.0.7", dst="93.184.200.5", sport=45000 + i,
                 ts=BASE_TS + i * 0.1, dur=5.0, fwd_pkts=40, bwd_pkts=4,
                 fwd_bytes=60_000, bwd_bytes=2_000, label=None)
             for i in range(25)]
    # bulk signature: one window with 8 MB uploaded across 40 flows
    bulk = [rec(i, src="10.20.0.9", dst="93.184.200.9", sport=46000 + i,
                ts=BASE_TS + 60 + i * 0.1, dur=8.0, fwd_pkts=300, bwd_pkts=300,
                fwd_bytes=200_000, bwd_bytes=200_000, label=None)
            for i in range(40)]
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + ratio + bulk))
              if a.threat_class == "exfil"]
    by_key = {a.key: a for a in alerts}
    assert "10.20.0.7" in by_key and "10.20.0.9" in by_key, \
        "ratio and bulk exfil signatures must both fire"
    conds7 = {e.condition for e in by_key["10.20.0.7"].evidence}
    conds9 = {e.condition for e in by_key["10.20.0.9"].evidence}
    assert "upload_ratio" in conds7 and "bulk_upload_bytes" not in conds7
    assert "bulk_upload_bytes" in conds9


def test_rules_respect_param_overrides():
    # with a huge rate threshold the volumetric branch goes quiet
    # (the independent fan-in signature may still fire — that is correct)
    rules = make_rules({"ddos": {"flows_per_sec": 10_000.0}})
    atk = [rec(i, src=f"10.1.0.{i % 50}", dst="10.9.9.9", sport=20000 + i,
               ts=BASE_TS + i * 0.005, dur=0.05, fwd_pkts=3, bwd_pkts=1,
               fwd_bytes=120, bwd_bytes=60, label="DoS Hulk")
           for i in range(600)]  # 60 flows/s over the 10 s window
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + atk), rules=rules)
              if a.key == "10.9.9.9"]
    conds = {e.condition for a in alerts for e in a.evidence}
    assert "volumetric_rate" not in conds
    # and the default rule set still catches it as volumetric
    alerts_default = [a for a in run_rules(pd.DataFrame(benign_mix() + atk))
                      if a.detector == "ddos" and a.key == "10.9.9.9"]
    assert any("volumetric_rate" in {e.condition for e in a.evidence}
               for a in alerts_default)


def test_every_alert_is_valid_and_serializable():
    atk = [rec(i, src=f"10.1.0.{i % 60}", dst="10.9.9.9", sport=20000 + i,
               ts=BASE_TS + i * 0.005, dur=0.02, fwd_pkts=4, bwd_pkts=1,
               fwd_bytes=100, bwd_bytes=50, syn_flags=2, label="DoS Hulk")
           for i in range(900)]  # ~90 flows/s: volumetric ddos
    alerts = run_rules(pd.DataFrame(benign_mix() + atk))
    assert alerts
    for a in alerts:
        assert validate_alert(a) == []
        json.dumps(a.to_dict())
        assert a.detector in {r.name for r in DEFAULT_RULES}
        assert a.window_start and a.window_end


# --------------------------------------------------------------------------- #
# slice regression (real data when downloaded)
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not FLOWS_NDJSON.exists(),
                    reason="flows.ndjson not downloaded (run unify first)")
def test_slice_ddos_fires_and_benign_stays_quiet():
    with FLOWS_NDJSON.open(encoding="utf-8") as fh:
        recs = [json.loads(l) for l in fh if l.strip()]
    flows = pd.DataFrame(recs)
    alerts = run_rules(flows)

    ddos = [a for a in alerts if a.threat_class == "ddos"]
    scans = [a for a in alerts if a.threat_class == "scan"]
    benign_only = [a for a in alerts if a.label == "BENIGN"]

    assert ddos, "DDoS alerts required on DDoS portions of the slice"
    assert all(a.label != "BENIGN" for a in ddos), "no DDoS alert on pure-benign windows"
    assert len(benign_only) <= 2, \
        f"too many alerts on benign-labelled windows: {len(benign_only)}"
    # scan detector must stay quiet on benign-labelled windows
    assert all(a.label != "BENIGN" for a in scans)


# --------------------------------------------------------------------------- #
# rules CLI
# --------------------------------------------------------------------------- #

def test_rules_cli_writes_ndjson(tmp_path):
    from src.detectors.rules import main as rules_main
    src = tmp_path / "flows.ndjson"
    src.write_text("\n".join(json.dumps(r) for r in benign_mix() + [
        rec(i, src=f"10.1.0.{i % 60}", dst="10.9.9.9", sport=20000 + i,
            ts=BASE_TS + i * 0.005, dur=0.05, fwd_pkts=3, bwd_pkts=1,
            fwd_bytes=120, bwd_bytes=60, label="DoS Hulk")
        for i in range(600)]), encoding="utf-8")
    out = tmp_path / "alerts.ndjson"
    assert rules_main(["--input", str(src), "--out", str(out)]) == 0
    lines = [json.loads(l) for l in out.open(encoding="utf-8") if l.strip()]
    assert any(d["threat_class"] == "ddos" for d in lines)
    assert all("evidence" in d and d["evidence"] for d in lines)
