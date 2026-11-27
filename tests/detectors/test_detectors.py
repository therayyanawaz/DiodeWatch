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
from src.detectors.rules import DEFAULT_RULES, arbitrate_alerts, make_rules, run_rules
from src.detectors.scan import ScanRule
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
    # 100 distinct sources, ~278 flows/s of tiny flows to one dst over ~22 s:
    # the rate must hold across two windows, not just spike in one.
    atk = [rec(i, src=f"10.1.0.{i % 100}", dst="10.9.9.9", sport=20000 + i,
               ts=BASE_TS + i * 0.0036, dur=0.05, fwd_pkts=3, bwd_pkts=1,
               fwd_bytes=120, bwd_bytes=60, label="DoS Hulk")
           for i in range(6000)]
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + atk))
              if a.detector == "ddos" and a.key == "10.9.9.9"]
    assert alerts, "volumetric flood must alert"
    top = max(alerts, key=lambda a: a.confidence)
    conds = {e.condition for e in top.evidence}
    assert "volumetric_rate" in conds
    assert top.confidence <= 1.0 and top.evidence


def test_port_sweep_is_not_a_volumetric_ddos():
    # High flow rate but spread over 100 destination ports: this is sweep
    # shape, so the DDoS volume branch must abstain.
    sweep = [rec(i, src=f"10.1.1.{i % 3}", dst="10.9.9.9", sport=20000 + i,
                 dport=1000 + i % 100, ts=BASE_TS + i * 0.0036, dur=0.05,
                 fwd_pkts=3, bwd_pkts=1, fwd_bytes=120, bwd_bytes=60,
                 label="BENIGN")
             for i in range(8000)]
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + sweep))
              if a.threat_class == "ddos" and a.key == "10.9.9.9"]
    assert not alerts, "a multi-port sweep must not be called a DDoS flood"


def test_random_port_flood_is_ddos_not_scan():
    # 6,000 flows over 6,000 ports in one 7.2 s window: a random-port
    # SYN-style flood. The scan rule caps at 5,000 ports; DDoS must claim it.
    flood = [rec(i, src=f"10.1.2.{i % 3}", dst="10.9.9.8", sport=20000 + i,
                 dport=1000 + i, ts=BASE_TS + i * 0.0012, dur=0.0,
                 fwd_pkts=1, bwd_pkts=0, fwd_bytes=0, bwd_bytes=0,
                 label="Syn")
             for i in range(6000)]
    alerts = run_rules(pd.DataFrame(benign_mix() + flood))
    assert any(a.threat_class == "ddos" and a.key == "10.9.9.8"
               for a in alerts), "random-port flood must be DDoS"
    assert not any(a.threat_class == "scan" for a in alerts), (
        "a random-port flood is not a port sweep")


def test_isolated_rate_spike_does_not_alert():
    # 1,200 flows in one 8.4 s window is 143 flows/s, but the next window is
    # quiet. A busy server spike is not a sustained flood.
    burst = [rec(i, src=f"10.1.1.{i % 3}", dst="10.9.9.9", sport=20000 + i,
                 ts=BASE_TS + i * 0.007, dur=0.05, fwd_pkts=3, bwd_pkts=1,
                 fwd_bytes=400, bwd_bytes=60, label="BENIGN")
             for i in range(1200)]
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + burst))
              if a.threat_class == "ddos" and a.key == "10.9.9.9"]
    assert not alerts, "a single-window spike must not be called a flood"


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
    # 120 flows from one source over 18 s, tiny requests, connections held:
    # the shape holds across two windows before it is called slow DoS
    atk = [rec(i, src="10.3.0.7", dst="10.7.7.7", sport=40000 + i,
               ts=BASE_TS + i * 0.15, dur=45.0, fwd_pkts=6, bwd_pkts=2,
               fwd_bytes=90, bwd_bytes=120, label="DoS slowloris")
           for i in range(120)]
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + atk))
              if a.detector == "slowdos" and a.key == "10.7.7.7"]
    assert alerts, "slowloris shape must alert"
    assert {a.threat_class for a in alerts} == {"slowdos"}
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

    # CIC slowloris dribbles average 100-160 B per forward packet, so the
    # 80 B demo cap missed them. 140 B is still a header-only request.
    cic = [rec(i, src="10.3.0.8", dst="10.7.7.8", sport=42000 + i,
               ts=BASE_TS + i * 0.15, dur=45.0, fwd_pkts=6, bwd_pkts=2,
               fwd_bytes=840, bwd_bytes=120, label="DoS slowloris")
           for i in range(120)]
    alerts3 = [a for a in run_rules(pd.DataFrame(benign_mix() + cic))
               if a.detector == "slowdos" and a.key == "10.7.7.8"]
    assert alerts3, "the CIC 140 B slowloris shape must alert"

    # Slowhttptest requests reach 169-296 B, above the old 160 B cap. The
    # shape is still tiny for a request, held, and one-sided.
    slowhttptest = [rec(i, src="10.3.0.9", dst="10.7.7.9", sport=43000 + i,
                        ts=BASE_TS + i * 0.15, dur=45.0, fwd_pkts=6,
                        bwd_pkts=2, fwd_bytes=1440, bwd_bytes=120,
                        label="DoS Slowhttptest")
                    for i in range(120)]
    alerts4 = [a for a in run_rules(pd.DataFrame(benign_mix() + slowhttptest))
               if a.detector == "slowdos" and a.key == "10.7.7.9"]
    assert alerts4, "the CIC 240 B Slowhttptest shape must alert"

    # A normal 400 B body is outside the slow-request band even when the
    # connection is held; the cap is what keeps ordinary HTTP out.
    oversized = [rec(i, src="10.3.0.10", dst="10.7.7.10", sport=44000 + i,
                     ts=BASE_TS + i * 0.15, dur=45.0, fwd_pkts=6,
                     bwd_pkts=2, fwd_bytes=2400, bwd_bytes=120,
                     label="BENIGN")
                 for i in range(120)]
    alerts5 = [a for a in run_rules(pd.DataFrame(benign_mix() + oversized))
               if a.detector == "slowdos" and a.key == "10.7.7.10"]
    assert alerts5 == []


def test_low_rate_flood_needs_real_bytes():
    # 125 flows/s for three windows is a persistent rate, but 6 KB/s of tiny
    # polls is normal chatter. The same rate carrying 50 KB/s is a flood.
    def burst(src, fwd_bytes):
        return [rec(i, src=f"{src}.{i % 3}", dst="10.9.9.9", sport=20000 + i,
                    ts=BASE_TS + i * 0.008, dur=0.05, fwd_pkts=3, bwd_pkts=1,
                    fwd_bytes=fwd_bytes, bwd_bytes=60, label="BENIGN")
                for i in range(3600)]

    thin = [a for a in run_rules(pd.DataFrame(benign_mix() + burst("10.11.0", 50)))
            if a.threat_class == "ddos" and a.key == "10.9.9.9"]
    assert thin == []
    thick = [a for a in run_rules(pd.DataFrame(benign_mix() + burst("10.12.0", 400)))
             if a.threat_class == "ddos" and a.key == "10.9.9.9"]
    assert thick, "a persistent rate carrying real bytes must alert"


def test_fanin_over_many_ports_is_not_ddos():
    # 60 sources fan in over 100 ports at 50 flows/s. This is distributed
    # background scanning, not a service flood; the fan-in branch must
    # require the destination to look like a service.
    scan = [rec(i, src=f"10.13.0.{i % 60}", dst="10.8.8.10",
                sport=30000 + i, dport=1000 + i % 100,
                ts=BASE_TS + i * 0.02, dur=0.02, fwd_pkts=2, bwd_pkts=1,
                fwd_bytes=60, bwd_bytes=40, label="DoS Hulk")
            for i in range(240)]
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + scan))
              if a.threat_class == "ddos" and a.key == "10.8.8.10"]
    assert not alerts, "a distributed port sweep is not a DDoS claim"


def test_answered_single_source_high_port_burst_is_not_ddos():
    # One source sends 5 KB to 1,100 destination ports for three windows
    # at 555 KB/s, and every flow gets four replies. That is a high-port
    # transfer, not a random-port flood: the single-source carve-out also
    # needs the traffic to be unanswered.
    burst = [rec(i, src="10.14.0.7", dst="10.9.9.10", sport=20000 + i,
                 dport=1000 + i % 1100, ts=BASE_TS + i * 0.009, dur=0.0,
                 fwd_pkts=5, bwd_pkts=4, fwd_bytes=5000, bwd_bytes=800,
                 label="BENIGN")
             for i in range(3300)]
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + burst))
              if a.threat_class == "ddos" and a.key == "10.9.9.10"]
    assert not alerts, "an answered multi-port transfer is not a flood"


def test_unanswered_single_source_random_port_flood_is_ddos():
    # Same shape with no replies: 555 KB/s across 1,100 ports for three
    # windows is the single-source random-port flood CIC-DDoS2019 shows.
    flood = [rec(i, src="10.14.0.8", dst="10.9.9.13", sport=20000 + i,
                  dport=1000 + i % 1100, ts=BASE_TS + i * 0.009, dur=0.0,
                  fwd_pkts=5, bwd_pkts=0, fwd_bytes=5000, bwd_bytes=0,
                  label="DoS Hulk")
              for i in range(3300)]
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + flood))
              if a.threat_class == "ddos" and a.key == "10.9.9.13"]
    assert alerts, "an unanswered random-port flood must still alert"


def test_rate_200_to_250_needs_real_bytes():
    # 210 flows/s across two windows is below the 250/s immediate rate,
    # so it is still server-chatter territory: 10.5 KB/s must stay quiet
    # while the same rate carrying 21 KB/s is a flood.
    def burst(src, dst, fwd_bytes):
        return [rec(i, src=f"{src}.{i % 3}", dst=dst, sport=20000 + i,
                    ts=BASE_TS + i * 0.0048, dur=0.05, fwd_pkts=3,
                    bwd_pkts=1, fwd_bytes=fwd_bytes, bwd_bytes=60,
                    label="DoS Hulk") for i in range(4200)]

    thin = [a for a in run_rules(pd.DataFrame(
        benign_mix() + burst("10.15.0", "10.9.9.11", 50)))
        if a.threat_class == "ddos" and a.key == "10.9.9.11"]
    assert thin == []
    thick = [a for a in run_rules(pd.DataFrame(
        benign_mix() + burst("10.16.0", "10.9.9.12", 100)))
        if a.threat_class == "ddos" and a.key == "10.9.9.12"]
    assert thick, "a 200-250/s rate carrying real bytes must alert"


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

    # A single-host, high-port sweep whose target answers every probe with RST.
    # CIC-IDS2017 PortScan has this shape and the no-reply gate missed it.
    rst_sweep = [rec(i, src="10.5.0.8", dst="10.61.0.1", sport=37000 + i,
                     dport=1000 + i, ts=BASE_TS + i * 0.05, dur=0.0,
                     fwd_pkts=1, bwd_pkts=1, fwd_bytes=60, bwd_bytes=60,
                     rst_flags=1, label=None)
                 for i in range(120)]
    alerts3 = [a for a in run_rules(pd.DataFrame(benign_mix() + rst_sweep))
               if a.threat_class == "scan" and a.key == "10.5.0.8"]
    assert alerts3, "a reset-closed single-host port sweep must alert"
    assert any(e.condition == "resp_share" for a in alerts3 for e in a.evidence)


def test_exfil_ratio_and_bulk_signatures_fire():
    # ratio signature: 25 sustained upload-heavy flows to an external host
    ratio = [rec(i, src="10.20.0.7", dst="93.184.200.5", sport=45000 + i,
                 ts=BASE_TS + i * 0.1, dur=5.0, fwd_pkts=40, bwd_pkts=4,
                 fwd_bytes=60_000, bwd_bytes=2_000, label=None)
             for i in range(25)]
    # below the 500 kB ratio floor: 25 x 12 kB = 300 kB, still 12:1 asymmetric
    small = [rec(i, src="10.20.0.8", dst="93.184.200.8", sport=47000 + i,
                 ts=BASE_TS + 120 + i * 0.1, dur=5.0, fwd_pkts=20, bwd_pkts=2,
                 fwd_bytes=12_000, bwd_bytes=1_000, label=None)
             for i in range(25)]
    # bulk signature: one window with 8 MB uploaded across 40 flows
    bulk = [rec(i, src="10.20.0.9", dst="93.184.200.9", sport=46000 + i,
                ts=BASE_TS + 60 + i * 0.1, dur=8.0, fwd_pkts=300, bwd_pkts=300,
                fwd_bytes=200_000, bwd_bytes=200_000, label=None)
            for i in range(40)]
    alerts = [a for a in run_rules(pd.DataFrame(benign_mix() + ratio + small
                                                + bulk))
              if a.threat_class == "exfil"]
    by_key = {a.key: a for a in alerts}
    assert "10.20.0.7" in by_key and "10.20.0.9" in by_key, \
        "ratio and bulk exfil signatures must both fire"
    assert "10.20.0.8" not in by_key, \
        "a 300 kB window is below the ratio floor and must not alert"
    conds7 = {e.condition for e in by_key["10.20.0.7"].evidence}
    conds9 = {e.condition for e in by_key["10.20.0.9"].evidence}
    assert "upload_ratio" in conds7 and "bulk_upload_bytes" not in conds7
    assert "bulk_upload_bytes" in conds9


def test_broad_host_and_port_enumeration_is_not_scan():
    # 35 hosts x 30 ports is the diagonal benign internal enumerators occupy.
    # A focused sweep is many ports on <=3 hosts; host cardinality alone is not
    # enough, because ordinary discovery walks 30-43 hosts on 2-6 ports.
    broad = [rec(i, src="10.5.0.9", dst=f"10.63.{i % 35}.1",
                 sport=43000 + i, dport=100 + i % 30,
                 ts=BASE_TS + i * 0.01, dur=0.0, fwd_pkts=1, bwd_pkts=0,
                 fwd_bytes=60, bwd_bytes=0, label="BENIGN")
             for i in range(35 * 30)]
    raw = ScanRule().evaluate(build_windows(pd.DataFrame(broad)))
    assert not any(a.key == "10.5.0.9" for a in raw), (
        "broad host+port enumeration must not be called a scan")

    host_sweep = [rec(i, src="10.5.0.10", dst=f"10.64.{i % 40}.1",
                      sport=44000 + i, dport=100 + i % 4,
                      ts=BASE_TS + i * 0.01, dur=0.0, fwd_pkts=1, bwd_pkts=0,
                      fwd_bytes=60, bwd_bytes=0, label="BENIGN")
                  for i in range(40 * 4)]
    raw2 = ScanRule().evaluate(build_windows(pd.DataFrame(host_sweep)))
    assert not any(a.key == "10.5.0.10" for a in raw2), (
        "many hosts on a handful of ports is host discovery, not a port scan")


def test_slowdos_strong_first_window_survives_corroboration():
    # Corroboration normally drops the first window of a run because a single
    # held-connection window can be a backup. 100 flows plus 100 held
    # connections is the starvation shape itself and keeps that window.
    from src.detectors.rules import _corroborate_slowdos

    def slow_alert(offset: int, flows: int, held: int) -> Alert:
        ts = pd.Timestamp(BASE_TS + offset, unit="s", tz="UTC") \
            .strftime("%Y-%m-%dT%H:%M:%S")
        return Alert(
            timestamp=ts, threat_class="slowdos", confidence=0.8,
            evidence=[
                EvidenceItem("flow_count", ">=", flows, 30, "", "flows"),
                EvidenceItem("held_connections", ">=", held, 5, "",
                             "connections"),
            ],
            flow_id="10.7.7.7/*", key="10.7.7.7", dst_ip="10.7.7.7",
            window_start=ts, detector="slowdos")

    flows = pd.DataFrame({"ts_epoch": [BASE_TS + 1, BASE_TS + 11]})
    strong = [slow_alert(0, 150, 120), slow_alert(10, 50, 10)]
    kept = _corroborate_slowdos(strong, flows, 10)
    assert {a.window_start for a in kept} == {strong[0].window_start,
                                             strong[1].window_start}

    weak = [slow_alert(0, 50, 10), slow_alert(10, 50, 10)]
    kept = _corroborate_slowdos(weak, flows, 10)
    assert [a.window_start for a in kept] == [weak[1].window_start]


def test_slowdos_yields_to_ddos_on_same_victim_window():
    # A fast flood and a slow-rate claim on the same destination/window are one
    # incident; the volume alert keeps the stronger class.
    ts = "2026-11-27T00:00:00"
    ddos = Alert(timestamp=ts, threat_class="ddos", confidence=1.0,
                 evidence=[], flow_id="10.9.9.9/*", key="10.9.9.9",
                 dst_ip="10.9.9.9", window_start=ts)
    slow = Alert(timestamp=ts, threat_class="slowdos", confidence=1.0,
                 evidence=[], flow_id="10.9.9.9/*", key="10.9.9.9",
                 dst_ip="10.9.9.9", window_start=ts)
    out = arbitrate_alerts(pd.DataFrame(), [slow, ddos], 10)
    assert [a.threat_class for a in out] == ["ddos"]


def test_scan_claim_inside_ddos_flood_is_suppressed():
    # A SYN flood and a port sweep look identical from one source: tiny flows
    # to many ports, no replies. The victim's DDoS alert owns that traffic.
    # 833 KB/s from 100 sources also satisfies the multi-port carve-out
    # once the victim is swept, so the DDoS claim is independent of the
    # fan-in shape being tested.
    flood = [rec(i, src=f"10.1.0.{i % 100}", dst="10.9.9.9", sport=20000 + i,
                 ts=BASE_TS + i * 0.006, dur=0.05, fwd_pkts=5, bwd_pkts=1,
                 fwd_bytes=5000, bwd_bytes=60, label="DoS Hulk")
             for i in range(1500)]
    sweep = [rec(i, src="10.5.0.7", dst="10.9.9.9", sport=41000 + i,
                 dport=1000 + i, ts=BASE_TS + i * 0.05, dur=0.0,
                 fwd_pkts=1, bwd_pkts=0, fwd_bytes=60, bwd_bytes=0,
                 label="PortScan")
             for i in range(60)]
    flows = pd.DataFrame(benign_mix() + flood + sweep)

    raw = ScanRule().evaluate(build_windows(flows))
    assert any(a.key == "10.5.0.7" for a in raw), "sweep must look like a scan"
    alerts = run_rules(flows)
    assert any(a.threat_class == "ddos" and a.key == "10.9.9.9" for a in alerts)
    assert not any(a.threat_class == "scan" and a.key == "10.5.0.7"
                   for a in alerts), "scan inside a DDoS flood is double-counting"

    # A port sweep that never touches the flood victim is still a scan.
    apart = [rec(i, src="10.5.0.8", dst=f"10.60.0.{i % 3 + 1}",
                 sport=42000 + i, dport=1000 + i, ts=BASE_TS + i * 0.05,
                 dur=0.0, fwd_pkts=1, bwd_pkts=0, fwd_bytes=60,
                 bwd_bytes=0, label="PortScan")
             for i in range(60)]
    alerts2 = run_rules(pd.DataFrame(benign_mix() + flood + apart))
    assert any(a.threat_class == "scan" and a.key == "10.5.0.8"
               for a in alerts2), "unrelated scan must survive arbitration"


def test_rules_respect_param_overrides():
    # with a huge rate threshold the volumetric branch goes quiet
    # (the independent fan-in signature may still fire, that is correct)
    rules = make_rules({"ddos": {"flows_per_sec": 10_000.0}})
    atk = [rec(i, src=f"10.1.0.{i % 50}", dst="10.9.9.9", sport=20000 + i,
               ts=BASE_TS + i * 0.004, dur=0.05, fwd_pkts=3, bwd_pkts=1,
               fwd_bytes=120, bwd_bytes=60, label="DoS Hulk")
           for i in range(7000)]  # 250 flows/s, sustained over three windows
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
