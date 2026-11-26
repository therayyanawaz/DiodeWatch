"""Benchmark & demo-pack tests: pack generator, benchmark helpers, manifest contract."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))


_SCRIPT_SUBDIR = {"bench_throughput": "benchmarks", "bench_accuracy": "benchmarks"}


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(
        name, REPO / "scripts" / _SCRIPT_SUBDIR[name] / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------- demo pack
def test_pack_manifest_contract():
    """The generated manifest describes every pack item and its detector."""
    man = json.loads((REPO / "data" / "pcaps" / "pack" /
                      "pack_manifest.json").read_text())
    items = {item["pcap"]: item for item in man["pack"]}
    assert set(items) == {"01_ddos.pcap", "02_c2_beacon.pcap",
                          "03_dga_tunnel.pcap", "04_exfil_scan.pcap",
                          "05_slowloris.pcap", "06_exfil_ratio.pcap"}
    for pcap, item in items.items():
        assert (REPO / "data" / "pcaps" / "pack" / pcap).exists()
        assert item["expected"]["threat_class"]
    assert items["01_ddos.pcap"]["expected"]["rule_expected"] == ["ddos"]
    assert items["04_exfil_scan.pcap"]["expected"]["rule_expected"] == [
        "scan", "exfil"]
    assert items["05_slowloris.pcap"]["expected"]["rule_expected"] == ["slowdos"]
    assert items["06_exfil_ratio.pcap"]["expected"]["rule_expected"] == ["exfil"]
    assert items["02_c2_beacon.pcap"]["expected"]["sidecar"] == \
        "02_c2_beacon_netflow.csv"
    assert items["03_dga_tunnel.pcap"]["expected"]["sidecar"] == \
        "03_dga_domains.txt"


def test_pack_replay_fires_rules():
    """DDoS and exfil/scan pcaps fire their rule classes on the right keys."""
    from src.detectors.rules import run_rules
    from src.ingest.pcap_reader import stream_flows

    pack = REPO / "data" / "pcaps" / "pack"
    ddos = pd.DataFrame(list(stream_flows(pack / "01_ddos.pcap")))
    alerts = run_rules(ddos, window_s=10)
    assert {a.key for a in alerts if a.threat_class == "ddos"} == {"10.9.9.9"}
    assert all(a.label is None for a in alerts)  # pcap flows are unlabeled

    exfil = pd.DataFrame(list(stream_flows(pack / "04_exfil_scan.pcap")))
    alerts4 = run_rules(exfil, window_s=10)
    got = {a.threat_class: a.key for a in alerts4}
    assert got.get("scan") == "10.5.0.7" and got.get("exfil") == "10.20.0.9"

    slow = pd.DataFrame(list(stream_flows(pack / "05_slowloris.pcap")))
    alerts5 = run_rules(slow, window_s=10)
    assert {a.key for a in alerts5 if a.detector == "slowdos"} == {"10.7.7.7"}
    assert all(a.label is None for a in alerts5)

    ratio = pd.DataFrame(list(stream_flows(pack / "06_exfil_ratio.pcap")))
    alerts6 = run_rules(ratio, window_s=10)
    by_key = {a.key: a for a in alerts6 if a.threat_class == "exfil"}
    assert "10.20.0.7" in by_key
    assert "upload_ratio" in {e.condition for e in by_key["10.20.0.7"].evidence}
    assert "bulk_upload_bytes" not in {e.condition for e in by_key["10.20.0.7"].evidence}
    assert all(a.label is None for a in alerts6)


def test_pack_beacon_sidecar_fires_model():
    """The beacon NetFlow sidecar (derived from the pcap) fires the model."""
    from src.detectors.ml import beacon as beacon_mod

    pack = REPO / "data" / "pcaps" / "pack"
    flows = beacon_mod.load_ctu(pack / "02_c2_beacon_netflow.csv")
    pairs = beacon_mod.pair_series(flows)
    model = beacon_mod.BeaconModel.load(REPO / "models")
    scores = model.predict_score(pairs)
    fired = {str(s) for s, sc in zip(pairs["src_ip"], scores)
             if sc >= model.threshold}
    assert "10.30.0.9" in fired  # bursty C2 bot, verified shape (score >= .95)
    benign = pairs[~pairs["src_ip"].isin(("10.30.0.9", "10.30.0.8"))]
    assert bool((model.predict_score(benign) < model.threshold).all())


def test_pack_dga_sidecar_fires_model():
    """The DGA sidecar flags every tunnel domain; benign names stay quiet."""
    from src.detectors.ml.dga import DgaModel

    pack = REPO / "data" / "pcaps" / "pack"
    doms = pd.Series([l.strip() for l in
                      (pack / "03_dga_domains.txt").read_text().splitlines()
                      if l.strip()])
    assert len(doms) >= 40
    dm = DgaModel.load(REPO / "models")
    scores = dm.score_domains(doms)
    assert bool((scores >= dm.threshold).all())
    benign = pd.Series(["www.example.com", "mail.google.com",
                        "updates.microsoft.com"])
    assert bool((dm.score_domains(benign) < dm.threshold).all())


# ------------------------------------------------------------ throughput bench
def test_bench_dense_window_shape():
    """_dense_window retimes corpus rows into ONE window at the offered rate."""
    bench = _load_script("bench_throughput")
    recs = [{"ts_epoch": float(i), "timestamp": f"t{i}", "src_ip": "10.0.0.1",
             "dst_ip": "10.0.0.2", "src_port": 1000, "dst_port": 80,
             "protocol": 6, "proto": "tcp", "duration_us": 1000,
             "fwd_pkts": 1, "bwd_pkts": 1, "fwd_bytes": 100, "bwd_bytes": 100,
             "flow_id": f"f{i}"} for i in range(50)]

    class _Rng:
        def choice(self, n, size, replace):
            import numpy as np
            return np.arange(size) % n

    win = bench._dense_window(recs, rate=5, rng=_Rng())  # 5 f/s * 10 s = 50
    assert len(win) == 50
    epochs = sorted(w["ts_epoch"] for w in win)
    span = epochs[-1] - epochs[0]
    assert 8.0 <= span <= 10.0  # dense single window, 0.2 s apart


def test_bench_percentile_helper():
    bench = _load_script("bench_throughput")
    vals = list(range(1, 101))  # 1..100, nearest-rank on 0-indexed list
    assert bench._percentile(vals, 0.5) == 51   # k = round(0.50 * 99) = 50
    assert bench._percentile(vals, 0.95) == 95  # k = round(0.95 * 99) = 94
    assert bench._percentile([], 0.99) == 0.0


# --------------------------------------------------------------- window rollup
def test_window_label_rollup_matches_original_semantics():
    """Attack label wins over BENIGN; unlabeled windows keep label=None."""
    from src.detectors.window import build_windows

    base = {"timestamp": "x", "duration_us": 1000,
            "fwd_pkts": 1, "bwd_pkts": 1, "fwd_bytes": 100, "bwd_bytes": 100,
            "src_port": 1000, "dst_port": 80, "protocol": 6, "proto": "tcp"}
    rows = []
    # benign window (labels present)
    for i in range(12):
        rows.append({**base, "flow_id": f"b{i}", "src_ip": f"10.0.0.{i}",
                     "dst_ip": "10.9.9.9", "label": "BENIGN",
                     "ts_epoch": 1000.0 + i * 0.1})
    # attack window: benign majority + one attack row (attack must win)
    for i in range(12):
        rows.append({**base, "flow_id": f"a{i}", "src_ip": f"10.0.1.{i}",
                     "dst_ip": "10.9.9.9",
                     "label": "BENIGN" if i else "DoS Hulk",
                     "ts_epoch": 1010.0 + i * 0.1})
    # unlabeled window (pcap shape)
    for i in range(12):
        rows.append({**base, "flow_id": f"u{i}", "src_ip": f"10.0.2.{i}",
                     "dst_ip": "10.9.9.9", "label": None,
                     "ts_epoch": 1020.0 + i * 0.1})
    wf = build_windows(pd.DataFrame(rows), window_s=10)
    dst = wf.dst.reset_index()
    vals = list(dst["label"])
    assert "DoS Hulk" in vals and "BENIGN" in vals and None in vals
    # exactly one aggregate row per (window, dst)
    assert len(vals) == 3


def test_unlabeled_rule_path_end_to_end():
    """Rules run over unlabeled pcap-shaped flows without KeyError (regression)."""
    from src.detectors.rules import run_rules

    base = {"ts_epoch": 1000.0, "timestamp": "x", "duration_us": 1000,
            "fwd_pkts": 1, "bwd_pkts": 0, "fwd_bytes": 60, "bwd_bytes": 0,
            "src_port": 1000, "dst_port": 80, "protocol": 6, "proto": "tcp",
            "fin_flags": 0, "syn_flags": 1, "rst_flags": 0, "psh_flags": 0,
            "ack_flags": 0, "urg_flags": 0, "flow_id": "f", "label": None}
    rows = [{**base, "src_ip": "10.5.0.7", "dst_ip": f"10.60.0.{i % 3}",
             "src_port": 35000 + i, "dst_port": 1000 + i,
             "flow_id": f"f{i}", "ts_epoch": 1000.0 + i * 0.05}
            for i in range(60)]
    alerts = run_rules(pd.DataFrame(rows), window_s=10)
    assert any(a.threat_class == "scan" and a.key == "10.5.0.7" for a in alerts)
    scan = next(a for a in alerts if a.threat_class == "scan")
    assert scan.src_ip == "10.5.0.7" and scan.dst_ip is None


# --------------------------------------------------------------- accuracy bench
def test_accuracy_gate_check_reads_real_metrics():
    """gate_check passes on the repo's real results/ml artifacts."""
    bench = _load_script("bench_accuracy")
    doc = bench.gather()
    assert doc["window_ensemble"]["ddos_f1"] >= 0.9
    assert doc["beacon"]["roc_auc_macro"] >= 0.85
    assert doc["dga"]["umbrella_fpr_at_threshold"] <= 0.15
    assert bench.gate_check(doc) is True

