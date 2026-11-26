"""Max-scale driver tests (synthetic frames, no corpus downloads).

Covers the properties the full-corpus pass depends on: official CIC headers
mapping to real counters, microsecond durations surviving normalization, the
parquet microsecond timestamp trap, unmapped truth staying out of every metric,
and the streamed driver reproducing bench_transfer.evaluate_corpus exactly.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bt = _load("bench_transfer", REPO / "scripts" / "benchmarks" / "bench_transfer.py")
bc = _load("bench_corpora", REPO / "scripts" / "benchmarks" / "bench_corpora.py")

from src.detectors.ml.labels import LABEL_MAPS


# --------------------------------------------------- corpus column mapping
def test_official_cic_headers_map_to_real_counters():
    """The 85-column official schema must not fall back to fabricated defaults."""
    df = pd.DataFrame({
        " Total Fwd Packets": [11],
        " Total Backward Packets": [7],
        " Total Length of Fwd Packets": [172],
        " Total Length of Bwd Packets": [9_000],
        " SYN Flag Count": [1],
        " ACK Flag Count": [1],
        " Flow Duration": [1_500_000],       # microseconds
        " Label": ["BENIGN"],
    })
    out = bt.normalize_columns(df)
    assert out.loc[0, "fwd_pkts"] == 11
    assert out.loc[0, "bwd_pkts"] == 7
    assert out.loc[0, "fwd_bytes"] == 172
    assert out.loc[0, "bwd_bytes"] == 9_000
    assert out.loc[0, "syn_flags"] == 1
    # µs is preserved under the µs name, never relabelled as seconds
    assert out.loc[0, "flow_duration"] == 1_500_000
    assert "duration_s" not in out.columns


def test_parquet_microsecond_timestamps_are_epoch_seconds():
    """datetime64[us] cast to int64 is microseconds, not nanoseconds."""
    df = pd.DataFrame({
        "timestamp": pd.Series(["2017-07-07 09:00:00"], dtype="datetime64[us]"),
    })
    ts = bc._epoch_seconds(df)
    assert ts.iloc[0] == pytest.approx(1_499_418_000.0)


def test_missing_clock_becomes_flagged_synthetic_clock():
    flows, synthetic = bc.canonical_frame(
        pd.DataFrame({"src_ip": ["10.0.0.1"], "dst_ip": ["10.0.0.2"]}), "x", 0)
    assert synthetic is True
    assert flows.loc[0, "ts_epoch"] == pytest.approx(1_499_268_000.0)
    parsed = pd.to_datetime(flows.loc[0, "timestamp"], utc=True)
    assert parsed.timestamp() == pytest.approx(1_499_268_000.0)


# --------------------------------------------------- truth handling
def test_unsw_truth_uses_attack_cat_and_keeps_unmapped_off_benign():
    df = pd.DataFrame({"attack_cat": ["Normal", "DoS", "Reconnaissance", "Worms"],
                       "label": [0, 1, 1, 1]})
    y, unmapped = bc.label_truth(df, "unsw-nb15", LABEL_MAPS["unsw-nb15"])
    assert list(y) == ["benign", "ddos", "scan", "unmapped"]
    assert unmapped == {}


def test_mapped_unmapped_vs_absent_label_are_different_events():
    """A map value 'unmapped' means known-but-unscorable; an absent key means
    the corpus has a label the register has never seen. Both are excluded from
    metrics, but only the absent label is reported as a coverage gap."""
    df = pd.DataFrame({"attack_cat": ["Normal", "Worms", "Mystery"]})
    y, unmapped = bc.label_truth(df, "unsw-nb15", LABEL_MAPS["unsw-nb15"])
    assert list(y) == ["benign", "unmapped", "unmapped"]
    assert unmapped == {"Mystery": 1}


# --------------------------------------------------- metrics math
def test_benign_fpr_counts_benign_flows_called_attack():
    c = bc.Counts()
    y = np.array(["benign"] * 10 + ["ddos"] * 10, dtype=object)
    p = np.array(["ddos"] * 3 + ["benign"] * 7 + ["ddos"] * 10, dtype=object)
    c.add(y, p)
    m = c.metrics()
    assert m["fpr"]["false_positives"] == 3
    assert m["fpr"]["fpr"] == pytest.approx(0.3)
    assert m["fpr"]["passes_gate"] is False
    assert m["per_class"]["ddos"]["recall"] == 1.0


def test_counts_round_trip_through_json():
    c = bc.Counts()
    c.add(np.array(["ddos", "benign"], dtype=object),
          np.array(["ddos", "ddos"], dtype=object))
    back = bc.counts_from_dict(c.to_dict())
    assert back.metrics() == c.metrics()


# --------------------------------------------------- driver == transfer bench
def _job(path: Path, family: str = "cic-ddos2019-selftest") -> dict:
    return {"name": path.stem, "family": family, "map_key": "cic-ddos2019-selftest",
            "path": str(path), "rules": True, "ml": False, "chunk": 100_000,
            "ml_rows": 200_000, "window_s": 10, "model_dir": str(REPO / "models"),
            "total_rows": None, "rules_reason": None, "ml_reason": None}


def test_streamed_rules_match_transfer_bench(tmp_path):
    df = bt.synth_ddos2019(n_benign=300, n_attack=400, seed=11)
    path = tmp_path / "selftest.csv"
    df.to_csv(path, index=False)
    ref = bt.evaluate_corpus("cic-ddos2019-selftest", df, model_dir=REPO / "models",
                             window_s=10, run_ml=False)
    cell = bc.evaluate_file(_job(path))
    assert cell["n_flows"] == len(df)
    assert cell["rules"]["per_class"] == ref["rules"]["per_class"]
    assert cell["rules"]["fpr"] == ref["rules"]["fpr"]
    assert cell["rules"]["alert_metrics"] == ref["rules"]["alert_metrics"]
    assert cell["alert_counts"]["alerts"] == \
        ref["rules"]["alert_metrics"]["alerts"]
    assert cell["unmapped_labels"] == ref["unmapped_labels"]


def test_attribution_matches_bench_rule_predictions():
    """Attribution is window-scoped and identical to the transfer bench."""
    n = 600
    df = pd.DataFrame({
        "flow_id": [f"f{i}" for i in range(n)],
        "src_ip": [f"10.0.{i % 7}.{(i % 200) + 1}" for i in range(n)],
        "dst_ip": ["203.0.113.9"] * n,          # one victim: dst rule must fire
        "src_port": np.arange(1024, 1024 + n, dtype="float64"),
        "dst_port": [80.0] * n,
        "protocol": [6.0] * n,
        "timestamp": ["2026-01-01 00:00:00"] * n,
        "duration_us": [1_000.0] * n,
        "fwd_pkts": [1.0] * n, "bwd_pkts": [0.0] * n,
        "fwd_bytes": [60.0] * n, "bwd_bytes": [0.0] * n,
        "syn_flags": [1.0] * n, "fin_flags": [0.0] * n, "rst_flags": [0.0] * n,
        "psh_flags": [0.0] * n, "ack_flags": [0.0] * n, "urg_flags": [0.0] * n,
    })
    flows, _ = bc.canonical_frame(df, "selftest", 0)
    ref, ref_alerts = bt.rule_predictions(flows, ["benign"] * len(flows), 10)
    mine, alerts = bc.rule_predictions_fast(flows, 10)
    assert [a.key for a in alerts] == [a["key"] for a in ref_alerts]
    assert list(mine) == list(ref)
    assert any(p != "benign" for p in mine)

# --------------------------------------------------- structural padding rows
def test_blank_mask_flags_only_all_null_rows():
    df = pd.DataFrame({
        "label": pd.Series(["BENIGN", None, "DDoS", None], dtype=str),
        "timestamp": pd.Series(["2026-01-01 00:00:00", None, "2026-01-01 00:00:01", None], dtype=str),
        "src_ip": pd.Series(["10.0.0.1", None, "10.0.0.2", None], dtype=str),
    })
    assert list(bc.blank_mask(df)) == [False, True, False, True]
    # one populated column keeps the row: unlabelled traffic is reported as
    # unmapped truth, never silently dropped as padding
    partial = pd.DataFrame({"label": [None], "timestamp": ["2026-01-01"],
                            "src_ip": ["10.0.0.9"]})
    assert list(bc.blank_mask(partial)) == [False]


def test_padding_rows_are_dropped_from_every_denominator(tmp_path):
    df = bt.synth_ddos2019(n_benign=20, n_attack=20, seed=13)
    path = tmp_path / "padded.csv"
    path.write_text(df.to_csv(index=False) + "\n,,,\n,,,\n")
    cell = bc.evaluate_file(_job(path))
    assert cell["n_flows"] == 40
    assert cell["blank_rows"] == 2
    assert cell["unmapped_labels"] == {}
    assert cell["rules"]["n"] == 40
