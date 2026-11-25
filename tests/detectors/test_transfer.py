"""Transfer-evaluation harness tests (synthetic corpus, no downloads).

Covers the P0-1 bench_transfer.py contract: deterministic selftest corpus in
the CIC-DDoS2019 table shape, explicit label harmonization (unmapped labels
reported, never merged), metrics math, PSI drift, pre-committed gates, and
the honest fail-closed ML cell.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pandas as pd
import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

_SPEC = importlib.util.spec_from_file_location(
    "bench_transfer", REPO / "scripts" / "benchmarks" / "bench_transfer.py")
bt = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(bt)


# ------------------------------------------------------------ selftest corpus
def test_selftest_corpus_shape_and_balance():
    df = bt.synth_ddos2019(n_benign=300, n_attack=400, seed=7)
    assert list(df.columns)[:5] == ["src_ip", "dst_ip", "src_port", "dst_port",
                                    "flow_duration"]
    assert (df["label"] == "BENIGN").sum() == 300
    assert (df["label"] == "DDoS").sum() == 400
    # deterministic
    df2 = bt.synth_ddos2019(n_benign=300, n_attack=400, seed=7)
    pd.testing.assert_frame_equal(df, df2)
    # µs convention: benign durations far above attack durations
    assert df[df.label == "BENIGN"].flow_duration.mean() > \
        df[df.label == "DDoS"].flow_duration.mean() * 10


# ------------------------------------------------------------ label handling
def test_label_map_prefix_resolution():
    assert bt.resolve_label_map("cic-ddos2019-selftest", None)["DDoS"] == "ddos"
    assert bt.resolve_label_map("cic-ddos2019", None)["BENIGN"] == "benign"
    assert bt.resolve_label_map("anything", {"X": "ddos"}) == {"X": "ddos"}
    assert bt.resolve_label_map("unknown-corpus", None) == {}


def test_unmapped_labels_reported_not_merged():
    df = bt.synth_ddos2019(n_benign=50, n_attack=50)
    df.loc[df.index[:5], "label"] = "SYN-Reflection-X"   # absent from the map
    cell = bt.evaluate_corpus("cic-ddos2019-selftest", df, model_dir=REPO / "models",
                              window_s=10, run_ml=False)
    assert cell["unmapped_labels"].get("SYN-Reflection-X") == 5


# ------------------------------------------------------------ metrics math
def test_confusion_metrics_perfect_and_mixed():
    m = bt.confusion_metrics(["ddos"] * 4 + ["benign"] * 6,
                             ["ddos"] * 4 + ["benign"] * 6)
    assert m["per_class"]["ddos"]["f1"] == 1.0
    assert m["macro_f1"] == 1.0
    mixed = bt.confusion_metrics(["ddos"] * 5 + ["benign"] * 5,
                                 ["ddos"] * 3 + ["benign"] * 7)
    assert mixed["per_class"]["ddos"]["recall"] == 0.6
    assert mixed["per_class"]["ddos"]["precision"] == 1.0
    assert mixed["per_class"]["benign"]["recall"] == 1.0
    assert mixed["per_class"]["benign"]["precision"] == pytest.approx(5 / 7)


def test_benign_fpr_gate():
    f = bt.benign_fpr(["benign"] * 100, ["benign"] * 99 + ["ddos"])
    assert f["false_positives"] == 1 and f["fpr"] == 0.01
    assert f["passes_gate"] is True
    bad = bt.benign_fpr(["benign"] * 100, ["ddos"] * 5 + ["benign"] * 95)
    assert bad["passes_gate"] is False


def test_psi_identical_and_shifted():
    import numpy as np
    rng = np.random.default_rng(3)
    a = rng.normal(0, 1, 20_000)
    assert bt.psi(a, rng.normal(0, 1, 20_000)) < 0.1       # same dist
    assert bt.psi(a, rng.normal(6, 1, 20_000)) > 3.0       # big shift
    assert bt.psi(a, a) == 0.0


# ------------------------------------------------------------ end-to-end cell
def test_evaluate_corpus_rules_cell_and_gates():
    df = bt.synth_ddos2019()
    cell = bt.evaluate_corpus("cic-ddos2019-selftest", df,
                              model_dir=REPO / "models", window_s=10,
                              run_ml=False)
    assert cell["n_flows"] == 2700
    ddos = cell["rules"]["per_class"]["ddos"]
    assert ddos["f1"] >= 0.95
    assert cell["rules"]["fpr"]["fpr"] == 0.0
    checks = bt.gate_check({"cic-ddos2019-selftest": cell})
    assert checks and all(c["passes"] for c in checks)


def test_ml_cell_fail_closed_or_honest():
    """With artifacts present the ML cell runs the real feature engine; the
    feature families the registry declares but the engine does not compute
    must be reported, never faked. Without artifacts the cell carries an
    explicit error, never silent junk scores."""
    df = bt.synth_ddos2019(n_benign=100, n_attack=100)
    cell = bt.evaluate_corpus("cic-ddos2019-selftest", df,
                              model_dir=REPO / "models", window_s=10,
                              run_ml=True)
    ml = cell["ml"]
    assert "features_not_computed" in cell
    assert "active_idle_*" in cell["features_not_computed"]
    if ml.get("error") is None:
        assert ml["channel"] and ml["per_class"]
    else:
        # no models on this clone: the cell says so, it does not score junk
        assert isinstance(ml["error"], str) and ml["error"]
        assert not ml.get("per_class")


# ------------------------------------------------------------ gates + summary
def test_gate_check_flags_low_ddos_f1():
    cell = {"rules": {"per_class": {"ddos": {"f1": 0.70}},
                      "fpr": {"fpr": 0.5, "passes_gate": False}}}
    checks = bt.gate_check({"x": cell})
    assert any(not c["passes"] for c in checks)


def test_render_summary_contains_cells_and_gates(tmp_path):
    df = bt.synth_ddos2019(n_benign=80, n_attack=80)
    cell = bt.evaluate_corpus("cic-ddos2019-selftest", df,
                              model_dir=REPO / "models", window_s=10,
                              run_ml=False)
    checks = bt.gate_check({"cic-ddos2019-selftest": cell})
    text = bt.render_summary({"cic-ddos2019-selftest": cell}, checks)
    assert "## cic-ddos2019-selftest" in text
    assert "Pre-committed gates" in text
    assert "[PASS]" in text


# ------------------------------------------------------------ CLI contract
def test_cli_selftest_end_to_end(tmp_path, capsys):
    out = tmp_path / "transfer"
    rc = bt.main(["--selftest", "--no-ml", "--out", str(out)])
    assert rc == 0
    assert (out / "summary.md").exists()
    assert (out / "transfer_results.json").exists()
    assert (out / "label_maps.json").exists()
    doc = json.loads((out / "transfer_results.json").read_text(encoding="utf-8"))
    assert "cic-ddos2019-selftest" in doc["results"]
    assert doc["gates"]["rule_ddos_f1_min"] == 0.95


def test_cli_missing_target_file_exits_2():
    assert bt.main(["--targets", "x=no_such_file.csv"]) == 2
