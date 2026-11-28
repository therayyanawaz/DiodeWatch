"""The shipped drift policy must stay consistent with what was measured."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from src.alerts.drift import DriftPolicy

REPO = Path(__file__).resolve().parents[1]
ARTIFACT = REPO / "docs" / "evaluation" / "models" / "drift.json"
SUMMARY = REPO / "docs" / "evaluation" / "runs" / "drift.json"


def _checker():
    path = REPO / "scripts" / "checks" / "check_drift.py"
    spec = importlib.util.spec_from_file_location("check_drift", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_artifact_loads_with_measured_channel_thresholds():
    policy = DriftPolicy.load(ARTIFACT)
    assert policy.threshold == 3.0
    assert policy.channels["ml.flowctx"].threshold == 3.0
    assert policy.channels["ml.beacon"].threshold == 1.0
    assert policy.channels["ml.dga"].threshold == 0.5
    tls = policy.channels["ml.tls"]
    assert tls.method == "identity" and tls.features == {}
    assert set(policy.channels["ml.flowctx"].features) == {
        "fwd_pkts", "fwd_bytes", "bwd_pkts", "bwd_bytes", "flow_pkts_per_s",
        "flow_bytes_per_s", "wdst_flows_per_sec", "wsrc_n_dports",
        "wdst_syn_share", "duration_s"}


def test_pinned_artifact_matches_local_model_when_present():
    local = REPO / "models" / "drift.json"
    if local.exists():
        assert local.read_bytes() == ARTIFACT.read_bytes()


def test_checker_accepts_the_shipped_pair():
    module = _checker()
    assert module.check(ARTIFACT, SUMMARY) == []


def test_checker_rejects_a_holdout_that_did_not_alarm(tmp_path):
    module = _checker()
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    summary["beacon"]["eval"]["52"]["alarm"] = False
    bad = tmp_path / "drift.json"
    bad.write_text(json.dumps(summary), encoding="utf-8")
    problems = module.check(ARTIFACT, bad)
    assert any("holdout" in p for p in problems)


def test_checker_rejects_tampered_reference_bins(tmp_path):
    module = _checker()
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    artifact["channels"]["ml.dga"]["features"]["sld_len"]["expected"][0] = 0.9
    bad = tmp_path / "drift.json"
    bad.write_text(json.dumps(artifact), encoding="utf-8")
    problems = module.check(bad, SUMMARY)
    assert any("proportions do not sum" in p for p in problems)


def test_summary_quotes_the_artifact_size():
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    assert summary["artifact_bytes"] == ARTIFACT.stat().st_size
    assert summary["threshold"] == 3.0
