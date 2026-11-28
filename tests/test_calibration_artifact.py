"""The shipped calibration artifact and its fail-capable checker."""
from __future__ import annotations

import json

from scripts.checks.check_calibration import ARTIFACT, SUMMARY, check


def test_shipped_artifact_is_consistent():
    assert check(ARTIFACT, SUMMARY) == []


def test_checker_catches_a_non_monotone_curve_and_a_floor_drift(tmp_path):
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    curve = artifact["channels"]["ml.dga"]["classes"]["*"]["curve"]
    curve[0][1] = 1.0
    curve[-1][1] = 0.0
    bad_curve = tmp_path / "bad-curve.json"
    bad_curve.write_text(json.dumps(artifact), encoding="utf-8")
    problems = check(bad_curve, SUMMARY)
    assert any("monotonicity" in p for p in problems), problems

    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    good = tmp_path / "good.json"
    good.write_text(json.dumps(artifact), encoding="utf-8")
    summary["beacon"]["min_confidence"] += 0.1
    bad_floor = tmp_path / "bad-floor.json"
    bad_floor.write_text(json.dumps(summary), encoding="utf-8")
    problems = check(good, bad_floor)
    assert any("floor mismatch for ml.beacon" in p for p in problems), problems
