"""Calibration policy: isotonic map, conformal p-value, live-store abstention."""
from __future__ import annotations

import json

from src.alerts.calibration import (
    CalibrationPolicy,
    ChannelCalibration,
    ClassCalibration,
    conformal_pvalue,
    fit_isotonic,
    predict_curve,
)
from src.alerts.live_store import LiveEvidenceStore
from tests.alerts.test_alerts import make_alert


def _policy(classes, detector="ml.test"):
    return CalibrationPolicy(
        channels={detector: ChannelCalibration(detector, classes)},
        generated_utc="2026-09-04T00:00:00Z",
    )


def test_isotonic_is_monotone_and_separates_the_two_modes():
    curve = fit_isotonic([0.1] * 50 + [0.9] * 50, [0] * 50 + [1] * 50)
    ys = [y for _, y in curve]
    assert ys == sorted(ys)
    assert predict_curve(curve, 0.1) < 0.1
    assert predict_curve(curve, 0.9) > 0.9


def test_isotonic_never_reorders_scores():
    curve = fit_isotonic([0.2, 0.2, 0.8, 0.8, 0.8], [0, 1, 0, 1, 1])
    xs = [0.25, 0.5, 0.75, 0.99]
    out = [predict_curve(curve, x) for x in xs]
    assert out == sorted(out)


def test_conformal_pvalue_matches_the_finite_sample_formula():
    scores = [0.1, 0.2, 0.3, 0.4]
    assert conformal_pvalue(scores, 0.0) == 1.0
    assert conformal_pvalue(scores, 0.2) == 4 / 5
    assert conformal_pvalue(scores, 0.5) == 1 / 5


def test_policy_calibrates_and_appends_audit_evidence():
    spec = ClassCalibration(curve=((0.0, 0.0), (1.0, 0.8)),
                            min_confidence=0.5)
    alert = make_alert(0, "bot", conf=0.95)
    alert.detector = "ml.test"
    report = _policy({"bot": spec}).apply([alert])
    assert report.calibrated == 1 and report.abstained == 0
    assert report.accepted == [alert]
    assert alert.confidence == 0.76
    conditions = [e.condition for e in alert.evidence]
    assert "calibration" in conditions


def test_policy_abstains_below_the_risk_floor():
    spec = ClassCalibration(curve=((0.0, 0.0), (1.0, 0.8)),
                            min_confidence=0.5)
    alert = make_alert(0, "bot", conf=0.6)
    alert.detector = "ml.test"
    report = _policy({"bot": spec}).apply([alert])
    assert report.calibrated == 1 and report.abstained == 1
    assert report.accepted == []


def test_conformal_gate_drops_benign_typical_scores():
    benign = tuple(i / 100 for i in range(100))
    spec = ClassCalibration(curve=((0.0, 0.0), (1.0, 1.0)),
                            conformal_scores=benign, alpha=0.05,
                            min_confidence=0.0)
    low = make_alert(0, "bot", conf=0.2)
    low.detector = "ml.test"
    high = make_alert(1, "bot", conf=0.99)
    high.detector = "ml.test"
    report = _policy({"bot": spec}).apply([low, high])
    assert report.abstained == 1
    assert report.accepted == [high]
    assert any(e.condition == "conformal_p" for e in high.evidence)


def test_class_specific_map_beats_the_star_fallback():
    fallback = ClassCalibration(method="identity", min_confidence=0.0)
    ddos = ClassCalibration(curve=((0.0, 0.0), (1.0, 0.2)),
                            min_confidence=0.0)
    alert = make_alert(0, "ddos", conf=0.9)
    alert.detector = "ml.test"
    report = _policy({"*": fallback, "ddos": ddos}).apply([alert])
    assert report.accepted[0].confidence == 0.18


def test_already_calibrated_alert_is_not_rewritten():
    spec = ClassCalibration(curve=((0.0, 0.0), (1.0, 0.8)),
                            min_confidence=0.5)
    policy = _policy({"bot": spec})
    alert = make_alert(0, "bot", conf=0.95)
    alert.detector = "ml.test"
    policy.apply([alert])
    before = alert.confidence
    second = policy.apply([alert])
    assert second.calibrated == 0 and second.abstained == 0
    assert alert.confidence == before
    assert sum(e.condition == "calibration" for e in alert.evidence) == 1


def test_artifact_round_trips_through_json(tmp_path):
    spec = ClassCalibration(curve=((0.0, 0.1), (1.0, 0.9)),
                            conformal_scores=(0.2, 0.4), alpha=0.01,
                            min_confidence=0.6)
    policy = _policy({"bot": spec})
    path = tmp_path / "calibration.json"
    path.write_text(json.dumps(policy.to_dict()), encoding="utf-8")
    loaded = CalibrationPolicy.load(path)
    assert loaded.status["channels"] == ["ml.test"]
    assert loaded.channels["ml.test"].classes["bot"].alpha == 0.01


def test_live_store_counts_abstentions_and_reports_the_policy(tmp_path):
    spec = ClassCalibration(curve=((0.0, 0.0), (1.0, 1.0)),
                            min_confidence=0.5)
    policy = _policy({"bot": spec})
    store = LiveEvidenceStore(path=tmp_path / "live.db", calibration=policy)
    keep = make_alert(0, "bot", conf=0.9)
    keep.detector = "ml.test"
    drop = make_alert(1, "bot", conf=0.2)
    drop.detector = "ml.test"
    shown = store.absorb_alerts([keep, drop])
    assert shown == [keep]
    assert store.abstained == 1
    assert store.evidence()["abstained"] == 1
    assert store.evidence()["calibration"]["available"] is True
    store.close()


def test_live_store_rejects_a_malformed_score_before_calibration(tmp_path):
    """The map must not clamp an invalid raw confidence into a valid alert."""
    spec = ClassCalibration(curve=((0.0, 0.0), (1.0, 1.0)),
                            min_confidence=0.0)
    store = LiveEvidenceStore(path=tmp_path / "live.db",
                              calibration=_policy({"bot": spec}))
    bad = make_alert(0, "bot", conf=1.5)
    bad.detector = "ml.test"
    shown = store.absorb_alerts([bad])
    assert shown == []
    assert store.rejected == 1 and store.abstained == 0
    store.close()
