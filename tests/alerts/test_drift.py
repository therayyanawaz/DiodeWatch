"""Drift baselines, PSI math, and the sticky channel latch."""
from __future__ import annotations

import json

import numpy as np
import pytest

from src.alerts.drift import (
    ChannelBaseline,
    DriftMonitor,
    DriftPolicy,
    FeatureBaseline,
)


def _policy(values: np.ndarray, threshold: float = 0.25,
            min_samples: int = 100) -> DriftPolicy:
    return DriftPolicy(
        channels={"ml.test": ChannelBaseline(
            channel="ml.test",
            features={"x": FeatureBaseline.from_values(values, bins=10)},
        )},
        threshold=threshold, min_samples=min_samples,
    )


def test_psi_is_low_on_a_resample_and_high_on_a_shift():
    rng = np.random.default_rng(7)
    ref = rng.normal(0, 1, 10_000)
    policy = _policy(ref)
    same = policy.evaluate("ml.test", {"x": rng.normal(0, 1, 2_000)})
    shifted = policy.evaluate("ml.test", {"x": rng.normal(6, 1, 2_000)})
    assert same.evaluated and not same.alarm
    assert same.max_psi is not None and same.max_psi < 0.05
    assert shifted.evaluated and shifted.alarm
    assert shifted.max_psi > 1.0


def test_values_outside_the_reference_land_in_the_outer_bins():
    policy = _policy(np.linspace(0, 1, 1_000))
    reading = policy.evaluate("ml.test", {"x": np.full(500, 100.0)})
    assert reading.evaluated and reading.alarm
    assert np.isfinite(reading.max_psi)


def test_a_constant_reference_does_not_divide_by_zero():
    base = FeatureBaseline.from_values(np.ones(1_000))
    assert base.psi(np.ones(500)) == pytest.approx(0.0, abs=1e-12)
    assert base.psi(np.zeros(500)) > 1.0
    assert base.psi(np.full(500, 100.0)) > 1.0


def test_too_few_rows_is_not_an_alarm():
    policy = _policy(np.random.default_rng(1).normal(0, 1, 1_000),
                     min_samples=500)
    reading = policy.evaluate("ml.test", {"x": np.full(10, 50.0)})
    assert not reading.evaluated and not reading.alarm
    assert "need 500" in reading.reason


def test_missing_feature_is_reported_not_silently_ignored():
    policy = _policy(np.random.default_rng(2).normal(0, 1, 1_000))
    reading = policy.evaluate("ml.test", {"other": np.ones(1_000)})
    assert not reading.evaluated
    assert "no monitored feature" in reading.reason


def test_an_unknown_channel_method_is_rejected_at_load():
    with pytest.raises(ValueError, match="unknown drift method"):
        ChannelBaseline.from_dict("ml.test", {"method": "magic", "features": {}})


def test_the_latch_sticks_and_clears_only_on_reset():
    rng = np.random.default_rng(3)
    policy = _policy(rng.normal(0, 1, 5_000))
    monitor = DriftMonitor(policy)
    monitor.observe("ml.test", {"x": rng.normal(4, 1, 1_000)})
    assert monitor.alarmed("ml.test")
    monitor.observe("ml.test", {"x": rng.normal(0, 1, 1_000)})
    assert monitor.alarmed("ml.test")   # a good window does not hide the alarm
    monitor.reset("ml.test")
    assert not monitor.alarmed("ml.test")


def test_a_channel_can_pin_a_stricter_threshold():
    values = np.random.default_rng(8).normal(0, 1, 5_000)
    policy = _policy(values, threshold=3.0)
    channel = policy.channels["ml.test"]
    strict = DriftPolicy(
        channels={"ml.test": ChannelBaseline(
            channel="ml.test", features=channel.features, threshold=0.2)},
        threshold=3.0, min_samples=100)
    reading = strict.evaluate("ml.test", {"x": values + 0.5})
    assert reading.threshold == 0.2
    assert reading.alarm and reading.max_psi < 3.0


def test_identity_channel_never_evaluates():
    policy = DriftPolicy(channels={"ml.tls": ChannelBaseline(
        channel="ml.tls", features={}, method="identity")})
    reading = policy.evaluate("ml.tls", {"x": np.ones(1_000)})
    assert not reading.evaluated and not reading.alarm
    assert "identity" in reading.reason


def test_record_frames_are_accepted():
    values = np.random.default_rng(9).normal(0, 1, 1_000)
    policy = _policy(values)
    records = [{"x": float(v)} for v in np.full(500, 8.0)]
    reading = policy.evaluate("ml.test", records)
    assert reading.n == 500 and reading.evaluated and reading.alarm


def test_json_round_trip(tmp_path):
    policy = _policy(np.random.default_rng(4).normal(0, 1, 2_000))
    p = policy.save(tmp_path / "drift.json")
    assert b"\r\n" not in p.read_bytes()   # pinned bytes are cross-platform
    back = DriftPolicy.load(p)
    assert back.threshold == policy.threshold
    assert back.channels["ml.test"].features["x"].edges == pytest.approx( \
        policy.channels["ml.test"].features["x"].edges)
    a = policy.evaluate("ml.test", {"x": np.linspace(-1, 1, 500)})
    b = back.evaluate("ml.test", {"x": np.linspace(-1, 1, 500)})
    assert a.max_psi == pytest.approx(b.max_psi)


def test_malformed_artifacts_are_refused(tmp_path):
    policy = _policy(np.random.default_rng(5).normal(0, 1, 1_000))
    data = policy.to_dict()
    data["schema"] = 99
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="schema"):
        DriftPolicy.load(p)
    data = policy.to_dict()
    data["min_samples"] = 1
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="min_samples"):
        DriftPolicy.load(p)
