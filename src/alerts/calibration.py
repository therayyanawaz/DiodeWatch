"""Per-channel confidence calibration and split-conformal abstention.

Detector scores are not probabilities. This module applies a monotone isotonic
map fitted on labelled, out-of-sample scores, then drops an alert when its raw
score is atypical of the channel's benign calibration sample (a split-conformal
p-value) or when the calibrated confidence is below the channel's risk floor.

Artifact: `models/calibration.json`, schema 1. Each channel stores one or more
`threat_class` maps plus an optional `"*"` fallback. A map carries the isotonic
knots, the sorted benign raw scores used for the p-value, the conformal alpha,
and the minimum calibrated confidence. Arrays are plain JSON so the live store
and the offline engine can load the same file without sklearn.

Conformal validity needs exchangeability between calibration and live traffic.
The artifact records whether its sample was out-of-sample, a family/scenario
holdout, or resubstitution; the README and evaluation notes report both the
exchangeable random split and a scenario-held-out stress test, because the
latter is where the guarantee stops holding.
"""
from __future__ import annotations

import bisect
import json
import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .schema import Alert, EvidenceItem, severity_for

SCHEMA = 1
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PATH = REPO_ROOT / "models" / "calibration.json"
CALIBRATION_EVIDENCE = "calibration"
CONFORMAL_EVIDENCE = "conformal_p"


def _finite(value: Any, default: float = 0.0) -> float:
    try:
        out = float(value)
    except (TypeError, ValueError):
        return default
    return out if math.isfinite(out) else default


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))


def fit_isotonic(scores: Sequence[float], labels: Sequence[int],
                 max_knots: int = 256) -> list[list[float]]:
    """Monotone least-squares fit (pool-adjacent-violators) as `[x, y]` knots.

    The fit is weighted so repeated raw scores (LightGBM emits many ties) count
    once per row. `max_knots` downsamples the step function for a small JSON
    artifact; the sampled y values stay monotone, so the map cannot reorder
    detections.
    """
    if len(scores) != len(labels):
        raise ValueError("scores and labels must have the same length")
    if len(scores) == 0:
        raise ValueError("cannot fit calibration on an empty sample")
    pairs = sorted((_clamp01(_finite(s)), 1 if int(y) else 0)
                   for s, y in zip(scores, labels))
    xs: list[float] = []
    counts: list[int] = []
    sums: list[int] = []
    for x, y in pairs:
        if xs and x == xs[-1]:
            counts[-1] += 1
            sums[-1] += y
        else:
            xs.append(x)
            counts.append(1)
            sums.append(y)
    # blocks: [row weight, positive weight, start index, end index)
    blocks: list[list[float]] = []
    for i, (w, sy) in enumerate(zip(counts, sums)):
        blocks.append([float(w), float(sy), float(i), float(i + 1)])
        while len(blocks) >= 2:
            prev, cur = blocks[-2], blocks[-1]
            if prev[1] / prev[0] <= cur[1] / cur[0]:
                break
            blocks[-2] = [prev[0] + cur[0], prev[1] + cur[1], prev[2], cur[3]]
            blocks.pop()
    fitted = [0.0] * len(xs)
    for w, sy, start, end in blocks:
        value = sy / w
        for i in range(int(start), int(end)):
            fitted[i] = value
    # Always keep both ends. Intermediate knots are chosen at even index
    # spacing, which is enough because the fit is piecewise constant.
    n = len(xs)
    if n <= max_knots:
        idx = list(range(n))
    else:
        stride = (n - 1) / (max_knots - 1)
        idx = sorted({round(i * stride) for i in range(max_knots)})
        idx[-1] = n - 1
    knots: list[list[float]] = []
    for i in idx:
        y = _clamp01(fitted[i])
        if knots and xs[i] == knots[-1][0]:
            knots[-1][1] = y
        else:
            knots.append([float(xs[i]), float(y)])
    # Extend flat to 0 and 1 so a score outside the fitted domain cannot fall
    # through to a default. This never changes the ordering of live scores.
    if knots[0][0] > 0.0:
        knots.insert(0, [0.0, knots[0][1]])
    if knots[-1][0] < 1.0:
        knots.append([1.0, knots[-1][1]])
    return knots


def predict_curve(curve: Sequence[Sequence[float]], score: float) -> float:
    """Piecewise-linear interpolation over monotone `[x, y]` knots."""
    if not curve:
        return _clamp01(score)
    x = _clamp01(_finite(score))
    xs = [float(p[0]) for p in curve]
    ys = [float(p[1]) for p in curve]
    if x <= xs[0]:
        return _clamp01(ys[0])
    if x >= xs[-1]:
        return _clamp01(ys[-1])
    hi = bisect.bisect_right(xs, x)
    lo = hi - 1
    span = xs[hi] - xs[lo]
    if span <= 0:
        return _clamp01(ys[hi])
    t = (x - xs[lo]) / span
    return _clamp01(ys[lo] + t * (ys[hi] - ys[lo]))


def conformal_pvalue(sorted_scores: Sequence[float], score: float) -> float:
    """Split-conformal p-value `(1 + #{s_i >= s}) / (n + 1)`."""
    n = len(sorted_scores)
    if not n:
        return 1.0
    x = _finite(score)
    idx = bisect.bisect_left(sorted_scores, x)
    return (1.0 + (n - idx)) / (n + 1.0)


@dataclass(frozen=True)
class ClassCalibration:
    """One threat class (or the `"*"` fallback) inside a channel."""
    curve: tuple[tuple[float, float], ...] = ()
    conformal_scores: tuple[float, ...] = ()
    alpha: float = 0.05
    min_confidence: float = 0.0
    method: str = "isotonic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "alpha": round(self.alpha, 6),
            "min_confidence": round(self.min_confidence, 6),
            "curve": [[round(float(x), 10), round(float(y), 10)]
                      for x, y in self.curve],
            "conformal_scores": [round(float(s), 10)
                                 for s in self.conformal_scores],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClassCalibration:
        method = str(data.get("method", "isotonic"))
        if method not in {"isotonic", "identity"}:
            raise ValueError(f"unknown calibration method: {method}")
        curve = tuple((_clamp01(_finite(p[0])), _clamp01(_finite(p[1])))
                      for p in data.get("curve") or [])
        if method == "isotonic" and not curve:
            raise ValueError("isotonic calibration needs at least one knot")
        scores = tuple(sorted(_finite(s) for s in
                              data.get("conformal_scores") or []))
        alpha = _clamp01(_finite(data.get("alpha", 0.05), 0.05))
        floor = _clamp01(_finite(data.get("min_confidence", 0.0)))
        return cls(curve=curve, conformal_scores=scores, alpha=alpha,
                   min_confidence=floor, method=method)


@dataclass(frozen=True)
class ChannelCalibration:
    detector: str
    classes: dict[str, ClassCalibration] = field(default_factory=dict)

    def select(self, threat_class: str) -> ClassCalibration | None:
        return self.classes.get(threat_class) or self.classes.get("*")

    def to_dict(self) -> dict[str, Any]:
        return {"classes": {k: v.to_dict() for k, v in self.classes.items()}}

    @classmethod
    def from_dict(cls, detector: str, data: dict[str, Any],
                  ) -> ChannelCalibration:
        classes = data.get("classes") or {}
        if not classes:
            raise ValueError(f"{detector}: no class maps")
        return cls(detector=detector,
                   classes={str(k): ClassCalibration.from_dict(v)
                            for k, v in classes.items()})


@dataclass
class ApplyReport:
    accepted: list[Alert] = field(default_factory=list)
    calibrated: int = 0
    abstained: int = 0


@dataclass(frozen=True)
class CalibrationPolicy:
    """A loaded artifact; applying it mutates accepted alerts in place."""
    channels: dict[str, ChannelCalibration]
    generated_utc: str = ""
    source: str = ""
    schema: int = SCHEMA

    @property
    def status(self) -> dict[str, Any]:
        return {
            "available": True,
            "schema": self.schema,
            "generated_utc": self.generated_utc,
            "source": self.source,
            "channels": sorted(self.channels),
        }

    def apply(self, alerts: Iterable[Alert]) -> ApplyReport:
        """Calibrate and filter a batch. Unlisted channels pass through."""
        report = ApplyReport()
        for alert in alerts:
            channel = self.channels.get(alert.detector or "")
            spec = channel.select(alert.threat_class) if channel else None
            if spec is None or self._already_calibrated(alert):
                report.accepted.append(alert)
                continue
            raw = _clamp01(_finite(alert.confidence))
            calibrated = (raw if spec.method == "identity"
                          else predict_curve(spec.curve, raw))
            p_value = (conformal_pvalue(spec.conformal_scores, raw)
                       if spec.conformal_scores else None)
            report.calibrated += 1
            if (p_value is not None and p_value > spec.alpha) or \
                    calibrated < spec.min_confidence:
                report.abstained += 1
                continue
            alert.confidence = round(float(calibrated), 4)
            alert.severity = severity_for(alert.threat_class,
                                          alert.confidence)
            alert.evidence.append(EvidenceItem(
                condition=CALIBRATION_EVIDENCE,
                operator=">=",
                observed=round(float(calibrated), 4),
                threshold=round(float(spec.min_confidence), 4),
                unit="probability",
                description=(f"isotonic confidence {calibrated:.3f} from raw "
                             f"score {raw:.4f}"),
            ))
            if p_value is not None:
                alert.evidence.append(EvidenceItem(
                    condition=CONFORMAL_EVIDENCE,
                    operator="<=",
                    observed=round(float(p_value), 4),
                    threshold=round(float(spec.alpha), 4),
                    unit="p-value",
                    description=(f"split-conformal p over "
                                 f"{len(spec.conformal_scores)} benign "
                                 f"scores"),
                ))
            report.accepted.append(alert)
        return report

    @staticmethod
    def _already_calibrated(alert: Alert) -> bool:
        return any(e.condition in {CALIBRATION_EVIDENCE, CONFORMAL_EVIDENCE}
                   for e in alert.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "generated_utc": self.generated_utc,
            "source": self.source,
            "channels": {k: v.to_dict() for k, v in self.channels.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str = "") -> CalibrationPolicy:
        schema = int(data.get("schema", 0))
        if schema != SCHEMA:
            raise ValueError(f"unsupported calibration schema: {schema}")
        raw_channels = data.get("channels") or {}
        channels = {str(k): ChannelCalibration.from_dict(str(k), v)
                    for k, v in raw_channels.items()}
        if not channels:
            raise ValueError("calibration artifact has no channels")
        return cls(channels=channels,
                   generated_utc=str(data.get("generated_utc", "")),
                   source=source or str(data.get("source", "")), schema=schema)

    @classmethod
    def load(cls, path: str | Path = DEFAULT_PATH) -> CalibrationPolicy:
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls.from_dict(data, source=str(p))
