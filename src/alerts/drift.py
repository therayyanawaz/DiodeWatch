"""Feature-drift alarm that can make a model channel abstain.

The transfer evaluation publishes PSI as an explanation after a channel has
already failed. This module gives that number a consequence: a pinned
reference distribution per channel and monitored feature, a PSI evaluation
for a live frame, and a latch that makes callers withhold every alert from a
channel whose input no longer looks like the population it was validated on.

Design choices, stated so they can be challenged:

* PSI is computed against **training-side reference bins**, never against the
  live batch itself; quantile bins come from the reference and are stored, so
  two runs with the same artifact agree exactly.
* The reference is the model training distribution, attacks included. Drift
  therefore means "this is not the traffic mix the model learned", not "this
  batch contains attacks".
* A channel latches on the first evaluation whose maximum feature PSI exceeds
  the pinned threshold, with at least `min_samples` finite rows. There is no
  auto-clear: after drift a human decides when the model is trustworthy again,
  because an alarm that clears itself is a chart again.
* `ml.tls` is identity by construction (watchlist lookup), so it has no
  probabilistic baseline and never gates.

Reference bins are built by `FeatureBaseline.from_values`; the artifact stores
only edges and proportions, not raw traffic.
"""
from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PATH = REPO_ROOT / "models" / "drift.json"
SCHEMA = 1
DEFAULT_THRESHOLD = 0.25
DEFAULT_MIN_SAMPLES = 500
DEFAULT_BINS = 10
EPS = 1e-6


def _finite(values: Any) -> np.ndarray:
    """Finite float copy of a column, ordered; non-numeric rows are dropped."""
    try:
        arr = np.asarray(values, dtype=float)
    except (TypeError, ValueError):
        return np.empty(0, dtype=float)
    arr = arr.ravel()
    return arr[np.isfinite(arr)]


def _column(frame: Any, name: str) -> Any:
    """One column from a DataFrame, a mapping, a record list, or a sequence."""
    if hasattr(frame, "columns"):
        if name not in frame.columns:
            raise KeyError(name)
        return frame[name]
    if isinstance(frame, Mapping):
        if name not in frame:
            raise KeyError(name)
        return frame[name]
    if (isinstance(frame, (list, tuple)) and frame
            and all(isinstance(row, Mapping) for row in frame)):
        return [row.get(name) for row in frame]
    if name in ("", "value"):
        return frame
    raise KeyError(name)


def _frame_len(frame: Any) -> int:
    if hasattr(frame, "columns"):
        return len(frame)
    if isinstance(frame, Mapping):
        lengths = [len(v) for v in frame.values()
                   if not isinstance(v, (str, bytes)) and hasattr(v, "__len__")]
        return max(lengths, default=1)
    if isinstance(frame, (list, tuple)):
        return len(frame)
    try:
        return len(frame)
    except TypeError:
        return 1


def _edges_for(values: np.ndarray, bins: int) -> np.ndarray:
    """Quantile edges from the reference; a constant column gets a thin band."""
    if len(np.unique(values)) < 2:
        # Four edges keep "same", "below" and "above" in three distinct bins.
        # With three edges the constant lands in the last (left-closed) bin,
        # so a reference at zero would score zero against any positive drift;
        # the extra edge gives values above the constant their own bin.
        v = float(values[0])
        eps = max(abs(v) * 1e-6, 1e-9)
        return np.array([v - eps, v, v + eps, v + 2 * eps], dtype=float)
    edges = np.unique(np.quantile(values, np.linspace(0.0, 1.0, bins + 1)))
    if len(edges) < 2:
        v = float(values[0])
        eps = max(abs(v) * 1e-6, 1e-9)
        return np.array([v - eps, v + eps], dtype=float)
    return edges.astype(float)


@dataclass(frozen=True)
class FeatureBaseline:
    """Reference histogram for one monitored feature."""

    edges: tuple[float, ...]
    expected: tuple[float, ...]
    n: int

    @classmethod
    def from_values(cls, values: Any, bins: int = DEFAULT_BINS) -> FeatureBaseline:
        vals = _finite(values)
        if len(vals) < 2:
            raise ValueError("a drift baseline needs at least 2 finite values")
        edges = _edges_for(vals, bins)
        if len(np.unique(vals)) < 2:
            # The constant sits in the middle of three bins by construction;
            # np.histogram would put it in the left-closed last bin instead.
            counts = np.array([0.0, float(len(vals)), 0.0])
        else:
            counts = np.histogram(vals, bins=edges)[0].astype(float)
        expected = counts / max(float(counts.sum()), 1.0)
        return cls(edges=tuple(float(x) for x in edges),
                   expected=tuple(float(x) for x in expected), n=len(vals))

    def psi(self, values: Any) -> float:
        """PSI of the live column against this stored reference."""
        vals = _finite(values)
        if len(vals) == 0:
            return float("nan")
        clipped = np.clip(vals, self.edges[0], self.edges[-1])
        actual = np.histogram(clipped, bins=np.asarray(self.edges))[0].astype(float)
        actual = actual / max(float(actual.sum()), 1.0)
        expected = np.asarray(self.expected, dtype=float)
        expected = np.clip(expected, EPS, None)
        actual = np.clip(actual, EPS, None)
        return float(np.sum((actual - expected) * np.log(actual / expected)))

    def to_dict(self) -> dict[str, Any]:
        return {"edges": [round(x, 10) for x in self.edges],
                "expected": [round(x, 8) for x in self.expected],
                "n": self.n}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FeatureBaseline:
        edges = tuple(float(x) for x in data["edges"])
        expected = tuple(float(x) for x in data["expected"])
        if len(edges) < 2 or len(expected) != len(edges) - 1:
            raise ValueError("baseline edges/expected lengths are inconsistent")
        if not all(math.isfinite(x) for x in edges + expected):
            raise ValueError("baseline values must be finite")
        if any(b <= a for a, b in pairwise(edges)):
            raise ValueError("baseline edges must be strictly increasing")
        if any(x < 0 for x in expected) or sum(expected) <= 0:
            raise ValueError("baseline proportions must be non-negative")
        if abs(sum(expected) - 1.0) > 1e-5:
            raise ValueError("baseline proportions must sum to 1")
        return cls(edges=edges, expected=expected, n=int(data.get("n", 0)))


@dataclass(frozen=True)
class ChannelBaseline:
    """Monitored features and provenance for one model channel."""

    channel: str
    features: dict[str, FeatureBaseline]
    provenance: dict[str, Any] = field(default_factory=dict)
    method: str = "psi"
    # A channel may pin its own threshold when its null distribution differs
    # from the others (day-to-day flow variation vs family holdout, say).
    threshold: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"method": self.method,
                "threshold": self.threshold,
                "features": {k: v.to_dict() for k, v in self.features.items()},
                "provenance": self.provenance}

    @classmethod
    def from_dict(cls, channel: str, data: Mapping[str, Any]) -> ChannelBaseline:
        threshold = data.get("threshold")
        if threshold is not None:
            threshold = float(threshold)
            if not 0 < threshold < 100:
                raise ValueError("channel drift threshold must be in (0, 100)")
        method = str(data.get("method", "psi"))
        if method not in {"psi", "identity"}:
            raise ValueError(f"{channel}: unknown drift method {method!r}")
        features = {k: FeatureBaseline.from_dict(v)
                    for k, v in (data.get("features") or {}).items()}
        if method == "psi" and not features:
            raise ValueError(f"{channel}: PSI channel has no monitored features")
        if method == "identity" and features:
            raise ValueError(f"{channel}: identity channel has monitored features")
        return cls(
            channel=channel,
            features=features,
            provenance=dict(data.get("provenance") or {}),
            method=method,
            threshold=threshold,
        )


@dataclass(frozen=True)
class DriftReading:
    """One channel evaluation; `alarm` is the only field callers gate on."""

    channel: str
    n: int
    evaluated: bool
    features: dict[str, float]
    threshold: float
    max_psi: float | None = None
    max_feature: str | None = None
    alarm: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "n": self.n,
            "evaluated": self.evaluated,
            "features": {k: round(v, 6) for k, v in self.features.items()},
            "threshold": self.threshold,
            "max_psi": (round(self.max_psi, 6)
                        if self.max_psi is not None else None),
            "max_feature": self.max_feature,
            "alarm": self.alarm,
            "reason": self.reason,
        }


@dataclass
class DriftPolicy:
    """Pinned PSI references and the threshold that turns them into abstention."""

    channels: dict[str, ChannelBaseline]
    threshold: float = DEFAULT_THRESHOLD
    min_samples: int = DEFAULT_MIN_SAMPLES
    bins: int = DEFAULT_BINS
    generated_utc: str = ""
    source: str = ""
    schema: int = SCHEMA

    def status(self) -> dict[str, Any]:
        return {"available": True, "schema": self.schema,
                "generated_utc": self.generated_utc, "source": self.source,
                "threshold": self.threshold, "min_samples": self.min_samples,
                "channels": sorted(self.channels)}

    def evaluate(self, channel: str, frame: Any) -> DriftReading:
        baseline = self.channels.get(channel)
        if baseline is None:
            return DriftReading(channel, _frame_len(frame), False, {},
                                self.threshold, reason="no baseline for channel")
        threshold = (baseline.threshold if baseline.threshold is not None
                     else self.threshold)
        if baseline.method != "psi" or not baseline.features:
            return DriftReading(channel, _frame_len(frame), False, {},
                                threshold,
                                reason=f"channel method is {baseline.method!r}")
        n = _frame_len(frame)
        if n < self.min_samples:
            return DriftReading(channel, n, False, {}, threshold,
                                reason=(f"{n} rows, need {self.min_samples} "
                                        "for a PSI reading"))
        values: dict[str, float] = {}
        missing: list[str] = []
        for name, ref in baseline.features.items():
            try:
                col = _column(frame, name)
            except KeyError:
                missing.append(name)
                continue
            vals = _finite(col)
            if len(vals) < self.min_samples:
                missing.append(name)
                continue
            values[name] = ref.psi(vals)
        if not values:
            return DriftReading(channel, n, False, {}, threshold,
                                reason=("no monitored feature has enough finite "
                                        "values" + (f"; missing {missing}" if missing else "")))
        max_feature = max(values, key=values.get)
        max_psi = values[max_feature]
        alarm = max_psi > threshold
        reason = (f"max PSI {max_psi:.3f} on {max_feature} "
                  f"(threshold {threshold:.3f})")
        if missing:
            reason += f"; {len(missing)} monitored feature(s) skipped"
        return DriftReading(channel, n, True, values, threshold,
                            max_psi=max_psi, max_feature=max_feature,
                            alarm=alarm, reason=reason)

    def to_dict(self) -> dict[str, Any]:
        return {"schema": self.schema, "generated_utc": self.generated_utc,
                "source": self.source, "threshold": self.threshold,
                "min_samples": self.min_samples, "bins": self.bins,
                "channels": {k: v.to_dict() for k, v in self.channels.items()}}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DriftPolicy:
        schema = int(data.get("schema", 0))
        if schema != SCHEMA:
            raise ValueError(f"drift artifact schema {schema} != {SCHEMA}")
        channels = {k: ChannelBaseline.from_dict(k, v)
                    for k, v in (data.get("channels") or {}).items()}
        if not channels:
            raise ValueError("drift artifact has no channels")
        threshold = float(data.get("threshold", DEFAULT_THRESHOLD))
        min_samples = int(data.get("min_samples", DEFAULT_MIN_SAMPLES))
        bins = int(data.get("bins", DEFAULT_BINS))
        if not 0 < threshold < 100:
            raise ValueError("drift threshold must be in (0, 100)")
        if min_samples < bins * 5:
            raise ValueError("min_samples is too small for the stored bins")
        return cls(channels=channels, threshold=threshold,
                   min_samples=min_samples, bins=bins,
                   generated_utc=str(data.get("generated_utc", "")),
                   source=str(data.get("source", "")), schema=schema)

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2) + "\n",
                     encoding="utf-8", newline="\n")
        return p

    @classmethod
    def load(cls, path: str | Path) -> DriftPolicy:
        p = Path(path)
        return cls.from_dict(json.loads(p.read_text(encoding="utf-8")))


@dataclass
class DriftMonitor:
    """Stateful latch around a policy: one alarm is sticky until reset."""

    policy: DriftPolicy
    readings: dict[str, DriftReading] = field(default_factory=dict)
    alarms: dict[str, DriftReading] = field(default_factory=dict)

    def observe(self, channel: str, frame: Any) -> DriftReading:
        reading = self.policy.evaluate(channel, frame)
        self.readings[channel] = reading
        if reading.alarm:
            self.alarms[channel] = reading
        return reading

    def observe_many(self, samples: Iterable[tuple[str, Any]]) -> list[DriftReading]:
        return [self.observe(channel, frame) for channel, frame in samples]

    def alarmed(self, channel: str) -> bool:
        return channel in self.alarms

    def reset(self, channel: str | None = None) -> None:
        if channel is None:
            self.alarms.clear()
            return
        self.alarms.pop(channel, None)

    def status(self) -> dict[str, Any]:
        return {"available": True,
                "threshold": self.policy.threshold,
                "min_samples": self.policy.min_samples,
                "alarmed": sorted(self.alarms),
                "readings": {k: v.to_dict() for k, v in self.readings.items()}}


def is_finite(value: float | None) -> bool:
    """Small helper for callers formatting a reading without a NaN surprise."""
    return value is not None and math.isfinite(value)
