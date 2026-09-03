"""Feature preparation for the ML detectors.

One place turns a features-parquet (or canonical-flow-derived frame) into
model-ready matrices:

  * MODEL_FEATURES — the exact numeric feature list the models are trained on.
    Identity columns (IP addresses, ports, flow ids, timestamps, label) are
    deliberately EXCLUDED: a model keyed on IPs memorizes corpus topology and
    transfers nothing to a new network. Drawn from the basic / rates / ratio /
    protocol / tcpflags / dns / context families of src.features.specs — read
    the length off MODEL_FEATURES, never off this docstring.
  * The label mapping (CLASSES / class_of) lives in
    src.detectors.ml.labels — the single owner of label truth, shared with
    the transfer-evaluation axis — and is re-exported here unchanged.
  * `prepare` applies the learned imputation (median from TRAIN data only,
    passed in by the caller) — no leakage, deterministic inference everywhere.

Every saved model records MODEL_FEATURES (with an md5 fingerprint) so drift
between feature registry and model is detected at load time.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

# The frozen model feature list (active numeric families, identity excluded).
MODEL_FEATURES: list[str] = [
    "duration_s", "fwd_pkts", "bwd_pkts", "tot_pkts",
    "fwd_bytes", "bwd_bytes", "tot_bytes",
    "avg_fwd_pkt_size", "avg_bwd_pkt_size", "avg_pkt_size",
    "flow_bytes_per_s", "flow_pkts_per_s",
    "fwd_bytes_per_s", "bwd_bytes_per_s", "fwd_pkts_per_s", "bwd_pkts_per_s",
    "fwd_byte_ratio", "byte_asymmetry", "pkt_asymmetry",
    "is_tcp", "is_udp", "is_icmp",
    "fin_flags", "syn_flags", "rst_flags", "psh_flags", "ack_flags", "urg_flags",
    "is_dns",
    "src_flow_count", "src_dst_port_count", "src_dst_ip_count",
    "src_dst_port_entropy", "src_dns_share",
    "dst_flow_count", "dst_src_port_count", "dst_src_ip_count",
    "dst_src_port_entropy",
]

# Label truth lives in labels.py (the single owner, shared with the
# evaluation axis in scripts/benchmarks/bench_transfer.py). Re-exported unchanged, never
# copied — `from .features import CLASSES` and `from .labels import CLASSES`
# are the same object.
from .labels import CLASSES, class_of  # noqa: F401


def features_fingerprint() -> str:
    """md5 of the sorted model-feature list (recorded in every model card)."""
    return hashlib.md5(json.dumps(sorted(MODEL_FEATURES)).encode()).hexdigest()


def with_epoch(df: pd.DataFrame, time_col: str = "timestamp") -> pd.DataFrame:
    """Add a float `ts_epoch` (seconds) parsed from the ISO timestamp column.

    Unit-safe: to_datetime may return ns- or us-resolution datetimes depending
    on the parsed formats, so the epoch is derived via total_seconds(), never
    from a raw int64 view.
    """
    if "ts_epoch" in df.columns:
        return df
    out = df.copy()
    ts = pd.to_datetime(out[time_col], errors="coerce", utc=True, format="mixed")
    epoch = (ts - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()
    out["ts_epoch"] = epoch.astype("float64")
    return out


def load_features(path: str | Path) -> pd.DataFrame:
    """Load a features parquet, validating the registry contract."""
    df = pd.read_parquet(path)
    missing = [c for c in MODEL_FEATURES if c not in df.columns]
    if missing:
        raise ValueError(f"{path}: features parquet lacks {len(missing)} "
                         f"registry columns (first: {missing[0]}); rebuild via "
                         f"python -m src.features.pipeline")
    return df


def safe_median(col) -> float:
    """Column median (pandas Series or ndarray), guarded: all-NaN columns
    (e.g. a missing feature) impute to 0 instead of poisoning the matrix."""
    arr = np.asarray(col, dtype=float)
    finite = arr[np.isfinite(arr)]
    return float(np.median(finite)) if finite.size else 0.0


def numeric_matrix(df: pd.DataFrame, medians: dict[str, float] | None = None
                   ) -> tuple[np.ndarray, dict[str, float]]:
    """Numeric model matrix with NaN→median imputation.

    medians=None learns the medians from this frame (training);
    pass the learned dict at inference time. Rows never contain Inf:
    ±Inf is coerced to the feature median as well (CIC sentinels produce some).
    """
    X = df.reindex(columns=MODEL_FEATURES).apply(pd.to_numeric, errors="coerce")
    if medians is None:
        medians = {c: safe_median(X[c]) for c in X.columns}
    for c in X.columns:
        m = medians.get(c, 0.0)
        col = X[c].to_numpy(dtype=float, copy=True)
        bad = ~np.isfinite(col)
        if bad.any():
            col[bad] = m
        X[c] = col
    return X.to_numpy(dtype=np.float32), medians


def split_temporal(df: pd.DataFrame, test_frac: float = 0.2,
                   time_col: str = "ts_epoch",
                   ) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Chronological split: oldest (1-test_frac) -> train, newest -> test.

    The epoch column is derived from the ISO `timestamp` column when missing.
    Falls back to a seeded random split when no usable time axis exists (e.g.
    hand-built fixtures).
    """
    work = df
    if time_col not in work.columns and "timestamp" in work.columns:
        work = with_epoch(work)
    if time_col in work.columns:
        t = pd.to_numeric(work[time_col], errors="coerce")
        if t.notna().sum() >= max(10, int(0.5 * len(df))):
            cutoff = t.quantile(1.0 - test_frac)
            train = df[t <= cutoff]
            test = df[t > cutoff]
            if len(train) >= 10 and len(test) >= 10:
                return train, test
    shuffled = df.sample(frac=1.0, random_state=42)
    k = int(len(shuffled) * (1.0 - test_frac))
    return shuffled.iloc[:k], shuffled.iloc[k:]
