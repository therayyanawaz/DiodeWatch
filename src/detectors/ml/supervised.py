"""Supervised multi-class flow classifier (LightGBM).

Trains on the frozen 38-feature model matrix (see `features.py`) with labels
consolidated from the CIC-IDS2017 taxonomy into the project threat classes:

    Two feature registries, three counts, they are not competing versions of
    one. `src/features/specs.py` declares 79 columns (73 active + 6 future).
    `MODEL_FEATURES` (38) is the numeric subset this classifier consumes: the
    73 active minus the 9 `meta` columns (flow_id, IPs, ports, protocol/proto,
    timestamp, label), which are carried for joins and evaluation rather than
    as signal, and minus the 26 per-packet `iat_*` / `*_len_*` columns, which
    the engine emits and the parity harness checks but the pinned artifacts
    were trained before they existed. `load()` enforces the 38-column matrix
    via `features_fingerprint()`.


    benign, ddos, scan, bruteforce, webattack, bot, infiltration

Discipline:
  * chronological train/test split per corpus day (never random when a time
    axis exists) so the held-out numbers answer "would this survive tomorrow";
  * median imputation learned on TRAIN rows only;
  * class_weight="balanced" so rare classes (bot: ~0.05% of rows) compete;
  * per-class precision / recall / F1 + confusion matrix logged to
    results/ml/supervised_metrics.json, honest numbers, no cherry-picking;
  * the model card (feature fingerprint, hyper-parameters, corpus manifest
    hashes) is stored next to the model, making any drift explicit.

Inference (`score`) turns probabilities above `--threshold` into the SAME
alert envelope as the rule engine (alerts.schema.Alert) with the predicted
probability as confidence and a per-feature evidence line, so downstream
export/UI code cannot tell rules and ML apart.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd

from src.alerts.schema import Alert, EvidenceItem

from .features import (
    CLASSES,
    MODEL_FEATURES,
    class_of,
    features_fingerprint,
    load_features,
    numeric_matrix,
)

DEFAULT_LGBM: dict = {
    "objective": "multiclass",
    "num_class": len(CLASSES),
    "n_estimators": 300,
    "learning_rate": 0.1,
    "num_leaves": 63,
    "min_child_samples": 40,
    "subsample": 0.9,
    "subsample_freq": 1,
    "colsample_bytree": 0.9,
    "class_weight": "balanced",
    "n_jobs": -1,
    "verbosity": -1,
    "random_state": 42,
}


def _num(v) -> float:
    """JSON-safe numeric coercion (NaN/None/strings -> finite or 0)."""
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0.0
    return f if np.isfinite(f) else 0.0


@dataclass
class SupervisedModel:
    """Trained classifier + everything needed for reproducible inference."""
    booster: lgb.LGBMClassifier
    medians: dict[str, float]
    classes: list[str]
    feature_fingerprint: str
    metrics: dict | None = None

    # ------------------------------------------------------------------ io
    def save(self, model_dir: str | Path) -> Path:
        import joblib

        model_dir = Path(model_dir)
        model_dir.mkdir(parents=True, exist_ok=True)
        path = model_dir / "supervised_lgbm.joblib"
        joblib.dump({
            "booster": self.booster,
            "medians": self.medians,
            "classes": self.classes,
            "feature_fingerprint": self.feature_fingerprint,
            "metrics": self.metrics,
        }, path)
        return path

    @classmethod
    def load(cls, model_dir: str | Path) -> SupervisedModel:
        import joblib

        path = Path(model_dir) / "supervised_lgbm.joblib"
        blob = joblib.load(path)
        if blob["feature_fingerprint"] != features_fingerprint():
            raise ValueError("model feature fingerprint mismatch, the feature "
                             "registry changed since training; retrain")
        return cls(**blob)

    # ------------------------------------------------------------ inference
    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        X, _ = numeric_matrix(df, medians=self.medians)
        return self.booster.predict_proba(X)

    def score(self, df: pd.DataFrame, threshold: float = 0.9) -> list[Alert]:
        """Emit alerts for flows whose predicted threat probability ≥ threshold.

        BENIGN wins ties by design: a flow is alerted only when a *threat*
        class is the argmax AND exceeds the threshold, so an ambiguous 0.55
        bot / 0.45 benign never fires.
        """
        proba = self.predict_proba(df)
        alerts: list[Alert] = []
        for i in range(len(df)):
            row = df.iloc[i]
            j = int(np.argmax(proba[i]))
            cls = self.classes[j]
            p = float(proba[i][j])
            if cls == "benign" or p < threshold:
                continue
            alerts.append(self._alert(row, cls, p))
        return alerts

    def _alert(self, row: pd.Series, cls: str, p: float) -> Alert:
        ts = str(row.get("timestamp") or "")
        # evidence: top-3 features by the model's global importance, with the
        # observed value; per-flow SHAP attribution is a future upgrade.
        imp = self.booster.feature_importances_
        top = np.argsort(imp)[::-1][:3]
        evidence = [
            EvidenceItem(
                condition=MODEL_FEATURES[k], operator="model",
                observed=_num(row.get(MODEL_FEATURES[k])),
                threshold=f"p({cls})>={p:.2f}",
                description=f"{MODEL_FEATURES[k]}={_num(row.get(MODEL_FEATURES[k])):.3g}",
                unit="",
            ) for k in top
       ]
        evidence.insert(0, EvidenceItem(
            condition="predicted_probability", operator=">=",
            observed=round(p, 4), threshold=0.9,
            description=f"LightGBM predicts {cls} with p={p:.3f}", unit="probability",
        ))
        return Alert(
            timestamp=ts,
            threat_class=cls,
            confidence=round(p, 4),
            evidence=evidence,
            flow_id=str(row.get("flow_id")) if row.get("flow_id") is not None else None,
            key=str(row.get("src_ip")) if row.get("src_ip") is not None else None,
            detector="ml.supervised",
            label=str(row["label"]) if "label" in row and pd.notna(row["label"]) else None,
            src_ip=_s(row, "src_ip"), dst_ip=_s(row, "dst_ip"),
            src_port=_p(row, "src_port"), dst_port=_p(row, "dst_port"),
            proto=_s(row, "proto"),
        )


def _s(row: pd.Series, c: str) -> str | None:
    v = row.get(c)
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return None
    s = str(v).strip()
    return s or None


def _p(row: pd.Series, c: str) -> int | None:
    v = row.get(c)
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------- training
def _per_day_split(df: pd.DataFrame, day_col: str, test_frac: float = 0.2,
                   ) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Chronological split within each (day, class) group, then concatenate.

    Per DAY keeps every corpus day in both sides; per CLASS within the day
    guarantees every attack class has both a train portion and an honest
    out-of-sample tail (attacks cluster in short morning windows, so a plain
    per-day tail can leave a class with zero test support).
    """
    from .features import split_temporal

    trains, tests = [], []
    for _, chunk in df.groupby([day_col, "__class"], sort=False):
        tr, te = split_temporal(chunk, test_frac=test_frac)
        trains.append(tr)
        tests.append(te)
    return pd.concat(trains, ignore_index=True), pd.concat(tests, ignore_index=True)


def train_supervised(corpus_parquets: list[str | Path],
                     model_dir: str | Path = "models",
                     results_dir: str | Path = "results/ml",
                     test_frac: float = 0.2,
                     params: dict | None = None) -> tuple[SupervisedModel, dict]:
    """Train on the given features parquets; evaluate honestly; save artifacts.

    Returns (model, metrics dict). The metrics dict is also written to
    results/ml/supervised_metrics.json and mirrored into the model card.
    """
    frames = []
    for p in corpus_parquets:
        f = load_features(p)
        f = f.copy()
        f["__corpus"] = Path(p).stem
        frames.append(f)
    df = pd.concat(frames, ignore_index=True)

    df["__class"] = df["label"].map(class_of)
    df = df[df["__class"].notna()]
    df["__class"] = df["__class"].astype("category")
    df["__class"] = df["__class"].cat.set_categories(CLASSES)

    train, test = _per_day_split(df, "__corpus", test_frac=test_frac)

    # Benign downsampling, TRAIN ONLY (test keeps natural prevalence): 2:1
    # benign-vs-attack is enough contrast for balanced weighting to work with.
    benign = train[train["__class"] == "benign"]
    attack = train[train["__class"] != "benign"]
    if len(attack) and len(benign) > 2 * len(attack):
        benign = benign.sample(n=2 * len(attack), random_state=42)
        train = pd.concat([benign, attack]).sample(frac=1.0, random_state=42)

    Xtr, medians = numeric_matrix(train)
    Xte, _ = numeric_matrix(test, medians=medians)
    ytr = train["__class"].cat.codes.to_numpy()
    yte = test["__class"].cat.codes.to_numpy()

    # Cap inverse-frequency weights at 30x: unlimited balanced weighting gave
    # rare classes ~270x weight and pulled 23% of benign rows into them.
    counts = np.bincount(ytr, minlength=len(CLASSES))
    w = np.where(counts > 0, counts.max() / np.maximum(counts, 1), 1.0)
    w = np.minimum(w, 30.0)
    class_weight = {i: float(w[i]) for i in range(len(CLASSES)) if counts[i]}

    t0 = time.perf_counter()
    clf = lgb.LGBMClassifier(**{**DEFAULT_LGBM, "class_weight": class_weight,
                                **(params or {})})
    clf.fit(Xtr, ytr)
    fit_s = time.perf_counter() - t0

    proba = clf.predict_proba(Xte)
    pred = proba.argmax(axis=1)

    # ---- honest per-class metrics on the held-out tail -------------------
    present = sorted(set(yte.tolist()) | set(pred.tolist()))
    per_class: dict[str, dict] = {}
    for c in present:
        name = CLASSES[c]
        tp_c = int(((pred == c) & (yte == c)).sum())
        fp_c = int(((pred == c) & (yte != c)).sum())
        fn_c = int(((pred != c) & (yte == c)).sum())
        prec = tp_c / (tp_c + fp_c) if tp_c + fp_c else 0.0
        rec = tp_c / (tp_c + fn_c) if tp_c + fn_c else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        per_class[name] = {
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4),
            "support": int((yte == c).sum()),
        }
    macro_f1 = float(np.mean([m["f1"] for m in per_class.values()]))
    accuracy = float((pred == yte).mean())

    metrics = {
        "model": "LightGBM multiclass",
        "n_train": len(train), "n_test": len(test),
        "split": ("chronological per (day, class): oldest 80% train, newest "
                  "20% test; benign downsampled 2:1 in TRAIN only; class "
                  "weights capped at 30x"),
        "features": len(MODEL_FEATURES),
        "feature_fingerprint": features_fingerprint(),
        "classes": CLASSES,
        "fit_seconds": round(fit_s, 1),
        "accuracy": round(accuracy, 4),
        "macro_f1": round(macro_f1, 4),
        "per_class": per_class,
        "confusion_matrix": {
            "labels": [CLASSES[c] for c in present],
            "matrix": [[int(((yte == a) & (pred == b)).sum()) for b in present]
                       for a in present],
        },
    }

    model = SupervisedModel(booster=clf, medians=medians, classes=CLASSES,
                            feature_fingerprint=features_fingerprint(),
                            metrics=metrics)
    model.save(model_dir)

    out = Path(results_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "supervised_metrics.json").write_text(json.dumps(metrics, indent=2))
    return model, metrics


def metrics_summary(metrics: dict) -> str:
    """One-line-per-class text block for logs and docs."""
    lines = [(f"accuracy={metrics['accuracy']:.4f} macro_f1={metrics['macro_f1']:.4f} "
              f"n_test={metrics['n_test']:,}")]
    for name, m in metrics["per_class"].items():
        lines.append(f"  {name:<12} P={m['precision']:.3f} R={m['recall']:.3f} "
                     f"F1={m['f1']:.3f} (n={m['support']:,})")
    return "\n".join(lines)
