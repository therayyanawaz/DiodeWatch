"""Botnet C2 / beaconing detector (CTU-13).

Beacons betray themselves as *pair-level* time series, not individual flows:
one (src, dst, dst_port) pair repeating at a near-constant interval with
near-constant payload sizes. The detector therefore aggregates flows into
pair series and computes interpretable periodicity features:

  n_flows      pair volume          dt_mean / dt_std / dt_cv   interval rhythm
  span_s       pair longevity       dt_median                  typical interval
  dt_scores    fraction of dts in the 2–70 s C2 band
  byte_std     payload steadiness   fwd/bwd asymmetry

Two classifiers, one label:
  * LightGBM on the pair features (supervised, catches "beacon-like" shapes);
  * a transparent fallback rule (dt_cv <= 0.25 AND dt_scores >= 0.9 AND
    n_flows >= 10) used when the model is unavailable — rule-style.

Evaluation is leave-one-scenario-out across CTU-13 scenarios 42/43/51/52/53:
the model never trains on the scenario it is tested on, so the reported F1
answers "does this generalize to a NEW botnet", not "did it memorize".
Operating domain: only beacon CANDIDATES (>= 5 flows, >= 60 s lifespan) are
evaluated — shorter contacts cannot exhibit periodicity and belong to the
flow+context supervised model instead.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from src.alerts.schema import Alert, EvidenceItem

from .features import safe_median

BEACON_FEATURES = [
    "n_flows", "span_s", "dt_mean", "dt_std", "dt_median", "dt_cv",
    "dt_scores", "dt_jitter_share", "fwd_bytes_mean", "fwd_bytes_std",
    "bwd_bytes_mean", "byte_std", "fwd_share",
]

FALLBACK_RULE = {"dt_cv": 0.25, "dt_scores": 0.9, "n_flows": 10}

# Operating domain of the BEACON detector: a pair with fewer flows or a
# shorter life cannot exhibit periodicity, so it is not a beacon candidate —
# those contacts belong to the flow+context supervised model / rule layer.
# (CTU-13 check: median labelled bot pair is a 1-flow spam/DNS burst; classic
# long-lived beacons are the minority of bot pairs.)
CANDIDATE_MIN_FLOWS = 5
CANDIDATE_MIN_SPAN_S = 60.0


def beacon_candidates(pairs: pd.DataFrame) -> pd.Series:
    """Boolean mask: pairs where the beacon question is even decidable."""
    return (pairs["n_flows"] >= CANDIDATE_MIN_FLOWS) \
        & (pairs["span_s"] >= CANDIDATE_MIN_SPAN_S)

CTU_SCENARIOS = {
    "42": "CTU-42-capture20110810.binetflow",
    "43": "CTU-43-capture20110811.binetflow",
    "51": "CTU-51-capture20110818.binetflow.labeled",
    "52": "CTU-52-capture20110818-2.binetflow",
    "53": "CTU-53-capture20110819.binetflow",
}
CTU_DIR = Path("data/raw/ctu13")


# --------------------------------------------------------------------- ingestion
def load_ctu(path: str | Path) -> pd.DataFrame:
    """Read one CTU-13 labeled NetFlow file into a canonical-ish frame.

    Handles the 15-col (StartTime..Label) and 16-col (extra CCDetector)
    dialects; NaN-safe. Returns columns: ts_epoch, src_ip, dst_ip, dst_port,
    proto, dur_s, pkts, bytes, src_bytes, label.
    """
    path = Path(path)
    head = path.open(encoding="utf-8", errors="replace").readline()
    ncols = head.lstrip("#").strip().split(",")
    df = pd.read_csv(path, names=ncols, skiprows=1, low_memory=False)
    # dialects: 'Label' (15-col) vs 'Label(Normal:CC:Background)' (16-col CTU-51/52)
    df.columns = [c.strip().lstrip("#") for c in df.columns]
    df.columns = ["Label" if c.startswith("Label") else c for c in df.columns]

    ts = pd.to_datetime(df["StartTime"], errors="coerce", format="mixed", utc=True)
    # unit-safe epoch: to_datetime may return ns- or us-resolution datetimes
    # depending on the parsed formats; total_seconds() is invariant to that.
    epoch = (ts - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()
    out = pd.DataFrame({
        "ts_epoch": epoch,
        "src_ip": df["SrcAddr"].astype(str),
        "dst_ip": df["DstAddr"].astype(str),
        "dst_port": pd.to_numeric(df["Dport"], errors="coerce").fillna(0).astype(int),
        "proto": df["Proto"].astype(str),
        "dur_s": pd.to_numeric(df["Dur"], errors="coerce").fillna(0),
        "pkts": pd.to_numeric(df["TotPkts"], errors="coerce").fillna(0),
        "bytes": pd.to_numeric(df["TotBytes"], errors="coerce").fillna(0),
        "src_bytes": pd.to_numeric(df["SrcBytes"], errors="coerce").fillna(0),
        "label": df["Label"].astype(str),
    })
    return out


def pair_series(flows: pd.DataFrame) -> pd.DataFrame:
    """Aggregate flows into (src_ip, dst_ip, dst_port) ordered-by-time series.

    Computes the periodicity features. dt_* are inter-flow-arrival gaps for
    the pair (shift within the sorted group — fully vectorized); pairs with a
    single flow carry NaN dt_* and are imputed by the model's medians.
    """
    flows = flows.copy()
    flows["ts_epoch"] = pd.to_numeric(flows["ts_epoch"], errors="coerce")
    flows = flows.dropna(subset=["ts_epoch"]).sort_values(
        ["src_ip", "dst_ip", "dst_port", "ts_epoch"], kind="mergesort")

    key = ["src_ip", "dst_ip", "dst_port"]
    g = flows.groupby(key, sort=False)
    flows["dt"] = flows["ts_epoch"] - g["ts_epoch"].shift(1)
    flows["in_band"] = ((flows["dt"] >= 2.0) & (flows["dt"] <= 70.0)).astype(float).where(
        flows["dt"].notna())
    # jitter share: fraction of gaps within ±25% of the pair's OWN median gap
    # (the classic fixed-interval beacon test, independent of absolute rate)
    med = flows.groupby(["src_ip", "dst_ip", "dst_port"], sort=False)["dt"] \
        .transform("median")
    flows["near_median"] = (
        (flows["dt"] - med).abs() <= 0.25 * med
    ).astype(float).where(flows["dt"].notna())

    agg = g.agg(
        n_flows=("ts_epoch", "size"),
        ts_first=("ts_epoch", "min"),
        ts_last=("ts_epoch", "max"),
        fwd_bytes_mean=("src_bytes", "mean"),
        fwd_bytes_std=("src_bytes", "std"),
        bwd_bytes_mean=("bytes", "mean"),
        byte_std=("bytes", "std"),
        fwd_sum=("src_bytes", "sum"),
        tot_sum=("bytes", "sum"),
        label=("label", "first"),
        dt_mean=("dt", "mean"),
        dt_std=("dt", "std"),
        dt_median=("dt", "median"),
        dt_scores=("in_band", "mean"),
    )
    agg["dt_jitter_share"] = flows.groupby(key, sort=False)["near_median"] \
        .mean().reindex(agg.index)
    agg["span_s"] = agg["ts_last"] - agg["ts_first"]
    agg["dt_cv"] = agg["dt_std"] / agg["dt_mean"].replace(0, np.nan)
    agg["fwd_share"] = agg["fwd_sum"] / agg["tot_sum"].replace(0, np.nan)
    out = agg.drop(columns=["fwd_sum", "tot_sum"])
    out["label"] = out["label"].fillna("flow=Background")
    return out.reset_index()


def pair_label(label: str) -> int:
    """1 when the pair is bot/C2 traffic, else 0.

    CTU-13 uses two label dialects: 'flow=From-Bot-...' (scenarios 42/43/53)
    and 'flow=From-CC-...' (51/52, where the C2 channel is labelled directly).
    """
    return 1 if any(k in label for k in ("From-Bot", "From-CC", "Botnet")) else 0


# --------------------------------------------------------------------- model
def _rule_score(f: pd.DataFrame) -> np.ndarray:
    """Transparent fallback: conjunctive beacon shape (rule-style)."""
    ok = (
        (f["dt_cv"] <= FALLBACK_RULE["dt_cv"])
        & (f["dt_scores"] >= FALLBACK_RULE["dt_scores"])
        & (f["n_flows"] >= FALLBACK_RULE["n_flows"])
    )
    return ok.to_numpy(dtype=float)


@dataclass
class BeaconModel:
    booster: lgb.LGBMClassifier | None
    medians: dict[str, float]
    threshold: float = 0.5

    def predict_score(self, pairs: pd.DataFrame) -> np.ndarray:
        """Beacon score in [0, 1] per pair row (model when loaded, else rule)."""
        if self.booster is None:
            return _rule_score(pairs)
        X = pairs.reindex(columns=BEACON_FEATURES).apply(pd.to_numeric,
                                                         errors="coerce")
        for c in X.columns:
            m = self.medians.get(c, 0.0)
            col = X[c].to_numpy(dtype=float, copy=True)
            col[~np.isfinite(col)] = m
            X[c] = col
        return self.booster.predict_proba(X.to_numpy(dtype=np.float32))[:, 1]

    def save(self, model_dir: str | Path) -> Path:
        import joblib

        model_dir = Path(model_dir)
        model_dir.mkdir(parents=True, exist_ok=True)
        path = model_dir / "beacon_lgbm.joblib"
        joblib.dump({"booster": self.booster, "medians": self.medians,
                     "threshold": self.threshold}, path)
        return path

    @classmethod
    def load(cls, model_dir: str | Path) -> BeaconModel:
        import joblib

        path = Path(model_dir) / "beacon_lgbm.joblib"
        if not path.exists():
            return cls(booster=None, medians={})
        blob = joblib.load(path)
        return cls(booster=blob.get("booster"), medians=blob.get("medians", {}),
                   threshold=float(blob.get("threshold", 0.5)))


BEACON_LGBM = {
    "n_estimators": 200, "learning_rate": 0.1, "num_leaves": 31,
    "min_child_samples": 20,
    # NOTE: no class_weight here — training negatives are already subsampled
    # to 10:1; LightGBM's balanced weighting on top of that double-corrects
    # and floods false positives (observed: P=0.09 pooled LOSO).
    "n_jobs": -1, "verbosity": -1, "random_state": 42,
}


# --------------------------------------------------------------------- training
def train_beacon(ctu_dir: str | Path = CTU_DIR,
                 model_dir: str | Path = "models",
                 results_dir: str | Path = "results/ml",
                 ) -> tuple[BeaconModel, dict]:
    """Leave-one-scenario-out training + eval over the pinned CTU-13 scenarios.

    The returned model is refit on ALL scenarios; metrics are the pooled
    out-of-sample predictions from the 5 folds (every pair scored exactly once
    by a model that never saw its scenario).
    """
    ctu_dir = Path(ctu_dir)
    pairs_by_scen: dict[str, pd.DataFrame] = {}
    cache_dir = ctu_dir / "_pair_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    for scen, fname in CTU_SCENARIOS.items():
        path = ctu_dir / fname
        if not path.exists():
            raise FileNotFoundError(f"{path} missing — run scripts/fetch/download_ml_corpora.py")
        cache = cache_dir / f"pairs__{scen}.v2.parquet"
        if cache.exists():
            pairs = pd.read_parquet(cache)
        else:
            pairs = pair_series(load_ctu(path))
            pairs.to_parquet(cache, index=False)
        pairs["y"] = pairs["label"].map(pair_label)
        pairs["scenario"] = scen
        # restrict to the beacon candidate domain (see beacon_candidates)
        pairs = pairs[beacon_candidates(pairs)].reset_index(drop=True)
        pairs_by_scen[scen] = pairs
        print(f"[beacon] CTU-{scen}: {len(pairs):,} candidate pairs "
              f"({int(pairs['y'].sum()):,} bot)")

    all_pairs = pd.concat(pairs_by_scen.values(), ignore_index=True)

    # ---- leave-one-scenario-out -----------------------------------------
    oof = np.full(len(all_pairs), np.nan)
    per_scenario: dict[str, dict] = {}
    fold_thresholds: list[float] = []
    for held_out in CTU_SCENARIOS:
        tr = all_pairs[all_pairs["scenario"] != held_out]
        te = all_pairs[all_pairs["scenario"] == held_out].copy()
        ytr_full = tr["y"].to_numpy()
        # deterministic negative subsample (>=10:1) keeps folds fast; the
        # held-out scenario is always scored in full
        pos = np.where(ytr_full == 1)[0]
        neg = np.where(ytr_full == 0)[0]
        rng = np.random.default_rng(42)
        neg = rng.choice(neg, size=min(len(neg), 10 * max(len(pos), 1)),
                         replace=False)
        keep = np.sort(np.concatenate([pos, neg]))
        tr_s = tr.iloc[keep]
        if tr_s["y"].sum() < 10:  # degenerate fold (no bot pairs in train)
            continue
        # Nested split: the decision threshold is chosen on an inner
        # validation slice (F1-optimal), never on the held-out scenario.
        idx = np.random.default_rng(7).permutation(len(tr_s))
        n_val = max(int(0.15 * len(tr_s)), 1)
        val_i, fit_i = idx[:n_val], idx[n_val:]
        Xfit, medians = _matrix(tr_s.iloc[fit_i])
        Xval, _ = _matrix(tr_s.iloc[val_i], medians)
        yfit = tr_s["y"].to_numpy()[fit_i]
        yval = tr_s["y"].to_numpy()[val_i]
        clf_fit = lgb.LGBMClassifier(**BEACON_LGBM)
        clf_fit.fit(Xfit, yfit)
        val_scores = clf_fit.predict_proba(Xval)[:, 1]
        order = np.argsort(-val_scores)
        ys, ss = yval[order], val_scores[order]
        tp = np.cumsum(ys == 1)
        fp = np.cumsum(ys == 0)
        prec = tp / np.maximum(tp + fp, 1)
        rec = tp / max(int(ys.sum()), 1)
        f1s = 2 * prec * rec / np.maximum(prec + rec, 1e-12)
        thr = float(ss[int(np.argmax(f1s))]) if len(ss) else 0.5
        fold_thresholds.append(thr)
        # refit on the whole (subsampled) fold, score the held-out scenario
        Xtr, _ = _matrix(tr_s, medians)
        clf = lgb.LGBMClassifier(**BEACON_LGBM)
        clf.fit(Xtr, tr_s["y"].to_numpy())
        Xte, _ = _matrix(te, medians)
        te_scores = clf.predict_proba(Xte)[:, 1]
        oof[te.index] = te_scores
        yte = te["y"].to_numpy()
        per_scenario[held_out] = _binary_metrics(yte, te_scores, thr)
        per_scenario[held_out]["threshold"] = round(thr, 4)
        per_scenario[held_out]["positives"] = int(yte.sum())
        per_scenario[held_out]["pr_auc"] = round(
            float(average_precision_score(yte, te_scores)), 4)
        per_scenario[held_out]["roc_auc"] = round(
            float(roc_auc_score(yte, te_scores)), 4)
        per_scenario[held_out]["n_pairs"] = len(te)

    y = all_pairs["y"].to_numpy()
    valid = ~np.isnan(oof)
    pooled_thr = float(np.median(fold_thresholds)) if fold_thresholds else 0.5
    metrics = _binary_metrics(y[valid], oof[valid], threshold=pooled_thr)
    metrics["threshold"] = round(pooled_thr, 4)
    metrics["pr_auc"] = round(float(average_precision_score(y[valid], oof[valid])), 4)
    metrics["roc_auc"] = round(float(roc_auc_score(y[valid], oof[valid])), 4)
    # Headline generalization metric: macro ROC-AUC over LOSO scenarios with
    # enough positive candidates for a meaningful estimate (>= 30). A fold
    # with 6 positives can swing its AUC wildly (CTU-53).
    macro_scen = [d for d in per_scenario.values() if d.get("positives", 0) >= 30]
    if macro_scen:
        metrics["roc_auc_macro"] = round(
            float(np.mean([d["roc_auc"] for d in macro_scen])), 4)
        metrics["roc_auc_macro_rule"] = ("macro mean over scenarios with "
                                         ">= 30 positive candidate pairs")
        metrics["roc_auc_macro_scenarios"] = sorted(
            s for s, d in per_scenario.items() if d.get("positives", 0) >= 30)
    metrics.update({
        "model": "LightGBM pair periodicity (leave-one-scenario-out)",
        "scenarios": sorted(CTU_SCENARIOS),
        "per_scenario": per_scenario,
        "n_pairs": int(valid.sum()),
        "positives": int(y[valid].sum()),
        "candidate_definition": (f"n_flows >= {CANDIDATE_MIN_FLOWS} and "
                                 f"span_s >= {CANDIDATE_MIN_SPAN_S:g}"),
        "caveat": ("task is beacon-candidate discrimination: CTU-13 bot C2 in "
                   "bidirectional NetFlow is mostly bursty (spam/DNS), so "
                   "non-candidate bot contacts are out of scope here and are "
                   "covered by the flow+context model and rules (docs/ml.md)"),
    })

    # ---- final model on all scenarios (negatives subsampled 10:1) --------
    pos = np.where(y == 1)[0]
    neg = np.where(y == 0)[0]
    rng = np.random.default_rng(42)
    neg = rng.choice(neg, size=min(len(neg), 10 * max(len(pos), 1)), replace=False)
    keep = np.sort(np.concatenate([pos, neg]))
    X, medians = _matrix(all_pairs.iloc[keep])
    final = lgb.LGBMClassifier(**BEACON_LGBM)
    final.fit(X, y[keep])
    model = BeaconModel(booster=final, medians=medians, threshold=pooled_thr)
    model.save(model_dir)

    out = Path(results_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "beacon_metrics.json").write_text(json.dumps(metrics, indent=2))
    return model, metrics


def _matrix(df: pd.DataFrame, medians: dict[str, float] | None = None
            ) -> tuple[np.ndarray, dict[str, float]]:
    X = df.reindex(columns=BEACON_FEATURES).apply(pd.to_numeric, errors="coerce")
    if medians is None:
        medians = {c: safe_median(X[c]) for c in X.columns}
    for c in X.columns:
        m = medians.get(c, 0.0)
        col = X[c].to_numpy(dtype=float, copy=True)
        col[~np.isfinite(col)] = m
        X[c] = col
    return X.to_numpy(dtype=np.float32), medians


def _binary_metrics(y: np.ndarray, score: np.ndarray, threshold: float = 0.5) -> dict:
    pred = (score >= threshold).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4), "tp": tp, "fp": fp, "fn": fn}


# --------------------------------------------------------------------- alerts
def emit_alerts(pairs: pd.DataFrame, scores: np.ndarray, threshold: float = 0.9,
                detector: str = "ml.beacon") -> list[Alert]:
    """Pair rows + scores -> Alert objects (same envelope as every detector)."""
    alerts: list[Alert] = []
    feats = {c: "pair" for c in BEACON_FEATURES}
    for i in range(len(pairs)):
        s = float(scores[i])
        if s < threshold:
            continue
        row = pairs.iloc[i]
        ev = [
            EvidenceItem(condition="beacon_score", operator=">=", observed=round(s, 4),
                         threshold=threshold, unit="score",
                         description=f"beacon score {s:.2f} (periodicity model)"),
        ]
        for c in ("dt_cv", "dt_mean", "dt_scores", "n_flows", "span_s"):
            v = row.get(c)
            try:
                fv = float(v)
            except (TypeError, ValueError):
                fv = float("nan")
            if not np.isfinite(fv):
                continue
            ev.append(EvidenceItem(
                condition=c, operator="feature", observed=round(fv, 4),
                threshold=FALLBACK_RULE.get(c, "learned"),
                description=f"{c}={fv:.3g}", unit=feats[c],
            ))
        ts_first = row.get("ts_first")
        try:
            ts_iso = pd.to_datetime(float(ts_first), unit="s", utc=True).isoformat()
        except (TypeError, ValueError):
            ts_iso = str(ts_first or "")
        alerts.append(Alert(
            timestamp=ts_iso,
            threat_class="beacon",
            confidence=round(s, 4),
            evidence=ev,
            flow_id=None,
            key=f"{row.get('src_ip')}->{row.get('dst_ip')}:{row.get('dst_port')}",
            detector=detector,
            label=str(row.get("label")) if pd.notna(row.get("label")) else None,
        ))
    return alerts
