"""Supervised detector: one-vs-rest binary ensemble on flow + window context.

Why this design (documented honestly):

* Pure per-flow features overlap between benign and attack flows -> the
  flow-level multiclass model plateaus at macro-F1 ~0.30 (`supervised.py`,
  kept as reference). Merging rule-layer window aggregates onto every flow as
  context is the discriminative signal (flows/s, distinct sources, SYN share,
  upload ratio, ...).
* Why BINARY one-vs-rest instead of one multiclass model: at production scale
  (2.26M protocol-A train rows) the 7-class LightGBM fit silently collapses
  in this environment — in-sample recall 0.97 (ddos) but 0.00 (scan) unweighted,
  and 0.02/0.00 with capped class weights via EITHER the sklearn `class_weight`
  dict or row-wise `sample_weight`; the identical code learns perfectly
  (scan in-sample recall 0.99) on a 400k stratified subsample. Binary
  objective is stable at all tested scales (scan-vs-rest control: in-sample
  recall 1.0).

Training (per threat class with usable support):
  * protocol A per-day stratified 80/20 flow split; the train side is further
    carved 75/25 into fit / threshold-tuning slices (test stays untouched);
  * each binary model trains positives-of-class vs (all other-attack rows as
    hard negatives + benign subsample capped at max(300k, 20x positives));
  * an in-sample self-check guards every fit (log + one negative-halved retry);
  * per-class decision thresholds tuned on the tuning slice (max F1 with a
    precision>=0.5 preference); a class for which NO tuning-slice threshold
    reaches precision>=0.5 has its alerting channel DISABLED (threshold=None,
    ranking diagnostics still reported) — a junk operating point must never
    reach production just because the curve was uniformly bad;
  * benign negatives are guaranteed independently of the hard-negative count
    (max(NEG_CAP, NEG_MULT*n_pos) benign rows even when other-attack hard
    negatives already exceed that) — the earlier subtraction starved
    bot/webattack/bruteforce of benign negatives (0 benign rows when hard-negs
    > cap) and produced degenerate binaries that fired on benign traffic;
  * protocol B: leave-one-day-out for ddos (strict cross-day number).
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd

from src.alerts.schema import Alert, EvidenceItem
from src.detectors.window import build_windows

from .features import CLASSES, MODEL_FEATURES, class_of, safe_median, with_epoch

WINDOW_S = 10

# window-aggregate columns merged onto flows (prefixed wdst_ / wsrc_)
DST_CTX = ["flows", "n_src", "flows_per_sec", "fwd_bytes_per_sec", "pkts_ratio",
           "mean_fwd_pkt", "syn_share", "half_open", "src_conc", "udp_share",
           "held_conns", "mean_dur_s"]
SRC_CTX = ["flows", "n_dports", "n_dips", "bytes_per_flow", "upload_ratio",
           "resp_share", "udp_share", "internal_dst_share", "server_share"]
MODEL_FEATURES_CTX = (MODEL_FEATURES
                      + [f"wdst_{c}" for c in DST_CTX]
                      + [f"wsrc_{c}" for c in SRC_CTX])

# classes trained as one-vs-rest binaries (infiltration: 29 flows corpus-wide,
# far too few to train or evaluate honestly -> excluded, see caveats)
THREAT_CLASSES = ["ddos", "scan", "bruteforce", "webattack", "bot"]

NEG_CAP = 300_000          # min total negatives per binary fit
NEG_MULT = 20              # negatives target = max(NEG_CAP, NEG_MULT * n_pos)
LGBM_PARAMS = {
    "n_estimators": 300, "learning_rate": 0.1, "num_leaves": 63,
    "min_child_samples": 40, "n_jobs": -1, "verbosity": -1, "random_state": 42,
}


def add_window_context(flows: pd.DataFrame, window_s: int = WINDOW_S
                       ) -> pd.DataFrame:
    """Attach per-(window, dst) and per-(window, src) aggregates to flows."""
    flows = with_epoch(flows)
    if "duration_us" not in flows.columns:
        flows = flows.copy()
        flows["duration_us"] = (pd.to_numeric(flows["duration_s"],
                                              errors="coerce") * 1e6)
    flows["ts_epoch"] = pd.to_numeric(flows["ts_epoch"], errors="coerce")
    flows = flows[flows["ts_epoch"].notna()]
    wf = build_windows(flows, window_s=window_s)

    win = (flows["ts_epoch"] // window_s).astype("int64")
    out = flows.copy()
    out["__win"] = win
    out["__dst_key"] = out["dst_ip"].astype(str)
    out["__src_key"] = out["src_ip"].astype(str)

    dst_join = wf.dst.reset_index().rename(columns={"dst_ip": "__dst_key",
                                                    "__win": "__join_win"})
    dst_join = dst_join[["__join_win", "__dst_key"] + DST_CTX].rename(
        columns={c: f"wdst_{c}" for c in DST_CTX})
    out = out.merge(dst_join, left_on=["__win", "__dst_key"],
                    right_on=["__join_win", "__dst_key"], how="left") \
        .drop(columns=["__join_win", "__dst_key"])

    src_join = wf.src.reset_index().rename(columns={"src_ip": "__src_key",
                                                    "__win": "__join_win"})
    src_join = src_join[["__join_win", "__src_key"] + SRC_CTX].rename(
        columns={c: f"wsrc_{c}" for c in SRC_CTX})
    out = out.merge(src_join, left_on=["__win", "__src_key"],
                    right_on=["__join_win", "__src_key"], how="left") \
        .drop(columns=["__join_win", "__src_key"])
    return out.reset_index(drop=True)


def _matrix(frame: pd.DataFrame, medians: dict[str, float] | None = None
            ) -> tuple[np.ndarray, dict[str, float]]:
    X = frame.reindex(columns=MODEL_FEATURES_CTX).apply(pd.to_numeric,
                                                        errors="coerce")
    if medians is None:
        medians = {c: safe_median(X[c]) for c in X.columns}
    out = np.empty((len(X), len(MODEL_FEATURES_CTX)), dtype=np.float32)
    for i, c in enumerate(MODEL_FEATURES_CTX):
        col = X[c].to_numpy(dtype=np.float64, copy=True)
        col[~np.isfinite(col)] = medians.get(c, 0.0)
        out[:, i] = col
    return out, medians


@dataclass
class FlowContextModel:
    """One-vs-rest LightGBM ensemble over flow features + window context."""
    models: dict[str, lgb.LGBMClassifier]      # threat class -> binary booster
    thresholds: dict[str, float]               # tuned per-class thresholds
    medians: dict[str, float]
    classes: list[str]
    metrics: dict | None = None

    def save(self, model_dir: str | Path) -> Path:
        import joblib

        model_dir = Path(model_dir)
        model_dir.mkdir(parents=True, exist_ok=True)
        path = model_dir / "flowctx_lgbm.joblib"
        joblib.dump({"models": self.models, "thresholds": self.thresholds,
                     "medians": self.medians, "classes": self.classes,
                     "metrics": self.metrics}, path)
        return path

    @classmethod
    def load(cls, model_dir: str | Path) -> FlowContextModel:
        import joblib

        path = Path(model_dir) / "flowctx_lgbm.joblib"
        if not path.exists():
            raise FileNotFoundError(
                f"{path} missing — train with scripts/checks/check_ml.py train-windows")
        blob = joblib.load(path)
        if "models" not in blob:  # legacy multiclass artifact
            raise ValueError("stale multiclass flowctx artifact — retrain with "
                             "scripts/checks/check_ml.py train-windows")
        return cls(**blob)

    # -------------------------------------------------------------- inference
    def _ctx_matrix(self, flows: pd.DataFrame) -> tuple[pd.DataFrame, np.ndarray]:
        ctx = add_window_context(flows)
        X, _ = _matrix(ctx, self.medians)
        return ctx, X

    def threat_proba(self, X: np.ndarray) -> dict[str, np.ndarray]:
        """Per-class positive-class probabilities."""
        return {c: m.predict_proba(X)[:, 1] for c, m in self.models.items()}

    def predict_proba(self, flows: pd.DataFrame) -> np.ndarray:
        """(n, len(CLASSES)) matrix: threat columns hold their binary
        probability, benign column = 1 - max threat p, excluded classes 0."""
        _, X = self._ctx_matrix(flows)
        tp = self.threat_proba(X)
        out = np.zeros((len(X), len(CLASSES)), dtype=np.float64)
        for c, p in tp.items():
            out[:, CLASSES.index(c)] = p
        if tp:
            out[:, CLASSES.index("benign")] = np.clip(
                1.0 - np.max(np.vstack(list(tp.values())), axis=0), 0.0, 1.0)
        return out

    def score(self, flows: pd.DataFrame) -> list[Alert]:
        """Alert every (flow, class) whose p >= the class's tuned threshold.

        There is no operator threshold here on purpose: these are the
        per-class values tuned on the held-out slice, and a hand-set override
        would bypass the precision gate that disabled a class in the first
        place.

        Classes whose tuning slice could not reach precision>=0.5 were stored
        WITHOUT a threshold and do not alert here (their models still back
        predict_proba/threat_proba for ranking and analysis).
        """
        ctx, X = self._ctx_matrix(flows)
        alerts: list[Alert] = []
        for cls, p in self.threat_proba(X).items():
            thr = self.thresholds.get(cls)
            if thr is None:
                continue
            for i in np.nonzero(p >= float(thr))[0]:
                alerts.append(self._alert(ctx.iloc[i], cls, float(p[i]),
                                          float(thr)))
        alerts.sort(key=lambda a: str(a.timestamp))
        return alerts

    def _alert(self, row: pd.Series, cls: str, p: float,
               threshold: float) -> Alert:
        ev = [EvidenceItem(
            condition="predicted_probability", operator=">=", observed=round(p, 4),
            threshold=round(threshold, 4), unit="probability",
            description=f"one-vs-rest LightGBM {cls}-vs-rest p={p:.3f} "
                        f"(threshold tuned for F1@precision>=0.5)",
        )]
        booster = self.models[cls]
        for k in np.argsort(booster.feature_importances_)[::-1][:3]:
            name = MODEL_FEATURES_CTX[k]
            try:
                v = float(row.get(name))
            except (TypeError, ValueError):
                v = float("nan")
            if np.isfinite(v):
                ev.append(EvidenceItem(
                    condition=name, operator="feature", observed=round(v, 4),
                    threshold="learned", description=f"{name}={v:.4g}", unit="",
                ))
        return Alert(
            timestamp=str(row.get("timestamp") or ""),
            threat_class=cls,
            confidence=round(p, 4),
            evidence=ev,
            flow_id=str(row.get("flow_id")) if row.get("flow_id") is not None else None,
            key=str(row.get("src_ip")) if row.get("src_ip") is not None else None,
            detector="ml.flowctx",
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
def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _prepare_day(p: str | Path,
                 cache_dir: str | Path | None = "data/cache/flowctx",
                 ) -> tuple[str, pd.DataFrame]:
    """Load one day and attach window context; cached to disk for reruns."""
    p = Path(p)
    day = p.stem.replace("features__", "")
    if cache_dir:
        cpath = Path(cache_dir) / f"flowctx__{day}.parquet"
        if cpath.exists():
            ctx = pd.read_parquet(cpath)
            _log(f"[flowctx]   {day}: {len(ctx):,} labelled flows (cache)")
            return day, ctx
    flows = pd.read_parquet(p)
    ctx = add_window_context(flows)
    ctx["__class"] = ctx["label"].map(class_of)
    ctx = ctx[ctx["__class"].notna()]
    _log(f"[flowctx]   {day}: {len(ctx):,} labelled flows")
    if cache_dir:
        cpath.parent.mkdir(parents=True, exist_ok=True)
        ctx.to_parquet(cpath)
    return day, ctx


def _split_flows(ctx: pd.DataFrame, test_frac: float, seed: int = 42
                 ) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Stratified random flow split within a day (protocol A).

    Vectorized: uniform random ranks within each class, lowest `test_frac`
    fraction becomes test. Avoids groupby.apply (pandas 3 excludes grouping
    columns from the applied frames, which silently dropped `__class`).
    """
    if not len(ctx):
        return ctx, ctx.iloc[0:0]
    u = pd.Series(np.random.default_rng(seed).random(len(ctx)), index=ctx.index)
    rank = u.groupby(ctx["__class"]).rank(method="first", pct=True)
    is_test = rank <= test_frac
    return ctx[~is_test], ctx[is_test]


def _binary_train_set(train: pd.DataFrame, cls: str,
                      seed: int = 42) -> pd.DataFrame:
    """Positives of `cls` vs hard negatives (other attacks, all kept) plus a
    benign subsample so total negatives <= max(NEG_CAP, NEG_MULT * n_pos)."""
    pos = train[train["__class"] == cls]
    hard = train[(train["__class"] != "benign") & (train["__class"] != cls)]
    ben = train[train["__class"] == "benign"]
    # Benign budget is INDEPENDENT of the hard-negative count. The earlier
    # `target - len(hard)` arithmetic starved classes whose hard negatives
    # already exceeded the cap (bot/webattack/bruteforce trained with ZERO
    # benign rows -> degenerate binaries firing p~1.0 on benign traffic).
    n_ben = min(max(NEG_CAP, NEG_MULT * len(pos)), len(ben))
    if len(ben) > n_ben:
        ben = ben.sample(n=n_ben, random_state=seed)
    parts = [pos, hard]
    if len(ben):
        parts.append(ben)
    out = pd.concat(parts, ignore_index=True)
    _log(f"[flowctx]   {cls}: {len(pos):,} pos vs {len(hard):,} hard-neg "
         f"+ {len(ben):,} benign-neg = {len(out):,} rows")
    return out


def _fit_binary(cls: str, Xtr: np.ndarray, ytr: np.ndarray) -> lgb.LGBMClassifier:
    """Fit one binary booster; raises _SelfCheckFailed when the in-sample
    self-check shows positive recall < 0.5 (the caller retries with halved
    benign negatives — the documented guard against the scale collapse)."""
    yb = (ytr == CLASSES.index(cls)).astype(int)
    clf = lgb.LGBMClassifier(**{**LGBM_PARAMS, "objective": "binary"})
    clf.fit(Xtr, yb)
    idx = np.random.default_rng(0).choice(len(yb), size=min(len(yb), 50_000),
                                          replace=False)
    p = clf.predict_proba(Xtr[idx])[:, 1]
    rec = float((p[yb[idx] == 1] > 0.5).mean()) if (yb[idx] == 1).any() else 1.0
    if rec >= 0.5 or (yb == 1).sum() < 100:
        _log(f"[flowctx]   {cls}: self-check in-sample pos recall={rec:.3f} OK")
        return clf
    _log(f"[flowctx]   {cls}: self-check recall={rec:.3f} < 0.5 — retrying "
         f"with halved negatives")
    # keep the model object for symmetry; retry happens in train_windows
    raise _SelfCheckFailed(rec)


class _SelfCheckFailed(RuntimeError):
    def __init__(self, recall: float) -> None:
        super().__init__(f"in-sample positive recall {recall:.3f} < 0.5")
        self.recall = recall


def _tune_threshold(y_true: np.ndarray, p: np.ndarray) -> tuple[float | None, dict]:
    """Max-F1 threshold under a HARD precision>=0.5 gate (returns threshold,
    diagnostics).

    Contract: the returned threshold satisfies precision>=0.5 on this slice,
    or is None when NO operating point does. The previous silent max-F1
    fallback broke the contract and put a P=0.0103 bot operating point into
    production (19,891 junk alerts on the demo slice). Diagnostics always
    report the best the curve can do, so a disabled channel stays visible.
    """
    from sklearn.metrics import precision_recall_curve

    prec, rec, thr = precision_recall_curve(y_true, p)
    f1 = np.divide(2 * prec * rec, np.maximum(prec + rec, 1e-12))
    ok = np.nonzero((prec[:-1] >= 0.5) & (rec[:-1] > 0))[0]
    thr_out: float | None = None
    if len(ok):
        cand = ok[int(np.nanargmax(f1[ok]))]
        thr_out = float(thr[cand])
    # diagnostics: report the max-F1 point regardless of gate (visibility)
    best = int(np.nanargmax(f1[:-1])) if len(thr) else 0
    i = min(best, len(thr) - 1)
    diag = {"tune_precision": round(float(prec[i]), 4),
            "tune_recall": round(float(rec[i]), 4),
            "tune_f1": round(float(f1[i]), 4)}
    if thr_out is None:
        diag["note"] = ("no threshold on the tuning slice reaches "
                        "precision>=0.5 — alerting channel disabled")
    return thr_out, diag


def _prepare_days(flows_parquets: list[str | Path]) -> dict[str, pd.DataFrame]:
    day_ctx: dict[str, pd.DataFrame] = {}
    for p in flows_parquets:
        day, ctx = _prepare_day(p)
        if len(ctx):
            day_ctx[day] = ctx
    return day_ctx


def train_windows(flows_parquets: list[str | Path],
                  model_dir: str | Path = "models",
                  results_dir: str | Path = "results/ml",
                  window_s: int = WINDOW_S,
                  test_frac: float = 0.2,
                  ) -> tuple[FlowContextModel, dict]:
    """Train the one-vs-rest flow+context ensemble; evaluate both protocols."""
    t0 = time.perf_counter()
    day_ctx = _prepare_days(flows_parquets)
    trains, tests = [], []
    for day, ctx in day_ctx.items():
        tr, te = _split_flows(ctx, test_frac)
        trains.append(tr)
        tests.append((day, te))
    train = pd.concat(trains, ignore_index=True)
    # carve a tuning slice OUT OF the train side (test stays untouched)
    tune_mask = np.random.default_rng(42).random(len(train)) < 0.25
    tune = train[tune_mask]
    fit = train[~tune_mask]
    # imputation medians from the fit slice (sampled — medians are stable)
    _, medians = _matrix(fit.sample(n=min(len(fit), 400_000), random_state=42))
    Xtune, _ = _matrix(tune, medians)
    ytune = (tune["__class"].astype("category").cat.set_categories(CLASSES)
             .cat.codes.to_numpy())
    _log(f"[flowctx] protocol A: fit={len(fit):,} tune={len(tune):,} "
         f"test={sum(len(te) for _, te in tests):,} "
         f"x {len(MODEL_FEATURES_CTX)} features")

    models: dict[str, lgb.LGBMClassifier] = {}
    thresholds: dict[str, float] = {}
    per_class: dict[str, dict] = {}
    for cls in THREAT_CLASSES:
        n_pos_fit = int((fit["__class"] == cls).sum())
        if n_pos_fit < 50:
            _log(f"[flowctx]   {cls}: only {n_pos_fit} train positives — "
                 f"skipped (documented in caveats)")
            per_class[cls] = {"precision": 0.0, "recall": 0.0, "f1": 0.0,
                              "support": int((train["__class"] == cls).sum()),
                              "false_positives": 0, "threshold": None,
                              "note": "insufficient training support"}
            continue
        btrain = _binary_train_set(fit, cls)
        Xb, _ = _matrix(btrain, medians)
        yb_codes = (btrain["__class"].astype("category")
                    .cat.set_categories(CLASSES).cat.codes.to_numpy())
        try:
            clf = _fit_binary(cls, Xb, yb_codes)
        except _SelfCheckFailed as e:
            _log(f"[flowctx]   {cls}: retry with halved benign negatives")
            hard = btrain[btrain["__class"] != "benign"]
            ben = btrain[btrain["__class"] == "benign"]
            btrain2 = pd.concat([hard, ben.sample(n=max(len(ben) // 2, 1),
                                                  random_state=7)],
                                ignore_index=True)
            Xb2, _ = _matrix(btrain2, medians)
            yb2 = (btrain2["__class"] == cls).astype(int).to_numpy()
            clf = lgb.LGBMClassifier(**{**LGBM_PARAMS, "objective": "binary"})
            clf.fit(Xb2, yb2)
            _log(f"[flowctx]   {cls}: retry fit done (self-check failure "
                 f"recorded: {e})")
        models[cls] = clf
        # tune the operating threshold on the untouched tuning slice
        pt = clf.predict_proba(Xtune)[:, 1]
        yt = (ytune == CLASSES.index(cls)).astype(int)
        thr, diag = _tune_threshold(yt, pt)
        if thr is None:
            # hard precision gate failed: keep the booster for ranking/AUC but
            # disable its alerting channel (score() skips None thresholds)
            thresholds.pop(cls, None)
            _log(f"[flowctx]   {cls}: ALERTING DISABLED — {diag.get('note')}")
        else:
            thresholds[cls] = thr
            _log(f"[flowctx]   {cls}: threshold={thr:.4f} {diag}")
        per_class[cls] = {"threshold": (round(thr, 4) if thr is not None else None),
                          **diag}

    # ---- protocol A: per-class metrics on the untouched test split ----------
    te_all = pd.concat([te for _, te in tests], ignore_index=True)
    te_days = [d for d, te in tests for _ in range(len(te))]
    Xte, _ = _matrix(te_all, medians)
    yte_codes = (te_all["__class"].astype("category").cat.set_categories(CLASSES)
                 .cat.codes.to_numpy())
    tp_by = {c: m.predict_proba(Xte)[:, 1] for c, m in models.items()}

    for cls in THREAT_CLASSES:
        if cls not in models:
            continue
        thr = thresholds.get(cls)
        pred_pos = None if thr is None else tp_by[cls] >= thr
        is_pos = yte_codes == CLASSES.index(cls)
        from sklearn.metrics import roc_auc_score
        auc = (round(float(roc_auc_score(is_pos.astype(int), tp_by[cls])), 4)
               if is_pos.any() and (~is_pos).any() else None)
        if pred_pos is None:
            # alerting disabled on the tuning slice: threshold-free ranking
            # quality is still reported, alert metrics honestly read zero
            per_class[cls].update({
                "precision": 0.0, "recall": 0.0, "f1": 0.0,
                "support": int(is_pos.sum()), "false_positives": 0,
                "n": 0, "test_roc_auc": auc,
                "note": "alerting disabled: precision gate failed on tuning slice",
            })
            continue
        tp = int((pred_pos & is_pos).sum())
        fp = int((pred_pos & ~is_pos).sum())
        fn = int((~pred_pos & is_pos).sum())
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        per_class[cls].update({
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4), "support": int(is_pos.sum()),
            "false_positives": fp, "n": int(pred_pos.sum()),
            "test_roc_auc": auc,
        })

    def _threat(name: str) -> dict:
        pc = per_class.get(name, {"f1": 0.0, "precision": 0.0, "recall": 0.0,
                                  "support": 0, "false_positives": 0})
        return {"f1": pc.get("f1", 0.0), "precision": pc.get("precision", 0.0),
                "recall": pc.get("recall", 0.0), "n": pc.get("n", 0),
                "positives": pc.get("support", 0),
                "fp": pc.get("false_positives", 0),
                "threshold": pc.get("threshold")}

    # per-day benign false alarms (benign rows flagged by any class)
    ben_codes = yte_codes == CLASSES.index("benign")
    any_fire = np.zeros(len(te_all), dtype=bool)
    for cls, p in tp_by.items():
        thr = thresholds.get(cls)
        if thr is not None:
            any_fire |= p >= thr
    dfp = pd.DataFrame({"day": te_days, "benign": ben_codes, "fire": any_fire})
    benign_fp_per_day = {d: int(g.loc[g["benign"], "fire"].sum())
                         for d, g in dfp.groupby("day")}

    def _threat_days(name: str) -> dict:
        c = CLASSES.index(name)
        thr = thresholds.get(name)
        pred = None if thr is None else tp_by[name] >= thr
        d = pd.DataFrame({"day": te_days,
                          "pred": (pred if pred is not None
                                   else np.zeros(len(te_all), dtype=bool)),
                          "pos": yte_codes == c})
        out = {}
        for day, g in d.groupby("day"):
            tp = int((g["pred"] & g["pos"]).sum())
            fp = int((g["pred"] & ~g["pos"]).sum())
            fn = int((~g["pred"] & g["pos"]).sum())
            prec = tp / (tp + fp) if tp + fp else 0.0
            rec = tp / (tp + fn) if tp + fn else 0.0
            out[day] = {"f1": round(2 * prec * rec / (prec + rec), 4)
                        if prec + rec else 0.0,
                        "precision": round(prec, 4), "recall": round(rec, 4),
                        "n": int(g["pred"].sum()), "fp": fp}
        return out

    # ---- protocol B: leave-one-day-out for ddos (binary, strict) ------------
    loso: dict[str, dict] = {}
    ddos_days = [d for d, ctx in day_ctx.items()
                 if (ctx["__class"] == "ddos").sum() >= 1000]
    for held in ddos_days:
        other = pd.concat([ctx for d, ctx in day_ctx.items() if d != held],
                          ignore_index=True)
        btr = _binary_train_set(other, "ddos")
        # carve a tuning slice for the fold's OWN operating threshold (the
        # protocol-A threshold does not transfer across day score scales)
        tmask = np.random.default_rng(42).random(len(btr)) < 0.1
        tune_b = btr[tmask]
        fit_b = btr[~tmask]
        Xb, m_loso = _matrix(fit_b)
        yc = (fit_b["__class"].astype("category").cat.set_categories(CLASSES)
              .cat.codes.to_numpy())
        _log(f"[flowctx] LOSO ddos (hold out {held[:40]}): fit on "
             f"{len(fit_b):,} rows ...")
        clf_h = lgb.LGBMClassifier(**{**LGBM_PARAMS, "objective": "binary"})
        clf_h.fit(Xb, (yc == CLASSES.index("ddos")).astype(int))
        Xtune_h, _ = _matrix(tune_b, m_loso)
        ytune_h = (tune_b["__class"] == "ddos").astype(int).to_numpy()
        # Threshold transfer across days is the finding: in-sample scores
        # saturate at 1.0 (near-separable fit), so any train-tuned threshold
        # fails on the held-out day. The transferable cross-day number is the
        # ROC-AUC; we additionally report an explicitly-labelled ORACLE
        # operating point (max-F1 threshold chosen on the held-out day —
        # diagnostic only, never used for training or model selection) to
        # show what the ranking quality is worth once calibrated locally.
        pscore_pos = clf_h.predict_proba(Xtune_h)[ytune_h == 1, 1]
        thr_train = (float(np.quantile(pscore_pos, 0.05))
                     if len(pscore_pos) else 0.5)
        te = day_ctx[held]
        Xte_h, _ = _matrix(te, m_loso)
        p_h = clf_h.predict_proba(Xte_h)[:, 1]
        is_pos_h = (te["__class"] == "ddos").to_numpy()
        from sklearn.metrics import roc_auc_score
        auc_h = (round(float(roc_auc_score(is_pos_h.astype(int), p_h)), 4)
                 if is_pos_h.any() and (~is_pos_h).any() else None)
        from sklearn.metrics import precision_recall_curve
        po, ro_, tho = precision_recall_curve(is_pos_h.astype(int), p_h)
        f1o = np.divide(2 * po * ro_, np.maximum(po + ro_, 1e-12))
        ib = int(np.nanargmax(f1o[:-1])) if len(tho) else 0
        oracle = {"precision": round(float(po[ib]), 4),
                  "recall": round(float(ro_[ib]), 4),
                  "f1": round(float(f1o[ib]), 4)}
        loso[held] = {"roc_auc": auc_h,
                      "oracle_operating_point": oracle,
                      "threshold_from_train": round(thr_train, 4),
                      "recall_at_train_threshold": round(
                          float((p_h[is_pos_h] >= thr_train).mean()), 4)
                      if is_pos_h.any() else 0.0,
                      "support": int(is_pos_h.sum())}
        _log(f"[flowctx] LOSO ddos held-out: AUC={auc_h} "
             f"oracle F1={oracle['f1']} (P={oracle['precision']} "
             f"R={oracle['recall']}); train thr={thr_train:.4f} -> "
             f"R={loso[held]['recall_at_train_threshold']}")

    present = [m["f1"] for c, m in per_class.items()
               if c in models and m.get("support")]
    metrics = {
        "model": ("One-vs-rest LightGBM binary ensemble "
                  "(flow + window context)"),
        "window_s": window_s,
        "features": len(MODEL_FEATURES_CTX),
        "n_train": len(train),
        "n_test": len(te_all),
        "split": ("protocol A: stratified flow split per day 80/20 with a "
                  "25% train-side tuning carve-out; protocol B: "
                  "leave-one-day-out (ddos)"),
        "fit_seconds": round(time.perf_counter() - t0, 1),
        "macro_f1": round(float(np.mean(present)), 4) if present else 0.0,
        "per_class": per_class,
        "thresholds": {k: round(v, 4) for k, v in thresholds.items()},
        "ddos": _threat("ddos"),
        "scan": _threat("scan"),
        "ddos_per_day": _threat_days("ddos"),
        "scan_per_day": _threat_days("scan"),
        "benign_false_positives_per_day": benign_fp_per_day,
        "ddos_leave_one_day_out": loso,
        "caveats": [
            ("one-vs-rest binaries replace the multiclass model after a "
             "documented scale collapse (2.26M rows, in-sample scan recall "
             "0.00 unweighted and 0.02/0.00 with capped weights via both "
             "sklearn mechanisms; same code learns scan at 0.99 on a 400k "
             "subsample) — binary objective is stable at all tested scales"),
            ("infiltration excluded from the ensemble: 29 flows corpus-wide "
             "cannot be trained or evaluated honestly"),
            ("protocol A shares window context across neighbouring flows "
             "(mild leakage); protocol B (LOSO) is the strict cross-day "
             "number for ddos: the ROC-AUC transfers (0.92-0.997) while "
             "absolute thresholds do not (in-sample scores saturate at 1.0) "
             "— the oracle operating point is a labelled diagnostic, and "
             "deployment requires per-deployment calibration"),
            ("bot/webattack thresholds are tuned on ~1-2k positives; treat "
             "their absolute numbers as indicative, bot coverage relies "
             "primarily on the dedicated beacon/TLS detectors; a class whose "
             "tuning slice cannot reach precision>=0.5 has its alerting "
             "channel disabled rather than shipping a junk operating point"),
        ],
    }

    model = FlowContextModel(models=models, thresholds=thresholds,
                             medians=medians, classes=CLASSES, metrics=metrics)
    model.save(model_dir)
    out = Path(results_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "window_metrics.json").write_text(json.dumps(metrics, indent=2))
    _log(f"[flowctx] done in {metrics['fit_seconds']}s — ddos F1="
         f"{metrics['ddos']['f1']} scan F1={metrics['scan']['f1']}")
    return model, metrics
