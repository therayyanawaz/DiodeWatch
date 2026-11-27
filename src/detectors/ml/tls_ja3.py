"""Encrypted-traffic (TLS) detector: JA3/JA3S watchlist + novelty.

Reads Zeek-style SSL session records (ssl.log in TSV or JSON, or equivalent
dicts) and flags suspicious TLS clients on two channels:

  1. Watchlist, exact JA3 hash match against the pinned abuse.ch SSLBL
     malicious-JA3 blacklist. Deterministic, auditable, and the "known
     malicious JA3s" requirement of the PS; honestly labelled as a lookup,
     not ML.

  2. Behavioral novelty, an IsolationForest over per-client-JA3 aggregates
     (connection count, distinct destinations, SNI-presence rate, distinct
     destination ports, connections per destination). Clients whose TLS
     behaviour is anomalous relative to the fitted baseline score high even
     when their fingerprint is unknown, the "behavioural anomalies" channel.
     Novelty is normalised against percentiles frozen from the *fit* set, so
     the same client scores the same whatever else is in the batch, and the
     layer reports `novelty_available: false` rather than a number when the
     baseline it was fitted on cannot discriminate (degenerate aggregates).

JA3/JA3S are metadata-only (ClientHello/ServerHello parameters), so this
respects the no-decryption constraint. Evaluation is a synthetic-plant
experiment (malicious-shaped clients injected into a benign mix) and is
labelled as such in the metrics file, no real-data claims we cannot back.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from src.alerts.schema import Alert, EvidenceItem

from .features import safe_median

TLS_FEATURES = ["n_conns", "n_dst", "sni_rate", "n_dst_ports", "conns_per_dst"]

REPO_ROOT = Path(__file__).resolve().parents[3]

# Committed, not fetched: data/ is git-ignored, so a watchlist that lives only
# there is empty on a fresh clone and the channel silently matches nothing.
# docs/evaluation/ already carries the pinned models for the same reason.
ABUSECH_JA3 = REPO_ROOT / "docs" / "evaluation" / "tls" / "ja3_fingerprints.csv"

NOVELTY_PARAMS = {"n_estimators": 150, "contamination": 0.02, "random_state": 42}

# Operating point on the frozen baseline scale: novelty 0.98 sits at the
# anomalous tail of the benign fit set (matching the 0.02 contamination the
# IsolationForest is fitted at). It is reachable, the previous 0.85 default
# was unreachable under the batch-relative normalization it replaced.
NOVELTY_THRESHOLD = 0.98


# --------------------------------------------------------------------- ingest
def load_ssl_log(path: str | Path) -> pd.DataFrame:
    """Parse a Zeek ssl.log (TSV with #fields header, or JSON lines).

    Returns columns: ts, src_ip, src_port, dst_ip, dst_port, ja3, ja3s, sni.
    Rows without a ja3 hash are dropped (they carry no fingerprint signal).
    """
    path = Path(path)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    fields: list[str] | None = None
    recs: list[dict] = []
    for ln in lines:
        if not ln.strip():
            continue
        if ln.startswith("#fields"):
            fields = ln.split("\t")[1:]
            continue
        if ln.startswith("#"):
            continue
        if fields is not None:
            vals = ln.split("\t")
            recs.append(dict(zip(fields, vals)))
        else:
            try:
                recs.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
    if not recs:
        return pd.DataFrame(columns=["ts", "src_ip", "src_port", "dst_ip",
                                     "dst_port", "ja3", "ja3s", "sni"])

    df = pd.DataFrame(recs)
    out = pd.DataFrame({
        "src_ip": df.get("id.orig_h", df.get("src_ip")),
        "src_port": pd.to_numeric(df.get("id.orig_p", df.get("src_port")),
                                  errors="coerce").fillna(0).astype(int),
        "dst_ip": df.get("id.resp_h", df.get("dst_ip")),
        "dst_port": pd.to_numeric(df.get("id.resp_p", df.get("dst_port")),
                                  errors="coerce").fillna(0).astype(int),
        "ja3": df.get("ja3", df.get("client_hash", df.get("ja3_hash"))),
        "ja3s": df.get("ja3s", df.get("server_hash", df.get("ja3s_hash"))),
        "sni": df.get("server_name", df.get("sni")),
    })
    out["ts"] = pd.to_numeric(df.get("ts", out.index), errors="coerce")
    out["ja3"] = out["ja3"].astype(str).str.strip().replace({"": None, "-": None,
                                                             "nan": None})
    out["sni"] = out["sni"].astype(str).str.strip().replace({"": None, "-": None})
    out = out.dropna(subset=["ja3"]).reset_index(drop=True)
    return out


# --------------------------------------------------------------------- watchlist
def load_watchlist(path: Path = ABUSECH_JA3) -> dict[str, str]:
    """abuse.ch SSLBL ja3_fingerprints.csv -> {ja3_hash: source_tag}."""
    wl: dict[str, str] = {}
    if not path.exists():
        return wl
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = [p.strip() for p in ln.split(",")]
        if len(parts) >= 1 and len(parts[0]) == 32 and all(
                c in "0123456789abcdefABCDEF" for c in parts[0]):
            wl[parts[0].lower()] = "abuse.ch_SSLBL"
    return wl


# --------------------------------------------------------------------- novelty
def client_aggregates(df: pd.DataFrame) -> pd.DataFrame:
    """One row per (src_ip, ja3): behavioural TLS profile of that client."""
    if "label" not in df.columns:
        df = df.copy()
        df["label"] = None
    g = df.groupby(["src_ip", "ja3"], sort=False)
    agg = g.agg(
        n_conns=("dst_ip", "size"),
        n_dst=("dst_ip", "nunique"),
        sni_rate=("sni", lambda s: float(s.notna().mean())),
        n_dst_ports=("dst_port", "nunique"),
        ts_first=("ts", "min"),
        ts_last=("ts", "max"),
        ja3s=("ja3s", "first"),
        label=("label", "first"),
    ).reset_index()
    agg["conns_per_dst"] = agg["n_conns"] / agg["n_dst"].replace(0, np.nan)
    return agg


@dataclass
class TlsModel:
    """Watchlist + fitted novelty detector.

    `nov_lo`/`nov_hi` are the 1st/99th percentiles of the *fit set's*
    decision_function values. Novelty is scored against those frozen bounds,
    so a client's score is a statement about the benign baseline and not
    about which other clients happen to be in the same batch.
    """
    watchlist: dict[str, str] = field(default_factory=dict)
    iso: IsolationForest | None = None
    medians: dict[str, float] = field(default_factory=dict)
    nov_lo: float | None = None
    nov_hi: float | None = None
    degenerate_baseline: bool = False

    # ------------------------------------------------------------------ io
    def save(self, model_dir: str | Path) -> Path:
        import joblib

        model_dir = Path(model_dir)
        model_dir.mkdir(parents=True, exist_ok=True)
        path = model_dir / "tls_novelty.joblib"
        joblib.dump({"watchlist": self.watchlist, "iso": self.iso,
                     "medians": self.medians,
                     "nov_lo": self.nov_lo, "nov_hi": self.nov_hi,
                     "degenerate_baseline": self.degenerate_baseline}, path)
        return path

    @classmethod
    def load(cls, model_dir: str | Path) -> TlsModel:
        import joblib

        path = Path(model_dir) / "tls_novelty.joblib"
        if not path.exists():
            # no artifact yet: watchlist-only mode (novelty disabled)
            return cls(watchlist=load_watchlist())
        blob = joblib.load(path)
        model = cls(watchlist=blob["watchlist"], iso=blob["iso"],
                    medians=blob["medians"])
        # a pre-anchor artifact has no frozen scale: refuse to score rather
        # than reproduce the old batch-relative numbers
        if blob.get("nov_hi") is None or blob.get("nov_lo") is None:
            model.degenerate_baseline = True
        else:
            model.nov_lo = float(blob["nov_lo"])
            model.nov_hi = float(blob["nov_hi"])
            model.degenerate_baseline = bool(blob.get("degenerate_baseline"))
        return model

    # -------------------------------------------------------------- scoring
    def score_clients(self, df: pd.DataFrame) -> pd.DataFrame:
        """Watchlist flag + novelty score per client aggregate row."""
        agg = client_aggregates(df)
        agg["watchlisted"] = agg["ja3"].str.lower().isin(self.watchlist)
        if not self.novelty_available():
            agg["novelty"] = np.nan
        else:
            X = agg.reindex(columns=TLS_FEATURES).apply(pd.to_numeric,
                                                        errors="coerce")
            for c in X.columns:
                m = self.medians.get(c, 0.0)
                col = X[c].to_numpy(dtype=float, copy=True)
                col[~np.isfinite(col)] = m
                X[c] = col
            dec = self.iso.decision_function(X.to_numpy(dtype=np.float32))
            # 0.0 = as normal as the benign 99th percentile, 1.0 = at or
            # beyond the benign 1st (i.e. most anomalous) percentile
            span = self.nov_hi - self.nov_lo
            agg["novelty"] = np.clip((self.nov_hi - dec) / span, 0.0, 1.0)
        return agg

    def novelty_available(self) -> bool:
        """True only when a fit baseline exists that can actually discriminate."""
        return (self.iso is not None and not self.degenerate_baseline
                and self.nov_hi is not None and self.nov_lo is not None
                and (self.nov_hi - self.nov_lo) > 0)

    def flag(self, df: pd.DataFrame, novelty_threshold: float = NOVELTY_THRESHOLD
             ) -> pd.DataFrame:
        """Rows of score_clients() that should alert (watchlist OR novelty)."""
        agg = self.score_clients(df)
        return agg[agg["watchlisted"]
                   | (agg["novelty"].fillna(0) >= novelty_threshold)]


def train_tls(ssl_frames: list[pd.DataFrame],
              model_dir: str | Path = "models",
              results_dir: str | Path = "results/ml",
              novelty_threshold: float = NOVELTY_THRESHOLD,
              ) -> tuple[TlsModel, dict]:
    """Fit the novelty baseline on benign-ish TLS client aggregates.

    `ssl_frames` are ssl-log frames (load_ssl_log output); rows carrying a
    watchlisted JA3 are excluded from the fit so known-malicious clients do
    not shape the baseline. Evaluation is an honest synthetic-plant
    experiment: watchlisted-JA3 clients with malware-ish shapes are injected
    into a holdout slice of the baseline and the flagged set is measured.
    """
    watchlist = load_watchlist()
    df = pd.concat([f for f in ssl_frames if len(f)], ignore_index=True)
    is_wl = df["ja3"].str.lower().isin(watchlist)
    base = df[~is_wl]

    cut = int(len(base) * 0.8)
    fit_df, eval_df = base.iloc[:cut], base.iloc[cut:]
    eval_df = eval_df.copy()
    eval_df["label"] = "baseline"

    agg_fit = client_aggregates(fit_df)
    X = agg_fit.reindex(columns=TLS_FEATURES).apply(pd.to_numeric, errors="coerce")
    medians = {c: safe_median(X[c]) for c in X.columns}
    for c in X.columns:
        col = X[c].to_numpy(dtype=float, copy=True)
        col[~np.isfinite(col)] = medians[c]
        X[c] = col

    iso = IsolationForest(**NOVELTY_PARAMS)
    iso.fit(X.to_numpy(dtype=np.float32))

    # Freeze the scale on the fit set: novelty is then read against the benign
    # baseline's own 1st/99th decision percentiles, never against the batch.
    ref = iso.decision_function(X.to_numpy(dtype=np.float32))
    nov_lo, nov_hi = (float(q) for q in np.quantile(ref, [0.01, 0.99]))
    # A baseline whose aggregates are all alike gives the model nothing to
    # discriminate on; scoring off a zero-width band would be noise.
    degenerate = not (nov_hi - nov_lo > 0)

    model = TlsModel(watchlist=watchlist, iso=iso, medians=medians,
                     nov_lo=nov_lo, nov_hi=nov_hi,
                     degenerate_baseline=degenerate)

    # ---- synthetic-plant evaluation on the untouched 20% slice -----------
    eval_agg = model.score_clients(eval_df)
    base_flag_rate = float((eval_agg["novelty"].fillna(0) >= novelty_threshold).mean())

    # planted clients get fresh source IPs so they aggregate independently
    planted = eval_df.copy()
    wl_hashes = sorted(watchlist) or ["0" * 32]
    rng = np.random.default_rng(42)
    n_plant = max(20, int(len(planted) * 0.05))
    take = rng.choice(len(planted), size=n_plant, replace=len(planted) < n_plant)
    planted = planted.iloc[take].copy().reset_index(drop=True)
    planted["src_ip"] = [f"10.255.{i // 256}.{i % 256}" for i in range(len(planted))]
    planted["ja3"] = [wl_hashes[i % len(wl_hashes)] for i in range(len(planted))]
    planted["sni"] = None  # malware usually skips SNI
    planted["label"] = "planted"
    mixed = pd.concat([eval_df, planted], ignore_index=True)
    mixed_agg = model.score_clients(mixed)

    y = mixed_agg["label"].isin(["planted"]).to_numpy(dtype=int)
    wl_only = mixed_agg["watchlisted"].to_numpy(dtype=bool)
    nov_only = (mixed_agg["novelty"].fillna(0).to_numpy()
                >= novelty_threshold)
    score = (wl_only | nov_only).astype(int)

    def _pr(flag: np.ndarray) -> dict:
        tp = int(((y == 1) & flag).sum())
        fp = int(((y == 0) & flag).sum())
        fn = int(((y == 1) & ~flag).sum())
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        return {"precision": round(prec, 4), "recall": round(rec, 4),
                "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
                "tp": tp, "fp": fp, "fn": fn}

    combined = _pr(score.astype(bool))
    watchlist_eval = _pr(wl_only)
    novelty_eval = _pr(nov_only)

    metrics = {
        "model": "JA3 watchlist (abuse.ch SSLBL) + IsolationForest novelty",
        "watchlist_size": len(watchlist),
        "watchlist_source": (ABUSECH_JA3.relative_to(REPO_ROOT).as_posix()
                             + " (pinned, offline)"),
        "n_fit_clients": len(agg_fit),
        "novelty_threshold": novelty_threshold,
        "novelty_scale": ("frozen fit-set percentiles: "
                          f"decision p1={round(nov_lo, 6)} "
                          f"p99={round(nov_hi, 6)}"),
        "novelty_available": model.novelty_available(),
        "baseline_flag_rate_on_real_eval": round(base_flag_rate, 5),
        "synthetic_plant_eval": {
            "note": ("planted = watchlisted-JA3 clients with malware-ish shapes "
                     "injected into the held-out slice; honest synthetic "
                     "evaluation, not real-data performance"),
            **combined,
            # reported per channel so a dead layer can never be credited for
            # a metric the other channel produced on its own
            "watchlist_only": watchlist_eval,
            "novelty_only": novelty_eval,
            "novelty_degenerate_baseline": degenerate,
        },
    }

    model.save(model_dir)
    out = Path(results_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "tls_metrics.json").write_text(json.dumps(metrics, indent=2))
    return model, metrics


# --------------------------------------------------------------------- alerts
def emit_alerts(agg: pd.DataFrame, detector: str = "ml.tls") -> list[Alert]:
    """Flagged client-aggregate rows -> Alert objects (shared envelope)."""
    alerts: list[Alert] = []
    for i in range(len(agg)):
        row = agg.iloc[i]
        ja3 = str(row["ja3"]).lower()
        wl = bool(row["watchlisted"])
        nov = row.get("novelty")
        nov = float(nov) if pd.notna(nov) else 0.0
        conf = 1.0 if wl else round(min(max(nov, 0.5), 1.0), 4)
        ev = [
            EvidenceItem(condition="ja3_watchlist" if wl else "tls_novelty",
                         operator="match" if wl else ">=",
                         observed=ja3 if wl else round(nov, 4),
                         threshold="abuse.ch SSLBL" if wl else str(NOVELTY_THRESHOLD),
                         unit="hash" if wl else "score",
                         description=(f"client fingerprint {ja3} is on the "
                                      "malicious-JA3 watchlist" if wl else
                                      f"TLS client behaviour novelty {nov:.2f}")),
        ]
        for c in ("n_conns", "n_dst", "sni_rate", "n_dst_ports", "conns_per_dst"):
            v = row.get(c)
            try:
                fv = float(v)
            except (TypeError, ValueError):
                fv = float("nan")
            if np.isfinite(fv):
                ev.append(EvidenceItem(
                    condition=c, operator="feature", observed=round(fv, 4),
                    threshold="baseline", description=f"{c}={fv:.3g}", unit="",
                ))
        try:
            ts_iso = pd.to_datetime(float(row.get("ts_first")), unit="s",
                                    utc=True).isoformat()
        except (TypeError, ValueError):
            ts_iso = ""
        alerts.append(Alert(
            timestamp=ts_iso,
            threat_class="tls_anomaly",
            confidence=conf,
            evidence=ev,
            flow_id=None,
            key=f"{row.get('src_ip')} (ja3={ja3[:12]}…)",
            detector=detector,
            label=str(row.get("label")) if pd.notna(row.get("label")) else None,
        ))
    return alerts
