"""Full-corpus ("max") evaluation over every pinned flow corpus.

`bench_transfer.py` scores one hand-picked file per corpus and holds the whole
frame in memory. This driver walks every pinned file, streams CSVs in chunks,
attributes rule alerts with vectorized entity masks, and scores the gated ML
ensemble on the first N contiguous flows of each file (the same 200k cap the
ensemble already applies). It writes per-file and per-family aggregates.

Honesty rules, the reason this driver exists separately from the transfer bench:

* a channel is reported NOT EVALUABLE, never approximated, when the export
  lacks the columns it needs: CSE-CIC-IDS2018 has no identity columns, and the
  CTU-13 NetFlow export has no TCP flags and no directional counters;
* chunk boundaries restart the window canvas and the entity-attribution scope,
  so a window straddling a seam can differ from a globally bucketed one. The
  seam cost is disclosed with the chunk size and never counted as detector
  behaviour;
* labels absent from the corpus map are counted and reported per file (the
  transfer bench folds them into benign, which is why the UNSW-NB15 map lists
  every attack family explicitly instead of leaving them absent);
* every ML number carries its sample size: the first `--ml-rows` contiguous
  flows per file, never the whole corpus.

Usage:
    python -m scripts.benchmarks.bench_corpora --jobs 4
    python -m scripts.benchmarks.bench_corpora --only cic-ids2017 --limit-files 1
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

_SPEC = importlib.util.spec_from_file_location(
    "bench_transfer_shared", Path(__file__).with_name("bench_transfer.py"))
bt = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(bt)

from src.detectors.rules import make_rules, run_rules

RAW = REPO / "data" / "raw"
LEDGER = RAW / "corpus_ledger.json"
OUT = REPO / "results" / "transfer" / "max"

#: columns the canonical record needs; everything else is not read at all
WANT = {"flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "timestamp", "flow_duration", "duration_s", "fwd_pkts", "bwd_pkts",
        "fwd_bytes", "bwd_bytes", "fin_flags", "syn_flags", "rst_flags",
        "psh_flags", "ack_flags", "urg_flags", "label"}

UNSW_PROTO = {"tcp": 6, "udp": 17, "icmp": 1, "igmp": 2, "sctp": 132}


# --------------------------------------------------------------------------
# registry: one entry per pinned corpus family
# --------------------------------------------------------------------------
def _families() -> dict[str, dict]:
    return {
        "cic-ids2017": {
            "map_key": "cic-ids2017",
            "rules": True,
            "ml": True,
            "files": sorted((RAW / "cic2017").glob("*.parquet")),
            "note": "all 8 day-files (5 capture days), 85-column official schema; "
                    "ML in-sample: these days trained the shipped artifact",
        },
        "cic-ddos2019": {
            "map_key": "cic-ddos2019",
            "rules": True,
            "ml": True,
            "files": sorted((RAW / "ddos2019").glob("*/*.csv")),
            "note": "all 18 CSVs of the 01-12 and 03-11 collection days; ML "
                    "out-of-sample: the shipped artifact predates the Phase 2 "
                    "retraining and no published training claim covers this corpus",
        },
        "cic-ids2018": {
            "map_key": "cic-ids2018-nf-v2",
            "rules": False,
            "ml": True,
            "files": sorted((RAW / "ids2018").glob("*.csv")),
            "note": "all 10 TrafficForML days; no identity columns, so rules "
                    "are not evaluable; ML is out-of-sample for the shipped artifact",
        },
        "unsw-nb15": {
            "map_key": "unsw-nb15",
            "rules": False,
            "ml": True,
            "files": [RAW / "unsw" / "UNSW_NB15_training-set.csv"],
            "note": "training-set.csv, 175,341 flows; no identity columns, "
                    "never used in training, so the ML cell is out-of-sample",
        },
        "ctu-13": {
            "map_key": "ctu13-heldout",
            "rules": False,
            "ml": False,
            "files": sorted((RAW / "ctu13").glob("*.binetflow*")),
            "note": "all 13 scenarios; NetFlow export, neither flow channel applies",
        },
    }


# --------------------------------------------------------------------------
# corpus adapters (vectorized; no per-row Python strings)
# --------------------------------------------------------------------------
def _numeric(s: pd.Series) -> pd.Series:
    if pd.api.types.is_numeric_dtype(s.dtype):
        return s.astype("float64")
    return pd.to_numeric(s, errors="coerce")


def _pick(df: pd.DataFrame, names: tuple[str, ...], default):
    for n in names:
        if n in df.columns:
            return df[n]
    return pd.Series(default, index=df.index)


def _epoch_seconds(df: pd.DataFrame) -> pd.Series:
    """Flow start time in epoch seconds, NaN where unusable.

    `build_windows` drops NaN timestamps and counts them; a fabricated spread
    would invent window structure, so only a real clock is used here. The
    transfer bench falls back to a synthetic spread for the selftest corpus;
    real corpora always carry a timestamp column.
    """
    if "ts_epoch" in df.columns:
        return _numeric(df["ts_epoch"])
    if "timestamp" not in df.columns:
        return pd.Series(np.nan, index=df.index)
    raw = df["timestamp"]
    ts = pd.to_datetime(raw, errors="coerce", utc=True, format="mixed")
    # Subtract a fixed epoch instead of casting to int64: parquet stores
    # datetime64[us], so an int64 cast is NOT nanoseconds and dividing by 1e9
    # silently produced epoch/1000 (window structure still looked plausible).
    epoch = (ts - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()
    return epoch.astype("float64")


def canonical_frame(df: pd.DataFrame, name: str, offset: int) -> tuple[pd.DataFrame, bool]:
    """Build the unified canonical record from an already-normalized chunk.

    Identity-less corpora get the same deterministic stand-ins the transfer
    bench uses (`10.200.x.y` / `93.184.0.z`); they are only ever consumed by
    the per-flow ML channel, because the rules channel refuses to run without
    real identity. Corpora with no capture clock (UNSW-NB15) get a synthetic
    10 ms/flow clock, mirroring the transfer bench, and the caller records that
    the window context is ordered by row, not by capture time.
    """
    n = len(df)
    idx = np.arange(offset, offset + n)
    flows = pd.DataFrame(index=df.index)
    flows["flow_id"] = name + "#" + pd.Series(idx, index=df.index).astype(str)
    if "src_ip" in df.columns:
        flows["src_ip"] = df["src_ip"].astype(str)
    else:
        flows["src_ip"] = "10.200." + ((idx // 254) % 254).astype(str) + "." \
            + (idx % 254 + 1).astype(str)
    if "dst_ip" in df.columns:
        flows["dst_ip"] = df["dst_ip"].astype(str)
    else:
        flows["dst_ip"] = "93.184.0." + (idx % 8 + 1).astype(str)
    flows["src_port"] = _numeric(_pick(df, ("src_port",), 0)).fillna(0)
    flows["dst_port"] = _numeric(_pick(df, ("dst_port",), 80)).fillna(0)
    flows["protocol"] = _numeric(_pick(df, ("protocol",), 6)).fillna(6)
    flows["proto"] = df["proto"].astype(str) if "proto" in df.columns else "tcp"
    ts = _epoch_seconds(df)
    synthetic_clock = bool(ts.isna().all())
    if synthetic_clock:
        ts = pd.Series(1_499_268_000.0 + 0.01 * idx, index=df.index)
        # the ML channel rebuilds ts_epoch from this ISO string when the feature
        # frame drops the float column, so the clock has to exist as text too
        flows["timestamp"] = (pd.to_datetime(ts, unit="s")
                              .dt.strftime("%Y-%m-%dT%H:%M:%S.%f"))
    else:
        flows["timestamp"] = (df["timestamp"].astype(str)
                              if "timestamp" in df.columns else "")
    flows["ts_epoch"] = ts
    if "flow_duration" in df.columns:          # CIC convention: microseconds
        flows["duration_us"] = _numeric(df["flow_duration"]).fillna(1e6)
    elif "duration_s" in df.columns:           # UNSW-NB15: seconds
        flows["duration_us"] = _numeric(df["duration_s"]).fillna(1.0) * 1e6
    else:
        flows["duration_us"] = 1e6
    flows["fwd_pkts"] = _numeric(_pick(df, ("fwd_pkts",), 4)).fillna(4)
    flows["bwd_pkts"] = _numeric(_pick(df, ("bwd_pkts",), 4)).fillna(4)
    flows["fwd_bytes"] = _numeric(_pick(df, ("fwd_bytes",), 800)).fillna(800)
    flows["bwd_bytes"] = _numeric(_pick(df, ("bwd_bytes",), 2000)).fillna(2000)
    for col, default in (("fin_flags", 0), ("syn_flags", 0), ("rst_flags", 0),
                         ("psh_flags", 0), ("ack_flags", 0), ("urg_flags", 0)):
        flows[col] = _numeric(_pick(df, (col,), default)).fillna(default)
    return flows, synthetic_clock


def blank_mask(df: pd.DataFrame) -> pd.Series:
    """Rows with no value in any column: CSV padding, not unlabelled traffic.

    Measured over the whole chunk rather than a few named columns, because
    column selection only keeps the columns a channel consumes, and a row is
    padding exactly when nothing at all was written. The CIC-IDS2017
    Thursday-Morning export carries 288,602 such rows (458,968 rows for 170,366
    flows); counted as flows they would enter the benign denominator as silent
    true negatives, so they are dropped and reported separately.
    """
    return df.isna().all(axis=1)


def label_truth(df: pd.DataFrame, family: str, label_map: dict) -> tuple[np.ndarray, dict]:
    """Map the corpus label column onto the canonical axis.

    UNSW-NB15 carries a binary `label` plus the multi-class `attack_cat`; the
    latter is what the canonical axis needs (a binary 0/1 split cannot tell a
    DoS from a fuzzer). Every other corpus uses `label`.

    A label absent from the map becomes 'unmapped', never benign. Otherwise an
    attack family the register has never seen would enter the benign
    denominator as a true negative and turn detector hits into false positives.
    Rows mapped to 'unmapped' are truth we cannot score: they stay in the
    alert/context computation but are excluded from every metric.
    """
    if family == "unsw-nb15" and "attack_cat" in df.columns:
        raw = df["attack_cat"]
    else:
        raw = df["label"] if "label" in df.columns else pd.Series("?", index=df.index)
    s = raw.fillna("?").astype(str).str.strip()
    mapped = s.map(label_map)
    unmapped = mapped.isna()
    counts = {str(k): int(v) for k, v in s[unmapped].value_counts().items()}
    return mapped.fillna("unmapped").to_numpy(dtype=object), counts


def rule_predictions_fast(flows: pd.DataFrame, window_s: int,
                          rules: list | None = None,
                          ) -> tuple[np.ndarray, list]:
    """Rule layer -> window-scoped flow classes, vectorized.

    Same attribution as bench_transfer.attribute_alerts: an alert labels only
    its own entity inside its own window, later alerts winning. The old
    whole-file endpoint mask painted hours of unrelated traffic with one alert
    and turned benign flows into detector false positives.

    Passing one rule list across every chunk of a file preserves the DDoS
    rule's online baseline; a fresh list per chunk would reset it at each seam.
    """
    alerts = run_rules(flows, rules=rules, window_s=window_s)
    pred = np.asarray(bt.attribute_alerts(flows, alerts, window_s=window_s),
                      dtype=object)
    return pred, alerts


# --------------------------------------------------------------------------
# metrics accumulated over chunks (never a Python list of predictions)
# --------------------------------------------------------------------------
class Counts:
    """Confusion counts per class, merged across chunks and files."""

    def __init__(self) -> None:
        self.tp: dict[str, int] = {}
        self.fp: dict[str, int] = {}
        self.fn: dict[str, int] = {}
        self.support: dict[str, int] = {}
        self.n = 0

    def add(self, y: np.ndarray, p: np.ndarray) -> None:
        self.n += len(y)
        for c in set(np.unique(y)).union(np.unique(p)):
            c = str(c)
            yc = y == c
            pc = p == c
            self.support[c] = self.support.get(c, 0) + int(yc.sum())
            self.tp[c] = self.tp.get(c, 0) + int((yc & pc).sum())
            self.fp[c] = self.fp.get(c, 0) + int((~yc & pc).sum())
            self.fn[c] = self.fn.get(c, 0) + int((yc & ~pc).sum())

    def merge(self, other: Counts) -> None:
        self.n += other.n
        for attr in ("tp", "fp", "fn", "support"):
            mine = getattr(self, attr)
            for k, v in getattr(other, attr).items():
                mine[k] = mine.get(k, 0) + v

    def metrics(self) -> dict:
        per_class: dict[str, dict] = {}
        tp_all = fp_all = fn_all = 0
        for c in sorted(set(self.support) | set(self.tp)):
            tp = self.tp.get(c, 0)
            fp = self.fp.get(c, 0)
            fn = self.fn.get(c, 0)
            support = self.support.get(c, 0)
            if not support and not tp and not fp:
                continue
            prec = tp / (tp + fp) if tp + fp else None
            rec = tp / (tp + fn) if tp + fn else None
            f1 = (2 * prec * rec / (prec + rec)) if prec and rec else 0.0
            per_class[c] = {"precision": round(prec, 6) if prec is not None else None,
                            "recall": round(rec, 6) if rec is not None else None,
                            "f1": round(f1, 6), "support": support}
            if c != "benign":
                tp_all, fp_all, fn_all = tp_all + tp, fp_all + fp, fn_all + fn
        micro = (2 * tp_all / (2 * tp_all + fp_all + fn_all)
                 if (2 * tp_all + fp_all + fn_all) else None)
        f1s = [v["f1"] for v in per_class.values() if v["support"]]
        macro = round(sum(f1s) / len(f1s), 6) if f1s else None
        n_benign = self.support.get("benign", 0)
        # benign FPR = benign flows predicted as another class; for the benign
        # class that is its false-negative count, not its false-positive count
        # (p==benign with y!=benign, which is an attack called benign).
        fp_benign = self.support.get("benign", 0) - self.tp.get("benign", 0)
        fpr = fp_benign / n_benign if n_benign else None
        return {
            "per_class": per_class,
            "macro_f1": macro,
            "micro_f1": round(micro, 6) if micro is not None else None,
            "fpr": {"benign_flows": n_benign, "false_positives": fp_benign,
                    "fpr": round(fpr, 8) if fpr is not None else None,
                    "passes_gate": fpr is not None
                    and fpr <= bt.GATES["benign_fpr_max"]},
        }

    def to_dict(self) -> dict:
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn,
                "support": self.support, "n": self.n}


def counts_from_dict(d: dict) -> Counts:
    c = Counts()
    c.tp = dict(d.get("tp", {}))
    c.fp = dict(d.get("fp", {}))
    c.fn = dict(d.get("fn", {}))
    c.support = dict(d.get("support", {}))
    c.n = int(d.get("n", 0))
    return c


# --------------------------------------------------------------------------
# file reading
# --------------------------------------------------------------------------
def _select_columns(path: Path) -> tuple[list[str], bool]:
    """Original header names whose normalized form is a canonical field.

    Reading 88 CIC columns to use 20 of them both wastes memory and forces
    object dtype on every column; the selection is computed from the header
    only (or the parquet schema)."""
    if path.suffix == ".parquet":
        try:
            import pyarrow.parquet as pq
            names = list(pq.ParquetFile(path).schema.names)
        except Exception:  # noqa: BLE001 - fall back to a full read
            return [], True
    else:
        names = list(pd.read_csv(path, nrows=0).columns)
    renamed = list(bt.normalize_columns(pd.DataFrame(columns=names)).columns)
    keep = [orig for orig, new in zip(names, renamed) if new in WANT]
    return keep, not keep


def _iter_chunks(path: Path, chunk: int, whole: bool = False):
    keep, fallback = _select_columns(path)
    use = None if (fallback or whole) else keep
    if path.suffix == ".parquet":
        yield pd.read_parquet(path, columns=use)
        return
    yield from pd.read_csv(path, chunksize=chunk, low_memory=False, usecols=use,
                           on_bad_lines="warn")


def model_provenance(model_dir: Path) -> dict:
    """Identity of the artifacts a run actually loaded (path, bytes, sha256)."""
    out: dict[str, dict] = {}
    for name in ("flowctx_lgbm.joblib", "tls_novelty.joblib",
                 "beacon_lgbm.joblib", "dga_lgbm.joblib"):
        p = Path(model_dir) / name
        if p.exists():
            data = p.read_bytes()
            out[name] = {"bytes": len(data),
                         "sha256": hashlib.sha256(data).hexdigest()}
    return out


# --------------------------------------------------------------------------
# one file
# --------------------------------------------------------------------------
def evaluate_file(job: dict) -> dict:
    t0 = time.time()
    path = Path(job["path"])
    name = job["name"]
    family = job["family"]
    label_map = bt.resolve_label_map(job["map_key"], None)
    counts = Counts()
    unmapped: dict[str, int] = {}
    alert_counts: dict[str, int] = {}
    alert_acc = bt.AlertCounts()
    ml_frames: list[pd.DataFrame] = []
    ml_truth: list[np.ndarray] = []
    ml_scored: list[np.ndarray] = []
    n = 0
    n_blank = 0
    n_excluded = 0
    n_ts_dropped = 0
    n_ml_no_clock = 0
    synthetic_clock = False
    error: str | None = None
    rule_engine = make_rules() if job["rules"] else None
    try:
        if not job["rules"] and not job["ml"]:
            return _cell(job, job.get("total_rows") or 0, None, unmapped,
                         alert_counts, None, None, t0, None)
        for df in _iter_chunks(path, job["chunk"], whole=(family == "unsw-nb15")):
            df = bt.normalize_columns(df)
            if family == "unsw-nb15":
                df = _unsw_adapter(df)
            blank = blank_mask(df)
            if blank.any():
                n_blank += int(blank.sum())
                df = df.loc[~blank]
            y, unm = label_truth(df, family, label_map)
            scored = y != "unmapped"
            n_excluded += int((~scored).sum())
            for k, v in unm.items():
                unmapped[k] = unmapped.get(k, 0) + v
            need_ml = job["ml"] and n < job["ml_rows"]
            if job["rules"] or need_ml:
                flows, synth = canonical_frame(df, name, n)
                synthetic_clock = synthetic_clock or synth
            else:
                flows = None
            if job["rules"] and flows is not None:
                before = int(flows["ts_epoch"].isna().sum())
                n_ts_dropped += before
                pred, alerts = rule_predictions_fast(
                    flows, job["window_s"], rule_engine)
                counts.add(y[scored], pred[scored])
                alert_acc.add(alerts, flows, y, job["window_s"])
                for a in alerts:
                    alert_counts[a.threat_class] = alert_counts.get(a.threat_class, 0) + 1
            if need_ml and flows is not None:
                take = min(job["ml_rows"] - sum(len(f) for f in ml_frames), len(flows))
                if take > 0:
                    sub = flows.iloc[:take]
                    # add_window_context drops rows without a usable clock, so
                    # they must leave the truth row too; keeping 200,000 truth
                    # labels against 199,992 predictions misaligned silently.
                    ok = sub["ts_epoch"].notna().to_numpy()
                    if not ok.all():
                        n_ml_no_clock += int((~ok).sum())
                        sub = sub.loc[ok]
                    ml_frames.append(sub)
                    ml_truth.append(y[:take][ok])
                    ml_scored.append(scored[:take][ok])
            n += len(df)
            if not job["rules"] and job["ml"] and sum(len(f) for f in ml_frames) >= job["ml_rows"]:
                break
    except Exception as exc:  # noqa: BLE001 - one bad file must not kill the pass
        error = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()
    total = n if job["rules"] else (job.get("total_rows") or n)

    ml_cell = None
    psi_cell = None
    if ml_frames and error is None:
        ml_frame = pd.concat(ml_frames, ignore_index=True)
        y_ml = np.concatenate(ml_truth)[:len(ml_frame)]
        keep_ml = np.concatenate(ml_scored)[:len(ml_frame)]
        from src.features.engine import build_features
        from src.features.specs import FUTURE_NAMES

        feats = build_features(ml_frame)
        ml = bt.ml_predictions(feats, Path(job["model_dir"]))
        if ml["predictions"] is not None:
            ml_pred = np.array([bt._map_ml_class(p) for p in ml["predictions"]],
                               dtype=object)
            if len(ml_pred) != len(y_ml):
                raise ValueError(
                    f"{len(y_ml):,} truth rows but {len(ml_pred):,} ML "
                    f"predictions; refusing to score a misaligned frame")
            ml_counts = Counts()
            ml_counts.add(y_ml[keep_ml], ml_pred[keep_ml])
            ml_cell = {"channel": ml["channel"],
                       "n": int(keep_ml.sum()),
                       "prefix_flows": len(ml_frame),
                       "dropped_no_clock": n_ml_no_clock,
                       "counts": ml_counts.to_dict(),
                       "features_not_computed": [n for n in FUTURE_NAMES
                                                 if n not in feats.columns],
                       **ml_counts.metrics()}
        else:
            ml_cell = {"channel": None, "error": ml["error"] or "fail-closed"}
        src = bt._source_reference()
        psi_cell = {col: bt.psi(src[col].to_numpy(),
                                ml_frame[col].to_numpy(dtype=float))
                    for col in ("fwd_pkts", "fwd_bytes", "duration_us")
                    if col in src and col in ml_frame}
    return _cell(job, total or n, counts if job["rules"] else None, unmapped,
                 alert_counts, ml_cell, psi_cell, t0, error,
                 n_ts_dropped=n_ts_dropped, synthetic_clock=synthetic_clock,
                 n_excluded=n_excluded, n_blank=n_blank,
                 alert_acc=alert_acc if job["rules"] else None)


def _unsw_adapter(df: pd.DataFrame) -> pd.DataFrame:
    """UNSW-NB15 -> canonical input columns (seconds -> µs, proto names)."""
    out = df
    out["duration_s"] = _numeric(out["dur"])
    out["fwd_pkts"] = _numeric(out["spkts"])
    out["bwd_pkts"] = _numeric(out["dpkts"])
    out["fwd_bytes"] = _numeric(out["sbytes"])
    out["bwd_bytes"] = _numeric(out["dbytes"])
    out["protocol"] = out["proto"].astype(str).str.lower().map(UNSW_PROTO).fillna(0)
    return out


def _cell(job: dict, n_flows: int, counts, unmapped, alert_counts, ml_cell,
          psi_cell, t0: float, error, n_ts_dropped: int = 0,
          synthetic_clock: bool = False, n_excluded: int = 0,
          n_blank: int = 0, alert_acc=None) -> dict:
    cell: dict = {
        "family": job["family"],
        "n_flows": int(n_flows),
        "unmapped_labels": unmapped,
        "rule_alerts": alert_counts,
        "excluded_unmapped_flows": int(n_excluded),
        "blank_rows": int(n_blank),
        "elapsed_s": round(time.time() - t0, 1),
    }
    if error:
        cell["error"] = error
    if not job["rules"]:
        cell["rules"] = {"error": job["rules_reason"] or "rules not evaluable"}
    elif counts is not None:
        cell["rules"] = counts.metrics()
        cell["rules"]["n"] = counts.n
        if alert_acc is not None:
            cell["rules"]["alert_metrics"] = alert_acc.metrics()
            cell["alert_counts"] = alert_acc.to_dict()
        cell["rule_counts"] = counts.to_dict()
        cell["ts_dropped"] = n_ts_dropped
    if ml_cell is not None:
        cell["ml"] = ml_cell
    elif job["ml"]:
        cell["ml"] = {"error": "ML channel not scored (no prefix or failed model)"}
    else:
        cell["ml"] = {"error": job["ml_reason"] or "ML not evaluable"}
    if psi_cell:
        cell["psi"] = psi_cell
    if synthetic_clock:
        cell["clock"] = "synthetic 10 ms/flow (export has no capture time)"
    return cell


# --------------------------------------------------------------------------
# aggregation + rendering
# --------------------------------------------------------------------------
def aggregate(cells: list[dict], family: str, meta: dict) -> dict:
    n = sum(c.get("n_flows", 0) for c in cells)
    unmapped: dict[str, int] = {}
    alerts: dict[str, int] = {}
    for c in cells:
        for k, v in c.get("unmapped_labels", {}).items():
            unmapped[k] = unmapped.get(k, 0) + v
        for k, v in c.get("rule_alerts", {}).items():
            alerts[k] = alerts.get(k, 0) + v
    out: dict = {"n_flows": n, "files": len(cells), "note": meta["note"],
                 "unmapped_labels": unmapped, "rule_alerts": alerts,
                 "excluded_unmapped_flows": sum(
                     c.get("excluded_unmapped_flows", 0) for c in cells),
                 "blank_rows": sum(c.get("blank_rows", 0) for c in cells)}
    ok_rules = [c for c in cells if c.get("rule_counts")]
    if ok_rules:
        merged = Counts()
        for c in ok_rules:
            merged.merge(counts_from_dict(c["rule_counts"]))
        m = merged.metrics()
        m["n"] = merged.n
        m["files"] = len(ok_rules)
        alert_cells = [c for c in ok_rules if c.get("alert_counts")]
        if alert_cells:
            acc = bt.AlertCounts()
            for c in alert_cells:
                acc.merge(bt.AlertCounts.from_dict(c["alert_counts"]))
            m["alert_metrics"] = acc.metrics()
        out["rules"] = m
    else:
        out["rules"] = {"error": cells[0]["rules"].get("error") if cells else
                        "no file evaluated"}
    ml_cells = [c for c in cells if c.get("ml") and c["ml"].get("counts")]
    if ml_cells:
        merged = Counts()
        for c in ml_cells:
            merged.merge(counts_from_dict(c["ml"]["counts"]))
        m = merged.metrics()
        m["n"] = merged.n
        m["files"] = len(ml_cells)
        m["channel"] = ml_cells[0]["ml"].get("channel")
        m["prefix_flows"] = sum(c["ml"].get("prefix_flows", 0) for c in ml_cells)
        m["dropped_no_clock"] = sum(c["ml"].get("dropped_no_clock", 0)
                                    for c in ml_cells)
        out["ml"] = m
    elif any(c.get("ml") for c in cells):
        out["ml"] = cells[0]["ml"]
    return out


def render(results: dict[str, dict], checks: list[dict], meta: dict) -> str:
    lines = ["# Max-scale evaluation, every pinned flow corpus",
             "",
             (f"Every corpus file on disk scored at its full row count, with the "
              f"rule layer streamed in {meta['chunk']:,}-flow chunks and the ML "
              f"channel on the first {meta['ml_rows']:,} contiguous flows of each "
              f"file. Rules never train, though the CIC-IDS2017 thresholds are "
              f"calibrated on its Wednesday table; every other rule cell is "
              f"out-of-sample. The ML cells name their own status: in-sample where "
              f"the corpus trained the shipped artifact, out-of-sample where it "
              f"never did. Artifacts: "
              + (", ".join(f"`{k}` {v['sha256'][:12]}"
                           for k, v in (meta.get("models") or {}).items())
                 or "none found in the model directory") + "."),
             ""]
    for fam, cell in results.items():
        lines.append(f"## {fam}, {cell['n_flows']:,} flows in {cell['files']} files")
        lines.append(f"- {cell['note']}")
        if cell.get("unmapped_labels"):
            lines.append(f"- unmapped labels (reported, never merged): `{cell['unmapped_labels']}`")
        for det in ("rules", "ml"):
            c = cell.get(det) or {}
            if not c or c.get("error"):
                lines.append(f"- **{det}**: not evaluable, {c.get('error', 'n/a')}")
                continue
            lines.append(f"- **{det}** ({c.get('channel', 'window rules')}): macro F1 "
                         f"{c.get('macro_f1')}, micro F1 {c.get('micro_f1')}, "
                         f"scored {c.get('n', 0):,} flows")
            for cls, m in (c.get("per_class") or {}).items():
                if m.get("support"):
                    lines.append(f"    - {cls}: P {m['precision']}, R {m['recall']}, "
                                 f"F1 {m['f1']}, n {m['support']:,}")
            if c.get("fpr"):
                lines.append(f"    - benign FPR {c['fpr']['false_positives']:,}/"
                             f"{c['fpr']['benign_flows']:,} = {c['fpr']['fpr']} "
                             f"([{'PASS' if c['fpr']['passes_gate'] else 'FAIL'}])")
            am = c.get("alert_metrics") or {}
            if am:
                lines.append(
                    f"    - alerts: {am.get('scored', 0):,}/"
                    f"{am.get('alerts', 0):,} scored, exact precision "
                    f"{am.get('precision_exact')}, any-attack precision "
                    f"{am.get('precision_any_attack')}, "
                    f"{am.get('benign_alerts', 0):,} benign-only")
                units = ", ".join(
                    f"{k} {v['covered']:,}/{v['total']:,}"
                    for k, v in (am.get("unit_recall") or {}).items()
                    if v.get("total"))
                if units:
                    lines.append(f"    - alert recall (window x entity): {units}")
            if det == "ml" and c.get("prefix_flows"):
                lines.append(
                    f"    - ML prefix {c['prefix_flows']:,} flows (first "
                    f"{meta['ml_rows']:,} per file, {c.get('dropped_no_clock', 0):,} "
                    f"without a usable clock): a coverage slice, and a single "
                    f"file's prefix is often one class, so read the family line")
        if cell.get("psi"):
            top = sorted(cell["psi"].items(), key=lambda kv: -kv[1])[:3]
            lines.append("- drift (PSI, top-3): "
                         + ", ".join(f"{k} {v}" for k, v in top))
        lines.append("")
    lines.append("## Pre-committed gates (unchanged from bench_transfer)")
    for c in checks:
        lines.append(f"- [{'PASS' if c['passes'] else 'FAIL'}] {c['gate']} "
                     f"({c['corpus']}): {c['value']}")
    return "\n".join(lines) + "\n"


def gate_checks(results: dict[str, dict]) -> list[dict]:
    checks = []
    for fam, cell in results.items():
        rule = cell.get("rules") or {}
        if rule.get("error"):
            continue
        pc = rule.get("per_class", {})
        if "ddos" in pc:
            v = pc["ddos"]["f1"]
            checks.append({"gate": f"rule ddos F1 >= {bt.GATES['rule_ddos_f1_min']}",
                           "corpus": fam, "value": v,
                           "passes": v is not None and v >= bt.GATES["rule_ddos_f1_min"]})
        f = (rule.get("fpr") or {}).get("fpr")
        if f is not None:
            checks.append({"gate": f"benign FPR <= {bt.GATES['benign_fpr_max']}",
                           "corpus": fam, "value": f,
                           "passes": f <= bt.GATES["benign_fpr_max"]})
    return checks


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m scripts.benchmarks.bench_corpora",
        description="Full-corpus evaluation over every pinned flow corpus.")
    ap.add_argument("--only", nargs="*", default=None,
                    help="restrict to these family names")
    ap.add_argument("--jobs", type=int, default=4, help="parallel file workers")
    ap.add_argument("--chunk", type=int, default=250_000,
                    help="CSV rows per streamed chunk")
    ap.add_argument("--ml-rows", type=int, default=200_000,
                    help="contiguous flows per file scored by the ML channel")
    ap.add_argument("--model-dir", default=str(REPO / "models"))
    ap.add_argument("--window", type=int, default=10)
    ap.add_argument("--limit-files", type=int, default=None,
                    help="smoke runs: first N files per family")
    ap.add_argument("--no-ml", action="store_true", help="rules only")
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--from-json", default=None,
                    help="re-render summary.md from an existing max_results.json "
                         "instead of scoring (numbers are never recomputed)")
    args = ap.parse_args(argv)

    ledger: dict = {}
    if LEDGER.exists():
        ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    fams = _families()
    if args.only:
        fams = {k: v for k, v in fams.items() if k in args.only}
    if not fams:
        print("no family selected", file=sys.stderr)
        return 2

    if args.from_json:
        blob = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
        families = blob["families"]
        for fam, cell in families.items():
            if fam in fams:
                cell["note"] = fams[fam]["note"]
            ml = cell.get("ml") or {}
            if ml and not ml.get("channel"):
                seen = {c["ml"].get("channel") for c in blob["files"].values()
                        if c.get("family") == fam and (c.get("ml") or {}).get("channel")}
                if len(seen) == 1:
                    ml["channel"] = seen.pop()
        meta_prev = dict(blob["meta"])
        meta_prev["models"] = model_provenance(Path(args.model_dir)) or \
            meta_prev.get("models", {})
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "summary.md").write_text(
            render(families, blob["checks"], meta_prev), encoding="utf-8")
        print(f"[max] re-rendered {out_dir}/summary.md from {args.from_json}",
              file=sys.stderr)
        return 0 if all(c["passes"] for c in blob["checks"]) else 1

    jobs: list[dict] = []
    skipped: list[dict] = []
    for fam, meta in fams.items():
        files = meta["files"]
        if args.limit_files:
            files = files[:args.limit_files]
        if not files:
            skipped.append({"family": fam, "reason": "no files on disk"})
            continue
        for path in files:
            rel = str(path.relative_to(RAW)).replace("\\", "/")
            job = {
                "name": Path(rel).stem,
                "rel": rel,
                "family": fam,
                "map_key": meta["map_key"],
                "path": str(path),
                "rules": bool(meta["rules"]),
                "ml": bool(meta["ml"]) and not args.no_ml,
                "chunk": args.chunk,
                "ml_rows": args.ml_rows,
                "window_s": args.window,
                "model_dir": args.model_dir,
                "total_rows": ledger.get(rel, {}).get("rows"),
                "rules_reason": (None if meta["rules"] else
                                 "identity columns absent in export, entity-scoped "
                                 "rules not evaluable (reported, never faked)") if fam != "ctu-13"
                                else "NetFlow export has no TCP flags or directional "
                                     "counters, so neither flow channel is defined",
                "ml_reason": (None if meta["ml"] else
                              "directional flow statistics unavailable in this export"),
            }
            jobs.append(job)

    print(f"[max] {len(jobs)} files, {len(fams)} families, jobs={args.jobs}",
          file=sys.stderr)
    cells: dict[str, dict] = {}
    t0 = time.time()
    if args.jobs <= 1:
        for job in jobs:
            cells[job["rel"] + "|" + job["family"]] = evaluate_file(job)
            print(f"[max] {job['family']}/{job['name']} done", file=sys.stderr)
    else:
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            futures = {pool.submit(evaluate_file, j): j for j in jobs}
            for fut in as_completed(futures):
                j = futures[fut]
                try:
                    cells[j["rel"] + "|" + j["family"]] = fut.result()
                except Exception as exc:  # noqa: BLE001
                    cells[j["rel"] + "|" + j["family"]] = {
                        "family": j["family"], "n_flows": 0, "error": str(exc),
                        "rules": {"error": str(exc)}, "ml": {"error": str(exc)},
                        "unmapped_labels": {}, "rule_alerts": {}}
                c = cells[j["rel"] + "|" + j["family"]]
                print(f"[max] {j['family']}/{j['name']}: "
                      f"{c.get('n_flows', 0):,} flows, "
                      f"{c.get('elapsed_s', 0)}s", file=sys.stderr)

    families: dict[str, dict] = {}
    for fam, meta in fams.items():
        fam_cells = [c for c in cells.values() if c.get("family") == fam]
        if fam_cells:
            families[fam] = aggregate(fam_cells, fam, meta)
    checks = gate_checks(families)
    meta_out = {"mode": "max", "window_s": args.window, "chunk": args.chunk,
                "ml_rows": args.ml_rows, "jobs": args.jobs,
                "elapsed_s": round(time.time() - t0, 1),
                "model_dir": str(Path(args.model_dir).resolve()),
                "models": model_provenance(Path(args.model_dir)),
                "protocol": ("shipped models only, target labels used only for "
                             "scoring; streamed chunks restart the window canvas")}
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "max_results.json").write_text(json.dumps(
        {"meta": meta_out, "gates": bt.GATES, "checks": checks,
         "families": families, "files": cells, "skipped": skipped},
        indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    (out_dir / "summary.md").write_text(
        render(families, checks, meta_out), encoding="utf-8")
    print(f"[max] wrote {out_dir}/{{summary.md,max_results.json}} "
          f"in {meta_out['elapsed_s']}s", file=sys.stderr)
    for c in checks:
        print(f"  [{'PASS' if c['passes'] else 'FAIL'}] {c['gate']} "
              f"({c['corpus']}): {c['value']}", file=sys.stderr)
    return 0 if all(c["passes"] for c in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())