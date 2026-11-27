"""ML-detector tests: supervised, beacon, DGA, TLS + ml_engine.

Unit tests use tiny synthetic fixtures with known ground truth so they run in
seconds. Slice-level regression tests run the REAL corpora when present
(skipped otherwise): those are the honest end-to-end checks.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src.alerts.schema import validate_alert
from src.detectors.ml import beacon as bc
from src.detectors.ml import dga as dg
from src.detectors.ml import supervised_windows as sw
from src.detectors.ml import tls_ja3 as tls
from src.detectors.ml.features import (
    MODEL_FEATURES,
    class_of,
    numeric_matrix,
    split_temporal,
    with_epoch,
)
from src.detectors.ml.supervised import _num

REPO = Path(__file__).resolve().parents[2]
CTU_DIR = REPO / "data" / "raw" / "ctu13"


# ===================================================================== features
def test_class_of_mapping():
    assert class_of("BENIGN") == "benign"
    assert class_of("DoS Hulk") == "ddos"
    assert class_of("PortScan") == "scan"
    assert class_of("FTP-Patator") == "bruteforce"
    assert class_of("Web Attack \u2013 XSS") == "webattack"
    assert class_of("Bot") == "bot"
    assert class_of("Infiltration") == "infiltration"
    assert class_of(float("nan")) == "benign"
    assert class_of("Mystery Label") is None


def test_numeric_matrix_median_imputation():
    df = pd.DataFrame({
        "tot_bytes": [10.0, 20.0, np.nan],
        "avg_pkt_size": [np.inf, 5.0, np.nan],
    })
    X, medians = numeric_matrix(df)
    assert X.shape == (3, len(MODEL_FEATURES))  # always the full registry
    assert np.isfinite(X).all()
    assert medians["tot_bytes"] == 15.0
    X2, _ = numeric_matrix(df, medians=medians)
    assert np.allclose(X, X2)


def test_split_temporal_prefers_chronology():
    ts = np.arange(100)
    df = pd.DataFrame({"ts_epoch": ts, "v": ts})
    tr, te = split_temporal(df, test_frac=0.2)
    assert tr["ts_epoch"].max() <= te["ts_epoch"].min()
    assert len(tr) == 80 and len(te) == 20


def test_with_epoch_parses_iso():
    df = pd.DataFrame({"timestamp": ["2017-07-05 09:00:01", "bogus"]})
    out = with_epoch(df)
    assert np.isfinite(out["ts_epoch"].iloc[0])
    assert np.isnan(out["ts_epoch"].iloc[1])


# =================================================================== supervised
def _synthetic_features(n=400, seed=7) -> pd.DataFrame:
    """Benign-ish vs attack-ish flows, interleaved in time and separable on
    packet size + rate (chronological splits keep both classes in train/test)."""
    rng = np.random.default_rng(seed)
    n2 = n // 2
    benign = pd.DataFrame({
        "tot_bytes": rng.normal(800, 200, n2).clip(50),
        "tot_pkts": rng.integers(5, 20, n2),
        "duration_s": rng.uniform(0.5, 60, n2),
    })
    attack = pd.DataFrame({
        "tot_bytes": rng.normal(60, 15, n2).clip(5),
        "tot_pkts": rng.integers(1, 3, n2),
        "duration_s": rng.uniform(0.001, 0.2, n2),
    })
    benign["label"] = "BENIGN"
    attack["label"] = "DoS Hulk"
    ts = 1_500_000_000 + np.arange(n) * 7
    benign["ts_epoch"] = ts[:n2].astype(float)
    attack["ts_epoch"] = ts[n2:].astype(float)
    df = pd.concat([benign, attack], ignore_index=True)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)  # interleave
    df["timestamp"] = pd.to_datetime(df["ts_epoch"], unit="s").astype(str)
    df["flow_id"] = [f"f{i}" for i in range(n)]
    df["src_ip"] = "10.0.0.1"
    return df


def test_supervised_train_score(tmp_path):
    df = _synthetic_features()
    tr, te = df.iloc[:300], df.iloc[300:]
    # build a full-registry frame by filling remaining model features
    for c in MODEL_FEATURES:
        if c not in tr.columns:
            tr[c] = 0.0
            te[c] = 0.0
    from src.detectors.ml.supervised import train_supervised
    model, metrics = train_supervised(
        [_save(tmp_path, tr)], model_dir=tmp_path / "models",
        results_dir=tmp_path / "results")
    proba = model.predict_proba(te)
    assert proba.shape == (len(te), len(model.classes))
    alerts = model.score(te, threshold=0.6)
    assert alerts, "attack rows should alert at 0.6"
    assert all(validate_alert(a) == [] for a in alerts)
    assert metrics["per_class"]["ddos"]


def _save(tmp_path: Path, df: pd.DataFrame) -> str:
    p = tmp_path / "feat.parquet"
    p.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(p, index=False)
    return str(p)


def test_num_helper():
    assert _num(np.nan) == 0.0
    assert _num("12.5") == 12.5
    assert _num(None) == 0.0
    assert _num(np.inf) == 0.0


# ======================================================================= beacon
def _synth_beacon_flows(n_pairs=6, per_pair=40, seed=3) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    t0 = 1_500_000_000
    for p in range(n_pairs):
        even = p % 2 == 0
        if even:  # periodic C2 beacon: 30 s +- 1.5 s
            times = t0 + np.cumsum(30 + rng.uniform(-1.5, 1.5, per_pair))
        else:     # background: independent uniform arrivals over 2 h
            times = t0 + rng.uniform(0, 7200, per_pair)
        for t in times:
            rows.append((t, f"10.0.0.{p}", "93.184.216.34", 80, "tcp",
                         0.02, 2, 120, 60,
                         "flow=From-Bot-v1" if even else "flow=Background"))
    df = pd.DataFrame(rows, columns=["ts_epoch", "src_ip", "dst_ip", "dst_port",
                                     "proto", "dur_s", "pkts", "bytes",
                                     "src_bytes", "label"])
    return df


def test_pair_series_periodicity():
    flows = _synth_beacon_flows()
    pairs = bc.pair_series(flows)
    assert {"n_flows", "dt_mean", "dt_cv", "dt_scores", "span_s"} <= set(pairs.columns)
    beacons = pairs[pairs["label"].str.contains("From-Bot")]
    quiet = pairs[pairs["label"].str.contains("Background")]
    assert (beacons["dt_cv"] < 0.25).all()
    assert (beacons["dt_scores"] >= 0.9).all()
    assert quiet["dt_cv"].max() > 0.5


def test_pair_label_dialects():
    assert bc.pair_label("flow=From-Bot-v1- establish") == 1
    assert bc.pair_label("flow=From-CC-v2 normal") == 1
    assert bc.pair_label("flow=Background-TCP-Established") == 0


def test_beacon_model_fallback_rule():
    pairs = bc.pair_series(_synth_beacon_flows())
    m = bc.BeaconModel(booster=None, medians={})
    scores = m.predict_score(pairs)
    labels = pairs["label"].str.contains("From-Bot").to_numpy()
    assert (scores[labels] == 1).all()
    assert (scores[~labels] == 0).all()


def test_beacon_alerts_shape():
    pairs = bc.pair_series(_synth_beacon_flows())
    scores = np.ones(len(pairs))
    alerts = bc.emit_alerts(pairs, scores, threshold=0.9)
    assert alerts
    for a in alerts:
        assert validate_alert(a) == []
        assert a.threat_class == "beacon"
        assert "->" in (a.key or "")


# ========================================================================== dga
def test_domain_features_shape():
    f = dg.domain_features(pd.Series(["www.google.com", "q7z2nbavb5ylchq3zj2.com"]))
    assert {"len", "entropy", "digit_ratio", "bigram_score"} <= set(f.columns)
    assert f["len"].iloc[0] == 14
    assert f["digit_ratio"].iloc[1] > 0


def test_bigram_learning_and_scores():
    benign = pd.Series(["facebook.com", "google.com", "amazon.com",
                        "microsoft.com", "netflix.com"])
    bg = dg.fit_bigrams(benign)
    scores = dg.domain_features(
        pd.Series(["google.com", "xqzkjvbf.com"]), bigrams=bg)["bigram_score"]
    assert scores.iloc[0] > scores.iloc[1]  # real word beats random junk


def test_dga_fallback_rule():
    m = dg.DgaModel.fallback()
    s = m.score_domains(pd.Series(["www.google.com",
                                   "a7z2nbavb5ylchq3zj2ksdf9.example.com"]))
    assert s[0] == 0.0 and s[1] == 1.0


def test_make_tunnels():
    benign = pd.Series(["example.com", "acme.org"] * 3)
    t = dg.make_tunnels(benign, n=4, seed=1)
    assert len(t) == 4
    assert t["domain"].str.contains(r"^[a-z2-7]{15,55}\.").all()
    # the payload hangs off a real seeded base, which is the shape the
    # benign-subdomain augmentation is deliberately drawn against
    assert t["domain"].str.endswith(("example.com", "acme.org")).all()


def test_dga_metrics_and_model(tmp_path, monkeypatch):
    """Tiny argencon slice -> family-holdout CV runs and beats chance.

    Benign domains are word-like (vowel-rich, low entropy) exactly like the
    real Alexa-style portion of the corpus; DGA families are consonant junk.
    """
    words = ["google", "amazon", "facebook", "wikipedia", "netflix",
             "microsoft", "apple", "spotify", "twitter", "linkedin"]
    rng = np.random.default_rng(5)
    doms = []
    for i in range(120):
        w = words[i % len(words)]
        doms.append((f"{w}{i}.com", "normal.alexa", False))
    for fam in ["famA", "famB"]:
        for i in range(40):
            junk = "".join(rng.choice(list("qxzjkvwb"), 12))
            doms.append((f"{junk}{i}.com", fam, True))
    for fam in ["famC", "famD"]:   # 4 families so both CV folds see DGA rows
        for i in range(40):
            junk = "".join(rng.choice(list("mjfhtpqd"), 12))
            doms.append((f"{junk}{i}.com", fam, True))
    frame = pd.DataFrame(doms, columns=["domain", "family", "is_dga"])
    monkeypatch.setattr(dg, "load_argencon", lambda max_rows=None: frame)
    monkeypatch.setattr(dg, "load_umbrella", lambda: pd.DataFrame({
        "domain": ["google.com", "wikipedia.org", "amazon.com"],
        "family": ["umbrella"] * 3, "is_dga": False}))

    model, metrics = dg.train_dga(model_dir=tmp_path / "m",
                                  results_dir=tmp_path / "r")
    assert metrics["f1"] > 0.5
    assert (metrics["known_benign_fpr_at_threshold"]
            <= dg.DGA_BENIGN_FPR_TARGET)
    assert model.booster is not None
    assert Path(tmp_path / "r" / "dga_metrics.json").exists()
    # umbrella domains must all get scores (holdout scored)
    s = model.score_domains(pd.Series(["q7z2nbavb5ylchq3zj2.com", "google.com"]))
    assert len(s) == 2 and np.all((s >= 0) & (s <= 1))


# ========================================================================== tls
def _ssl_frame(n_clients=12, per=6, seed=11) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    t = 1_500_000_000.0
    for c in range(n_clients):
        ip = f"192.168.1.{c}"
        for k in range(per):
            rows.append({
                "ts": t + k * rng.uniform(1, 300),
                "src_ip": ip, "src_port": 40000 + k,
                "dst_ip": f"151.101.{rng.integers(0, 255)}.{rng.integers(0, 255)}",
                "dst_port": int(rng.choice([443, 443, 8443])),
                "ja3": f"aa{c:030d}", "ja3s": f"bb{c:030d}",
                "ja4": f"t13d1516h2_{c:012x}_b186095e22b6",
                "ja4s": f"t1303h2_1301_{c:012x}",
                "sni": f"site{c}.example.com",
            })
    return pd.DataFrame(rows)


def test_load_ssl_log_tsv_and_json(tmp_path):
    tsv = tmp_path / "ssl.log"
    tsv.write_text(
        "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tja3\tja3s\t"
        "server_name\tja4\tja4s\n"
        "1500000000.0\t10.0.0.5\t4433\t93.1.2.3\t443\taa33\taa44\twww.x.com\t"
        "t13d1516h2_8daaf6152771_e5627efa2ab1\tt1303h2_1301_4e8089b08790\n")
    df = tls.load_ssl_log(tsv)
    assert len(df) == 1 and df["ja3"].iloc[0] == "aa33"
    assert df["ja4"].iloc[0] == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert df["ja4s"].iloc[0] == "t1303h2_1301_4e8089b08790"
    js = tmp_path / "ssl.json"
    js.write_text(json.dumps({"ts": 1500000000.0, "id.orig_h": "10.0.0.6",
                              "id.orig_p": 4434, "id.resp_h": "93.1.2.4",
                              "id.resp_p": 443, "ja3": "aa55", "ja3s": "-",
                              "server_name": "-"}) + "\n")
    df2 = tls.load_ssl_log(js)
    assert len(df2) == 1 and df2["sni"].iloc[0] is None
    assert df2["ja4"].isna().iloc[0] and df2["ja4s"].isna().iloc[0]


def test_watchlist_loading(tmp_path):
    f = tmp_path / "ja3.csv"
    f.write_text("# comment\n" + "a" * 32 + ",Some Malware\n"
                 + "zz-not-a-hash,skip\n" + "B" * 32 + ",Other\n")
    wl = tls.load_watchlist(f)
    assert wl == {"a" * 32: "abuse.ch_SSLBL", "b" * 32: "abuse.ch_SSLBL"}


def test_tls_watchlist_and_novelty(tmp_path):
    df = _ssl_frame()
    client0_ja3 = df["ja3"].iloc[0]          # "aa" + 30 digits
    m = tls.TlsModel(watchlist={client0_ja3: "test"})
    agg = m.score_clients(df)
    assert agg["watchlisted"].any()
    assert agg["ja4"].iloc[0].startswith("t13d1516h2_")
    # novelty model trained on this same benign set; planted rogue shape
    model, metrics = tls.train_tls([_ssl_frame(n_clients=30, per=10)],
                                   model_dir=tmp_path / "m",
                                   results_dir=tmp_path / "r")
    assert metrics["watchlist_size"] == len(tls.load_watchlist()) == 97
    assert Path(tmp_path / "m" / "tls_novelty.joblib").exists()
    flagged = model.flag(_ssl_frame(n_clients=8, per=4))
    assert "watchlisted" in flagged.columns
    alerts = tls.emit_alerts(m.flag(_ssl_frame(n_clients=2, per=1)))
    assert alerts and any(e.condition == "ja4" for e in alerts[0].evidence)
    assert any(e.condition == "ja4s" for e in alerts[0].evidence)


def test_tls_metrics_artifact_is_reproducible_from_code(tmp_path):
    """The pinned tls_metrics.json must still come out of the current code.

    bench_accuracy and the claim guardrail both read this artifact instead of
    recomputing, which is how a novelty layer that could never fire kept
    shipping a 1.000 next to it. Re-running the same deterministic fit here
    and diffing the numbers turns the pin into evidence rather than a
    declaration.
    """
    from scripts.checks.check_ml import _synthetic_ssl_baseline

    pin = json.loads((Path(__file__).resolve().parents[2] / "docs" / "evaluation"
                      / "runs" / "tls_metrics.json").read_text(encoding="utf-8"))
    _, m = tls.train_tls([_synthetic_ssl_baseline()],
                         model_dir=tmp_path / "m", results_dir=tmp_path / "r")
    assert m["watchlist_size"] == pin["watchlist_size"]
    assert m["novelty_available"] == pin["novelty_available"]
    for key in ("f1", "precision", "recall"):
        assert m["synthetic_plant_eval"][key] == pytest.approx(
            pin["synthetic_plant_eval"][key])
    for channel in ("watchlist_only", "novelty_only"):
        assert (m["synthetic_plant_eval"][channel]["tp"]
                == pin["synthetic_plant_eval"][channel]["tp"])


def test_tls_watchlist_loads_outside_the_repo_root(tmp_path, monkeypatch):
    """The pin resolves from the repo root, not from the working directory.

    It was a CWD-relative path under git-ignored data/, so a fresh clone or a
    CI runner loaded zero hashes: the watchlist channel went silent while the
    metric still printed, and the assertion above passed as 0 == 0.
    """
    monkeypatch.chdir(tmp_path)
    assert tls.ABUSECH_JA3.exists()
    assert len(tls.load_watchlist()) == 97


def test_tls_novelty_is_batch_independent(tmp_path):
    """A client's novelty must not depend on who else is in the batch.

    The shipped scorer normalised with per-batch min/ptp, which made the same
    client score differently in different batches and capped novelty at 0.5.
    """
    model, _ = tls.train_tls([_ssl_frame(n_clients=30, per=10)],
                             model_dir=tmp_path / "m", results_dir=tmp_path / "r")
    df = _ssl_frame(n_clients=30, per=10)
    solo = model.score_clients(df[df["src_ip"] == "192.168.1.7"])
    crowd = model.score_clients(df)
    a = float(solo.loc[solo["src_ip"] == "192.168.1.7", "novelty"].iloc[0])
    b = float(crowd.loc[crowd["src_ip"] == "192.168.1.7", "novelty"].iloc[0])
    assert a == b
    vals = crowd["novelty"].dropna().to_numpy(dtype=float)
    assert 0.0 <= vals.min() and vals.max() <= 1.0


def test_tls_novelty_threshold_is_reachable(tmp_path):
    """The gate must be able to fire: under the old normalisation novelty could
    never exceed 0.5, so `>= 0.85` was dead code and every planted client was
    caught by the watchlist alone."""
    frame = _ssl_frame(n_clients=30, per=10)
    model, metrics = tls.train_tls([frame], model_dir=tmp_path / "m",
                                   results_dir=tmp_path / "r")
    assert metrics["novelty_available"] is True
    assert metrics["synthetic_plant_eval"]["novelty_degenerate_baseline"] is False
    thr = metrics["novelty_threshold"]
    assert model.score_clients(frame)["novelty"].dropna().max() >= thr
    # the novelty channel must be credited with detections of its own
    assert metrics["synthetic_plant_eval"]["novelty_only"]["tp"] > 0


def test_tls_novelty_disables_on_degenerate_baseline(tmp_path):
    """One connection per unique JA3 => every aggregate is identical, so the
    fit set has no spread. The layer must report itself unavailable instead of
    scoring noise off a zero-width band."""
    rows = [{"ts": 1_500_000_000.0 + i, "src_ip": f"10.0.0.{i % 250}",
             "src_port": 40000 + i, "dst_ip": f"93.1.1.{i % 50}",
             "dst_port": 443, "ja3": f"{i:032x}", "ja3s": "b" * 32,
             "sni": "x.example.com"} for i in range(400)]
    model, metrics = tls.train_tls([pd.DataFrame(rows)],
                                   model_dir=tmp_path / "m",
                                   results_dir=tmp_path / "r")
    assert metrics["novelty_available"] is False
    assert metrics["synthetic_plant_eval"]["novelty_only"]["tp"] == 0
    assert metrics["synthetic_plant_eval"]["novelty_degenerate_baseline"] is True
    assert model.score_clients(_ssl_frame(n_clients=4, per=4))["novelty"].isna().all()
    # the combined headline may not be quoted as if novelty earned it
    split = metrics["synthetic_plant_eval"]
    assert {"watchlist_only", "novelty_only"} <= set(split)


def test_tls_model_roundtrip_and_legacy_blob(tmp_path):
    """Saved bounds survive reload; a blob predating the frozen scale reloads
    with the channel disabled rather than reproducing batch-relative numbers."""
    import joblib

    model, _ = tls.train_tls([_ssl_frame(n_clients=20, per=8)],
                             model_dir=tmp_path / "m", results_dir=tmp_path / "r")
    reloaded = tls.TlsModel.load(tmp_path / "m")
    assert reloaded.novelty_available()
    df = _ssl_frame(n_clients=6, per=6)
    assert (model.score_clients(df)["novelty"].to_numpy()
            == reloaded.score_clients(df)["novelty"].to_numpy()).all()

    joblib.dump({"watchlist": {}, "iso": model.iso, "medians": model.medians},
                tmp_path / "m" / "tls_novelty.joblib")
    legacy = tls.TlsModel.load(tmp_path / "m")
    assert legacy.novelty_available() is False
    assert legacy.score_clients(df)["novelty"].isna().all()


# =================================================================== ml_engine
# =================================================== supervised_windows
def test_tune_threshold_requires_precision_gate():
    """No operating point reaches precision>=0.5 -> threshold is None (channel
    disabled), never a silent max-F1 fallback (the P=0.0103 bot bug)."""
    from src.detectors.ml.supervised_windows import _tune_threshold
    rng = np.random.default_rng(0)
    # 20 positives drowned inside 3980 negatives scoring HIGHER than them:
    # every recall>0 region has precision << 0.5, so the gate must fail
    y = np.zeros(4000, dtype=int)
    y[:20] = 1
    p = np.empty(4000)
    p[:20] = rng.uniform(0.60, 0.65, 20)     # positives: stuck in a low band
    p[20:] = rng.uniform(0.60, 1.0, 3980)    # negatives: overlap and above
    thr, diag = _tune_threshold(y, p)
    assert thr is None
    assert "disabled" in diag["note"]
    # separable scores -> a threshold satisfying the gate is returned
    p2 = rng.uniform(0.0, 0.2, len(y))
    p2[y == 1] = rng.uniform(0.8, 1.0, int(y.sum()))
    thr2, diag2 = _tune_threshold(y, p2)
    assert thr2 is not None
    assert diag2["tune_precision"] >= 0.5


def test_binary_train_set_keeps_benign_negatives():
    """Benign negatives must survive even when hard negatives exceed the cap
    (the zero-benign-negatives bot/webattack/bruteforce degenerate-fit bug)."""
    from src.detectors.ml.supervised_windows import _binary_train_set
    n_pos, n_hard, n_ben = 50, 400, 250
    rows = []
    for i in range(n_pos):
        rows.append(("tot_bytes", 1.0 + i, "Bot"))
    for i in range(n_hard):
        rows.append(("tot_bytes", 50.0 + i, "DoS Hulk"))
    for i in range(n_ben):
        rows.append(("tot_bytes", 100.0 + i, "BENIGN"))
    df = pd.DataFrame(rows, columns=["feat", "tot_bytes", "label"])
    df["__class"] = df["label"].map(class_of)
    out = _binary_train_set(df, "bot")
    n_ben_out = int((out["__class"] == "benign").sum())
    assert n_ben_out > 0, "benign negatives must not be starved to zero"
    assert n_ben_out == min(300, n_ben)  # NEG_CAP budget, capped by availability
    assert (out["__class"] == "bot").sum() == n_pos
    assert (out["__class"] == "ddos").sum() == n_hard


def test_score_skips_disabled_channels():
    """A class stored without a threshold must not alert, even at p=1.0."""
    from src.detectors.ml.supervised_windows import MODEL_FEATURES_CTX, FlowContextModel

    class _StubBooster:
        """Duck-typed binary booster: constant positive probability."""

        def __init__(self, p_const: float):
            self.p_const = p_const
            self.feature_importances_ = np.zeros(len(MODEL_FEATURES_CTX))

        def predict_proba(self, X: np.ndarray) -> np.ndarray:
            out = np.zeros((len(X), 2))
            out[:, 1] = self.p_const
            return out

    df = _synthetic_features(200)
    for c in MODEL_FEATURES:
        if c not in df.columns:
            df[c] = 0.0
    for c in ("duration_us", "ts_epoch", "src_port"):
        if c not in df.columns:
            df[c] = 0.0
    df["ts_epoch"] = 1_500_000_000 + np.arange(len(df)) * 7
    df["dst_ip"] = "93.184.216.34"
    df["dst_port"] = 80
    df["proto"] = "tcp"
    df["protocol"] = 6
    df["fwd_pkts"] = df["tot_pkts"]
    df["bwd_pkts"] = 0
    df["fwd_bytes"] = df["tot_bytes"]
    df["bwd_bytes"] = 0
    m = FlowContextModel(
        models={"ddos": _StubBooster(1.0), "bot": _StubBooster(1.0)},
        thresholds={"ddos": 0.99, "bot": None},
        medians={},
        classes=["benign", "ddos", "scan", "bruteforce", "webattack", "bot",
                 "infiltration"])
    alerts = m.score(df)
    assert alerts, "ddos channel (threshold present) must fire"
    fired = {a.threat_class for a in alerts}
    assert fired == {"ddos"}, "disabled bot channel (threshold=None) must stay silent"


def test_ml_engine_end_to_end(tmp_path, monkeypatch):
    """CLI round-trip with a tiny trained model: features -> alerts jsonl."""
    from src.detectors.ml_engine import main as engine_main

    df = _synthetic_features(200)
    for c in MODEL_FEATURES:
        if c not in df.columns:
            df[c] = 0.0
    feat = tmp_path / "feat.parquet"
    df.to_parquet(feat, index=False)
    monkeypatch.chdir(tmp_path)  # models/ and results/ land in the tmp dir

    rc = engine_main(["--input", str(feat), "--out", "alerts.jsonl",
                      "--train-input", str(feat), "--threshold", "0.6"])
    assert rc == 0
    lines = Path("alerts.jsonl").read_text().splitlines()
    assert lines, "engine must emit alerts for the attack rows"
    rec = json.loads(lines[0])
    assert {"timestamp", "flow_id", "threat_class", "confidence", "evidence"} <= set(rec)
    assert rec["threat_class"] in {"ddos", "scan"}


def test_ml_engine_validates_alerts(tmp_path, monkeypatch):
    from src.alerts.schema import Alert, EvidenceItem
    from src.detectors.ml_engine import _write_alerts
    a = Alert(timestamp="2017-07-05T09:00:00+00:00", threat_class="ddos",
              confidence=0.95,
              evidence=[EvidenceItem(condition="p", operator=">=", observed=0.95,
                                     threshold=0.9)])
    bad = _write_alerts([a], tmp_path / "out.jsonl")
    assert bad == 0
    assert len(json.loads((tmp_path / "out.jsonl").read_text())["evidence"]) == 1


# ===================================================== slice regression (real)
@pytest.mark.skipif(not CTU_DIR.exists() or not any(CTU_DIR.iterdir()),
                    reason="CTU-13 corpora not downloaded")
def test_beacon_on_real_ctu():
    """Honest regression on real CTU-13: pair framework + labels behave.

    Documented reality (docs/ml.md): CTU-13 bidirectional NetFlow bot traffic
    is mostly bursty C2/spam rather than classic periodic beacons, so the
    assertion checks multi-flow bot pairs exist, not perfect periodicity.
    """
    flows = bc.load_ctu(CTU_DIR / "CTU-53-capture20110819.binetflow")
    pairs = bc.pair_series(flows)
    pairs["y"] = pairs["label"].map(bc.pair_label)
    assert len(pairs) > 50_000
    assert pairs["y"].sum() > 500
    assert (pairs.loc[pairs["y"] == 1, "n_flows"] >= 2).any()
    # timestamps parse to real epoch seconds (capture spans hours, not seconds)
    span_h = (flows["ts_epoch"].max() - flows["ts_epoch"].min()) / 3600
    assert 0.5 < span_h < 24


# ============================================= pinned-model column contract
# The training order is pinned in the tree, not only inside the shipped pickle.
# A `.joblib` under a git-ignored `models/` is absent for anyone who has not
# restored it, so on its own it could never gate the two channels whose
# artifacts are not distributed (flowctx, tls). The pin covers all four.
FEATURE_PIN = REPO / "docs" / "models" / "feature_order.json"
_PINNED_VECTORS = [
    pytest.param("dga", lambda: dg.DGA_FEATURES, "dga_lgbm.joblib", id="dga"),
    pytest.param("beacon", lambda: bc.BEACON_FEATURES, "beacon_lgbm.joblib",
                 id="beacon"),
    pytest.param("flowctx", lambda: sw.MODEL_FEATURES_CTX, "flowctx_lgbm.joblib",
                 id="flowctx"),
    pytest.param("tls", lambda: tls.TLS_FEATURES, "tls_novelty.joblib", id="tls"),
]


def _feature_pin() -> dict:
    return json.loads(FEATURE_PIN.read_text(encoding="utf-8"))["channels"]


@pytest.mark.parametrize("channel,live,artifact", _PINNED_VECTORS)
def test_a_channel_still_scores_the_columns_it_was_trained_on(channel, live,
                                                             artifact):
    """Each channel scores with `frame.reindex(columns=FEATURES).to_numpy()`: a
    positional matrix, so an artifact and the module must agree on column ORDER,
    not just on the set of names. Reorder, rename, insert or drop one entry and
    every column shifts: the shipped booster then scores the wrong features, and
    nothing else notices. No crash, no NaN, no failing test, and every published
    accuracy figure becomes fiction. `docs/models/feature_order.json` records the
    training order for all four channels, so the two artifacts that are not
    distributed are covered as well as the two that are.
    """
    assert list(live()) == _feature_pin()[channel]


@pytest.mark.parametrize("channel,live,artifact", _PINNED_VECTORS)
def test_an_artifact_agrees_with_the_pin(channel, live, artifact):
    """An artifact's own record of its training order must match the module and
    the pin, checked against whichever copy of the bytes exists.

    This used to `return` when `models/` was empty, which made it a pass that
    asserted nothing on an ordinary checkout. Every parameter now asserts
    something: the two distributed artifacts are read from their shipped copy in
    `docs/evaluation/models/`, and the two that are not distributed are asserted
    to be genuinely absent, which is precisely why the pin exists.
    """
    joblib = pytest.importorskip("joblib")
    candidates = [REPO / "models" / artifact,
                  REPO / "docs" / "evaluation" / "models" / artifact]
    present = [p for p in candidates if p.exists()]
    if not present:
        assert channel in {"flowctx", "tls"}, (
            f"{artifact} is not distributed and not restored, but {channel} is "
            f"one of the channels that ships a copy")
        return
    medians = list(joblib.load(present[0])["medians"])
    assert medians == list(live()), f"{present[0].name} drifted from {channel}.FEATURES"
    assert medians == _feature_pin()[channel], (
        f"{present[0].name} drifted from docs/models/feature_order.json")


def test_dga_demo_alert_is_lexical_not_tld_based():
    """`tld_suspicious` flags a TLD outside the benign prior. The pack's tunnel
    names end in .com/.net/.tk, all inside that prior, so the flag is 0 for every
    domain the DGA demo alerts on: the demo proves shape/entropy/bigram
    detection, never cheap-TLD detection. Measured on the pinned corpora the flag
    fires on ~11% of benign names and ~3% of argencon DGA names, so it is a
    negative indicator there, not a positive one. The second half keeps the
    mechanism honest: the flag must still fire outside the prior.
    """
    from src.alerts.pack import PACK_DIR, ensure_pack

    ensure_pack()
    doms = pd.Series([ln.strip() for ln in
                      (PACK_DIR / "03_dga_domains.txt").read_text().splitlines()
                      if ln.strip()])
    assert float(dg.domain_features(doms)["tld_suspicious"].sum()) == 0.0
    out = dg.domain_features(pd.Series(["qvdx.loan"]))["tld_suspicious"]
    assert float(out.iloc[0]) == 1.0
