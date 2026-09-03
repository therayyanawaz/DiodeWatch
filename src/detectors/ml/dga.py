"""DGA / DNS-tunnel domain classifier.

Lexical/statistical detection on the domain NAME itself (no payload needed —
fits the passive data-diode constraint). Features are classic and
interpretable: length, Shannon entropy, digit/vowel ratios, consonant-run
flags, TLD shape, a bigram plausibility score learned from TRAIN benign
domains only (the anti-overfit shield: the model learns what *benign* names
look like, not a memorized list of malicious ones), and a parallel SLD
(second-level domain) view — benign CDN/tech infra hides random-looking
sub-labels under word-like SLDs, while DGA kits own the random SLD itself.

Corpora (see scripts/fetch/download_ml_corpora.py):
  * argencon.csv.gz (HF harpomaxx/dga-detection, CC-BY-2.0): 1.0M benign
    (Alexa 1M + Bambenek suspicious-normal) + 1.9M DGA domains from 51
    malware families;
  * Umbrella top-1m: an INDEPENDENT benign list used only for holdout —
    "does the model misfire on a million domains it has never seen?"

DNS-tunnel coverage: synthetic tunnel queries (benign base + random base32
subdomains of length 15–55) are trained alongside the DGA families.

Evaluation is FAMILY-holdout CV: the 51 families + tunnels are split into two
deterministic halves; each fold trains on one half (plus half the benign
domains, split by hash) and tests on the other. Pooled metrics therefore
answer "does this generalize to a NEW DGA family", the question that matters.
"""
from __future__ import annotations

import hashlib
import io
import json
import random
import re
import zipfile
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from src.alerts.schema import Alert, EvidenceItem

from .features import safe_median

DGA_DIR = Path("data/raw/dga")
DNS_DIR = Path("data/raw/dns")
ARGENCON = DGA_DIR / "argencon.csv.gz"
TOP1M = DNS_DIR / "top-1m.csv.zip"

DGA_FEATURES = [
    "len", "entropy", "digit_ratio", "vowel_ratio", "unique_ratio",
    "digits", "dots", "hyphens", "consonant_run4", "consonant_run6",
    "is_common_tld", "tld_len", "bigram_score", "tld_suspicious",
    "sld_len", "sld_entropy", "sld_digit_ratio", "sld_consonant_run4",
]

COMMON_TLDS = {"com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "uk"}
# The TLD territory these corpora's benign side actually occupies (Tranco
# top-list plus the ccTLDs its ranks reach). `tld_suspicious` means "outside this
# prior", NOT "cheap .tk/.ml TLD": on argencon + Umbrella (400k-row cap) the flag
# fires on ~11.4% of benign names but only ~3.0% of DGA names, because the kits
# register under .com/.net, which sit inside the prior, so the booster reads the
# column with that direction. A cheap-TLD list carries no signal here (0.5% DGA vs
# 0.9% benign). The column name is frozen: the pinned model scores positionally.
BENIGN_TLD_PRIOR = frozenset(
    ["com", "net", "org", "edu", "gov", "int", "mil", "io", "co", "uk", "jp", "de", "fr", "br", "in", "ru", "it", "au", "nl", "ca", "ch", "cn", "se", "es", "us", "pl", "be", "at", "cz", "dk", "hu", "no", "fi", "ie", "pt", "gr", "ro", "tr", "mx", "ar", "cl", "za", "kr", "tw", "hk", "sg", "my", "id", "th", "vn", "ph", "nz", "ua", "by", "sk", "bg", "hr", "rs", "si", "lt", "lv", "ee", "il", "ae", "sa", "ng", "ke", "gh", "ma", "info", "biz", "name", "pro", "tel", "xyz", "online", "site", "store", "shop", "app", "dev", "blog", "news", "tv", "me", "ai", "fm", "gg", "so", "to", "cloud", "top", "website", "space", "fun", "icu", "vip", "win", "cash", "link", "download", "stream", "live", "life", "world", "today", "zone", "club", "party", "gq", "ml", "cf", "tk"])
_BIGRAM_SLICES = 8  # bigram_score evaluated over the first 2*_BIGRAM_SLICES chars


# --------------------------------------------------------------------- features
def base_domain(domain: str) -> str:
    """Lower-cased eTLD+1-ish base (strips www. and any subdomain labels)."""
    d = str(domain).strip().lower().rstrip(".")
    d = d.removeprefix("www.")
    return d.rsplit(".", 1)[0] if d.count(".") else d


def _char_counts(names: pd.Series) -> tuple[np.ndarray, np.ndarray]:
    """Counts of [a-z0-9] per name + total length (vectorized)."""
    L = names.str.len().to_numpy(dtype=np.float64)
    counts = np.zeros((len(names), 36), dtype=np.int32)
    for i, ch in enumerate("abcdefghijklmnopqrstuvwxyz0123456789"):
        counts[:, i] = names.str.count(re.escape(ch)).to_numpy()
    return counts, L


def entropy_of(names: pd.Series) -> np.ndarray:
    """Shannon entropy of the character distribution, per name."""
    counts, L = _char_counts(names)
    with np.errstate(divide="ignore", invalid="ignore"):
        p = counts / np.maximum(L[:, None], 1)
        logp = np.where(counts > 0, np.log(np.where(p > 0, p, 1)), 0.0)
        H = -(p * logp).sum(axis=1)
    return H


def domain_features(domains: pd.Series, bigrams: dict[str, float] | None = None
                    ) -> pd.DataFrame:
    """Lexical feature frame for a series of domain names (full query names)."""
    s = domains.astype(str).str.lower().str.rstrip(".")
    base = s.map(base_domain)
    counts, L = _char_counts(s)
    vowel = counts[:, :5].sum(axis=1)  # a e i o u
    digits = counts[:, 26:].sum(axis=1)

    feats = pd.DataFrame(index=s.index)
    feats["len"] = L
    feats["entropy"] = entropy_of(s)
    feats["digit_ratio"] = digits / np.maximum(L, 1)
    feats["vowel_ratio"] = vowel / np.maximum(L, 1)
    feats["unique_ratio"] = (counts > 0).sum(axis=1) / np.maximum(L, 1)
    feats["digits"] = digits
    feats["dots"] = s.str.count(r"\.").to_numpy()
    feats["hyphens"] = s.str.count("-").to_numpy()
    feats["consonant_run4"] = base.str.contains(r"[^aeiou0-9.]{4}", regex=True).to_numpy()
    feats["consonant_run6"] = base.str.contains(r"[^aeiou0-9.]{6}", regex=True).to_numpy()
    tld = s.str.rsplit(".", n=1).str[-1]
    feats["is_common_tld"] = tld.isin(COMMON_TLDS).to_numpy()
    feats["tld_len"] = tld.str.len().to_numpy()
    feats["tld_suspicious"] = (~tld.isin(BENIGN_TLD_PRIOR)).astype(float).to_numpy()
    feats["bigram_score"] = _bigram_scores(s, bigrams) if bigrams is not None else 0.0
    # SLD (second-level) features: the label a registrar actually owns.
    # Random-looking sub-labels under a word-like SLD are benign CDN/tech
    # infra (kv801.prod.do.dsp.mp.microsoft.com); a random SLD is the DGA
    # signal itself. DGA kits own the SLD, tunnels don't — keep both views.
    sld = np.where(s.str.count(r"\.").to_numpy() >= 1,
                   s.str.rsplit(".", n=1).str[-2].fillna(""),
                   base)
    sld_s = pd.Series(sld, index=s.index, dtype="string").fillna("")
    sld_counts, sld_L = _char_counts(sld_s)
    sld_digits = sld_counts[:, 26:].sum(axis=1)
    feats["sld_len"] = sld_L
    feats["sld_entropy"] = entropy_of(sld_s)
    feats["sld_digit_ratio"] = sld_digits / np.maximum(sld_L, 1)
    feats["sld_consonant_run4"] = sld_s.str.contains(
        r"[^aeiou0-9.]{4}", regex=True).fillna(False).to_numpy()
    return feats.astype(np.float64)


def _bigram_scores(s: pd.Series, bigrams: dict[str, float]) -> np.ndarray:
    """Mean log-probability of letter bigrams over the first 16 characters."""
    total = np.zeros(len(s))
    seen = np.zeros(len(s))
    head = s.str.slice(0, 2 * _BIGRAM_SLICES)
    for i in range(_BIGRAM_SLICES):
        bg = head.str.slice(2 * i, 2 * i + 2)
        valid = bg.str.fullmatch(r"[a-z]{2}").fillna(False)
        lp = bg.map(bigrams).to_numpy(dtype=np.float64)
        total += np.where(valid.to_numpy(), np.nan_to_num(lp), 0.0)
        seen += valid.to_numpy()
    return np.where(seen > 0, total / np.maximum(seen, 1), 0.0)


def fit_bigrams(benign_domains: pd.Series) -> dict[str, float]:
    """Letter-bigram log-probability table learned from benign domains.

    Counts come from vectorized slice value_counts (no per-domain Python loop);
    add-1 smoothing over the 26x26 table keeps unseen bigrams finite but rare.
    """
    head = benign_domains.astype(str).str.lower().str.slice(0, 2 * _BIGRAM_SLICES)
    counts: dict[str, int] = {}
    for i in range(_BIGRAM_SLICES):
        bg = head.str.slice(2 * i, 2 * i + 2)
        bg = bg[bg.str.fullmatch(r"[a-z]{2}", na=False)]
        for k, v in bg.value_counts().items():
            counts[k] = counts.get(k, 0) + int(v)
    letters = "abcdefghijklmnopqrstuvwxyz"
    total = sum(counts.values()) + len(letters) ** 2  # add-1 smoothing
    logp = {}
    for a in letters:
        for b in letters:
            k = a + b
            logp[k] = float(np.log((counts.get(k, 0) + 1) / total))
    return logp


# --------------------------------------------------------------------- corpora
def load_argencon(path: Path = ARGENCON, max_rows: int | None = None) -> pd.DataFrame:
    """argencon.csv.gz -> DataFrame(domain, family, is_dga)."""
    df = pd.read_csv(path, usecols=["domain", "label"], nrows=max_rows or None)
    df["family"] = df["label"].astype(str)
    df["is_dga"] = ~df["family"].str.startswith("normal.")
    df = df[["domain", "family", "is_dga"]]
    return df


def load_umbrella(path: Path = TOP1M, max_rows: int = 1_000_000) -> pd.DataFrame:
    """Umbrella top-1m zip -> DataFrame(domain, family='umbrella', is_dga=False)."""
    with zipfile.ZipFile(path) as zf:
        name = zf.namelist()[0]
        with zf.open(name) as fh:
            head = pd.read_csv(io.TextIOWrapper(fh, "utf-8", errors="replace"),
                               nrows=max_rows, header=None,
                               names=["rank", "domain"])
    out = pd.DataFrame({"domain": head["domain"].astype(str)})
    out["family"] = "umbrella"
    out["is_dga"] = False
    return out


def make_tunnels(benign_domains: pd.Series, n: int = 200_000,
                 seed: int = 42) -> pd.DataFrame:
    """Synthetic DNS-tunnel queries: benign base + random base32 subdomains."""
    rng = random.Random(seed)
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    bases = benign_domains.sample(n=min(n, len(benign_domains)),
                                  random_state=seed).to_numpy()
    rows = []
    for b in bases:
        payload = "".join(rng.choices(alphabet, k=rng.randrange(15, 56)))
        rows.append((f"{payload}.{b}", "synthetic-tunnel", True))
    return pd.DataFrame(rows, columns=["domain", "family", "is_dga"])


def make_benign_subdomains(benign_domains: pd.Series, n: int = 300_000,
                           seed: int = 43) -> pd.DataFrame:
    """Synthetic benign FQDNs: infra-style sub-labels under real SLDs.

    Benign train corpora (Alexa) are bare registrable domains, but live DNS
    traffic is full hostnames with deep sub-label chains (CDNs, CDNs behind
    CDNs, cloud endpoints). Without this augmentation the model flags exactly
    that shape as DGA — the dominant Umbrella holdout FPR. Labels stay SHORT
    (<= 12 chars, mixed alpha/digit, service prefixes), which also sharpens
    the boundary against long uniform base32 tunnel payloads.
    """
    rng = random.Random(seed)
    bases = benign_domains.sample(n=min(n, len(benign_domains)),
                                  random_state=seed).to_numpy()
    prefixes = ("www", "mail", "cdn", "img", "api", "static", "assets",
                "edge", "ns1", "ns2", "smtp", "vpn", "portal", "auth")
    rows = []
    for b in bases:
        labels = []
        for _ in range(rng.randrange(1, 4)):
            r = rng.random()
            if r < 0.35:
                labels.append(rng.choice(prefixes))
            elif r < 0.7:
                letters = "abcdefghijklmnopqrstuvwxyz"
                labels.append(rng.choice(letters) + str(rng.randrange(0, 1000)))
            else:
                k = rng.randrange(3, 13)
                alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
                labels.append("".join(rng.choices(alphabet, k=k)))
        rows.append((".".join(labels) + "." + b, "synthetic-subdomain", False))
    return pd.DataFrame(rows, columns=["domain", "family", "is_dga"])


def _fold_of(family: str) -> int:
    """Deterministic family fold (0/1) from the family name hash."""
    return int(hashlib.md5(family.encode()).hexdigest(), 16) % 2


def _domain_fold(domain: str) -> int:
    """Deterministic benign-domain fold so benigns also get honest OOF scores."""
    return int(hashlib.md5(str(domain).encode()).hexdigest(), 16) % 2


# --------------------------------------------------------------------- training
def _matrix(feats: pd.DataFrame, medians: dict[str, float] | None = None
            ) -> tuple[np.ndarray, dict[str, float]]:
    X = feats.reindex(columns=DGA_FEATURES).apply(pd.to_numeric, errors="coerce")
    if medians is None:
        medians = {c: float(X[c].median()) for c in X.columns}
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


DGA_LGBM = {
    "n_estimators": 300, "learning_rate": 0.1, "num_leaves": 63,
    "min_child_samples": 50, "class_weight": "balanced",
    "n_jobs": -1, "verbosity": -1, "random_state": 42,
}
# A DGA alert must be actionable: the deployment threshold is the most
# permissive one (max recall) whose known-corpus OOF precision clears this.
DGA_PRECISION_TARGET = 0.90


def train_dga(model_dir: str | Path = "models",
              results_dir: str | Path = "results/ml",
              max_rows: int | None = 2_000_000,
              ) -> tuple[DgaModel, dict]:
    """Family-holdout CV over the DGA corpus; final model refit on everything.

    max_rows caps the argencon read for smoke runs (None = full corpus).
    """
    data = load_argencon(max_rows=max_rows)
    # Folds: DGA rows split by FAMILY hash, benign rows by DOMAIN hash — every
    # fold keeps benigns, and no malware family appears in train AND test.
    data["fold"] = np.where(
        data["is_dga"],
        data["family"].map(_fold_of),
        data["domain"].map(_domain_fold),
    )
    benign = data[~data["is_dga"]]

    umbrella = load_umbrella()
    tunnels = make_tunnels(benign["domain"])
    tunnels["fold"] = tunnels["domain"].map(_domain_fold)
    # benign sub-label augmentation: train-only (fold -1 never lands in test)
    benign_sub = make_benign_subdomains(benign["domain"])
    benign_sub["fold"] = -1

    # per-fold bigram tables are learned from that fold's TRAIN benign domains
    y_all = np.concatenate([
        data["is_dga"].to_numpy(dtype=int),
        tunnels["is_dga"].to_numpy(dtype=int),
        umbrella["is_dga"].to_numpy(dtype=int),
    ])
    fam_all = np.concatenate([
        data["family"].to_numpy(), tunnels["family"].to_numpy(),
        umbrella["family"].to_numpy(),
    ])

    parts = {
        "argencon": data, "tunnels": tunnels, "umbrella": umbrella,
    }
    feats_by_part = {k: domain_features(v["domain"]) for k, v in parts.items()}
    sub_feats = domain_features(benign_sub["domain"])

    oof = np.full(len(y_all), np.nan)
    for fold in (0, 1):
        tr_idx = {k: [] for k in parts}
        te_idx = {k: [] for k in parts}
        for k, v in parts.items():
            if k == "umbrella":
                te_idx[k] = np.arange(len(v))  # umbrella is ALWAYS holdout
                continue
            f = v["fold"].to_numpy()
            te_idx[k] = np.where(f == fold)[0]
            tr_idx[k] = np.where(f != fold)[0]
        tr_domains_benign = parts["argencon"]["domain"].iloc[
            tr_idx["argencon"]][
                ~parts["argencon"]["is_dga"].to_numpy()[tr_idx["argencon"]]]
        bigrams = fit_bigrams(tr_domains_benign)
        sub_X = sub_feats.assign(
            bigram_score=_bigram_scores(benign_sub["domain"], bigrams)
        ).reindex(columns=DGA_FEATURES).to_numpy(dtype=np.float32)
        Xtr = np.vstack([
            feats_by_part["argencon"].iloc[tr_idx["argencon"]].assign(
                bigram_score=_bigram_scores(
                    parts["argencon"]["domain"].iloc[tr_idx["argencon"]], bigrams)
            ).reindex(columns=DGA_FEATURES).to_numpy(dtype=np.float32),
            feats_by_part["tunnels"].iloc[tr_idx["tunnels"]].assign(
                bigram_score=_bigram_scores(
                    parts["tunnels"]["domain"].iloc[tr_idx["tunnels"]], bigrams)
            ).reindex(columns=DGA_FEATURES).to_numpy(dtype=np.float32),
            sub_X,
        ])
        ytr = np.concatenate([
            y_all[tr_idx["argencon"]],
            y_all[len(data):len(data) + len(tunnels)][tr_idx["tunnels"]],
            benign_sub["is_dga"].to_numpy(dtype=int),
        ])
        if ytr.sum() == 0 or ytr.sum() == len(ytr):
            continue  # degenerate fold (single class) — skip rather than crash
        medians = {c: safe_median(Xtr[:, i]) for i, c in enumerate(DGA_FEATURES)}
        for i, c in enumerate(DGA_FEATURES):
            Xtr[:, i][~np.isfinite(Xtr[:, i])] = medians[c]

        clf = lgb.LGBMClassifier(**DGA_LGBM)
        clf.fit(Xtr, ytr)

        # honest OOF scores for every held-out row (incl. umbrella + tunnels)
        for k in ("argencon", "tunnels", "umbrella"):
            if not len(te_idx[k]):
                continue
            f = feats_by_part[k].iloc[te_idx[k]].assign(
                bigram_score=_bigram_scores(parts[k]["domain"].iloc[te_idx[k]], bigrams)
            ).reindex(columns=DGA_FEATURES)
            Xte, _ = _matrix(f, medians)
            offset = 0 if k == "argencon" else (
                len(data) if k == "tunnels" else len(data) + len(tunnels))
            oof[offset + te_idx[k]] = clf.predict_proba(Xte)[:, 1]

    valid = ~np.isnan(oof)
    # Operational threshold on OOF rows of the KNOWN corpus (argencon +
    # tunnels, themselves family-holdout) — umbrella stays an untouched
    # reporting set. Most permissive cut with precision >= DGA_PRECISION_TARGET.
    known = valid.copy()
    known[len(data) + len(tunnels):] = False
    kw = np.where(known)[0]
    order = np.argsort(-oof[kw])
    ys_k, ss_k = y_all[kw][order], oof[kw][order]
    tp_k = np.cumsum(ys_k == 1)
    fp_k = np.cumsum(ys_k == 0)
    prec_k = tp_k / np.maximum(tp_k + fp_k, 1)
    ok = np.where(prec_k >= DGA_PRECISION_TARGET)[0]
    dga_threshold = float(max(ss_k[int(ok[-1])], 1e-9)) if len(ok) else 0.5

    metrics = _binary_metrics(y_all[valid], oof[valid], threshold=dga_threshold)
    metrics["threshold"] = round(dga_threshold, 4)
    # precision on the population the threshold was tuned on (known corpus,
    # family-holdout OOF); umbrella is reported separately as FPR
    kmask = known[valid]
    yk, sk = y_all[valid][kmask], oof[valid][kmask]
    ktp = int(((sk >= dga_threshold) & (yk == 1)).sum())
    kfp = int(((sk >= dga_threshold) & (yk == 0)).sum())
    metrics["known_precision"] = round(ktp / max(ktp + kfp, 1), 4)
    metrics["pr_auc"] = round(float(average_precision_score(
        y_all[valid], oof[valid])), 4)
    metrics["roc_auc"] = round(float(roc_auc_score(y_all[valid], oof[valid])), 4)
    fp_mask = valid & (y_all == 0) & (oof >= dga_threshold)
    metrics["false_positives_by_family"] = {
        str(f): int(c) for f, c in
        pd.Series(fam_all[fp_mask]).value_counts().head(10).items()
    }
    metrics["umbrella_fpr_at_threshold"] = round(float(
        ((oof[len(data) + len(tunnels):] >= dga_threshold)
         & (y_all[len(data) + len(tunnels):] == 0)).mean()), 5)
    metrics.update({
        "model": "LightGBM lexical DGA/DNS-tunnel (family-holdout CV)",
        "families": int(pd.Series(fam_all[y_all == 1]).nunique()),
        "n_scored": int(valid.sum()),
        "positives": int(y_all[valid].sum()),
        "holdout_benign": "Umbrella top-1m (independent corpus, never trained on)",
    })

    # ---- final model on ALL argencon + tunnels (umbrella stays holdout) ----
    bigrams = fit_bigrams(benign["domain"])
    Xall = np.vstack([
        feats_by_part["argencon"].assign(
            bigram_score=_bigram_scores(data["domain"], bigrams)
        ).reindex(columns=DGA_FEATURES).to_numpy(dtype=np.float32),
        feats_by_part["tunnels"].assign(
            bigram_score=_bigram_scores(tunnels["domain"], bigrams)
        ).reindex(columns=DGA_FEATURES).to_numpy(dtype=np.float32),
        sub_feats.assign(
            bigram_score=_bigram_scores(benign_sub["domain"], bigrams)
        ).reindex(columns=DGA_FEATURES).to_numpy(dtype=np.float32),
    ])
    yall = np.concatenate([data["is_dga"].to_numpy(dtype=int),
                           tunnels["is_dga"].to_numpy(dtype=int),
                           benign_sub["is_dga"].to_numpy(dtype=int)])
    medians = {c: safe_median(Xall[:, i]) for i, c in enumerate(DGA_FEATURES)}
    for i, c in enumerate(DGA_FEATURES):
        col = Xall[:, i]
        col[~np.isfinite(col)] = medians[c]
    final = lgb.LGBMClassifier(**DGA_LGBM)
    final.fit(Xall, yall)

    model = DgaModel(booster=final, medians=medians, bigrams=bigrams,
                     threshold=dga_threshold)
    model.save(model_dir)

    out = Path(results_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "dga_metrics.json").write_text(json.dumps(metrics, indent=2))
    return model, metrics


class DgaModel:
    """Trained lexical classifier + its bigram table, ready for inference."""

    def __init__(self, booster: lgb.LGBMClassifier | None,
                 medians: dict[str, float],
                 bigrams: dict[str, float] | None,
                 threshold: float = 0.5) -> None:
        self.booster = booster
        self.medians = medians
        self.bigrams = bigrams or {}
        self.threshold = float(threshold)

    @classmethod
    def fallback(cls) -> DgaModel:
        """No-model mode: transparent lexical rule flags tunnel-shaped names."""
        return cls(booster=None, medians={}, bigrams={})

    def score_domains(self, domains: pd.Series) -> np.ndarray:
        """P(dga-or-tunnel) per domain (model); heuristic score when untrained."""
        if self.booster is None:
            feats = domain_features(domains)
            lex = (feats["len"] >= 30) | (feats["consonant_run6"].astype(bool)) \
                | (feats["digit_ratio"] >= 0.4)
            return lex.to_numpy(dtype=float)
        feats = domain_features(domains, bigrams=self.bigrams)
        X, _ = _matrix(feats, self.medians)
        return self.booster.predict_proba(X)[:, 1]

    def save(self, model_dir: str | Path) -> Path:
        import joblib

        model_dir = Path(model_dir)
        model_dir.mkdir(parents=True, exist_ok=True)
        path = model_dir / "dga_lgbm.joblib"
        joblib.dump({"booster": self.booster, "medians": self.medians,
                     "bigrams": self.bigrams, "threshold": self.threshold}, path)
        return path

    @classmethod
    def load(cls, model_dir: str | Path) -> DgaModel:
        import joblib

        path = Path(model_dir) / "dga_lgbm.joblib"
        if not path.exists():
            raise FileNotFoundError(f"{path} missing — train with train_dga() first")
        blob = joblib.load(path)
        return cls(booster=blob.get("booster"), medians=blob.get("medians", {}),
                   bigrams=blob.get("bigrams") or {},
                   threshold=float(blob.get("threshold", 0.5)))

    def emit_alerts(self, domains: pd.Series, scores: np.ndarray,
                    threshold: float = 0.9, detector: str = "ml.dga") -> list[Alert]:
        alerts: list[Alert] = []
        feats = domain_features(domains, bigrams=self.bigrams)
        for i in range(len(domains)):
            s = float(scores[i])
            if s < threshold:
                continue
            d = str(domains.iloc[i])
            f = feats.iloc[i]
            ev = [EvidenceItem(
                condition="dga_probability", operator=">=", observed=round(s, 4),
                threshold=threshold, unit="probability",
                description=f"lexical model flags {d!r} (p={s:.3f})",
            )]
            for c in ("entropy", "len", "digit_ratio", "consonant_run6",
                      "bigram_score", "unique_ratio"):
                v = float(f.get(c, np.nan))
                if np.isfinite(v):
                    ev.append(EvidenceItem(
                        condition=c, operator="feature", observed=round(v, 4),
                        threshold="learned", description=f"{c}={v:.3g}", unit="",
                    ))
            alerts.append(Alert(
                timestamp="", threat_class="dga", confidence=round(s, 4),
                evidence=ev, flow_id=None, key=d, detector=detector,
            ))
        return alerts
