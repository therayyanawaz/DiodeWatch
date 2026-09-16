#!/usr/bin/env python3
"""Baseline data slice: download + verify + summarize a pinned CIC-IDS2017 slice.

Downloads the CIC-IDS2017 Wednesday corpus (BENIGN + DoS GoldenEye/Hulk/slowhttptest/
slowloris + Heartbleed), verifies SHA256, samples a slice into data/slices/, and
prints row/label counts.

Primary corpus is the *traffic_labels* mirror (bvsam/cic-ids-2017 on Hugging Face):
it keeps the full official CIC schema - Flow ID, Source IP/Port, Destination
IP/Port, Protocol, Timestamp + 79 features + Label - which the ingest layer
(src/ingest) needs for identity fields. Earlier mirrors (c01dsnap) stripped the
identity columns, so they are kept only as fallbacks.

Usage:
    python scripts/fetch/download_baseline_slice.py [--rows 200000]

Full corpus (if you want it later): https://www.unb.ca/cic/datasets/ids-2017.html
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RAW_DIR = REPO / "data" / "raw"
SLICE_DIR = REPO / "data" / "slices"

# Pinned sources (primary first). Wednesday contains BENIGN + DoS + Heartbleed.
URLS = [
    # Full identity columns (Flow ID, IPs, ports, Protocol, Timestamp) + labels.
    ("https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/"
     "traffic_labels/Wednesday-workingHours.pcap_ISCX.csv.parquet"),
    # No identity columns (stripped by the mirror) - fallback only.
    ("https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/"
     "Wednesday-workingHours.pcap_ISCX.csv"),
    # Small benign-only sample (smoke tests only).
    ("https://raw.githubusercontent.com/tilakkm20225-maker/"
     "Neuro-Symbolic-AI-for-Automated-Cyber-Threat-Intelligence-Generation/main/"
     "Dataset/sample_Wednesday-workingHours.pcap_ISCX.csv"),
]
DEST_NAME = "cic-ids2017-wednesday.parquet"   # primary; .csv fallbacks keep their suffix
CHUNK = 1 << 20


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def download(dest: Path) -> Path:
    """Download the corpus; returns the path actually written (fallbacks may change the suffix)."""
    last_err: Exception | None = None
    for url in URLS:
        suffix = Path(url.split("?")[0]).suffix.lower()
        print(f"[get] {url}")
        try:
            with (urllib.request.urlopen(url, timeout=900) as resp,  # pinned https
                  tempfile.NamedTemporaryFile(
                      dir=dest.parent, prefix=".dl-", suffix=".part", delete=False
                  ) as tmp):
                tmp_path = Path(tmp.name)
                h = hashlib.sha256()
                total = 0
                while True:
                    chunk = resp.read(CHUNK)
                    if not chunk:
                        break
                    tmp.write(chunk)
                    h.update(chunk)
                    total += len(chunk)
            if suffix != dest.suffix.lower():
                dest = dest.with_suffix(suffix)
            tmp_path.replace(dest)
            print(f"[sha256] {h.hexdigest()}")
            print(f"[ok] {dest} ({total / 1e6:.1f} MB)")
            return dest
        except Exception as exc:  # noqa: BLE001 - try next mirror on any failure
            last_err = exc
            print(f"[error] {exc}", file=sys.stderr)
            tmp_path.unlink(missing_ok=True)
    raise RuntimeError(f"all mirrors failed: {last_err}")


def summarize(corpus_path: Path, rows: int) -> Path:
    import pandas as pd  # local import: only needed for the summarize step

    SLICE_DIR.mkdir(parents=True, exist_ok=True)
    suffix = corpus_path.suffix.lower()
    print(f"[load] reading {suffix} ...")
    if suffix == ".csv":
        df = pd.read_csv(corpus_path, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
    else:
        df = pd.read_parquet(corpus_path)

    label_col = "Label" if "Label" in df.columns else next(
        c for c in df.columns if "label" in c.lower()
    )
    counts = df[label_col].value_counts()
    print(f"[rows] total={len(df):,}")
    print("[labels]")
    for label, n in counts.items():
        print(f"    {label:<40} {n:>10,}")

    have_identity = {"Source IP", "Destination IP", "Source Port",
                     "Destination Port", "Protocol", "Timestamp"} <= set(df.columns)
    print(f"[schema] {len(df.columns)} columns; identity fields present: {have_identity}")

    # Balanced slice: attack rows capped at half the budget, benign fills the rest.
    attacks = df[df[label_col] != "BENIGN"]
    benign = df[df[label_col] == "BENIGN"]
    attack_budget = rows // 2
    if len(attacks) > attack_budget:
        attacks = attacks.sample(n=attack_budget, random_state=42)
    benign_budget = rows - len(attacks)
    if len(benign) > benign_budget:
        benign = benign.sample(n=benign_budget, random_state=42)
    sliced = pd.concat([benign, attacks], ignore_index=True)
    sliced = sliced.sample(frac=1.0, random_state=42).reset_index(drop=True)

    out = SLICE_DIR / "baseline_slice.parquet"
    sliced.to_parquet(out, index=False)
    print(f"[slice] {out}: {len(sliced):,} rows "
          f"({int((sliced[label_col] != 'BENIGN').sum()):,} attacks)")
    print(f"[sha256] {sha256_of_file(out)}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=200_000, help="slice budget")
    args = parser.parse_args()
    try:
        RAW_DIR.mkdir(parents=True, exist_ok=True)
        dest = RAW_DIR / DEST_NAME
        if not dest.exists():
            dest = download(dest)
        else:
            print(f"[skip] already downloaded: {dest}")
        summarize(dest, args.rows)
    except Exception as exc:  # noqa: BLE001 - network/IO failures, report and exit 1
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
