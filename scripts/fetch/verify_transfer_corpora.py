#!/usr/bin/env python3
"""Verify every transfer corpus: rows, columns, labels, identity fields.

Writes data/raw/corpus_ledger.json (the honest ledger) and prints a table.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[2]
RAW = REPO / "data" / "raw"
LEDGER = RAW / "corpus_ledger.json"

IDENTITY = ["Flow ID", "Source IP", "Source Port",
            "Destination IP", "Destination Port", "Protocol", "Timestamp"]


def verify_csv(path: Path) -> dict:
    header = pd.read_csv(path, nrows=0, skipinitialspace=True)
    cols = [str(c).strip() for c in header.columns]
    label_col = next((c for c in ("Label", "label", "attack_cat")
                      if c in cols), None)
    n, labs = 0, {}
    use = [label_col] if label_col else []
    for ch in pd.read_csv(path, usecols=use or None, chunksize=500_000,
                          skipinitialspace=True, low_memory=False):
        if use:
            n += len(ch)
            for k, v in ch[label_col].astype(str).value_counts().items():
                labs[str(k).strip()] = labs.get(str(k).strip(), 0) + int(v)
        else:
            n += len(ch)
    return {"rows": n, "columns": len(cols), "label_col": label_col,
            "labels": labs,
            "identity": [c for c in IDENTITY if c in cols],
            "identity_full": all(c in cols for c in IDENTITY)}


def verify_binetflow(path: Path) -> dict:
    n, bot = 0, 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i == 0:
                header = line.strip()
                continue
            n += 1
            if "Bot" in line:
                bot += 1
    return {"rows": n, "header": header[:120], "bot_rows": bot,
            "identity_full": True}


def main() -> int:
    ledger: dict = {}
    targets = sorted((RAW / "ddos2019").rglob("*.csv")) \
        + sorted((RAW / "ids2018").rglob("*.csv")) \
        + [RAW / "unsw" / "UNSW_NB15_training-set.csv"] \
        + sorted((RAW / "ctu13").glob("CTU-4*.binetflow*")) \
        + sorted((RAW / "ctu13").glob("CTU-5*.binetflow*"))
    for p in targets:
        rel = p.relative_to(RAW).as_posix()
        print(f"[verify] {rel} ({p.stat().st_size / 1e6:.0f} MB)", flush=True)
        try:
            if p.suffix == ".csv":
                ledger[rel] = verify_csv(p)
            else:
                ledger[rel] = verify_binetflow(p)
        except Exception as exc:  # noqa: BLE001
            ledger[rel] = {"error": str(exc)[:200]}
            print(f"  ERROR {exc}", flush=True)
            continue
        info = ledger[rel]
        print(f"  rows={info.get('rows'):,} labels={list(info.get('labels', {}))[:8]}"
              f" identity_full={info.get('identity_full')}", flush=True)
    LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True))
    print(f"[ledger] {LEDGER}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
