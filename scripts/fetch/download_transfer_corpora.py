#!/usr/bin/env python3
"""Transfer corpora: download + verify + manifest (MAX scope).

Extends scripts/fetch/download_ml_corpora.py (CIC-IDS2017, 5x CTU-13, DGA,
Umbrella) with every remaining corpus the evaluation axis references:

  * CIC-DDoS2019, ALL attack days, both collection dates (01-12: 11 files,
    03-11: 7 files), HF baalajimaestro mirror (per-day CSVs incl. Syn.csv,
    the Sep-2026 zero-shot corpus) -> data/raw/ddos2019/
  * CSE-CIC-IDS2018, ALL 10 TrafficForML days (HF bencorn mirror of the
    official CICFlowMeter exports) -> data/raw/ids2018/
  * UNSW-NB15, training-set.csv + feature doc (HF Mouwiya mirror; the
    testing-set.csv is not hosted on this mirror) -> data/raw/unsw/
  * CTU-13, the 8 remaining scenarios (44-50, 54), same mcfp host + path
    scheme as the 5 pinned in download_ml_corpora.py (dir listings verified
    2026-09-16) -> data/raw/ctu13/

Every file is pinned (URL recorded in data/raw/manifest.json with SHA256
after download); existing non-empty files are skipped, so re-runs are
resumable. Corpora are NEVER committed (data/ is git-ignored).

Usage:
    python scripts/fetch/download_transfer_corpora.py            # everything missing
    python scripts/fetch/download_transfer_corpora.py --only ctu13
    python scripts/fetch/download_transfer_corpora.py --jobs 4   # parallel (default)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RAW = REPO / "data" / "raw"
MANIFEST = RAW / "manifest.json"
CHUNK = 1 << 20

HF_DDOS = "https://huggingface.co/datasets/baalajimaestro/CICDDoS2019/resolve/main"
HF_IDS = ("https://huggingface.co/datasets/bencorn/CICIDS2018/resolve/main"
          "/Processed_Traffic_Data_for_ML_Algorithms")
HF_UNSW = "https://huggingface.co/datasets/Mouwiya/UNSW-NB15/resolve/main"
CTU = "https://mcfp.felk.cvut.cz/publicDatasets"

# (group, relpath, url)
FILES: list[tuple[str, str, str]] = [
    # --- UNSW-NB15 (small: first, fails fast if the mirror moves) ---------
    ("unsw", "unsw/UNSW_NB15_training-set.csv",
     f"{HF_UNSW}/UNSW_NB15_training-set.csv"),
    ("unsw", "unsw/NUSW-NB15_features.csv",
     f"{HF_UNSW}/NUSW-NB15_features.csv"),
    # --- CIC-DDoS2019 01-12 (training day: 11 attack CSVs) -----------------
    *[(
        "ddos2019", f"ddos2019/01-12/{n}.csv", f"{HF_DDOS}/01-12/{n}.csv")
        for n in ("DrDoS_DNS", "DrDoS_LDAP", "DrDoS_MSSQL", "DrDoS_NTP",
                  "DrDoS_NetBIOS", "DrDoS_SNMP", "DrDoS_SSDP", "DrDoS_UDP",
                  "Syn", "TFTP", "UDPLag")],
    # --- CIC-DDoS2019 03-11 (test day: 7 attack CSVs) -----------------------
    *[(
        "ddos2019", f"ddos2019/03-11/{n}.csv", f"{HF_DDOS}/03-11/{n}.csv")
        for n in ("LDAP", "MSSQL", "NetBIOS", "Portmap", "Syn", "UDP", "UDPLag")],
    # --- CTU-13 remaining scenarios (verified dir listings, 2026-09-16) -----
    ("ctu13", "ctu13/CTU-44-capture20110812.binetflow",
     f"{CTU}/CTU-Malware-Capture-Botnet-44/detailed-bidirectional-flow-labels/capture20110812.binetflow"),
    ("ctu13", "ctu13/CTU-45-capture20110815.binetflow",
     f"{CTU}/CTU-Malware-Capture-Botnet-45/detailed-bidirectional-flow-labels/capture20110815.binetflow"),
    ("ctu13", "ctu13/CTU-46-capture20110815-2.binetflow",
     f"{CTU}/CTU-Malware-Capture-Botnet-46/detailed-bidirectional-flow-labels/capture20110815-2.binetflow"),
    ("ctu13", "ctu13/CTU-47-capture20110816.binetflow",
     f"{CTU}/CTU-Malware-Capture-Botnet-47/detailed-bidirectional-flow-labels/capture20110816.binetflow"),
    ("ctu13", "ctu13/CTU-48-capture20110816-2.binetflow",
     f"{CTU}/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/capture20110816-2.binetflow"),
    ("ctu13", "ctu13/CTU-49-capture20110816-3.binetflow",
     f"{CTU}/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816-3.binetflow"),
    ("ctu13", "ctu13/CTU-50-capture20110817.binetflow",
     f"{CTU}/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow"),
    ("ctu13", "ctu13/CTU-54-capture20110815-3.binetflow",
     f"{CTU}/CTU-Malware-Capture-Botnet-54/detailed-bidirectional-flow-labels/capture20110815-3.binetflow"),
    # --- CSE-CIC-IDS2018 (all 10 ML days; biggest: last) --------------------
    *[(
        "ids2018", f"ids2018/{n}_TrafficForML_CICFlowMeter.csv", f"{HF_IDS}/{n}_TrafficForML_CICFlowMeter.csv")
        for n in ("Friday-02-03-2018", "Friday-16-02-2018", "Friday-23-02-2018",
                  "Thuesday-20-02-2018", "Thursday-01-03-2018",
                  "Thursday-15-02-2018", "Thursday-22-02-2018",
                  "Wednesday-14-02-2018", "Wednesday-21-02-2018",
                  "Wednesday-28-02-2018")],
]


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[get] {url}", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    total = 0
    with (urllib.request.urlopen(req, timeout=3600) as resp,
          tempfile.NamedTemporaryFile(dir=dest.parent, prefix=".dl-", delete=False) as tmp):
        tmp_path = Path(tmp.name)
        while True:
            chunk = resp.read(CHUNK)
            if not chunk:
                break
            tmp.write(chunk)
            total += len(chunk)
    tmp_path.replace(dest)
    print(f"[ok] {dest.relative_to(REPO)} ({total / 1e6:.1f} MB)", flush=True)
    return total


def main() -> int:
    import concurrent.futures
    import threading

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", choices=sorted({g for g, _, _ in FILES}),
                    help="restrict to one corpus group")
    ap.add_argument("--jobs", type=int, default=4,
                    help="parallel downloads (default 4)")
    args = ap.parse_args()

    RAW.mkdir(parents=True, exist_ok=True)
    manifest: dict = {}
    if MANIFEST.exists():
        manifest = json.loads(MANIFEST.read_text())
    lock = threading.Lock()

    pending = []
    for group, rel, url in FILES:
        if args.only and group != args.only:
            continue
        dest = RAW / rel
        if dest.exists() and dest.stat().st_size > 0:
            print(f"[skip] {rel} (exists)", flush=True)
            # Preserve an existing pin; a missing one (older script
            # revision) is backfilled from the file, mtime as fetch time.
            manifest.setdefault(rel, {
                "url": url,
                "sha256": sha256_of(dest),
                "bytes": dest.stat().st_size,
                "fetched_at": datetime.fromtimestamp(
                    dest.stat().st_mtime, timezone.utc).isoformat(),
            })
            continue
        else:
            pending.append((rel, url, dest))

    def save(rel: str, url: str, dest: Path) -> None:
        with lock:
            manifest[rel] = {
                "url": url,
                "sha256": sha256_of(dest),
                "bytes": dest.stat().st_size,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }
            MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    def fetch_one(item: tuple[str, str, Path]) -> str | None:
        rel, url, dest = item
        try:
            download(url, dest)
        except Exception as exc:  # noqa: BLE001 - report and continue
            print(f"[error] {rel}: {exc}", file=sys.stderr)
            return rel
        save(rel, url, dest)
        return None

    failures = 0
    jobs = max(1, args.jobs)
    if len(pending) > 1 and jobs > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            for failed in pool.map(fetch_one, pending):
                failures += failed is not None
    else:
        for item in pending:
            failures += fetch_one(item) is not None

    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"[manifest] {MANIFEST} ({len(manifest)} entries)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
