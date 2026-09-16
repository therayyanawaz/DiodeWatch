#!/usr/bin/env python3
"""ML corpora: download + verify + manifest.

Every corpus is pinned (URL + SHA256 recorded in data/raw/manifest.json before
it is used in training), per the quality gates in
docs/history/project-context.md. Files that
already exist (any size > 0) are skipped, so the script is resumable.

Corpora:
  * CIC-IDS2017, six days as parquet (HF bvsam traffic_labels mirror, the same
    mirror pinned in docs/datasets.md) -> data/raw/cic2017/
  * CTU-13 scenarios 42/43/51/52/53, detailed-bidirectional labeled NetFlows
    (mcfp.felk.cvut.cz) -> data/raw/ctu13/
  * DGA corpus: harpomaxx/dga-detection argencon.csv.gz (CC-BY-2.0; 1.0M benign
    incl. Bambenek suspicious-normal + 1.9M DGA from 51 malware families)
    -> data/raw/dga/
  * Cisco Umbrella top-1m (independent benign domain list) -> data/raw/dns/

Usage:
    python scripts/fetch/download_ml_corpora.py            # everything missing
    python scripts/fetch/download_ml_corpora.py --only cic2017
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

CIC = "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/traffic_labels"
CTU = "https://mcfp.felk.cvut.cz/publicDatasets"

# (group, relpath, url)
FILES: list[tuple[str, str, str]] = [
    # --- CIC-IDS2017 days (parquet, full official schema + Label) ---------
    ("cic2017", "cic2017/Monday-WorkingHours.pcap_ISCX.csv.parquet",
     f"{CIC}/Monday-WorkingHours.pcap_ISCX.csv.parquet"),
    ("cic2017", "cic2017/Tuesday-WorkingHours.pcap_ISCX.csv.parquet",
     f"{CIC}/Tuesday-WorkingHours.pcap_ISCX.csv.parquet"),
    ("cic2017", "cic2017/Wednesday-workingHours.pcap_ISCX.csv.parquet",
     f"{CIC}/Wednesday-workingHours.pcap_ISCX.csv.parquet"),
    ("cic2017", "cic2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet",
     f"{CIC}/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet"),
    ("cic2017", "cic2017/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv.parquet",
     f"{CIC}/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv.parquet"),
    ("cic2017", "cic2017/Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet",
     f"{CIC}/Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet"),
    ("cic2017", "cic2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet",
     f"{CIC}/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet"),
    ("cic2017", "cic2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet",
     f"{CIC}/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet"),
    # --- CTU-13 botnet captures (detailed-bidirectional labeled NetFlow) --
    ("ctu13", "ctu13/CTU-42-capture20110810.binetflow",
     (f"{CTU}/CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/"
      "capture20110810.binetflow")),
    ("ctu13", "ctu13/CTU-43-capture20110811.binetflow",
     (f"{CTU}/CTU-Malware-Capture-Botnet-43/detailed-bidirectional-flow-labels/"
      "capture20110811.binetflow")),
    ("ctu13", "ctu13/CTU-51-capture20110818.binetflow.labeled",
     (f"{CTU}/CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/"
      "capture20110818.binetflow.labeled")),
    ("ctu13", "ctu13/CTU-52-capture20110818-2.binetflow",
     (f"{CTU}/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/"
      "capture20110818-2.binetflow")),
    ("ctu13", "ctu13/CTU-53-capture20110819.binetflow",
     (f"{CTU}/CTU-Malware-Capture-Botnet-53/detailed-bidirectional-flow-labels/"
      "capture20110819.binetflow")),
    # --- DGA + benign domains --------------------------------------------
    ("dga", "dga/argencon.csv.gz",
     "https://huggingface.co/datasets/harpomaxx/dga-detection/resolve/main/argencon.csv.gz"),
    ("dga", "dns/top-1m.csv.zip",
     "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"),
]


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[get] {url}")
    with (urllib.request.urlopen(url, timeout=900) as resp,
          tempfile.NamedTemporaryFile(dir=dest.parent, prefix=".dl-", delete=False) as tmp):
        tmp_path = Path(tmp.name)
        total = 0
        while True:
            chunk = resp.read(CHUNK)
            if not chunk:
                break
            tmp.write(chunk)
            total += len(chunk)
    tmp_path.replace(dest)
    print(f"[ok] {dest} ({total / 1e6:.1f} MB)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", choices=sorted({g for g, _, _ in FILES}),
                    help="restrict to one corpus group")
    args = ap.parse_args()

    RAW.mkdir(parents=True, exist_ok=True)
    manifest: dict = {}
    if MANIFEST.exists():
        manifest = json.loads(MANIFEST.read_text())

    failures = 0
    for group, rel, url in FILES:
        if args.only and group != args.only:
            continue
        dest = RAW / rel
        if dest.exists() and dest.stat().st_size > 0:
            print(f"[skip] {rel} (exists)")
            sha = sha256_of(dest)
        else:
            try:
                download(url, dest)
                sha = sha256_of(dest)
            except Exception as exc:  # noqa: BLE001 - report and continue
                print(f"[error] {rel}: {exc}", file=sys.stderr)
                failures += 1
                continue
        manifest[rel] = {
            "url": url,
            "sha256": sha,
            "bytes": dest.stat().st_size,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }

    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"[manifest] {MANIFEST} ({len(manifest)} entries)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
