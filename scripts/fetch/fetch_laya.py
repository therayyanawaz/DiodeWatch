#!/usr/bin/env python3
"""Fetch the Laya ONNX bundle once (pinned), offline afterwards.

Downloads the receptron/laya export bundle from the pinned Hugging Face
commit, so every enclave re-derives byte-identical decisions. The bundle
(~1.7 GB fp32) lands in models/laya-onnx/ (git-ignored); runtime never calls
the network, this script is the only place huggingface_hub is imported.

    python scripts/fetch/fetch_laya.py            # pin + fetch
    python scripts/fetch/fetch_laya.py --list     # show the pinned commit
    python scripts/fetch/fetch_laya.py --out D:\\laya  # custom dir (air-gap copy)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from src.triage.laya_runtime import MODEL_REVISION

# The receptron/laya export bundle (its `repo:` default). This commit hash
# pins it (reproducible decisions across enclaves). Single source of truth
# lives in src/triage/laya_runtime.py (MODEL_REVISION).
HF_REPO = "receptron/laya-onnx"
HF_REVISION = MODEL_REVISION

# Files of the export bundle (BUNDLE_FILES in receptron/laya; laya.onnx
# carries external data in the sibling laya.onnx.data file).
WANTED = (
    "laya.onnx",
    "laya.onnx.data",
    "laya_config.json",
    "tokenizer/tokenizer.json",
    "tokenizer/tokenizer_config.json",
)


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(out_dir: Path, revision: str = HF_REVISION) -> dict:
    from huggingface_hub import hf_hub_download

    out_dir.mkdir(parents=True, exist_ok=True)
    got = {}
    for rel in WANTED:
        p = hf_hub_download(HF_REPO, rel, revision=revision)
        dst = out_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if p != dst:
            shutil.copyfile(p, dst)
        got[rel] = _sha256(dst)
    return got


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(REPO / "models" / "laya-onnx"))
    ap.add_argument("--list", action="store_true",
                    help="print the pin and exit")
    args = ap.parse_args(argv)

    if args.list:
        print(json.dumps({"repo": HF_REPO, "revision": HF_REVISION,
                          "files": list(WANTED)}, indent=2))
        return 0
    try:
        hashes = fetch(Path(args.out))
    except ImportError:
        print("huggingface_hub is required for the one-time fetch: "
              "pip install huggingface_hub", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 - network failures are expected
        print(f"fetch failed: {e}\n"
              f"(the enclave stays offline; run this once on a networked "
              f"machine and ship models/laya-onnx/ with the bundle)",
              file=sys.stderr)
        return 1
    print(f"Laya bundle pinned at {args.out}")
    for rel, h in hashes.items():
        print(f"  {h[:16]}…  {rel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
