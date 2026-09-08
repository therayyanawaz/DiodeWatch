"""Pinned ML evaluation metrics, read the same way by every panel.

`results/ml/` is git-ignored training output, so a fresh clone falls back to
the committed snapshot under `docs/evaluation/runs/`. Both surfaces (the
Streamlit metrics tab and the mission-control /api/ml_metrics route) call
this one loader, so a channel's numbers cannot differ between the two apps.
"""
from __future__ import annotations

import json
from pathlib import Path

CHANNELS = ("window", "supervised", "beacon", "dga", "tls")
_RUNTIME = Path("results") / "ml"
_PINNED = Path("docs") / "evaluation" / "runs"


def load_ml_metrics(repo_root: Path) -> dict[str, dict]:
    """Channel -> metrics dict, omitting any channel with no readable pin."""
    out: dict[str, dict] = {}
    for name in CHANNELS:
        for sub in (_RUNTIME, _PINNED):
            p = repo_root / sub / f"{name}_metrics.json"
            if p.exists():
                try:
                    out[name] = json.loads(p.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    pass
                break
    return out
