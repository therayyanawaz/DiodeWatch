"""Shared test setup.

CI restores the pinned evaluation artifacts (models + metric JSONs) before
running pytest. Do the same locally so a fresh clone, where ``models/`` and
``results/`` are git-ignored, runs the identical suite instead of failing on
missing files that are committed under ``docs/evaluation/``.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

# The live store loads models/calibration.json by default in production. Tests
# must not depend on a repo artifact: calibration tests build their own policy.
os.environ["DIODE_CALIBRATION"] = "off"

REPO = Path(__file__).resolve().parents[1]
_RESTORE = (
    (REPO / "docs" / "evaluation" / "models", REPO / "models", "*.joblib"),
    (REPO / "docs" / "evaluation" / "models", REPO / "models", "calibration.json"),
    (REPO / "docs" / "evaluation" / "runs", REPO / "results" / "ml", "*_metrics.json"),
)


@pytest.fixture(scope="session", autouse=True)
def _pinned_eval_artifacts() -> None:
    """Mirror the CI restore step, without overwriting local artifacts."""
    for src, dst, pattern in _RESTORE:
        dst.mkdir(parents=True, exist_ok=True)
        for artifact in src.glob(pattern):
            target = dst / artifact.name
            if not target.exists():
                shutil.copy2(artifact, target)
