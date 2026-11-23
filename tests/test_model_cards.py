"""A model card that drifts from the artifact is worse than no card.

These tests tie each shipped `.joblib` to its documentation: the digest in the
card and in the register must be the digest of the bytes in the tree, the size
must match, the recorded decision threshold must be the one inside the artifact,
and the feature-order pin must cover every channel the code scores with.

Rebuilding a model without touching its card now fails here, which is the only
way a register stays true.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MODEL_DIR = REPO / "docs" / "evaluation" / "models"
CARDS = REPO / "docs" / "models"
REGISTER = CARDS / "README.md"
PIN = CARDS / "feature_order.json"

pytest.importorskip("joblib")


def _shipped() -> list[Path]:
    return sorted(MODEL_DIR.glob("*.joblib"))


def test_the_register_lists_every_shipped_artifact():
    assert _shipped(), "no model artifacts in docs/evaluation/models"
    register = REGISTER.read_text(encoding="utf-8")
    for path in _shipped():
        assert path.name in register, f"{path.name} missing from docs/models/README.md"


@pytest.mark.parametrize("path", _shipped(), ids=lambda p: p.name)
def test_the_card_records_the_digest_of_the_shipped_bytes(path):
    """The card is the human-readable half of an integrity check; it has to name
    the file that is actually in the tree."""
    stem = path.stem.split("_")[0]
    card = CARDS / f"{stem}.md"
    assert card.exists(), f"no card for {path.name} (expected {card.name})"

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    size = f"{path.stat().st_size:,}"
    text = card.read_text(encoding="utf-8")
    assert digest in text, f"{card.name} does not record sha256 {digest}"
    assert size in text, f"{card.name} does not record the size {size} bytes"

    # the register's short digest is the same digest, truncated
    register = REGISTER.read_text(encoding="utf-8")
    assert digest[:16] in register, f"register does not record {digest[:16]}"


@pytest.mark.parametrize("path", _shipped(), ids=lambda p: p.name)
def test_the_card_threshold_is_the_artifact_threshold(path):
    """A card that quotes the operating point wrong is how an alert gets read as
    a false positive when it was a true one."""
    joblib = pytest.importorskip("joblib")
    threshold = joblib.load(path)["threshold"]
    stem = path.stem.split("_")[0]
    text = (CARDS / f"{stem}.md").read_text(encoding="utf-8")
    assert repr(threshold) in text, (
        f"{stem}.md does not quote the artifact threshold {threshold!r}")


@pytest.mark.parametrize("path", _shipped(), ids=lambda p: p.name)
def test_the_card_feature_table_matches_the_pin(path):
    """One row per feature, in order: the card's table is a readable copy of the
    positional contract, so it has to be the same length and the same names."""
    joblib = pytest.importorskip("joblib")
    channel = path.stem.split("_")[0]
    pinned = json.loads(PIN.read_text(encoding="utf-8"))["channels"][channel]
    assert list(joblib.load(path)["medians"]) == pinned

    text = (CARDS / f"{channel}.md").read_text(encoding="utf-8")
    rows = re.findall(r"^\|\s*\d+\s*\|\s*`([a-z0-9_]+)`", text, re.MULTILINE)
    assert rows == pinned, f"{channel}.md feature rows drifted from the pin"


def test_the_pin_covers_every_channel_the_code_scores_with():
    """The two channels whose artifacts are not distributed are exactly the ones
    a pin inside a pickle could never protect."""
    from src.detectors.ml import beacon, dga, supervised_windows, tls_ja3

    channels = json.loads(PIN.read_text(encoding="utf-8"))["channels"]
    live = {
        "beacon": list(beacon.BEACON_FEATURES),
        "dga": list(dga.DGA_FEATURES),
        "flowctx": list(supervised_windows.MODEL_FEATURES_CTX),
        "tls": list(tls_ja3.TLS_FEATURES),
    }
    assert set(channels) == set(live)
    for name, features in live.items():
        assert channels[name] == features, f"{name} pin drifted from the module"
        assert len(features) == len(set(features)), f"{name} has duplicate features"


def test_the_register_does_not_restate_measured_quality():
    """Quality figures live in the run records, where the claim guardrail
    reconciles them. A card that copies one creates a second place to go stale."""
    texts = [REGISTER] + sorted(CARDS.glob("*.md"))
    for path in texts:
        if path.name == "README.md":
            text = path.read_text(encoding="utf-8")
            assert "run records" in text
        for line in path.read_text(encoding="utf-8").splitlines():
            assert not re.search(r"\bF1\b|\bROC-AUC\b|\bprecision\b\s+of\s+\d",
                                 line), f"{path.name} restates a metric: {line}"
