"""Smoke test: the baseline slice exists, loads, and has both classes."""
from pathlib import Path

import pandas as pd
import pytest

SLICE = Path(__file__).resolve().parents[2] / "data" / "slices" / "baseline_slice.parquet"


@pytest.mark.skipif(not SLICE.exists(), reason="slice not downloaded (run scripts/fetch/download_baseline_slice.py)")
def test_slice_loads_with_labels():
    df = pd.read_parquet(SLICE)
    label_col = "Label" if "Label" in df.columns else next(
        c for c in df.columns if "label" in c.lower()
    )
    assert len(df) > 0
    labels = set(df[label_col].unique())
    assert "BENIGN" in labels
    assert any(lb != "BENIGN" for lb in labels)
