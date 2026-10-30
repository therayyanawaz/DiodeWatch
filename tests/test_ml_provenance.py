"""The shipped models must be loaded by the sklearn version that wrote them.

A pickle is only reproducible on the version that produced it; sklearn says so
itself when it meets an estimator from another version. The beacon and DGA
artifacts carried objects written by 1.9.0 while requirements accepted any
install at 1.4 or newer, which made "runs on a fresh clone" a claim nobody
checked. So the pin is derived from the artifacts rather than remembered by
hand: each model is asked, at load time, which version it came from, and the
dependency declaration has to answer with that exact number.
"""
from __future__ import annotations

import re
import warnings
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _provenance() -> set[str]:
    """Every sklearn version the shipped models report about themselves.

    A model unpickled by the same version that wrote it stays silent, so an
    empty result means "no conflict here", not "nothing to pin".
    """
    joblib = pytest.importorskip("joblib")
    found: set[str] = set()
    for path in sorted((REPO / "models").glob("*.joblib")):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            joblib.load(path)
        for w in caught:
            m = re.search(r"unpickle estimator \w+ from version ([\d.]+)",
                          str(w.message))
            if m:
                found.add(m.group(1))
    return found


def test_requirements_pin_the_sklearn_the_models_were_written_by():
    lines = [ln.strip() for ln in
             (REPO / "requirements.txt").read_text(encoding="utf-8").splitlines()]
    spec = [ln for ln in lines if ln.startswith("scikit-learn")]
    assert len(spec) == 1, spec          # one declaration, not a floor plus a pin

    # An open range would let a fresh clone install a version that sklearn
    # itself calls unsafe for these pickles, so the declaration must be exact.
    assert spec[0].startswith("scikit-learn=="), spec[0]

    trained = _provenance()
    if trained:
        assert len(trained) == 1, (
            f"the shipped models were written by more than one sklearn version "
            f"{sorted(trained)}; no single pin can reproduce them all")
        assert spec[0] == f"scikit-learn=={trained.pop()}", (
            f"the models report {sorted(trained)}, requirements declares "
            f"{spec[0]!r}")
