"""The SBOM has to be a real inventory, not a file that exists.

A generated artifact is only worth its CI step if the step would fail when the
artifact went wrong. These tests check the properties a scanner depends on:
CycloneDX shape, a `purl` per component, no duplicate (name, version) pairs, and
byte-identical output across runs so a diff means a dependency moved.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "checks" / "make_sbom.py"


def test_sbom_is_cyclonedx_with_purls_and_no_duplicates(tmp_path):
    out = tmp_path / "sbom.cdx.json"
    proc = subprocess.run([sys.executable, str(SCRIPT), "--out", str(out),
                           "--timestamp", "2026-11-22T09:00:00Z"],
                          capture_output=True, text=True, timeout=180,
                          check=False)
    assert proc.returncode == 0, proc.stderr

    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["metadata"]["timestamp"] == "2026-11-22T09:00:00Z"
    assert doc["serialNumber"].startswith("urn:uuid:")

    comps = doc["components"]
    assert len(comps) > 10, "a nearly empty SBOM means the environment was not read"
    names = [(c["name"], c["version"]) for c in comps]
    assert len(names) == len(set(names)), "duplicate components in the SBOM"
    for comp in comps:
        assert comp["purl"] == f"pkg:pypi/{comp['name']}@{comp['version']}"
        assert comp["bom-ref"] == comp["purl"]
        assert comp["name"] == comp["name"].lower()
        assert "_" not in comp["name"], "purl name was not normalised"
    # sorted, so a diff points at what changed and not where it moved
    assert names == sorted(names)


def test_the_sbom_covers_the_runtime_dependencies(tmp_path):
    out = tmp_path / "sbom.cdx.json"
    subprocess.run([sys.executable, str(SCRIPT), "--out", str(out)],
                   capture_output=True, text=True, timeout=180, check=True)
    names = {c["name"] for c in json.loads(out.read_text(encoding="utf-8"))["components"]}
    for expected in ("pandas", "numpy", "scipy", "scikit-learn", "fastapi"):
        assert expected in names, f"{expected} missing from the SBOM"


def test_two_runs_over_one_environment_are_identical(tmp_path):
    """Determinism is the point: a nightly diff has to be readable."""
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    for target in (first, second):
        subprocess.run([sys.executable, str(SCRIPT), "--out", str(target),
                        "--timestamp", "2026-11-22T09:00:00Z"],
                       capture_output=True, text=True, timeout=180, check=True)
    assert first.read_bytes() == second.read_bytes()


def test_skipped_distributions_really_are_omitted(tmp_path):
    out = tmp_path / "sbom.cdx.json"
    subprocess.run([sys.executable, str(SCRIPT), "--out", str(out),
                    "--skip", "pandas,pip"],
                   capture_output=True, text=True, timeout=180, check=True)
    names = {c["name"] for c in json.loads(out.read_text(encoding="utf-8"))["components"]}
    assert "pandas" not in names and "pip" not in names
    assert "numpy" in names
