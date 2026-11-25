"""The reference-IDS harness has to fail honestly when nothing is installed.

That is the property worth locking: a comparison script that prints a plausible
row for a tool it never ran is worse than one that stops, because the row travels
into a slide. The measurement half runs here against the demo capture, which needs
no external tool.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "benchmarks" / "bench_reference.py"
DEMO = REPO / "data" / "pcaps" / "demo_threats.pcap"
# The absence checks need a path that exists and nothing more: the capture is
# generated, not committed, so using it there made the assertion depend on a
# build step that has nothing to do with what it verifies.
PRESENT = REPO / "README.md"


def _module():
    spec = importlib.util.spec_from_file_location("bench_reference", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_a_missing_capture_is_an_error_not_an_empty_result(tmp_path):
    proc = subprocess.run([sys.executable, str(SCRIPT), "--pcap",
                           str(tmp_path / "nope.pcap")],
                          capture_output=True, text=True, timeout=120, check=False)
    assert proc.returncode == 1
    assert "no such capture" in proc.stderr
    assert proc.stdout.strip() == ""


def test_no_reference_ids_installed_exits_two_with_install_instructions(tmp_path):
    """Exit 2 is "nothing was measured", a distinct outcome from a failure, so a
    caller can tell the two apart without parsing prose."""
    bench = _module()
    if bench.available():
        pytest.skip("a reference IDS is installed on this host")
    proc = subprocess.run([sys.executable, str(SCRIPT), "--pcap", str(PRESENT)],
                          capture_output=True, text=True, timeout=600, check=False)
    assert proc.returncode == 2
    assert "nothing was measured" in proc.stderr
    for tool in ("suricata", "zeek"):
        assert tool in proc.stderr
    assert "{" not in proc.stdout, "a JSON document was emitted with no measurement"


def test_asking_for_an_uninstalled_tool_also_exits_two():
    bench = _module()
    for tool in bench.TOOLS:
        if shutil.which(bench.TOOLS[tool]["binary"]):
            pytest.skip(f"{tool} is installed on this host")
    proc = subprocess.run([sys.executable, str(SCRIPT), "--pcap", str(PRESENT),
                           "--tool", "zeek"],
                          capture_output=True, text=True, timeout=600, check=False)
    assert proc.returncode == 2
    assert "not installed" in proc.stderr


@pytest.mark.skipif(not DEMO.exists(), reason="demo capture not generated")
def test_our_own_pass_reports_flows_alerts_and_wall_clock(tmp_path):
    """The half that needs no external tool still has to produce a real row."""
    bench = _module()
    row = bench.run_ours(DEMO)
    assert row["tool"] == "diodewatch"
    assert row["flows"] > 100
    assert row["alerts"] >= 1, "the demo capture is built to fire at least one rule"
    assert row["wall_seconds"] > 0
    assert row["pcap_bytes"] == DEMO.stat().st_size
    # CPU accounting is platform-dependent, and null must mean null, not zero
    assert row["cpu_seconds"] is None or row["cpu_seconds"] >= 0
    json.dumps(row)  # serialisable, this is what --out writes


def test_a_failed_tool_run_reports_unknown_rather_than_zero(tmp_path, monkeypatch):
    """"0 alerts" from a tool that crashed reads as a clean, cheap pass.

    The failure is simulated at the process boundary rather than with a shell
    script, so the assertion is the same on Windows and on the runner."""
    import types

    bench = _module()
    monkeypatch.setattr(bench.shutil, "which", lambda name: f"/fake/{name}")
    monkeypatch.setattr(bench.subprocess, "run", lambda *a, **k: types.SimpleNamespace(
        returncode=3, stdout="", stderr="boom"))
    row = bench.run_tool("suricata", PRESENT)
    assert row["exit_code"] == 3
    assert row["alerts"] is None, "a crashed run must not report zero alerts"
    assert row["alerts_per_cpu_second"] is None


def test_the_help_states_it_does_not_score_accuracy():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "does **not** compute precision" in text
    assert "guessed mapping" in text
