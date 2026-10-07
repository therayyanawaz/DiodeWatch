"""End-to-end CLI checks for the WAF replay harness (report §5.4 / Appendix A).

Runs waf_replay.py as a subprocess so the exact documented commands stay
working: --help (side-effect free), --schema, --generate-corpus, --dry-run,
--self-test (real ephemeral server, 12/12 metric assertions), and the
degraded exit-2 path against a dead port.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

WAF_DIR = Path(__file__).resolve().parents[2] / "waf"
HARNESS = WAF_DIR / "waf_replay.py"
CORPUS = WAF_DIR / "cases.jsonl"


def test_edge_rejection_statuses_count_as_blocked():
    """400/413 must count as blocked, not as misses.

    Measured against a live nginx+ModSecurity stack: the traversal case
    returns 400 from nginx in both the armed and rules-off runs, and an
    oversized body is refused 413 before ModSecurity can answer 403. A
    narrower set would report stopped attacks as misses.
    """
    sys.path.insert(0, str(WAF_DIR))
    import waf_replay

    assert {400, 403, 405, 413, 414} <= waf_replay.BLOCK_STATUSES


def run(*args: str, cwd: Path = WAF_DIR) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HARNESS), *args],
        cwd=cwd, capture_output=True, text=True, timeout=120, check=False,
    )


def test_help_is_side_effect_free():
    proc = run("--help")
    assert proc.returncode == 0


def test_schema_is_valid_json():
    proc = run("--schema")
    assert proc.returncode == 0
    schema = json.loads(proc.stdout)
    assert "category" in schema and "expect" in schema


def test_generate_corpus_roundtrip(tmp_path):
    out = tmp_path / "smoke.jsonl"
    proc = run("--generate-corpus", str(out))
    assert proc.returncode == 0
    lines = [l for l in out.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 20
    records = [json.loads(l) for l in lines]
    assert sum(1 for r in records if r["expect"] == "blocked") == 12


def test_committed_corpora_match_generated_builtin(tmp_path):
    """The on-disk corpora must be exactly what --generate-corpus produces.

    They drifted once (cases.jsonl kept a placeholder long URI) and the
    divergence was invisible because nothing compared the two.
    """
    out = tmp_path / "builtin.jsonl"
    proc = run("--generate-corpus", str(out))
    assert proc.returncode == 0
    expected = out.read_bytes()
    assert b"\r\n" not in expected, "corpus must be LF-only across platforms"
    assert (WAF_DIR / "cases.jsonl").read_bytes() == expected
    assert (WAF_DIR / "smoke.jsonl").read_bytes() == expected


def test_dry_run_plans_without_traffic(tmp_path):
    summary = tmp_path / "plan.json"
    proc = run("--dry-run", "--corpus", str(CORPUS), "--summary", str(summary))
    assert proc.returncode == 0
    assert "12 attack" in proc.stdout and "8 benign" in proc.stdout
    plan = json.loads(summary.read_text(encoding="utf-8"))
    assert plan["planned"] == 20 and plan["attack"] == 12


def test_self_test_asserts_metric_math(tmp_path):
    summary = tmp_path / "selftest.json"
    proc = run("--self-test", "--summary", str(summary))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert all(c["pass"] for c in payload["checks"])
    assert len(payload["checks"]) == 12


def test_dead_server_degrades_with_exit_2(tmp_path):
    summary = tmp_path / "dead.json"
    proc = run("--corpus", str(CORPUS), "--nginx-url", "http://127.0.0.1:9",
               "--timeout", "3", "--summary", str(summary))
    assert proc.returncode == 2
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["errors"] == payload["total"]


def test_malformed_corpus_is_usage_error(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"id": "no-category", "expect": "allowed"}\n', encoding="utf-8")
    proc = run("--corpus", str(bad))
    assert proc.returncode == 1
    assert "category" in (proc.stderr + proc.stdout).lower()


# Corpus format detection: JSONL, a JSON array, a wrapper object, and CSV
# (canonical + aliased headers) must all load. JSONL is the case worth
# guarding: its objects carry more commas than braces, so any detection
# that sniffs comma density routes it to the CSV reader and every record
# fails field validation with a misleading message.

A = {"id": "a", "category": "sqli", "uri": "/x", "expect": "blocked"}
B = {"id": "b", "category": "benign", "uri": "/", "expect": "allowed"}

FORMATS = [
    ("cases.jsonl", "\n".join(json.dumps(r) for r in (A, B)) + "\n"),
    ("array.json", json.dumps([A, B], indent=2)),
    ("wrapper.json", json.dumps({"cases": [A, B]})),
    ("plain.csv", "id,category,uri,expect\na,sqli,/x,blocked\nb,benign,/,allowed\n"),
    ("alias.csv", "case,class,path,verdict\na,sqli,/x,blocked\nb,benign,/,allowed\n"),
]


@pytest.mark.parametrize("name, content", FORMATS, ids=[f[0] for f in FORMATS])
def test_corpus_formats_all_load(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    summary = tmp_path / "plan.json"
    proc = run("--dry-run", "--corpus", str(path), "--summary", str(summary))
    assert proc.returncode == 0, proc.stderr
    plan = json.loads(summary.read_text(encoding="utf-8"))
    assert plan["planned"] == 2
    assert plan["attack"] == 1 and plan["benign"] == 1


def test_jsonl_is_not_misrouted_to_the_csv_reader(tmp_path):
    """Regression: comma-density sniffing sent JSONL to the CSV reader.

    The symptom was exit 1 with "'category' is required" for every record,
    so both the clean exit and the absence of that error are asserted.
    """
    path = tmp_path / "cases.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in (A, B)) + "\n", encoding="utf-8")
    proc = run("--dry-run", "--corpus", str(path))
    assert proc.returncode == 0, proc.stderr
    assert "2 records" in proc.stdout
    assert "category" not in (proc.stderr + proc.stdout).lower()


def test_lone_json_object_is_one_record(tmp_path):
    path = tmp_path / "one.json"
    path.write_text(json.dumps(A), encoding="utf-8")
    summary = tmp_path / "plan.json"
    proc = run("--dry-run", "--corpus", str(path), "--summary", str(summary))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(summary.read_text(encoding="utf-8"))["planned"] == 1


def test_empty_corpus_is_usage_error_not_crash(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    proc = run("--corpus", str(empty))
    assert proc.returncode == 1
    assert "no usable records" in (proc.stderr + proc.stdout)
    assert "Traceback" not in proc.stderr
