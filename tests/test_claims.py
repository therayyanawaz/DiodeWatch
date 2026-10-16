"""Claim-guardrail tests: the executable Appendix A must stay clean, and each
of its three contracts must actually bite when a number or a scope is wrong.

Every negative test builds a throwaway tree (`--root`) instead of editing the
real README/docs, the guardrail's own test suite must never put the repo in a
dirty state, and a test that rewrites a scanned surface can corrupt it if the
run is interrupted.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

_SPEC = importlib.util.spec_from_file_location(
    "check_claims", REPO / "scripts" / "checks" / "check_claims.py")
cc = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cc)

BEACON = {"roc_auc_macro": 0.9184}
ROW = "| beacon (C2 periodicity) | leave-one-scenario-out, CTU-13 " \
      "| ROC-AUC (macro) | **{}** |"
# a file that quotes the benign denominator honestly: layer named, 91 stated
HONEST_FP = "The ML engine measured 1 FP in 440,031 benign flows; the rule " \
            "layer fires 91 alerts on benign-labelled windows of it.\n"
SLOGAN_FP = "Measured 1 FP in 440,031 benign flows.\n"


def tree(tmp_path: Path, files: dict[str, str] | None = None,
         metrics: dict[str, dict] | None = None) -> Path:
    """A minimal scan-root: judge-facing files + pinned metric artifacts."""
    root = tmp_path / "repo"
    for rel, text in (files or {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    for name, payload in (metrics or {}).items():
        p = root / "results" / "ml" / f"{name}_metrics.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload), encoding="utf-8")
    return root


def kinds(doc: dict) -> set[tuple[str, str]]:
    return {(f["kind"], f["file"]) for f in doc["findings"]}


# --------------------------------------------------------------------------- #
# the repo as it stands
# --------------------------------------------------------------------------- #
def test_guardrail_clean_on_current_tree():
    doc = cc.scan(REPO)
    assert doc["files_scanned"] > 20, doc["files_scanned"]
    assert doc["findings"] == [], doc["findings"]
    # the numeric contract must be live, not silently skipped for lack of
    # artifacts, a claim checked against nothing proves nothing
    assert doc["metrics_checked"] >= 9, doc
    assert doc["artifact_source"], "no metric artifacts were loaded"
    # same for the suite-size contract: the repo publishes counts, so pytest
    # must have been consulted and the documented figure must equal it
    assert doc["collected_tests"], "pytest collection did not run"
    published = [int(n) for _, t in cc._texts(REPO, include_exempt=True)
                 for n in (cc.DOC_COLLECTED.findall(t)
                           + cc.DOC_PASSED.findall(t))]
    assert published, "no documented test count to reconcile"
    assert all(int(n) == doc["collected_tests"] for n in published), published


def test_metrics_fall_back_to_the_pinned_copies(tmp_path):
    """docs/evaluation/runs is byte-for-byte what results/ml is restored from,
    so the guardrail still reconciles numbers in a fresh clone that never ran
    a training job."""
    root = tree(tmp_path, {"README.md": ROW.format("0.918")}, {})
    for name in ("beacon", "window", "dga", "tls", "supervised"):
        src = REPO / "docs" / "evaluation" / "runs" / f"{name}_metrics.json"
        dst = root / "docs" / "evaluation" / "runs" / f"{name}_metrics.json"
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
    doc = cc.scan(root)
    assert doc["artifact_source"] == "docs/evaluation/runs"
    assert doc["metrics_checked"] >= 1
    assert doc["findings"] == [], doc["findings"]


# --------------------------------------------------------------------------- #
# contract 1, phrasings
# --------------------------------------------------------------------------- #
def test_guardrail_catches_banned_phrase(tmp_path):
    root = tree(tmp_path, {"README.md": "uses SHAP attribution everywhere\n"})
    doc = cc.scan(root)
    assert ("banned-phrase", "README.md") in kinds(doc)
    assert any(f["phrase"] == "SHAP attribution" for f in doc["findings"])


def test_banned_readiness_proclamations(tmp_path):
    root = tree(tmp_path, {"README.md":
                           "battle-tested enterprise-grade world-class\n"})
    flagged = {f["phrase"] for f in cc.scan(root)["findings"]}
    assert {"battle-tested", "enterprise-grade", "world-class"} <= flagged


def test_readiness_internal_exempt(tmp_path):
    """docs/readiness.md quotes banned phrases in its lock table; it must be
    exempt so the guardrail never trips on its own reference."""
    assert "docs/readiness.md" in cc.INTERNAL_EXEMPT
    root = tree(tmp_path, {"docs/readiness.md": "SHAP attribution, "
                                                "zero false positives\n"})
    assert cc.scan(root)["findings"] == []


def test_absolute_fp_claim_needs_a_denominator(tmp_path):
    bad = tree(tmp_path, {"README.md": "Our detector has zero false "
                                       "positives, full stop.\n"})
    assert ("unscoped-zero", "README.md") in kinds(cc.scan(bad))
    ok = tree(tmp_path, {"README.md": "zero false positives on 2.0M benign "
                                      "flows across four corpora\n"})
    assert cc.scan(ok)["findings"] == []


# --------------------------------------------------------------------------- #
# contract 2, numbers must equal the artifact
# --------------------------------------------------------------------------- #
def test_metric_cell_matching_its_artifact_passes(tmp_path):
    root = tree(tmp_path, {"README.md": ROW.format("0.918")},
                {"beacon": BEACON})
    doc = cc.scan(root)
    assert doc["metrics_checked"] == 1
    assert doc["findings"] == []


def test_number_drift_is_caught(tmp_path):
    """The loophole this replaces: a doc edited to a nicer number than the run."""
    root = tree(tmp_path, {"README.md": ROW.format("0.970")},
                {"beacon": BEACON})
    findings = cc.scan(root)["findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["kind"] == "number-drift"
    assert f["phrase"] == "beacon.roc_auc_macro"
    assert "0.97" in f["detail"] and "0.9184" in f["detail"]


def test_approximate_cell_gets_a_tolerance(tmp_path):
    approx = tree(tmp_path, {"README.md":
                             "| supervised reference | per-day holdout "
                             "| macro-F1 | ~0.30 |\n"},
                  {"supervised": {"macro_f1": 0.3401}})
    assert cc.scan(approx)["findings"] == []
    exact = tree(tmp_path, {"README.md":
                            "| supervised reference | per-day holdout "
                            "| macro-F1 | **0.30** |\n"},
                 {"supervised": {"macro_f1": 0.3401}})
    assert {f["kind"] for f in cc.scan(exact)["findings"]} == {"number-drift"}


def test_claim_without_an_artifact_is_loud(tmp_path):
    """An unverifiable number is a finding, not a silent skip."""
    root = tree(tmp_path, {"README.md": ROW.format("0.918")}, {})
    findings = cc.scan(root)["findings"]
    assert [f["kind"] for f in findings] == ["missing-artifact"]


# --------------------------------------------------------------------------- #
# contract 3, a benign denominator must be scoped
# --------------------------------------------------------------------------- #
def test_bare_fp_slogan_is_rejected(tmp_path):
    root = tree(tmp_path, {"README.md": SLOGAN_FP})
    kinds_seen = kinds(cc.scan(root))
    assert ("unscoped-denominator", "README.md") in kinds_seen
    assert ("missing-counter", "README.md") in kinds_seen


def test_scoped_fp_claim_is_accepted(tmp_path):
    root = tree(tmp_path, {"README.md": HONEST_FP})
    assert cc.scan(root)["findings"] == []


# --------------------------------------------------------------------------- #
# contract 4, documented test counts are re-derived, not remembered
# --------------------------------------------------------------------------- #
def test_documented_count_matching_collection_passes(tmp_path):
    root = tree(tmp_path, {"README.md":
                           "| Test suite | **320 collected, 320 passed** |\n"})
    assert cc.scan(root, collected=320)["findings"] == []


def test_stale_documented_count_is_flagged(tmp_path):
    """The bug class this exists for: readiness.md said 152 while the suite had
    grown to 320, and nothing in CI or the tests noticed."""
    root = tree(tmp_path, {"docs/competition/readiness.md":
                           "| Test suite | **152 collected, 152 passed** |\n"})
    doc = cc.scan(root, collected=320)
    assert {f["kind"] for f in doc["findings"]} == {"test-count-drift"}
    assert "320" in doc["findings"][0]["detail"]


def test_count_with_no_way_to_measure_is_loud(tmp_path):
    """A published count that cannot be re-derived is a finding, not a skip."""
    root = tree(tmp_path, {"README.md": "**320 collected**\n"})
    doc = cc.scan(root, collected=None)
    assert {f["kind"] for f in doc["findings"]} == {"test-count-unverifiable"}


def test_skipped_suite_wording_is_not_a_drift(tmp_path):
    """`318 passed, 2 skipped` is legitimate prose when collection is 320."""
    root = tree(tmp_path, {"README.md": "| 318 passed, 2 skipped |\n"})
    assert cc.scan(root, collected=320)["findings"] == []


def test_exempt_reference_docs_still_answer_for_counts(tmp_path):
    """readiness.md is exempt from the phrase scan because it quotes banned
    wording; that exemption must not let it publish a stale number."""
    assert "docs/competition/readiness.md" in cc.INTERNAL_EXEMPT
    root = tree(tmp_path, {"docs/competition/readiness.md":
                           "production ready vibes; **999 collected**\n"})
    doc = cc.scan(root, collected=320)
    assert {f["kind"] for f in doc["findings"]} == {"test-count-drift"}


# --------------------------------------------------------------------------- #
# contract 5, documented commands must resolve
# --------------------------------------------------------------------------- #
def test_broken_documented_command_is_flagged(tmp_path):
    root = tree(tmp_path, {"CONTRIBUTING.md":
                           "Run `python -m scripts.check_claims` first.\n"})
    doc = cc.scan(root)
    assert {f["kind"] for f in doc["findings"]} == {"broken-command"}
    assert doc["findings"][0]["phrase"] == "scripts.check_claims"


def test_command_pointing_at_a_real_file_passes(tmp_path):
    root = tree(tmp_path, {"CONTRIBUTING.md":
                            "Run `python -m scripts.checks.check_claims`, or "
                            "`python scripts/checks/check_claims.py`.\n"})
    mod = root / "scripts" / "checks" / "check_claims.py"
    mod.parent.mkdir(parents=True, exist_ok=True)
    mod.write_text("# noqa\n", encoding="utf-8")
    assert cc.scan(root)["findings"] == []


def test_bare_script_path_is_checked(tmp_path):
    root = tree(tmp_path, {"docs/x.md":
                            "python scripts/check_ml.py train-tls\n"})
    doc = cc.scan(root)
    assert [f["phrase"] for f in doc["findings"]] == ["scripts/check_ml.py"]


def test_stale_command_inside_source_is_flagged(tmp_path):
    """A script's own usage line gets copied into a terminal, so it is a claim:
    over a dozen survived the scripts/ -> scripts/checks/ move still advertising
    a path that no longer existed."""
    root = tree(tmp_path, {"src/alerts/cli.py":
                            "    run: python scripts/check_ml.py train-tls\n"})
    doc = cc.scan(root)
    assert [f["kind"] for f in doc["findings"]] == ["broken-command"]
    assert doc["findings"][0]["file"] == "src/alerts/cli.py"


def test_guardrail_own_placeholders_are_not_commands(tmp_path):
    """check_claims documents its rules with abstract examples
    (`python -m scripts.x.y`); those must not read as broken commands."""
    root = tree(tmp_path, {"scripts/checks/check_claims.py":
                           "every ``python -m scripts.x.y`` / ``python "
                           "scripts/x.py`` in a doc\n"})
    assert cc.scan(root)["findings"] == []


def test_stale_path_pointer_is_flagged(tmp_path):
    """Not every stale pointer is a command. `Mirrors scripts/check_diode.py`
    sits in a docstring, is never run, and still sends the reader to a file that
    moved to scripts/checks/, as did a FileNotFoundError that told an operator
    to run a script which no longer existed at that path."""
    root = tree(tmp_path, {"scripts/checks/check_laya.py":
                           "Mirrors scripts/check_diode.py's shape.\n"})
    doc = cc.scan(root)
    assert [f["kind"] for f in doc["findings"]] == ["broken-path"]
    assert doc["findings"][0]["phrase"] == "scripts/check_diode.py"
    ok = tree(tmp_path / "fixed", {"scripts/checks/check_laya.py":
                                   "Mirrors scripts/checks/check_diode.py.\n",
                                   "scripts/checks/check_diode.py": "# noqa\n"})
    assert cc.scan(ok)["findings"] == []


def test_a_deep_url_is_not_a_local_pointer(tmp_path):
    """A link into the hosted tree ends in what looks like a repo-relative
    path; the checkout on disk cannot be expected to contain that spelling."""
    root = tree(tmp_path, {"README.md":
                           "source: https://github.com/o/r/blob/main/"
                           "src/alerts/watch.py\n"})
    assert cc.scan(root)["findings"] == []


# --------------------------------------------------------------------------- #
# 6, repository contract
# --------------------------------------------------------------------------- #
def test_stale_repo_url_is_flagged():
    """Renaming the remote left README telling judges to clone the stub that
    inherited the old name. Every number in the repo was true, and the first
    instruction a judge follows was still wrong, nothing else in the guardrail
    could see it, because a wrong URL is not a phrase, a metric or a command."""
    found = cc.check_repo_urls(
        [("README.md", "git clone https://github.com/me/DiodeWatch.git\n")],
        "me/legacy-stub")
    assert [f["kind"] for f in found] == ["repo-url-stale"]
    assert found[0]["phrase"] == "github.com/me/DiodeWatch.git"


def test_current_and_third_party_repo_urls_pass():
    """`.git` and path suffixes are spelling, not a different repository, and
    links to upstream projects are not this project's self-reference."""
    readme = ("git clone https://github.com/me/legacy-stub.git\n"
              "![CI](https://github.com/me/legacy-stub/actions/workflows/ci.yml)\n"
              "upstream: https://github.com/pandas-dev/pandas\n")
    texts = [("README.md", readme)]
    assert cc.check_repo_urls(texts, "me/legacy-stub") == []
    # a tree with no origin cannot be judged, so the contract stays silent
    assert cc.check_repo_urls(texts, None) == []


def test_origin_slug_reads_the_live_checkout():
    """The contract is only as good as the slug it compares against."""
    slug = cc.origin_slug(cc.REPO)
    assert slug is not None and "/" in slug
    assert cc.check_repo_urls(
        [("README.md", f"https://github.com/{slug}\n")], slug) == []


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_main_exit_codes(tmp_path):
    clean = tree(tmp_path, {"README.md": HONEST_FP}, {"beacon": BEACON})
    dirty = tree(tmp_path / "d", {"README.md":
                                  "SHAP value + zero false positives\n"})
    assert cc.main(["--quiet", "--root", str(clean)]) == 0
    assert cc.main(["--quiet", "--root", str(dirty)]) == 1
    out = tmp_path / "out.json"
    assert cc.main(["--quiet", "--root", str(clean), "--json", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["findings"] == [] and doc["files_scanned"] == 1
