#!/usr/bin/env python3
"""Claim guardrail: judge-facing prose must agree with the committed artifacts.

Readiness-dossier Appendix A, made executable and test-enforced. Six
contracts, checked over every public surface (README, docs, the web UI, the
Streamlit UI):

1. **Banned phrasings**, wording that must never reach a judge. The two
   absolute-freedom claims ("zero/no false positives") are only banned when
   *unscoped*: a zero with no denominator is a promise, a zero measured over
   2.0M flows is a result.
2. **Numeric contract**, every metric quoted in a table row named by
   ``METRIC_CLAIMS`` must equal the value in the pinned artifact
   (``results/ml/*.json``, falling back to the byte-for-byte
   ``docs/evaluation/runs/*.json`` copy CI restores it from). A doc cell is
   compared at the precision the document itself prints; a ``~``/``≈`` cell
   gets ±0.05. This is what catches a number drifting away from the run, or a
   table being edited to a prettier figure.
3. **Scope contract**, a false-positive claim that quotes a benign
   denominator (440,031 flows, 2.03M flows) must, in the same file, name the
   layer that produced it and state that corpus's own benign-window reality.
   Those two numbers are what keep a per-flow ML precision figure from
   reading as a system-wide FPR: the rule layer emits 3 alerts on
   benign-labelled windows of the Wednesday table, and 32 on the full
   CIC-IDS2017 register (``docs/rules.md``).
4. **Suite-size contract**, any documented "N collected" / "N passed" must
   equal what ``pytest --collect-only`` actually collects here. A hand-kept
   count went stale by more than 160 tests and nothing noticed, so the figure
   is re-derived instead of remembered.
5. **Command contract**, every ``python -m scripts.x.y`` / ``python
   scripts/x.py`` in a doc must resolve to a file in this tree. Contributor
   docs pointed at ``scripts.check_claims`` after that module moved to
   ``scripts/checks/``, i.e. an instruction that cannot run. The rule reads the
   bare path too, because a command is only one way a stale pointer hurts: a
   docstring that says ``Mirrors scripts/check_diode.py`` and a
   ``FileNotFoundError`` that tells the operator to run
   ``scripts/download_ml_corpora.py`` both outlived the moves to
   ``scripts/checks/`` and ``scripts/fetch/``, and neither is a ``python``
   invocation.
6. **Repository contract**, a ``github.com/<owner>/<repo>`` link under this
   project's own owner must be the repository the checkout came from. Renaming
   the remote left the README's clone command pointing at the stub that
   inherited the old name: every figure in the repo was true and the first
   thing a judge is told to do was fail.

Contracts 4, 5 and 6 also read the exempt reference docs: their exemption exists
only so they may quote banned wording, not so they can publish unverifiable
numbers, commands or links.

The headline used to be a mandated *string* ("1 FP in 440,031 benign"), which
only ever proved the slogan had been copy-pasted. It is now derived from the
artifacts, so the check fails when the numbers stop matching rather than when
the wording changes.

    python -m scripts.checks.check_claims             # scan + report
    python -m scripts.checks.check_claims --quiet     # exit code only
    python -m scripts.checks.check_claims --json out.json
    python -m scripts.checks.check_claims --root DIR  # scan another tree (tests)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Judge-facing surfaces (glob patterns relative to the scan root).
SURFACES = [
    "README.md",
    "CONTRIBUTING.md",
    "docs/**/*.md",
    # The wall's formatter module, hand-written and served beside the bundle.
    "apps/mission_control/static/js/*.js",
    # The wall ships its own copy to the same judges, so it carries the same
    # obligations, both page entries, since the service board is a second
    # entry rather than a route inside the first. What frontend/ emits into
    # apps/mission_control/static/ (its two shells and their chunks) is excluded
    # as derived text: the source is what a human edits, and CI rebuilds it and
    # fails unless the shipped bytes match.
    "frontend/*.html",
    "frontend/src/*.ts",
    "frontend/src/*.tsx",
    "frontend/src/components/*.tsx",
    "apps/dashboard/*.py",
]

# Internal files exempt from the phrase scan: docs/readiness.md is the
# master-status document whose §1 table QUOTES the banned phrasings verbatim -
# it is the guardrail's own reference, never shown to judges. The competition
# tree holds historical internal planning artifacts with the same property.
INTERNAL_EXEMPT = {
    "docs/readiness.md",
    "docs/competition/readiness.md",
    "docs/competition/implementation-plan.md",
}

# Phrasings that must never reach a judge (dossier §1 approved-language lock).
BANNED = [
    "SHAP-explained",
    "SHAP attribution",
    "SHAP value",
    "TreeExplainer",
    "fusion layer",
    "fusion engine",
    "Isolation Forest novelty layer",
    "per-flow p95 <= 200 ms",
    "per-flow p95 ≤ 200 ms",
    "p95 / p99 per-flow latency | ≤ 200 ms / ≤ 500 ms",
    # Unqualified readiness/maturity proclamations, status must be scoped
    # ("SIH finale ready", "demo-ready"), never asserted bare.
    "production ready",
    "production-ready",
    "battle-tested",
    "enterprise-grade",
    "world-class",
    "state-of-the-art",
]

# Absolute FPR claims, allowed only beside a measured denominator.
UNSCOPED_ZERO = re.compile(r"\b(zero|no) false positives?\b", re.IGNORECASE)
_HAS_NUMBER = re.compile(r"\d")

# A metric cell is trusted only as far as the artifact it came from.
# (row keywords, artifact, dotted value path), the keywords must ALL appear in
# the row's descriptor cells; the value is read from the row's last cell.
METRIC_CLAIMS = [
    (("beacon (c2 periodicity)", "roc-auc (macro)"), "beacon", "roc_auc_macro"),
    (("window ensemble (ddos)", "f1"), "window", "per_class.ddos.f1"),
    (("window ensemble (scan)", "f1"), "window", "per_class.scan.f1"),
    (("dga / dns-tunnel", "precision (known corpus)"), "dga", "known_precision"),
    (("dga / dns-tunnel", "roc-auc"), "dga", "roc_auc"),
    (("dga / dns-tunnel", "fpr at threshold"), "dga",
     "umbrella_fpr_at_threshold"),
    (("tls/ja3 channel", "f1"), "tls", "synthetic_plant_eval.f1"),
    (("novelty layer", "f1"), "tls", "synthetic_plant_eval.novelty_only.f1"),
    (("supervised reference", "macro-f1"), "supervised", "macro_f1"),
]

# Scope contract: denominator -> the two facts that make its file honest.
FP_DENOMINATORS = ("440,031", "440031", "2.03M")
LAYER_QUALIFIER = re.compile(
    r"\b(ml channel|ml flow-context|flow-context channel|rule layer|"
    r"rule engine|window ensemble|flow[- ]level model|supervised reference)\b",
    re.IGNORECASE)
# "3 ... benign" or "benign ... 3" in the same file: the rule layer's own
# count on the Wednesday table (32 on the full CIC2017 register), so the ML
# number cannot stand in for the whole system.
BENIGN_WINDOW_COUNT = re.compile(r"\b(?:3|32)\b.{0,80}\bbenign"
                                 r"|\bbenign.{0,80}\b(?:3|32)\b",
                                 re.IGNORECASE)

APPROX = re.compile(r"[~≈]")

# Contract 4: a documented suite size must be the size pytest actually
# collects. "152 collected, 152 passed" sat stale for three weeks because the
# number was hand-maintained and nothing re-derived it.
DOC_COLLECTED = re.compile(r"\b(\d{2,4})\s+collected\b", re.IGNORECASE)
# The verb form is how status.md published its stale figure: "collects 465
# tests" never matched "N collected", so a 27-test drift passed the guardrail.
DOC_COLLECTS = re.compile(r"\bcollects?\s+(\d{2,4})\s+tests?\b", re.IGNORECASE)
DOC_PASSED = re.compile(r"\b(\d{2,4})\s+passed\b", re.IGNORECASE)
# a suite that skips/deselects legitimately reports fewer passed than collected
COUNT_EXEMPT = re.compile(r"skip|deselect|xfail|error|fail", re.IGNORECASE)

# Contract 5: every documented repo command must resolve to a file that exists.
# CONTRIBUTING.md told people to run `python -m scripts.check_claims` after the
# script had moved to scripts/checks/, a command that cannot work.
DOC_MODULE_CMD = re.compile(
    r"python[3]?\s+-m\s+((?:scripts|src|apps)(?:\.[\w]+)+)")
DOC_PATH_CMD = re.compile(
    r"python[3]?\s+((?:scripts|src|apps)[\w/\\.\-]*\.py)")

# A repo-relative path with a slash in it is a pointer a reader may follow,
# whatever sentence it sits in. The lookbehind demands the token start at a
# boundary: every tail of `https://host/o/r/blob/main/src/x.py` is glued to a
# word character or a slash, and this tree cannot be expected to contain it.
DOC_PY_PATH = re.compile(r"(?<![\w.\-/])(?:[\w.\-]+/)+[\w.\-]+\.py")

# The command contract also reads the executable tree: a script's own usage
# line is documentation, and when the checks moved under scripts/checks/ more
# than a dozen of them kept advertising `python scripts/check_ml.py`, a
# command that cannot run, copied straight into a terminal by an operator.
COMMAND_SURFACES = SURFACES + ["src/**/*.py", "scripts/**/*.py",
                               "apps/**/*.py"]
# this file's own examples are deliberately abstract (`python -m scripts.x.y`)
COMMAND_EXEMPT = {"scripts/checks/check_claims.py"}

# Contract 6: a surface must point at the repository this code is actually in.
# Renaming the remote left README telling judges to `git clone` the empty stub
# that inherited the old name, every number in it was true, and the first
# instruction a judge follows was wrong. Nothing else in the guardrail could
# see it, because a stale URL is not a phrase, a metric or a command.
DOC_REPO_URL = re.compile(r"github\.com[:/]([\w.-]+)/([\w.-]+)")


def _rel(root: Path, p: Path) -> str:
    return p.relative_to(root).as_posix()


def _is_exempt(rel: str) -> bool:
    return rel in INTERNAL_EXEMPT


def surface_files(root: Path, include_exempt: bool = False) -> list[Path]:
    """Every judge-facing file under `root`, deduped.

    Exempt entries are removed unless `include_exempt`, the phrase scan must
    skip docs/readiness.md (it quotes banned wording on purpose), but the
    numeric contracts still have to check the counts and commands it publishes.
    """
    files: set[Path] = set()
    for pattern in SURFACES:
        files.update(p for p in root.glob(pattern) if p.is_file())
    ordered = sorted(files)
    if include_exempt:
        return [p for p in ordered if p.is_file()]
    return [p for p in ordered if not _is_exempt(_rel(root, p))]


def _texts(root: Path, include_exempt: bool = False) -> list[tuple[str, str]]:
    out = []
    for path in surface_files(root, include_exempt=include_exempt):
        try:
            out.append((_rel(root, path),
                        path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return out


# a period only ends a sentence when it is not part of a decimal figure
_TERMS = re.compile(r"[!?;]|(?<!\d)\.(?!\d)|\n[ \t]*\n")


def _sentence(text: str, span: tuple[int, int]) -> str:
    """The sentence containing `span` (periods, ? ! or a blank line end it)."""
    start = 0
    for m in _TERMS.finditer(text[:span[0]]):
        start = m.end()
    tail = _TERMS.search(text, span[1])
    return text[start:tail.end() if tail else len(text)]


# --------------------------------------------------------------------------- #
# 1, phrasings
# --------------------------------------------------------------------------- #
def check_phrases(texts: list[tuple[str, str]]) -> list[dict]:
    findings: list[dict] = []
    for rel, text in texts:
        low = text.lower()
        for phrase in BANNED:
            if phrase.lower() in low:
                findings.append({"kind": "banned-phrase", "file": rel,
                                 "phrase": phrase})
        for m in UNSCOPED_ZERO.finditer(text):
            if not _HAS_NUMBER.search(_sentence(text, m.span())):
                findings.append({
                    "kind": "unscoped-zero", "file": rel,
                    "phrase": m.group(0),
                    "detail": "an absolute false-positive claim with no "
                              "measured denominator in its sentence"})
    return findings


# --------------------------------------------------------------------------- #
# 2, numbers vs artifacts
# --------------------------------------------------------------------------- #
def _dotted(doc: dict, path: str) -> float | None:
    cur: object = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur if isinstance(cur, (int, float)) else None


def load_metrics(root: Path) -> tuple[dict[str, dict], str]:
    """Pinned metric artifacts, preferring the live `results/ml` copies."""
    loaded: dict[str, dict] = {}
    where = ""
    for name in ("beacon", "window", "dga", "tls", "supervised"):
        for cand, tag in ((root / "results" / "ml" / f"{name}_metrics.json",
                           "results/ml"),
                          (root / "docs" / "evaluation" / "runs" /
                           f"{name}_metrics.json", "docs/evaluation/runs")):
            if cand.exists():
                try:
                    loaded[name] = json.loads(cand.read_text(encoding="utf-8"))
                    where = tag
                except (OSError, json.JSONDecodeError):
                    continue
                break
    return loaded, where


def _parse_cell(cell: str) -> tuple[float, int, bool] | None:
    """(value, decimals, approximate) from a table's value cell, or None."""
    clean = cell.replace("**", "").strip()
    if not clean:
        return None
    m = re.search(r"(\d+(?:\.\d+)?)", clean)
    if not m:
        return None
    text = m.group(1)
    dp = len(text.split(".")[1]) if "." in text else 0
    return float(text), dp, bool(APPROX.search(clean[:m.start() + 1]))


def check_metrics(texts: list[tuple[str, str]],
                  metrics: dict[str, dict]) -> tuple[list[dict], int]:
    """Compare each claimed metric in a markdown table against its artifact."""
    findings: list[dict] = []
    checked = 0
    for rel, text in texts:
        if not rel.endswith(".md"):
            continue
        for line in text.splitlines():
            if not line.strip().startswith("|"):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) < 2:
                continue
            descriptor = " ".join(cells[:-1]).lower()
            parsed = _parse_cell(cells[-1])
            if parsed is None:
                continue
            doc_val, dp, approx = parsed
            for keywords, art_name, path in METRIC_CLAIMS:
                if not all(k in descriptor for k in keywords):
                    continue
                checked += 1
                if art_name not in metrics:
                    findings.append({
                        "kind": "missing-artifact", "file": rel,
                        "phrase": f"{art_name}.{path}",
                        "detail": "no pinned artifact to check this number "
                                  "against, the claim is unverifiable"})
                    continue
                real = _dotted(metrics[art_name], path)
                if real is None:
                    findings.append({
                        "kind": "missing-artifact", "file": rel,
                        "phrase": f"{art_name}.{path}",
                        "detail": "the artifact has no such value"})
                    continue
                tol = 0.05 if approx else 0.5 * 10 ** -dp
                if abs(doc_val - real) > tol:
                    findings.append({
                        "kind": "number-drift", "file": rel,
                        "phrase": f"{art_name}.{path}",
                        "detail": f"{rel} claims {cells[-1].strip()!r} but "
                                  f"{art_name}_metrics.json says {real} "
                                  f"(printed precision {dp} dp"
                                  f"{', approximate' if approx else ''})"})
    return findings, checked


# --------------------------------------------------------------------------- #
# 3, scope of false-positive claims
# --------------------------------------------------------------------------- #
def check_scope(texts: list[tuple[str, str]]) -> list[dict]:
    findings: list[dict] = []
    for rel, text in texts:
        if not any(d in text for d in FP_DENOMINATORS):
            continue
        # markdown prose is hard-wrapped, so pair the two halves of a claim
        # across the wrapping rather than demanding one physical line
        flat = re.sub(r"\s+", " ", text)
        if not LAYER_QUALIFIER.search(flat):
            findings.append({
                "kind": "unscoped-denominator", "file": rel,
                "phrase": "benign-flow denominator",
                "detail": f"{rel} quotes a benign-flow count "
                          "(440,031 / 2.03M) without naming which layer was "
                          "measured, so the number reads as a system-wide "
                          "FPR"})
        if not BENIGN_WINDOW_COUNT.search(flat):
            findings.append({
                "kind": "missing-counter", "file": rel,
                "phrase": "3 benign-window alerts",
                "detail": f"{rel} quotes a benign-flow denominator without "
                          "the rule layer's 3 Wednesday alerts on "
                          "benign-labelled windows, or the full CIC2017 "
                          "count of 32 (docs/rules.md)"})
    return findings


_MEASURE = object()


# --------------------------------------------------------------------------- #
# 4, documented test counts vs what pytest actually collects
# --------------------------------------------------------------------------- #
def measure_collected(root: Path) -> int | None:
    """How many tests pytest collects under `root`, or None if it cannot say."""
    if not (root / "tests").is_dir():
        return None
    try:
        p = subprocess.run(
            [sys.executable, "-m", "pytest", "tests", "--collect-only", "-q",
             "-p", "no:cacheprovider"],
            cwd=str(root), capture_output=True, text=True, timeout=300,
            check=False)  # a non-zero collection exit is data, not an error
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"(\d+) tests? collected",
                  (p.stdout or "") + (p.stderr or ""))
    return int(m.group(1)) if m else None


def check_test_counts(texts: list[tuple[str, str]],
                      collected: int | None) -> list[dict]:
    """A file may not publish a suite size that pytest does not collect."""
    findings: list[dict] = []
    for rel, text in texts:
        for line in text.splitlines():
            claimed = (DOC_COLLECTED.findall(line)
                       + DOC_COLLECTS.findall(line)
                       + DOC_PASSED.findall(line))
            if not claimed:
                continue
            if collected is None:
                findings.append({
                    "kind": "test-count-unverifiable", "file": rel,
                    "phrase": ", ".join(claimed),
                    "detail": f"{rel} publishes a test count but pytest could "
                              "not collect here, so nothing backs it"})
                continue
            bad = [n for n in claimed if int(n) != collected]
            if bad and not COUNT_EXEMPT.search(line):
                findings.append({
                    "kind": "test-count-drift", "file": rel,
                    "phrase": ", ".join(bad),
                    "detail": f"{rel} claims {', '.join(bad)} test(s) but "
                              f"`pytest tests --collect-only -q` collects "
                              f"{collected}, re-derive the figure, do not "
                              "hand-maintain it"})
    return findings


# --------------------------------------------------------------------------- #
# 5, documented commands must resolve
# --------------------------------------------------------------------------- #
def command_texts(root: Path) -> list[tuple[str, str]]:
    """Every file whose text an operator might copy a command out of."""
    files: set[Path] = set()
    for pattern in COMMAND_SURFACES:
        files.update(p for p in root.glob(pattern) if p.is_file())
    out = []
    for path in sorted(files):
        rel = _rel(root, path)
        if rel in COMMAND_EXEMPT:
            continue
        try:
            out.append((rel, path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return out


def check_commands(root: Path, texts: list[tuple[str, str]]) -> list[dict]:
    """`python -m scripts.x.y` / `python scripts/x.py` in a doc must exist, and
    so must every other slashed ``.py`` path the text points at."""
    findings: list[dict] = []
    seen: set[str] = set()

    def resolves(rel: str, target: str) -> bool:
        """A pointer is written relative to the repository root, or to the
        document that names it. The second half was missing: every link in
        ``docs/pipeline.md`` was a ``file:///`` URL to one workstation, and the
        nearest honest repair (a document-relative path) resolved for a
        reader on GitHub and for nothing in this check."""
        if (root / target).exists():
            return True
        return ((root / rel).parent / target).exists()

    for rel, text in texts:
        for match in DOC_MODULE_CMD.finditer(text):
            target = match.group(1)
            if (root / f"{target.replace('.', '/')}.py").exists():
                continue
            findings.append({
                "kind": "broken-command", "file": rel, "phrase": target,
                "detail": f"{rel} tells the reader to run `python -m {target}`, "
                          f"which resolves to {target.replace('.', '/')}.py, "
                          "no such file (renamed or moved without the doc)"})
        for match in DOC_PATH_CMD.finditer(text):
            target = match.group(1).replace("\\", "/")
            if target in seen:
                continue
            seen.add(target)
            if resolves(rel, target):
                continue
            findings.append({
                "kind": "broken-command", "file": rel, "phrase": target,
                "detail": f"{rel} tells the reader to run `{target}`, which "
                          "does not exist in this tree"})
        for match in DOC_PY_PATH.finditer(text):
            target = match.group(0)
            if target in seen:
                continue
            seen.add(target)
            if resolves(rel, target):
                continue
            findings.append({
                "kind": "broken-path", "file": rel, "phrase": target,
                "detail": f"{rel} points at `{target}`, which is not a file in "
                          "this tree, a path the reader cannot follow "
                          "(moved or renamed without the pointer)"})
    return findings




# --------------------------------------------------------------------------- #
# 6, documented repo URLs must name this repository
# --------------------------------------------------------------------------- #
def _repo_refs(text: str):
    """(owner, repo, matched text) for every github.com/<owner>/<repo> in text.

    ``.git`` is dropped because the greedy name class swallows it, and the two
    spellings of one repository must compare equal.
    """
    for m in DOC_REPO_URL.finditer(text):
        yield m.group(1), m.group(2).removesuffix(".git"), m.group(0)


def origin_slug(root: Path) -> str | None:
    """`owner/repo` of this checkout's origin remote, or None if there is none.

    Returns None rather than guessing: a tree with no git and no origin (an
    unpacked release, a packaged install) cannot be checked, and inventing a
    slug there would fail a correct README.
    """
    if not (root / ".git").exists():
        return None
    try:
        p = subprocess.run(["git", "config", "--get", "remote.origin.url"],
                           cwd=str(root), capture_output=True, text=True,
                           timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    for owner, repo, _ in _repo_refs((p.stdout or "").strip()):
        return f"{owner}/{repo}"
    return None


def check_repo_urls(texts: list[tuple[str, str]],
                    slug: str | None) -> list[dict]:
    """A URL under this repo's own owner must be this repo, not its old name.

    Only same-owner references are judged, so links to pandas or streamlit
    pass untouched, the failure this catches is a doc pointing at another of
    this account's repositories as if it were the project.
    """
    if slug is None:
        return []
    owner, _, name = slug.partition("/")
    findings: list[dict] = []
    for rel, text in texts:
        for ref_owner, ref_repo, matched in _repo_refs(text):
            if ref_owner == owner and ref_repo != name:
                findings.append({
                    "kind": "repo-url-stale", "file": rel, "phrase": matched,
                    "detail": f"{rel} links to {ref_owner}/{ref_repo} "
                              f"but this code lives in {owner}/{name} (remote "
                              "origin), the reader follows a link to the wrong "
                              "repository"})
    return findings


# --------------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------------- #
def scan(root: Path | None = None, collected=_MEASURE) -> dict:
    """Return {findings, files_scanned, metrics_checked, artifact_source,
    collected_tests}.

    `collected` overrides the pytest collection count (the tests pass a number
    so they never spawn a nested pytest run); the default measures it live, but
    only when some surface actually publishes a count.
    """
    root = Path(root) if root is not None else REPO
    texts = _texts(root)
    # counts and commands are checked on every surface, including the exempt
    # reference docs, the exemption is only about quoted banned phrasings
    numeric = _texts(root, include_exempt=True)
    if collected is _MEASURE:
        collects_claims = any(DOC_COLLECTED.search(t) or DOC_PASSED.search(t)
                              for _, t in numeric)
        collected = measure_collected(root) if collects_claims else None
    metrics, artifact_source = load_metrics(root)
    metric_findings, checked = check_metrics(texts, metrics)
    findings = (check_phrases(texts) + metric_findings + check_scope(texts)
                + check_test_counts(numeric, collected)
                + check_commands(root, command_texts(root))
                + check_repo_urls(numeric, origin_slug(root)))
    return {"findings": findings, "files_scanned": len(texts),
            "metrics_checked": checked, "artifact_source": artifact_source,
            "metrics_loaded": sorted(metrics), "collected_tests": collected}


def run(quiet: bool = False, root: Path | None = None,
        doc: dict | None = None) -> bool:
    doc = doc if doc is not None else scan(root)
    ok = not doc["findings"]
    if not quiet:
        print(f"[claims] scanned {doc['files_scanned']} judge-facing files")
        print(f"[claims] {doc['metrics_checked']} documented metrics "
              f"reconciled against {doc['artifact_source'] or 'NO ARTIFACTS'}")
        print(f"[claims] documented test count reconciled against "
              f"{doc['collected_tests'] if doc['collected_tests'] is not None else 'NOT COLLECTED'}"
              " collected by pytest")
        for f in doc["findings"]:
            print(f"  {f['kind'].upper()}: {f['file']}: {f['phrase']}"
                  + (f", {f['detail']}" if f.get("detail") else ""))
        print("[claims] GUARDRAIL CLEAN" if ok else "[claims] GUARDRAIL FAILED")
    return ok


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m scripts.checks.check_claims",
                                 description=__doc__)
    ap.add_argument("--quiet", action="store_true", help="exit code only")
    ap.add_argument("--root", type=Path, default=None,
                    help="scan another tree (used by the tests)")
    ap.add_argument("--json", metavar="PATH", default=None,
                    help="also write the scan result as JSON")
    args = ap.parse_args(argv)

    doc = scan(args.root)
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    ok = run(quiet=args.quiet, root=args.root, doc=doc)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
