"""Structural guard: label truth has exactly one owner.

src/detectors/ml/labels.py owns both axes — the production taxonomy
(CLASSES / CLASS_LABELS / class_of) and the evaluation maps (CANONICAL_CLASSES
/ LABEL_MAPS). These tests fail if either surface is duplicated, reordered, or
edited without documenting the production-vs-evaluation relationship. They
exist because a 'Web Attack – Brute Force' ordering flip was once caught by
hand, not by structure.
"""
from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from src.detectors.ml import labels
from src.detectors.ml.features import CLASSES as FEAT_CLASSES
from src.detectors.ml.features import class_of as feat_class_of


def _load_bench_transfer():
    spec = importlib.util.spec_from_file_location(
        "bench_transfer_labels", REPO / "scripts" / "benchmarks" / "bench_transfer.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------ single owner
def test_features_reexports_are_the_owner_objects():
    """features.py must re-export labels.py's objects, never carry a copy."""
    assert feat_class_of is labels.class_of
    assert FEAT_CLASSES is labels.CLASSES


def _top_level_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                               ast.AnnAssign)) and getattr(node, "name", None):
            names.add(node.name)
    return names


def test_no_duplicate_label_definitions_anywhere():
    """The duplicate surfaces stay gone: bench_transfer and features must not
    re-declare the maps or class_of — they import/derive from labels.py."""
    for rel in ("scripts/benchmarks/bench_transfer.py", "src/detectors/ml/features.py"):
        owned = _top_level_names(REPO / rel)
        for banned in ("LABEL_MAPS", "CANONICAL_CLASSES", "CLASS_LABELS"):
            assert banned not in owned, (
                f"{rel} re-declares {banned}; label truth lives in "
                "src/detectors/ml/labels.py")
        assert "class_of" not in owned, (
            f"{rel} re-defines class_of; label truth lives in "
            "src/detectors/ml/labels.py")


def test_bench_transfer_uses_owner_objects():
    bt = _load_bench_transfer()
    assert bt.LABEL_MAPS is labels.LABEL_MAPS
    assert bt.resolve_label_map is labels.resolve_label_map
    # bench_transfer carries no local copy of the canonical axis: it imports
    # only LABEL_MAPS/resolve_label_map. Adding CANONICAL_CLASSES back as a
    # top-level assignment (or in the banned-definitions check below) fails
    # the duplicate-detection test.
    assert "CANONICAL_CLASSES" not in _top_level_names(
        REPO / "scripts" / "benchmarks" / "bench_transfer.py")


# ------------------------------------------------- production axis (golden)
GOLDEN_CLASS_LABELS: dict[str, tuple[str, ...]] = {
    "ddos": ("DDoS", "DDOS", "DoS ", "Heartbleed", "Syn"),
    "scan": ("PortScan",),
    "webattack": ("Web Attack",),
    "bruteforce": ("Patator", "BruteForce", "Bruteforce", "Brute Force"),
    "bot": ("Bot",),
    "infiltration": ("Infil",),
}
GOLDEN_CLASSES = ["benign", "ddos", "scan", "bruteforce", "webattack",
                  "bot", "infiltration"]


def test_production_taxonomy_ordering_is_immutable():
    """Substring tables are ORDER-SENSITIVE: reordering or editing a key
    reclassifies real corpora (the documented near-miss). To change the
    taxonomy, update this golden table and the evaluation snapshot in the
    same commit."""
    assert labels.CLASS_LABELS == GOLDEN_CLASS_LABELS
    assert list(labels.CLASS_LABELS) == list(GOLDEN_CLASS_LABELS)
    assert labels.CLASSES == GOLDEN_CLASSES


def test_order_sensitive_classifications_locked():
    """Behavior pins for the exact strings that make ordering matter."""
    c = labels.class_of
    assert c("Web Attack – Brute Force") == "webattack"   # before bruteforce
    assert c("Web Attack \u2013 XSS") == "webattack"
    assert c("FTP-BruteForce") == "bruteforce"
    assert c("SSH-Bruteforce") == "bruteforce"
    assert c("FTP-Patator") == "bruteforce"
    assert c("Infilteration") == "infiltration"           # 2018 spelling
    assert c("Infiltration") == "infiltration"
    assert c("Syn") == "ddos"                             # 2019 family label
    assert c("DDOS attack-HOIC") == "ddos"                # 2018 title case
    assert c("DoS Hulk") == "ddos"
    assert c("Bot") == "bot"
    assert c("PortScan") == "scan"
    assert c("BENIGN") == "benign" and c("Benign") == "benign"
    assert c(None) == "benign" and c(float("nan")) == "benign"
    assert c("Mystery Label") is None                     # never silently benign


# ------------------------------------------- relationship between the axes
def test_every_label_map_pair_is_documented_in_relationship():
    """Every (class_of(label), canonical) pair in LABEL_MAPS must have a
    documented relationship row — a new/edited mapping fails here until its
    production-vs-evaluation behavior is written down in labels.py."""
    for corpus, mapping in labels.LABEL_MAPS.items():
        for lab, canon in mapping.items():
            pair = (labels.class_of(lab), canon)
            assert pair in labels.RELATIONSHIP, (
                f"{corpus}: {lab!r} -> {canon!r} has undocumented pair "
                f"{pair}; add it (with the reason) to labels.RELATIONSHIP")


def test_every_relationship_row_is_reachable():
    """No stale documentation: each RELATIONSHIP row must be produced by at
    least one current LABEL_MAPS entry (or the row is deleted)."""
    reachable: set[tuple[str | None, str]] = set()
    for mapping in labels.LABEL_MAPS.values():
        for lab, canon in mapping.items():
            reachable.add((labels.class_of(lab), canon))
    stale = set(labels.RELATIONSHIP) - reachable
    assert not stale, (f"stale RELATIONSHIP rows no current label produces: "
                       f"{sorted(stale)}")


def test_relationship_known_deliberate_divergences():
    """The axes agree where they must and diverge only where documented."""
    assert labels.class_of("Heartbleed") == "ddos"        # production folds it in
    assert labels.LABEL_MAPS["cic-ids2017-wednesday"]["Heartbleed"] == "benign"
    assert labels.LABEL_MAPS["cic-ids2018-nf-v2"]["Heartbleed"] == "unmapped"
    assert labels.class_of("DoS slowloris") == "ddos"     # production has no slowdos
    assert labels.LABEL_MAPS["cic-ids2017-wednesday"]["DoS slowloris"] == "slowdos"


def test_canonical_classes_are_frozen():
    """bench_transfer summaries and gates index by these names."""
    assert labels.CANONICAL_CLASSES == ("ddos", "slowdos", "scan", "exfil",
                                        "benign")
