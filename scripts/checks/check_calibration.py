#!/usr/bin/env python3
"""Exit check: the calibration artifact is internally consistent and honest.

    python scripts/checks/check_calibration.py

Validates the shipped artifact (`docs/evaluation/models/calibration.json`)
without needing corpora: schema, monotone curves, sorted conformal samples,
policy floors, and agreement with the pinned evaluation summary. Exits non-zero
on the first class of failure, so CI cannot ship a hand-edited curve.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ARTIFACT = REPO / "docs" / "evaluation" / "models" / "calibration.json"
SUMMARY = REPO / "docs" / "evaluation" / "runs" / "calibration.json"
CHANNELS = {"ml.flowctx", "ml.beacon", "ml.dga", "ml.tls"}


def _fail(problems: list[str], message: str) -> None:
    problems.append(message)


def _check_curve(name: str, curve, problems: list[str]) -> None:
    if not isinstance(curve, list) or not curve:
        _fail(problems, f"{name}: missing isotonic curve")
        return
    last_x = -1.0
    last_y = -1.0
    for i, point in enumerate(curve):
        if not isinstance(point, list) or len(point) != 2:
            _fail(problems, f"{name}: knot {i} is not [x, y]")
            continue
        x, y = float(point[0]), float(point[1])
        if not (math.isfinite(x) and math.isfinite(y)):
            _fail(problems, f"{name}: knot {i} is not finite")
        if x < 0.0 or x > 1.0 or y < 0.0 or y > 1.0:
            _fail(problems, f"{name}: knot {i} outside [0,1]")
        if x < last_x or y < last_y:
            _fail(problems, f"{name}: knot {i} breaks monotonicity")
        last_x, last_y = x, y
    if curve[0][0] > 0.0 or curve[-1][0] < 1.0:
        _fail(problems, f"{name}: curve does not cover the full score range")


def check(artifact_path: Path, summary_path: Path) -> list[str]:
    problems: list[str] = []
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if artifact.get("schema") != 1:
        _fail(problems, "schema is not 1")
    channels = artifact.get("channels") or {}
    if set(channels) != CHANNELS:
        _fail(problems, f"channels are {sorted(channels)}, expected {sorted(CHANNELS)}")
    floors: dict[tuple[str, str], float] = {}
    for channel, body in channels.items():
        classes = body.get("classes") or {}
        if not classes:
            _fail(problems, f"{channel}: no class maps")
            continue
        for cls, spec in classes.items():
            where = f"{channel}:{cls}"
            method = spec.get("method")
            if method not in {"isotonic", "identity"}:
                _fail(problems, f"{where}: unknown method {method!r}")
            if method == "isotonic":
                _check_curve(where, spec.get("curve"), problems)
            alpha = float(spec.get("alpha", 0.0))
            floor = float(spec.get("min_confidence", 0.0))
            if not 0.0 <= alpha <= 1.0:
                _fail(problems, f"{where}: alpha outside [0,1]")
            if not 0.0 <= floor <= 1.0:
                _fail(problems, f"{where}: min_confidence outside [0,1]")
            scores = spec.get("conformal_scores") or []
            if scores != sorted(scores):
                _fail(problems, f"{where}: conformal scores are not sorted")
            if any(float(s) < 0.0 or float(s) > 1.0 for s in scores):
                _fail(problems, f"{where}: conformal score outside [0,1]")
            if method == "isotonic" and not scores:
                _fail(problems, f"{where}: isotonic map has no conformal sample")
            floors[(channel, cls)] = floor
    # the summary must quote the same policy floors, not a hand-written table
    for cls, row in (summary.get("flowctx_by_class") or {}).items():
        floor = floors.get(("ml.flowctx", cls))
        if floor is None or abs(floor - float(row["min_confidence"])) > 1e-9:
            _fail(problems, f"summary floor mismatch for flowctx/{cls}")
    for channel, row in (("ml.beacon", summary.get("beacon")),
                         ("ml.dga", summary.get("dga"))):
        floor = floors.get((channel, "*"))
        if row is None or floor is None or abs(floor - float(row["min_confidence"])) > 1e-9:
            _fail(problems, f"summary floor mismatch for {channel}")
    for label, row in (("beacon", summary.get("beacon")),
                       ("dga", summary.get("dga"))):
        before, after = row["before"], row["after"]
        if after["alerts"] > before["alerts"]:
            _fail(problems, f"{label}: policy increased alert count")
        if after["precision"] + 1e-6 < before["precision"]:
            _fail(problems, f"{label}: policy lowered precision")
    flow = summary.get("flowctx") or {}
    if flow.get("after", {}).get("alerts", 0) > flow.get("before", {}).get("alerts", 0):
        _fail(problems, "flowctx: policy increased alert count")
    if int(summary.get("artifact_bytes", 0)) != artifact_path.stat().st_size:
        _fail(problems, "summary artifact_bytes does not match the artifact")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--artifact", default=str(ARTIFACT))
    ap.add_argument("--summary", default=str(SUMMARY))
    args = ap.parse_args(argv)
    problems = check(Path(args.artifact), Path(args.summary))
    if problems:
        for p in problems:
            print(f"[FAIL] {p}", file=sys.stderr)
        return 1
    artifact = json.loads(Path(args.artifact).read_text(encoding="utf-8"))
    n_maps = sum(len(v.get("classes") or {}) for v in artifact["channels"].values())
    print(f"[PASS] calibration artifact: {len(artifact['channels'])} channels, "
          f"{n_maps} maps, curves monotone, floors match the pinned summary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
