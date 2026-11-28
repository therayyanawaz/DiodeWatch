#!/usr/bin/env python3
"""Exit check: the drift artifact is consistent and its alarms are measured.

    python scripts/checks/check_drift.py

Validates the shipped policy (`docs/evaluation/models/drift.json`) without
corpora: schema, sorted reference bins, proportions, per-channel thresholds,
and the pinned evaluation summary. It also refuses a summary that claims a
null day alarmed, or a holdout that did not, so the two cannot drift apart.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from itertools import pairwise
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ARTIFACT = REPO / "docs" / "evaluation" / "models" / "drift.json"
SUMMARY = REPO / "docs" / "evaluation" / "runs" / "drift.json"
CHANNELS = {"ml.flowctx", "ml.beacon", "ml.dga", "ml.tls"}


def _fail(problems: list[str], message: str) -> None:
    problems.append(message)


def _check_features(channel: str, body: dict, problems: list[str]) -> None:
    features = body.get("features") or {}
    if body.get("method") == "identity":
        if features:
            _fail(problems, f"{channel}: identity channel carries feature bins")
        return
    if not features:
        _fail(problems, f"{channel}: PSI channel has no monitored features")
        return
    for name, spec in features.items():
        edges = spec.get("edges") or []
        expected = spec.get("expected") or []
        where = f"{channel}:{name}"
        if len(edges) < 2 or len(expected) != len(edges) - 1:
            _fail(problems, f"{where}: edges/expected lengths are inconsistent")
            continue
        if any(not math.isfinite(float(x)) for x in edges + expected):
            _fail(problems, f"{where}: non-finite baseline value")
        if any(b <= a for a, b in pairwise(edges)):
            _fail(problems, f"{where}: edges are not strictly increasing")
        if any(float(x) < 0 for x in expected):
            _fail(problems, f"{where}: negative proportion")
        if abs(sum(float(x) for x in expected) - 1.0) > 1e-5:
            _fail(problems, f"{where}: proportions do not sum to 1")
        if int(spec.get("n", 0)) < 2:
            _fail(problems, f"{where}: reference has fewer than 2 rows")


def check(artifact_path: Path, summary_path: Path) -> list[str]:
    problems: list[str] = []
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if artifact.get("schema") != 1:
        _fail(problems, "schema is not 1")
    channels = artifact.get("channels") or {}
    if set(channels) != CHANNELS:
        _fail(problems, f"channels are {sorted(channels)}, expected {sorted(CHANNELS)}")
    threshold = float(artifact.get("threshold", 0.0))
    min_samples = int(artifact.get("min_samples", 0))
    bins = int(artifact.get("bins", 0))
    if not 0 < threshold < 100:
        _fail(problems, "fallback threshold is outside (0, 100)")
    if min_samples < 5 * max(bins, 1):
        _fail(problems, "min_samples is too small for the bin count")
    if "raw" in artifact or "values" in artifact:
        _fail(problems, "artifact appears to contain raw reference rows")
    for channel, body in channels.items():
        if body.get("method") not in {"psi", "identity"}:
            _fail(problems, f"{channel}: unknown method {body.get('method')!r}")
        _check_features(channel, body, problems)
        channel_threshold = body.get("threshold")
        if body.get("method") == "identity":
            if channel_threshold is not None:
                _fail(problems, f"{channel}: identity channel has a threshold")
            continue
        if channel_threshold is None or not 0 < float(channel_threshold) < 100:
            _fail(problems, f"{channel}: missing or invalid channel threshold")

    if abs(float(summary.get("threshold", -1)) - threshold) > 1e-9:
        _fail(problems, "summary threshold does not match the artifact")
    if int(summary.get("min_samples", -1)) != min_samples:
        _fail(problems, "summary min_samples does not match the artifact")
    if int(summary.get("bins", -1)) != bins:
        _fail(problems, "summary bins does not match the artifact")
    if summary.get("generated_utc") != artifact.get("generated_utc"):
        _fail(problems, "summary generated_utc does not match the artifact")
    if int(summary.get("artifact_bytes", 0)) != artifact_path.stat().st_size:
        _fail(problems, "summary artifact_bytes does not match the artifact")

    flow = summary.get("flowctx") or {}
    flow_body = channels.get("ml.flowctx", {})
    flow_threshold = float(flow_body.get("threshold", 0.0))
    if sorted(flow.get("features") or []) != sorted(
            (flow_body.get("features") or {}).keys()):
        _fail(problems, "flowctx summary features do not match the artifact")
    if abs(float(flow.get("channel_threshold", -1)) - flow_threshold) > 1e-9:
        _fail(problems, "flowctx summary threshold does not match the artifact")
    if float(flow.get("null_max", float("inf"))) >= flow_threshold:
        _fail(problems, "flowctx null PSI reaches its alarm threshold")
    for day, reading in (flow.get("eval") or {}).items():
        if reading.get("alarm"):
            _fail(problems, f"flowctx null day {day} alarms")
        if float(reading.get("max_psi", 0.0)) > flow_threshold + 1e-9:
            _fail(problems, f"flowctx day {day} exceeds the threshold without alarm")
    stress = flow.get("stress_shifted_wednesday") or {}
    if not stress.get("alarm") or float(stress.get("max_psi", 0.0)) <= flow_threshold:
        _fail(problems, "flowctx injected-shift stress does not alarm")

    beacon = summary.get("beacon") or {}
    beacon_body = channels.get("ml.beacon", {})
    beacon_threshold = float(beacon_body.get("threshold", 0.0))
    if sorted(beacon.get("features") or []) != sorted(
            (beacon_body.get("features") or {}).keys()):
        _fail(problems, "beacon summary features do not match the artifact")
    if abs(float(beacon.get("channel_threshold", -1)) - beacon_threshold) > 1e-9:
        _fail(problems, "beacon summary threshold does not match the artifact")
    if float(beacon.get("null_max", float("inf"))) >= beacon_threshold:
        _fail(problems, "beacon null PSI reaches its alarm threshold")
    beacon_eval = beacon.get("eval") or {}
    holdout = str(beacon.get("holdout", ""))
    if holdout not in beacon_eval:
        _fail(problems, "beacon holdout scenario is missing from the summary")
    elif not beacon_eval[holdout].get("alarm"):
        _fail(problems, "beacon holdout scenario does not alarm")
    for scenario, reading in beacon_eval.items():
        if scenario != holdout and reading.get("alarm"):
            _fail(problems, f"beacon reference scenario {scenario} alarms")
    pack = beacon.get("pack") or {}
    if int(pack.get("n", min_samples)) >= min_samples:
        _fail(problems, "beacon demo pack has enough rows to estimate PSI")
    if pack.get("alarm"):
        _fail(problems, "beacon demo pack alarms")

    dga = summary.get("dga") or {}
    dga_body = channels.get("ml.dga", {})
    dga_threshold = float(dga_body.get("threshold", 0.0))
    if sorted(dga.get("features") or []) != sorted(
            (dga_body.get("features") or {}).keys()):
        _fail(problems, "dga summary features do not match the artifact")
    if abs(float(dga.get("channel_threshold", -1)) - dga_threshold) > 1e-9:
        _fail(problems, "dga summary threshold does not match the artifact")
    if float(dga.get("null_max", float("inf"))) >= dga_threshold:
        _fail(problems, "dga null PSI reaches its alarm threshold")
    for label in ("fold1", "umbrella"):
        reading = dga.get(label) or {}
        if not reading.get("alarm"):
            _fail(problems, f"dga {label} shift does not alarm")
        if float(reading.get("max_psi", 0.0)) <= dga_threshold:
            _fail(problems, f"dga {label} is below threshold but claims an alarm")
    dga_pack = dga.get("pack") or {}
    if int(dga_pack.get("n", min_samples)) >= min_samples:
        _fail(problems, "dga demo pack has enough rows to estimate PSI")
    if dga_pack.get("alarm"):
        _fail(problems, "dga demo pack alarms")
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
    print(f"[PASS] drift artifact: {len(artifact['channels'])} channels, "
          f"{artifact['threshold']:g} fallback threshold, per-channel nulls "
          "below their alarms, holdouts measured above")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
