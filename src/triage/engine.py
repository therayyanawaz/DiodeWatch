"""Laya triage engine: alert envelope -> calibrated analyst guidance.

One wrapper class (`LayaTriage`) around the ONNX runtime port. Engine rules
of the road (mirroring the repo's degradation contract):

  * the channel is **advisory**, it never rewrites confidence, severity or
    any field a rule/ML detector produced; it appends analyst guidance;
  * missing runtime or bundle => `available()` False and `status()` says why;
    `triage()` raises `LayaUnavailable` so callers decide their own fallback,
    while `triage_quiet` returns the reason instead of raising;
  * every triage verdict lands in the alert envelope as an extra `EvidenceItem`
    (condition="triage.disposition") so the store, UI, STIX bundle and HTML
    report pick it up with zero schema churn;
  * the model runs fully offline (CPU ONNX Runtime); no external call exists.

Throughput honesty (measured, not promised): triage is a *post-detection*
advisory layer over a 424M-parameter encoder, it is never in the 5,000
flows/s window loop. Latency is hardware-bound: seconds per alert on a
typical laptop CPU (measured ~7 s/alert on the dev box's 8-core x86), so
budget accordingly and treat `status().avg_ms` as the local truth. The
operating pattern is bounded triage, newest-first over the current alert
set (see --limit), not blanket scoring of every alert.

    python -m src.triage.engine --input data/slices/ml_alerts.jsonl \
                                --out data/slices/triaged.jsonl --limit 200
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from src.alerts.schema import Alert, EvidenceItem, alert_from_dict
from src.triage import questions as Q
from src.triage.laya_runtime import (
    DEFAULT_BUNDLE_DIR,
    MODEL_NAME,
    MODEL_REVISION,
    Laya,
    LayaUnavailable,
    SystemOneResult,
    bundle_sha256,
)

# Advisory contract, enforced in every verdict envelope:
#   * auto_close_allowed is ALWAYS False, a Laya verdict is guidance, never
#     a close/suppress decision. In particular `recommended == "false_positive"
#     means "likely false positive" and NOT "safe to close"; no code path may
#     auto-close, auto-suppress or downgrade an alert from this field.
#   * requires_human_review is ALWAYS True.
AUTO_CLOSE_ALLOWED = False
REQUIRES_HUMAN_REVIEW = True


def stamp_contract(summary: dict[str, Any],
                   model_dir: str | Path = DEFAULT_BUNDLE_DIR) -> dict[str, Any]:
    """Stamp the advisory guard + model provenance into a verdict dict.

    Module-level so every path that puts a verdict on an alert, live
    inference and the background worker, carries the same contract.
    Hashes the weights file once per process and caches the digest.
    """
    global _CACHED_SHA
    summary["auto_close_allowed"] = AUTO_CLOSE_ALLOWED
    summary["requires_human_review"] = REQUIRES_HUMAN_REVIEW
    summary["model_name"] = MODEL_NAME
    summary["model_revision"] = MODEL_REVISION
    if _CACHED_SHA is None:
        _CACHED_SHA = bundle_sha256(model_dir)
    summary["bundle_sha256"] = _CACHED_SHA
    return summary


_CACHED_SHA: str | None = None


def attach_evidence(a: Alert, summary: dict[str, Any]) -> None:
    """Append the triage verdict to the alert's evidence (advisory channel)."""
    a.evidence.append(EvidenceItem(
        condition="triage.disposition",
        operator="==",
        observed=str(summary.get("recommended", "")),
        threshold="escalate",
        description=(
            f"Laya triage: {summary.get('recommended', '?')} "
            f"(P={summary.get('p_false_positive', 0):.2f} false-positive, "
            f"urgency {summary.get('urgency', 0):.2f}/3, "
            f"corroborates class P={summary.get('corroborates_class', 0):.2f})"),
        unit="disposition",
    ))


class LayaTriage:
    """Load-once triage channel over the Laya ONNX bundle."""

    def __init__(self, model_dir: str | Path = DEFAULT_BUNDLE_DIR,
                 intra_op_threads: int | None = None) -> None:
        self.model_dir = Path(model_dir)
        # None = onnxruntime's own default sizing (measured as good or better
        # than 2/4/8 explicit threads on the dev box).
        self.intra_op_threads = intra_op_threads
        self._laya: Laya | None = None
        self._error: str | None = None
        self.calls = 0
        self.tokens = 0
        self.ms_total = 0.0

    # ---------------------------------------------------------------- status
    def available(self) -> bool:
        if self._laya is not None:
            return True
        try:
            self._load()
            return True
        except LayaUnavailable:
            return False

    def status(self) -> dict[str, Any]:
        """Honest channel status for dashboards and rehearsal checks."""
        if self._laya is not None:
            return {"available": True, "model_dir": str(self.model_dir),
                    "calls": self.calls,
                    "avg_ms": (self.ms_total / self.calls) if self.calls else None}
        try:
            self._load()
        except LayaUnavailable as e:
            return {"available": False, "reason": str(e)}
        return {"available": True, "model_dir": str(self.model_dir),
                "calls": self.calls, "avg_ms": None}

    def _load(self) -> Laya:
        if self._laya is None:
            self._laya = Laya.load(self.model_dir,
                                   intra_op_threads=self.intra_op_threads)
        return self._laya

    # ---------------------------------------------------------------- triage
    def triage(self, a: Alert) -> dict[str, Any]:
        """Triage one alert; returns the analyst-facing summary dict.

        Raises LayaUnavailable when the channel is down (caller decides the
        fallback). Use `triage_quiet` for degrade-to-silent semantics.
        """
        laya = self._load()
        t0 = time.perf_counter()
        result: SystemOneResult = laya.system_one(
            Q.state_of(a), Q.triage_questions(a))
        dt_ms = (time.perf_counter() - t0) * 1000.0
        self.calls += 1
        self.tokens += result.input_tokens
        self.ms_total += dt_ms
        summary = Q.answer_summary(result.answers)
        summary["latency_ms"] = round(dt_ms, 1)
        # Stamp in triage() so EVERY path that produces a verdict, CLI,
        # triage_quiet (pack generator), the background worker, carries
        # the advisory guard + provenance, not just direct stamp callers.
        return stamp_contract(summary, self.model_dir)

    def triage_quiet(self, a: Alert) -> dict[str, Any] | None:
        """Triage or return None with the reason stored on self._error."""
        try:
            return self.triage(a)
        except LayaUnavailable as e:
            self._error = str(e)
            return None

    def status_reason(self) -> str | None:
        return self._error

    def close(self) -> None:
        if self._laya is not None:
            self._laya.close()
            self._laya = None


def triage_alerts(alerts: list[Alert], model_dir: str | Path = DEFAULT_BUNDLE_DIR,
                  attach: bool = True) -> tuple[list[Alert], dict[str, Any]]:
    """Batch helper: triage every alert (quiet), attach evidence, report.

    Returns (alerts, status). Alerts pass through untouched when the channel
    is unavailable, degradation is the caller's to surface, never silent.
    """
    eng = LayaTriage(model_dir)
    if not eng.available():
        return alerts, {"available": False,
                        "reason": eng.status().get("reason")}
    n_triaged = 0
    for a in alerts:
        s = eng.triage_quiet(a)
        if s is not None:
            if attach:
                attach_evidence(a, s)
            a.triage = s  # type: ignore[attr-defined]  # advisory extra field
            n_triaged += 1
    status = eng.status()
    status["triaged"] = n_triaged
    return alerts, status


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m src.triage.engine",
        description="Laya System-1 triage over an alert NDJSON file.")
    ap.add_argument("--input", required=True, help="alert NDJSON (to_dict lines)")
    ap.add_argument("--out", required=True, help="output NDJSON (triage added)")
    ap.add_argument("--model-dir", default=str(DEFAULT_BUNDLE_DIR))
    ap.add_argument("--limit", type=int, default=None, help="triage N alerts")
    args = ap.parse_args(argv)

    from src.alerts.store import write_jsonl

    dicts = [json.loads(ln) for ln in
             Path(args.input).read_text("utf-8").splitlines() if ln.strip()]
    if args.limit:
        dicts = dicts[:args.limit]
    alerts = [alert_from_dict(d) for d in dicts]
    print(f"[laya_triage] {len(alerts):,} alerts from {args.input}",
          file=sys.stderr)

    alerts, status = triage_alerts(alerts, args.model_dir)
    if not status["available"]:
        print(f"[laya_triage] channel unavailable: {status.get('reason')}",
              file=sys.stderr)
        return 1
    print(f"[laya_triage] triaged {status['triaged']:,} of {len(alerts):,} | "
          f"avg {status.get('avg_ms') or 0:.0f} ms/alert "
          f"({status['model_dir']})", file=sys.stderr)
    write_jsonl(alerts, args.out)
    print(f"[laya_triage] wrote -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
