"""Shared plumbing for rule-based detectors.

One `Rule` subclass = one interpretable condition family. Rules evaluate
vectorized window frames (from `detectors.window`) and emit fully-populated
`alerts.schema.Alert` objects. Confidence is the unweighted fraction of the
rule's evidence conditions that fired, deliberately not a probability, and
readable: 3 of 4 conditions firing means 0.75 and the evidence list names the
one that did not.
"""
from __future__ import annotations

import math
from abc import ABC, abstractmethod

from src.alerts.schema import Alert, EvidenceItem

from .window import WindowFrames, iso_at


class Rule(ABC):
    """A rule over window aggregates. Subclasses fill in the class constants."""
    name: str = "rule"
    threat_class: str = "unknown"
    description: str = ""
    # "any": independent signatures, one suffices (ddos, exfil);
    # "all": conjunctive shape, every condition must hold (slowdos, scan).
    mode: str = "any"

    def __init__(self, params: dict | None = None) -> None:
        # params override class-level thresholds by keyword (e.g. flows_per_sec=100)
        self.params = dict(params or {})

    def get(self, key: str, default):
        return self.params.get(key, default)

    @abstractmethod
    def evaluate(self, wf: WindowFrames) -> list[Alert]:
        """Return alerts for every window-group where the rule fires."""

    # ---- helpers ------------------------------------------------------------
    def decide(self, conditions: list[tuple[bool, EvidenceItem]],
               ) -> list[EvidenceItem] | None:
        """Apply the rule's firing semantics; None when the rule stays silent."""
        fired = [e for ok, e in conditions if ok]
        if self.mode == "all":
            return fired if len(fired) == len(conditions) else None
        return fired or None

    def make_alert(self, *, ts: str, flow_id: str | None, key: str,
                   evidence: list[EvidenceItem], n_fired: int, n_total: int,
                   wf: WindowFrames, win_idx: int | None = None,
                   end_offset_s: float | None = None,
                   label: str | None = None,
                   src_ip: str | None = None,
                   dst_ip: str | None = None) -> Alert:
        """Assemble an Alert with simple fraction-of-conditions confidence.

        `src_ip`/`dst_ip` carry the alert's entity side (rules aggregate per
        src or per dst, so only that side is known; the other stays None -
        per-flow alerts from the ML layer fill both).
        """
        confidence = (n_fired / n_total) if n_total else 0.0
        start = None
        end = None
        if win_idx is not None:
            start = iso_at(win_idx, wf.window_s)
            end = iso_at(win_idx, wf.window_s,
                         end_offset_s if end_offset_s is not None else wf.window_s)
        return Alert(
            timestamp=end or ts,
            flow_id=flow_id,
            threat_class=self.threat_class,
            confidence=confidence,
            evidence=evidence,
            window_start=start,
            window_end=end,
            window_seconds=float(wf.window_s),
            key=key,
            detector=self.name,
            label=label,
            src_ip=src_ip,
            dst_ip=dst_ip,
        )


def _fmt(v, nd: int = 1) -> str:
    try:
        f = float(v)
        return f"{f:,.{nd}f}" if not math.isnan(f) else "n/a"
    except (TypeError, ValueError):
        return str(v)


def ev(condition: str, operator: str, observed, threshold, description: str,
       unit: str = "") -> EvidenceItem:
    """Shorthand to build one evidence item with a readable description."""
    return EvidenceItem(condition=condition, operator=operator, observed=observed,
                        threshold=threshold, description=description, unit=unit)
