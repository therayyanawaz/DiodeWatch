"""Laya System-1 triage channel for DiodeWatch alerts.

Detection decides THAT something is suspicious; triage decides WHAT TO DO
about it. This module maps a fully-populated `alerts.schema.Alert` envelope
into Laya's state + typed questions and turns the calibrated answers back
into analyst-facing fields:

  * disposition (choice)   — escalate / investigate / monitor / false-positive
  * urgency    (score)     — 0..3 on a rubric; expected level, not a hard bucket
  * corroborate (noul)     — calibrated P(true) that the evidence genuinely
                             supports the assigned threat class

The state passed to Laya is the alert's own JSON dict — the same
observed-vs-threshold evidence a SOC analyst reads — so the model's decision
surface is exactly the envelope that later lands in the store and exports.
Nothing here talks to the network; the only input is the alert itself.
"""
from __future__ import annotations

from typing import Any

from src.alerts.schema import Alert
from src.triage.laya_runtime import Answer, Question

DISPOSITIONS = ("escalate", "investigate", "monitor", "false_positive")

# urgency rubric: index = level used in the expected-level score
URGENCY_LEVELS = (
    "routine, no time pressure",
    "should be looked at today",
    "analyst attention needed now",
    "drop everything: probable active attack",
)

# threat classes where "false_positive" is a plausible first disposition
# (window-shape rules misfire more often than the ML channels' tuned gates)
_NOISY_CLASSES = {"scan", "ddos", "slowdos", "exfil"}


def state_of(a: Alert) -> dict[str, Any]:
    """The analyst-readable state: alert envelope minus free-text noise.

    Window bookkeeping and alert ids stay out (they carry no decision
    signal and eat the 512-token budget); the 5-tuple, class, confidence,
    severity, detector, key and every evidence item stay in.
    """
    return {
        "threat_class": a.threat_class,
        "confidence": round(float(a.confidence), 3),
        "severity": a.severity,
        "detector": a.detector,
        "key": a.key,
        "src": a.src_ip, "dst": a.dst_ip,
        "src_port": a.src_port, "dst_port": a.dst_port, "proto": a.proto,
        "att&ck": a.attack_technique,
        "evidence": [
            {"condition": e.condition, "op": e.operator,
             "observed": e.observed, "threshold": e.threshold,
             "unit": e.unit}
            for e in a.evidence
        ],
    }


def triage_questions(a: Alert) -> dict[str, Question]:
    """The three typed questions asked of every alert (one forward pass)."""
    noisy = a.threat_class in _NOISY_CLASSES
    return {
        "disposition": Question(
            type="choice",
            instructions=(
                "You are the first-pass triage analyst for a passive "
                "network threat detector. Which action should the SOC "
                "queue for this alert?"),
            criteria={
                "escalate": "probable real threat: page the on-call and open an incident",
                "investigate": "worth a human look now, but not clearly an attack",
                "monitor": "keep watching; no action yet",
                "false_positive": (
                    "detector artifact or benign look-alike"
                    if noisy else
                    "detector artifact or benign look-alike (rare for this class)"),
            },
        ),
        "urgency": Question(
            type="score",
            instructions=("How urgent is handling this alert, on the "
                          "ordered rubric below?"),
            criteria=list(URGENCY_LEVELS),
        ),
        "corroborate": Question(
            type="noul",
            instructions=(
                f"Does the observed evidence genuinely support the "
                f"assigned threat class {a.threat_class!r}?"),
            criteria={
                "true": "the observed-vs-threshold items support this class",
                "false": "the evidence looks coincidental or mislabeled",
            },
        ),
    }


def answer_summary(answers: dict[str, Answer]) -> dict[str, Any]:
    """Analyst-facing triage dict: short names, no model internals.

    `recommended` echoes the choice's argmax; `p_false_positive` pulls the
    calibrated probability of the false-positive option; urgency is the
    expected level (0..3) with its legend so exports stay self-describing.
    """
    d = answers.get("disposition")
    u = answers.get("urgency")
    c = answers.get("corroborate")
    out: dict[str, Any] = {}
    if d is not None and d.type == "choice":
        out["recommended"] = d.choice
        out["p_false_positive"] = round(
            (d.probabilities or {}).get("false_positive", 0.0), 4)
        out["disposition_confidence"] = round(d.confidence, 4)
    if u is not None and u.type == "score":
        out["urgency"] = u.score
        out["urgency_legend"] = u.legend
    if c is not None and c.type == "noul":
        out["corroborates_class"] = c.noul
    return out
