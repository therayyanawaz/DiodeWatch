"""Rule-based threat detectors — fast, interpretable, auditable.

Each module is one interpretable detector over time-window aggregates:

  ddos     — volumetric flood / distributed fan-in / SYN flood (per dst window)
  slowdos  — slow-rate asymmetric DoS, slowloris family (per dst window)
  scan     — port/host sweeps from one source (per src window)
  exfil    — bulk outbound transfer / asymmetric uploads (per src window)

`rules.run_rules` evaluates the default set and returns evidence-rich Alert
objects (src.alerts.schema). Thresholds are calibrated on the CIC-IDS2017
Wednesday slice; see docs/rules.md and scripts/checks/check_rules.py.
"""
from .base import Rule
from .ddos import DDoSRule
from .exfil import ExfilRule
from .rules import DEFAULT_RULES, make_rules, run_rules
from .scan import ScanRule
from .slowdos import SlowDoSRule
from .window import WindowFrames, build_windows

__all__ = [
    "DEFAULT_RULES",
    "DDoSRule",
    "ExfilRule",
    "Rule",
    "ScanRule",
    "SlowDoSRule",
    "WindowFrames",
    "build_windows",
    "make_rules",
    "run_rules",
]
