"""DDoS rule detector: volumetric floods, distributed fan-in, SYN floods.

Windows are 10 s by default; signals are per-destination.

Calibration re-derived 2026-08-30 from the pinned CIC-IDS2017 Wednesday
table (692,703 flows / 440,031 BENIGN / 57,134 benign dst windows). Reproduce
every number quoted below with:

    python scripts/checks/check_thresholds.py

HONEST STATE ON THIS CORPUS — read before re-tuning. `volumetric_rate` is
NOT clean at 50 flows/s: benign traffic reaches 210.9 flows/s and 77 benign
windows cross the threshold, 74 of them against a single destination
(192.168.10.3, median 66.9 flows/s). Those 74 are the bulk of this rule's
benign alerts. The fan-in signature separates far better — 73 benign windows
reach 50 distinct sources, but only 2 are also concentrated (src_conc <= 0.3).
An earlier revision of this docstring claimed "benign tops out at 48.8
flows/s ... zero benign window false-positives"; that did not reproduce and
has been replaced. See docs/rules.md "Acceptance reality".

Three interpretable signatures (any combination fires; each contributes an
evidence item):

  volumetric   flows_per_sec  >= 50            (flow-rate flood)
               OR fwd_bytes_per_sec >= 2 MB/s when n_src >= 3 (bandwidth flood)
  fan_in       n_src >= 50 AND src_conc <= 0.3 (many distinct hosts, each
               sending several flows, onto one target)
  syn_flood    syn_share >= 0.8 AND half_open >= 50 (fwd pkts ≫ bwd, unacked SYNs)

Slow-rate asymmetric DoS (slowloris-style: many small held connections) is
deliberately NOT folded in here — it is a distinct signature with different
thresholds and its own detector (`slowdos`).
"""
from __future__ import annotations

import pandas as pd

from src.alerts.schema import Alert

from .base import Rule, _fmt, ev
from .window import WindowFrames

FLOWS_PER_SEC = 50.0
BYTES_PER_SEC = 2_000_000.0     # 2 MB/s sustained to one destination
FANIN_SRC_IPS = 50              # benign max is 136 srcs/window, but only 2 of
                                 # those windows are also concentrated
                                 # (src_conc <= 0.3) — see module docstring
FANIN_CONCENTRATION = 0.3
SYN_SHARE = 0.8
HALF_OPEN = 50


class DDoSRule(Rule):
    name = "ddos"
    threat_class = "ddos"
    description = "volumetric flood / distributed fan-in / SYN flood to one destination"

    def evaluate(self, wf: WindowFrames) -> list[Alert]:
        fps_th = float(self.get("flows_per_sec", FLOWS_PER_SEC))
        bps_th = float(self.get("bytes_per_sec", BYTES_PER_SEC))
        fanin_n = int(self.get("fanin_src_ips", FANIN_SRC_IPS))
        fanin_c = float(self.get("fanin_concentration", FANIN_CONCENTRATION))
        syn_sh = float(self.get("syn_share", SYN_SHARE))
        half_open_th = float(self.get("half_open", HALF_OPEN))

        d: pd.DataFrame = wf.dst
        alerts: list[Alert] = []
        # itertuples (~10x faster than iterrows) + two-phase: cheap numeric
        # pre-check first; build EvidenceItems only when something fires.
        # Benign-heavy windows (the common case) previously paid full _fmt/ev
        # formatting per group then discarded it in decide().
        for tup in d.itertuples():
            win_idx, dst_ip = tup.Index
            fps = tup.flows_per_sec
            fwd_bps = tup.fwd_bytes_per_sec
            n_src = tup.n_src
            vol = bool(fps >= fps_th or (fwd_bps >= bps_th and n_src >= 3))
            # NaN-safe by IEEE semantics: NaN comparisons are always False,
            # identical to the old explicit (x if x==x else fallback) guards
            # (NaN src_conc/syn_share never fired before, never fires now).
            fan = bool(n_src >= fanin_n and tup.src_conc <= fanin_c)
            syn = bool(tup.syn_share >= syn_sh
                       and tup.half_open >= half_open_th)
            if not (vol or fan or syn):
                continue
            conditions: list[tuple[bool, object]] = []
            # volumetric (build ev only for context; unfired ev discarded by decide anyway)
            conditions.append((vol, ev(
                "volumetric_rate", ">=",
                _fmt(fps), fps_th,
                f"{_fmt(fps)} flows/s to {dst_ip} "
                f"(threshold {fps_th:g}/s; bandwidth branch: "
                f"{_fmt(fwd_bps)} B/s vs {bps_th:g})",
                unit="flows/s")))
            conditions.append((fan, ev(
                "fan_in_distinct_sources", ">=", int(n_src), fanin_n,
                f"{int(n_src)} distinct source IPs -> {dst_ip} "
                f"(concentration {_fmt(tup.src_conc, 2)} <= {fanin_c})",
                unit="src IPs")))
            conditions.append((syn, ev(
                "syn_flood_half_open", ">=", int(tup.half_open), half_open_th,
                f"SYN share {_fmt(tup.syn_share, 2)} of fwd packets "
                f"(>= {syn_sh}), {int(tup.half_open)} unacked SYNs, "
                f"fwd/bwd pkts {_fmt(tup.pkts_ratio, 2)}",
                unit="half-open SYNs")))

            fired = self.decide(conditions)
            if not fired:
                continue
            alerts.append(self.make_alert(
                ts=None, flow_id=f"{dst_ip}/*", key=str(dst_ip),
                dst_ip=str(dst_ip),
                evidence=fired, n_fired=len(fired), n_total=len(conditions),
                wf=wf, win_idx=int(win_idx), label=tup.label,
            ))
        return alerts
