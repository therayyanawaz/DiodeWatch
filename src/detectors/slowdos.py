"""Slow-rate asymmetric DoS detector (slowloris / slowhttptest / slow read).

Distinct from the volumetric signature: the attacker holds MANY connections
open with tiny requests, starving server worker slots. Calibrated on the CIC
slice: benign windows with the same small-packet shape (scheduled pollers,
CDN beacons) have mean flow duration < 0.5 s and zero connections held longer
than the window, while slowloris windows hold 100-400 connections open across
consecutive windows.

Fires per (window, dst_ip) when the shape matches AND connections are held:

  flows >= 30            (coordinated pressure, not one chatty client)
  mean_fwd_pkt >= 10 B   (a real request has a header; 3 B ACK-only windows
                          are noise, not slowloris)
  mean_fwd_pkt <= 300 B  (small requests: headers-only / partial-header dribble)

and one of two held-connection profiles:

  base                   pkts_ratio >= 2 and held_conns >= 5
  held-dominant          pkts_ratio >= 1.6 and held_conns >= 15

The held-dominant profile exists because a mixed window can carry ordinary
web traffic that dilutes the all-flow packet ratio while the victim still has
15+ starved connections open. Held connections are direct evidence of the
starvation mechanism, so a larger count earns a lower ratio floor. It does not
widen the 300 B cap: a normal 400 B HTTP body with 100+ held connections must
stay outside the slow-request band.

The 300 B cap covers both CIC-IDS2017 slow families, not the 80 B used by
the synthetic demo. Slowloris sits at 49-160 B; Slowhttptest requests reach
169-296 B on the Wednesday file, so a 160 B cap missed most of that family.
The 300 B ceiling still separates a header-only slow request from a normal
HTTP body; the latter also fails the held-connection gate. At 80 B only 5
slow-labelled destination windows pass the rate, ratio, and size gates; 160 B
reaches the slowloris half and 300 B reaches both. The 10 B floor rejects 14
Thursday benign windows of about 2,000 flows each whose mean forward packet
is 2.7-3.5 B; those are ACK-only bursts, not requests. CIC slowloris is
49-160 B and the demo is 15 B, so both clear the floor.
"""
from __future__ import annotations

from src.alerts.schema import Alert

from .base import Rule, _fmt, ev
from .window import WindowFrames

MIN_FLOWS = 30
PKT_RATIO = 2.0
MIN_MEAN_FWD_PKT = 10.0
MAX_MEAN_FWD_PKT = 300.0
MIN_HELD_CONNS = 5
# Held-dominant alternative: 15 connections still open past the window is
# enough starvation evidence to accept a lower packet ratio. Calibrated on the
# CIC-IDS2017 Wednesday slow-DoS windows; the full eight-day corpus keeps the
# same single benign-only slow alert.
HELD_PKT_RATIO = 1.6
HELD_MIN_CONNS = 15
# A single window this strong is not a benign poller or backup: 100 flows in
# 10 s and 100 connections still open past the window is the starvation shape
# itself. Corroboration keeps it even when no earlier slow window exists, so
# the first window of a sustained run is no longer lost.
STRONG_MIN_FLOWS = 100
STRONG_HELD_CONNS = 100


class SlowDoSRule(Rule):
    name = "slowdos"
    threat_class = "slowdos"
    mode = "all"
    description = "slow-rate asymmetric DoS: many tiny, long-held connections to one dst"

    def evaluate(self, wf: WindowFrames) -> list[Alert]:
        min_flows = int(self.get("min_flows", MIN_FLOWS))
        pkt_ratio_th = float(self.get("pkt_ratio", PKT_RATIO))
        min_pkt = float(self.get("min_mean_fwd_pkt", MIN_MEAN_FWD_PKT))
        max_pkt = float(self.get("max_mean_fwd_pkt", MAX_MEAN_FWD_PKT))
        min_held = float(self.get("min_held_conns", MIN_HELD_CONNS))
        held_ratio_th = float(self.get("held_pkt_ratio", HELD_PKT_RATIO))
        held_min_conns = float(self.get("held_min_conns", HELD_MIN_CONNS))

        alerts: list[Alert] = []
        for tup in wf.dst.itertuples():
            win_idx, dst_ip = tup.Index
            # cheap pre-check (mode=all: any failure => skip ev building)
            # NaN-safe: NaN comparisons are False, same as old explicit guards.
            c1 = tup.flows >= min_flows
            pr = tup.pkts_ratio
            mfp = tup.mean_fwd_pkt
            c3 = min_pkt <= mfp <= max_pkt
            held = float(tup.held_conns)
            base = c1 and c3 and pr >= pkt_ratio_th and held >= min_held
            held_dominant = (c1 and c3 and pr >= held_ratio_th
                             and held >= held_min_conns)
            if not (base or held_dominant):
                continue
            ratio_th = pkt_ratio_th if base else held_ratio_th
            held_th = min_held if base else held_min_conns
            ratio_note = ("" if base else
                          f"; {int(held)} held connections lower the floor "
                          f"from {pkt_ratio_th:.1f} to {held_ratio_th:.1f}")
            conditions: list[tuple[bool, object]] = [
                (bool(tup.flows >= min_flows), ev(
                    "flow_count", ">=", int(tup.flows), min_flows,
                    f"{int(tup.flows)} flows to {dst_ip} in one window",
                    unit="flows")),
                (bool(pr >= ratio_th), ev(
                    "fwd_bwd_pkt_ratio", ">=",
                    _fmt(pr, 2), ratio_th,
                    f"fwd/bwd packets {_fmt(pr, 2)} "
                    f"(fwd {int(tup.fwd_pkts)}, bwd {int(tup.bwd_pkts)})"
                    f"{ratio_note}",
                    unit="ratio")),
                (bool(min_pkt <= mfp), ev(
                    "mean_fwd_pkt_floor", ">=",
                    _fmt(mfp), min_pkt,
                    f"mean fwd packet {_fmt(mfp)} B carries a real header "
                    f"(ACK-only 3 B bursts are not slowloris)", unit="bytes")),
                (bool(mfp <= max_pkt), ev(
                    "mean_fwd_pkt_size", "<=",
                    _fmt(mfp), max_pkt,
                    f"mean fwd packet {_fmt(mfp)} B "
                    f"(tiny partial requests)", unit="bytes")),
                (bool(held >= held_th), ev(
                    "held_connections", ">=", int(held), held_th,
                    f"{int(held)} connections still open past the {wf.window_s}s "
                    f"window (slow client starvation)", unit="connections")),
            ]
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
