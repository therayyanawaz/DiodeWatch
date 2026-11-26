"""Slow-rate asymmetric DoS detector (slowloris / slowhttptest / slow read).

Distinct from the volumetric signature: the attacker holds MANY connections
open with tiny requests, starving server worker slots. Calibrated on the CIC
slice: benign windows with the same small-packet shape (scheduled pollers,
CDN beacons) have mean flow duration < 0.5 s and zero connections held longer
than the window, while slowloris windows hold 100-400 connections open across
consecutive windows.

Fires per (window, dst_ip) when the shape matches AND connections are held:

  flows >= 30            (coordinated pressure, not one chatty client)
  pkts_ratio >= 2        (fwd packets >> bwd; server gets no chance to talk)
  mean_fwd_pkt >= 10 B   (a real request has a header; 3 B ACK-only windows
                          are noise, not slowloris)
  mean_fwd_pkt <= 160 B  (small requests: headers-only / partial-header dribble)
  held_conns >= 5        (connections still open after the window ends)

The 160 B cap is the CIC-IDS2017 slowloris range, not the 80 B used by the
synthetic demo. On the Wednesday file 25 of 41 slow-labelled destination
windows pass the rate, ratio, and 160 B cap; at 80 B only 5 do, which is why
the stricter value missed the corpus. The 10 B floor rejects 14 Thursday
benign windows of about 2,000 flows each whose mean forward packet is
2.7-3.5 B; those are ACK-only bursts, not requests. CIC slowloris is 49-160 B and the demo is 15 B,
so both clear the floor.
"""
from __future__ import annotations

from src.alerts.schema import Alert

from .base import Rule, _fmt, ev
from .window import WindowFrames

MIN_FLOWS = 30
PKT_RATIO = 2.0
MIN_MEAN_FWD_PKT = 10.0
MAX_MEAN_FWD_PKT = 160.0
MIN_HELD_CONNS = 5


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

        alerts: list[Alert] = []
        for tup in wf.dst.itertuples():
            win_idx, dst_ip = tup.Index
            # cheap pre-check (mode=all: any failure => skip ev building)
            # NaN-safe: NaN comparisons are False, same as old explicit guards.
            c1 = tup.flows >= min_flows
            pr = tup.pkts_ratio
            c2 = pr >= pkt_ratio_th
            mfp = tup.mean_fwd_pkt
            c3 = min_pkt <= mfp <= max_pkt
            held = float(tup.held_conns)
            c4 = held >= min_held
            if not (c1 and c2 and c3 and c4):
                continue
            conditions: list[tuple[bool, object]] = [
                (bool(tup.flows >= min_flows), ev(
                    "flow_count", ">=", int(tup.flows), min_flows,
                    f"{int(tup.flows)} flows to {dst_ip} in one window",
                    unit="flows")),
                (bool(pr >= pkt_ratio_th), ev(
                    "fwd_bwd_pkt_ratio", ">=",
                    _fmt(pr, 2), pkt_ratio_th,
                    f"fwd/bwd packets {_fmt(pr, 2)} "
                    f"(fwd {int(tup.fwd_pkts)}, bwd {int(tup.bwd_pkts)})",
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
                (bool(held >= min_held), ev(
                    "held_connections", ">=", int(held), min_held,
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
