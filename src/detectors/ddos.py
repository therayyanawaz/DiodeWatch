"""DDoS rule detector: volumetric floods, distributed fan-in, SYN floods.

Windows are 10 s by default; signals are per-destination.

Calibration re-derived 2026-08-30 from the pinned CIC-IDS2017 Wednesday
table (692,703 flows / 440,031 BENIGN / 57,134 benign dst windows). Reproduce
every number quoted below with:

    python scripts/checks/check_thresholds.py

HONEST STATE ON THIS CORPUS, read before re-tuning. The raw 50 flows/s rate is
NOT clean: benign traffic reaches 210.9 flows/s and 77 benign windows cross
that line, 74 of them against 192.168.10.3 (median 66.9 flows/s). Fan-in
separates better: 73 benign windows reach 50 distinct sources, but only 2 are
also concentrated (src_conc <= 0.3). The volume branch therefore adds four
guards before it claims a flood: an online rate baseline, persistence, a
minimum byte rate below 200 flows/s, and a destination-port cardinality check.
Those guards are what make the branch usable; the raw threshold alone is not.

Three interpretable signatures (any combination fires; each contributes an
evidence item):

  volumetric   flows_per_sec >= 50 with all of:
                 - rate at or above max(50, 3x its online baseline) once 10 windows
                   have been seen
                 - persistence: >= 250 flows/s needs one window; 200-250 needs
                   two; 50-200 needs three and 20 KB/s (the baseline still
                   applies to every rate)
                 - a multi-port burst needs 500 KB/s to count as a flood,
                   unless it spreads over >= 5000 ports at >= 500 flows/s:
                   46k ports at 8k flows/s is a random-port SYN flood, not
                   a sweep (the scan rule caps at 5000 ports)
               OR fwd_bytes_per_sec >= 2 MB/s when n_src >= 3 (bandwidth flood)
  fan_in       n_src >= 50 AND src_conc <= 0.3 (many distinct hosts, each
               sending several flows, onto one target)
  syn_flood    syn_share >= 0.8 AND half_open >= 50 (fwd pkts ≫ bwd, unacked SYNs)

Slow-rate asymmetric DoS (slowloris-style: many small held connections) is
deliberately NOT folded in here, it is a distinct signature with different
thresholds and its own detector (`slowdos`).
"""
from __future__ import annotations

import pandas as pd

from src.alerts.schema import Alert

from .base import Rule, _fmt, ev
from .window import WindowFrames

FLOWS_PER_SEC = 50.0
HIGH_RATE = 200.0               # below this a volume claim needs one more window
IMMEDIATE_RATE = 250.0          # a flood this fast is not a busy-server spike
MIN_FLOOD_BPS = 20_000.0        # a low-rate flood must still move real bytes
BYTES_PER_SEC = 2_000_000.0     # 2 MB/s sustained to one destination
FANIN_SRC_IPS = 50              # benign max is 136 srcs/window, but only 2 of
                                 # those windows are also concentrated
                                 # (src_conc <= 0.3), see module docstring
FANIN_CONCENTRATION = 0.3
SYN_SHARE = 0.8
HALF_OPEN = 50

# Online per-destination rate baseline. The absolute threshold is the cold
# start; once a destination has a history, its own normal rate is the floor.
# Updates skip anomalous windows, so an attack cannot raise the baseline it is
# being measured against, while a busy server learns its own sustained rate.
BASELINE_ALPHA = 0.2
BASELINE_RATIO = 3.0
BASELINE_MIN_WINDOWS = 10
BASELINE_INIT_CAP = 2.0          # multiple of flows_per_sec
BASELINE_RESET_WINDOWS = 360     # one hour at 10 s windows
VOLUME_PERSISTENCE_GAP_S = 60.0  # CIC-IDS2017 timestamps are minute-granular
DPORT_FLOOD_MAX = 16            # a flood targets a service, not a port sweep
DPORT_SWEEP_BPS = 500_000.0     # a multi-port burst this large is still a flood
DPORT_RANDOM_MIN = 5000         # beyond the scan rule's port cap
DPORT_RANDOM_RATE = 500.0       # a random-port burst this fast is a flood


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
        dport_max = int(self.get("dport_flood_max", DPORT_FLOOD_MAX))
        dport_random_min = int(self.get("dport_random_min", DPORT_RANDOM_MIN))
        dport_random_rate = float(self.get("dport_random_rate",
                                            DPORT_RANDOM_RATE))

        alpha = float(self.get("baseline_alpha", BASELINE_ALPHA))
        ratio = float(self.get("baseline_ratio", BASELINE_RATIO))
        min_windows = int(self.get("baseline_min_windows", BASELINE_MIN_WINDOWS))
        init_cap = float(self.get("baseline_init_cap", BASELINE_INIT_CAP)) * fps_th
        reset_windows = int(self.get("baseline_reset_windows",
                                     BASELINE_RESET_WINDOWS))
        if not hasattr(self, "_rate_baseline"):
            self._rate_baseline: dict[str, float] = {}
            self._rate_samples: dict[str, int] = {}
            self._vol_run: dict[str, tuple[int, int]] = {}
            self._last_win: int | None = None

        # Baseline updates need chronological windows. The groupby preserves
        # first-seen order, which is not guaranteed when a batch is appended,
        # so sort the much smaller (window, destination) frame explicitly.
        d: pd.DataFrame = wf.dst.sort_index()
        alerts: list[Alert] = []
        # itertuples (~10x faster than iterrows) + two-phase: cheap numeric
        # pre-check first; build EvidenceItems only when something fires.
        # Benign-heavy windows (the common case) previously paid full _fmt/ev
        # formatting per group then discarded it in decide().
        for tup in d.itertuples():
            win_idx, dst_ip = tup.Index
            if self._last_win is not None and (
                    win_idx < self._last_win
                    or win_idx - self._last_win > reset_windows):
                self._rate_baseline.clear()
                self._rate_samples.clear()
                self._vol_run.clear()
            self._last_win = int(win_idx)
            fps = tup.flows_per_sec
            fwd_bps = tup.fwd_bytes_per_sec
            n_src = tup.n_src
            base = self._rate_baseline.get(str(dst_ip))
            samples = self._rate_samples.get(str(dst_ip), 0)
            threshold_used = fps_th
            novelty_ok = True
            if base is not None and samples >= min_windows:
                threshold_used = max(fps_th, base * ratio)
                novelty_ok = bool(fps >= threshold_used)
            raw_vol = bool(fps >= fps_th
                           or (fwd_bps >= bps_th and n_src >= 3))
            n_dports = float(getattr(tup, "n_dports", 0.0) or 0.0)
            # A flood against a service touches a handful of destination
            # ports. A low-bandwidth burst spread over hundreds of ports is
            # a port sweep and belongs to the scan class. A high-bandwidth
            # multi-port burst is a reflection flood, not a sweep.
            service = bool(n_dports == 0 or n_dports <= dport_max
                            or fwd_bps >= DPORT_SWEEP_BPS
                            or (n_dports >= dport_random_min
                                and fps >= dport_random_rate))
            # Tiny request traffic at 50-200 flows/s is ordinary server
            # chatter. A low-rate volume claim must also carry real bytes;
            # high-rate floods do not need this second check.
            credible = bool(fps >= HIGH_RATE or fwd_bps >= MIN_FLOOD_BPS)
            flood = bool(raw_vol and novelty_ok and service and credible)
            # CIC-IDS2017 exports only whole minutes, so occupied 10 s buckets
            # are 60 s apart. Treat any gap up to one minute as consecutive;
            # a truly idle minute in finer captures is still below the rate
            # threshold in the intervening buckets.
            max_gap = round(VOLUME_PERSISTENCE_GAP_S / wf.window_s)
            prev = self._vol_run.get(str(dst_ip))
            if flood:
                run = (prev[1] + 1 if prev is not None
                       and 0 < win_idx - prev[0] <= max_gap else 1)
            else:
                run = 0
            self._vol_run[str(dst_ip)] = (int(win_idx), run)
            # A one-window burst is not a flood. A flood above 250 flows/s
            # passes the persistence gate in that window; 200-250 needs two
            # windows and a lower rate needs three, because a busy server can
            # spike to a couple of hundred flows/s for a minute. Fan-in and SYN
            # signatures stay immediate: they are shape evidence, not a rate
            # spike.
            if fps >= IMMEDIATE_RATE:
                needed = 1
            elif fps >= HIGH_RATE:
                needed = 2
            else:
                needed = 3
            vol = bool(flood and run >= needed)
            # NaN-safe by IEEE semantics: NaN comparisons are always False,
            # identical to the old explicit (x if x==x else fallback) guards
            # (NaN src_conc/syn_share never fired before, never fires now).
            fan = bool(n_src >= fanin_n and tup.src_conc <= fanin_c)
            syn = bool(tup.syn_share >= syn_sh
                       and tup.half_open >= half_open_th)

            # Learn before the early return: quiet windows are exactly the
            # history a destination's baseline needs. A window above its own
            # baseline is the anomaly being claimed, so it must not raise the
            # baseline it is measured against.
            if base is None:
                base = min(float(fps), init_cap)
                samples = 1
            elif samples < min_windows:
                base = base + alpha * (min(float(fps), init_cap) - base)
                samples += 1
            elif not (raw_vol and novelty_ok):
                if fps <= base * ratio:
                    base = base + alpha * (fps - base)
                    samples += 1
            self._rate_baseline[str(dst_ip)] = float(base)
            self._rate_samples[str(dst_ip)] = samples

            if not (vol or fan or syn):
                continue
            if threshold_used > fps_th:
                rate_note = (
                    f"effective threshold {_fmt(threshold_used)}/s "
                    f"(baseline {_fmt(base)}/s x {ratio:g}; "
                    f"absolute floor {fps_th:g}/s)")
            else:
                rate_note = f"threshold {fps_th:g}/s"
            conditions: list[tuple[bool, object]] = []
            # volumetric (build ev only for context; unfired ev discarded by decide anyway)
            conditions.append((vol, ev(
                "volumetric_rate", ">=",
                _fmt(fps), threshold_used,
                f"{_fmt(fps)} flows/s to {dst_ip} "
                f"({rate_note}; {int(n_dports)} dst ports; bandwidth branch: "
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
