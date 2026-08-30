"""Data-exfiltration detector.

Two orthogonal signatures, both about bytes LEAVING the monitored network
(first-packet direction = outbound):  ratio   strongly asymmetric windows: upload/download bytes >= 10x sustained
          across >= 20 flows from one host, uploaded OUT of the monitored
          network (majority-external destinations) AND a meaningful absolute
          volume (>= 10 kB, a 600 B DNS burst with ratio 17:1 is not theft).
          Internal LAN transfers are not exfiltration; on the slice the
          asymmetric windows are client->gateway chatter and file copies,
          never external.

  bulk    large absolute upload: >= 5 MB forwarded in one window (>= 500 kB/s)
          from a single host to external destinations, regardless of ratio.
          Catches tunneling over responsive protocols where the reply channel
          is legitimately busy.

Calibration re-derived 2026-08-30 from the pinned CIC-IDS2017 Wednesday table
(39,213 benign source windows); reproduce with
`python scripts/checks/check_thresholds.py`. Benign windows top out at
4,369.8 kB uploaded per 10 s window (p95 18.2 kB), and NO benign window
reaches the 5 MB bulk threshold, so `bulk_upload_bytes` keeps ~0.6 MB of
headroom over the worst benign window. An earlier revision quoted "968 kB",
which did not reproduce.

The slice contains no exfil-labelled traffic, so these rules are also
unit-tested against synthetic scenarios (tests/detectors/test_detectors.py)."""

from __future__ import annotations

from src.alerts.schema import Alert

from .base import Rule, _fmt, ev
from .window import WindowFrames

MIN_UPLOAD_RATIO = 10.0
RATIO_MIN_FLOWS = 20
MIN_RATIO_UPLOAD_BYTES = 10_000.0   # ratio needs absolute volume to matter
BULK_UPLOAD_BYTES = 5_000_000.0
MIN_EXTERNAL_SHARE = 0.5        # most flows must LEAVE the monitored network


class ExfilRule(Rule):
    name = "exfil"
    threat_class = "exfil"
    description = "bulk outbound transfer: asymmetric byte ratio or large sustained upload"

    def evaluate(self, wf: WindowFrames) -> list[Alert]:
        ratio_th = float(self.get("upload_ratio", MIN_UPLOAD_RATIO))
        ratio_flows = int(self.get("ratio_min_flows", RATIO_MIN_FLOWS))
        ratio_floor = float(self.get("min_upload_bytes", MIN_RATIO_UPLOAD_BYTES))
        bulk_th = float(self.get("bulk_upload_bytes", BULK_UPLOAD_BYTES))
        min_ext = float(self.get("min_external_share", MIN_EXTERNAL_SHARE))

        alerts: list[Alert] = []
        for tup in wf.src.itertuples():
            win_idx, src_ip = tup.Index
            _internal = tup.internal_dst_share
            try:
                import math as _math
                if _internal is None or (
                        isinstance(_internal, float) and _math.isnan(_internal)):
                    _internal = 0.0
            except TypeError:
                _internal = 0.0
            ext_share = 1.0 - float(_internal)
            ext_ok = bool(ext_share >= min_ext)
            fwd_b = float(tup.fwd_bytes)
            up_ratio = tup.upload_ratio
            ratio_ok = bool(ext_ok
                            and up_ratio >= ratio_th
                            and tup.flows >= ratio_flows
                            and fwd_b >= ratio_floor)
            bulk_ok = bool(ext_ok and fwd_b >= bulk_th)
            if not (ratio_ok or bulk_ok):
                continue
            gate_ev = ev(
                "external_dst_share", ">=", _fmt(ext_share, 2), min_ext,
                f"{_fmt(ext_share * 100, 0)}% of the window's flows leave "
                f"the monitored network (exfiltration crosses the boundary)",
                unit="fraction")

            conditions: list[tuple[bool, object]] = []

            # `fired` only ever holds conditions that passed, so the detail
            # rows below cannot carry the NaN a zero-reply window produces
            conditions.append((ratio_ok, ev(
                "upload_ratio", ">=", _fmt(up_ratio, 1), ratio_th,
                f"upload:download bytes {up_ratio:.1f}:1 over {int(tup.flows)} "
                f"flows, {_fmt(fwd_b, 0)} B uploaded (fwd vs bwd "
                f"{_fmt(float(tup.bwd_bytes), 0)} B; volume floor {ratio_floor:g} B)",
                unit="ratio")))

            conditions.append((bulk_ok, ev(
                "bulk_upload_bytes", ">=", _fmt(fwd_b, 0), bulk_th,
                f"{_fmt(fwd_b, 0)} B uploaded from {src_ip} in one window "
                f"({_fmt(fwd_b / wf.window_s / 1000, 0)} kB/s sustained)",
                unit="bytes")))

            fired = self.decide(conditions)
            if not fired:
                continue
            # the direction gate is part of the proof whenever the rule fires
            alerts.append(self.make_alert(
                ts=None, flow_id=f"{src_ip}/*", key=str(src_ip),
                src_ip=str(src_ip),
                evidence=[gate_ev, *fired], n_fired=len(fired),
                n_total=len(conditions),
                wf=wf, win_idx=int(win_idx), label=tup.label,
            ))
        return alerts
