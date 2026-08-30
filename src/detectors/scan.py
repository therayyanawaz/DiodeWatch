"""Port-scan / reconnaissance detector.Fires per (window, src_ip). One source touching many distinct destination
ports or many distinct hosts within a window is the classic scan signature;
on the CIC slice, benign high-cardinality sources exist (proxies, monitors,
load balancers), so cardinality alone is noisy (66 benign windows > 30 ports).
The rule therefore requires the recon SHAPE as well:

  server_share <= 0.2      (a host whose flows mostly originate FROM service
                            ports is a server answering clients — the
                            observed 'ports' are client-side ephemeral ports)
  min flows from the source          (>= 8, excludes one-shot stragglers)
  cardinality                        ports >= 30 OR hosts >= 30
  low bytes per flow                 <= 600 B total per flow (probes, not sessions)
  incomplete responses               resp_share <= 0.5 (at least half the
                                     probes never got a single reply packet)

Calibration re-derived 2026-08-30 from the pinned CIC-IDS2017 Wednesday table
(39,213 benign source windows); reproduce with
`python scripts/checks/check_thresholds.py`:

  server_share <= 0.2 removes 65 of the 66 high-cardinality benign windows —
    it is the decisive gate, not the byte-size or response gates
  benign high-cardinality windows carry 285 B/flow at the median (p95 9,178 B)
  benign resp_share p50 = 0.965, so the <= 0.5 gate keeps 9 of the 66
  all four conditions together leave 3 benign windows passing

HONEST STATE: the conjunction is NOT zero on this corpus — it yields 3 benign
alerts. An earlier revision claimed "median > 1 kB/flow" and "yields zero
benign false positives"; neither reproduced. The overall benign
bytes-per-flow median is 12 B, far below the > 1 kB quoted."""

from __future__ import annotations

from src.alerts.schema import Alert

from .base import Rule, _fmt, ev
from .window import WindowFrames

MIN_FLOWS = 8
MIN_PORTS = 30
MIN_HOSTS = 30
MAX_BYTES_PER_FLOW = 600.0
MAX_RESP_SHARE = 0.5
MAX_SERVER_SHARE = 0.2


class ScanRule(Rule):
    name = "scan"
    threat_class = "scan"
    mode = "all"
    description = "port/host sweep from one source: high cardinality, tiny flows, unanswered probes"

    def evaluate(self, wf: WindowFrames) -> list[Alert]:
        min_flows = int(self.get("min_flows", MIN_FLOWS))
        min_ports = int(self.get("min_ports", MIN_PORTS))
        min_hosts = int(self.get("min_hosts", MIN_HOSTS))
        max_bpf = float(self.get("max_bytes_per_flow", MAX_BYTES_PER_FLOW))
        max_resp = float(self.get("max_resp_share", MAX_RESP_SHARE))
        max_srv = float(self.get("max_server_share", MAX_SERVER_SHARE))

        alerts: list[Alert] = []
        for tup in wf.src.itertuples():
            win_idx, src_ip = tup.Index
            flows = int(tup.flows)
            if flows < min_flows:
                continue
            ports = int(tup.n_dports)
            hosts = int(tup.n_dips)
            bpf = tup.bytes_per_flow
            resp = tup.resp_share
            srv = tup.server_share

            c_srv = srv <= max_srv
            c_card = (ports >= min_ports) or (hosts >= min_hosts)
            c_bpf = bpf <= max_bpf
            c_resp = resp <= max_resp
            if not (c_srv and c_card and c_bpf and c_resp):
                continue
            conditions: list[tuple[bool, object]] = [
                (bool(srv <= max_srv), ev(
                    "server_share", "<=", _fmt(srv, 2), max_srv,
                    f"only {_fmt(srv * 100, 0)}% of flows originate "
                    f"from a service port (< {int(max_srv * 100)}% — this host "
                    f"initiates, it is not a server answering clients)",
                    unit="fraction")),
                (c_card, ev(
                    "cardinality", ">=",
                    f"ports={ports}/hosts={hosts}",
                    f"ports={min_ports}/hosts={min_hosts}",
                    f"{ports} distinct dst ports, {hosts} distinct dst hosts "
                    f"from {src_ip} in one window", unit="count")),
                (bool(bpf <= max_bpf), ev(
                    "bytes_per_flow", "<=", _fmt(bpf), max_bpf,
                    f"{_fmt(bpf)} total bytes per flow (probe-sized, no payloads)",
                    unit="bytes")),
                (bool(resp <= max_resp), ev(
                    "resp_share", "<=", _fmt(resp, 2), max_resp,
                    f"only {_fmt(resp * 100, 0)}% of flows received any response "
                    f"(incomplete handshakes)", unit="fraction")),
            ]
            fired = self.decide(conditions)
            if not fired:
                continue
            alerts.append(self.make_alert(
                ts=None, flow_id=f"{src_ip}/*", key=str(src_ip),
                src_ip=str(src_ip),
                evidence=fired, n_fired=len(fired), n_total=len(conditions),
                wf=wf, win_idx=int(win_idx), label=tup.label,
            ))
        return alerts
