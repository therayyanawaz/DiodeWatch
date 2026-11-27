"""Port-scan detector. Fires per (window, src_ip). One source touching many
distinct destination ports within a window is the classic scan signature; on
the CIC slice, benign high-cardinality sources exist (proxies, monitors, load
balancers), so cardinality alone is noisy (66 benign windows > 30 ports). The
rule therefore requires the recon SHAPE as well:

  server_share <= 0.2      (a host whose flows mostly originate FROM service
                            ports is a server answering clients, the
                            observed 'ports' are client-side ephemeral ports)
  min flows from the source          (>= 8, excludes one-shot stragglers)
  cardinality                        30-5000 ports on <= 3 destinations
                                     46k ports in one window is a SYN flood
                                     with random destinations, not a sweep
  low bytes per flow                 <= 600 B total per flow (probes, not sessions)
  a response shape, either:
    incomplete responses             resp_share <= 0.5 (at least half the
                                     probes never got a single reply packet)
    reset-closed sweep               ports >= 100 on <= 2 hosts AND
                                     resp_share >= 0.9 (the target answers every
                                     probe with RST, so "no reply" is false for
                                     this scanner style)

A separate narrow-sweep branch covers short boundary fragments of the CIC
PortScan:

  5-10 ports on <= 2 hosts, flows >= 30, bytes/flow <= 50, resp_share >= 0.9

Those fragments are probes to five ports answered on every flow at 2.4-9.2 B
per flow; the thirty-probe floor separates them from one-shot service checks
and ordinary five-connection page loads. The branch adds four CIC-IDS2017
PortScan windows and no benign window across the eight-day corpus. The other
twelve PortScan truth units carry 1-29 flows on 1-5 ports and stay
sub-threshold: they are too small to separate from normal client traffic.

Calibration re-derived 2026-08-30 from the pinned CIC-IDS2017 Wednesday table
(39,213 benign source windows); reproduce with
`python scripts/checks/check_thresholds.py`:

  server_share <= 0.2 removes 65 of the 66 high-cardinality benign windows -
    it is the decisive gate, not the byte-size or response gates
  benign high-cardinality windows carry 285 B/flow at the median (p95 9,178 B)
  benign resp_share p50 = 0.965, so the <= 0.5 gate keeps 9 of the 66
  all four conditions together leave zero benign windows passing

HONEST STATE: the rule emits 2 benign alerts on the full eight-day CIC-IDS2017
corpus, both high-port sweeps from one source that satisfy every gate: one
reset-closed sweep (956 ports, 2 hosts) and one 1,003-port unanswered sweep on
3 hosts. They are accepted and reported. An earlier revision claimed "median >
1 kB/flow" and "yields zero benign false positives"; neither reproduced. The
overall benign bytes-per-flow median is 12 B, far below the > 1 kB quoted.

The host-sweep branch (hosts >= 30 and ports <= 16) was removed 2026-11-27
after it fired 29 benign CIC-IDS2017 windows and zero scan-labelled windows
across all eight files. Those 30-43 host sweeps were internal discovery by
ordinary hosts, not the focused high-port recon this rule claims. Broad host
discovery is left to the behaviour layer rather than guessed from cardinality;
removing the branch cut scan alerts from 42 to 13 without losing a truth unit.

The reset-closed branch was added 2026-11-26 after the CIC-IDS2017 PortScan
file exposed 11 scan-labelled windows that every probe got a reply to. It
fires those 11 windows and one Thursday BENIGN window (973 flows, 956 ports,
2 hosts); no Wednesday window passes. The plain no-reply branch also fires the
3-host 1,003-port window listed above. Both are accepted and reported rather
than papered over."""

from __future__ import annotations

from src.alerts.schema import Alert

from .base import Rule, _fmt, ev
from .window import WindowFrames

MIN_FLOWS = 8
MIN_PORTS = 30
MAX_SCAN_PORTS = 5000
MAX_PORT_SCAN_HOSTS = 3
MAX_BYTES_PER_FLOW = 600.0
MAX_RESP_SHARE = 0.5
MAX_SERVER_SHARE = 0.2
MIN_RESET_PORTS = 100
MAX_RESET_HOSTS = 2
MIN_RESET_RESP_SHARE = 0.9
# Narrow-sweep boundary fragments: a handful of ports, but enough repeated
# probe-sized answered flows in one window to be a sweep rather than a page
# load. Full-corpus calibration leaves zero benign windows passing this branch.
MIN_NARROW_PORTS = 5
MAX_NARROW_PORTS = 10
MIN_NARROW_FLOWS = 30
MAX_NARROW_HOSTS = 2
MAX_NARROW_BYTES_PER_FLOW = 50.0
MIN_NARROW_RESP_SHARE = 0.9


class ScanRule(Rule):
    name = "scan"
    threat_class = "scan"
    mode = "all"
    description = "port sweep from one source: high cardinality, tiny flows, unanswered probes"

    def evaluate(self, wf: WindowFrames) -> list[Alert]:
        min_flows = int(self.get("min_flows", MIN_FLOWS))
        min_ports = int(self.get("min_ports", MIN_PORTS))
        max_scan_hosts = int(self.get("max_port_scan_hosts",
                                      MAX_PORT_SCAN_HOSTS))
        max_scan_ports = int(self.get("max_scan_ports", MAX_SCAN_PORTS))
        max_bpf = float(self.get("max_bytes_per_flow", MAX_BYTES_PER_FLOW))
        max_resp = float(self.get("max_resp_share", MAX_RESP_SHARE))
        max_srv = float(self.get("max_server_share", MAX_SERVER_SHARE))
        min_reset_ports = int(self.get("min_reset_ports", MIN_RESET_PORTS))
        max_reset_hosts = int(self.get("max_reset_hosts", MAX_RESET_HOSTS))
        min_reset_resp = float(self.get("min_reset_resp_share",
                                        MIN_RESET_RESP_SHARE))
        min_narrow_ports = int(self.get("min_narrow_ports", MIN_NARROW_PORTS))
        max_narrow_ports = int(self.get("max_narrow_ports", MAX_NARROW_PORTS))
        min_narrow_flows = int(self.get("min_narrow_flows", MIN_NARROW_FLOWS))
        max_narrow_hosts = int(self.get("max_narrow_hosts", MAX_NARROW_HOSTS))
        max_narrow_bpf = float(self.get("max_narrow_bytes_per_flow",
                                       MAX_NARROW_BYTES_PER_FLOW))
        min_narrow_resp = float(self.get("min_narrow_resp_share",
                                        MIN_NARROW_RESP_SHARE))

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
            c_card = (ports <= max_scan_ports
                      and ports >= min_ports
                      and hosts <= max_scan_hosts)
            c_bpf = bpf <= max_bpf
            c_reset = (ports >= min_reset_ports
                       and hosts <= max_reset_hosts
                       and resp >= min_reset_resp)
            c_resp = (resp <= max_resp) or c_reset
            c_narrow = (min_narrow_ports <= ports <= max_narrow_ports
                        and flows >= min_narrow_flows
                        and hosts <= max_narrow_hosts
                        and bpf <= max_narrow_bpf
                        and resp >= min_narrow_resp)
            if c_srv and c_card and c_bpf and c_resp:
                if resp <= max_resp:
                    response_ev = ev(
                        "resp_share", "<=", _fmt(resp, 2), max_resp,
                        f"only {_fmt(resp * 100, 0)}% of flows received any "
                        f"response (incomplete handshakes)", unit="fraction")
                else:
                    response_ev = ev(
                        "resp_share", ">=", _fmt(resp, 2), min_reset_resp,
                        f"{_fmt(resp * 100, 0)}% of flows received a reply across "
                        f"{ports} ports on {hosts} host(s) "
                        f"(reset-closed sweep)", unit="fraction")
                conditions: list[tuple[bool, object]] = [
                    (bool(srv <= max_srv), ev(
                        "server_share", "<=", _fmt(srv, 2), max_srv,
                        f"only {_fmt(srv * 100, 0)}% of flows originate "
                        f"from a service port (< {int(max_srv * 100)}%, this "
                        f"host initiates, it is not a server answering clients)",
                        unit="fraction")),
                    (c_card, ev(
                        "cardinality", ">=",
                        f"ports={ports}/hosts={hosts}",
                        f"{min_ports}-{max_scan_ports} ports on "
                        f"<={max_scan_hosts} hosts",
                        f"{ports} distinct dst ports on {hosts} distinct dst "
                        f"host(s) from {src_ip} in one window", unit="count")),
                    (bool(bpf <= max_bpf), ev(
                        "bytes_per_flow", "<=", _fmt(bpf), max_bpf,
                        f"{_fmt(bpf)} total bytes per flow "
                        f"(probe-sized, no payloads)", unit="bytes")),
                    (bool(c_resp), response_ev),
                ]
            elif c_srv and c_narrow:
                conditions = [
                    (bool(srv <= max_srv), ev(
                        "server_share", "<=", _fmt(srv, 2), max_srv,
                        f"only {_fmt(srv * 100, 0)}% of flows originate "
                        f"from a service port (< {int(max_srv * 100)}%, this "
                        f"host initiates, it is not a server answering clients)",
                        unit="fraction")),
                    (bool(c_narrow), ev(
                        "cardinality", ">=",
                        f"ports={ports}/hosts={hosts}",
                        f"{min_narrow_ports}-{max_narrow_ports} ports on "
                        f"<={max_narrow_hosts} hosts",
                        f"{ports} distinct dst ports on {hosts} distinct dst "
                        f"host(s) from {src_ip} in one window "
                        f"(narrow boundary sweep)", unit="count")),
                    (bool(bpf <= max_narrow_bpf), ev(
                        "bytes_per_flow", "<=", _fmt(bpf), max_narrow_bpf,
                        f"{_fmt(bpf)} total bytes per flow "
                        f"(probe-sized, no payloads)", unit="bytes")),
                    (bool(resp >= min_narrow_resp), ev(
                        "resp_share", ">=", _fmt(resp, 2), min_narrow_resp,
                        f"{_fmt(resp * 100, 0)}% of flows received a reply "
                        f"across {ports} ports on {hosts} host(s) "
                        f"(answered narrow sweep)", unit="fraction")),
                    (bool(flows >= min_narrow_flows), ev(
                        "flow_count", ">=", flows, min_narrow_flows,
                        f"{flows} probes to {ports} ports in one window "
                        f"(not a one-shot service check)", unit="flows")),
                ]
            else:
                continue
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
