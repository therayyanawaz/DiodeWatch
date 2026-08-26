"""Aggregate raw pcap/pcapng captures into canonical flow records.

Streams packets (never loads the capture into memory), folds both directions of
a conversation into one flow keyed on the endpoint pair, and closes a flow when
it has been idle longer than `flow_timeout` seconds (CICFlowMeter semantics:
idle timeout 120 s). A new flow on the same 5-tuple after an idle gap is emitted
as a separate record.

Emitted records share the exact schema of the table reader
(see src.ingest.schema.FLOW_FIELDS); labels are null — ground truth only exists
in the labeled CIC tables. The per-packet timing and size statistics are measured
here from the packets themselves, with the same encodings CIC uses, so a
pcap-derived row and a table-derived row mean the same thing.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path

from .schema import iso_from_epoch, proto_name, synth_flow_id

# TCP flag bits (matches scapy's TCP flag ints).
F_FIN, F_SYN, F_RST, F_PSH, F_ACK, F_URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

PCAP_SUFFIXES = {".pcap", ".pcapng"}

_FLAG_FIELDS = ("fin_flags", "syn_flags", "rst_flags",
                "psh_flags", "ack_flags", "urg_flags")


class _Stat:
    """Running count / min / max / mean / sample-std over one stream of numbers.

    O(1) memory per flow: packets are folded in as they arrive, never stored.
    std divides by n-1 (sample), which is what CICFlowMeter's Std columns do.
    An empty population encodes as 0.0 rather than null, matching CIC's own
    tables (a one-packet direction reports Std 0.0, not blank).
    """

    __slots__ = ("_m2", "_mean", "max", "min", "n", "total")

    def __init__(self) -> None:
        self.n = 0
        self.total = 0.0
        self.min = None
        self.max = None
        self._mean = 0.0
        self._m2 = 0.0

    def add(self, x: float) -> None:
        self.n += 1
        if self.min is None or x < self.min:
            self.min = x
        if self.max is None or x > self.max:
            self.max = x
        self.total += x
        delta = x - self._mean
        self._mean += delta / self.n
        self._m2 += delta * (x - self._mean)

    @property
    def mean(self) -> float:
        return self._mean if self.n else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self._m2 / (self.n - 1)) if self.n > 1 else 0.0

    @property
    def minimum(self) -> float:
        return 0.0 if self.min is None else self.min

    @property
    def maximum(self) -> float:
        return 0.0 if self.max is None else self.max


@dataclass
class _Flow:
    """Accumulating state for one bidirectional conversation."""
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    protocol: int
    first_ts: float
    last_ts: float
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    flags: dict[str, int] = field(default_factory=lambda: {f: 0 for f in _FLAG_FIELDS})
    len: _Stat = field(default_factory=_Stat)
    fwd_len: _Stat = field(default_factory=_Stat)
    bwd_len: _Stat = field(default_factory=_Stat)
    iat: _Stat = field(default_factory=_Stat)
    fwd_iat: _Stat = field(default_factory=_Stat)
    bwd_iat: _Stat = field(default_factory=_Stat)
    fwd_last_ts: float = 0.0
    bwd_last_ts: float = 0.0
    prev_ts: float = 0.0

    def observe(self, meta) -> None:
        """Fold one packet into the flow, updating the timing/size statistics."""
        ts, length = meta["ts"], float(meta["length"])
        # Flow IAT is the gap to the packet observed immediately before this
        # one, in arrival order: a capture with out-of-order packets yields a
        # negative gap, which is exactly how CIC ends up with negative
        # Flow IAT Min values in its published tables.
        if self.fwd_pkts + self.bwd_pkts:
            self.iat.add((ts - self.prev_ts) * 1e6)
        self.prev_ts = ts
        self.len.add(length)

        fwd = (meta["src_ip"] == self.src_ip and meta["src_port"] == self.src_port)
        if fwd:
            if self.fwd_pkts:
                self.fwd_iat.add((ts - self.fwd_last_ts) * 1e6)
            self.fwd_last_ts = ts
            self.fwd_pkts += 1
            self.fwd_bytes += meta["length"]
            self.fwd_len.add(length)
        else:
            if self.bwd_pkts:
                self.bwd_iat.add((ts - self.bwd_last_ts) * 1e6)
            self.bwd_last_ts = ts
            self.bwd_pkts += 1
            self.bwd_bytes += meta["length"]
            self.bwd_len.add(length)

        self.last_ts = max(self.last_ts, ts)
        if meta["flags"] is not None:
            for name, bit in (("fin_flags", F_FIN), ("syn_flags", F_SYN),
                              ("rst_flags", F_RST), ("psh_flags", F_PSH),
                              ("ack_flags", F_ACK), ("urg_flags", F_URG)):
                if meta["flags"] & bit:
                    self.flags[name] += 1

    def to_record(self) -> dict:
        duration_us = round((self.last_ts - self.first_ts) * 1_000_000)
        record = {
            "flow_id": synth_flow_id(self.src_ip, self.src_port,
                                     self.dst_ip, self.dst_port, self.protocol),
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "proto": proto_name(self.protocol),
            "timestamp": iso_from_epoch(self.first_ts),
            "ts_epoch": self.first_ts,
            "duration_us": duration_us,
            "fwd_pkts": self.fwd_pkts,
            "bwd_pkts": self.bwd_pkts,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            **self.flags,
            "label": None,
        }
        record.update({
            "iat_us_mean": self.iat.mean, "iat_us_std": self.iat.std,
            "iat_us_max": self.iat.maximum, "iat_us_min": self.iat.minimum,
            "fwd_iat_us_total": self.fwd_iat.total,
            "fwd_iat_us_mean": self.fwd_iat.mean, "fwd_iat_us_std": self.fwd_iat.std,
            "fwd_iat_us_max": self.fwd_iat.maximum,
            "fwd_iat_us_min": self.fwd_iat.minimum,
            "bwd_iat_us_total": self.bwd_iat.total,
            "bwd_iat_us_mean": self.bwd_iat.mean, "bwd_iat_us_std": self.bwd_iat.std,
            "bwd_iat_us_max": self.bwd_iat.maximum,
            "bwd_iat_us_min": self.bwd_iat.minimum,
            "len_min": self.len.minimum, "len_max": self.len.maximum,
            "len_mean": self.len.mean, "len_std": self.len.std,
            "fwd_len_min": self.fwd_len.minimum, "fwd_len_max": self.fwd_len.maximum,
            "fwd_len_mean": self.fwd_len.mean, "fwd_len_std": self.fwd_len.std,
            "bwd_len_min": self.bwd_len.minimum, "bwd_len_max": self.bwd_len.maximum,
            "bwd_len_mean": self.bwd_len.mean, "bwd_len_std": self.bwd_len.std,
        })
        return record


def _endpoint_key(src_ip, src_port, dst_ip, dst_port, protocol):
    """Direction-insensitive flow key: endpoints sorted, so replies fold in."""
    a = (src_ip, src_port if src_port is not None else 0)
    b = (dst_ip, dst_port if dst_port is not None else 0)
    lo, hi = (a, b) if a <= b else (b, a)
    return (lo[0], lo[1], hi[0], hi[1], protocol)


def _iter_packets(path: Path):
    """Yield scapy packets from .pcap or .pcapng without loading the capture."""
    import scapy.all  # noqa: F401 - loads the layer registry; without it a

    #                      pcap's Ethernet link-type dissects to bare Raw when
    #                      nothing else in the process imported scapy.all
    from scapy.utils import PcapNgReader, PcapReader

    reader_cls = PcapNgReader if path.suffix.lower() == ".pcapng" else PcapReader

    with reader_cls(str(path)) as reader:
        yield from reader


def _packet_meta(pkt) -> dict | None:
    """Extract (ts, ips, ports, proto, length, tcp flags) or None for non-IP."""
    try:
        if pkt is None or not hasattr(pkt, "time"):
            return None
        ts = float(pkt.time)
        ip = pkt.getlayer("IP") or pkt.getlayer("IPv6")
        if ip is None:
            return None
        src_ip, dst_ip = str(ip.src), str(ip.dst)

        try:
            proto = int(ip.proto)
        except AttributeError:
            proto = int(getattr(ip, "nh", 0))

        tcp = pkt.getlayer("TCP")
        udp = pkt.getlayer("UDP")
        sport = dport = None
        flags = None
        if tcp is not None:
            sport, dport = int(tcp.sport), int(tcp.dport)
            proto = 6
            try:
                flags = int(tcp.flags)
            except (ValueError, TypeError):
                flags = None
        elif udp is not None:
            sport, dport = int(udp.sport), int(udp.dport)
            proto = 17

        length = getattr(pkt, "wirelen", None)
        if length is None:
            length = len(pkt)
        return {
            "ts": ts, "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": sport, "dst_port": dport, "protocol": proto,
            "length": int(length), "flags": flags,
        }
    except Exception:  # noqa: BLE001 - malformed packet; do not kill the whole capture
        return None


def stream_flows(path: Path, *, flow_timeout: float = 120.0,
                 stats: dict | None = None):
    """Yield canonical flow records aggregated from a capture.

    `flow_timeout`: seconds of inactivity after which a flow is closed.
    `stats`: optional dict mutated with counters (pkts/ip_pkts/skipped/timeouts/
    flows/at_eof).
    """
    if stats is None:
        stats = {}
    stats.update(pkts=0, ip_pkts=0, skipped=0, timeouts=0, flows=0, at_eof=0)
    open_flows: dict[tuple, _Flow] = {}

    def new_flow(meta) -> _Flow:
        return _Flow(
            src_ip=meta["src_ip"], src_port=meta["src_port"],
            dst_ip=meta["dst_ip"], dst_port=meta["dst_port"],
            protocol=meta["protocol"],
            first_ts=meta["ts"], last_ts=meta["ts"], prev_ts=meta["ts"],
        )

    for pkt in _iter_packets(path):
        stats["pkts"] += 1
        meta = _packet_meta(pkt)
        if meta is None:
            stats["skipped"] += 1
            continue
        stats["ip_pkts"] += 1

        key = _endpoint_key(meta["src_ip"], meta["src_port"],
                            meta["dst_ip"], meta["dst_port"], meta["protocol"])
        flow = open_flows.get(key)
        if flow is None:
            flow = new_flow(meta)
            open_flows[key] = flow
        elif meta["ts"] - flow.last_ts > flow_timeout:
            # idle gap: previous flow is over, same 5-tuple restarts fresh
            stats["timeouts"] += 1
            yield flow.to_record()
            open_flows.pop(key, None)
            flow = new_flow(meta)
            open_flows[key] = flow

        flow.observe(meta)

    # EOF: flush remaining flows ordered by first-seen time.
    stats["at_eof"] = len(open_flows)
    yield from (f.to_record()
                for f in sorted(open_flows.values(), key=lambda fl: fl.first_ts))
