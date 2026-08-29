"""Frozen feature schema for the detectors.

One row per flow. Everything the detectors will ever consume is declared HERE so
the feature list is stable across runs, sources, and future stages; the registry
is the single source of truth for both `engine.build_features` and `docs`.

Column groups:

  meta        identity/provenance carried for joins, eval and alerting
              (never model inputs)
  basic       duration, packet/byte counts, mean packet sizes
  rates       throughput per direction and total (bytes/s, pkts/s)
  ratio       directional ratios / asymmetry
  protocol    one-hot transport families
  tcpflags    TCP flag-packet counts (0 for non-TCP flows)
  dns         DNS-shape flags (payload-derived fields are 'future')
  iat         per-packet inter-arrival timing in microseconds, per flow and per
              direction (passthrough of the canonical record's measurements)
  pktlen      per-packet size in bytes, per flow and per direction (same)
  context     group statistics over the batch window (same source / destination)
  future      declared but NOT yet emitted, needs Zeek DNS/SSL logs (domain
              entropy, NXDOMAIN, JA3/JA3S), live windows, or a burst-split
              definition we can stand behind (active_idle_*). Present so the
              schema can grow without churn and consumers know the intended
              semantics.

All 'active' numeric features are null-safe: rates that divide by zero duration
are NaN (never Inf), mean sizes with no packets are NaN.
"""
from __future__ import annotations

from typing import Literal

# dtype: one of int / float / bool / str
_SPEC = Literal["int", "float", "bool", "str"]


def _f(name: str, family: str, dtype: _SPEC, desc: str,
       status: str = "active", source: str = "") -> dict:
    return {"name": name, "family": family, "dtype": dtype, "status": status,
            "desc": desc, "source": source}


FEATURES: list[dict] = [
    # ------------------------------------------------------------- meta
    _f("flow_id", "meta", "str", "CIC-style flow identifier (join key)"),
    _f("src_ip", "meta", "str", "source IP (dotted quad)"),
    _f("src_port", "meta", "int", "source port (0/None for ICMP-like rows)"),
    _f("dst_ip", "meta", "str", "destination IP"),
    _f("dst_port", "meta", "int", "destination port"),
    _f("protocol", "meta", "int", "IANA protocol number"),
    _f("proto", "meta", "str", "protocol name (tcp/udp/icmp/...)"),
    _f("timestamp", "meta", "str", "flow start, ISO-8601"),
    _f("label", "meta", "str", "ground truth when known, else null"),
    # ------------------------------------------------------------- basic
    _f("duration_s", "basic", "float", "flow duration in seconds",
       source="duration_us"),
    _f("fwd_pkts", "basic", "int", "packets in first-packet direction"),
    _f("bwd_pkts", "basic", "int", "packets in reply direction"),
    _f("tot_pkts", "basic", "int", "fwd+bwd packets"),
    _f("fwd_bytes", "basic", "int", "bytes in first-packet direction"),
    _f("bwd_bytes", "basic", "int", "bytes in reply direction"),
    _f("tot_bytes", "basic", "int", "fwd+bwd bytes"),
    _f("avg_fwd_pkt_size", "basic", "float", "fwd_bytes / fwd_pkts (NaN if no packets)"),
    _f("avg_bwd_pkt_size", "basic", "float", "bwd_bytes / bwd_pkts (NaN if no packets)"),
    _f("avg_pkt_size", "basic", "float", "tot_bytes / tot_pkts"),
    # ------------------------------------------------------------- rates
    _f("flow_bytes_per_s", "rates", "float", "tot_bytes / duration_s (NaN if 0 duration)"),
    _f("flow_pkts_per_s", "rates", "float", "tot_pkts / duration_s"),
    _f("fwd_bytes_per_s", "rates", "float", "fwd_bytes / duration_s"),
    _f("bwd_bytes_per_s", "rates", "float", "bwd_bytes / duration_s"),
    _f("fwd_pkts_per_s", "rates", "float", "fwd_pkts / duration_s"),
    _f("bwd_pkts_per_s", "rates", "float", "bwd_pkts / duration_s"),
    # ------------------------------------------------------------- ratio
    _f("fwd_byte_ratio", "ratio", "float", "fwd_bytes / tot_bytes (0 when no bytes)"),
    _f("byte_asymmetry", "ratio", "float",
       "(fwd_bytes - bwd_bytes) / tot_bytes in [-1, 1]; 0 when no bytes"),
    _f("pkt_asymmetry", "ratio", "float", "(fwd_pkts - bwd_pkts) / tot_pkts"),
    # ------------------------------------------------------------- protocol
    _f("is_tcp", "protocol", "bool", "protocol == 6"),
    _f("is_udp", "protocol", "bool", "protocol == 17"),
    _f("is_icmp", "protocol", "bool", "protocol == 1"),
    # ------------------------------------------------------------- tcpflags
    _f("fin_flags", "tcpflags", "int", "TCP FIN packets (0 for non-TCP)"),
    _f("syn_flags", "tcpflags", "int", "TCP SYN packets"),
    _f("rst_flags", "tcpflags", "int", "TCP RST packets"),
    _f("psh_flags", "tcpflags", "int", "TCP PSH packets"),
    _f("ack_flags", "tcpflags", "int", "TCP ACK packets"),
    _f("urg_flags", "tcpflags", "int", "TCP URG packets"),
    # ------------------------------------------------------------- dns
    _f("is_dns", "dns", "bool", "either endpoint port is 53 (DNS-shaped flow)"),
    # ------------------------------------------------------------- iat (per-packet timing, microseconds)
    # Pure passthrough of the canonical record's measured/aliased statistics, so
    # a pcap row and a CIC-table row carry the same definition. Null in, NaN out.
    _f("iat_us_mean", "iat", "float", "mean gap between consecutive packets of the flow",
       source="iat_us_mean"),
    _f("iat_us_std", "iat", "float", "sample std (n-1) of those gaps",
       source="iat_us_std"),
    _f("iat_us_max", "iat", "float", "longest inter-packet gap", source="iat_us_max"),
    _f("iat_us_min", "iat", "float", "shortest inter-packet gap (negative in "
       "out-of-order captures, as in CIC's own columns)", source="iat_us_min"),
    _f("fwd_iat_us_total", "iat", "float", "sum of forward-direction gaps "
       "(first to last forward packet)", source="fwd_iat_us_total"),
    _f("fwd_iat_us_mean", "iat", "float", "mean forward-direction gap",
       source="fwd_iat_us_mean"),
    _f("fwd_iat_us_std", "iat", "float", "sample std of forward-direction gaps",
       source="fwd_iat_us_std"),
    _f("fwd_iat_us_max", "iat", "float", "longest forward-direction gap",
       source="fwd_iat_us_max"),
    _f("fwd_iat_us_min", "iat", "float", "shortest forward-direction gap",
       source="fwd_iat_us_min"),
    _f("bwd_iat_us_total", "iat", "float", "sum of reply-direction gaps",
       source="bwd_iat_us_total"),
    _f("bwd_iat_us_mean", "iat", "float", "mean reply-direction gap",
       source="bwd_iat_us_mean"),
    _f("bwd_iat_us_std", "iat", "float", "sample std of reply-direction gaps",
       source="bwd_iat_us_std"),
    _f("bwd_iat_us_max", "iat", "float", "longest reply-direction gap",
       source="bwd_iat_us_max"),
    _f("bwd_iat_us_min", "iat", "float", "shortest reply-direction gap",
       source="bwd_iat_us_min"),
    # ------------------------------------------------------------- pktlen (per-packet size, bytes)
    _f("len_min", "pktlen", "float", "smallest packet in the flow", source="len_min"),
    _f("len_max", "pktlen", "float", "largest packet in the flow", source="len_max"),
    _f("len_mean", "pktlen", "float", "mean packet size in the flow", source="len_mean"),
    _f("len_std", "pktlen", "float", "sample std of packet size in the flow",
       source="len_std"),
    _f("fwd_len_min", "pktlen", "float", "smallest forward packet", source="fwd_len_min"),
    _f("fwd_len_max", "pktlen", "float", "largest forward packet", source="fwd_len_max"),
    _f("fwd_len_mean", "pktlen", "float", "mean forward packet size, the same length "
       "measure as fwd_bytes, so this matches fwd_bytes/fwd_pkts as it does in CIC",
       source="fwd_len_mean"),
    _f("fwd_len_std", "pktlen", "float", "sample std of forward packet size",
       source="fwd_len_std"),
    _f("bwd_len_min", "pktlen", "float", "smallest reply packet", source="bwd_len_min"),
    _f("bwd_len_max", "pktlen", "float", "largest reply packet", source="bwd_len_max"),
    _f("bwd_len_mean", "pktlen", "float", "mean reply packet size", source="bwd_len_mean"),
    _f("bwd_len_std", "pktlen", "float", "sample std of reply packet size",
       source="bwd_len_std"),
    # ------------------------------------------------------------- context (per source ip, batch window)
    _f("src_flow_count", "context", "int", "flows sharing this source IP in the window"),
    _f("src_dst_port_count", "context", "int", "distinct destination ports this source contacted"),
    _f("src_dst_ip_count", "context", "int", "distinct destination IPs this source contacted"),
    _f("src_dst_port_entropy", "context", "float",
       "Shannon entropy of this source's destination-port distribution"),
    _f("src_dns_share", "context", "float", "fraction of this source's flows that are DNS-shaped"),
    # ------------------------------------------------------------- context (per destination ip, batch window)
    _f("dst_flow_count", "context", "int", "flows sharing this destination IP in the window"),
    _f("dst_src_port_count", "context", "int", "distinct source ports seen at this destination"),
    _f("dst_src_ip_count", "context", "int", "distinct source IPs seen at this destination"),
    _f("dst_src_port_entropy", "context", "float",
       "Shannon entropy of this destination's source-port distribution"),
    # ------------------------------------------------------------- future (declared, not yet emitted)
    _f("active_idle_*", "future", "float", "bursty active/idle statistics. CIC ships "
       "Active/Idle Mean/Std/Max/Min, and the burst floor is measurable (the smallest "
       "non-zero Idle value on the pinned 200k slice is 5,000,002 us, so gaps are split "
       "at 5 s, not the 1 s usually quoted). The aggregation itself is NOT reproduced: "
       "a per-direction 'gap > 5 s starts an idle period' rule agrees with CIC's Idle "
       "Mean on only 98.13% of those rows (3,731 rows it counts idle and CIC does not, "
       "9 the other way), so emitting our own version under these names would put two "
       "different measures in one column. Stays future until the split is settled.",
       status="future"),
    _f("dns_domain_length", "future", "float", "query domain name length, needs Zeek dns.log",
       status="future"),
    _f("dns_domain_entropy", "future", "float", "Shannon entropy of the query domain, "
       "needs Zeek dns.log", status="future"),
    _f("dns_nxdomain_rate", "future", "float", "NXDOMAIN response rate, needs Zeek dns.log",
       status="future"),
    _f("tls_ja3", "future", "str", "JA3 client fingerprint hash, needs Zeek ssl.log",
       status="future"),
    _f("tls_ja3s", "future", "str", "JA3S server fingerprint hash, needs Zeek ssl.log",
       status="future"),
]

ACTIVE = [f for f in FEATURES if f["status"] == "active"]
ACTIVE_NAMES: list[str] = [f["name"] for f in ACTIVE]
META_NAMES = [f["name"] for f in FEATURES if f["family"] == "meta"]
FUTURE_NAMES = [f["name"] for f in FEATURES if f["status"] == "future"]


def describe() -> str:
    lines = [f"{len(ACTIVE)} active features + {len(FUTURE_NAMES)} declared-future entries"]
    last = None
    for f in FEATURES:
        if f["family"] != last:
            lines.append(f"\n[{f['family']}]")
            last = f["family"]
        tag = "" if f["status"] == "active" else "  (future)"
        lines.append(f"  {f['name']:<26} {f['dtype']:>5}{tag}  {f['desc']}")
    return "\n".join(lines)
