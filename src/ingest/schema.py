"""Canonical flow-record schema shared by every ingest source.

All readers (CICFlowMeter-style tables, pcap aggregation) emit records with
exactly these keys, so downstream consumers (features, detectors, alerts, UI)
never see source-specific naming.

Canonical record shape (JSON object, one per flow):

    flow_id      str   "192.168.10.14-209.48.71.168-49459-80-6" (CIC style; synthesized when absent)
    src_ip       str   dotted-quad IPv4 (or raw IPv6 string)          | null
    src_port     int                                                 | null (e.g. ICMP)
    dst_ip       str                                                 | null
    dst_port     int                                                 | null
    protocol     int   IANA protocol number (6 = TCP, 17 = UDP)       | null
    proto        str   lowercase name ("tcp"/"udp"/...)               | null if unknown
    timestamp    str   ISO-8601 "2017-07-05T11:42:00"                 | null if unparseable
    ts_epoch     float seconds since epoch (naive, source clock)      | null
    duration_us  int   flow duration in microseconds                  | null
    fwd_pkts     int   packets travelling in the first-packet direction
    bwd_pkts     int
    fwd_bytes    int   payload/wire bytes, same directions
    bwd_bytes    int
    fin_flags    int   TCP flag-packet counts (null for non-TCP)
    syn_flags    int
    rst_flags    int
    psh_flags    int
    ack_flags    int
    urg_flags    int
    label        str   "BENIGN" / "DoS Hulk" / ...                     | null when unknown

Per-packet timing and size, collapsed to one row per flow. CIC tables carry
these columns already (they are aliased straight through); the pcap reader
computes the same statistics from the packets it streams. Units follow the
CIC convention: inter-arrival times in microseconds, lengths in bytes.

    iat_us_*     float  inter-arrival between consecutive packets of the whole
                        flow: mean/std/max/min
    fwd/bwd_iat_us_*
               float  the same over one direction only, plus `total` (first to
                        last packet of that direction)
    len_*        float  packet length over the whole flow: min/max/mean/std
    fwd/bwd_len_*
               float  the same over one direction only

Encoding rules, held identical across both sources:
  * std is the SAMPLE deviation (divided by n-1). CIC's own columns are sample
    std: on the pinned 200k slice, 3-packet flows (two deltas, so the spread
    fixes both formulas) match sample in 96.05% of rows and population in
    14.64%.
  * a statistic with no population to speak of (0 packets in a direction, or
    fewer than two members for std) is 0.0, which is how CIC encodes it too.
  * nothing here is ever Inf; an unparseable cell is null.
"""
from __future__ import annotations

import ipaddress
import math
import re
from datetime import datetime, timezone

CORE_FIELDS: tuple[str, ...] = (
    "flow_id",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "proto",
    "timestamp",
    "ts_epoch",
    "duration_us",
    "fwd_pkts",
    "bwd_pkts",
    "fwd_bytes",
    "bwd_bytes",
    "fin_flags",
    "syn_flags",
    "rst_flags",
    "psh_flags",
    "ack_flags",
    "urg_flags",
    "label",
)

# Per-packet timing (microseconds) and size (bytes), collapsed per flow and per
# direction. Both readers emit all of them: the table source aliases CIC's own
# columns, the pcap source measures them from the packets it streams.
STAT_FIELDS: tuple[str, ...] = (
    "iat_us_mean", "iat_us_std", "iat_us_max", "iat_us_min",
    "fwd_iat_us_total", "fwd_iat_us_mean", "fwd_iat_us_std",
    "fwd_iat_us_max", "fwd_iat_us_min",
    "bwd_iat_us_total", "bwd_iat_us_mean", "bwd_iat_us_std",
    "bwd_iat_us_max", "bwd_iat_us_min",
    "len_min", "len_max", "len_mean", "len_std",
    "fwd_len_min", "fwd_len_max", "fwd_len_mean", "fwd_len_std",
    "bwd_len_min", "bwd_len_max", "bwd_len_mean", "bwd_len_std",
)

FLOW_FIELDS: tuple[str, ...] = CORE_FIELDS + STAT_FIELDS

# --------------------------------------------------------------------------- #
# Column-name normalization: CICFlowMeter CSVs exist in many dialects
# (" Destination Port", "Total Fwd Packets" vs "Total Fwd Packet", decimal IPs,
# renamed variants). We normalize a raw header cell to lowercase alnum and look
# it up in COLUMN_ALIASES; unmatched columns are simply ignored.
# --------------------------------------------------------------------------- #
_ALNUM = re.compile(r"[^a-z0-9]")


def normalize_column(name: str) -> str:
    """Normalize a raw header cell for alias lookup (" Destination Port" -> "destinationport")."""
    return _ALNUM.sub("", name.strip().lower())


COLUMN_ALIASES: dict[str, str] = {}


def _alias(canonical: str, *raw_names: str) -> None:
    for raw in raw_names:
        COLUMN_ALIASES[normalize_column(raw)] = canonical


_alias("flow_id", "Flow ID", "flow id", "flowid")
_alias("src_ip", "Source IP", "Src IP", "Source IP dec", "Src IP dec", "src")
_alias("dst_ip", "Destination IP", "Dst IP", "Destination IP dec", "Dst IP dec", "dst")
_alias("src_port", "Source Port", "Src Port")
_alias("dst_port", "Destination Port", "Dst Port")
_alias("protocol", "Protocol", "proto")
_alias("timestamp", "Timestamp", "Start Time")
_alias("duration_us", "Flow Duration", "Flow duration")
_alias("fwd_pkts", "Total Fwd Packets", "Total Fwd Packet", "Tot Fwd Pkts")
_alias("bwd_pkts", "Total Backward Packets", "Total Backward Packet",
       "Total Bwd Packets", "Total Bwd Packet", "Tot Bwd Pkts")
_alias("fwd_bytes", "Total Length of Fwd Packets", "Total Length of Fwd Packet",
       "TotLen Fwd Packets")
_alias("bwd_bytes", "Total Length of Bwd Packets", "Total Length of Bwd Packet",
       "TotLen Bwd Packets", "Total Length of Backward Packets")
_alias("fin_flags", "FIN Flag Count")
_alias("syn_flags", "SYN Flag Count")
_alias("rst_flags", "RST Flag Count")
_alias("psh_flags", "PSH Flag Count")
_alias("ack_flags", "ACK Flag Count")
_alias("urg_flags", "URG Flag Count")
_alias("label", "Label", "Attack Type", "class")

# Per-packet timing and size, as CICFlowMeter exports them. Names are matched
# after normalization, so the leading-space dialects of the official CSVs work.
_alias("iat_us_mean", "Flow IAT Mean")
_alias("iat_us_std", "Flow IAT Std")
_alias("iat_us_max", "Flow IAT Max")
_alias("iat_us_min", "Flow IAT Min")
_alias("fwd_iat_us_total", "Fwd IAT Total")
_alias("fwd_iat_us_mean", "Fwd IAT Mean")
_alias("fwd_iat_us_std", "Fwd IAT Std")
_alias("fwd_iat_us_max", "Fwd IAT Max")
_alias("fwd_iat_us_min", "Fwd IAT Min")
_alias("bwd_iat_us_total", "Bwd IAT Total")
_alias("bwd_iat_us_mean", "Bwd IAT Mean")
_alias("bwd_iat_us_std", "Bwd IAT Std")
_alias("bwd_iat_us_max", "Bwd IAT Max")
_alias("bwd_iat_us_min", "Bwd IAT Min")
_alias("len_min", "Min Packet Length")
_alias("len_max", "Max Packet Length")
_alias("len_mean", "Packet Length Mean")
_alias("len_std", "Packet Length Std")
_alias("fwd_len_min", "Fwd Packet Length Min")
_alias("fwd_len_max", "Fwd Packet Length Max")
_alias("fwd_len_mean", "Fwd Packet Length Mean")
_alias("fwd_len_std", "Fwd Packet Length Std")
_alias("bwd_len_min", "Bwd Packet Length Min")
_alias("bwd_len_max", "Bwd Packet Length Max")
_alias("bwd_len_mean", "Bwd Packet Length Mean")
_alias("bwd_len_std", "Bwd Packet Length Std")

PROTO_NAMES: dict[int, str] = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "ipv6-icmp",
    132: "sctp",
}

_ISO_FORMAT = "%Y-%m-%dT%H:%M:%S"

_TS_FORMATS = (
    "%d/%m/%Y %I:%M:%S %p",   # CIC-IDS2017 official ("7/7/2017 9:20:00 AM")
    "%m/%d/%Y %I:%M:%S %p",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
)


def empty(v) -> bool:
    """True for None / pandas-NA / NaN / blank strings."""
    if v is None:
        return True
    try:
        if isinstance(v, float) and math.isnan(v):
            return True
    except TypeError:
        pass
    s = str(v).strip()
    return s == "" or s.lower() in {"nan", "nat", "na", "null", "none", "inf", "-inf"}


def to_int(v) -> int | None:
    """Best-effort integer coercion; null on blanks, NaN, infinities, junk."""
    if empty(v):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(f):
        return None
    return int(f)


def to_float(v) -> float | None:
    """Float coercion for the timing/size statistics; null on blanks, NaN and
    infinities. Sentinels the source really published (-1, a negative IAT from
    out-of-order capture timestamps) are passed through unchanged."""
    if empty(v):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def to_protocol(v) -> int | None:
    """IANA protocol number as an int (parquet/CSV store it as 6.0 / 6 / '6')."""
    p = to_int(v)
    return None if p is None else p


def proto_name(proto: int | None) -> str | None:
    return None if proto is None else PROTO_NAMES.get(proto)


def to_ip(v) -> str | None:
    """Normalize an IP cell to dotted-quad (or raw IPv6 string). Accepts dotted
    strings and the decimal-integer form some mirrors use ("Source IP dec")."""
    if empty(v):
        return None
    s = str(v).strip()
    if not s:
        return None
    if ":" in s:  # IPv6
        return s
    if "." not in s:  # decimal form: 3232238089 -> 192.168.1.9
        try:
            return str(ipaddress.IPv4Address(int(float(s))))
        except (ValueError, TypeError):
            return None
    try:
        return str(ipaddress.IPv4Address(s))
    except ValueError:
        return None


def to_timestamp(v) -> tuple[str | None, float | None]:
    """Return (iso-8601 string, epoch seconds). Accepts pandas Timestamps,
    datetimes and common CIC string formats; null for everything else."""
    if empty(v):
        return None, None
    dt: datetime | None = None
    if isinstance(v, datetime):
        dt = v
    elif hasattr(v, "to_pydatetime"):  # pandas.Timestamp
        try:
            dt = v.to_pydatetime()
        except (ValueError, TypeError):
            dt = None
    else:
        s = str(v).strip()
        for fmt in _TS_FORMATS:
            try:
                # The formats carry no zone; we assume the source clock and tag
                # UTC immediately so ordering/epochs stay consistent.
                dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
    if dt is None:
        return None, None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    iso = dt.astimezone(timezone.utc).strftime(_ISO_FORMAT)
    return iso, dt.timestamp()


def iso_from_epoch(ts) -> str | None:
    """Epoch seconds -> the canonical ISO-8601 string, same shape as
    to_timestamp produces, so pcap-derived and table-derived records carry the
    same timestamp format. Null for anything that is not a finite number."""
    try:
        f = float(ts)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(f):
        return None
    dt = datetime.fromtimestamp(f, tz=timezone.utc)
    return dt.strftime(_ISO_FORMAT)


def to_label(v) -> str | None:
    if empty(v):
        return None
    s = str(v).strip()
    return s if s else None


def synth_flow_id(src_ip, src_port, dst_ip, dst_port, protocol) -> str:
    """CIC-style flow id; falls back to the parts that are known."""
    parts = [str(x) if x is not None else "*" for x in
             (src_ip, dst_ip, src_port, dst_port, protocol)]
    return "-".join(parts)
