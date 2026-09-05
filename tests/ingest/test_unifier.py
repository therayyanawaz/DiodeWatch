"""Ingest-layer tests: schema normalization, table + pcap readers, unify CLI."""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from src.ingest.pcap_reader import stream_flows
from src.ingest.schema import (
    COLUMN_ALIASES,
    FLOW_FIELDS,
    normalize_column,
    proto_name,
    synth_flow_id,
    to_int,
    to_ip,
    to_protocol,
    to_timestamp,
)
from src.ingest.table_reader import stream_records
from src.ingest.unify import main as unify_main

# --------------------------------------------------------------------------- #
# schema unit tests
# --------------------------------------------------------------------------- #

def test_normalize_column():
    assert normalize_column(" Destination Port") == "destinationport"
    assert normalize_column("Total  Fwd   Packets") == "totalfwdpackets"
    assert normalize_column("Flow ID") == "flowid"
    assert normalize_column("") == ""


def test_aliases_resolve_to_canonical_fields():
    assert COLUMN_ALIASES["destinationport"] == "dst_port"
    assert COLUMN_ALIASES["sourceip"] == "src_ip"
    assert COLUMN_ALIASES["totalfwdpacket"] == "fwd_pkts"      # plural variant
    assert COLUMN_ALIASES["totalfwdpackets"] == "fwd_pkts"
    assert COLUMN_ALIASES["label"] == "label"


def test_ip_normalization_handles_decimal_form():
    assert to_ip("3232238089") == "192.168.10.9"
    assert to_ip("3232235785") == "192.168.1.9"
    assert to_ip("192.168.10.14") == "192.168.10.14"
    assert to_ip(" 203.0.113.5 ") == "203.0.113.5"
    assert to_ip(None) is None
    assert to_ip("not-an-ip") is None


def test_timestamp_parsing():
    iso, epoch = to_timestamp("7/7/2017 9:20:00 AM")
    assert iso == "2017-07-07T09:20:00"
    assert abs(epoch - 1499419200.0) < 1e-6
    assert to_timestamp("") == (None, None)
    import datetime as dt
    iso2, _ = to_timestamp(dt.datetime(2017, 7, 5, 11, 42, tzinfo=dt.timezone.utc))
    assert iso2 == "2017-07-05T11:42:00"


def test_numeric_coercion():
    assert to_int("6.0") == 6
    assert to_int(38308) == 38308
    assert to_int(float("nan")) is None
    assert to_int(float("inf")) is None
    assert to_int("junk") is None
    assert to_protocol(6) == 6
    assert to_protocol(None) is None
    assert proto_name(6) == "tcp"
    assert proto_name(17) == "udp"
    assert proto_name(1) == "icmp"
    assert proto_name(99) is None


def test_flow_id_synthesis_matches_cic_style():
    fid = synth_flow_id("192.168.10.14", 49459, "209.48.71.168", 80, 6)
    assert fid == "192.168.10.14-209.48.71.168-49459-80-6"
    assert set(FLOW_FIELDS) >= {
        "flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
        "proto", "timestamp", "ts_epoch", "duration_us", "fwd_pkts",
        "bwd_pkts", "fwd_bytes", "bwd_bytes", "label",
    }


# --------------------------------------------------------------------------- #
# table reader (CICFlowMeter-style CSV dialects)
# --------------------------------------------------------------------------- #

OFFICIAL_HEADER = [
    "Flow ID", " Source IP", " Source Port", " Destination IP",
    " Destination Port", " Protocol", " Timestamp", " Flow Duration",
    " Total Fwd Packets", " Total Backward Packets",
    " Total Length of Fwd Packets", " Total Length of Bwd Packets",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", " Label",
]
OFFICIAL_ROWS = [
    ["192.168.10.14-209.48.71.168-49459-80-6", "192.168.10.14", "49459",
     "209.48.71.168", "80", "6", "5/7/2017 9:20:00 AM", "38308",
     "10", "12", "1500", "1800", "1", "2", "0", "3", "20", "0", "BENIGN"],
    ["192.168.10.14-209.48.71.168-49460-80-6", "192.168.10.14", "49460",
     "209.48.71.168", "80", "6", "5/7/2017 9:20:01 AM", "500000",
     "200", "0", "30000", "0", "0", "200", "0", "200", "200", "0", "DoS Hulk"],
]


@pytest.fixture()
def official_csv(tmp_path: Path) -> Path:
    p = tmp_path / "flows.csv"
    lines = [",".join(OFFICIAL_HEADER)] + [",".join(r) for r in OFFICIAL_ROWS]
    p.write_text("\n".join(lines), encoding="utf-8")
    return p


def test_table_reader_official_dialect(official_csv):
    recs = list(stream_records(official_csv))
    assert len(recs) == 2
    first = recs[0]
    assert first["flow_id"] == "192.168.10.14-209.48.71.168-49459-80-6"
    assert first["src_ip"] == "192.168.10.14"
    assert first["dst_ip"] == "209.48.71.168"
    assert first["src_port"] == 49459
    assert first["dst_port"] == 80
    assert first["protocol"] == 6
    assert first["proto"] == "tcp"
    assert first["timestamp"] == "2017-07-05T09:20:00"
    assert first["duration_us"] == 38308
    assert first["fwd_pkts"] == 10
    assert first["bwd_pkts"] == 12
    assert first["fwd_bytes"] == 1500
    assert first["bwd_bytes"] == 1800
    assert first["syn_flags"] == 2
    assert first["rst_flags"] == 0
    assert first["label"] == "BENIGN"
    assert recs[1]["label"] == "DoS Hulk"
    assert set(recs[0].keys()) == set(FLOW_FIELDS)
    assert len(recs[1]["timestamp"]) > 0


def test_table_reader_passes_timing_columns_through(tmp_path, official_csv):
    """CIC publishes the per-packet timing/size columns itself.

    They arrive unchanged, including the source's own sentinels (a negative
    Flow IAT Min from an out-of-order capture is real data, not junk), and a
    dialect that omits them still yields the whole record with those null.
    """
    header = OFFICIAL_HEADER + ["Flow IAT Mean", "Flow IAT Std", "Flow IAT Min",
                                "Fwd IAT Total", "Fwd Packet Length Mean",
                                "Packet Length Std"]
    row = [*OFFICIAL_ROWS[0], "3830.8", "1.5", "-13", "76616", "150", "0.7"]
    p = tmp_path / "timing.csv"
    p.write_text("\n".join([",".join(header), ",".join(row)]), encoding="utf-8")

    rec = next(stream_records(p))
    assert rec["iat_us_mean"] == 3830.8
    assert rec["iat_us_std"] == 1.5
    assert rec["iat_us_min"] == -13.0
    assert rec["fwd_iat_us_total"] == 76616.0
    assert rec["fwd_len_mean"] == 150.0
    assert rec["len_std"] == 0.7
    assert rec["bwd_len_std"] is None          # this dialect does not publish it
    assert list(rec.keys()) == list(FLOW_FIELDS)

    plain = next(stream_records(official_csv))  # OFFICIAL_HEADER has no timing cols
    assert plain["iat_us_mean"] is None and plain["len_std"] is None
    assert list(plain.keys()) == list(FLOW_FIELDS)


def test_table_reader_decimal_ip_variant(tmp_path):
    """Mirrors that store IPs as decimal integers must still yield dotted quads."""
    p = tmp_path / "dec.csv"
    p.write_text(
        "Src IP dec,Src Port,Dst IP dec,Dst Port,Protocol,Timestamp,"
        "Flow Duration,Total Fwd Packets,Total Backward Packets,"
        "Total Length of Fwd Packets,Total Length of Bwd Packets,Label\n"
        "3232238089,13793,885387958,443,6,5/7/2017 9:20:00 AM,187889,"
        "1,1,0,0,BENIGN\n",
        encoding="utf-8",
    )
    rec = next(stream_records(p))
    assert rec["src_ip"] == "192.168.10.9"
    assert rec["dst_ip"] is not None and rec["dst_ip"].count(".") == 3
    assert rec["flow_id"] == "192.168.10.9-{}-13793-443-6".format(rec["dst_ip"])


def test_table_reader_synthesizes_missing_flow_id(tmp_path):
    p = tmp_path / "nofid.csv"
    p.write_text(
        "Source IP,Source Port,Destination IP,Destination Port,Protocol,"
        "Flow Duration,Total Fwd Packets,Total Backward Packets,"
        "Total Length of Fwd Packets,Total Length of Bwd Packets,Label\n"
        "192.0.2.1,12345,198.51.100.2,53,17,100,1,1,64,64,BENIGN\n",
        encoding="utf-8",
    )
    rec = next(stream_records(p))
    assert rec["flow_id"] == "192.0.2.1-198.51.100.2-12345-53-17"
    assert rec["proto"] == "udp"


# --------------------------------------------------------------------------- #
# pcap reader (packet -> flow aggregation)
# --------------------------------------------------------------------------- #

def _pkt(ts: float, ip_src: str, ip_dst: str, sport: int, dport: int,
         proto: str, payload_len: int = 100, flags: str | None = None):
    """Build a single packet with a fixed timestamp."""
    from scapy.all import IP, TCP, UDP, Ether, Raw

    p = Ether() / IP(src=ip_src, dst=ip_dst)
    if proto == "tcp":
        p /= TCP(sport=sport, dport=dport, flags=flags or "A")
        p /= Raw(b"x" * payload_len)
    else:
        p /= UDP(sport=sport, dport=dport)
        p /= Raw(b"x" * payload_len)
    p.time = ts
    return p


@pytest.fixture()
def synthetic_pcap(tmp_path: Path) -> Path:
    """Three flows: an HTTP-ish TCP conversation, a UDP exchange, and a second
    TCP conversation on the *same 5-tuple* starting 30 s later (idle gap)."""
    from scapy.all import wrpcap

    pkts = [
        # flow 1: tcp 10.0.0.1:50000 -> 10.0.0.2:80
        _pkt(1000.0, "10.0.0.1", "10.0.0.2", 50000, 80, "tcp", flags="S", payload_len=0),
        _pkt(1000.1, "10.0.0.1", "10.0.0.2", 50000, 80, "tcp", flags="PA"),
        _pkt(1000.2, "10.0.0.2", "10.0.0.1", 80, 50000, "tcp", flags="A", payload_len=200),
        _pkt(1000.3, "10.0.0.1", "10.0.0.2", 50000, 80, "tcp", flags="R", payload_len=0),
        # flow 2: udp 10.0.0.1:5353 -> 10.0.0.3:53
        _pkt(1001.0, "10.0.0.1", "10.0.0.3", 5353, 53, "udp"),
        _pkt(1001.1, "10.0.0.3", "10.0.0.1", 53, 5353, "udp", payload_len=80),
        # flow 3: same tcp 5-tuple as flow 1, but 30 s later -> new flow
        _pkt(1030.0, "10.0.0.1", "10.0.0.2", 50000, 80, "tcp", flags="S", payload_len=0),
        _pkt(1030.1, "10.0.0.2", "10.0.0.1", 80, 50000, "tcp", flags="A", payload_len=50),
    ]
    p = tmp_path / "flows.pcap"
    wrpcap(str(p), pkts)
    return p


def test_pcap_reader_aggregates_flows(synthetic_pcap):
    stats: dict = {}
    recs = list(stream_flows(synthetic_pcap, flow_timeout=5.0, stats=stats))
    assert stats["pkts"] == 8
    assert stats["skipped"] == 0
    assert len(recs) == 3, [r["flow_id"] for r in recs]

    tcp1, udp, tcp2 = recs  # tcp1 flushed on idle gap at t=1030; udp/tcp2 at EOF
    assert tcp1["proto"] == "tcp" and tcp1["protocol"] == 6
    assert tcp1["src_ip"] == "10.0.0.1" and tcp1["dst_ip"] == "10.0.0.2"
    assert tcp1["src_port"] == 50000 and tcp1["dst_port"] == 80
    assert tcp1["fwd_pkts"] == 3          # SYN, PSH+ACK, RST
    assert tcp1["bwd_pkts"] == 1          # single ACK back
    assert tcp1["syn_flags"] == 1 and tcp1["rst_flags"] == 1
    assert tcp1["ack_flags"] == 2         # the PA ack + the lone bwd ACK
    assert tcp1["fwd_bytes"] > 0 and tcp1["bwd_bytes"] > 0
    assert tcp1["duration_us"] == 300_000
    assert tcp1["ts_epoch"] == 1000.0
    assert tcp1["label"] is None

    assert udp["proto"] == "udp" and udp["protocol"] == 17
    assert udp["src_port"] == 5353 and udp["dst_port"] == 53
    assert udp["fwd_pkts"] == 1 and udp["bwd_pkts"] == 1
    assert udp["syn_flags"] is None or udp["syn_flags"] == 0

    # same 5-tuple, > idle timeout apart -> two records, both TCP, distinct starts
    assert tcp2["proto"] == "tcp"
    assert tcp2["flow_id"] == tcp1["flow_id"]
    assert tcp2["ts_epoch"] == 1030.0
    assert stats["timeouts"] == 1 and stats["at_eof"] == 2


def test_pcap_reader_measures_packet_timing(synthetic_pcap):
    """tcp1 is four packets 100 ms apart: forward .0 -> .1 -> .3, one reply at .2.

    So flow gaps are [100k, 100k, 100k] us and forward gaps [100k, 200k] us.
    """
    recs = list(stream_flows(synthetic_pcap, flow_timeout=5.0))
    tcp1 = recs[0]
    assert tcp1["iat_us_mean"] == pytest.approx(100_000, rel=1e-6)
    assert tcp1["iat_us_std"] == pytest.approx(0.0, abs=1e-3)
    assert tcp1["iat_us_min"] == pytest.approx(100_000, rel=1e-6)
    assert tcp1["iat_us_max"] == pytest.approx(100_000, rel=1e-6)
    assert tcp1["fwd_iat_us_total"] == pytest.approx(300_000, rel=1e-6)
    assert tcp1["fwd_iat_us_mean"] == pytest.approx(150_000, rel=1e-6)
    assert tcp1["fwd_iat_us_min"] == pytest.approx(100_000, rel=1e-6)
    assert tcp1["fwd_iat_us_max"] == pytest.approx(200_000, rel=1e-6)
    # sample std (divided by n-1) of [100_000, 200_000], which is what CIC's own
    # Std columns do; the population formula would give 50_000 instead.
    assert tcp1["fwd_iat_us_std"] == pytest.approx(70_710.678, rel=1e-6)
    # one packet in a direction leaves no population: 0.0, as CIC encodes it
    udp = recs[1]
    assert udp["fwd_pkts"] == 1 and udp["bwd_pkts"] == 1
    assert udp["bwd_iat_us_total"] == 0.0
    assert udp["bwd_iat_us_std"] == 0.0
    assert udp["fwd_iat_us_mean"] == 0.0


def test_pcap_reader_measures_packet_sizes(synthetic_pcap):
    """Sizes use the same byte measure as fwd_bytes/bwd_bytes, so the mean of the
    per-packet sizes must equal bytes/packets, exactly as it does in CIC."""
    import statistics

    recs = list(stream_flows(synthetic_pcap, flow_timeout=5.0))
    tcp1 = recs[0]
    assert tcp1["fwd_pkts"] == 3 and tcp1["bwd_pkts"] == 1
    assert tcp1["len_min"] == 54.0            # bare SYN / RST: eth+ip+tcp, no payload
    assert tcp1["len_max"] == 254.0           # the reply carries a 200-byte payload
    assert tcp1["len_mean"] == pytest.approx(
        (tcp1["fwd_bytes"] + tcp1["bwd_bytes"]) / 4)
    assert tcp1["len_std"] == pytest.approx(
        statistics.stdev([54, 154, 254, 54]), rel=1e-9)
    assert tcp1["fwd_len_mean"] == pytest.approx(tcp1["fwd_bytes"] / tcp1["fwd_pkts"])
    assert tcp1["fwd_len_min"] == 54.0 and tcp1["fwd_len_max"] == 154.0
    assert tcp1["fwd_len_std"] == pytest.approx(statistics.stdev([54, 154, 54]), rel=1e-9)
    assert tcp1["bwd_len_mean"] == 254.0 and tcp1["bwd_len_std"] == 0.0


def test_pcap_records_carry_a_real_timestamp(synthetic_pcap):
    """Table rows have had an ISO timestamp all along; pcap rows used to be null,
    which left every capture-derived alert without a displayable flow time."""
    rec = next(iter(stream_flows(synthetic_pcap, flow_timeout=5.0)))
    assert rec["ts_epoch"] == 1000.0
    assert rec["timestamp"] == "1970-01-01T00:16:40"


# --------------------------------------------------------------------------- #
# unify CLI
# --------------------------------------------------------------------------- #

def test_unify_cli_writes_ndjson(official_csv, tmp_path):
    out = tmp_path / "flows.ndjson"
    rc = unify_main(["--input", str(official_csv), "--out", str(out)])
    assert rc == 0
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[0])
    assert rec["src_ip"] == "192.168.10.14"
    assert rec["label"] == "BENIGN"
    assert "src_ip" in rec and "duration_us" in rec  # sanity: real keys


def test_unify_cli_stdout_and_limit(official_csv):
    buf = io.StringIO()
    import contextlib
    with contextlib.redirect_stdout(buf):
        rc = unify_main(["--input", str(official_csv), "--out", "-", "--limit", "1"])
    assert rc == 0
    assert len(buf.getvalue().strip().splitlines()) == 1


def test_unify_cli_pcap(synthetic_pcap, tmp_path):
    out = tmp_path / "flows.ndjson"
    rc = unify_main(["--input", str(synthetic_pcap), "--out", str(out),
                     "--flow-timeout", "5"])
    assert rc == 0
    recs = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines()]
    assert len(recs) == 3
    assert all(r["src_ip"] for r in recs)


def test_unify_cli_rejects_unknown_format(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("hello", encoding="utf-8")
    with pytest.raises(SystemExit):
        unify_main(["--input", str(p), "--out", str(tmp_path / "o.ndjson")])
