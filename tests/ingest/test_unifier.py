"""Ingest-layer tests: schema normalization, table + pcap + export readers, unify CLI."""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from src.ingest.flow_reader import (
    detect_format,
    stream_argus,
    stream_goflow2,
    stream_nfdump,
)
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

# --------------------------------------------------------------------------- #
# flow exports (Argus CSV, nfdump CSV, goflow2 JSON)
# --------------------------------------------------------------------------- #

ARGUS_HEADER = ("StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,"
                "sTos,dTos,TotPkts,TotBytes,SrcBytes,Label")


def test_flow_export_timestamp_fraction_and_protocol_names():
    iso, epoch = to_timestamp("2011/08/10 09:46:53.047277")
    assert iso == "2011-08-10T09:46:53"
    assert epoch == pytest.approx(1312969613.047277)
    iso2, _ = to_timestamp("2011-08-10 09:46:53.047")
    assert iso2 == "2011-08-10T09:46:53"
    assert to_protocol("tcp") == 6
    assert to_protocol("UDP") == 17
    assert to_protocol("icmpv6") == 58
    assert to_protocol("ICMP6") == 58
    assert to_protocol("0x11") == 17
    assert to_protocol("junk") is None


def test_argus_reader_ctu_dialect(tmp_path):
    p = tmp_path / "ctu.binetflow"
    p.write_text(
        ARGUS_HEADER + "\n"
        + "2011/08/10 09:46:53.047277,3550.182373,udp,212.50.71.179,39678,"
        + "  <->,147.32.84.229,13363,CON,0,0,12,875,413,"
        + "flow=Background-UDP-Established\n"
        + "2011/08/10 09:46:53.049895,0.000326,tcp,217.163.21.35,80,"
        + "  <?>,147.32.86.194,2063,FA_A,0,0,2,120,60,flow=Background\n"
        + "2011/08/10 09:46:54.000,0.1,tcp,,,  <->,,,,0,0,0,0,\n",
        encoding="utf-8",
    )
    assert list(stream_argus(p, limit=0)) == []
    stats: dict = {}
    recs = list(stream_argus(p, stats=stats))
    assert stats == {"rows": 3, "skipped": 1}, stats
    assert len(recs) == 2
    first = recs[0]
    assert first["src_ip"] == "212.50.71.179"
    assert first["dst_ip"] == "147.32.84.229"
    assert first["src_port"] == 39678 and first["dst_port"] == 13363
    assert first["protocol"] == 17 and first["proto"] == "udp"
    assert first["timestamp"] == "2011-08-10T09:46:53"
    assert first["ts_epoch"] == pytest.approx(1312969613.047277)
    assert first["duration_us"] == 3_550_182_373
    # Argus publishes no directional packet split; bytes do split.
    assert (first["fwd_pkts"], first["bwd_pkts"]) == (12, 0)
    assert (first["fwd_bytes"], first["bwd_bytes"]) == (413, 462)
    assert first["label"] == "flow=Background-UDP-Established"
    assert first["syn_flags"] is None and first["iat_us_mean"] is None
    assert set(first) == set(FLOW_FIELDS)
    assert detect_format(p) == "argus"


def test_argus_reader_uses_published_directional_split(tmp_path):
    p = tmp_path / "argus.csv"
    p.write_text(
        "StartTime,FlId,Seq,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,"
        "SrcPkts,DstPkts,SrcBytes,DstBytes,TotPkts,TotBytes,Label\n"
        "2011/08/10 09:46:53.047277,1,0,3.55,tcp,10.0.0.1,50000,->,"
        "10.0.0.2,80,CON,4,6,400,600,10,1000,flow=Background\n",
        encoding="utf-8",
    )
    rec = next(stream_argus(p))
    assert (rec["fwd_pkts"], rec["bwd_pkts"]) == (4, 6)
    assert (rec["fwd_bytes"], rec["bwd_bytes"]) == (400, 600)
    assert rec["duration_us"] == 3_550_000


def test_nfdump_reader_header_and_headerless(tmp_path):
    row = ("2011-08-10 09:46:53.047,2011-08-10 09:46:56.597,3.550,udp,"
           "10.0.0.1,10.0.0.2,50000,53,0,12,875,72,...S...")
    header = "ts,te,td,pr,sa,da,sp,dp,op,packets,bytes,pkt_size,flg"
    headered = tmp_path / "headered.csv"
    headered.write_text(header + "\n" + row, encoding="utf-8")
    bare = tmp_path / "bare.csv"
    bare.write_text(row + "\n", encoding="utf-8")

    for path in (headered, bare):
        rec = next(stream_nfdump(path))
        assert rec["src_ip"] == "10.0.0.1" and rec["dst_ip"] == "10.0.0.2"
        assert rec["protocol"] == 17 and rec["proto"] == "udp"
        assert rec["timestamp"] == "2011-08-10T09:46:53"
        assert rec["duration_us"] == 3_550_000
        assert (rec["fwd_pkts"], rec["bwd_pkts"]) == (12, 0)
        assert (rec["fwd_bytes"], rec["bwd_bytes"]) == (875, 0)
        assert rec["syn_flags"] is None
        assert detect_format(path) == "nfdump"


def test_nfdump_reader_derives_start_from_end(tmp_path):
    p = tmp_path / "end.csv"
    p.write_text(
        "te,td,pr,sa,da,sp,dp,packets,bytes\n"
        "2011-08-10 09:46:56.597,3.550,tcp,10.0.0.1,10.0.0.2,1,2,1,60\n",
        encoding="utf-8",
    )
    rec = next(stream_nfdump(p))
    assert rec["timestamp"] == "2011-08-10T09:46:53"
    assert rec["ts_epoch"] == pytest.approx(1312969613.047)


def test_goflow2_reader_ndjson_and_array(tmp_path):
    good = (
        '{"time_flow_start_ns":1312969613047000000,'
        '"time_flow_end_ns":1312969616597000000,"bytes":875,"packets":12,'
        '"src_addr":"10.0.0.1","dst_addr":"10.0.0.2","src_port":50000,'
        '"dst_port":53,"proto":"UDP"}'
    )
    received = (
        '{"time_received_ns":1312969617000000000,"bytes":"120","packets":"2",'
        '"src_addr":"10.0.0.3","dst_addr":"10.0.0.4","src_port":"1234",'
        '"dst_port":"443","proto":6}'
    )
    p = tmp_path / "flows.jsonl"
    p.write_text(good + "\n" + received + "\n{bad\n" + '{"bytes":1}',
                 encoding="utf-8")
    stats: dict = {}
    recs = list(stream_goflow2(p, stats=stats))
    assert stats == {"rows": 4, "skipped": 2}, stats
    assert len(recs) == 2
    first = recs[0]
    assert first["proto"] == "udp" and first["protocol"] == 17
    assert first["duration_us"] == 3_550_000
    assert first["timestamp"] == "2011-08-10T09:46:53"
    assert (first["fwd_pkts"], first["fwd_bytes"]) == (12, 875)
    second = recs[1]
    assert second["duration_us"] is None
    assert second["timestamp"] == "2011-08-10T09:46:57"
    assert detect_format(p) == "goflow2"

    arr = tmp_path / "flows.json"
    arr.write_text("[" + good + "," + received + ",7]", encoding="utf-8")
    stats = {}
    assert len(list(stream_goflow2(arr, stats=stats))) == 2
    assert stats == {"rows": 3, "skipped": 1}, stats


def test_csv_detection_disambiguates_table_argus_and_nfdump(tmp_path, official_csv):
    assert detect_format(official_csv) == "table"
    assert detect_format(tmp_path / "x.binetflow") == "argus"
    argus = tmp_path / "argus.csv"
    argus.write_text(ARGUS_HEADER + "\n", encoding="utf-8")
    assert detect_format(argus) == "argus"
    nfdump = tmp_path / "nfdump.csv"
    nfdump.write_text("ts,te,td,pr,sa,da,sp,dp\n", encoding="utf-8")
    assert detect_format(nfdump) == "nfdump"
    cic = tmp_path / "cic.csv"
    cic.write_text("Start Time,Source IP,Destination IP,Source Port,Destination Port\n",
                   encoding="utf-8")
    assert detect_format(cic) == "table"
    meta = tmp_path / "meta.json"
    meta.write_text('{"files": 3}', encoding="utf-8")
    assert detect_format(meta) is None


def test_unify_cli_directory_mixes_flow_exports(tmp_path):
    (tmp_path / "a.csv").write_text(
        ARGUS_HEADER + "\n"
        "2011/08/10 09:46:53.047277,3.55,tcp,10.0.0.1,1,->,10.0.0.2,2,"
        "CON,0,0,3,180,120,flow=Background\n",
        encoding="utf-8",
    )
    (tmp_path / "b.csv").write_text(
        "ts,te,td,pr,sa,da,sp,dp,op,packets,bytes,pkt_size,flg\n"
        "2011-08-10 09:46:53.047,2011-08-10 09:46:56.597,3.550,udp,"
        "10.0.0.3,10.0.0.4,50000,53,0,12,875,72,...S...\n",
        encoding="utf-8",
    )
    (tmp_path / "c.jsonl").write_text(
        '{"time_received_ns":1312969617000000000,"bytes":120,"packets":2,'
        '"src_addr":"10.0.0.5","dst_addr":"10.0.0.6","src_port":1234,'
        '"dst_port":443,"proto":"TCP"}\n',
        encoding="utf-8",
    )
    (tmp_path / "meta.json").write_text('{"files": 3}', encoding="utf-8")
    out = tmp_path / "flows.ndjson"
    assert unify_main(["--input", str(tmp_path), "--out", str(out)]) == 0
    recs = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(recs) == 3
    assert {r["src_ip"] for r in recs} == {"10.0.0.1", "10.0.0.3", "10.0.0.5"}
    assert all(set(r) == set(FLOW_FIELDS) for r in recs)


def test_unify_cli_flow_limit_and_forced_format(tmp_path):
    p = tmp_path / "flows.jsonl"
    p.write_text(
        '{"time_received_ns":1312969617000000000,"bytes":120,"packets":2,'
        '"src_addr":"10.0.0.5","dst_addr":"10.0.0.6","src_port":1234,'
        '"dst_port":443,"proto":"TCP"}\n' * 2,
        encoding="utf-8",
    )
    out = tmp_path / "one.ndjson"
    assert unify_main(["--input", str(p), "--out", str(out),
                       "--format", "goflow2", "--limit", "1"]) == 0
    assert len(out.read_text(encoding="utf-8").splitlines()) == 1
