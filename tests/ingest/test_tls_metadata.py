"""Tests for the metadata-only TLS and QUIC reader."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

from src.ingest import tls_metadata as meta


def _u16(value: int) -> bytes:
    return struct.pack("!H", value)


def _ext(etype: int, data: bytes) -> bytes:
    return _u16(etype) + _u16(len(data)) + data


def _sni(name: str) -> bytes:
    host = name.encode("ascii")
    entry = b"\x00" + _u16(len(host)) + host
    return _u16(len(entry)) + entry


def _alpn(*values: bytes) -> bytes:
    body = b"".join(bytes([len(v)]) + v for v in values)
    return _u16(len(body)) + body


def _client_body() -> bytes:
    ciphers = [0x002F, 0x0035, 0x009C, 0x009D, 0x1301, 0x1302, 0x1303,
               0xC013, 0xC014, 0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9]
    sig = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    exts = [
        (0x001B, b"\x02\x00\x01"), (0x0000, _sni("example.com")),
        (0x0033, b"\x00\x00"), (0x0010, _alpn(b"h2")), (0x4469, b""),
        (0x0017, b""), (0x002D, b"\x01\x01"),
        (0x000D, _u16(len(sig) * 2) + b"".join(_u16(s) for s in sig)),
        (0x0005, b"\x00"), (0x0023, b""), (0x0012, b""),
        (0x002B, b"\x02\x03\x04"), (0xFF01, b"\x00"),
        (0x000B, b"\x01\x00"),
        (0x000A, _u16(4) + _u16(0x001D) + _u16(0x0017)), (0x0015, b""),
    ]
    ext_block = b"".join(_ext(t, d) for t, d in exts)
    return (b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + _u16(len(ciphers) * 2)
            + b"".join(_u16(c) for c in ciphers)
            + b"\x01\x00" + _u16(len(ext_block)) + ext_block)


def _server_body() -> bytes:
    exts = [
        (0x002B, b"\x03\x04"),
        (0x0010, _alpn(b"h2")),
        (0x0033, b"\x00\x1D\x00\x20" + b"x" * 32),
    ]
    ext_block = b"".join(_ext(t, d) for t, d in exts)
    return (b"\x03\x03" + b"\x11" * 32 + b"\x00"
            + _u16(0x1301) + b"\x00" + _u16(len(ext_block)) + ext_block)


def _record(htype: int, body: bytes) -> bytes:
    handshake = bytes([htype]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _packet(src: str, dst: str, sport: int, dport: int, seq: int,
            payload: bytes, ts: float):
    pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
           / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq,
                                        flags="PA") / Raw(load=payload))
    pkt.time = ts
    return pkt


def _quic_varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return struct.pack("!H", value | 0x4000)
    raise ValueError("test varint too large")


def _quic_initial(version: int = 1, packet_bits: int = 0,
                  dcid: bytes = b"\x01" * 8, scid: bytes = b"\x02" * 8) -> bytes:
    first = 0x80 | 0x40 | (packet_bits << 4)
    header = (bytes([first]) + version.to_bytes(4, "big")
              + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid)
    token = b"\x00" * 4
    header += _quic_varint(len(token)) + token + _quic_varint(20)
    return header + b"\x00" * 20


def _write_pcap(path: Path, packets) -> Path:
    wrpcap(str(path), packets)
    return path


def test_client_hello_matches_foxio_ja4_vector():
    hello = meta.parse_client_hello(_client_body())
    assert hello["ja4"] == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert hello["sni"] == "example.com"
    assert hello["version_name"] == "1.3"
    assert hello["alpn_text"] == "h2"
    assert len(hello["ja3"]) == 32


def test_server_hello_hashes_extension_wire_order():
    hello = meta.parse_server_hello(_server_body())
    expected = hashlib.sha256(b"002b,0010,0033").hexdigest()[:12]
    assert hello["ja4s"] == f"t1303h2_1301_{expected}"
    assert hello["ja3s"] == hashlib.md5(b"771,4865,43-16-51").hexdigest()
    assert hello["version_name"] == "1.3"


def test_ja4_signatures_hash_without_other_extensions():
    def ext(eid, data):
        return eid.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data

    exts = (ext(0x0000, b"\x00\x00")  # empty SNI is not a server name
            + ext(0x0010, b"\x00\x03\x02h2")
            + ext(0x000D, b"\x00\x02\x04\x03"))
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01"
            + b"\x01\x00" + len(exts).to_bytes(2, "big") + exts)
    hello = meta.parse_client_hello(body)
    assert hello["ja4"].startswith("t12i")
    assert hello["ja4"].split("_")[2] == hashlib.sha256(b"000d_0403").hexdigest()[:12]


def test_draft_version_does_not_hide_final_tls13():
    # A real TLS 1.3 ClientHello can offer draft 28 (0x7f1c) alongside 0x0304.
    assert meta._version_tag(0x0303, [0x7F1C, 0x0304, 0x0303]) == "13"
    assert meta._version_tag(0x0303, [0x7F1C]) == "12"


def test_server_hello_without_extensions_uses_empty_hash():
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\xc0\x30" + b"\x00"
    hello = meta.parse_server_hello(body)
    assert hello["ja4s"] == "t120000_c030_000000000000"
    assert hello["alpn"] == []


def test_pcap_reassembles_out_of_order_tls_segments(tmp_path):
    client = _record(1, _client_body())
    server = _record(2, _server_body())
    split = 100
    first = _packet("10.0.0.5", "93.1.2.3", 40000, 443, 1000,
                    client[:split], 1_700_000_000.0)
    second = _packet("10.0.0.5", "93.1.2.3", 40000, 443, 1000 + split,
                     client[split:], 1_700_000_001.0)
    reply = _packet("93.1.2.3", "10.0.0.5", 443, 40000, 5000,
                    server, 1_700_000_002.0)
    path = _write_pcap(tmp_path / "tls.pcap", [second, first, reply])

    records = list(meta.iter_tls_sessions(path))
    assert len(records) == 1
    row = records[0]
    assert row["src_ip"] == "10.0.0.5" and row["dst_ip"] == "93.1.2.3"
    assert row["sni"] == "example.com"
    assert row["ja4"] == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert row["ja4s"].startswith("t1303h2_1301_")
    assert row["tls_version"] == "1.3" and row["server_cipher"] == 4865


def test_pcap_client_only_still_emits_ja4(tmp_path):
    packet = _packet("10.0.0.6", "93.1.2.4", 40001, 443, 1,
                     _record(1, _client_body()), 1_700_000_010.0)
    path = _write_pcap(tmp_path / "client.pcap", [packet])
    row = next(iter(meta.iter_tls_sessions(path)))
    assert row["ja4"].startswith("t13d1516h2_")
    assert row["ja4s"] is None and row["ja3s"] is None


def test_malformed_client_hello_is_skipped(tmp_path):
    body = bytearray(_client_body())
    body[35:37] = b"\xff\xff"  # cipher-suite length past the end of the body
    packet = _packet("10.0.0.10", "93.1.2.8", 40003, 443, 1,
                     _record(1, bytes(body)), 1_700_000_015.0)
    path = _write_pcap(tmp_path / "bad.pcap", [packet])
    assert list(meta.iter_tls_sessions(path)) == []


def test_quic_initial_and_short_header_metadata(tmp_path):
    initial = _quic_initial()
    short = b"\x40" + b"\x00" * 19
    first = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
             / IP(src="10.0.0.7", dst="93.1.2.5") / UDP(sport=50000, dport=443)
             / Raw(load=initial))
    first.time = 1_700_000_020.0
    second = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
              / IP(src="10.0.0.7", dst="93.1.2.5") / UDP(sport=50000, dport=443)
              / Raw(load=short))
    second.time = 1_700_000_020.1
    path = _write_pcap(tmp_path / "quic.pcap", [first, second])

    rows = list(meta.iter_quic_sessions(path))
    assert len(rows) == 1
    row = rows[0]
    assert row["quic_version"] == "v1"
    assert row["quic_version_number"] == 1
    assert row["quic_packet_types"] == {"1-RTT": 1, "Initial": 1}
    assert row["dcid"] == "01" * 8 and row["scid"] == "02" * 8
    assert row["packets"] == 2 and row["long_header_packets"] == 1
    assert row["packet_sizes"] == [len(initial), len(short)]
    assert "ja4" not in row


def test_quic_v2_type_mapping(tmp_path):
    # QUIC v2 swaps the Initial and Retry type bits: 01 is an Initial.
    initial = _quic_initial(version=0x6B3343CF, packet_bits=1)
    packet = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
              / IP(src="10.0.0.8", dst="93.1.2.6") / UDP(sport=50001, dport=443)
              / Raw(load=initial))
    packet.time = 1_700_000_030.0
    path = _write_pcap(tmp_path / "quic2.pcap", [packet])
    row = next(iter(meta.iter_quic_sessions(path)))
    assert row["quic_version"] == "v2"
    assert row["quic_packet_types"] == {"Initial": 1}


def test_cli_writes_tls_and_quic_outputs(tmp_path, capsys):
    client = _packet("10.0.0.9", "93.1.2.7", 40002, 443, 1,
                     _record(1, _client_body()), 1_700_000_040.0)
    initial = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
               / IP(src="10.0.0.9", dst="93.1.2.7") / UDP(sport=50002, dport=443)
               / Raw(load=_quic_initial()))
    initial.time = 1_700_000_041.0
    path = _write_pcap(tmp_path / "both.pcap", [client, initial])
    tls_out = tmp_path / "tls.ndjson"
    quic_out = tmp_path / "quic.ndjson"

    assert meta.main(["--pcap", str(path), "--tls-out", str(tls_out),
                      "--quic-out", str(quic_out)]) == 0
    tls_rows = [json.loads(line) for line in tls_out.read_text().splitlines()]
    quic_rows = [json.loads(line) for line in quic_out.read_text().splitlines()]
    assert len(tls_rows) == 1 and tls_rows[0]["ja4"].startswith("t13d")
    assert len(quic_rows) == 1 and quic_rows[0]["transport"] == "quic"
    assert "tls_sessions=1 quic_flows=1" in capsys.readouterr().err


def test_cli_requires_an_output():
    with pytest.raises(SystemExit):
        meta.main(["--pcap", "capture.pcap"])
