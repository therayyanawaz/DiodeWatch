"""Extract metadata-only fingerprints from a packet capture.

The reader touches only fields the protocols expose in the clear:

* TLS handshake records. ClientHello and ServerHello are plaintext by design,
  so JA3, JA3S, JA4 and JA4S can be computed without keys or payload access.
* QUIC long headers. Version, connection IDs, packet type, packet sizes and
  arrival gaps are unprotected. QUIC Initial payloads are encrypted and are
  deliberately not decrypted here.

No application data, TLS application records, or QUIC Initial payloads are
read. The output is JSON-lines shaped for the TLS detector and for direct
inspection of QUIC header metadata.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .pcap_reader import iter_packets
from .schema import iso_from_epoch

TLS_HANDSHAKE = 22
TLS_CLIENT_HELLO = 1
TLS_SERVER_HELLO = 2
MAX_STREAM_BYTES = 65536
MAX_PENDING_SEGMENTS = 8
MAX_STORED_SIZES = 32
QUIC_PORT = 443
TLS_PORTS = {443, 465, 993, 995, 8443}
ZERO_HASH = "000000000000"

# RFC 8446 section 4.1.3: a HelloRetryRequest is a ServerHello with this random.
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

_VERSION_TAG = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
    0x0300: "s3", 0x0002: "s2",
    0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3",
}
_VERSION_NAME = {
    "13": "1.3", "12": "1.2", "11": "1.1", "10": "1.0",
    "s3": "SSL 3.0", "s2": "SSL 2.0", "d1": "DTLS 1.0",
    "d2": "DTLS 1.2", "d3": "DTLS 1.3", "00": "unknown",
}

_QUIC_V1 = 0x00000001
_QUIC_V2 = 0x6B3343CF
_QUIC_V1_TYPES = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
_QUIC_V2_TYPES = {0: "Retry", 1: "Initial", 2: "0-RTT", 3: "Handshake"}


# --------------------------------------------------------------------- bytes
def _u16(data: bytes, off: int) -> int:
    if off + 2 > len(data):
        raise ValueError("truncated 16-bit field")
    return int.from_bytes(data[off:off + 2], "big")


def _u24(data: bytes, off: int) -> int:
    if off + 3 > len(data):
        raise ValueError("truncated 24-bit field")
    return int.from_bytes(data[off:off + 3], "big")


def _extension_data(exts: list[tuple[int, bytes]], etype: int) -> bytes | None:
    for eid, data in exts:
        if eid == etype:
            return data
    return None


def _parse_extensions(data: bytes, off: int) -> list[tuple[int, bytes]]:
    total = _u16(data, off)
    off += 2
    end = off + total
    if end > len(data):
        raise ValueError("truncated extension block")
    exts: list[tuple[int, bytes]] = []
    while off < end:
        if off + 4 > end:
            raise ValueError("truncated extension header")
        eid = _u16(data, off)
        elen = _u16(data, off + 2)
        off += 4
        if off + elen > end:
            raise ValueError("truncated extension body")
        exts.append((eid, data[off:off + elen]))
        off += elen
    return exts


def _parse_sni(data: bytes | None) -> str | None:
    if not data:
        return None
    off = 0
    total = _u16(data, off)
    off += 2
    end = min(off + total, len(data))
    while off + 3 <= end:
        name_type = data[off]
        name_len = _u16(data, off + 1)
        off += 3
        if off + name_len > end:
            return None
        if name_type == 0:
            return data[off:off + name_len].decode("ascii", "replace") or None
        off += name_len
    return None


def _parse_alpn(data: bytes | None) -> list[bytes]:
    if not data:
        return []
    off = 0
    total = _u16(data, off)
    off += 2
    end = min(off + total, len(data))
    out: list[bytes] = []
    while off < end:
        alen = data[off]
        off += 1
        if off + alen > end:
            break
        out.append(data[off:off + alen])
        off += alen
    return out


def _parse_client_versions(data: bytes | None) -> list[int]:
    if not data:
        return []
    count = data[0]
    end = min(1 + count, len(data))
    return [_u16(data, off) for off in range(1, end - 1, 2)]


def _parse_server_version(data: bytes | None) -> list[int]:
    return [_u16(data, 0)] if data and len(data) >= 2 else []


def _parse_signature_algorithms(data: bytes | None) -> list[int]:
    if not data:
        return []
    total = _u16(data, 0)
    end = min(2 + total, len(data))
    return [_u16(data, off) for off in range(2, end - 1, 2)]


def _parse_groups(data: bytes | None) -> list[int]:
    if not data:
        return []
    total = _u16(data, 0)
    end = min(2 + total, len(data))
    return [_u16(data, off) for off in range(2, end - 1, 2)]


def _parse_point_formats(data: bytes | None) -> list[int]:
    if not data:
        return []
    count = data[0]
    return list(data[1:1 + count])


def _is_grease(value: int) -> bool:
    return ((value & 0x0F0F) == 0x0A0A
            and (value >> 8) == (value & 0xFF))


def _sha12(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:12]


def _version_tag(legacy: int, supported: list[int]) -> str:
    # Draft and private codepoints have no JA4 tag. Take the highest codepoint
    # the table knows, so a trailing draft offer cannot hide a final version.
    for code in sorted((v for v in supported if not _is_grease(v)), reverse=True):
        if code in _VERSION_TAG:
            return _VERSION_TAG[code]
    return _VERSION_TAG.get(legacy, "00")


def _alpn_tag(protocols: list[bytes]) -> str:
    if not protocols or not protocols[0]:
        return "00"
    value = protocols[0]
    first, last = value[0], value[-1]
    is_alnum = ((48 <= first <= 57) or (65 <= first <= 90) or (97 <= first <= 122))
    is_alnum = is_alnum and ((48 <= last <= 57) or (65 <= last <= 90)
                             or (97 <= last <= 122))
    if is_alnum:
        return chr(first) + chr(last)
    text = value.hex()
    return text[0] + text[-1]


def _ja3(legacy: int, ciphers: list[int],
         exts: list[tuple[int, bytes]], groups: list[int],
         point_formats: list[int]) -> str:
    raw = ",".join([
        str(legacy),
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e, _ in exts),
        "-".join(str(g) for g in groups),
        "-".join(str(p) for p in point_formats),
    ])
    return hashlib.md5(raw.encode("ascii")).hexdigest()


def _ja3s(legacy: int, cipher: int, exts: list[tuple[int, bytes]]) -> str:
    raw = f"{legacy},{cipher}," + "-".join(str(e) for e, _ in exts)
    return hashlib.md5(raw.encode("ascii")).hexdigest()


def _ja4(legacy: int, ciphers: list[int], exts: list[tuple[int, bytes]],
         supported: list[int], sig_algs: list[int],
         alpn: list[bytes]) -> str:
    ciphers = [c for c in ciphers if not _is_grease(c)]
    ext_types = [e for e, _ in exts if not _is_grease(e)]
    version = _version_tag(legacy, supported)
    sni = "d" if _parse_sni(_extension_data(exts, 0x0000)) else "i"
    if ciphers:
        cipher_hash = _sha12(",".join(f"{c:04x}" for c in sorted(ciphers)))
    else:
        cipher_hash = ZERO_HASH
    hashed_exts = sorted(e for e in ext_types if e not in (0x0000, 0x0010))
    signatures = [s for s in sig_algs if not _is_grease(s)]
    ext_text = ",".join(f"{e:04x}" for e in hashed_exts)
    if signatures:
        ext_text += "_" + ",".join(f"{s:04x}" for s in signatures)
    ext_hash = _sha12(ext_text) if ext_text else ZERO_HASH
    return (f"t{version}{sni}{min(len(ciphers), 99):02d}"
            f"{min(len(ext_types), 99):02d}{_alpn_tag(alpn)}_"
            f"{cipher_hash}_{ext_hash}")


def _ja4s(legacy: int, cipher: int, exts: list[tuple[int, bytes]],
          supported: list[int], alpn: list[bytes]) -> str:
    ext_types = [e for e, _ in exts if not _is_grease(e)]
    version = _version_tag(legacy, supported)
    ext_text = ",".join(f"{e:04x}" for e in ext_types)
    ext_hash = _sha12(ext_text) if ext_text else ZERO_HASH
    return (f"t{version}{min(len(ext_types), 99):02d}{_alpn_tag(alpn)}_"
            f"{cipher:04x}_{ext_hash}")


def parse_client_hello(body: bytes) -> dict:
    """Parse a ClientHello body (without the 4-byte handshake header)."""
    if len(body) < 35:
        raise ValueError("truncated ClientHello")
    legacy = _u16(body, 0)
    off = 34
    sid_len = body[off]
    off += 1
    if off + sid_len > len(body):
        raise ValueError("truncated session id")
    off += sid_len
    cipher_len = _u16(body, off)
    off += 2
    if cipher_len % 2 or off + cipher_len > len(body):
        raise ValueError("malformed cipher suite list")
    ciphers = [_u16(body, p) for p in range(off, off + cipher_len, 2)]
    off += cipher_len
    if off >= len(body):
        raise ValueError("missing compression methods")
    comp_len = body[off]
    off += 1
    if off + comp_len > len(body):
        raise ValueError("truncated compression methods")
    off += comp_len
    exts = _parse_extensions(body, off) if off < len(body) else []
    supported = _parse_client_versions(_extension_data(exts, 0x002B))
    sig_algs = _parse_signature_algorithms(_extension_data(exts, 0x000D))
    groups = _parse_groups(_extension_data(exts, 0x000A))
    point_formats = _parse_point_formats(_extension_data(exts, 0x000B))
    alpn = _parse_alpn(_extension_data(exts, 0x0010))
    version = _version_tag(legacy, supported)
    return {
        "legacy_version": legacy,
        "cipher_suites": ciphers,
        "extensions": exts,
        "supported_versions": supported,
        "signature_algorithms": sig_algs,
        "groups": groups,
        "point_formats": point_formats,
        "sni": _parse_sni(_extension_data(exts, 0x0000)),
        "alpn": alpn,
        "ja3": _ja3(legacy, ciphers, exts, groups, point_formats),
        "ja4": _ja4(legacy, ciphers, exts, supported, sig_algs, alpn),
        "version_tag": version,
        "version_name": _VERSION_NAME.get(version, "unknown"),
        "alpn_text": alpn[0].decode("ascii", "replace") if alpn and alpn[0] else None,
    }


def parse_server_hello(body: bytes) -> dict:
    """Parse a ServerHello body (without the 4-byte handshake header)."""
    if len(body) < 38:
        raise ValueError("truncated ServerHello")
    legacy = _u16(body, 0)
    random = body[2:34]
    off = 34
    sid_len = body[off]
    off += 1 + sid_len
    cipher = _u16(body, off)
    off += 2
    if off >= len(body):
        raise ValueError("missing compression method")
    off += 1  # legacy_compression_method
    exts = _parse_extensions(body, off) if off < len(body) else []
    supported = _parse_server_version(_extension_data(exts, 0x002B))
    alpn = _parse_alpn(_extension_data(exts, 0x0010))
    version = _version_tag(legacy, supported)
    return {
        "legacy_version": legacy,
        "cipher": cipher,
        "extensions": exts,
        "supported_versions": supported,
        "alpn": alpn,
        "ja3s": _ja3s(legacy, cipher, exts),
        "ja4s": _ja4s(legacy, cipher, exts, supported, alpn),
        "version_tag": version,
        "version_name": _VERSION_NAME.get(version, "unknown"),
        "alpn_text": alpn[0].decode("ascii", "replace") if alpn and alpn[0] else None,
        "is_hrr": random == HRR_RANDOM,
    }


# ---------------------------------------------------------------------- tcp
def _conn_key(src_ip: str, src_port: int, dst_ip: str,
              dst_port: int) -> tuple:
    a, b = (src_ip, src_port), (dst_ip, dst_port)
    return (a, b) if a <= b else (b, a)


@dataclass
class _Dir:
    started: bool = False
    dead: bool = False
    next_seq: int = 0
    buf: bytearray = field(default_factory=bytearray)
    hs: bytearray = field(default_factory=bytearray)
    pending: dict[int, bytes] = field(default_factory=dict)

    def feed(self, seq: int, payload: bytes, on_handshake, ctx: dict) -> None:
        if self.dead:
            return
        if not self.started:
            if payload[:2] != b"\x16\x03":
                self.pending[seq] = payload
                self._trim()
                return
            self.started = True
            self.next_seq = seq
        if seq > self.next_seq:
            self.pending[seq] = payload
            self._trim()
            return
        if seq < self.next_seq:
            skip = self.next_seq - seq
            if skip >= len(payload):
                return
            payload = payload[skip:]
        self.buf.extend(payload)
        self.next_seq += len(payload)
        self._merge_pending()
        self._drain(on_handshake, ctx)
        if len(self.buf) > MAX_STREAM_BYTES:
            self.dead = True

    def _trim(self) -> None:
        while len(self.pending) > MAX_PENDING_SEGMENTS:
            self.pending.pop(next(iter(self.pending)))

    def _merge_pending(self) -> None:
        while True:
            match = None
            for seq, payload in self.pending.items():
                if seq <= self.next_seq < seq + len(payload):
                    match = (seq, payload)
                    break
            if match is None:
                return
            seq, payload = match
            self.pending.pop(seq, None)
            skip = self.next_seq - seq
            self.buf.extend(payload[skip:])
            self.next_seq += len(payload) - skip

    def _drain(self, on_handshake, ctx: dict) -> None:
        while len(self.buf) >= 5:
            ctype = self.buf[0]
            if self.buf[1] != 3 or ctype not in (20, 21, 22, 23):
                self.dead = True
                return
            length = _u16(self.buf, 3)
            if len(self.buf) < 5 + length:
                return
            record = bytes(self.buf[5:5 + length])
            del self.buf[:5 + length]
            if ctype == TLS_HANDSHAKE:
                self.hs.extend(record)
                self._drain_handshakes(on_handshake, ctx)
                if len(self.hs) > MAX_STREAM_BYTES:
                    self.dead = True
                    return
        self._drain_handshakes(on_handshake, ctx)

    def _drain_handshakes(self, on_handshake, ctx: dict) -> None:
        while len(self.hs) >= 4:
            length = _u24(self.hs, 1)
            if len(self.hs) < 4 + length:
                return
            htype = self.hs[0]
            body = bytes(self.hs[4:4 + length])
            del self.hs[:4 + length]
            if htype in (TLS_CLIENT_HELLO, TLS_SERVER_HELLO):
                on_handshake(htype, body, ctx)


@dataclass
class _TlsSession:
    key: tuple
    client: dict | None = None
    server: dict | None = None
    client_ip: str | None = None
    client_port: int | None = None
    server_ip: str | None = None
    server_port: int | None = None
    first_ts: float = 0.0
    client_ts: float = 0.0


# ---------------------------------------------------------------------- quic
def _varint(data: bytes, off: int) -> tuple[int | None, int]:
    if off >= len(data):
        return None, off
    width = 1 << (data[off] >> 6)
    if off + width > len(data):
        return None, off
    value = int.from_bytes(data[off:off + width], "big")
    value &= (1 << (width * 8 - 2)) - 1
    return value, off + width


def _quic_version_name(version: int) -> str:
    if version == 0:
        return "negotiation"
    if version == _QUIC_V1:
        return "v1"
    if version == _QUIC_V2:
        return "v2"
    if 0xFF000000 <= version <= 0xFF0000FF:
        return f"draft-{version & 0xFF}"
    return f"0x{version:08x}"


def _parse_quic_long(data: bytes) -> dict | None:
    if len(data) < 7 or not data[0] & 0x80:
        return None
    version = int.from_bytes(data[1:5], "big")
    off = 5
    dcil = data[off]
    off += 1
    if dcil > 20 or off + dcil > len(data):
        return None
    dcid = data[off:off + dcil]
    off += dcil
    scil = data[off]
    off += 1
    if scil > 20 or off + scil > len(data):
        return None
    scid = data[off:off + scil]
    off += scil
    bits = (data[0] & 0x30) >> 4
    if version == 0:
        packet_type = "Version Negotiation"
    elif version == _QUIC_V1:
        packet_type = _QUIC_V1_TYPES.get(bits, f"long-{bits}")
    elif version == _QUIC_V2:
        packet_type = _QUIC_V2_TYPES.get(bits, f"long-{bits}")
    else:
        packet_type = f"long-{bits}"
    header = {
        "version": version,
        "version_name": _quic_version_name(version),
        "packet_type": packet_type,
        "dcid": dcid.hex(),
        "scid": scid.hex(),
    }
    if packet_type == "Initial":
        token_len, off = _varint(data, off)
        if token_len is None or off + token_len > len(data):
            return header
        off += token_len
    if packet_type in ("Initial", "0-RTT", "Handshake"):
        length, _ = _varint(data, off)
        header["length"] = length
    return header


@dataclass
class _QuicFlow:
    key: tuple
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    first_ts: float
    last_ts: float
    packets: int = 0
    bytes: int = 0
    long_packets: int = 0
    short_packets: int = 0
    versions: Counter = field(default_factory=Counter)
    types: Counter = field(default_factory=Counter)
    sizes: list[int] = field(default_factory=list)
    iats: list[int] = field(default_factory=list)
    dcid: str | None = None
    scid: str | None = None
    first_version: int | None = None

    def observe(self, ts: float, size: int, header: dict | None = None) -> None:
        if self.packets and ts >= self.last_ts:
            self.iats.append(round((ts - self.last_ts) * 1_000_000))
        self.last_ts = max(self.last_ts, ts)
        self.packets += 1
        self.bytes += size
        if len(self.sizes) < MAX_STORED_SIZES:
            self.sizes.append(size)
        if header is None:
            self.short_packets += 1
            self.types["1-RTT"] += 1
            return
        self.long_packets += 1
        self.types[header["packet_type"]] += 1
        self.versions[header["version"]] += 1
        if self.dcid is None:
            self.dcid = header["dcid"] or None
            self.scid = header["scid"] or None
            self.first_version = header["version"]

    def record(self) -> dict:
        size_mean = self.bytes / self.packets if self.packets else 0.0
        iat_mean = sum(self.iats) / len(self.iats) if self.iats else 0.0
        version = self.first_version if self.first_version is not None else 0
        return {
            "ts": self.first_ts,
            "timestamp": iso_from_epoch(self.first_ts),
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "transport": "quic",
            "quic_version": _quic_version_name(version),
            "quic_version_number": version,
            "quic_versions": {f"0x{v:08x}": n
                              for v, n in sorted(self.versions.items())},
            "quic_packet_types": dict(sorted(self.types.items())),
            "dcid": self.dcid,
            "scid": self.scid,
            "packets": self.packets,
            "bytes": self.bytes,
            "long_header_packets": self.long_packets,
            "short_header_packets": self.short_packets,
            "duration_us": round((self.last_ts - self.first_ts) * 1_000_000),
            "packet_size_min": min(self.sizes) if self.sizes else 0,
            "packet_size_max": max(self.sizes) if self.sizes else 0,
            "packet_size_mean": round(size_mean, 3),
            "iat_mean_us": round(iat_mean, 3),
            "iat_max_us": max(self.iats) if self.iats else 0,
            "packet_sizes": list(self.sizes),
            "iat_us": list(self.iats[:MAX_STORED_SIZES]),
        }


# -------------------------------------------------------------------- reader
class _Extractor:
    def __init__(self) -> None:
        self.streams: dict[tuple, _Dir] = {}
        self.sessions: dict[tuple, _TlsSession] = {}
        self.completed: list[dict] = []
        self.quic: dict[tuple, _QuicFlow] = {}

    def feed(self, pkt) -> None:
        try:
            ip = pkt.getlayer("IP") or pkt.getlayer("IPv6")
            if ip is None:
                return
            ts = float(pkt.time)
            src_ip, dst_ip = str(ip.src), str(ip.dst)
            tcp = pkt.getlayer("TCP")
            udp = pkt.getlayer("UDP")
            if tcp is not None:
                self._feed_tcp(ts, src_ip, dst_ip, int(tcp.sport),
                               int(tcp.dport), int(tcp.flags),
                               int(tcp.seq), bytes(tcp.payload))
            elif udp is not None:
                self._feed_udp(ts, src_ip, dst_ip, int(udp.sport),
                               int(udp.dport), bytes(udp.payload))
        except (AttributeError, TypeError, ValueError):
            return

    def _feed_tcp(self, ts: float, src_ip: str, dst_ip: str, sport: int,
                  dport: int, flags: int, seq: int, payload: bytes) -> None:
        key = _conn_key(src_ip, sport, dst_ip, dport)
        if flags & 0x02 and not flags & 0x10:
            self.sessions.pop(key, None)
            self.streams.pop((src_ip, sport, dst_ip, dport), None)
            self.streams.pop((dst_ip, dport, src_ip, sport), None)
        if not payload:
            return
        dkey = (src_ip, sport, dst_ip, dport)
        stream = self.streams.get(dkey)
        if stream is None:
            # Keep a short pre-buffer only on plausible TLS ports, so an
            # out-of-order first segment can still be reassembled. Any port
            # whose first observed payload starts with a TLS record is also
            # accepted.
            if (payload[:2] != b"\x16\x03"
                    and sport not in TLS_PORTS and dport not in TLS_PORTS):
                return
            stream = self.streams[dkey] = _Dir()
        ctx = {"src_ip": src_ip, "src_port": sport, "dst_ip": dst_ip,
               "dst_port": dport, "ts": ts, "key": key, "dkey": dkey}
        stream.feed(seq, payload, self._on_handshake, ctx)

    def _feed_udp(self, ts: float, src_ip: str, dst_ip: str, sport: int,
                  dport: int, payload: bytes) -> None:
        if QUIC_PORT not in (sport, dport) or not payload:
            return
        key = _conn_key(src_ip, sport, dst_ip, dport)
        header = _parse_quic_long(payload) if payload[0] & 0x80 else None
        if header is None and payload[0] & 0x80:
            return
        flow = self.quic.get(key)
        if flow is None:
            if header is None:
                return
            flow = self.quic[key] = _QuicFlow(
                key=key, src_ip=src_ip, src_port=sport,
                dst_ip=dst_ip, dst_port=dport,
                first_ts=ts, last_ts=ts,
            )
        flow.observe(ts, len(payload), header)

    def _on_handshake(self, htype: int, body: bytes, ctx: dict) -> None:
        try:
            hello = (parse_client_hello(body) if htype == TLS_CLIENT_HELLO
                     else parse_server_hello(body))
        except (ValueError, IndexError):
            return
        if htype == TLS_SERVER_HELLO and hello.get("is_hrr"):
            return
        key = ctx["key"]
        sess = self.sessions.get(key)
        if sess is None:
            sess = self.sessions[key] = _TlsSession(key=key, first_ts=ctx["ts"])
        if htype == TLS_CLIENT_HELLO:
            if sess.client is not None:
                return
            sess.client = hello
            sess.client_ip, sess.client_port = ctx["src_ip"], ctx["src_port"]
            sess.server_ip, sess.server_port = ctx["dst_ip"], ctx["dst_port"]
            sess.client_ts = ctx["ts"]
        else:
            if sess.server is not None:
                return
            sess.server = hello
            sess.server_ip, sess.server_port = ctx["src_ip"], ctx["src_port"]
        if sess.client is not None and sess.server is not None:
            self.completed.append(_session_record(sess))
            self.sessions.pop(key, None)

    def tls_records(self) -> list[dict]:
        for sess in sorted(self.sessions.values(), key=lambda s: s.first_ts):
            if sess.client is not None:
                self.completed.append(_session_record(sess))
        self.sessions.clear()
        return self.completed

    def quic_records(self) -> list[dict]:
        return [f.record() for f in sorted(self.quic.values(),
                                           key=lambda x: x.first_ts)]


def _session_record(sess: _TlsSession) -> dict:
    client = sess.client or {}
    server = sess.server or {}
    return {
        "ts": sess.client_ts,
        "timestamp": iso_from_epoch(sess.client_ts),
        "src_ip": sess.client_ip,
        "src_port": sess.client_port,
        "dst_ip": sess.server_ip,
        "dst_port": sess.server_port,
        "sni": client.get("sni"),
        "alpn": client.get("alpn_text"),
        "ja3": client.get("ja3"),
        "ja3s": server.get("ja3s"),
        "ja4": client.get("ja4"),
        "ja4s": server.get("ja4s"),
        "tls_version": client.get("version_name"),
        "server_tls_version": server.get("version_name"),
        "server_cipher": server.get("cipher"),
    }


def scan_capture(path: str | Path) -> tuple[list[dict], list[dict]]:
    """Read one capture and return TLS sessions and QUIC flow summaries."""
    extractor = _Extractor()
    for pkt in iter_packets(Path(path)):
        extractor.feed(pkt)
    return extractor.tls_records(), extractor.quic_records()


def iter_tls_sessions(path: str | Path) -> Iterator[dict]:
    yield from scan_capture(path)[0]


def iter_quic_sessions(path: str | Path) -> Iterator[dict]:
    yield from scan_capture(path)[1]


def _write_jsonl(path: str, records: list[dict]) -> None:
    if path == "-":
        for record in records:
            print(json.dumps(record, separators=(",", ":"), ensure_ascii=False))
        return
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, separators=(",", ":"),
                                    ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract TLS JA3/JA3S/JA4/JA4S and QUIC header metadata "
                    "from a pcap without decrypting payloads.")
    parser.add_argument("--pcap", required=True, help=".pcap or .pcapng file")
    parser.add_argument("--tls-out", help="TLS session JSON-lines, or - for stdout")
    parser.add_argument("--quic-out", help="QUIC flow JSON-lines, or - for stdout")
    args = parser.parse_args(argv)
    if not args.tls_out and not args.quic_out:
        parser.error("give --tls-out, --quic-out, or both")
    if args.tls_out == "-" and args.quic_out == "-":
        parser.error("only one output can be stdout")
    tls_records, quic_records = scan_capture(args.pcap)
    if args.tls_out:
        _write_jsonl(args.tls_out, tls_records)
    if args.quic_out:
        _write_jsonl(args.quic_out, quic_records)
    print(f"tls_sessions={len(tls_records)} quic_flows={len(quic_records)}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
