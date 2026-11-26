#!/usr/bin/env python3
"""Generate a synthetic demo pcap for the judge walkthrough.

One self-contained capture (~1.5 min of traffic) with a realistic benign
background and two mixed battlespace windows: a volumetric DDoS flood
under a simultaneous port sweep, then a slow-rate DoS under a
simultaneous bulk-exfiltration burst, the exact shapes the rule layer
is calibrated to fire on, overlapping the way real incidents do. The
dashboard's Live tab replays it and shows paired signatures alerting in
the same windows.

    python scripts/generators/make_demo_pcap.py                 # data/pcaps/demo_threats.pcap
    python scripts/generators/make_demo_pcap.py --out other.pcap --seed 7

Scapy builds the packets; ground truth is printed as a scenario schedule so
the demo narration can point at the timeline.
"""
from __future__ import annotations

import argparse
import random
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

REPO = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO / "data" / "pcaps" / "demo_threats.pcap"

BASE_TS = 1_700_000_000.0          # fixed epoch for determinism

# Seeded realistic background: jittered multi-packet downloads, mixed
# ports/sizes, DNS underlay. Stays under every rule gate (per-dst ~0.5/s,
# per-src <= 3 flows/ports per window, download-heavy, short-lived) and
# never touches victim subnets, attack aggregates keep their shape,
# only interleaved with background like a real capture.
BG_SERVERS = ([f"93.184.0.{10 + i}" for i in range(4)]
              + [f"93.184.1.{20 + i}" for i in range(4)])
BG_CLIENTS = [f"10.0.{(i // 250) % 5}.{11 + i * 7 % 200}" for i in range(12)]
BG_NAMES = ["www.example.com", "cdn.assets.example.org", "mail.google.com",
            "updates.microsoft.com", "api.dropbox.com", "login.example.net",
            "video.cdn.example.com", "docs.example.org", "shop.example.com",
            "news.example.net", "static.cdn.example.net", "app.example.io",
            "auth.example.com", "files.example.org", "img.cdn.example.com",
            "portal.example.net", "api.example.com", "cdn2.example.org",
            "webmail.example.com", "status.example.io"]


def _tcp_pkt(src_ip: str, sport: int, dst_ip: str, dport: int, ts: float,
             *, payload: bytes = b"", flags: str = "PA", seq: int = 1):
    pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
           / IP(src=src_ip, dst=dst_ip)
           / TCP(sport=sport, dport=dport, flags=flags, seq=seq)
           / Raw(payload))
    pkt.time = ts
    return pkt


def _udp_dns_pkt(client: str, sport: int, name: str, ts: float):
    pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
           / IP(src=client, dst="10.40.0.53")
           / UDP(sport=sport, dport=53)
           / DNS(rd=1, qd=DNSQR(qname=name)))
    pkt.time = ts
    return pkt


def _bg_exchange(rng: random.Random, seq: int, ts: float) -> list:
    """One realistic web download: jittered multi-packet response + DNS."""
    client = BG_CLIENTS[rng.randrange(len(BG_CLIENTS))]
    srv = rng.choice(BG_SERVERS)
    dport = 443 if rng.random() < 0.7 else 80
    sport = 40000 + (seq % 20000)
    pkts: list = []
    t = ts
    if rng.random() < 0.25:
        pkts.append(_udp_dns_pkt(client, 50000 + (seq % 10000),
                                 rng.choice(BG_NAMES), t))
        t += 0.03
    n_req = rng.randint(1, 2)
    for q in range(n_req):
        pkts.append(_tcp_pkt(client, sport, srv, dport, t + q * 0.01,
                             payload=b"GET /r HTTP/1.1\r\n" + b"h" * rng.randint(0, 900)))
    t += 0.02 + rng.random() * 0.05
    n_resp = rng.randint(1, 6)
    for s in range(n_resp):
        pkts.append(_tcp_pkt(srv, dport, client, sport,
                            t + s * (0.005 + rng.random() * 0.015),
                            payload=b"HTTP/1.1 200 OK\r\n" + b"x" * rng.randint(200, 1350)))
    if rng.random() < 0.1:
        pkts.append(_tcp_pkt(client, sport, srv, dport,
                             t + n_resp * 0.02 + 0.05, flags="R"))
    return pkts


def bg_traffic(seed: int, t_start: float, duration_s: float,
               rate_per_s: float = 2.5, seq_start: int = 0) -> tuple[list, int]:
    """Seeded benign background over [t_start, t_start+duration_s)."""
    rng = random.Random(seed)
    pkts: list = []
    t, seq = t_start, seq_start
    end = t_start + duration_s
    while t < end:
        pkts.extend(_bg_exchange(rng, seq, t))
        seq += 1
        t += rng.expovariate(rate_per_s)
    return pkts, seq


def ddos_flood(i: int, ts: float):
    """Volumetric flood: many hosts, tiny SYN flows, one target."""
    src = f"10.1.{(i // 250) % 4}.{i % 250}"
    return _tcp_pkt(src, 20000 + i, "10.9.9.9", 80, ts,
                    payload=b"\x00" * 100, flags="S")


def slowdos_packets(t_start: float) -> list:
    """Slow-rate DoS: 40 long-held conversations, tiny dribbled requests.

    The rule needs, per (10 s window, dst): flows >= 30, fwd/bwd pkt ratio
    >= 2, mean fwd packet 10-160 B, and >= 5 flows still open past the window
    (duration > 10 s). 40 conversations open at t_start and receive a
    header-only dribble every 0.3 s for 13.2 s; the server answers every
    second dribble with a small reply (ratio 2:1, starvation shape).
    """
    pkts: list = []
    n_convs, n_calls = 40, 44
    for i in range(n_calls):
        ts = t_start + i * 0.3
        for c in range(n_convs):
            pkts.append(_tcp_pkt("10.3.0.7", 41000 + c, "10.7.7.7", 80,
                                 ts + c * 0.004,
                                 payload=b"GET /slow HTTP/1.1\r\n", flags="PA"))
            if i % 2 == 0:  # starved server: replies to every other request
                pkts.append(_tcp_pkt("10.7.7.7", 80, "10.3.0.7", 41000 + c,
                                     ts + c * 0.004 + 0.01,
                                     payload=b"HTTP/1.1 100 C\r\n\r\n",
                                     flags="PA"))
    return pkts


def scan_probe(i: int, ts: float):
    """Recon sweep: one source, many ports, unanswered SYN probes."""
    return _tcp_pkt("10.5.0.7", 35000 + i, f"10.60.0.{i % 3}",
                    1000 + i, ts, flags="S")


def exfil_burst(i: int, ts: float):
    """Bulk upload: one host pushing megabytes outward in one window."""
    # 24 x 200 kB segments x 40 flows = ~192 MB total... too big; keep it at
    # 40 flows x 24 packets x 60 kB = ~57 MB? No, the rule needs >= 5 MB in
    # ONE 10 s window per source; 40 flows x 8 x 60 kB = 19.2 MB is plenty.
    pkts = []
    for seg in range(8):
        pkts.append(_tcp_pkt("10.20.0.9", 46000 + i, "93.184.200.9", 443,
                             ts + seg * 0.02, payload=b"\xff" * 60_000,
                             flags="PA"))
    return pkts


def build_packets() -> list:
    """Mixed battlespace: threats overlap the way real captures look.

    0-40 s : realistic background only (quiet windows)
    50-62 s: volumetric DDoS (10.9.9.9) UNDER simultaneous port sweep
             (10.5.0.7 reconning under cover of the flood, window [50,60)
             fires ddos + scan together)
    80-93 s: slow-rate DoS (10.7.7.7, held dribbles) UNDER simultaneous
             bulk exfiltration (10.20.0.9, 86-88 s, window [80,90)
             fires slowdos + exfil together)
    Attacks target different entities, so per-entity window aggregates
    keep their exact firing shapes; only the timeline gets honest -
    two threats landing in the same window, like a real incident.
    """
    pkts: list = []
    t = BASE_TS

    # ---- 0-40 s: realistic benign background only --------------------------
    bg, seq = bg_traffic(201, t, 40.0, rate_per_s=2.5)
    pkts.extend(bg)
    t += 50

    # ---- 50-62 s: DDoS flood + concurrent recon sweep ----------------------
    for i in range(1200):
        pkts.append(ddos_flood(i, t + i * 0.008))
    for i in range(60):
        pkts.append(scan_probe(i, t + i * 0.2))
    overlay, seq = bg_traffic(202, t, 12.0, rate_per_s=1.5, seq_start=seq)
    pkts.extend(overlay)
    t += 30

    # ---- 80-93 s: slow-rate DoS + concurrent bulk exfil --------------------
    pkts.extend(slowdos_packets(t))
    for i in range(40):
        pkts.extend(exfil_burst(i, t + 6 + i * 0.05))
    overlay, seq = bg_traffic(203, t, 13.5, rate_per_s=1.5, seq_start=seq)
    pkts.extend(overlay)

    pkts.sort(key=lambda p: float(p.time))
    return pkts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--seed", type=int, default=42,
                    help="reserved for future randomized variants")
    args = ap.parse_args(argv)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    pkts = build_packets()
    wrpcap(str(args.out), pkts)
    size_mb = args.out.stat().st_size / 1e6
    print(f"[demo] wrote {len(pkts):,} packets ({size_mb:.1f} MB) -> {args.out}")
    print("[demo] scenario schedule (replay clock):")
    print("         0-40 s   realistic background (no alerts expected)")
    print("        50-62 s   volumetric DDoS flood  -> 10.9.9.9")
    print("              +   port sweep under cover -> 10.5.0.7 (same window fires both)")
    print("        80-93 s   slow-rate DoS          -> 10.7.7.7")
    print("              +   bulk exfiltration      -> 10.20.0.9 (same window fires both)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
