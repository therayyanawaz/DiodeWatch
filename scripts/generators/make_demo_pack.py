#!/usr/bin/env python3
"""Demo pack: four short pcaps, one per attack story, plus the
sidecar inputs the ML channels consume and a ground-truth manifest.

    python scripts/generators/make_demo_pack.py            # data/pcaps/pack/ + manifest

Pack contents (all offline, synthetic, seconds-long):

  01_ddos.pcap          benign web mix -> volumetric SYN flood
  02_c2_beacon.pcap     benign web mix -> fixed-interval C2 beacon
                        + 02_c2_beacon_netflow.csv  (CTU-style NetFlow for the
                        beacon detector; derived from THIS pcap via the real
                        ingest path, so pcap and sidecar can never diverge)
  03_dga_tunnel.pcap    benign DNS -> DNS-tunnel / DGA queries
                        + 03_dga_domains.txt        (queried names, the input
                        the DGA channel consumes in production: dns.log)
  04_exfil_scan.pcap    benign web mix -> port sweep + bulk exfiltration
  05_slowloris.pcap     benign web mix -> slow-rate DoS (held dribbles)
  06_exfil_ratio.pcap   benign web mix -> sustained asymmetric upload (ratio)

The manifest records the scenario schedule and the detector each item is
expected to trip (rules: ddos/scan/exfil; ML: beacon/DGA), which the rehearsal
(scripts/checks/rehearse_demo.py) asserts before every demo.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections.abc import Iterator
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

PACK_DIR = REPO / "data" / "pcaps" / "pack"

BASE_TS = 1_750_000_000.0
WEB_SERVERS = [f"93.184.0.{10 + i}" for i in range(4)]

# ---------------------------------------------------------------------------
# Realistic benign background (seeded, deterministic).
#
# The old background was metronomic (1 identical exchange/s to 4 servers).
# Real access links show jittered arrivals, mixed ports/sizes, multi-packet
# downloads and a DNS underlay. This builder produces that shape while
# provably staying under every rule gate: per-dst rates stay ~0.5/s
# (volumetric needs 50/s), per-src cardinality stays <= 3 flows/ports per
# window (scan needs >= 8 flows AND >= 30 ports/hosts), transfers are
# download-heavy (exfil needs >= 10:1 upload), and flows are short-lived
# (slowloris needs >= 30 flows held past the window). Victim subnets and
# ports are never touched, so attack aggregates are bit-for-bit unaffected
# in shape, only interleaved with background, the way real captures look.
# ---------------------------------------------------------------------------
BG_SERVERS = ([f"93.184.0.{10 + i}" for i in range(4)]
              + [f"93.184.1.{20 + i}" for i in range(4)])
BG_CLIENTS = [f"10.0.0.{11 + i * 7}" for i in range(12)]
BG_NAMES = ["www.example.com", "cdn.assets.example.org", "mail.google.com",
            "updates.microsoft.com", "api.dropbox.com", "login.example.net",
            "video.cdn.example.com", "docs.example.org", "shop.example.com",
            "news.example.net", "static.cdn.example.net", "app.example.io",
            "auth.example.com", "files.example.org", "img.cdn.example.com",
            "portal.example.net", "api.example.com", "cdn2.example.org",
            "webmail.example.com", "status.example.io"]
BG_RESOLVER = "10.40.0.53"


def _bg_exchange(rng: random.Random, seq: int, ts: float) -> list:
    """One realistic web download: jittered multi-packet response + DNS."""
    pkts: list = []
    client = BG_CLIENTS[rng.randrange(len(BG_CLIENTS))]
    srv = rng.choice(BG_SERVERS)
    dport = 443 if rng.random() < 0.7 else 80
    sport = 40000 + (seq % 20000)
    t = ts
    if rng.random() < 0.25:  # DNS underlay ahead of the connection
        pkts.append(_udp_dns(client, 50000 + (seq % 10000), BG_RESOLVER,
                             rng.choice(BG_NAMES), t))
        t += 0.03
    n_req = rng.randint(1, 2)  # small upstream request(s)
    for q in range(n_req):
        pkts.append(_tcp(client, sport, srv, dport, t + q * 0.01,
                         payload=b"GET /r HTTP/1.1\r\n" + b"h" * rng.randint(0, 900)))
    t += 0.02 + rng.random() * 0.05
    n_resp = rng.randint(1, 6)  # download-heavy multi-segment response
    for s in range(n_resp):
        pkts.append(_tcp(srv, dport, client, sport,
                         t + s * (0.005 + rng.random() * 0.015),
                         payload=b"HTTP/1.1 200 OK\r\n" + b"x" * rng.randint(200, 1350)))
    if rng.random() < 0.1:  # occasional RST teardown, as real stacks send
        pkts.append(_tcp(client, sport, srv, dport,
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


def _tcp(src_ip, sport, dst_ip, dport, ts, *, payload=b"", flags="PA"):
    pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
           / IP(src=src_ip, dst=dst_ip)
           / TCP(sport=sport, dport=dport, flags=flags, seq=1)
           / Raw(payload))
    pkt.time = ts
    return pkt


def _udp_dns(client, sport, resolver, name, ts):
    pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
           / IP(src=client, dst=resolver)
           / UDP(sport=sport, dport=53)
           / DNS(rd=1, qd=DNSQR(qname=name)))
    pkt.time = ts
    return pkt


def benign_web(i: int, ts: float) -> Iterator:
    client = f"10.0.{(i // 250) % 5}.{i % 250}"
    sport = 40000 + i
    srv = WEB_SERVERS[i % len(WEB_SERVERS)]
    yield _tcp(client, sport, srv, 80, ts, payload=b"GET / HTTP/1.1\r\n")
    yield _tcp(srv, 80, client, sport, ts + 0.02,
               payload=b"HTTP/1.1 200 OK\r\n" + b"x" * 1200)


def benign_dns(i: int, ts: float) -> Iterator:
    client = f"10.0.{(i // 250) % 5}.{i % 250}"
    names = ["www.example.com", "cdn.assets.example.org", "mail.google.com",
             "updates.microsoft.com", "api.dropbox.com"]
    yield _udp_dns(client, 50000 + i, "10.40.0.53",
                   names[i % len(names)] if i < len(names)
                   else f"host{i % 40}.example.com", ts)


# ------------------------------------------------------------------ scenarios
def ddos_packets() -> list:
    """0-8 s realistic background, 8-17 s SYN flood from 90 hosts to one
    target over a live background, 17-25 s calm."""
    pkts: list = []
    bg, seq = bg_traffic(101, BASE_TS, 8.0, rate_per_s=2.5)
    pkts.extend(bg)
    t0 = BASE_TS + 8
    for i in range(900):
        src = f"10.1.{(i // 250) % 4}.{i % 250}"
        pkts.append(_tcp(src, 20000 + i, "10.9.9.9", 80, t0 + i * 0.01,
                         payload=b"\x00" * 100, flags="S"))
    overlay, seq = bg_traffic(102, t0, 9.0, rate_per_s=1.5, seq_start=seq)
    pkts.extend(overlay)
    tail, _ = bg_traffic(103, t0 + 9, 8.0, rate_per_s=2.0, seq_start=seq)
    pkts.extend(tail)
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def beacon_events() -> list[dict]:
    """0-12 s benign web, then two C2-infected hosts reaching one controller.

    Shapes mirror CTU-13's real bot C2 distribution (the model's training
    data), not a textbook metronome:
      * 10.30.0.9, bursty: ~20 contacts over ~13 min, dt_cv ~2.6
        (measured: CTU-13 bot pairs are bursty, median dt_cv 1.7; the
        trained LightGBM scores this pair 0.99);
      * 10.30.0.8, metronomic: exactly 15 s apart for 17 contacts, which
        the transparent fallback rule (dt_cv <= 0.25 AND dt_scores >= 0.9
        AND n_flows >= 10) catches on its own.
    Two layers, two detections, one C2 channel.
    """
    import numpy as np

    events: list[dict] = []
    for i in range(12):
        events.append({"kind": "web", "i": i, "ts": BASE_TS + i})

    c2 = "198.51.100.23"
    t = BASE_TS + 20.0

    # bursty bot: deterministic contact schedule (numpy seed 20, verified
    # against the trained model at >= 0.95 in scripts/checks/rehearse_demo.py).
    # Payloads are keepalive-sized (~8 B): the model learned CTU-13's small
    # C2 exchanges (folded fwd_bytes_mean ~ 70-76 B), and larger payloads
    # score far below threshold.
    rng = np.random.default_rng(20)
    dts = [float(rng.uniform(2, 10)) if rng.random() < 0.78
           else float(rng.uniform(300, 1500)) for _ in range(19)]
    for k, d in enumerate(dts):
        events.append({"kind": "beacon", "src": "10.30.0.9", "dst": c2,
                       "sport": 41000 + k, "ts": t, "up": 8, "down": 96})
        t += d

    # metronomic bot: 17 contacts, fixed 15 s cadence
    t2 = BASE_TS + 30.0
    for k in range(17):
        events.append({"kind": "beacon", "src": "10.30.0.8", "dst": c2,
                       "sport": 42000 + k, "ts": t2, "up": 8, "down": 96})
        t2 += 15.0

    for i in range(4):
        events.append({"kind": "web", "i": 50 + i, "ts": t2 + i})
    return events


def beacon_packets(events: list[dict]) -> list:
    """Each C2 contact is a pure SYN / SYN-ACK keepalive (~54 B per side).

    That is the shape the beacon model learned from CTU-13 (folded
    fwd_bytes_mean ~ 70 B): with folded forward bytes over ~80 B the model
    reads the pair as ordinary TLS traffic, so payload-bearing check-ins are
    deliberately avoided here.
    """
    pkts: list = []
    for ev in events:
        if ev["kind"] == "web":
            pkts.extend(benign_web(ev["i"], ev["ts"]))
        else:
            ts, sp = ev["ts"], ev["sport"]
            pkts.append(_tcp(ev["src"], sp, ev["dst"], 443, ts, flags="S"))
            pkts.append(_tcp(ev["dst"], 443, ev["src"], sp, ts + 0.01,
                             flags="SA"))
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def dga_queries() -> tuple[list, list[str]]:
    """Benign DNS first, then 40 base32 tunnel queries + 6 random SLDs."""
    pkts: list = []
    domains: list[str] = []
    for i in range(15):
        pkts.extend([benign_dns(i, BASE_TS + i * 0.5)])
    rng = random.Random(1337)
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    t = BASE_TS + 12
    benign_bases = ["dropbox.com", "akamai.net", "cloudflare.com",
                    "microsoft.com", "google.com"]
    for i in range(40):
        payload = "".join(rng.choices(alphabet, k=40))
        name = f"{payload}.{benign_bases[i % len(benign_bases)]}"
        domains.append(name)
        pkts.append(_udp_dns("10.50.0.9", 51000 + i, "10.40.0.53", name,
                             t + i * 0.5))
    for i in range(6):
        sld = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz", k=14))
        name = f"{sld}.tk"
        domains.append(name)
        pkts.append(_udp_dns("10.50.0.9", 52000 + i, "10.40.0.53", name,
                             t + 25 + i))
    return pkts, domains


def exfil_scan_packets() -> list:
    """0-8 s background, 8-11 s port sweep + 14-24 s bulk exfil over a live
    background (~19 MB)."""
    pkts: list = []
    bg, seq = bg_traffic(104, BASE_TS, 8.0, rate_per_s=2.5)
    pkts.extend(bg)
    t0 = BASE_TS + 8
    for i in range(60):
        pkts.append(_tcp("10.5.0.7", 35000 + i, f"10.60.0.{i % 3}",
                         1000 + i, t0 + i * 0.05, flags="S"))
    overlay, seq = bg_traffic(105, t0, 6.0, rate_per_s=1.5, seq_start=seq)
    pkts.extend(overlay)
    te = BASE_TS + 14
    for i in range(40):
        for seg in range(8):
            pkts.append(_tcp("10.20.0.9", 46000 + i, "93.184.200.9", 443,
                             te + i * 0.05 + seg * 0.02,
                             payload=b"\xff" * 60_000))
    overlay2, seq = bg_traffic(106, te, 10.0, rate_per_s=1.5, seq_start=seq)
    pkts.extend(overlay2)
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def slowloris_packets() -> list:
    """0-8 s benign, 8-21 s slow-rate DoS, 21-25 s calm.

    40 conversations from one client hold past the 10 s window with tiny
    header-only dribbles (fwd/bwd 2:1, starved-server shape), the exact
    shape the slowdos rule (flows>=30, ratio>=2, mean fwd 10-160 B, held>=5)
    fires on. Same construction as the combined demo capture. A live
    benign background runs underneath; it never touches the victim.
    """
    pkts: list = []
    bg, seq = bg_traffic(107, BASE_TS, 8.0, rate_per_s=2.5)
    pkts.extend(bg)
    t0 = BASE_TS + 8
    n_convs, n_calls = 40, 44
    for i in range(n_calls):
        ts = t0 + i * 0.3
        for c in range(n_convs):
            pkts.append(_tcp("10.3.0.7", 41000 + c, "10.7.7.7", 80,
                             ts + c * 0.004,
                             payload=b"GET /slow HTTP/1.1\r\n"))
            if i % 2 == 0:  # starved server: replies to every other request
                pkts.append(_tcp("10.7.7.7", 80, "10.3.0.7", 41000 + c,
                                 ts + c * 0.004 + 0.01,
                                 payload=b"HTTP/1.1 100 C\r\n\r\n"))
    overlay, seq = bg_traffic(108, t0, 13.5, rate_per_s=1.5, seq_start=seq)
    pkts.extend(overlay)
    tail, _ = bg_traffic(109, t0 + 13.5, 3.5, rate_per_s=2.0, seq_start=seq)
    pkts.extend(tail)
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def ratio_exfil_packets() -> list:
    """0-8 s benign, 8-11 s sustained asymmetric upload, 11-15 s calm.

    One host pushes ~1.5 MB outward across 25 flows with ~28:1
    upload:download byte ratio (40 x 1.5 kB segments up, 4 small replies
    down per flow), the upload_ratio signature (>= 10x over >= 20 flows
    with >= 10 kB volume, majority-external). Total stays well under the
    5 MB bulk threshold, so only the ratio branch fires. A live benign
    background runs underneath; it never touches the victim.
    """
    pkts: list = []
    bg, seq = bg_traffic(110, BASE_TS, 8.0, rate_per_s=2.5)
    pkts.extend(bg)
    t0 = BASE_TS + 8
    for i in range(25):
        ts = t0 + i * 0.1
        for seg in range(40):
            pkts.append(_tcp("10.20.0.7", 45000 + i, "93.184.200.5", 443,
                             ts + seg * 0.02, payload=b"\xee" * 1500))
        for r in range(4):
            pkts.append(_tcp("93.184.200.5", 443, "10.20.0.7", 45000 + i,
                             ts + 0.85 + r * 0.02, payload=b"ack" + b"\x00" * 497))
    overlay, seq = bg_traffic(111, t0, 7.0, rate_per_s=1.5, seq_start=seq)
    pkts.extend(overlay)
    pkts.sort(key=lambda p: float(p.time))
    return pkts


# ------------------------------------------------------------- sidecar export
def beacon_netflow_csv(pcap: Path, out_csv: Path, bot_events: list[dict]) -> int:
    """Derive the CTU-style NetFlow sidecar from the pcap via the REAL ingest.

    stream_flows() aggregates the capture exactly as deployment would; the
    bot contacts are then labelled from the generator's ground truth. This
    keeps pcap and sidecar consistent by construction.
    """
    import csv

    import pandas as pd

    from src.ingest.pcap_reader import stream_flows

    bot_srcs = {ev["src"] for ev in bot_events if ev["kind"] == "beacon"}
    bot_ts = {round(ev["ts"], 3) for ev in bot_events if ev["kind"] == "beacon"}
    rows = []
    for rec in stream_flows(pcap):
        ts = float(rec["ts_epoch"])
        is_bot = rec["src_ip"] in bot_srcs and any(
            abs(ts - b) < 1.0 for b in bot_ts)
        rows.append({
            "StartTime": pd.Timestamp(ts, unit="s", tz="UTC")
            .strftime("%Y-%m-%d %H:%M:%S"),
            "SrcAddr": rec["src_ip"], "DstAddr": rec["dst_ip"],
            "Dport": rec["dst_port"], "Proto": rec["proto"],
            "Dur": round(rec["duration_us"] / 1e6, 6),
            "TotPkts": rec["fwd_pkts"] + rec["bwd_pkts"],
            "TotBytes": rec["fwd_bytes"] + rec["bwd_bytes"],
            "SrcBytes": rec["fwd_bytes"],
            "Label": "flow=From-Bot" if is_bot else "flow=Background",
        })
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    return len(rows)


# --------------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=PACK_DIR)
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)

    manifest: dict = {"base_ts": BASE_TS, "pack": []}

    def emit(name: str, pkts: list, schedule: list[str],
             expected: dict) -> Path:
        out = args.out / name
        wrpcap(str(out), pkts)
        mb = out.stat().st_size / 1e6
        print(f"[pack] {name}: {len(pkts):,} packets ({mb:.2f} MB)")
        for line in schedule:
            print(f"         {line}")
        manifest["pack"].append({"pcap": out.name, "n_packets": len(pkts),
                                 "size_mb": round(mb, 2), "schedule": schedule,
                                 "expected": expected})
        return out

    # 1 - DDoS
    emit("01_ddos.pcap", ddos_packets(),
         [" 0- 8 s  benign web mix", " 8-17 s  volumetric SYN flood -> 10.9.9.9:80",
          "17-25 s  benign tail"],
         {"detector": "rules.ddos", "threat_class": "ddos", "key": "10.9.9.9",
          "rule_expected": ["ddos"], "sidecar": None})

    # 2 - C2 beacon (+ NetFlow sidecar derived from the pcap)
    events = beacon_events()
    pcap2 = emit("02_c2_beacon.pcap", beacon_packets(events),
                 [" 0-12 s  benign web mix",
                  "20-810 s  C2: 10.30.0.9 bursty + 10.30.0.8 metronomic",
                  "          -> 198.51.100.23:443 (SYN/SYN-ACK keepalives)"],
                 {"detector": "ml.beacon", "threat_class": "beacon",
                  "key": "10.30.0.9->198.51.100.23:443",
                  "note": ("with models loaded the trained pair model fires on "
                           "10.30.0.9 (score >= 0.9); 10.30.0.8's metronomic "
                           "cadence is caught by the transparent fallback rule "
                           "in no-model deployments and is deliberately NOT "
                           "model-flagged (fixed cadence alone is benign "
                           "auto-updater shaped)"),
                  "rule_expected": [], "sidecar": "02_c2_beacon_netflow.csv"})
    n_rows = beacon_netflow_csv(pcap2, args.out / "02_c2_beacon_netflow.csv",
                                events)
    print(f"[pack] 02_c2_beacon_netflow.csv: {n_rows} flows "
          f"(derived from the pcap via src.ingest)")

    # 3 - DNS tunnel / DGA (+ domains sidecar)
    pkts3, domains = dga_queries()
    emit("03_dga_tunnel.pcap", pkts3,
         [" 0- 8 s  benign DNS to 10.40.0.53",
          "12-32 s  DNS tunnel: 40 base32 subdomain queries + 6 random SLDs"],
         {"detector": "ml.dga", "threat_class": "dga", "key": "<queried domains>",
          "rule_expected": [], "sidecar": "03_dga_domains.txt",
          "n_malicious_domains": len(domains)})
    (args.out / "03_dga_domains.txt").write_text(
        "\n".join(domains) + "\n", encoding="utf-8")

    # 4 - exfil + scan
    emit("04_exfil_scan.pcap", exfil_scan_packets(),
         [" 0- 8 s  benign web mix", " 8-11 s  port sweep from 10.5.0.7",
          "14-24 s  bulk exfil 10.20.0.9 -> 93.184.200.9:443 (~19 MB)"],
         {"detector": "rules.scan+rules.exfil", "threat_class": "scan,exfil",
          "key": "10.5.0.7 / 10.20.0.9",
          "rule_expected": ["scan", "exfil"], "sidecar": None})

    # 5 - slow-rate DoS (slowloris shape, no volumetric footprint)
    emit("05_slowloris.pcap", slowloris_packets(),
         [" 0- 8 s  benign web mix",
          " 8-21 s  slow-rate DoS 10.3.0.7 -> 10.7.7.7:80 (40 held dribbles)",
          "21-25 s  benign tail"],
         {"detector": "rules.slowdos", "threat_class": "slowdos",
          "key": "10.7.7.7",
          "rule_expected": ["slowdos"], "sidecar": None})

    # 6 - asymmetric-upload exfil (ratio branch, under the bulk threshold)
    emit("06_exfil_ratio.pcap", ratio_exfil_packets(),
         [" 0- 8 s  benign web mix",
          " 8-11 s  ratio exfil 10.20.0.7 -> 93.184.200.5:443 (~1.5 MB, ~28:1)",
          "11-15 s  benign tail"],
         {"detector": "rules.exfil", "threat_class": "exfil",
          "key": "10.20.0.7",
          "rule_expected": ["exfil"], "sidecar": None})

    man = args.out / "pack_manifest.json"
    man.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[pack] manifest -> {man.relative_to(REPO)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
