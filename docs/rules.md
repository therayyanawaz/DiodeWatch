# Rule-Based Detectors

Immediate, interpretable detection ahead of the ML layer. One module per
threat signature family; every alert is a `src.alerts.schema.Alert` with
`timestamp`, `flow_id`, `threat_class`, `confidence`, and evidence items that
state **observed value vs threshold** (with units and a human-readable line).

## Pipeline

```
canonical flows (unify schema)
      │
      ▼
detectors.window.build_windows   tumbling windows (default 10 s)
      │   per (window, dst_ip) frame  → ddos / slowdos signals
      │   per (window, src_ip) frame  → scan / exfil signals
      ▼
rule modules (src/detectors/{ddos,slowdos,scan,exfil}.py)
      │   mode="any": independent signatures, one suffices (ddos, exfil)
      │   mode="all": conjunctive shape, every condition must hold (slowdos, scan)
      ▼
alerts.schema.Alert  →  JSON / SQLite / STIX
```

## Rules and calibrated thresholds

Thresholds are calibrated against the pinned CIC-IDS2017 Wednesday working-hours
table (`data/raw/cic2017/Wednesday-workingHours.pcap_ISCX.csv.parquet`,
692,703 flows / 440,031 BENIGN). The rule layer emits 55 alerts on this table,
15 of them on benign windows; every threshold number below is re-derived by one
command:

```bash
python scripts/checks/check_thresholds.py    # exit 1 on drift, 2 if no corpus
```

### Acceptance reality

Full-pass results for the shipped rules, 10 s windows, same code as the
benchmark:

| corpus | alerts | exact | benign-only | ddos P / R / F1 | benign FPR |
|---|---|---|---|---|---|
| CIC-IDS2017 | 192 | 70 (0.365) | 122 | 0.947 / 0.979 / 0.963 | 0.0126 |
| CIC-DDoS2019 | 1,195 | 1,175 (0.983) | 12 | 0.995 / 0.998 / 0.996 | 0.0068 |

Flow-level precision is higher than alert-level precision because one alert
paints its whole `(window, destination)` scope, and a CIC-IDS2017 benign
window can contain thousands of flows. The residual CIC-IDS2017 alerts are
31 scan, 63 exfil, 27 ddos-class and 1 slowdos claim, not one volumetric
source: on the Wednesday table the old `192.168.10.3` rate spike is now one
alert.

The raw 50 flows/s line is still not clean on the pinned Wednesday table:
benign traffic reaches 210.9 flows/s and 77 benign windows cross it, 74 of
them against `192.168.10.3` (median 66.9 flows/s). The guards below are what
make the branch usable; do not quote the raw threshold as a detector on its
own.

### ddos, volumetric flood / fan-in / SYN flood  (mode="any")

| condition | threshold | rationale (measured on the pinned corpus) |
|---|---|---|
| `volumetric_rate` | ≥ 50 flows/s to one dst, plus the guards below | raw threshold alone is **not clean** (see above); the guards cut CIC-IDS2017 benign FPR to 0.0126 |
| `volumetric_rate` (persistence) | ≥ 250 flows/s one window; 200-250 two windows; 50-200 three windows | a one-window busy-server spike is not a flood; the baseline still applies, so this gate controls delay, not the rate floor |
| `volumetric_rate` (byte floor) | ≥ 20 KB/s below 200 flows/s | 50-200 flows/s of 40-80 B requests is ordinary chatter; CIC-IDS2017 false bursts carried 4-21 KB/s while true low-rate floods carried 37-640 KB/s |
| `volumetric_rate` (port gate) | ≤ 16 dst ports, ≥ 500 KB/s, or ≥ 5,000 ports at ≥ 500 flows/s | a low-bandwidth burst over hundreds of ports is a sweep; a high-bandwidth multi-port burst is a reflection flood; a 46k-port burst at 8k flows/s is a random-port SYN flood, not a sweep (the scan rule caps at 5,000 ports) |
| `volumetric_rate` (baseline) | rate >= max(50, 3× online baseline) after 10 windows | tracks each destination's own normal rate; EWMA α 0.2, 60 s gap tolerance for minute-granular exports |
| `volumetric_rate` (bandwidth branch) | ≥ 2 MB/s fwd with ≥ 3 srcs | bandwidth floods that shard across many ports |
| `fan_in_distinct_sources` | ≥ 50 distinct srcs AND src_conc ≤ 0.3 | **near-clean**: benign max 136 srcs/window and 73 benign windows reach 50 srcs, but only 2 are also concentrated |
| `syn_flood_half_open` | SYN share ≥ 0.8 of fwd pkts AND ≥ 50 unacked SYNs | classic fwd ≫ bwd half-open signature |

The fan-in branch is still the cleanest single separator. The volume branch is
now a gated rate claim, not a bare constant.

### slowdos, slow-rate asymmetric DoS, slowloris family  (mode="all")

| condition | threshold | rationale |
|---|---|---|
| `flow_count` | ≥ 30 flows/window to one dst | coordinated pressure, not one chatty client |
| `fwd_bwd_pkt_ratio` | ≥ 2.0 | server gets almost no packets out |
| `mean_fwd_pkt_floor` | ≥ 10 B | a real request carries a header; 2.7-3.5 B ACK-only windows are noise, not slowloris |
| `mean_fwd_pkt_size` | ≤ 160 B | partial-header dribble, not real requests; CIC slowloris is 49-160 B, the demo is 15 B |
| `held_connections` | ≥ 5 connections still open past the window | **the decisive separator**: benign small-packet pollers hold 0 (mean duration < 0.5 s), slowloris holds 100-400 across consecutive windows |

The held-connections condition is what kills the false positives that the
first four conditions alone produce (scheduled pollers, CDN beacons). The
10 B floor rejects 14 Thursday benign windows of about 2,000 flows each whose
mean forward packet is 2.7-3.5 B; those are ACK-only bursts, not requests.

### scan, port sweep / recon  (mode="all")

| condition | threshold | rationale |
|---|---|---|
| `server_share` | ≤ 0.2 | a host whose flows originate FROM service ports is a server answering clients; the 'ports' it touches are client-side ephemeral ports. **The decisive gate**: removes 65 of the 66 high-cardinality benign windows |
| `cardinality` | ≤ 5,000 ports AND (≥ 30 ports on ≤ 3 hosts OR ≥ 30 hosts on ≤ 16 ports) | benign proxies reach 30 ports (66 benign windows), and a broad 35-host x 30-port internal enumeration is not a focused sweep; 46k ports at 8k flows/s is a SYN flood (the DDoS rule claims it) |
| `bytes_per_flow` | ≤ 600 B | probes carry no payloads; benign high-cardinality windows median 285 B/flow (p95 9,178 B) |
| `resp_share` | ≤ 0.5, or a reset-closed sweep (≥ 100 ports, ≤ 2 hosts, ≥ 0.9 replies) | at least half the probes get no reply packet; a scanner that receives RSTs still reveals itself through 100+ ports on one or two hosts |

The port/host bounds are the precision fix. On CIC-IDS2017 the reset-closed
branch covers 11 of 27 PortScan truth units; bounding the probe branch removes
the 28,571-flow Thursday benign host+port burst that the old diagonal claimed.
The scan class still emits 31 benign alerts on small windows, so the conjunction
is not clean; measure it, do not assume it.

### exfil, bulk outbound transfer  (mode="any", with a direction gate)

| condition | threshold | rationale |
|---|---|---|
| gate `external_dst_share` | ≥ 0.5 of flows leave RFC1918 space | exfiltration crosses the network boundary; the slice's asymmetric windows are internal LAN copies |
| `upload_ratio` | ≥ 10:1 fwd:bwd bytes AND ≥ 20 flows AND ≥ 10 kB uploaded | ratio without volume is noise (a 600 B DNS burst hit 17:1) |
| `bulk_upload_bytes` | ≥ 5 MB fwd in one window | benign max 4,369.8 kB/window, so **no** benign window reaches it (~0.6 MB headroom); catches exfil over responsive protocols |

## Confidence (start simple)

`confidence = fired_conditions / total_conditions` of the rule, unweighted,
interpretable, and refined by calibration against labelled data. Alerts carry
`attack_technique` / `attack_tactic` (T1498 Impact,
T1046 Discovery, T1048 Exfiltration, T1499.002 Endpoint Denial of Service).

## Usage

```bash
# one-call API
python - <<'EOF'
from src.detectors.rules import run_rules
alerts = run_rules(flows_df, window_s=10)
EOF

# CLI over canonical flow NDJSON
python -m src.detectors.rules --input data/slices/flows.ndjson \
                              --out data/slices/rules_alerts.ndjson

# Acceptance check (synthetic scenarios; slice needs data/slices/flows.ndjson)
python scripts/checks/check_rules.py

# Recalibration check (re-derives every threshold number in this doc)
python scripts/checks/check_thresholds.py
```

Per-rule thresholds are overridable:

```python
run_rules(flows, rules=make_rules({"ddos": {"flows_per_sec": 100.0}}))
```

## Known limits (documented, honest)

* Slow-rate attacks whose connections turn over faster than the window
  (e.g. very short slowloris cycles) can evade `held_connections`, the ML
  layer is the intended backstop.
* Exfil targets outside RFC1918 are judged "external" purely by IP; a pinned
  per-deployment CIDR allowlist (the monitored prefix) should replace the
  blanket private-address test when the config stage lands.
* Windows are tumbling; a scan straddling a boundary is detected in the
  window holding most of its probes, not split.
* The per-destination baseline lives in a rule-engine instance and warms over
  10 windows. A fresh call or a capture shorter than that relies on the
  absolute floor and persistence guards; the baseline does not model daily
  seasonality.
* Slow-DoS corroboration drops the first window of a sustained run and any
  isolated claim when the batch contains another slow window. A short capture
  with only one slow window is exempt, so streaming chunks can differ from a
  single full-file replay.
* CIC-IDS2017 exact alert precision is 0.3646 (70/192) even though DDoS flow
  precision is 0.9468. The remaining 122 benign-only alerts are mostly scan
  and exfil shapes on benign windows, not the volume branch; report alert
  precision, not only flow F1.
* CIC-DDoS2019 DDoS incident recall is 1,175/9,927 (0.1184) even though flow
  recall is 0.9979. Incident units demand the exact `(window, destination,
  class)`; a scoped alert cannot cover every attack window in a long capture.
* Slow-DoS truth recall is 18/46 on CIC-IDS2017 (all Wednesday) and 0/448 on
  CIC-DDoS2019. The rule now emits `slowdos`; the pinned ML classifier still
  folds the class into `ddos` because its artifacts were not retrained, so
  rule-only cells carry the slow-DoS claim.
* The cross-corpus transfer numbers in `docs/evaluation/transfer.md` are the
  source of truth for generalisation; this table is a calibration record.
