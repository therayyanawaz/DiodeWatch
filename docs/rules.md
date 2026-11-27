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
692,703 flows / 440,031 BENIGN). The rule layer emits 40 alerts on this table,
none of them on benign windows; every threshold number below is re-derived by
one command:

```bash
python scripts/checks/check_thresholds.py    # exit 1 on drift, 2 if no corpus
```

### Acceptance reality

Full-pass results for the shipped rules, 10 s windows, same code as the
benchmark:

| corpus | alerts | exact | benign-only | ddos P / R / F1 | benign FPR |
|---|---|---|---|---|---|
| CIC-IDS2017 | 75 | 70 (0.933) | 5 | 0.999 / 0.979 / 0.989 | 0.00236 |
| CIC-DDoS2019 | 1,183 | 1,175 (0.993) | 0 | 0.995 / 0.998 / 0.996 | 0.00045 |

Flow-level precision is higher than alert-level precision because one alert
paints its whole `(window, destination)` scope, and a CIC-IDS2017 benign
window can contain thousands of flows. The residual CIC-IDS2017 alerts are
2 scan, 2 exfil and 1 slowdos claim; no DDoS-class alert lands on a benign
window. The old Wednesday `192.168.10.3` rate spike now fails the 250/s byte
floor at 210.9 flows/s and 19.6 KB/s. The 500 kB exfil ratio floor and the
removal of the scan host-sweep branch cut benign-only alerts from 122 to 32
without dropping a CIC-IDS2017 truth unit. The 20 KB/s floor below 250 flows/s
and the reply-aware port gate then cut 32 to 5, again with no truth loss. The 2
remaining exfil alerts are 5.29 MB and 12.9 MB bulk uploads, not small
chatter; the 2 scan alerts are high-port sweeps from one source over 2-3
destinations that satisfy every gate. On CIC-DDoS2019 the host-sweep removal
dropped 9 benign-only scan alerts and the exfil floor dropped 3, leaving 8
scan-class alerts inside attack-labelled windows, 51 benign flow-level false
positives (FPR 0.00045) and no benign-only window.

The raw 50 flows/s line is still not clean on the pinned Wednesday table:
benign traffic reaches 210.9 flows/s and 77 benign windows cross it, 74 of
them against `192.168.10.3` (median 66.9 flows/s). The guards below are what
make the branch usable; do not quote the raw threshold as a detector on its
own.

### ddos, volumetric flood / fan-in / SYN flood  (mode="any")

| condition | threshold | rationale (measured on the pinned corpus) |
|---|---|---|
| `volumetric_rate` | ≥ 50 flows/s to one dst, plus the guards below | raw threshold alone is **not clean** (see above); the guards cut CIC-IDS2017 benign FPR to 0.00236 |
| `volumetric_rate` (persistence) | ≥ 250 flows/s one window; 200-250 two windows; 50-200 three windows | a one-window busy-server spike is not a flood; the baseline still applies, so this gate controls delay, not the rate floor |
| `volumetric_rate` (byte floor) | ≥ 20 KB/s below 250 flows/s | 50-250 flows/s of 40-80 B requests is ordinary chatter; the last CIC-IDS2017 false burst in the 200-250 band carried 19.6 KB/s, while true low-rate floods carried 37-640 KB/s |
| `volumetric_rate` (port gate) | ≤ 16 dst ports, or ≥ 500 KB/s plus 3 sources, 500 flows/s, or ≤ 1 reply/flow, or ≥ 5,000 ports at ≥ 500 flows/s | a low-bandwidth burst over hundreds of ports is a sweep; a multi-port burst is a reflection flood only when distributed, fast, or unanswered; a 1,200-port answered transfer is a sweep, while CIC-DDoS2019 single-source random-port floods still fire; 46k ports at 8k flows/s is a random-port SYN flood (the scan rule caps at 5,000) |
| `volumetric_rate` (baseline) | rate >= max(50, 3× online baseline) after 10 windows | tracks each destination's own normal rate; EWMA α 0.2, 60 s gap tolerance for minute-granular exports |
| `volumetric_rate` (bandwidth branch) | ≥ 2 MB/s fwd with ≥ 3 srcs | bandwidth floods that shard across many ports |
| `fan_in_distinct_sources` | ≥ 50 distinct srcs AND src_conc ≤ 0.3 AND the destination looks like a service (≤ 16 ports, or a high-rate random-port burst) | clean on both pinned corpora: 19 benign CIC-IDS2017 windows fan in over 102-1,025 ports and are rejected by the service shape; the old 2-concentrated-windows caveat is gone |
| `syn_flood_half_open` | SYN share ≥ 0.8 of fwd pkts AND ≥ 50 unacked SYNs | classic fwd ≫ bwd half-open signature |

The fan-in branch remains a strong separator, but it is service-gated:
distributed background traffic onto hundreds of ports is a sweep, not a DDoS.
The volume branch is a gated rate claim, not a bare constant.

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
| `cardinality` | 30-5,000 ports on ≤ 3 hosts | benign proxies reach 30 ports (66 benign windows); host sweeps are out of scope after the 2026-11-27 removal; 46k ports at 8k flows/s is a SYN flood (the DDoS rule claims it) |
| `bytes_per_flow` | ≤ 600 B | probes carry no payloads; benign high-cardinality windows median 285 B/flow (p95 9,178 B) |
| `resp_share` | ≤ 0.5, or a reset-closed sweep (≥ 100 ports, ≤ 2 hosts, ≥ 0.9 replies) | at least half the probes get no reply packet; a scanner that receives RSTs still reveals itself through 100+ ports on one or two hosts |

The port bounds are the precision fix. On CIC-IDS2017 the reset-closed branch
supplies all 11 true scan alerts; the PortScan capture answers every probe with
RST, so the plain no-reply gate missed it. Bounding the probe branch still
removes the 28,571-flow Thursday benign host+port burst that the old diagonal
claimed. The host-sweep branch was removed 2026-11-27: across all eight files it
fired 29 benign windows and zero scan-labelled windows. Those were 30-43 host
walks on 2-6 ports by ordinary internal hosts, not focused recon. The rule now
emits 2 benign scan alerts on the full corpus, one reset-closed and one
1,003-port probe shape; on Wednesday zero benign windows pass. Measure it, do
not assume it.

### exfil, bulk outbound transfer  (mode="any", with a direction gate)

| condition | threshold | rationale |
|---|---|---|
| gate `external_dst_share` | ≥ 0.5 of flows leave RFC1918 space | exfiltration crosses the network boundary; the slice's asymmetric windows are internal LAN copies |
| `upload_ratio` | ≥ 10:1 fwd:bwd bytes AND ≥ 20 flows AND ≥ 500 kB uploaded | ratio without volume is noise (a 600 B DNS burst hit 17:1); the old 10 kB floor produced 63 benign alerts, 61 under 200 kB, and the largest benign ratio window is 141,375 B, so 500 kB keeps 3.5x headroom |
| `bulk_upload_bytes` | ≥ 5 MB fwd in one window | Wednesday benign max is 4,369.8 kB/window, below the gate; the full eight-day corpus has two benign bulk windows, 5.29 MB on Tuesday and 12.9 MB in Thursday's Infiltration capture, which the rule reports (truth scores both benign), so do not claim the gate is globally benign-free |

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
* CIC-IDS2017 exact alert precision is 0.9333 (70/75) and DDoS flow
  precision is 0.9989 (F1 0.9890). The 5 benign-only alerts are 2 scan,
  2 exfil and 1 slowdos; the 250/s byte floor and the reply-aware DDoS port
  gate removed all 27 DDoS false bursts, leaving only the large or high-port
  scan and exfil sessions that satisfy every gate. Report alert precision,
  not only flow F1.
* The scan rule no longer claims host sweeps (many hosts, few ports). They were
  29 benign windows and zero scan truth units across CIC-IDS2017, so the branch
  was removed rather than tuned; a targeted ping sweep is left to the behaviour
  layer and can be missed by the rule alone.
* Two benign bulk uploads still trigger exfil: 5.29 MB on Tuesday and
  12.9 MB in Thursday's Infiltration capture. Both are above the 5 MB bulk gate
  and are reported rather than filtered away; the largest Wednesday upload
  window (4,369.8 kB) is below the gate and does not alert.
* CIC-DDoS2019 DDoS incident recall is 1,175/9,927 (0.1184) even though flow
  recall is 0.9979. Incident units demand the exact `(window, destination,
  class)`; a scoped alert cannot cover every attack window in a long capture.
* Slow-DoS truth recall is 18/46 on CIC-IDS2017 (all Wednesday) and 0/448 on
  CIC-DDoS2019. The rule now emits `slowdos`; the pinned ML classifier still
  folds the class into `ddos` because its artifacts were not retrained, so
  rule-only cells carry the slow-DoS claim.
* The cross-corpus transfer numbers in `docs/evaluation/transfer.md` are the
  source of truth for generalisation; this table is a calibration record.
