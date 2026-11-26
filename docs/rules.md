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
692,703 flows / 440,031 BENIGN). Every number in the tables below is re-derived
by one command:

```bash
python scripts/checks/check_thresholds.py    # exit 1 on drift, 2 if no corpus
```

### Acceptance reality

On that corpus the rule engine emits **128 alerts, of which 91 land on
benign-labelled windows** (ddos 79, exfil 9, scan 3).

| metric | value |
|---|---|
| total alerts | 128 (ddos 115, exfil 9, scan 4) |
| alerts on BENIGN windows | **91** |
| worst single contributor | `192.168.10.3`, 74 ddos alerts via `volumetric_rate` |
| benign dst windows / src windows | 57,134 / 39,213 |

The full-corpus pass now scores the same alert stream at alert level: on
CIC-IDS2017, 594 alerts, 50 exact (precision 0.084) and 523 benign-only; on
CIC-DDoS2019, 1,424 alerts, exact precision 0.919 but DDoS incident recall
0.122. The Wednesday table above is the single-day calibration record that
explains the CIC-IDS2017 false-positive mechanism; it is not a cross-corpus
precision claim.

Earlier revisions of this document reported "29 alerts, all on DoS-labelled
windows, 0 on benign-labelled windows" over the 200k-flow stratified slice
(`data/slices/flows.ndjson`). That slice is git-ignored runtime output, but it
is regenerable (`scripts/fetch/download_baseline_slice.py`, then
`python -m src.ingest.unify`) and the 29/0 figure still reproduces there. It is
a 50/50 subsample, however; the full pinned Wednesday table is the stricter
test, and the figures above quote it: 128 alerts, 91 on benign-labelled
windows. The prose rationale in each table has been corrected to match the
full day. The remaining false positives are dominated by one busy benign host
crossing the raw volumetric-rate threshold; see the `ddos` table and "Known
limits".

### ddos, volumetric flood / fan-in / SYN flood  (mode="any")

| condition | threshold | rationale (measured on the pinned corpus) |
|---|---|---|
| `volumetric_rate` | ≥ 50 flows/s to one dst | **not clean**: benign max 210.9 flows/s; 77 benign windows cross it, 74 of them one destination (192.168.10.3, median 66.9 flows/s) |
| `volumetric_rate` (bandwidth branch) | ≥ 2 MB/s fwd with ≥ 3 srcs | bandwidth floods that shard across many ports |
| `fan_in_distinct_sources` | ≥ 50 distinct srcs AND src_conc ≤ 0.3 | **near-clean**: benign max 136 srcs/window and 73 benign windows reach 50 srcs, but only 2 are also concentrated |
| `syn_flood_half_open` | SYN share ≥ 0.8 of fwd pkts AND ≥ 50 unacked SYNs | classic fwd ≫ bwd half-open signature |

The fan-in branch, not the raw rate, is what separates on this corpus. A
per-destination baseline (each host's own normal rate) would remove the
single-host false positives; that is a config change, not a constant edit.

### slowdos, slow-rate asymmetric DoS, slowloris family  (mode="all")

| condition | threshold | rationale |
|---|---|---|
| `flow_count` | ≥ 30 flows/window to one dst | coordinated pressure, not one chatty client |
| `fwd_bwd_pkt_ratio` | ≥ 2.0 | server gets almost no packets out |
| `mean_fwd_pkt_size` | ≤ 80 B | partial-header dribble, not real requests |
| `held_connections` | ≥ 5 connections still open past the window | **the decisive separator**: benign small-packet pollers hold 0 (mean duration < 0.5 s), slowloris holds 100-400 across consecutive windows |

The held-connections condition is what kills the false positives that the
first three conditions alone produce (scheduled pollers, CDN beacons).

### scan, port sweep / recon  (mode="all")

| condition | threshold | rationale |
|---|---|---|
| `server_share` | ≤ 0.2 | a host whose flows originate FROM service ports is a server answering clients; the 'ports' it touches are client-side ephemeral ports. **The decisive gate**: removes 65 of the 66 high-cardinality benign windows |
| `cardinality` | ≥ 30 dst ports OR ≥ 30 dst hosts | benign proxies reach this (66 benign windows > 30 ports), so shape is required too |
| `bytes_per_flow` | ≤ 600 B | probes carry no payloads; benign high-cardinality windows median 285 B/flow (p95 9,178 B) |
| `resp_share` | ≤ 0.5 | at least half the probes get no reply packet; benign resp_share p50 = 0.965, so the gate keeps only 9 of the 66 |

All four together still leave **3 benign windows** passing. The conjunction is
a strong filter, but it is not a guarantee, measure it, don't assume it.

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
T1046 Discovery, T1048 Exfiltration).

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
* `volumetric_rate` is an absolute constant, so a single legitimately busy
  host generates recurring false positives (74 of the 91 on the pinned
  corpus). A per-destination baseline would fix this; the constant stays
  until that exists.
* The 91 benign alerts are measured against one CIC day. The cross-corpus
  transfer numbers in `docs/evaluation/transfer.md` are the source of truth
  for generalisation, this table is a single-corpus calibration record.
