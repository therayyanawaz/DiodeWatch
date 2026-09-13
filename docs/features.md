# Feature schema

The frozen feature schema is declared in **`src/features/specs.py`** — the single
source of truth for the detectors. Every feature names its family, dtype,
semantics and (for future entries) the data stage that will fill it.
`python -m src.features.pipeline --describe` prints the registry.

## Pipeline

```bash
python -m src.ingest.unify \
    --input data/slices/baseline_slice.parquet \
    --out  data/slices/flows.ndjson          # canonical flow records

python -m src.features.pipeline \
    --input data/slices/flows.ndjson \
    --out  data/slices/features.parquet      # frozen feature vectors

python scripts/experiments/spotcheck_features.py         # parity vs the source CIC slice
```

200,000 flows × 73 active features build in ~11 s on a laptop, in one streaming
read + vectorized pass. The record itself carries 47 canonical fields
(`src/ingest/schema.py::FLOW_FIELDS`); 73 is the width of the derived frame.

## Column groups (73 active)

| Group | Columns | Semantics |
|---|---|---|
| meta (9) | `flow_id`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `proto`, `timestamp`, `label` | identity/provenance, carried for joins & eval — not model inputs |
| basic (10) | `duration_s`, `fwd_pkts`, `bwd_pkts`, `tot_pkts`, `fwd_bytes`, `bwd_bytes`, `tot_bytes`, `avg_fwd_pkt_size`, `avg_bwd_pkt_size`, `avg_pkt_size` | flow duration (s), per-direction counts & bytes, mean packet sizes |
| rates (6) | `flow/fwd/bwd_bytes_per_s`, `flow/fwd/bwd_pkts_per_s` | throughput; **NaN when duration is 0** (never Inf) |
| ratio (3) | `fwd_byte_ratio`, `byte_asymmetry`, `pkt_asymmetry` | directional balance in [-1, 1]; 0 when no traffic |
| protocol (3) | `is_tcp`, `is_udp`, `is_icmp` | transport one-hots |
| tcpflags (6) | `fin/syn/rst/psh/ack/urg_flags` | TCP flag-packet counts, 0 for non-TCP |
| dns (1) | `is_dns` | either endpoint port is 53 |
| iat (14) | `iat_us_mean/std/max/min`, `fwd_iat_us_total/mean/std/max/min`, `bwd_iat_us_total/mean/std/max/min` | per-packet inter-arrival gaps in microseconds, over the whole flow and per direction |
| pktlen (12) | `len_min/max/mean/std`, `fwd_len_*`, `bwd_len_*` | per-packet size in bytes, same breakdown, on the same length measure as `fwd_bytes`/`bwd_bytes` |
| context (9) | per source: `src_flow_count`, `src_dst_port_count`, `src_dst_ip_count`, `src_dst_port_entropy`, `src_dns_share`; per destination: `dst_flow_count`, `dst_src_port_count`, `dst_src_ip_count`, `dst_src_port_entropy` | group statistics over the batch window (Shannon entropy over port distributions) |

The `iat` and `pktlen` families are measured at ingest and passed through, so
they mean the same thing whichever source produced the row: the table reader
aliases CIC's own `Flow IAT *` / `Fwd IAT *` / `* Packet Length *` columns, and
the pcap reader computes the same statistics from the packets it streams.

## Declared-future features (not yet emitted)

DNS/TLS features need Zeek logs, and the burst split needs a definition we can
stand behind — declared in the registry so the schema grows without churn:

- `active_idle_*` — CIC publishes `Active/Idle Mean/Std/Max/Min`, and the burst
  floor is measurable from it (the smallest non-zero Idle value on the pinned
  200k slice is 5,000,002 µs, so the split is at 5 s, not the 1 s usually
  quoted). The aggregation is *not* reproduced: a per-direction "gap > 5 s
  starts an idle period" rule matches CIC's own `Idle Mean` on only 98.13% of
  those rows (3,731 rows counted idle that CIC does not, 9 the other way), so
  our version and CIC's would put two different measures in one column name.
- `dns_domain_length`, `dns_domain_entropy`, `dns_nxdomain_rate` — from Zeek `dns.log`
- `tls_ja3`, `tls_ja3s` — from Zeek `ssl.log`

## Conventions

- NaN (never ±Inf) for rates over zero-duration flows and mean sizes over empty
  directions; LightGBM/pandas consume NaN natively.
- A source that publishes no timing data gives NaN, not 0: "not measured" must
  never read as "perfectly evenly spaced packets".
- `*_std` is the **sample** deviation (÷ n−1), which is what CIC's own Std
  columns are: on the pinned slice, 3-packet flows have exactly two gaps, so
  their spread fixes both formulas, and the observed Std matches sample in
  96.05% of those rows versus 14.64% for population.
- A statistic with no population (a direction with one packet, std over fewer
  than two values) is 0.0, matching how the CIC tables encode it.
- TCP flag counts are 0 for non-TCP flows (matches the CIC tables).
- Context features are computed over the whole input batch (one window);
  sliding-window semantics arrive with the live streaming stage.

## Parity verification

`scripts/experiments/spotcheck_features.py` compares every feature row against the original
CIC slice (positionally aligned — unify preserves source row order, asserted via
flow ids):

| Field | Result |
|---|---|
| `duration_s` vs `Flow Duration` (µs) | exact, 0/200,000 mismatches |
| `fwd/bwd_pkts` vs `Total Fwd/Backward Packets` | exact, 0/200,000 |
| `fwd/bwd_bytes` vs `Total Length of Fwd/Bwd Packets` | exact, 0/200,000 |
| all 26 `iat_*` / `pktlen_*` columns vs their CIC source columns | exact, 0/200,000 each |
| `flow_bytes_per_s` / `flow_pkts_per_s` vs `Flow Bytes/s` / `Flow Packets/s` | within **0.46%** max rel err on 199,571 finite pairs |

The rate columns need tolerance because **CIC-IDS2017 quantizes large rates in
the released CSV** (true 10,328,125 bytes/s is published as 10,300,000); the
engine recomputes exact rates from integer bytes/durations. Zero/zero rate pairs
count as exact matches. Timing sentinels are passed through rather than cleaned:
a `-1`, or a negative `Flow IAT Min` from an out-of-order capture, is source
data, and the check asserts it survives.
