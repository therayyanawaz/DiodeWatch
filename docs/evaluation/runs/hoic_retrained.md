# Transfer evaluation — zero-shot cross-corpus summary

Zero-shot protocol: models loaded from `models/`; target labels used **only** for scoring. Rules = window-layer alone; ML = gated ensemble (fail-closed).

## cic-ids2018-nf-v2-hoic — 1,048,575 flows
- feature families not computed (declared future, reported — never faked): `iat_*, pkt_len_*, active_idle_*, dns_domain_length, dns_domain_entropy, dns_nxdomain_rate, tls_ja3, tls_ja3s`
- **rules**: unavailable — identity columns absent in export — entity-scoped rules not evaluable (reported, never faked); ML per-flow scoring unaffected
- **ml** (ml.flowctx (flow + window context)): macro F1 0.010953 · micro F1 0.0
    - ddos: P None · R 0.0 · F1 0.0 · n 687742
    - benign FPR 0/360,833 = 0.0 (PASS)
- drift (PSI, top-3): duration_us 10.018997, fwd_bytes 4.918908, fwd_pkts 3.959373

## Pre-committed gates
