# Transfer evaluation — zero-shot cross-corpus summary

Zero-shot protocol: models loaded from `models/`; target labels used **only** for scoring. Rules = window-layer alone; ML = gated ensemble (fail-closed).

## cic-ids2018-nf-v2-infil — 331,100 flows
- feature families not computed (declared future, reported — never faked): `iat_*, pkt_len_*, active_idle_*, dns_domain_length, dns_domain_entropy, dns_nxdomain_rate, tls_ja3, tls_ja3s`
- **rules**: unavailable — identity columns absent in export — entity-scoped rules not evaluable (reported, never faked); ML per-flow scoring unaffected
- **ml** (ml.flowctx (flow + window context)): macro F1 0.421437 · micro F1 0.0
    - unmapped: P None · R 0.0 · F1 0.0 · n 93063
    - benign FPR 5/238,037 = 2.101e-05 (PASS)
- drift (PSI, top-3): duration_us 7.004476, fwd_bytes 1.266456, fwd_pkts 1.045787

## Pre-committed gates
