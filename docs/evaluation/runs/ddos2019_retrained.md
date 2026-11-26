# Transfer evaluation, zero-shot cross-corpus summary

> **Archived result, superseded 2026-11-26.** This run used whole-file
> entity attribution, so a single alert painted every flow of that entity for
> the capture and the flow F1 overstated incident coverage. The 392-flow benign
> denominator is also not the full-corpus denominator. Kept as history; quote
> [`max_scale.md`](max_scale.md) for current figures.

Zero-shot protocol: models loaded from `models/`; target labels used **only** for scoring. Rules = window-layer alone; ML = gated ensemble (fail-closed).

## cic-ddos2019, 1,582,681 flows
- feature families not computed (declared future, reported, never faked): `iat_*, pkt_len_*, active_idle_*, dns_domain_length, dns_domain_entropy, dns_nxdomain_rate, tls_ja3, tls_ja3s`
- **rules** (window rules): macro F1 1.0 · micro F1 1.0
    - ddos: P 1.0 · R 1.0 · F1 1.0 · n 1582289
    - benign FPR 0/392 = 0.0 (PASS)
- **ml** (ml.flowctx (flow + window context)): macro F1 1.0 · micro F1 1.0
    - ddos: P 1.0 · R 1.0 · F1 1.0 · n 1582289
    - benign FPR 0/392 = 0.0 (PASS)
- drift (PSI, top-3): fwd_pkts 14.44106, fwd_bytes 13.398197, duration_us 7.638591

## Pre-committed gates
- [PASS] rule ddos F1 >= 0.95 (cic-ddos2019): 1.0, pre-committed; fix rules before finals if this fails
- [PASS] benign FPR <= 0.02 (cic-ddos2019): 0.0, alerts/hour-equivalent proxy
