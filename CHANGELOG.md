# Changelog

All notable changes to DiodeWatch are documented here.

## [0.8.0] — 2026-10-03

- Benchmarks & demo pack: 10,000 flows/s sustained ladder, out-of-sample
  accuracy gates re-asserted, 4-scenario demo pack, scripted rehearsal.
- Packaging: offline wheelhouse, one-command launchers (Windows + bash).

## [0.7.0] — 2026-09-30

- Alert store & exports: SQLite evidence store, STIX 2.1 bundles, HTML
  incident reports. Streamlit analyst dashboard with Diode Proof panel.

## [0.5.0] — 2026-09-12

- ML detectors: LightGBM flow+window ensemble, C2 beaconing (CTU-13 LOSO),
  DGA (family-holdout), TLS/JA3 channel — all quality gates pass.
- Diode guard: kernel egress-deny + live zero-byte proof panel.

## [0.4.0] — 2026-08-31

- Feature engine (frozen 47-feature registry, pandas-vectorised, parity-validated) and
  rule detectors (DDoS / slow-DoS / scan / exfil) with ATT&CK mapping.
