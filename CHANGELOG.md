# Changelog

All notable changes to DiodeWatch are documented here.

## [Unreleased]

_Nothing yet._

## [0.8.0] (2026-10-18)

### Added
- The executable claim guardrail. Six contracts over every judge-facing
  surface: banned phrasings, figures reconciled against the pinned artifacts,
  false-positive claims that must carry their denominator and their layer, a
  suite size re-derived from `pytest --collect-only` rather than remembered, a
  command and path contract, and a repository-URL contract. It has its own
  tests, so a guardrail that stops guarding fails CI.
- Alerts, dashboard and demo-rehearsal checks, plus a browser-side time-format
  check that runs on a non-UTC host.
- Cross-corpus transfer write-up and feature spot-check tooling.

### Changed
- `CONTRIBUTING.md` and `SECURITY.md`, with CI's lint scope stated verbatim.

## [0.7.0] (2026-10-11)

### Added
- WAF harness: a ModSecurity ruleset, an nginx container, graded case corpora
  and a replay tool that reports which case each rule caught.
- A tamper-evident evidence chain over the alert store, with an offline
  attestation bundle, and live chain persistence behind the wall.
- Alert-store, chain, attestation and pack-source tests; a diode egress proof
  check.

### Changed
- Release notes through 0.6.0 below.

## [0.6.0] (2026-10-04)

### Added
- The analyst dashboard (Streamlit) with live replay and demo capture, and the
  mission-control backend: server, status page, wall stylesheet and the client
  helpers the pages share.
- Route and replay tests for both surfaces.
- CI: lint, the full test suite and the claim guardrail on every push.

## [0.5.0] (2026-09-27)

### Added
- System-1 triage: the engine, its question bank, a background worker and the
  runtime that produces one verdict per alert. Every verdict carries the
  provenance of the model that produced it, and an advisory guard so a verdict
  can never read as a decision the operator did not make.
- The triage side-table store.
- Deterministic demo pack and demo pcap generators, so a rehearsal runs with no
  network at all.
- A model-provenance check that fails when a channel's artifact and its
  declared configuration disagree.

## [0.4.0] (2026-09-20)

### Added
- Throughput and accuracy harnesses plus a cross-corpus transfer benchmark,
  each with a self-test so the harness itself can be wrong loudly.
- Corpus downloaders that record a verified ledger, hash, origin and
  verification date, for every artifact they fetch, so a published figure can
  always be traced to bytes.
- The abuse.ch SSLBL JA3 watchlist, committed because the channel needs it on a
  fresh clone and `data/` is ignored.
- Baseline-slice integrity tests, supervised-channel tests and the transfer
  test; the dataset ledger and the diode verification notes.

## [0.3.0] (2026-09-13)

### Added
- `src/detectors/ml/labels.py` as the single owner of label truth, with the
  artifact pins beside it.
- A TLS/JA3 channel over the watchlist.
- STIX 2.1 export, HTML incident reports and an analyst CLI, plus a live
  watcher that replays a capture into the store.
- One-command setup for Windows and Linux, and the demo, rehearsal and wall
  launchers.
- The rule, threshold and claim checks under `scripts/checks/`, and the
  reference docs for features, rules and alerts.

## [0.2.0] (2026-09-06)

### Added
- The alert schema with ATT&CK technique and tactic tags, and a SQLite evidence
  store whose ingest is idempotent: an alert's identity is derived from what it
  describes, so replaying a capture cannot duplicate a row.
- The diode guard: a kernel egress enforcer and a socket monitor, plus a CLI
  that reports the mode the host actually granted, enforced, monitor-only, or
  nothing observable.
- ML channels for C2 beaconing (periodicity) and DGA, over windowed flows, with
  a bridge that reads the same feature frame the rule channels read.
- First coverage for the unifier, the feature engine, the rule channels and the
  guard.

## [0.1.0] (2026-08-30)

### Added
- The flow record, built once: a pcap reader and a flow-table reader emit the
  same canonical record and one unifier settles the fields they share.
- A vectorised feature engine over a frozen registry, with window specs shared
  by every channel that reads it.
- Rule channels for DDoS, slow-DoS, scanning and exfiltration, each carrying
  its ATT&CK mapping and a calibration note naming the corpus it was derived
  from.
- Repository scaffolding: licence, editor and EOL contract, and packaging.

