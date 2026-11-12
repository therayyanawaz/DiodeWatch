# Changelog

All notable changes to DiodeWatch are documented here.

## [Unreleased]

_Nothing yet._

## [0.12.0] (2026-11-14)

### Added
- The product README: scoped badges, the architecture in one screen, and the
  research the pipeline is built on, cited per component.
- The judge demo script for the wall, what to click, in what order, and what
  each panel is evidence of.
- Team documentation: ownership per area, issue forms for bug reports and
  feature requests, and a pull request template whose checklist mirrors the
  guardrail.

### Changed
- `.gitignore` covers the Node install tree and editor scratch; the committed
  build output is still tracked on purpose, so the offline launch asks nothing
  of the host.

## [0.11.0] (2026-11-08)

### Added
- The rest of the wall in React: evidence drawer, diode proof, detection
  quality, capacity, radar and timeline panels, the status board and the help
  tooltips, every panel the hand-written page printed, over the routes
  `server.py` already answers.
- The built bundle and the shell that serves it, so `/` and `/status` are one
  `FileResponse` each and no Node is needed at run time.
- `docs/pipeline.md`: the whole path from an empty folder to an analyst's
  alert, command by command.
- A re-measured throughput ladder and dashboard screenshots.

## [0.10.0] (2026-11-01)

### Added
- The wall's new client begins: a Vite + TypeScript build with a typed API
  client, the wall/status/theme hooks, the topbar and clock, the hero session
  controls, the detectors grid, the class tiles and the alert feed.
- The judge brief.

### Changed
- `scikit-learn` pinned to the exact version the shipped model artifacts report
  about themselves, instead of a range that could install any newer one;
  `tests/test_ml_provenance.py` derives the pin from the artifacts and fails
  when the declaration and the artifacts disagree.

### Fixed
- A shebang script committed from a host without an exec bit landed
  unexecutable and failed lint on Linux. `waf/waf_replay.py` now records mode
  `100755`, and `tests/test_file_modes.py` reads `git ls-files -s` so the
  defect is visible from a host that has no exec bit of its own.

## [0.9.0] (2026-10-26)

### Added
- Cross-corpus evaluation snapshot: retrained and true zero-shot runs across
  CIC-IDS2017, CIC-DDoS2019 and CSE-CIC-IDS2018, with the shipped LightGBM
  artifacts and the metric JSON for every channel.
- `docs/ml.md`: the channels, the retrain protocol, and the disclosures that
  belong beside the numbers, the leave-one-day-out gap, the published PSI
  drift, and the cells that are correctly not evaluable on a corpus that
  carries no identity columns.

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

