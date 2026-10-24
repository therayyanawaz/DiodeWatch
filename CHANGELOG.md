# Changelog

All notable changes to DiodeWatch are documented here.

## [Unreleased]

_Nothing yet._

_Nothing yet._

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


