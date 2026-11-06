# Changelog

All notable changes to DiodeWatch are documented here.

## [Unreleased]

_Nothing yet._

_Nothing yet._

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


