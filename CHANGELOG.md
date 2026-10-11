# Changelog

All notable changes to DiodeWatch are documented here.

## [Unreleased]

_Nothing yet._

_Nothing yet._

## [1.0.0] (2026-11-20)

First stable release: the detection stack, the evidence chain and the wall are
frozen, and every claim a judge can read is re-derived from this tree on every
CI run.

### Added
- CI rebuilds the React wall on the pinned Node version and fails unless the
  bundle shipped in `apps/mission_control/static/` is byte-identical to what
  the build writes, the only mechanical defence against a committed build
  output drifting from its source.
- Dependency and release automation (`.github/dependabot.yml`,
  `.github/release.yml`), and citation metadata (`CITATION.cff`).
- `AUTHORS.md`, `.github/CODEOWNERS` and `docs/roadmap.md`: the team, the area
  each person owns, and the thirteen-week schedule the releases were cut on.

### Changed
- `docs/competition/readiness.md` re-verified against this tree, with the
  status figures and the ledger dates brought forward to the current run.

### Removed
- The README's CI badge. On a repository that is not public it answers 404 to
  any signed-out reader, so it was deleted rather than reworded; CI state stays
  documented where it is measured, in the readiness ledger.

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


## [Unreleased]

### Added
- **Per-packet timing and size statistics on the flow record.** Both ingest
  sources already held the per-packet clock and per-packet length and threw them
  away at aggregation. The canonical record now carries 26 of those measurements
  (inter-arrival mean/std/max/min over the flow and over each direction, packet
  size min/max/mean/std over the same three scopes): the pcap reader folds them
  in with Welford accumulators in the same single pass, and the table reader
  carries the publisher's own values across untouched. Active registry 47 → 73
  columns; `MODEL_FEATURES` stays at 38, so every pinned model, fingerprint and
  published metric is unchanged.
- All 26 columns verified row-for-row against the pinned 200,000-flow CIC slice
  (`scripts/experiments/spotcheck_features.py`): exact, 0 mismatches each.
- **The wall's client is now React (`frontend/`), and it ships at `/` and
  `/status`.** A Vite + TypeScript build over the routes `server.py` already
  answers (no new endpoint, no invented path) taking the replay session, the
  `/ws/live` broadcast and the `/api/diode` verdict from the same server the
  hand-written page did. Every panel it printed is ported: the hero session
  controls, the threat-level headline, the three throughput tiles, the alert
  feed with its filters and custody pill, the evidence drawer with its STIX and
  report exports, the Diode Proof panel, the detectors grid, the class tiles
  with their radar canvas, the benchmark capacity card, the alert timeline
  canvas, the Detection Quality table, the custom source picker, all seventeen
  help tooltips, and (as a second page of the same build) the ten-row service
  board. `frontend/` is a two-entry rollup built with `base: "/"`, so `/` is the
  home page and the wall in one: the build emits its two shells and their chunks
  into `apps/mission_control/static/`, the directory the server already mounts
  at `/`, and `/` and `/status` are one `FileResponse` each over them with no
  path under `/wall/` reaching a browser. The build output is committed and
  `node_modules` is not, so the offline launch still asks nothing of the host: no
  Node, no registry, no CDN. Committing a build output is the one place this repo
  can ship an artifact that no longer matches its source, so CI rebuilds
  `frontend/` on Node 22 and fails unless the shipped bundle is byte-identical
  to what that build writes.
  Parity was checked in a browser, panel by panel, over one shared replay, and
  that comparison found a real defect: the React Diode panel painted literal
  zeros for connections and violations under a `NO-STATUS` or stale verdict,
  where the page it replaced withheld them as `, ` because an observer that saw
  nothing cannot evidence an absence. The gate is now hoisted above the verdict
  branch, so an unknown proof cannot print a contradiction beside it.

### Changed
- **The published per-flow latency was wrong by two orders of magnitude, and it
  was wrong in our own disfavour.** README, the judge brief, the readiness
  claim table and `docs/benchmarks.md` all quoted "2.4-4.2 ms" per flow, defined
  as window eval ÷ flows. That division gives 0.026-0.073 ms; the quoted figure
  was window-eval **milliseconds ÷ 1,000** with the label changed. Corrected on
  every surface, and the dashboard tile now renders microseconds so a sub-0.01 ms
  cost cannot display as `0.00 ms`.
- Throughput ladder re-measured with the 47-field record and the 73-column frame
  (`scripts/benchmarks/bench_throughput.py`, 2026-11-03): 10,000 flows/s holds
  with 4.2x headroom where the previous run recorded 2.8x, end-to-end replay p95
  175 ms (was 243), batch ML scoring 32,301 flows/s (was 30,653). The rating is
  unchanged; the wider frame cost nothing measurable.
- PCAP-derived flows now carry a real `timestamp` (first packet, ISO-8601 UTC).
  They carried `None`, which disqualified capture traffic from every time-ordered
  path downstream, chronological splits, sliding windows, an alert on a clock.
- CIC-IDS2017 semantics measured rather than assumed, and recorded where they
  surprised: `Std` is the **sample** deviation (÷n-1, 96.05% of rows agree with
  that formula, 14.64% with the population one), one-packet directions publish
  `0.0` rather than blank, and the idle-burst floor is 5,000,002 µs.
- `active_idle_*` stays declared-future on evidence: the aggregation on top of
  that floor reproduces only 98.13% of the published columns (3,731 of 200,000
  rows disagree, 9 beyond rounding), so emitting it would put two meanings in one
  column name. Negative findings published, not patched over.
- Source quirks added to the dataset register: 213 of 200,000 slice rows carry a
  negative inter-arrival time (200 are CIC's `-1` "not computable" sentinel), and
  the `120000000` µs ceiling in the IAT columns is exactly the 120 s flow timeout.
- **Fixed: reloading the wall redrew a different session than the one on
  screen.** The feed's card painter prepends, so the live path shows
  newest-first; the snapshot rebuild reversed the store's oldest-first array
  before handing it to that same prepending function, which landed the **oldest**
  alert on top and then let the 80-card DOM cap trim from the bottom -
  discarding the newest alerts. Found by running the same snapshot through a
  second client beside the first, and pinned by
  `test_the_wall_rebuild_lands_the_order_the_live_path_drew`, which fails if
  either paint path stops normalising the store's oldest-first array to
  newest-first.
- `fmt`, `fmtTime` and `fmtLocal` have one implementation: the wall's client
  re-exports them from `static/js/dom.js` instead of carrying a second copy.
  `scripts/checks/check_timefmt.mjs` proves the naive-UTC rule on a +5:30 CI
  host, and it was proving one file while a divergence-prone duplicate was on
  screen; a new pin fails CI if any component file re-declares one of the three.
  `fmt` reads an absent measurement as 0 rather than `NaN`, which is what an
  idle wall genuinely has.
- **Fixed: resuming a paused replay moved the label, not the worker.** The
  replay loop ran while `state == "running"`, so the moment `pause()` set
  `"paused"` the worker exited and `_pause_evt` was left guarding nothing;
  `resume()` restored the label and every browser kept showing the frozen
  window count as if it were live. Found by driving the wall in a browser and
  proven with curl alone, so it never belonged to the new client. The loop
  condition now treats `"paused"` as a state that keeps a consumer alive, the
  event is the gate, and
  `test_resuming_a_paused_replay_moves_the_replay_not_just_the_label` pins it
  (it fails against the old condition).
- **Fixed: two of the wall's four page spellings skipped revalidation.**
  Building at `base: "/"` moved the shipped shells into `static/`, the directory
  the mount answers at any path, so `/index.html` and `/status.html` began
  serving the same bytes as `/` and `/status` without the `no-cache` header the
  middleware sets: a warm disk cache could keep a judge on the previous index
  after a rebuild, while the route they typed revalidated correctly. The header
  now covers both spellings of both pages, and deliberately skips the chunks -
  Vite names them after their own bytes, so a rebuilt bundle is a different URL
  and no conditional request is needed.
  `test_the_wall_shell_always_revalidates` pins the whole set, including the
  chunk that must not carry it.

### Removed
- **The hand-written vanilla wall: `static/index.html`, `static/status.html`,
  `static/js/app.js`, `static/js/status.js`, 2,016 lines across four files,
  replaced by the client that reached parity with it rather than kept beside
  it.** Two walls over one session is two surfaces for a claim to drift across,
  and every panel either one printed is now pinned on the one client:
  `test_the_wall_prints_every_caveat_its_help_buttons_carry` holds the seventeen
  tooltip sentences as a spec,
  `test_the_wall_renders_every_panel_its_stylesheet_lays_out` the panel class
  contracts, the two canvases and the ten status rows, and
  `test_the_wall_sprite_holds_every_glyph_its_pages_reference` the icon set both
  page entries carry. Kept on purpose: `static/css/app.css`, which the client is
  built against, and `static/js/dom.js` with its `.d.ts`, whose formatters the
  client imports and `scripts/checks/check_timefmt.mjs` proves on a non-UTC host.

## [0.9.0] (2026-09-09)

### Added
- Cross-corpus transfer evaluation on **real data**: CIC-DDoS2019 Syn day
  (1.58M flows, full identity) + 4 CSE-CIC-IDS2018 attack days (3.5M flows).
  True zero-shot: rule DDoS F1 = 1.0 with benign FPR = 0.0 on the
  never-trained CIC-DDoS2019 corpus, both pre-committed gates pass.
- Supervised channel retrained on 13 corpus days across 3 labs (7 classes);
  flow-context windows retrained on the 10 identity-bearing days.
- Consolidated transfer summary (`results/transfer/summary.md`) with both
  phases, gates, and honest limitations.
- Mission-control web UI (`web/`): FastAPI backend + offline vanilla-JS SPA,
  parity with the Streamlit dashboard.
- Dedup/suppression counters surfaced on both live feeds.
- Executable claim guardrail (`scripts/checks/check_claims.py`, CI-enforced).

### Changed
- Superseded unqualified readiness claims with scoped status badges.
- Repositioned the repository product-first ("DiodeWatch"); competition
  artifacts moved to `docs/competition/`.

### Disclosed (not hidden)
- ML flow-context recall 0.0 on untrained corpora, with PSI drift published
  as the explanation; IDS2018 rule cells not evaluable (export lacks
  identity columns); leave-one-day-out threshold-transfer gap; webattack
  channel auto-disabled by its own quality gate.

## [0.8.0] (2026-09-07)

- Benchmarks & demo pack: 10,000 flows/s sustained ladder, out-of-sample
  accuracy gates re-asserted, 4-scenario demo pack, scripted rehearsal.
- Packaging: offline wheelhouse, one-command launchers (Windows + bash).

## [0.7.0] (2026-09-06)

- Alert store & exports: SQLite evidence store, STIX 2.1 bundles, HTML
  incident reports. Streamlit analyst dashboard with Diode Proof panel.

## [0.5.0] (2026-09-05)

- ML detectors: LightGBM flow+window ensemble, C2 beaconing (CTU-13 LOSO),
  DGA (family-holdout), TLS/JA3 channel, all quality gates pass.
- Diode guard: kernel egress-deny + live zero-byte proof panel.

## [0.4.0] (2026-09-04)

- Feature engine (frozen 47-feature registry, pandas-vectorised, parity-validated) and
  rule detectors (DDoS / slow-DoS / scan / exfil) with ATT&CK mapping.
