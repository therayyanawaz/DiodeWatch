# Changelog

All notable changes to DiodeWatch are documented here.

## [Unreleased]

### Added
- Wall request guards: `apps/mission_control/limits.py` adds a `TrustedHost`
  allowlist (default `127.0.0.1,localhost,[::1]`, bare `*` refused) and a 1 MiB
  ASGI body cap that counts the stream rather than trusting Content-Length.
  Sliding-window limits admit 600 `/api` requests and 12 unsafe requests per
  60 s, then answer 429 with `Retry-After`. A foreign Host is 400 once the
  token layer admits it (401 first if configured and absent) and an
  oversized body 413; the security layer stays outermost so all three keep the
  hardening headers. The buckets are process-global, which is stated in the
  deployment and threat model along with the nginx Host drop-in.
- Deployment bundle for the wall: `deploy/nginx/diodewatch.conf` terminates
  TLS 1.2/1.3, redirects port 80, proxies one `127.0.0.1:8530` upstream with the
  WebSocket upgrade, and writes a query-string-free access log;
  `deploy/systemd/diodewatch-wall.service` runs as an unprivileged user with a
  systemd sandbox, keeps the live db and logs under `/var/lib/diodewatch`, and
  pins `--workers 1`. The server now rejects any other worker count with
  argparse, because the session and WebSocket set are process-local.
  `scripts/checks/check_deployment.py` guards the file contract, and
  `docs/deployment.md` records install, certificate, verification, operations
  and the authentication limit.
- OCSF 1.10.0 Detection Finding export: `src/alerts/export_ocsf.py` maps one
  alert to one `class_uid=2004` Create event (`type_uid=200401`) and writes a
  deterministic JSONL stream, one compact object per line. `time` is the
  detection instant (the alert timestamp, normally its window end), not the
  export clock; the alert window is in `start_time`/`end_time` and
  `finding_info.first_seen_time`/`last_seen_time`. `evidences[0].data` keeps the
  full observed-vs-threshold list, endpoints are emitted only when the alert
  carries them, DNS `query.hostname` only for the DGA and DNS-tunnel classes,
  and observables must resolve to values present in the event. The stdlib
  validator checks the required attributes, enum siblings, ATT&CK ids,
  endpoints and observable paths before writing, and refuses an invalid stream.
  Wired through the alerts CLI (`ocsf`), the `:8530` route
  `/api/export/ocsf/{alert_id}`, the Streamlit dashboard and the wall evidence
  drawer. Mapping, version pin and limits: `docs/ocsf.md`.
- Per-channel drift abstention: `src/alerts/drift.py` pins quantile PSI
  references for the flow-context, beacon and DGA channels and latches a channel
  whose live frame exceeds its threshold. `LiveEvidenceStore` evaluates samples
  before the tick's alerts, so a latched channel's alerts never reach calibration;
  `ml_engine` applies the same gate before scoring. The latch is sticky within a
  process and clears only on an explicit reset. Rules and identity TLS are not
  gated. Thresholds are empirical: the flow null maximum is 2.808149, giving 3.0,
  and all eight held-out CIC days stay under it (max 2.815199) while an injected
  shift reaches 13.221836.
  Beacon null 0.535586 gives 1.0, and the excluded scenario-52 holdout reaches
  1.117500; DGA null 0.000423 gives 0.5, with family fold 1 at 1.885670 and
  Umbrella at 1.257144. The canned pack has 2 beacon pairs and 46 DGA domains,
  below `min_samples=500`, so it abstains from drift judgment instead of
  suppressing its alerts. Artifact, measured readings and limits:
  `docs/drift.md` and `docs/evaluation/runs/drift.json`.
- Per-channel calibration and conformal abstention: `src/alerts/calibration.py`
  fits an isotonic score-to-frequency map and a split-conformal benign sample for
  each ML channel and class. `LiveEvidenceStore` and `ml_engine` apply the policy
  before persistence, so an alert abstains when `p > alpha` or the calibrated
  confidence is below the floor; severity is recomputed, the alert id is stable,
  and already-calibrated alerts are skipped. A pinned artifact ships at
  `models/calibration.json` (copy under `docs/evaluation/models/`), with rules
  deliberately excluded because their confidence is coverage, not probability.
  On the pinned split, beacon precision rises 0.301 to 0.791 (recall 0.195 to
  0.070), DGA 0.99716 to 0.99767, and flowctx is unchanged because its thresholds
  were already tighter than `alpha=0.01`. The beacon scenario holdout keeps 3
  alerts and 0 true positives, recorded as the shift limitation that motivates a
  drift alarm. Artifact and caveats: `docs/evaluation/runs/calibration.json`.
- Paced flow-intake clock and bounded backpressure: `src/alerts/stream.py`
  wraps the existing `replay_flows` worker with a producer that paces canonical
  records in wall-clock time and a blocking `queue.Queue` sized to two seconds
  of offered traffic. `WindowResult` reports first-ingress, last-ingress,
  evaluation start/finish, fill, queue wait, last-flow-to-alert, window work and
  first-flow-to-alert; the batch path keeps its old behavior and has no clock.
  The benchmark measures six 10 s windows per rate: p95 flow-ingest-to-alert is
  11.81 s at 5,000 flows/s and 12.68 s at 10,000, with brief queue saturation at
  10k; the 50,000 target fills the queue, blocks the producer for 53.59 s, and
  accepts 23,880 flows/s at a 39.92 s p95. The clock excludes packet capture and
  capture-to-flow export. Artifact and caveats:
  `docs/evaluation/runs/stream_backpressure.md`.
- TLS and QUIC metadata: `src/ingest/tls_metadata.py` reassembles a TLS
  handshake from a pcap and computes JA3, JA3S, JA4 and JA4S from the real
  ClientHello/ServerHello bytes, including optional `ja4`/`ja4s` columns in the
  Zeek-style loader. It also aggregates QUIC version, connection IDs, long-header
  packet type, packet sizes and inter-arrival gaps per flow. QUIC Initial
  payloads are never decrypted, so no QUIC JA4 is claimed; JA4/JA4S are evidence
  context beside the pinned JA3 watchlist, not a new detection channel.
- Flow-export ingest: `src/ingest/flow_reader.py` reads Argus CSV (`ra -c ,`,
  including CTU-13 `.binetflow`), nfdump CSV (with or without a header row) and
  goflow2 JSON/NDJSON into the canonical 47-field schema. `unify.py` sniffs a
  `.csv` header and gains `--format argus|nfdump|goflow2`; the readers keep absent
  per-packet flags and timing statistics null, never invent a directional split
  or a zero, and skip malformed rows with a count.
- `scripts/benchmarks/bench_corpora.py` scores every pinned flow corpus at its
  full row count, not only the five files the transfer summary quoted:
  CIC-IDS2017 (8/8), CIC-DDoS2019 (18/18), CSE-CIC-IDS2018 (10/10), UNSW-NB15
  and CTU-13 (13/13, reported not-evaluable because a NetFlow export has no
  TCP flags or directional counters). The rule layer streams the whole file in
  250,000-flow chunks; the ML channel runs on the first 200,000 contiguous
  flows; structural padding rows are dropped and counted, truth labels absent
  from the register are reported and excluded, and a channel that cannot be
  computed says so instead of printing a zero. Output: `summary.md` plus
  `max_results.json` per run, and the run records the byte count and SHA256 of
  every artifact it loaded, so a cell can be traced to the model that produced it.
- The wall logs structured JSON lines under `data/logs/`: application events in
  `mission_control.log` (session lifecycle, websocket handshakes, replay
  failures) and one record per request in `access.log`. Rotation is
  size-based (5 MB, 5 files, `DIODE_LOG_MAX_BYTES` / `DIODE_LOG_BACKUPS`), and
  the query string is never logged, because the wall token rides `?token=`.
- `/api/health` is now computed, not constant: it touches the evidence store
  with a real query (row count, chain length, optionally `PRAGMA quick_check`
  under `?deep=true`), proves the data directory writable, and reports the
  version, uptime and the configured maintenance interval. A degraded store
  answers `ok: false` with the reason, which the status board renders.
- `/metrics` exposes process-local counters in the Prometheus text format:
  session state, alerts inserted and rejected, chain links, live socket clients,
  alerts by class, and maintenance counters, which stay zero because this build
  does not schedule maintenance. Outside `/api`, like the read-only pages.
- `src/alerts/maintenance.py` (also a CLI) backs the evidence db up online
  through SQLite's backup API, copies the append-only ledger with it, and then
  verifies the copy: a backup that does not itself verify is reported failed,
  not shelved. It prunes whole stamped families past a retention count
  (`DIODE_BACKUP_KEEP`), and vacuums the WAL's freed pages. The CLI runs one
  maintenance pass; this build does not schedule it, so the wall's
  `DIODE_MAINTENANCE_INTERVAL_S` only feeds health output until a timer or
  other external schedule calls the CLI. Row deletion is deliberately absent:
  the chain hashes every row in append order, so retention happens by rotating
  and pruning whole dbs, never rows.
- `.pre-commit-config.yaml`: ruff over CI's exact scope and the claim guardrail,
  as pre-push hooks. Both call the tools from this repository's own pins rather
  than pinning their own, so a hook cannot agree with a laptop and disagree with
  the workflow on Linux.
- The wall answers with a strict security policy on every response, and a
  configured `DIODE_WALL_TOKEN` turns `/api` into a 401 without it. Binding to a
  non-loopback interface now refuses to start unless a token is set, because an
  open wall lets any reachable caller start, pause and reset a capture.
- `src/alerts/attest.py` exports a canonical digest of the evidence chain and,
  with OpenSSL, the RFC 3161 request that binds it to a wall clock. Nothing
  contacts a time-stamp authority automatically: the request is a file you send.
- `docs/threat-model.md`: the three trust boundaries in STRIDE, what is
  implemented at each, what is out of scope by name, and the test that re-checks
  every claim on it.
- `docs/models/`: a card per shipped artifact, the digest of the exact bytes, and
  `feature_order.json`, which pins the training column order for all four scoring
  channels including the two whose artifacts are not distributed.
- `scripts/checks/make_sbom.py` emits a CycloneDX 1.5 inventory of the installed
  environment, uploaded as a build artifact; `scripts/checks/make_lock.py`
  produces `requirements.lock` and checks it offline.
- `scripts/benchmarks/bench_reference.py` measures Suricata or Zeek on one
  capture beside our own pass, and reports that a tool is absent instead of
  emitting a row for something it never ran.
- `.github/workflows/integration.yml` fetches the corpora the repository never
  commits, then requires that the cells which skip without them actually run.
- The wall's accessibility contract is tested: accessible names on every control,
  a named listbox that announces its highlighted option, the tooltip wired as the
  button's description, and no focus indicator removed without a replacement.
- The volumetric rule claims a flood only after four guards: an online
  per-destination rate baseline, persistence (250 flows/s for one window, 200-250
  for two, 50-200 for three), a 20 KB/s byte floor below 250 flows/s, and a
  destination-port check that requires a multi-port burst to be distributed,
  at least 500 flows/s, or unanswered at 500 KB/s (the 46k-port CIC-DDoS2019
  SYN flood also clears 500 flows/s). The fan-in branch requires a service
  shape. Scan claims that overlap a DDoS victim in the same window are
  suppressed, and a slow-DoS claim is kept only when a same-window volume claim
  or a prior slow window within 60 s corroborates it. Short captures with a
  single slow window are exempt, so the demo pcap still alerts.

### Changed
- Slow-DoS accepts a held-dominant profile (at least 15 connections held and
  a 1.6 packet ratio, beside the base 5-held/2.0 profile), and scan accepts a
  narrow 5-10-port sweep (at least 30 probes, at most 2 hosts, at most 50 B per
  flow, at least 90% answered). Full CIC-IDS2017: slow-DoS 33/46 (was 28/46),
  PortScan 15/27 (was 11/27), 96 alerts with exact precision 89/96 = 0.927083
  (was 80/85), still 5 benign-only. Two of the new slow claims are DDoS Hulk
  windows, a class confusion rather than a benign false positive. Benign FPR is
  5,523/2,273,108 = 0.00242971 (was 5,453/2,273,108 = 0.00239892).
- The DGA threshold now targets a 0.5% benign false-positive rate on the
  family-holdout OOF corpus instead of maximizing recall at 90% precision. On
  the untouched Umbrella holdout this moves FPR from 0.1076 to 0.01864 at
  threshold 0.9321; known-corpus recall falls from 0.7941 to 0.5955, and the
  `check_ml` gate now fails above a 0.02 Umbrella FPR.
- The README's CI badge is back. Its removal at 1.0.0 named the condition for
  restoring it (a public repository, and a signed-out fetch that answers) and
  publication met it.
- CI runs on a read-only token (`contents: read`) and cancels superseded
  pull-request runs. Pushes to `main` are exempt: that run is what the badge and
  the required status check read.
- Dependency updates arrive as one grouped pull request per ecosystem, monthly.
  The first scheduled run opened nine at once, and each of those needs a decision
  rather than a merge.
- The suite now fails on a coverage floor (`[tool.coverage.report]` in
  `pyproject.toml`, set below the measured figure so a refactor may move lines and
  a new detector may not ship untested).
- `tests/detectors/test_ml.py` compares every channel against the committed column
  order pin rather than only against a restored artifact, so the two channels
  whose boosters are not distributed are covered as well as the two that are.
- The flow-context evaluation axis speaks the official corpus headers now: the
  CIC-IDS2017 map covers all 15 official labels (DoS GoldenEye, Hulk,
  slowhttptest, slowloris, Heartbleed, the three WebAttack variants,
  Infiltration, Bot, PortScan, DDoS), the CIC-DDoS2019 map is complete
  (WebDDoS included) and UNSW-NB15 has its own map on `attack_cat`.
  `bench_transfer.normalize_columns` accepts the official column names
  ("Total Fwd Packets", "Flow Bytes/s", and the rest) and maps "Flow Duration"
  to microseconds rather than seconds. Without both, whole-corpus scoring
  silently dropped or mislabelled most of the rows.

### Fixed
- `run_web.sh`, `run_web.bat` and the launch examples now invoke the wall as
  `python -m apps.mission_control.server`. Running the file path directly could
  not satisfy the server's package-relative imports and failed before binding,
  so the documented one-line launch was broken.
- Rule evaluation no longer paints every flow of an alerted entity for a whole
  capture. An alert labels only flows on its own entity inside its own 10-second
  window, unmapped truth is excluded instead of entering the benign denominator,
  and every rules cell reports exact and any-attack alert precision plus
  incident recall over `(window, entity, class)`. The corpus spellings for
  `DDoS attacks-LOIC-HTTP` and `UDP-lag` are mapped, so those attack flows are
  no longer counted on the benign side.
- A second full-corpus pass after the slow-DoS changes supersedes the alert
  counts and CIC-IDS2017 FPR in the entry below: 85 alerts with exact precision
  80/85 = 0.941176, 5 benign-only, slow-DoS recall 28/46, and benign FPR
  5,453/2,273,108 = 0.00239892. DDoS flow and CIC-DDoS2019 cells are unchanged.
  The ten added slow windows paint 94 more benign flows but create no new
  benign-only alert.
- The full-corpus record is republished with the corrected denominators: all
  four pre-committed gates pass (CIC-IDS2017 F1 0.989026 / FPR 0.00235757,
  CIC-DDoS2019 F1 0.996426 / FPR 0.00044804), and the old 1.0 / 0-of-392 and
  0.797 flow FPR figures are withdrawn. The CIC-IDS2017 margin is 0.039 and its
  5 benign-only alerts stay on the page.
- The wall's live socket (`/ws/live`) was not covered by `DIODE_WALL_TOKEN`: a
  WebSocket handshake is not an HTTP request, so the middleware that guarded
  `/api` never saw it and the whole alert stream stayed open. The handshake is
  checked now and closed with 1008 before it is accepted.
- The wall's policy allowed `connect-src 'self' ws: wss:`, and a bare `ws:` scheme
  source permits a socket to any host that speaks WebSocket. `'self'` already
  covers this origin.
- An exported evidence digest could not be checked by anyone holding only that
  file; `attest.verify_digest` and `--verify` close that, and a digest of a broken
  chain never reports a clean verification.
- The reference-IDS harness reported `0 alerts` for a tool that exited non-zero.
  A crashed run now reports unknown, because a partial log counted as zero reads
  as a clean pass at unusually low cost.
- `integration.yml` piped pytest through `tee` without `pipefail`, so a failing
  suite exited 0 and the job would have reported success.
- The SBOM stamped itself with a 1970 timestamp and an `unknown` application
  version; it now records the build time, keeps `SOURCE_DATE_EPOCH` for
  reproducible builds, and reads the version from `pyproject.toml`.
- Both corpus fetchers re-stamped a skipped file's manifest entry with the current
  time (and `download_ml_corpora.py` also rewrote its SHA256), so a re-run made a
  file look freshly downloaded and moved the provenance clock. A skipped file keeps
  its original pin; a file the manifest never recorded is backfilled from its mtime.
  `docs/datasets.md` now records that all 54 on-disk corpus files are pinned, and its
  row counts were corrected: CIC-IDS2017 is 8 files over 5 capture days, and
  CSE-CIC-IDS2018 is 16,233,002 rows with 7 capped day-files, not 17.28M with 8.
- Two CSE-CIC-IDS2018 ML cells errored in the whole-corpus pass because the
  window builder drops rows without a usable clock while the truth slice stayed
  at 200,000 rows, so truth and predictions were 8 and 12 rows apart. The truth
  follows the same mask now, the dropped rows are counted in the artifact, and a
  length mismatch raises instead of scoring shifted labels.
- The CIC-IDS2017 register row carries the measured 2,830,743 real flow rows
  (288,602 all-null padding rows from the doubled WebAttacks header excluded and
  counted), and the full-corpus driver reports truth rows it had to exclude
  (2,002 CIC-IDS2017, 200,786 CSE-CIC-IDS2018, 96,586 UNSW-NB15) instead of
  leaving them out of the totals silently.

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

