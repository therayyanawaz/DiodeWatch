# Status and what is next

This page is the honest answer to "where does DiodeWatch stand, and what does it
not do yet". It is written for whoever is reading the repository cold: a judge, a
reviewer, a team picking it up.

Two rules govern it:

* **Every figure with a pinned artifact is re-derived by CI.**
  `scripts/checks/check_claims.py` reconciles the documented metrics against the
  artifacts and the published suite size against pytest itself, and fails the
  build when one drifts. Figures without an artifact behind them are marked as
  such rather than presented as measured.
* **The "not yet" list is real.** An unfinished item stays visible here and in
  `docs/competition/readiness.md` rather than being quietly dropped, because a
  status page that only lists successes is a brochure.

## Shipped and verified

The 1.0.0 release is the detection stack, end to end, with the evidence to back
each claim:

* **Ingest and features:** capture and flow-table readers, one frozen 73-feature
  registry, parity-checked against the CICFlowMeter schema.
* **Detection:** rule, window-ensemble, flow-context, DGA/tunnel, beacon,
  TLS/JA3 novelty and triage channels, each with a run record under
  `docs/evaluation/runs/`.
* **Evidence:** a hash chain over every alert row, an append-only ledger, incident
  packs, STIX 2.1 and report export, and an off-box digest that a third party can
  verify without this repository.
* **Surfaces:** the Streamlit dashboard and the mission-control wall at `:8530`,
  both offline, both reading the same store.
* **Guards:** a claim guardrail, a documentation link check, a coverage floor, a
  CycloneDX SBOM per build, and a dependency lock.

## Recently landed, after 1.0.0

* **Wall hardening.** Every response carries a strict policy (`frame-ancestors
  'none'`, `script-src 'self'`, `connect-src 'self'`), a configured
  `DIODE_WALL_TOKEN` protects `/api` **and** the `/ws/live` alert stream, and a
  non-loopback bind refuses to start without one.
* **Off-box anchoring.** `src/alerts/attest.py` exports a canonical digest of the
  chain and an RFC 3161 request that binds it to a wall clock. `--verify` checks
  one from its own bytes; a digest of a broken chain never verifies clean.
* **Accessibility.** Every control has an accessible name, the listbox announces
  its active option, tooltips are wired as descriptions, and no focus indicator is
  removed without a replacement.
* **Column-order pin.** `docs/models/feature_order.json` records the training
  order for all four scoring channels, including the two whose boosters are not
  distributed, so a reorder fails a test instead of silently falsifying results.
* **Model cards.** `docs/models/` documents what each shipped artifact reads, what
  it decides, its operating point, its provenance, its limits, and the digest of
  its exact bytes.
* **Threat model.** `docs/threat-model.md` walks the three trust boundaries in
  STRIDE, names what is implemented where, and names what is out of scope.
* **Comparison harness.** `scripts/benchmarks/bench_reference.py` measures
  Suricata or Zeek on one capture beside our own pass, reporting volume and cost
  only, and exits with a distinct code when the tool is absent instead of printing
  a row for a run that never happened.
* **Full-scale evaluation.** All 50 pinned files of five corpora, 109,643,423
  flows, scored in one pass and published in
  [`evaluation/runs/max_scale.md`](evaluation/runs/max_scale.md). Two of the four
  pre-committed gate checks pass; both CIC-IDS2017 failures stay on the page.
* **Window-scoped attribution and alert-level scoring.** A rule alert now labels
  only its own entity inside its own 10-second window, and every rules cell
  reports exact precision, any-attack precision and incident recall `(window,
  entity, class)`. The full pass gives CIC-DDoS2019 exact precision 0.919 but
  incident recall 0.122, and CIC-IDS2017 exact precision 0.084 with 523 of 594
  alerts benign-only. The old 0.845 and 0.797 flow FPRs were attribution and
  label artifacts; they are withdrawn.
* **The suite** collects 498 tests. Three of them need corpora this repository
  deliberately never commits, so they skip locally and run in
  `.github/workflows/integration.yml`, which fails if they skip there.

## What is next

Ordered by what would embarrass us first. "Blocked" means an environment we do not
have, not a decision we have not made.

| Item | Why it matters | State |
|---|---|---|
| Rule precision on benign windows: per-destination baselines, source-IP entropy, dedup | alert-level scoring shows the gap directly: CIC-IDS2017 exact precision is 0.084 with 523 of 594 alerts benign-only, and CIC-DDoS2019 DDoS incident recall is 0.122 | **next** |
| Pin the two retrained channel artifacts, or delete the rows that depend on them | an unpinned artifact cannot be re-scored | **next** |
| Flow-record ingest: Argus CSV, nfdump CSV, goflow2 JSON | the PS accepts NetFlow/IPFIX/sFlow and CTU-13, 19,976,700 flows, is unscored for rules and flow context | **next** |
| JA4 and JA4S over TLS, QUIC observable metadata | PS clause (d) names JA4; only JA3 is shipped and QUIC has no reader | **next** |
| Scan and slow-DoS recall on CIC-IDS2017 | the port-scan day scores recall 0; slow-DoS scores 0 | **next** |
| DGA false-positive work on Umbrella hard negatives | 0.1076 FPR at the operating threshold is not usable | **next** |
| Packet-to-alert clock, bounded queue, backpressure at 5k/10k/50k flows/s | the 175 ms figure is window-evaluation p95, not end-to-end latency | planned |
| Calibration and conformal abstention per channel | confidence is not calibrated and no alert can abstain | planned |
| Drift alarm that makes a channel abstain, not just a chart | PSI is published as an explanation, not acted on | planned |
| OCSF Detection Finding export beside STIX | SOC interoperability a judge can name | planned |
| Rootless diode proof: container `--network=none` self-test and a PowerShell elevated path, with the enforcement mode wired into both UIs | the one-way guarantee is demonstrated on Linux with root today; a reviewer on a laptop cannot reproduce it | **blocked** on Docker or administrator rights |
| Live-interface rehearsal over a veth pair, with a recorded clip | proves the pipeline under enforcement on a real interface, not only on a replay | **blocked** on Linux root |
| Reverse proxy, TLS, and a service unit pinning **one worker** | the wall is plain HTTP on loopback; the shared session is per process, so multiple workers would fragment it | planned |
| Rate limit, request-size cap and `TrustedHost` on the wall | a token holder can drive the replay in a loop | planned |
| An authentication story for the Streamlit dashboard | it is a second, unprotected surface | planned |
| One config module that validates every environment variable at startup | the variables are read at their call sites, so a typo fails at use time | planned |
| Schema versioning and a migration path for the alert store | tables are created if absent, with no version recorded | planned |
| A daemon entry point for triage | triage ticks only while a dashboard session is open | planned |

## What we deliberately do not do

Naming these keeps the list above honest:

* **No CORS.** The wall is same-origin by design; nothing should call it from
  another origin.
* **No in-app TLS, no RBAC, no multi-tenancy.** One analyst, one host, one wall.
  Termination belongs in a reverse proxy, and pretending otherwise would add
  surface without adding safety.
* **No public API documentation routes.** `docs_url` and `redoc_url` stay off.
* **No claim of container or process-level enforcement** until the rootless proof
  above is closed.

## How to check this page yourself

```bash
python -m pytest tests/ -q                    # the suite, and what it skips
python -m scripts.checks.check_claims         # metrics, test counts, commands, wording
python -m src.alerts.attest --verify <file>   # a digest, with nothing else installed
```

The two workflow files are the machine half of this page:
`.github/workflows/ci.yml` runs on every push, and
`.github/workflows/integration.yml` fetches the corpora and requires the
corpus-gated cells to run.
