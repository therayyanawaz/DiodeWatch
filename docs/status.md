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

* **Ingest and features:** capture, flow-table and flow-export readers, one
  frozen 73-feature registry, parity-checked against the CICFlowMeter schema.
* **Detection:** rule, window-ensemble, flow-context, DGA/tunnel, beacon,
  TLS/JA3 novelty (with JA4 context) and triage channels, each with a run record
  under `docs/evaluation/runs/`.
* **Evidence:** a hash chain over every alert row, an append-only ledger, incident
  packs, STIX 2.1 and report export, and an off-box digest that a third party can
  verify without this repository.
* **Surfaces:** the Streamlit dashboard and the mission-control wall at `:8530`,
  both offline, both reading the same store.
* **Guards:** a claim guardrail, a documentation link check, a coverage floor, a
  CycloneDX SBOM per build, and a dependency lock.

## Recently landed, after 1.0.0

* **DGA false-positive budget.** The DGA cut now maximizes recall subject to a
  0.5% benign FPR on family-holdout OOF, replacing the 90%-precision rule that
  let roughly 11% of the independent Umbrella holdout through. At threshold
  0.9321 the known-corpus figures are precision 0.9708 and recall 0.5955, while
  Umbrella FPR falls from 0.1076 to 0.01864; the recall cost is explicit and the
  `check_ml` gate fails above 0.02.
* **TLS and QUIC metadata.** `src/ingest/tls_metadata.py` reads a pcap, reassembles
  a TLS handshake across TCP segments, and computes JA3, JA3S, JA4 and JA4S from
  the real ClientHello/ServerHello bytes. It also aggregates QUIC on UDP/443:
  version, connection IDs, long-header packet type, packet sizes and
  inter-arrival gaps per flow. QUIC Initial payloads are never decrypted, so no
  QUIC JA4 is claimed. JA4/JA4S reach the TLS alert evidence as context; the
  pinned abuse.ch list is still a JA3 list and the evaluated channels are
  unchanged.
* **Flow-export ingest.** `src/ingest/flow_reader.py` reads Argus CSV (including
  CTU-13 `.binetflow`), nfdump CSV (header or headerless) and goflow2 JSON/NDJSON
  into the same 47-field records as the capture and CIC readers. `unify.py` sniffs
  a `.csv` header for the format and accepts `--format argus|nfdump|goflow2` when
  it is ambiguous. A flow export publishes a final flag set, not per-packet
  counts, and nfdump/goflow2 publish one counter pair, so absent flags and timing
  fields stay null instead of becoming zeros; CTU-13 therefore remains not
  evaluable for rules and flow context.
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
* **Pinned flow-context and TLS artifacts.** The 2,326,265-byte CIC-IDS2017
  flow-context ensemble and the 97,163-byte TLS watchlist/novelty model now
  live in `docs/evaluation/models/`, rebuilt on scikit-learn 1.9.0, with cards
  and card tests. The retrained phase records and the supervised reference were
  withdrawn because their bytes were never preserved; the zero-shot phase and
  the full-corpus pass remain, both tied to pinned artifacts.
* **Full-scale evaluation.** All 50 pinned files of five corpora, 109,643,423
  flows, scored in one pass and published in
  [`evaluation/runs/max_scale.md`](evaluation/runs/max_scale.md). All four
  pre-committed gate checks pass; the CIC-IDS2017 F1 margin is 0.039, and the
  pass is still reported with its remaining alert-level weaknesses beside it.
* **Window-scoped attribution and alert-level scoring.** A rule alert now labels
  only its own entity inside its own 10-second window, and every rules cell
  reports exact precision, any-attack precision and incident recall `(window,
  entity, class)`. The full pass gives CIC-DDoS2019 exact precision 0.993 with no
  benign-only alert but incident recall 0.118, and CIC-IDS2017 exact precision
  0.941 with 5 of 85 alerts benign-only. The old 0.845 and 0.797 flow FPRs
  were attribution and label artifacts; they are withdrawn.
* **Rule precision on CIC-IDS2017.** A 500 kB exfil ratio floor removed 61 small
  benign uploads (the old floor was 10 kB), and dropping the scan host-sweep
  branch removed 29 benign windows and zero scan truth units. A 20 KB/s byte
  floor below 250 flows/s then removed the last busy-server DDoS claim, and a reply-aware
  multi-port gate removed 26 fan-in or high-port sweeps. Benign-only alerts
  fell from 122 of 192 to 5 of 85, exact precision rose from 0.365 to 0.941,
  and DDoS flow recall stayed at 0.979 with precision rising from 0.947 to
  0.999. The 5 remaining are 2 scan, 2 exfil and 1 slowdos; the scan and exfil
  shapes still present are large or high-port sessions that satisfy every gate.
* **Slow-DoS recall.** Raising the request ceiling from 160 B to 300 B covers
  CIC-IDS2017 Slowhttptest (169-296 B), and a first window with 100 flows and
  100 held connections now survives corroboration. Slow-DoS truth recall rose
  from 18/46 to 28/46 with no new benign-only slow alert; the one remaining
  benign slow alert is the Thursday Infiltration 40-flow window.
* **The suite** collects 538 tests. Three of them need corpora this repository
  deliberately never commits, so they skip locally and run in
  `.github/workflows/integration.yml`, which fails if they skip there.

## What is next

Ordered by what would embarrass us first. "Blocked" means an environment we do not
have, not a decision we have not made.

| Item | Why it matters | State |
|---|---|---|
| Scan and slow-DoS recall on CIC-IDS2017 | slow-DoS is 28/46 after the 300 B and strong-window fixes; scan is 11/222 canonically, but 195 units are Patator/web attacks folded into scan and the port-sweep rule covers 11/27 PortScan units | **partly done** |
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
