# Status and what is next

This page is the honest answer to "where does DiodeWatch stand, and what does it
not do yet". It is written for whoever is reading the repository cold: a judge, a
reviewer, a team picking it up.

Two rules govern it:

* **Every number here is re-derived by CI.** `scripts/checks/check_claims.py`
  reconciles the figures in the documentation against the pinned artifacts and
  against pytest itself, and fails the build when one drifts. Nothing on this page
  is hand-maintained.
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
* **The suite** collects 465 tests. Three of them need corpora this repository
  deliberately never commits, so they skip locally and run in
  `.github/workflows/integration.yml`, which fails if they skip there.

## What is next

Ordered by what would embarrass us first. "Blocked" means an environment we do not
have, not a decision we have not made.

| Item | Why it matters | State |
|---|---|---|
| Rootless diode proof: container `--network=none` self-test and a PowerShell elevated path, with the enforcement mode wired into both UIs | the one-way guarantee is demonstrated on Linux with root today; a reviewer on a laptop cannot reproduce it | **blocked** on Docker or administrator rights |
| Live-interface rehearsal over a veth pair, with a recorded clip | proves the pipeline under enforcement on a real interface, not only on a replay | **blocked** on Linux root |
| Reverse proxy, TLS, and a service unit pinning **one worker** | the wall is plain HTTP on loopback; the shared session is per process, so multiple workers would fragment it | planned |
| A health check that reads the store, plus a metrics endpoint | `/api/health` answers a constant today, so a healthy process can still be unable to serve evidence | planned |
| Retention and backup for the alert store and the ledger | they grow without bound and live on one disk | planned |
| Structured logging with rotation and an access log | the backend logs nothing today | planned |
| One config module that validates every environment variable at startup | the variables are read at their call sites, so a typo fails at use time | planned |
| Rate limit, request-size cap and `TrustedHost` on the wall | a token holder can drive the replay in a loop | planned |
| An authentication story for the Streamlit dashboard | it is a second, unprotected surface | planned |
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
