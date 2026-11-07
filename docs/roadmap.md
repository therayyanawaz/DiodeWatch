# Roadmap

The programme ran for **13 weeks**, 2026-08-25 → 2026-11-20. Each week ends in a
tagged release; the table below is the schedule the work was actually delivered
on, and every row is backed by commits in this repository.

| Week | Dates | Milestone | Release |
|---|---|---|---|
| 1 | Aug 25 – Aug 31 | Flow record, feature registry and the rule channels | `v0.1.0` |
| 2 | Sep 1 – Sep 7 | Alert schema and store, diode guard, ML channels | `v0.2.0` |
| 3 | Sep 8 – Sep 14 | Packaging, launchers, checks, first docs | `v0.3.0` |
| 4 | Sep 15 – Sep 21 | Throughput and accuracy harness, corpus ledger | `v0.4.0` |
| 5 | Sep 22 – Sep 28 | System-1 triage channel, deterministic demo pack | `v0.5.0` |
| 6 | Sep 29 – Oct 5 | Analyst dashboard, mission-control backend, CI | `v0.6.0` |
| 7 | Oct 6 – Oct 12 | WAF harness, tamper-evident evidence chain | `v0.7.0` |
| 8 | Oct 13 – Oct 19 | Executable claim guardrail, packaging layout | `v0.8.0` |
| 9 | Oct 20 – Oct 26 | Cross-corpus evaluation snapshot and model pins | `v0.9.0` |
| 10 | Oct 27 – Nov 2 | React wall: build, types, first panels | `v0.10.0` |
| 11 | Nov 3 – Nov 9 | React wall complete, shipped bundle, pipeline doc | `v0.11.0` |
| 12 | Nov 10 – Nov 16 | Team docs, ownership map, demo script, README | `v0.12.0` |
| 13 | Nov 17 – Nov 20 | Bundle gate, honest badge retirement, 1.0 | `v1.0.0` |

## Where the work went

- **Detection core** — the summary record is built once in `src/ingest/` and
  measured once in `src/features/`, so a rule channel and a model read the same
  numbers. Channels that cannot meet their quality gate on new data disable
  themselves and say so.
- **Evidence** — every alert carries the flows that produced it, lands in a
  tamper-evident chain, and exports as STIX 2.1 or as an analyst report. The
  same alert identity answers the same on every surface.
- **The wall** — one React client over the routes the backend already answers;
  the shipped bundle is committed so the offline launch asks nothing of the
  host, and CI rebuilds it and fails unless the shipped bytes match their
  source.
- **Proof** — the diode panel reports what the host actually measured. Where
  the kernel refused the packets it says so; where nothing could be observed it
  withholds the number instead of printing a zero.

## Beyond 1.0

Open items are tracked in [`docs/competition/readiness.md`](competition/readiness.md)
under "Next action", each with the environment it needs. Nothing there is
promised for a date.
