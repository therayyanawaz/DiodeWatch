# Alert Schema, Evidence Store & Exports

Make alerts **SOC-ready**: one stable, self-describing envelope from every
detector (rules and ML), persisted to an indexed SQLite evidence store, and
exportable as STIX 2.1 bundles and human-readable incident reports, fully
offline, stdlib-only, no runtime network calls.

## The alert schema (`src/alerts/schema.py`)

One `Alert` dataclass (plain, zero-dependency) is the contract every detector
emits (`detectors.base`, `detectors.ml.*`, `ml_engine`) and every sink
consumes. `to_dict()` produces JSON-safe plain types:

| Field | Meaning |
|---|---|
| `alert_id` | stable `uuid5` over the detection payload → re-ingesting the same detection is idempotent |
| `timestamp` | ISO-8601 UTC (detection time / window end) |
| `flow_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto` | flow 5-tuple; best-effort, flow-level detectors (rules, ML on features) fill it, aggregate/window alerts may leave parts unset |
| `threat_class` | `ddos` · `scan` · `exfil` · `slowdos`-family · `bot` · `beacon` · `dga` · `dns_tunnel` · `tls_anomaly` · `bruteforce` · `webattack` · `infiltration`, of these, `dns_tunnel` is a severity/ATT&CK mapping kept for a channel no detector ships yet; `slowdos` is a live rule class (`src/detectors/slowdos.py`), while the pinned ML classifier still folds it into `ddos` until its artifacts are retrained |
| `severity` | **derived, never hand-set**: base from `SEVERITY_BY_CLASS` (exfil/webattack `critical`, most C2/DoS `high`, scan `medium`); a very confident alert (conf ≥ 0.9) escalates one notch; unknown classes stay `medium` without escalation |
| `confidence` | 0..1 (rules: fired-conditions fraction; ML: calibrated prediction probability) |
| `evidence[]` | `{condition, operator, observed, threshold, description, unit}`, observed **vs** threshold, human-auditable |
| `detector` | module id, e.g. `ddos`, `ml.flowctx`, `ml.beacon` |
| `attack_technique`, `attack_tactic`, `att&ck_techniques[]` | MITRE ATT&CK mapping (list form for exports) |
| `window_start/end`, `window_seconds`, `key`, `label` | window bounds, aggregated entity, ground truth when known (eval only) |

`validate_alert()` enforces the contract (timestamp, known class, confidence
∈ [0,1], evidence present, severity ∈ ladder, alert_id is a UUID, ports in
range); `alert_from_dict()` rebuilds alerts from any stored/exported dict -
**old-format files without the SOC-schema keys reparse cleanly** (severity and
alert_id are derived on rebuild).

Severity ladder (deterministic):

```text
base: exfil/webattack → critical     ddos/bot/beacon/dga/dns_tunnel/
      tls_anomaly/bruteforce/infiltration → high      scan → medium
escalate (conf >= 0.9): medium → high · high → critical     unknown class → medium (no escalation)
```

## Evidence store (`src/alerts/store.py`)

`AlertStore(db_path)`, SQLite (stdlib `sqlite3`, WAL journal, `synchronous=NORMAL`):

* one row per alert, evidence as a JSON document, `ts_epoch` derived from the
  ISO timestamp for sortable indexed queries;
* indexes: `ts_epoch DESC` (recency), `threat_class`, `severity`,
  `src_ip`, `dst_ip`;
* `insert_many(alerts)` → `(inserted, duplicates, invalid)`; thousands of
  inserts commit per-2,000 batch; `alert_id` PK with `INSERT OR IGNORE`
  makes re-ingestion idempotent;
* `recent(limit, threat_class=, severity=, since_epoch=)`, newest-first,
  single indexed scan;
* `between(start_iso, end_iso)`, the incident-window query (chronological);
* `count() / count_by(column) / stats()`.

JSONL is the shared serialization contract with the detectors (one
`to_dict()` object per line): `write_jsonl()` / `iter_jsonl()` /
`ingest_jsonl()`. `iter_jsonl` also tolerates a single top-level JSON array.

## STIX 2.1 export (`src/alerts/export_stix.py`)

Offline hand-built bundle (the `stix2` library is deliberately **not** a
dependency, nodal centres are air-gapped and the requirements stay small).
Emitted object types, all with deterministic `<type>--uuid5` ids and
`created_by_ref` naming the producer:

* `identity`, the analytics enclave (producer);
* `attack-pattern`, one per ATT&CK technique, `external_references` to the
  public matrix (no network call). 2.1 deprecated `kill_chain_phases` and the
  `indicates` relationship, so the technique reference plus the tactic in the
  description is the mapping, and nothing SRO-links an indicator to its
  observation: the pattern and the observed value already name the same thing;
* `indicator`, one per alert: `pattern` over the alert's best observable (dst
  endpoint → src → key IP/domain → beacon-key dst) with the required
  `pattern_type: "stix"` and `pattern_version`, `valid_from`, `confidence`
  0-100, severity in the description. `indicator_types` leads with the term
  2.1 recommends for the alert's severity (`malicious-activity` /
  `suspicious-activity` / `anomalous-activity`, derived from the same ladder
  the alert carries) and adds the threat class, which the open vocabulary
  allows, so a consumer filtering either way finds the record.
* `observed-data`, the alert as one observation (`first_observed`,
  `last_observed`, `number_observed: 1`) whose `object_refs` name the 2.1
  first-class cyber observables (`ipv4-addr` / `ipv6-addr` / `domain-name`)
  carried beside it, one object per distinct value, shared by every
  observation that saw it.

Honest limitations: patterns are single-item equality patterns (no boolean
composition); alerts with **no** observable (no IP/domain anywhere) fall back
to a never-matching sentinel pattern and carry the full detail in the
description, observed-data is omitted rather than fabricated. `confidence` is
the detector's own score scaled to 0-100, not a calibrated probability.
`validate_bundle()` enforces the 2.1 shape before writing: ids are
`<type>--<uuid>`, indicators carry `pattern_type`/`indicator_types` and none of
the 2.0-era `labels`/`kill_chain_phases`, observations use `object_refs` rather
than the 2.0 `objects` map, observables are value-only objects with no SDO
properties, and every reference resolves. The reason it is that strict: a bundle
of bare UUIDs is JSON, but no TAXII server, SIEM or `stix2` parser will take it.

## Incident report (`src/alerts/report.py`)

`write_report(alerts, path, title=)` renders a **self-contained HTML** file
(zero external assets; print-to-PDF from the browser if a hard copy is
wanted): summary by class and severity, then per alert the envelope,
ATT&CK mapping, 5-tuple, evidence table (condition · observed vs threshold ·
description · unit), and the advisory Laya triage verdict when the alert
carries one.

`render_report_page(alerts, title=)` renders the same per-alert facts as the
page behind the wall's `/report/{alert_id}` route, on the console's own
stylesheet instead of an inline one. Both go through the same `_five_tuple`
and `triage_line` helpers, so an exported file and the page a judge opens
in the console cannot disagree about what an alert contained. The 5-tuple
names only the endpoints a detector actually saw (`dst 10.9.9.9` for a fan-in
alert rather than empty octets), and the triage line reads the engine's own
`recommended` key and omits fields the verdict does not carry.

Neither renderer opens the side table: a surface that wants the advisory trail
asks `src.alerts.triage_store.join_verdicts` first, so a report prints the
verdicts the pipeline recorded rather than only the ones that happen to be in
this process's memory. The join returns copies, an alert the wall is still
broadcasting must not change because somebody downloaded its report.

Threat classes print through `schema.display_class`, the one table that names
them for a reader (`Recon Scan`, `C2 Beacon`; a class nobody named keeps its
own words upper-cased, a blank one prints `UNCLASSIFIED`). The report used to
pass the detector's identifier straight through, which is how the same alert
was "Recon Scan" on both screens and "scan" on the page printed from it. Both
renderers take their timestamp from one `_generated()` helper, printed as
`generated 2026-09-04 01:00:00 UTC`, the file is exported to PDF by hand at
demo time, so a duplicated zone (`…+00:00 UTC`) was visible on the paper.

## CLI

```bash
python -m src.alerts.cli store  --alerts alerts.ndjson --db alerts.db [--jsonl out.ndjson]
python -m src.alerts.cli recent --db alerts.db [--limit 50] [--class ddos] [--severity critical]
python -m src.alerts.cli stats  --db alerts.db
python -m src.alerts.cli report (--alerts f.ndjson | --db alerts.db [--window-start T --window-end T]) --out incident.html
python -m src.alerts.cli stix   --alerts f.ndjson --out bundle.json
```

## Acceptance (`scripts/checks/check_alerts.py`, exit 0 = pass)

Verified 2026-09-05 on the ml_engine full-day corpus:

* **insert thousands error-free**: 50,000 real alerts ingested in seconds;
  every row passes `validate_alert`; re-ingesting the first 5,000 inserts 0
  duplicates (idempotent by stable `alert_id`);
* **schema audit**: severity ∈ ladder, UUID alert_ids, evidence present on
  100% of the sample;
* **quick queries**: `recent(20)` newest-first plus class/severity filters
  answer in milliseconds over the 50k-row store;
* **STIX 2.1**: class-balanced bundle exports with clean structural
  validation;
* **incident report**: every alert block renders with its evidence rows
  (condition, observed vs threshold, description, unit) and the flow 5-tuple
  when the detectors supplied it.
