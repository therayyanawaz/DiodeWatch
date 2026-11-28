# OCSF 1.10 Detection Finding export

DiodeWatch already exports STIX 2.1 for threat-intelligence tooling and an HTML
incident report for a human reader. This export adds the third contract a SOC
can name: an OCSF Detection Finding stream that a SIEM, SOAR or data lake can
ingest without a bespoke adapter.

The implementation is in `src/alerts/export_ocsf.py`. It uses only the Python
standard library, performs no network or model call, and has no OCSF package
dependency. The schema version is pinned rather than imported so a build cannot
change its output because a transitive package updated.

## Version pin

| Item | Value |
|---|---|
| OCSF schema release | **v1.10.0**, the latest stable release at implementation time (2026-11-28) |
| Release tag commit | `9695d9beb6565e2a1df49ded27d9bcbe55a38a43` |
| Emitted `metadata.version` | `1.10.0` |
| Class | Detection Finding, `class_uid` **2004** |
| Category | Findings, `category_uid` **2** |
| Activity | Create, `activity_id` **1** |
| Event type | `type_uid` **200401**, `type_name` `Detection Finding: Create` |

The upstream `main` branch is `1.11.0-dev` and is not a release. This exporter
does not follow it. A version bump needs a review of the required fields and
enums against the next tagged release, plus a regenerated expected event in
`tests/alerts/test_export_ocsf.py`; it is not a one-line constant change.

## What one alert becomes

One alert becomes one event. The exporter does not merge alerts, invent a
lifecycle, or wrap the events in a bundle. Because OCSF defines event objects
rather than a file envelope, a batch is written as JSONL: one compact JSON
object per line. A single-alert file is therefore one line that is also one
valid JSON document. That is why the mission-control route can return a normal
`application/json` response while the CLI appends lines for a batch.

### Identity and time

| OCSF field | Source | Meaning |
|---|---|---|
| `finding_info.uid` | `alert_id` | Stable finding id; deterministic UUIDv5 fallback only for an alert with no id |
| `metadata.uid`, `metadata.correlation_uid` | same id | Lets a consumer correlate the event with the alert and the finding |
| `time` | `timestamp`, then `window_end` | When the detector created the finding (the alert timestamp, normally the end of its window), not the start of the traffic and not the export clock |
| `finding_info.created_time` | same as `time` | The same detection instant at the finding level; the alert store keeps no separate record-insertion time |
| `start_time`, `end_time` | `window_start`, `window_end` | The contributing activity window |
| `finding_info.first_seen_time` | `window_start` | First activity time, not detection time |
| `finding_info.last_seen_time` | `window_end` | Last activity time |
| `metadata.original_time` | `timestamp` | The source timestamp normalized to UTC RFC3339 with milliseconds |

An alert with neither a parseable `timestamp` nor `window_end` is refused. The
exporter does not stamp the current clock, a zero epoch, or the export time on
an alert whose event time is unknown.

### Classification and confidence

| Alert | OCSF |
|---|---|
| `severity` low, medium, high, critical | `severity_id` 2, 3, 4, 5 with `severity` Low, Medium, High, Critical |
| missing or unknown severity | `severity_id` 0, `severity` Unknown |
| `is_alert` | always `true` |
| finding status | `status_id` 1, `status` New; this is lifecycle, not the analyst's triage verdict |
| `confidence >= 0.9` | `confidence_id` 3, `confidence` High |
| `confidence >= 0.7` | `confidence_id` 2, `confidence` Medium |
| `confidence > 0` | `confidence_id` 1, `confidence` Low |
| `confidence <= 0` or unavailable | `confidence_id` 0, `confidence` Unknown |
| `confidence_score` | `round(confidence * 100)`, clamped to 0..100 |

The confidence is the value stored on the alert. For calibrated ML channels that
is the calibrated confidence; for rules it is the detector's score, not a
probability of intrusion. The OCSF labels do not add calibration.

### Analytic and ATT&CK

`finding_info.analytic` names the detector:

* `uid` and `name` are the detector id, or `diodewatch.unknown` when absent;
* `type_id` is **4** (Learning) for an id beginning `ml`, otherwise **1** (Rule);
* `version` is the product version, pinned at `1.0.0` to match `pyproject.toml`.

The ATT&CK fields come from the alert's existing tactic and technique, never
from a lookup that could add a mapping the detector did not record. A dotted
technique id is split the way OCSF models it: `T1568.002` becomes
`technique.uid = T1568` and `sub_technique.uid = T1568.002`, with the mapped
name on the sub-technique. A base technique that is not in the project's
`ATTACK_MAP` keeps its id and omits the name rather than inventing one.

### Evidence, endpoints and query

`evidences[0]` is the finding's evidence object:

| Field | Content |
|---|---|
| `uid` | The same stable finding id |
| `name` | Detector id, or `<threat class> evidence` |
| `data` | Alert id, threat class, severity, detector, confidence, flow id, key, window bounds and seconds, ATT&CK ids, and the complete `EvidenceItem` list (condition, operator, observed, threshold, description, unit) |
| `src_endpoint`, `dst_endpoint` | Emitted only when the alert carries the IP or port |
| `query.hostname` | Emitted only for the `dga` and `dns_tunnel` classes, when the key is a valid queried domain (a dotted IP is not) |

The free-form `data` object is deliberate: OCSF has no first-class field for
"observed 695.4 flows/s against a threshold of 500", and dropping that detail
would turn an auditable finding into a label. The alert's original evidence is
preserved inside the event. Other classes do not get a synthetic DNS query just
because their key happens to look like a domain.

### Observables

Observables are pointers, not new facts. Each `name` resolves to a field already
present in the event and each `value` is compared with that field before the
event can be written:

| Observable name | Type | Emitted when |
|---|---|---|
| `evidences[0].src_endpoint.ip` | IP Address, type 2 | the alert has a source IP |
| `evidences[0].dst_endpoint.ip` | IP Address, type 2 | the alert has a destination IP |
| `evidences[0].query.hostname` | Hostname, type 1 | the class is `dga` or `dns_tunnel` and the key is a domain |

Duplicates are removed. If the alert carries no endpoint or DNS hostname, the
`observables` key is omitted rather than filled with the destination port, the
flow id, or a hostname parsed out of a five-tuple.

## Usage

### Command line

```bash
python -m src.alerts.cli ocsf --alerts data/alerts/alerts.ndjson \
    --out data/alerts/ocsf_findings.jsonl
```

The command prints the alert count and event count to stderr. Exit **0** means
every event validated and the file was written; exit **2** means validation
failed and **no new output is written** (an existing file is left untouched).
`--limit N` caps the batch at the first N alerts through the same loader as the
STIX export; it does not reorder the file.

A single alert can be exported from the API or with the same Python call:

```python
from src.alerts.export_ocsf import write_ocsf

events, problems = write_ocsf(alerts, "data/alerts/ocsf_findings.jsonl")
if problems:
    raise SystemExit(problems)
```

### Mission control and analyst surfaces

| Surface | Path or control | Response |
|---|---|---|
| Mission control API | `GET /api/export/ocsf/{alert_id}` | One Detection Finding as `application/json` |
| Mission control wall | `OCSF 1.10 FINDING` in the evidence drawer | Opens the API route |
| Streamlit dashboard | `Build OCSF 1.10 finding` then the download button | `ocsf_detection_<class>.json` |

All three end at `write_ocsf`. A validation failure is an error at the surface,
not a partial file left for a downstream job to ingest.

## Validation scope

`validate_event` is a focused structural check over the subset this exporter
emits. `write_ocsf` runs `validate_events` before opening the output file. It
checks:

* the required Detection Finding base attributes and the exact class, category,
  activity and type identity;
* `time`, `start_time`, `end_time`, `created_time` and the finding window as
  positive integer epoch milliseconds, with window and first/last ordering;
* `metadata.version` equal to `1.10.0`, and a product with name, vendor and
  version;
* `finding_info.uid`, title, `created_time`, analytic identity and a known
  analytic type;
* enum siblings: `severity`, `confidence` and `status` labels must agree with
  their ids;
* every ATT&CK tactic/technique/sub-technique object has an identity, and every
  technique id matches the `T` plus digits shape;
* every evidence object has a name or uid and an object `data`, endpoints have
  an identity and a valid IP and port, and a DNS query has a valid hostname;
* every observable resolves to the event path it names, matches that value, has
  the right type label and type id, and is not duplicated;
* no `null` value anywhere in the event. OCSF JSON omits absent attributes;
  null is not an absent attribute.

This is **not** the official OCSF JSON Schema validator. It does not check every
optional attribute, every class this project never emits, or constraints that
require the full OCSF meta-schema. CI does not install `jsonschema` or an OCSF
package for this test, and the export does not claim conformance beyond the
subset above. The pinned version and the checks above are what the repository
can prove offline today.

## Limits and non-claims

* **Create only.** The exporter never emits Update or Close findings. It has no
  lifecycle history, so a New status means "this finding was created", not "no
  analyst has looked at it".
* **Creation time is detection time.** The alert carries the instant the detector
  fired (the window end when one is present); it does not carry a separate
  record-insertion timestamp. `time` and `finding_info.created_time` use that
  detection instant, never the wall clock at export.
* **No triage verdict in OCSF.** The advisory Laya verdict is joined into the
  HTML report and the evidence API, not rewritten as an OCSF status. A triage
  disposition is not the same thing as finding lifecycle.
* **No invented enrichment.** There is no malware, process, user, cloud,
  remediation or threat-intelligence object unless the source alert actually
  carries the data. This export maps what the detection stack recorded.
* **No severity escalation.** The OCSF severity is the alert's stored severity;
  the exporter does not recompute it.
* **No silent repair.** A bad timestamp, invalid endpoint or broken observable
  stops the write. The caller sees the problem list.
* **Original time is normalized.** `metadata.original_time` is UTC with
  milliseconds; an input offset is not preserved in that string. The epoch
  fields carry the instant.
* **JSONL is a transport choice.** OCSF does not standardize a multi-event file
  envelope. A consumer that expects an array must read the lines; this is stated
  in the output path, the CLI help and this document rather than left implicit.

## Acceptance

```bash
python scripts/checks/check_alerts.py --limit 2000
```

The checker exports the same class-balanced sample through STIX and OCSF and
fails if either validator reports a problem. Focused tests:

```bash
python -m pytest tests/alerts/test_export_ocsf.py -q
python -m pytest tests/ui/test_dashboard.py::test_session_alert_exports_to_ocsf -q
python -m pytest tests/ui/test_mission_control.py::test_ocsf_route_returns_one_valid_detection_finding -q
```

## References

* OCSF schema release v1.10.0: <https://github.com/ocsf/ocsf-schema/tree/v1.10.0>
* Detection Finding class: <https://schema.ocsf.io/1.10.0/classes/detection_finding>
* Finding object: <https://schema.ocsf.io/1.10.0/objects/finding>
* OCSF dictionary: <https://schema.ocsf.io/1.10.0/dictionary>
* Project STIX export: [alerts.md](alerts.md#stix-21-export)
