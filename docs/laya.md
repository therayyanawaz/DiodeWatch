# Laya System-1 triage channel

**Detection decides *that* something is suspicious; triage decides *what to
do about it*.** The Laya channel adds a calibrated first-pass analyst to the
alert pipeline: it reads the same observed-vs-threshold evidence a human
would, and answers three typed questions about every alert in one ONNX
forward pass, fully offline, on the enclave side of the diode.

Laya is the open-source, Jev-compatible System-1 decision model (Convai
Innovations; Apache-2.0 weights, MIT runtime), a ModernBERT encoder plus a
from-scratch decision head, exported to one ONNX graph. It generates no text.
DiodeWatch integrates it via `src/triage/` (this doc) and the pinned bundle
fetcher `scripts/fetch/fetch_laya.py`; the reference ports it follows are
`rl_common.py`/`rl_agent_api.py` in the checkpoint and the TS port
[`receptron/laya`](https://github.com/receptron/laya).

## The three questions (one forward pass)

| Key | Type | Asks | Returns |
|---|---|---|---|
| `disposition` | choice | Which SOC action should this alert get? | argmax + probability per option (escalate / investigate / monitor / false_positive) |
| `urgency` | score | How urgent, on an ordered rubric? | expected level 0..3 + full distribution + legend |
| `corroborate` | noul | Does the evidence genuinely support the assigned class? | calibrated P(true) |

Every answer carries `confidence` (1 - normalized entropy) and
`act_probability` (the act head's P(answer honest), Laya's own calibrated
self-check trained with RLCD).

The **state** passed to the model is the alert envelope an analyst would
read: threat class, confidence, severity, detector, 5-tuple, and every
evidence item (observed vs threshold). Window bookkeeping and ids are
dropped, no decision signal, wasted tokens.

## Why advisory, and where verdicts live

* Triage **never mutates** detection fields (confidence, severity, ATT&CK,
  alert_id). It appends one evidence item (`triage.disposition`) and sets an
  additive `triage` dict on the envelope, the `alert_id` the SQLite store
  hashes stays byte-identical.
* Verdicts persist in a **side table** (`alert_triage`, keyed by `alert_id`),
  deliberately **outside the tamper-evident evidence chain**: triage is
  produced *after* the detection, so re-triaging with a newer model must
  never look like evidence tampering, and pre-triage databases keep
  verifying unchanged (`store.verify_chain` is untouched, tested).
* Old alert dicts without `triage` round-trip unchanged
  (`alert_from_dict` tolerates the missing key).

## Offline by construction

```bash
python scripts/fetch/fetch_laya.py        # ONE networked-machine step (pinned HF commit)
python scripts/checks/check_laya.py        # acceptance gate, passes WITHOUT weights
python scripts/checks/check_laya.py --infer  # + real triage (needs models/laya-onnx/)
```

The bundle (~1.7 GB fp32) lands in `models/laya-onnx/` (git-ignored,
SHA256s printed at fetch). `huggingface_hub` is used **only** by the fetcher;
at inference the runtime touches nothing but disk and CPU. Missing runtime or
bundle = the channel degrades loudly (`LayaUnavailable` with the fix in the
message), never silently.

## Honest operating envelope

* **Not in the flow-rate path.** Triage is post-detection over finished
  alerts; the 5,000 flows/s window loop never calls it.
* **Latency is hardware-bound and reported, not promised.** The 424M-param
  encoder costs **seconds per alert on a typical laptop CPU**, measured
  **~7 s/alert** on the dev box (8-core x86, fp32 CPU EP). `status().avg_ms`
  reports the local truth after warm-up; do not assume another machine's
  number. The operating pattern is bounded triage: newest-first over the
  current alert set (`--limit`), not blanket scoring of every alert.
* **fp32 only, measured.** int8 dynamic quantization was evaluated and
  rejected: ≈1.3× speed for a Δlogit up to 0.66, unacceptable for
  calibrated probabilities. Ship the fp32 bundle.

## The advisory guard (never auto-close)

Every verdict envelope carries two hard-coded fields:

```json
"auto_close_allowed": false,
"requires_human_review": true
```

`recommended == "false_positive"` means *the model thinks this alert is
likely a false positive*, it **never** means *safe to close*. No code path
in DiodeWatch auto-closes, auto-suppresses or downgrades an alert because of
a Laya verdict, and the guard fields exist so downstream consumers cannot
mistake guidance for a decision. Closing an alert is always a human act.

## CLI

```bash
# triage an alert NDJSON (e.g. the ml_engine output) newest-first, first 200
python -m src.triage.engine --input data/slices/ml_alerts.jsonl \
                            --out data/slices/triaged.jsonl --limit 200

# stored verdicts, `store` records any verdict an alert already carries, into
# a side table beside the chain (annotation: re-triaging never re-hashes history)
python -m src.alerts.cli store --alerts data/slices/triaged.jsonl \
                               --db data/alerts/phase6_alerts.db
python -m src.alerts.triage_store counts --db data/alerts/phase6_alerts.db
python -m src.alerts.triage_store recent --db data/alerts/phase6_alerts.db
```

## API sketch

```python
from src.alerts.schema import alert_from_dict
from src.triage.engine import LayaTriage, attach_evidence

eng = LayaTriage()               # loads models/laya-onnx/
if eng.available():
    a = alert_from_dict(alert_dict)
    summary = eng.triage(a)      # {recommended, urgency, p_false_positive,
                                 #  auto_close_allowed, requires_human_review,
                                 #  model_name, model_revision, bundle_sha256, ...}
    attach_evidence(a, summary)  # advisory evidence item
    a.triage = summary           # additive envelope field (exports carry it)
```

**Provenance.** Each verdict is stamped with `model_name`, the pinned
`model_revision` (the Hugging Face commit `scripts/fetch/fetch_laya.py` downloads)
and `bundle_sha256`, the SHA256 of the weights file `laya.onnx.data` (the
graph in `laya.onnx` is fixed by the revision pin; the digest is computed
once per process). A verdict therefore carries everything needed to
reproduce it.

Dashboard: the Evidence tab shows the verdict banner when `triage` is
present on the selected alert.

## Background worker (`src/triage/worker.py`)

`TriageWorker` is a daemon thread that moves triage fully off the replay
hot path. Callers `submit(alert)` (or `submit_many`); the worker scores
candidates by priority (severity rank, then newest first) with a bounded
PriorityQueue (maxsize 64, drop-oldest, never blocks the producer) and
`drain()` returns finished `{alert_id: summary}` verdicts exactly once.
One bad alert degrades the status line, never the thread.

```python
from src.triage.worker import TriageWorker, tick

tw = TriageWorker()                  # loads the bundle in the background
tick(alerts, tw, db_path())          # submit newest · attach · persist: verdicts written
print(tw.status_line())              # e.g. "triage: 12 queued · 7 done · 210 ms/alert"
tw.close()
```

`tick` is the whole cycle the dashboard calls: it submits the newest alerts that
have no verdict yet, attaches whatever the worker finished (`attach_verdicts`,
idempotent, still public for callers that only want that half), and writes those
verdicts to the side table.

If the bundle or onnxruntime is missing, the worker starts in degraded
mode: `status().mode == "unavailable"`, nothing blocks, the dashboard
caption reports the reason instead of the verdicts.

### Where a verdict goes

`tick` persists each drained verdict into the side table beside the evidence
chain (`src.alerts.triage_store`, keyed on the stable `alert_id`), so
a verdict outlives the browser session that computed it. Every surface that
renders an incident report reads the same table through `join_verdicts` before
rendering: the mission-control export at `:8530`, `python -m src.alerts.cli
report`, and the batch pipeline that `python -m src.alerts.cli store` fills.
Without that join one `alert_id` exported two different reports, the advisory
line on the surface that triaged, a blank on the one that did not.

The join is a copy, not a mutation, and it attaches both halves of what the
worker produces (`.triage` plus the `triage.disposition` evidence row derived
from it). Neither end creates the database: a surface with no chained session
to write into records nothing, so there is no file holding verdicts for
detections nobody persisted.

## Future work (documented, not built)

The channel ships as advisory guidance with the guard and provenance above;
the following validation is deliberately **not** claimed for the current
release:

* **Labeled evaluation.** No per-threat-class precision/recall/FPR or
  calibration (ECE) study against a representative labeled alert set exists
  yet, zero-shot accuracy on generic decision benchmarks does not transfer
  to alert triage, and we say so rather than borrow those numbers.
* **Analyst agreement.** No comparison of Laya dispositions against human
  analyst decisions has been run.
* **Load testing.** Latency under sustained multi-alert load, queue-drop
  behaviour beyond the bounded design, and memory profiling are unmeasured.
* **Security review.** The model-loading path (a 1.6 GB untrusted-by-default
  file) has SHA256 provenance but no signature verification, sandboxing or
  resource-limiting review.

A production deployment should close these before trusting verdicts beyond
advisory display.
