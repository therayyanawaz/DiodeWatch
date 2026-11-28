# Calibration and Conformal Abstention

Status: shipped. The policy artifact is
[`evaluation/models/calibration.json`](evaluation/models/calibration.json);
the measured record is
[`evaluation/runs/calibration.json`](evaluation/runs/calibration.json); the
guardrail is `python scripts/checks/check_calibration.py`.

## Two different numbers, deliberately kept apart

A rule alert carries **coverage**, `fired_conditions / total_conditions`. It is
not a probability and is not calibrated here: a rule that checks four independent
conditions and sees three has 0.75 coverage whatever the base rate is. Turning that
into a probability would need labelled windows per rule and would change what the
evidence list means. Rules therefore bypass this policy unchanged.

An ML alert carries a **model score**. The score ranks well but it is not the
frequency with which an alert of that score is correct, and the shipped thresholds
were chosen for recall or FPR, not for probability. The policy makes it honest in
two steps:

1. **Isotonic calibration** fits a monotone map from raw score to the observed
   correctness frequency on a labelled fit split. The map is stored as knots;
   between knots it interpolates linearly. It never changes the ranking of two
   scores.
2. **Split conformal abstention** stores benign scores from the fit split. For a
   new raw score `s`, the p-value is
   `(1 + #{benign >= s}) / (n + 1)`. If `p > alpha`, the score is not unusual
   enough under benign traffic and the alert abstains.

An alert is kept only when **both** gates pass: `p <= alpha` and
`calibrated_confidence >= min_confidence`. The floor is selected on the fit split
as the lowest calibrated score in the longest high-score prefix that meets the
target precision, then the whole policy is evaluated on a disjoint split. The
artifact stores the target and the floor, so a reader can see what was optimised.

## Artifact

`models/calibration.json`, schema 1, copied to
`docs/evaluation/models/calibration.json` for clones and CI:

```json
{
  "schema": 1,
  "generated_utc": "...",
  "source": "...",
  "channels": {
    "ml.flowctx": {"classes": {"ddos": {"method": "isotonic", "alpha": 0.01,
                   "min_confidence": 0.987, "curve": [[0, 0], ...],
                   "conformal_scores": [...]}}},
    "ml.beacon":  {"classes": {"*": {...}}},
    "ml.dga":     {"classes": {"*": {...}}},
    "ml.tls":     {"classes": {"*": {"method": "identity", ...}}}
  }
}
```

`ml.flowctx` is per class, falling back to `"*"` when a class has no map.
`ml.beacon` and `ml.dga` are binary channels and use `"*"`. `ml.tls` is
deterministic abuse.ch watchlist membership: its alert confidence is already the
watchlist identity, so it uses `identity` with no floor and no conformal gate. It
does not abstain, and the doc says so rather than inventing a probability for an
exact hash match. The novelty layer remains disabled (see [ml.md](ml.md)).

Runtime loading:

* `LiveEvidenceStore` loads `models/calibration.json` by default and applies the
  policy after raw schema validation, so a malformed score is rejected rather
  than clamped into validity. `DIODE_CALIBRATION=off` disables it; an
  explicit path selects another artifact. `evidence()` reports availability and
  the cumulative `abstained` count.
* `ml_engine` applies the same policy before writing standalone NDJSON, so the
  sidecar and live window paths agree. `--no-calibration` writes raw scores.
* Applying the policy twice is a no-op: alerts already carrying `calibration` or
  `conformal_p` evidence are skipped. `alert_id` is unchanged; severity is
  recomputed from the calibrated confidence.

`tests/conftest.py` sets `DIODE_CALIBRATION=off`, so the committed artifact cannot
silently change unrelated deterministic tests. Calibration tests pass an explicit
policy.

## Protocol and measured result

All figures below are out of sample for the **calibration map**, which is what this
change is about. The underlying models are themselves out of sample for the
shipped artifacts as recorded in their run files; in particular the beacon and DGA
maps are fitted on out-of-fold scores from the same leave-one-scenario-out and
family-holdout protocols, then evaluated on a disjoint half or held-out family.

| Channel | Fit split | Evaluation split | Alerts before | Alerts after | Precision before | Precision after | Recall before | Recall after | Brier before | Brier after |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| flowctx ddos | first random half of protocol-A held-out 20% | second half | 37,971 | 37,971 | 0.999974 | 0.999974 | 0.999974 | 0.999974 | 7.05e-6 | 3.68e-6 |
| flowctx webattack | same | same | 213 | 213 | 0.99061 | 0.99061 | 1.0 | 1.0 | 7.07e-6 | 7.02e-6 |
| flowctx scan | same | same | 15,934 | 15,934 | 1.0 | 1.0 | 1.0 | 1.0 | 0 | 0 |
| flowctx bot | same | same | 74 | 74 | 1.0 | 1.0 | 0.3645 | 0.3645 | 3.53e-6 | 3.53e-6 |
| flowctx bruteforce | same | same | 0 | 0 | n/a | n/a | 0 | 0 | 4.92e-3 | 1.44e-5 |
| beacon | random half of LOSO OOF pairs | other half | 312 | 43 | 0.3013 | 0.7907 | 0.1946 | 0.0704 | 1.30e-2 | 1.08e-2 |
| DGA | family fold 0 + synthetic tunnels | family fold 1 | 305,086 | 295,694 | 0.99716 | 0.99767 | 0.5785 | 0.5610 | 1.73e-1 | 1.45e-1 |
| TLS | n/a | n/a | identity, no abstention | identity | n/a | n/a | n/a | n/a | n/a | n/a |

Flowctx overall: 54,192 alerts at precision 0.999945 before and after. Its existing
thresholds are already stricter than the conformal gate at `alpha = 0.01`, so no
flowctx alert abstains on this split. The calibration still changes the confidence
and improves Brier for ddos, bruteforce and webattack; scan and bot are already at
the ceiling. Reporting "no alert change" is the honest outcome, not a reason to
loosen the gate.

Beacon is where the policy earns its place: precision rises from 0.301 to 0.791 and
ECE falls from 0.0132 to 0.0016, at the cost of recall 0.195 to 0.070. DGA keeps
precision and loses 1.8 points of recall; its ECE improves from 0.180 to 0.147.
These are trade-offs, not free wins.

## What these numbers do not show

* **Exchangeability is assumed, not guaranteed.** A random split is exchangeable by
  construction; deployment is not. On the beacon scenario-holdout protocol (fit
  scenarios 42/43/53, evaluate 51/52), the same policy keeps 3 alerts, 0 true
  positives and 3 false positives (benign FPR 0.000216). The conformal p-value is
  valid only while the benign and attack distributions match the fit sample. The
  next item, a drift alarm that forces abstention, is motivated directly by this
  failure.
* **The DGA Umbrella stress is at the edge.** At `alpha = 0.01` the policy flags
  1.14% of 1,000,000 never-trained Umbrella domains, close to the 1% target but not
  below it. The model was not trained on that family; treat this as a shift stress,
  not a coverage proof.
* **Flowctx depends on the aggregation horizon.** The held-out 20% preserves the
  full-day context the model was trained on. Replaying a subsample changes the
  aggregate features and collapses scores below the threshold; calibration does not
  repair that, as recorded in [ml.md](ml.md).
* **Small positives.** The beacon evaluation half has 483 positives and the
  scenario stress only 32, so the recall figures have wide intervals. The point of
  the policy is the precision/abstention trade, not a precise recall estimate.
* **No per-alert guarantee.** Conformal validity is marginal over exchangeable
  draws. It does not promise that a particular alert is correct, and it is not a
  multiple-testing correction across channels.
* **Rules are not calibrated.** Their confidence remains coverage by design; the
  policy ignores them.

## Reproduce the check

```bash
python scripts/checks/check_calibration.py
```

This validates schema, curve monotonicity, conformal sample ordering, class
coverage, and that every floor quoted in the summary matches the artifact. It does
not need corpora. Re-fitting requires the OOF caches from the protocol-A, LOSO and
DGA family-holdout runs; the committed artifact is the pinned result, and the
summary records the sample sizes so a future re-fit can be compared like for like.
