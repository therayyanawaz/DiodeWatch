# Model card, `beacon_lgbm.joblib`

Periodicity detector for command-and-control beaconing. It scores one
conversation pair (a source talking to one destination port on one destination
address), not a single flow: a beacon is a property of the repetition, and a
lone flow carries no period.

## What it reads

Thirteen per-pair features, in this order (the order is the contract, see
[`feature_order.json`](feature_order.json)):

| # | Feature | What it captures |
|---|---|---|
| 1 | `n_flows` | how many flows the pair produced, the support for every timing statistic |
| 2 | `span_s` | seconds between first and last flow |
| 3 | `dt_mean` | mean inter-arrival gap |
| 4 | `dt_std` | spread of the gap, the first thing jitter destroys |
| 5 | `dt_median` | gap robust to one outlier |
| 6 | `dt_cv` | `dt_std / dt_mean`, scale-free regularity |
| 7 | `dt_scores` | how many gaps land on a repeated value or multiple |
| 8 | `dt_jitter_share` | fraction of gaps that are near-misses of a base period |
| 9 | `fwd_bytes_mean` | mean bytes out per flow, a heartbeat is small |
| 10 | `fwd_bytes_std` | spread of those bytes, a scripted check-in is uniform |
| 11 | `bwd_bytes_mean` | mean bytes back, a tasking reply is small too |
| 12 | `byte_std` | spread across both directions |
| 13 | `fwd_share` | outbound fraction of the pair's bytes |

Missing values are filled from the per-feature medians stored in the artifact
(`medians`), which is why that mapping is ordered: it is both the imputation
table and the record of training order.

## What it decides

A probability that the pair is beaconing, compared against a threshold stored in
the artifact so the operating point travels with the weights instead of being
re-tuned by whoever loads it. The threshold is deliberately not the point that
maximises training accuracy, it is the point chosen on the labelled corpus and
recorded with the run.

| Property | Value |
|---|---|
| Estimator | LightGBM, 200 trees, 31 leaves, learning rate 0.1 |
| Classes | binary, `0` not beaconing, `1` beaconing |
| Decision threshold | `0.35914078817085937` (compared as `>=`) |
| Imputation | median per feature, stored in the artifact |

## Provenance and limits

Trained on the C2-labelled conversations described in
[`docs/datasets.md`](../datasets.md); the measured behaviour, the scenario spread
it was measured across and the rule baseline it was compared to are in
`docs/evaluation/runs/beacon_metrics.json`.

The limits are the ones that matter when someone reads an alert:

* **Bidirectional NetFlow bot traffic is not mostly beacons.** In CTU-13 the
  labelled bot conversations are bursty C2 and spam; periodicity is one shape of
  malicious repetition, not the shape. The pair framework is what carries the
  signal, and it is honest about being weaker on that corpus.
* **A pair needs repetition to be scorable.** A single flow, or two flows an hour
  apart, gives the timing features nothing to describe.
* **A regular legitimate job looks like a beacon.** Polling agents, NTP-adjacent
  telemetry and health checks are periodic by design; the alert is a candidate
  for review, and the evidence attached to it names which features fired.
* **Jitter-tolerant, not jitter-immune.** Scheduled jitter, or a period that
  drifts with the sleep timer, pushes `dt_scores` and `dt_cv` toward the benign
  side.

## Integrity

| | |
|---|---|
| File | `docs/evaluation/models/beacon_lgbm.joblib` |
| Bytes | 694,654 |
| sha256 | `6ba89cc912c1caad665b72ce2d6851800337226656ec84e284d71ec33003e99e` |
| Restored to | `models/beacon_lgbm.joblib` |
| Loader | `src/detectors/ml/beacon.py` |

If the file is absent the loader reports the channel as unavailable and the
pipeline continues on its rule path; nothing silently scores with a fallback
model.
