# Drift alarms that make a channel abstain

This page describes the drift policy shipped in `src/alerts/drift.py`, the
artifact at [`evaluation/models/drift.json`](evaluation/models/drift.json), and
the measured evidence behind its thresholds. The short version: a channel whose
input distribution leaves its pinned reference abstains. It does not merely
publish a PSI number beside an alert it still emits.

## What is pinned

Every monitored feature has a quantile baseline built from training-side rows:
sorted edges plus the reference proportion in each bin. The artifact stores
edges and proportions, never raw traffic. A live frame is scored against those
pinned edges with the Population Stability Index:

```text
PSI = sum over bins of (actual - expected) * ln(actual / expected)
```

Expected and actual proportions are clipped at `1e-6` so an empty bin cannot
produce an infinite score. A constant reference gets four edges, not two: the
constant sits in the middle bin, values below it fall in the first bin, and
values above it fall in the last. Without the extra edge a reference at zero
would score zero against any positive drift.

The policy is per channel, and a channel may pin its own threshold:

| Channel | Method | Reference | Null maximum PSI | Alarm threshold | Shift read |
|---|---|---|---:|---:|---|
| `ml.flowctx` | PSI | 160,000 CIC-IDS2017 rows, 20,000 per training day, protocol-A 80% split | 2.808149 | **3.0** | injected Wednesday shift: **13.221836** on `fwd_pkts` |
| `ml.beacon` | PSI | 50,000 candidate pairs from CTU-13 scenarios 42/43/51/53 | 0.535586 | **1.0** | scenario 52 holdout: **1.117500** on `dt_scores` |
| `ml.dga` | PSI | 50,000 rows from family fold 0 plus synthetic tunnels | 0.000423 | **0.5** | family fold 1: **1.885670** on `sld_len`; Umbrella: **1.257144** on `entropy` |
| `ml.tls` | identity | watchlist lookup, no learned distribution | not applicable | none | never gates |

The fallback threshold in the artifact is 3.0 and applies only to a channel that
does not pin its own value. `min_samples` is 500, so a frame needs at least 500
rows with at least 500 finite values per monitored feature before any PSI is
computed. Monitored features that fail that check are reported as skipped; they
are not silently treated as stable.

## Why the thresholds are not 0.25

Textbook PSI bands call 0.25 a large shift. On this data that band would alarm
on ordinary day-to-day variation. The flow reference is a mix of training days;
the eight held-out CIC-IDS2017 days reach a maximum PSI of **2.815199** on
`wdst_flows_per_sec` under the same bins. A 0.25 alarm would fire on every one
of them, and a wall that cries drift every day teaches an analyst to ignore it.

The threshold rule is therefore empirical and stated in each channel's
provenance: take the maximum null PSI (a disjoint half of the held-out rows for
flowctx, within-scenario rows for beacon, within-fold rows for DGA), then round
up to the next 0.5 step. That gives 3.0 for flowctx, 1.0 for beacon and 0.5 for
DGA. The separate evaluation days are not used to choose the value; they are the
check that the choice does not false-alarm. All eight stay below 3.0. The closest is
Monday at 2.815199, so there is real margin but not a large one. A smaller shift
between 2.8 and 3.0 is tolerated by design. That is a policy choice, not a claim
that such a shift is harmless.

Beacon uses a lower threshold because its within-scenario null is lower. Scenario
53 reaches 0.507488, just under 1.0, while the excluded holdout 52 reaches
1.117500 and alarms. Scenario 52 is the documented weak holdout from the
calibration work: 3 alerts, 0 true positives, benign FPR 0.000216. It was kept
out of the beacon reference on purpose, so the drift alarm has to earn the
holdout rather than memorize it. It does, at 1.117500.

DGA uses 0.5 because its within-fold null is almost zero (0.000423). Family fold
1 reaches 1.885670 and the independent Umbrella sample reaches 1.257144. Both are
shift reads, not proofs of a universal detector: the DGA map is a family holdout
and the artifact records `exchangeable: false`, just as calibration does.

## What happens on an alarm

A `DriftMonitor` evaluates a frame and records the reading. The first reading
whose maximum feature PSI is strictly greater than the channel threshold sets a
sticky latch. Later healthy frames do not clear it. `reset(channel)` is the
only clear within a running wall, deliberately: an alarm that removes itself is
a chart again. A human decides when the model is trustworthy after drift. The
latch is process memory, so restarting the wall also starts with no latches. The
wall does not expose a reset button; `LiveEvidenceStore.drift_monitor.reset()`
is the programmatic clear.

The live path evaluates samples before the alerts from the same tick:

```text
validate schema -> drift gate -> calibration -> persist and chain
```

That order matters. An alert from a latched channel is withheld before the
calibration policy runs, so it never receives a calibrated confidence and never
looks like a normal abstention. `LiveEvidenceStore` counts it in
`drift_abstained`, not in `abstained` (the calibration counter), and the store
evidence gains a `drift` block with per-channel readings, the threshold, the
latched channel list, and `available: false` when the artifact is absent or
unreadable. The chain status carries the same block. Rules are not passed through
this gate, and `ml.tls` is identity, so neither can be suppressed by a feature
distribution.

`ml_engine` applies the same policy before scoring `ml.flowctx`, before emitting
beacon pair alerts, and before emitting DGA domain alerts. It prints the reading
and a gated summary. `--no-drift` disables the gate. An explicit `--drift` path
that does not exist exits 2; an auto-discovered artifact that is missing or
unreadable warns and leaves the channels ungated, because a missing explanation
must not take the detection wall down.

## The demo pack cannot exercise it, and says so

The canned `02_c2_beacon` sidecar has **2** candidate pairs and `03_dga_tunnel`
has **46** domains. Both are below `min_samples = 500`, so the policy reports
`2 rows, need 500 for a PSI reading` or `46 rows, need 500` and does not alarm.
The demo therefore keeps its beacon and DGA alerts. This is deliberate: a toy
sidecar is not evidence of drift, and inventing a PSI from 46 rows would be
worse than abstaining from the judgment. It also means the canned demo does not
demonstrate suppression. The measured alarm evidence is in the evaluation
summary and the engine test, not in the demo pack.

## Limits

* **PSI is univariate.** A joint shift that leaves every marginal nearly intact
  is invisible. The policy is a guard, not a distribution test.
* **The reference includes attacks.** Drift means "this is not the traffic mix
  the model learned", not "this batch contains attacks". A traffic-composition
  change can alarm without any model failure.
* **No confidence interval.** The thresholds are pinned from a finite null, not
  a sequential test. They should be re-derived when the reference changes.
* **Exchangeability is not guaranteed for beacon or DGA.** Their `provenance`
  records that, and their shift reads are the reason the alarm exists.
* **The latch is channel-wide and in memory.** One shifted feature withholds
  every alert from that channel, not only alerts that depend on the shifted
  feature, and a wall restart clears the latch.
* **The reference fallback is not covered.** `ml.supervised` is the flow-level
  model tried only when the flow-context artifact is absent; it has no pinned
  baseline in this artifact and runs without a drift gate. The shipped
  flow-context path does not use it.
* **Small live sidecars abstain from judgment.** A demo with fewer than 500 rows
  is outside what this policy can measure.

## Reproduce the check

```bash
python scripts/checks/check_drift.py
python -m pytest tests/alerts/test_drift.py tests/test_drift_artifact.py -q
python -m pytest tests/detectors/test_ml.py -q -k drift
```

The checker validates schema, sorted edges, reference proportions, per-channel
thresholds, the pinned summary size and the measured null/holdout claims. It
needs no corpora. Re-fitting needs the CIC, CTU-13 and DGA source runs plus the
trained models; the committed artifact is the pinned result, and
[`evaluation/runs/drift.json`](evaluation/runs/drift.json) records the sample
sizes and every measured reading so a future re-fit can be compared like for
like.
