# ML Detectors

The ML layer sits beside the rule layer and emits the same
`src.alerts.schema.Alert` envelope (`timestamp`, `flow_id`, `threat_class`,
`confidence`, evidence with observed-vs-threshold items). Unified entry point:

```bash
python -m src.detectors.ml_engine \
    --input data/slices/ml/features__Wednesday-workingHours.pcap_ISCX.csv.parquet \
    --out data/slices/ml_alerts__Wednesday.jsonl
```

The engine loads trained artifacts from `models/` (missing artifacts degrade
gracefully: rule-mode DGA, watchlist-only TLS, no flow+context alerts). Two of
those artifacts are distributed under `docs/evaluation/models/` and carry a model
card each, with the digest of the exact bytes and the training column order that
every scorer depends on: see [`docs/models/`](models/README.md). The end-to-end
train + gate + engine check runs via `scripts/checks/check_ml.py`:

```bash
python scripts/checks/check_ml.py train-windows train-beacon train-dga train-tls gates engine
```

Input must be a FULL corpus day, not a subsampled slice, the window-context
models are calibrated to the full-day aggregation horizon (see Honest
limitations). `check_ml.py engine` picks the full Wednesday parquet
automatically.

## Two feature registries, do not confuse them

The codebase has two different, deliberately separate feature lists, and the
numbers `73` and `38` refer to different things:

| | count | source of truth | what it is |
|---|---|---|---|
| **Declared registry** | **79** | `src/features/specs.py` (`FEATURES`) | every column the schema declares for a flow record: 73 marked `active` plus 6 marked `future` (declared but not yet emitted, so the schema can grow without churn). |
| **Active registry** | **73** | same list, `status == "active"` | what `features.engine.build_features` actually emits; this is the number `docs/features.md` documents. |
| **Model matrix** | **38** | `src/detectors/ml/features.py` (`MODEL_FEATURES`) | the numeric subset a classifier consumes. |

**38 of the 73 active columns are model inputs.** The other 35 are the nine
`meta` columns the model never sees, `flow_id`, `src_ip`, `src_port`, `dst_ip`,
`dst_port`, `protocol`, `proto`, `timestamp`, `label`, carried for joins,
evaluation and alerting rather than as signal (`protocol` and `proto` are
identifiers/enums, `label` is the target itself), plus the 26 `iat_*` and
`pktlen_*` passthrough columns, which are emitted and parity-checked but are
**not** in any saved model's matrix. That is deliberate: `MODEL_FEATURES` is
frozen, so the 26 enrich the dataset without invalidating a trained artifact.
Training picks them up only if they are added to `MODEL_FEATURES` and every
model is retrained; until then no reported accuracy figure includes them, and a
saved model still refuses to load against a changed matrix -
`SupervisedModel.load` compares a `features_fingerprint()` of `MODEL_FEATURES`
and raises on mismatch, so a silently-drifted matrix cannot score traffic.

```bash
# all three numbers and the 35-column gap, printed from the code
python -c "from src.features.specs import FEATURES; \
from src.detectors.ml.features import MODEL_FEATURES; \
a={f['name'] for f in FEATURES if f['status']=='active'}; \
gap=a - set(MODEL_FEATURES); \
meta={'flow_id','src_ip','src_port','dst_ip','dst_port','protocol','proto','timestamp','label'}; \
print('declared', len(FEATURES), '| active', len(a), '| model', len(MODEL_FEATURES), '| gap', len(gap), '| of which meta', len(gap & meta), '| of which timing/size passthrough', len(gap - meta))"
# -> declared 79 | active 73 | model 38 | gap 35 | of which meta 9 | of which timing/size passthrough 26
```

## What trains on what

| Module | Corpora (see `docs/datasets.md` + SHA256 manifest) | Evaluation |
|---|---|---|
| `ml.supervised_windows` (flow + window context) | 13 real corpus days across three CIC collections from one lab (2026-10-18 retrain): CIC-IDS2017 8 days + CIC-DDoS2019 Syn day (full identity → flowctx windows) + 4 CSE-CIC-IDS2018 days (no identity columns → supervised per-flow classes only, 0 flowctx windows (disclosed) | Protocol A: stratified per-day flow split 80/20; Protocol B: leave-one-day-out for ddos. LOSO disclosure: held-out ddos folds AUC 0.998 (2/3) but fixed train threshold can yield R 0.0 on a held-out day (Friday-2017 fold AUC 0.584)) pooled F1 1.0 is in-sample and never quoted as cross-day generalization |
| `ml.supervised` (reference, flow-level only) | same 13 days (2.6M labelled flows, 7 classes) | same protocols, macro F1 0.34 (7-class; was 0.299 over 4) |
| `ml.beacon` | CTU-13 scenarios 42/43/51/52/53 (labeled NetFlows) | Leave-one-scenario-out; ROC-AUC macro over scenarios with >=30 positive candidate pairs |
| `ml.dga` | argencon corpus (1.0M benign incl. Bambenek + 1.9M DGA, 51 families) + Umbrella top-1m as never-trained benign | 48-family holdout CV; threshold selected on known corpus at precision >= 0.90; Umbrella FPR reported separately |
| `ml.tls_ja3` | 97 abuse.ch SSLBL malicious JA3 hashes (watchlist) + generated benign-shaped workload | Synthetic-plant labelled eval (honest: no Zeek/pcap in this lab); watchlist channel is fully real |

## Key design decisions (and why)

1. **Flow + window context, not pure windows.** The whole DDoS attack in this
   corpus spans ~3.5 minutes -> only ~22 positive 10 s windows: window-level
   classification is statistically starved. Instead each flow inherits its
   window's aggregates (flows/s to its destination, distinct sources, SYN
   share, response share, upload ratio, ...) as context features, the exact
   signal the rules use, and the model emits per-flow probabilities with
   a real `flow_id` on every alert. Pure per-flow features alone plateau at
   macro-F1 ~0.30 (benign and attack flows genuinely overlap); that model is
   kept in `supervised.py` as the documented reference.

2. **Benign negatives are guaranteed in every binary fit.** The original
   budget was `max(NEG_CAP, 20×pos) - hard_negatives`, which starved
   bot/webattack/bruteforce (hard-negs ≈ 333k > 300k cap) to **zero benign
   rows**. Those binaries then fired p≈1.0 on benign traffic (measured:
   19,891 junk bot alerts on the demo slice; benign p90 for bot = 1.0 even
   on a full day). The benign budget is now independent of the hard-negative
   count (`min(max(NEG_CAP, 20×pos), available_benign)`).

2. **Threshold tuning is a hard precision gate, not a preference.** A class
   with NO tuning-slice operating point at precision ≥ 0.5 gets its alerting
   channel disabled (`threshold=None`) instead of a silent max-F1 fallback -
   the fallback once shipped a P=0.0103 bot threshold to production. Ranking
   quality (ROC-AUC) is still reported for disabled channels; `score()`
   skips them so they can never fire at inference. After the benign-negatives
   fix no class is currently disabled (bot: tune P=0.9976, was 0.0103;
   webattack recovered via the self-check retry).
2. **One-vs-rest binaries, not one multiclass model.** At production scale
   (2.26M protocol-A train rows) the 7-class LightGBM fit silently collapses
   in this environment: in-sample recall 0.97 (ddos) but 0.00 (scan)
   unweighted, and 0.02/0.00 with capped class weights via either sklearn
   mechanism (`class_weight` dict or row-wise `sample_weight`), while the
   identical code learns scan at 0.99 on a 400k stratified subsample. Binary
   objectives are stable at every tested scale, so the production ensemble
   trains one binary `class-vs-rest` LightGBM per threat class (positives vs
   other-attack hard negatives + capped benign subsample), each with an
   in-sample self-check (log + one negative-halved retry) and its own
   threshold tuned on a train-side slice (max F1 with precision >= 0.5
   preference). `infiltration` (29 flows corpus-wide) is excluded and
   documented rather than trained dishonestly.
2. **Beacons are pair-level candidates, not flows.** CTU-13's bidirectional
   NetFlow representation contains almost no classic periodic beacons: the
   bot C2 is bursty spam/DNS, and the strongly periodic pairs are Background
   lab traffic. The detector therefore (a) restricts candidates to pairs with
   >= 5 flows and >= 60 s span (a definition, not a learned parameter),
   (b) learns behavioral C2 features with interval periodicity (incl. jitter
   vs median-interval) among them, and (c) is gated on ROC-AUC, ranking
   quality, rather than a single global threshold that cannot serve very
   different scenarios.
3. **DGA threshold is operational.** The decision threshold is picked on the
   known corpus (argencon + tunnels) for precision >= 0.90; Umbrella top-1m
   is a never-trained benign corpus whose FPR at that threshold is reported
   separately (not mixed into the tuning objective). Benign training data is
   augmented with realistic sub-label chains (`kv801.prod.do.dsp.mp.microsoft.com`
   shaped) because bare-registrable-domain benign lists under-represent real
   infra hostnames; SLD features let the model separate random sub-labels
   under word-like bases from random registrable domains.
4. **No silent training at inference.** `ml_engine` only loads existing
   artifacts; if none exist it says so and (optionally) falls back to
   non-ML channels. Training happens only via `scripts/checks/check_ml.py`.

## Honest limitations

- **The flowctx models are calibrated to a full-day aggregation horizon.**
  Per-flow columns like `src_flow_count` / `dst_src_port_count` are
  whole-corpus aggregates, and the trees learn sharp splits at full-day
  scale. Scoring the 200k-flow subsample of a 692k
  day) shifts every aggregate down ~2.5-3.5× and collapses ddos scores from
  med≈1.0 to max≈0.9977, below the tuned 0.9999 threshold (verified by
  per-feature contribution analysis, `pred_contrib`). This is not a code
  bug: the same models score a 50/50 subsample of the *cached full-day
  context* at med=1.0. The engine therefore evaluates on the full Wednesday
  corpus day (`check_ml.py engine`), where the result is exact: 252,672
  alerts = 252,671 ddos + 1 bot, matching the day's 252,672 attack flows
  (precision 0.999996, 440,030/440,031 benign silent). That figure is
  per-flow ML-engine precision only; the rule layer's own benign-window
  count on the same corpus is 0 of 50 alerts, and 5 of 85 benign-only on the
  full CIC-IDS2017 register, see `docs/rules.md`.
  Deployment must preserve the training aggregation horizon (full replay of
  the captured window), and per-deployment threshold calibration is advised
  (see LOSO finding in `window_metrics.json`).

- Protocol A shares 10 s window context across neighbouring flows (mild
  temporal leakage); it is the protocol comparable with published CIC results.
  Protocol B (leave-one-day-out) is the strict cross-day number for ddos.
- `bot` / `infiltration` support in CIC-IDS2017 is tiny (36 Infiltration flows
  in the whole corpus); bot coverage relies primarily on the dedicated beacon
  and TLS detectors, as intended by the layered design.
- TLS novelty channel is fit on a generated benign-shaped workload (no Zeek /
  pcap in this lab); its eval is the labelled synthetic-plant experiment. The
  watchlist channel is fully real. In this lab the novelty layer is
  **disabled**: the generated baseline gives every client the same aggregate
  vector, so the fit set has zero spread and `train_tls` reports
  `novelty_available: false` rather than scoring noise. The synthetic-plant
  F1 of 1.0 is therefore the 97-hash abuse.ch watchlist lookup alone, the
  novelty channel contributes 0 of the 62 planted detections
  (`synthetic_plant_eval.novelty_only`). It becomes usable when a real Zeek
  `ssl.log` is supplied (`--tls-ssl-log`).
- Beacon positives on CTU-13 are "bot-host pair activity", not verified
  periodic beacons (see #2); scenario 53 contributes only ~6 positive
  candidate pairs, hence the support>=30 rule in the headline metric.
- All final numbers live in `results/ml/*_metrics.json` (written by training
  runs; never hand-edited) and are summarized by `scripts/checks/check_ml.py gates`.
