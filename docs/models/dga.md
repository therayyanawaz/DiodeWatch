# Model card, `dga_lgbm.joblib`

Domain-name classifier for algorithmically generated names and DNS tunnels. It
scores one queried name, not a host and not a session: the evidence is the shape
of the string, so every name stands on its own.

## What it reads

Eighteen per-name features, in this order (the order is the contract, see
[`feature_order.json`](feature_order.json)):

| # | Feature | What it captures |
|---|---|---|
| 1 | `len` | total name length, tunnel labels are long |
| 2 | `entropy` | character entropy of the name |
| 3 | `digit_ratio` | digit share, DGA families lean on digits |
| 4 | `vowel_ratio` | vowel share, random strings starve consonants and vowels alike |
| 5 | `unique_ratio` | distinct characters over length |
| 6 | `digits` | digit count |
| 7 | `dots` | label count, a tunnel encodes data in extra labels |
| 8 | `hyphens` | hyphen count |
| 9 | `consonant_run4` | longest consonant run of four or more |
| 10 | `consonant_run6` | longest consonant run of six or more |
| 11 | `is_common_tld` | whether the TLD is in the benign prior |
| 12 | `tld_len` | TLD length |
| 13 | `bigram_score` | mean log-probability of the name's bigrams under the corpus prior |
| 14 | `tld_suspicious` | whether the TLD is outside that prior |
| 15 | `sld_len` | second-level label length |
| 16 | `sld_entropy` | second-level entropy, the part an operator actually reads |
| 17 | `sld_digit_ratio` | second-level digit share |
| 18 | `sld_consonant_run4` | second-level consonant run |

`bigram_score` is computed against the 676-entry bigram table stored in the
artifact, so the prior travels with the weights rather than being rebuilt at load
time from whatever corpus happens to be on the host.

## What it decides

A probability that the name was machine-generated, compared against the stored
threshold.

| Property | Value |
|---|---|
| Estimator | LightGBM, 300 trees, 63 leaves, learning rate 0.1, `class_weight=balanced` |
| Classes | binary, `0` benign, `1` generated or tunnel |
| Decision threshold | `0.1572725714820621` (compared as `>=`) |
| Imputation | median per feature, stored in the artifact |
| Bigram prior | 676 entries, stored in the artifact |

## Provenance and limits

Trained on the DGA families and the benign name population described in
[`docs/datasets.md`](../datasets.md); the measured behaviour, including the
false-positive families, is in `docs/evaluation/runs/dga_metrics.json`.

The limits worth repeating next to an alert:

* **`tld_suspicious` is a negative indicator on the measured corpora**, not a
  positive one: it fires more often on benign names than on the DGA set there.
  Cheap-TLD detection is not what this model is doing, and the demo pack is built
  so the flag is zero on every name it alerts on.
* **Tunnels hide in ordinary-looking names.** A tunnel that encodes payload in a
  single long label of plausible letters scores near benign on entropy and
  bigram shape; volume over time, which this model does not see, is what catches
  it.
* **A hostname is not a domain.** Per-name scoring says nothing about which
  internal host resolved it, so enrichment is the caller's job.
* **Family drift is real.** A DGA family that changes its alphabet or its length
  profile after training is a distribution shift the frozen artifact cannot
  absorb; the rule layer and the novelty channel exist for that case.

## Integrity

| | |
|---|---|
| File | `docs/evaluation/models/dga_lgbm.joblib` |
| Bytes | 2,108,576 |
| sha256 | `5662ee27802366ffbe0a368d8de1b4a5016f1f8cbd6b410131bf4c163357e7d0` |
| Restored to | `models/dga_lgbm.joblib` |
| Loader | `src/detectors/ml/dga.py` |

As with the beacon channel, an absent file means the channel reports itself
unavailable and the pipeline continues on its rule path.
