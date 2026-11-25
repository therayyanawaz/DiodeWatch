# Model artifacts

Two stopped-tree boosters ship in `docs/evaluation/models/` and are copied into
`models/` by whoever evaluates the system (CI does it, the launch scripts do it).
Everything else under `models/` is built on the host and is git-ignored.

This page is the register: what each artifact is, what it reads, what it decides,
and the digest of the exact bytes in the tree. `tests/test_model_cards.py` fails
if a shipped file stops matching its card, so a rebuilt model cannot leave a card
describing the previous one.

| Artifact | Bytes | sha256 (first 16) | Decides | Card |
|---|---|---|---|---|
| `beacon_lgbm.joblib` | 694,654 | `6ba89cc912c1caad` | C2 beaconing, per conversation pair | [beacon.md](beacon.md) |
| `dga_lgbm.joblib` | 2,108,576 | `5662ee27802366ff` | DGA and DNS-tunnel domains, per name | [dga.md](dga.md) |

Two further channels score through artifacts that are **not** distributed, and
the loaders degrade to their rule path when the file is absent:

| Channel | Artifact | Built by | Reads |
|---|---|---|---|
| Flow-context windows | `flowctx_lgbm.joblib` | `supervised_windows.WindowModel.save` after fitting | 59 window features |
| TLS / JA3 novelty | `tls_novelty.joblib` | `tls_ja3.Ja3Novelty.save` after fitting | 5 channel features |

Their column order is still pinned and still tested: a distributed artifact and a
git-ignored one fail the same way if the module is reordered, so the pin lives in
the tree rather than only inside a pickle that most checkouts do not have.

The full-corpus pass in `docs/evaluation/transfer.md` loads a locally built
flow-context artifact (2,322,045 bytes, sha256 `fcc1e635a4fe...`, 2,264,599
training rows, 2026-10-05). It is the CIC-IDS2017 model, so the CIC-IDS2017 ML
cell there is in-sample and every other corpus is unseen by it. A rebuild
replaces those bytes and moves every ML number in the evaluation; the run
records the digest it actually loaded, which is how the two are kept apart.

## The column order pin

[`feature_order.json`](feature_order.json) records the training order of every
channel. Each scorer builds its matrix with
`frame.reindex(columns=FEATURES).to_numpy()`, which is positional: an artifact and
its module agree only if the order is identical. Reordering, renaming, inserting
or dropping one entry shifts every column, and the model then scores the wrong
feature under the right name with no crash, no NaN and no failing accuracy check.

`tests/detectors/test_ml.py` compares the modules against this file for all four
channels, and additionally compares any restored artifact's own record
(`medians`, which is an ordered mapping for this reason) against both.

## What is deliberately not here

* **No accuracy numbers.** They live in the run records under
  `docs/evaluation/runs/` with the corpus, the split and the rule baseline beside
  them, and `scripts/checks/check_claims.py` reconciles every figure the
  documentation publishes against those files. Restating them in a card is how a
  number goes stale in two places at once.
* **No download of the corpora.** The artifacts are bytes; the evidence they were
  trained on is described in [`docs/datasets.md`](../datasets.md) and fetched by
  the scripts in `scripts/fetch/`.
