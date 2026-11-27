# Model artifacts

Four model artifacts ship in `docs/evaluation/models/` and are copied into
`models/` by whoever evaluates the system (CI does it, the launch scripts do it).
The runtime `models/` directory itself stays git-ignored.

This page is the register: what each artifact is, what it reads, what it decides,
and the digest of the exact bytes in the tree. `tests/test_model_cards.py` fails
if a shipped file stops matching its card, so a rebuilt model cannot leave a card
describing the previous one.

| Artifact | Bytes | sha256 (first 16) | Decides | Card |
|---|---|---|---|---|
| `beacon_lgbm.joblib` | 694,654 | `6ba89cc912c1caad` | C2 beaconing, per conversation pair | [beacon.md](beacon.md) |
| `dga_lgbm.joblib` | 2,108,576 | `5662ee27802366ff` | DGA and DNS-tunnel domains, per name | [dga.md](dga.md) |
| `flowctx_lgbm.joblib` | 2,326,265 | `01c72bbe06ed42ae` | attack classes from flow plus 10-second window context | [flowctx.md](flowctx.md) |
| `tls_novelty.joblib` | 97,163 | `1ce23b359e446d16` | JA3 watchlist hits and TLS novelty | [tls.md](tls.md) |

The two channel artifacts that were previously left on the host are now pinned
for the same reason as the other two: a published figure cannot be re-scored
from bytes that most checkouts do not have. Both were rebuilt on the declared
scikit-learn 1.9.0, so restoring them raises no version warning. Their column
order is pinned and tested in the same way as every other channel.

The full-corpus pass in `docs/evaluation/transfer.md` loads the pinned
flow-context artifact: 2,326,265 bytes, sha256 `01c72bbe06ed...`, 2,264,599
training rows, trained on the eight CIC-IDS2017 days. It is the CIC-IDS2017
model, so that corpus is in-sample and every other corpus is unseen by it. A
rebuild replaces those bytes and can move every ML number in the evaluation; the
run records the digest it actually loaded, which is how the two are kept apart.

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
