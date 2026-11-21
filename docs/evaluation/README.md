# Evaluation evidence, committed snapshot

Snapshot committed 2026-10-24. Files were copied byte-for-byte from the
generated outputs, **no metric was hand-edited.**

| File | Origin |
|---|---|
| `transfer.md` | `results/transfer/summary.md` (consolidated cross-corpus summary) |
| `runs/<corpus>_<phase>.md` / `.json` | per-run `summary.md` / `transfer_results.json` from `scripts/benchmarks/bench_transfer.py --out results/transfer/<dir>` |
| `runs/label_maps.json` | `results/transfer/label_maps.json` |
| `runs/window_metrics.json` | `results/ml/window_metrics.json` (flowctx window ensemble, retrained) |
| `runs/supervised_metrics.json` | `results/ml/supervised_metrics.json` (retrained reference model) |
| `models/beacon_lgbm.joblib` | `models/beacon_lgbm.joblib`, pinned copy used by CI so the sidecar tests exercise the real trained model, not a fallback |
| `models/dga_lgbm.joblib` | `models/dga_lgbm.joblib`, same for the DGA channel |

Corpora naming: `ddos2019` = CIC-DDoS2019 Syn day · `hoic` / `bot` /
`bruteforce` / `infil` = the four CSE-CIC-IDS2018 attack days.
Phases: `zeroshot_2017models` = evaluated with models trained only on
CIC-IDS2017 (true zero-shot, the defensible cross-corpus claim);
`retrained` = evaluated after the expanded 13-day retraining (CIC-DDoS2019
is in-sample there, disclosed inside the files).

One line in those archives no longer describes the pipeline: each run reports
`feature families not computed`, and the `iat_*` / `pkt_len_*` entries in it
were true when the snapshot was taken. The engine emits per-packet timing and
size statistics now, so a fresh run lists only the DNS, TLS and active/idle
families. The archived text is left exactly as generated.

The full `results/` tree is git-ignored runtime output; regenerate anything
not snapshotted here with the commands in `transfer.md` §Reproduce.

## The ten run records

Five corpora were evaluated, twice each: the zero-shot pass with the 2017 models, and the
retrained pass. Both are kept so the gap between them stays visible.

| Run | Read it as |
|---|---|
| [`bot_retrained.md`](runs/bot_retrained.md) | bot (retrained) |
| [`bot_zeroshot_2017models.md`](runs/bot_zeroshot_2017models.md) | bot (zero-shot, 2017 models) |
| [`bruteforce_retrained.md`](runs/bruteforce_retrained.md) | bruteforce (retrained) |
| [`bruteforce_zeroshot_2017models.md`](runs/bruteforce_zeroshot_2017models.md) | bruteforce (zero-shot, 2017 models) |
| [`ddos2019_retrained.md`](runs/ddos2019_retrained.md) | ddos2019 (retrained) |
| [`ddos2019_zeroshot_2017models.md`](runs/ddos2019_zeroshot_2017models.md) | ddos2019 (zero-shot, 2017 models) |
| [`hoic_retrained.md`](runs/hoic_retrained.md) | hoic (retrained) |
| [`hoic_zeroshot_2017models.md`](runs/hoic_zeroshot_2017models.md) | hoic (zero-shot, 2017 models) |
| [`infil_retrained.md`](runs/infil_retrained.md) | infil (retrained) |
| [`infil_zeroshot_2017models.md`](runs/infil_zeroshot_2017models.md) | infil (zero-shot, 2017 models) |
