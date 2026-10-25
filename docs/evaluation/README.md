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
