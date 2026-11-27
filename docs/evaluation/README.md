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
| `runs/max_scale.md` / `.json` | `results/transfer/max/summary.md` / `max_results.json` from `scripts/benchmarks/bench_corpora.py --out results/transfer/max`, regenerated and committed 2026-11-27 |

Corpora naming: `ddos2019` = CIC-DDoS2019 Syn day · `hoic` / `bot` /
`bruteforce` / `infil` = the four CSE-CIC-IDS2018 attack days.
Phases: `zeroshot_2017models` = evaluated with models trained only on
CIC-IDS2017 (true zero-shot, the defensible cross-corpus claim);
`retrained` = evaluated after the expanded 13-day retraining (CIC-DDoS2019
is in-sample there, disclosed inside the files). The retrained flow-context
artifact itself was never pinned, so those retrained records describe a model that is
not in this tree; the full-corpus pass below measures the artifact that is.

One line in those archives no longer describes the pipeline: each run reports
`feature families not computed`, and the `iat_*` / `pkt_len_*` entries in it
were true when the snapshot was taken. The engine emits per-packet timing and
size statistics now, so a fresh run lists only the DNS, TLS and active/idle
families. The archived text is left exactly as generated.

The full `results/` tree is git-ignored runtime output; regenerate anything
not snapshotted here with the commands in `transfer.md` §Reproduce.

### Truth labels and the 2026-11-26 correction

Two real corpus spellings were missing from the label register:
`DDoS attacks-LOIC-HTTP` (249,873 CSE-CIC-IDS2018 flows) and `UDP-lag`
(366,461 CIC-DDoS2019 flows). They were scored as unmapped, so they stayed out
of the truth vector but inside the benign denominator of the old summaries.
The register now maps them to `ddos` and `slowdos` respectively, and an
unknown label is `unmapped`, never benign. The phase tables below are archived
runs and still show the old denominators. The full-corpus pass was regenerated
after the fix, and only its figures are current. Two consequences are recorded
rather than smoothed over: the CIC-DDoS2019 benign denominator falls from
480,289 to 113,828 because the UDP-lag flows are now slow-DoS truth, and the
CSE-CIC-IDS2018 ML FPR falls from 0.1704 to 3.3e-05 because the LOIC flows it
already detected are now true positives instead of false positives.

### Reading the rule cells

Every flow cell is a projection of an alert, not the alert itself. An alert is
scoped to one entity and one 10-second window, and the last matching alert
wins; it no longer paints a whole capture file. A window can still contain
benign flows of the same entity, so flow-level FPR is not alert-level FPR.

The full-corpus rules cells also carry raw alert counts. An alert is
**exact** when the truth inside its own window and entity contains the class
it claims, **any-attack** when that scope contains any non-benign truth, and
**unlabeled** when it contains no scorable truth, in which case it is excluded
from precision. **Incident recall** counts truth `(window, entity, class)`
units that received an alert of the same class. Raw counts, not rounded rates,
are merged across chunks and files before any ratio is computed.

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

## The full-corpus pass (2026-11-27)

[`max_scale.md`](runs/max_scale.md) is a different kind of record: not a phase,
but every pinned file of all five corpora scored at its full row count, 50 files
and 109,643,423 flows in 1,020.4 seconds. The rule layer streams each file in
250,000-flow chunks; the ML channel scores the first 200,000 contiguous flows of
each file, because the window model needs a feature frame. Each family line says
whether that corpus trained the artifact, so the ML column cannot be read as
generalization by accident.

The artifact identity is recorded in the JSON: `flowctx_lgbm.joblib`, 2,322,045
bytes, sha256 `fcc1e635a4fe...`, 2,264,599 training rows, built 2026-10-05. That
is the CIC-IDS2017 model, not the Phase-2 retrain, which is why CIC-IDS2017 is the
only in-sample ML family here and why the retrained records cannot be reproduced
from this checkout.

Gate outcome, pre-committed and unmoved: **four PASS**. On CIC-IDS2017 the
rule layer reaches DDoS F1 0.989026 and benign FPR 5,453/2,273,108 =
0.00239892. On CIC-DDoS2019 it reaches F1 0.996426 and FPR 51/113,828 =
0.00044804. The CIC-IDS2017 F1 is 0.039 above its gate and its FPR is 0.0176
below its ceiling; it is the stronger of the two passes but still a measured
one.

The gain came from several changes, tested in staged runs, not one trick: a
per-destination rate baseline, persistence, a low-rate byte floor and a
destination-port gate on the volume branch, scan arbitration against a DDoS
victim, and slow-DoS corroboration. The older 0.845 FPR was mostly a
window-attribution artefact; after attribution the rate branch still produced
0.1496, dominated by the `192.168.10.3` benign burst and other volume claims.
The 500 kB exfil ratio floor and the scan host-sweep removal took the 192-alert
pass to 102. The 20 KB/s floor below 250 flows/s then removed the last
busy-server claim, and the reply-aware port gate removed 26 multi-port fan-in
or high-port sweeps,
leaving 5 benign-only alerts out of 75 before the slow-DoS work. All 27 DDoS
false bursts are gone; DDoS flow recall is unchanged at 0.979339 and precision
rose from 0.94683 to 0.998907.
Raising the slow-request ceiling and keeping strong first windows then added ten
attack-side slow alerts, taking the pass from 75 to 85 without a new benign-only
alert.

Alert-level scoring still shows the remaining weak side. On CIC-IDS2017, 85
alerts are all scorable: exact precision is 80/85 = 0.941176, any-attack
precision is also 80/85, and 5 alerts contain no attack truth (2 scan, 2 exfil,
1 slow DoS). DDoS incident recall is 41/51; slow-DoS is 28/46. Canonical scan
recall is 11/222, but 195 of those units are 127 Patator and 68 web-attack
units mapped to `scan`, and the port-sweep rule covers 11/27 PortScan units.
On CIC-DDoS2019, 1,183 alerts give exact precision 1,175/1,183 =
0.993238, any-attack precision 1,183/1,183 = 1.0, and none are benign-only.
DDoS incident recall is 1,175/9,927 = 0.1184 even though flow recall is
0.99788: one scoped alert cannot cover every small victim window in a long
capture. Volume recall and incident recall answer different questions, and the
artifact prints both.

The corrected CIC-DDoS2019 benign denominator is 113,828, not 480,289,
because 366,461 `UDP-lag` flows are slow-DoS truth. Its FPR gate passes on
that smaller denominator. The slow-DoS rule finds 28/46 CIC-IDS2017 units but
0/448 here, because UDPLag is a low-rate flood without the held-connection
shape. This is a narrow rule-layer pass, not a cross-corpus victory, and the
ML column is unchanged by these rules.
