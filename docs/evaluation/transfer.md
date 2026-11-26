# Transfer evaluation, consolidated cross-corpus summary (REAL corpora)

**Date:** 2026-10-18 · **Harness:** `scripts/benchmarks/bench_transfer.py` · **Pre-committed gates:** rule DDoS F1 ≥ 0.95 on every evaluable corpus; benign FPR ≤ 0.02. Gates were fixed before any run and never tuned after seeing results.

## Corpora actually evaluated (all real, never synthetic)

| Corpus | Rows | Source | Identity columns | Evaluable rules? |
|---|---|---|---|---|
| CIC-DDoS2019 (Syn day) | 1,582,681 | cicresearch.ca mirror | Full (Flow ID, IPs, ports, timestamp) | YES |
| CIC-IDS2018 Wed 21-02 (HOIC) | 1,048,575 | official UNB S3 (mirror verified byte-identical) | None (known CIC export quirk) | NO, reported, never faked |
| CIC-IDS2018 Fri 02-03 (Bot) | 1,048,575 | same | None | NO |
| CIC-IDS2018 Wed 14-02 (FTP/SSH brute force) | 1,048,575 | same | None | NO |
| CIC-IDS2018 Thu 01-03 (Infilteration) | 331,125 | same | None | NO |

Notes: mirror files are capped at 1,048,575 rows/day (export limitation, disclosed). IDS2018 `Bot`/`Infilteration` are binary-axis labels with no flow-window class mapping, the harness reports them `unmapped` rather than forcing them into a class. 25 repeated-header remnant rows in the Thursday file are dropped by an explicit guard.

## Phase 1, TRUE zero-shot (2017-only models, archived 2026-10-18)

Archived at `results/archive/transfer_zeroshot_2017models/`.

| Corpus | Rule ddos F1 | Rule benign FPR | ML recall (attack) | ML benign FPR | Verdict |
|---|---|---|---|---|---|
| CIC-DDoS2019 Syn | **1.0** | **0/392 = 0.0** | 0.0 | 0.0 | **GATES PASS** |
| IDS2018 HOIC | n/a (no identity) | n/a | 0.0 | 0/360,833 = 0.0 | fail-closed |
| IDS2018 Bot | n/a | n/a | 0.0 | 0/762,384 = 0.0 | fail-closed |
| IDS2018 BruteForce | n/a | n/a | 0.0 | 0/667,626 = 0.0 | fail-closed |
| IDS2018 Infil | n/a | n/a | 0.0 | 0/238,037 = 0.0 | fail-closed |

**ML recall 0.0 with the explanation published, not hidden:** top PSI drift on the new corpora is 1.0-14.4 (e.g. CIC-DDoS2019 `fwd_pkts` 14.4, IDS2018 `duration_us` 6.8-10.0). The flowctx channel never saw these labs' feature distributions; its quality gate correctly refuses to emit confident junk on drifted input. The archived phase-1 run reported zero false positives on 2.0M benign flows. That figure is withdrawn: the denominator included 249,873 LOIC attack flows that are now true positives. The corrected full pass reports 28/1,179,766 on CIC-IDS2017, 0/32,368 on CIC-DDoS2019, 32/973,140 on IDS2018 and 0/56,000 on UNSW-NB15. Fail-closed silence is real; a universal zero is not.

## Phase 2, after retraining (archived 2026-10-18)

Models retrained: `supervised` (all 13 days, 2.6M labelled flows incl. IDS2018 per-flow classes, macro F1 0.34 over **7** classes vs 0.299 over 4 previously) and `flowctx` windows (10 days with identity columns; the 4 IDS2018 days contribute 0 flowctx rows, no identity, so the ML cell below remains genuinely out-of-sample for IDS2018).

| Corpus | Rule ddos F1 | Rule benign FPR | ML (flowctx) | ML benign FPR | Verdict |
|---|---|---|---|---|---|
| CIC-DDoS2019 Syn *(now in-sample for both channels)* | **1.0** | **0.0** | F1 1.0 | 0.0 | **GATES PASS** |
| IDS2018 HOIC | n/a | n/a | R 0.0 | 0/360,833 = 0.0 | fail-closed |
| IDS2018 Bot | n/a | n/a | R 0.0 | 0/762,384 = 0.0 | fail-closed |
| IDS2018 BruteForce | n/a | n/a | R 0.0 | 0/667,626 = 0.0 | fail-closed |
| IDS2018 Infil | n/a | n/a | R 0.0 | **5/238,037 = 2.1e-05** | fail-closed |

Aggregate benign pressure across all ML cells this session: **2,029,036 benign flows → 5 false positives** (2.5e-06 aggregate FP rate).

**2026-11-26 correction to the archived phase tables.** These two tables are
left as the 2026-10-18 record. They were produced before two real label
spellings were registered: `DDoS attacks-LOIC-HTTP` (249,873 CSE-CIC-IDS2018
flows) and `UDP-lag` (366,461 CIC-DDoS2019 flows). Both were scored as
unmapped and stayed inside the benign denominators above. The register now
maps them, and the full-corpus pass below is regenerated from the corrected
truth. Do not quote the phase-table FPRs as current: the IDS2018 ML FPR in
particular was 0.1704 partly because LOIC attack flows the model already
detected were counted as benign false positives. They are now true positives,
and the corrected family FPR is 3.288e-05.

## Max scale, every pinned file (2026-11-26)

The phases above scored five files chosen from what happened to be on disk. This pass scores the register: `scripts/benchmarks/bench_corpora.py` reads every pinned file of all five corpora, 50 files and 109,643,423 flows in 697.6 seconds, with the rule layer streamed in 250,000-flow chunks and the ML channel on the first 200,000 contiguous flows of each file. The ML scope is a deliberate limit, not a sample: the window model needs a feature frame, and a capture-wide pass is not what a deployment feeds it, so the artifact prints the prefix next to every ML number.

```bash
python -m scripts.benchmarks.bench_corpora --jobs 4 --model-dir <models>
```

| Corpus | Files | Flows scored | Rules, macro F1 | ML, macro F1 |
|---|---|---|---|---|
| CIC-IDS2017 | 8/8 | 2,830,743 | 0.381 | 0.413 |
| CIC-DDoS2019 | 18/18 | 70,427,637 | 0.555 | 0.006 |
| CSE-CIC-IDS2018 | 10/10 | 16,233,002 | not evaluable, no identity | 0.192 |
| UNSW-NB15 | 1/1 | 175,341 | not evaluable, no identity | 0.278 |
| CTU-13 | 13/13 | 19,976,700 | not evaluable, NetFlow | not evaluable, NetFlow |

**Which artifact produced the ML cells.** The run loaded `flowctx_lgbm.joblib`, 2,322,045 bytes, sha256 `fcc1e635a4fe...`, whose own metadata records 2,264,599 training rows and a 2026-10-05 build date. That is the CIC-IDS2017 model. The Phase-2 retrained artifact behind the `*_retrained` records above was never pinned (`docs/models/README.md` says two artifacts are not distributed), so those numbers cannot be reproduced from this checkout and are not extended here. The consequence is useful rather than embarrassing: CIC-IDS2017 is in-sample for the ML channel, while CIC-DDoS2019, CSE-CIC-IDS2018 and UNSW-NB15 are genuinely unseen by it. The run records the byte count and SHA256 of every artifact it loads, so a cell can always be traced to the bytes that produced it.

**What the full pass adds.**

1. **Flow recall is not incident recall.** On CIC-DDoS2019 the rule layer reaches DDoS flow recall 0.920118 (F1 0.958094), but only 1,216 of 9,927 DDoS truth units `(window, destination)` receive an alert, incident recall 0.122494. The alerts concentrate on the large floods that carry most of the 69.9M flows; most small victim windows are missed. On CIC-IDS2017 the opposite mix appears: DDoS flow recall is 0.998216 and incident recall 47/51, but only 50 of 594 alerts are exact (precision 0.084175); 523 alerts contain no attack truth, and scan and slow-DoS incident recall are both zero.
2. **Specificity is now measured at both levels.** CIC-IDS2017 benign FPR is 340,169/2,273,108 = 0.14964929, 7.5 times the 0.02 gate, with 523 of 594 alerts benign-only. CIC-DDoS2019 benign FPR is 788/113,828 = 0.00692273, so the gate passes on the corrected denominator; 13 alerts are benign-only and exact alert precision is 0.918539. The old 0.797 FPR is withdrawn: 366,461 `UDP-lag` attack flows were inside its benign denominator.
3. **The zero-shot ML gap remains large.** The CIC-IDS2017 model calls 0 of 3,361,567 CIC-DDoS2019 attack flows DDoS, 0.34% of 506,537 IDS2018 DDoS flows, and 0.13% of UNSW-NB15 DoS flows. In-sample CIC-IDS2017 reaches 51.9% DDoS recall at 28 false positives in 1,179,766 benign flows (FPR 2.4e-05). The IDS2018 family FPR is 32/973,140 = 3.288e-05 after the LOIC correction, not the archived 0.1704; that old figure counted detected attack flows as benign false positives.
4. **Coverage is complete and nothing is faked.** CTU-13 has neither flow channel (a NetFlow export carries no TCP flags or directional counters), and IDS2018 and UNSW-NB15 have no identity columns for entity-scoped rules, so those cells say not evaluable. The 288,602 all-null padding rows in the CIC-IDS2017 Thursday-Morning file are dropped and counted instead of entering the benign denominator. Truth that cannot be scored is excluded, not merged into benign: 58 literal `Label` rows on IDS2018 are absent from the register, and 96,586 UNSW-NB15 rows carry categories the register marks unscorable. `DDoS attacks-LOIC-HTTP` (249,873) and `UDP-lag` (366,461) are no longer in that excluded set; they are scored as `ddos` and `slowdos`.

**Gate outcome of this pass:** two PASS and two FAIL. CIC-DDoS2019 passes both DDoS F1 (0.958094) and benign FPR (0.00692273); CIC-IDS2017 fails both DDoS F1 (0.611296) and benign FPR (0.14964929). The gates were fixed before the run and were not moved afterwards. The artifact is `runs/max_scale.md`, with every per-file cell and raw alert count in `runs/max_scale.json`.

## Gate verdicts

Two scopes, because they answer different questions. The phase rows were scored before this pass; the full-corpus rows are the ones to quote.

| Gate | Five-file phases (archived) | Full-corpus pass (current) |
|---|---|---|
| rule DDoS F1 >= 0.95 | PASS, 1.0 on CIC-DDoS2019 | PASS on CIC-DDoS2019 (0.958094), FAIL on CIC-IDS2017 (0.611296) |
| benign FPR <= 0.02 | PASS, worst 2.1e-05 | PASS on CIC-DDoS2019 (0.00692273, 113,828 benign), FAIL on CIC-IDS2017 (0.14964929) |

The phase rows are kept as history and their FPR denominators are not current;
the correction above explains why. The full pass scores every flow of every
capture, benign traffic included, and CIC-IDS2017 is the harder mixed-capture
test. IDS2018 and UNSW-NB15 rule cells and all CTU-13 cells remain not
evaluable, reported as such rather than as a zero. Alert-level precision and
incident recall are not pre-committed gates; they are reported beside the
gated flow metrics so a pass cannot hide a detector that fires on benign
windows or misses small incidents.

## Honest limitations

1. **The shipped artifact set is the CIC-IDS2017 one.** The Phase-2 retrained flow-context model was never pinned, so its records above cannot be reproduced from this tree and the full-corpus pass measures the earlier, zero-shot artifact instead. Its 2,264,599 training rows are the 80% split of the 2,830,743-flow CIC-IDS2017 register, which is what makes that corpus in-sample and nothing else. That retires the earlier "CIC-DDoS2019 is in-sample after Phase 2" wording: with the bytes that exist, the whole corpus is unseen, and the channel calls none of its 3.36M attack flows DDoS.
2. **IDS2018 ML DDoS recall is 0.34% at 3.288e-05 benign FPR** for the flowctx channel (no identity columns → 0 training windows), measured on 1.78M prefix flows. The old 0.56% at 17% figure is withdrawn with the label correction. The supervised channel learned IDS2018 per-flow classes (bot F1 0.30, bruteforce 0.49 in-sample) but those are in-sample numbers and not cross-corpus claims.
3. **ML cells are prefix slices.** The full pass scores the first 200,000 contiguous flows per file because the window model needs a feature frame. A file's prefix is often a single class, so per-file macro F1 is a coverage fact, not a quality estimate; only the family aggregates are read here, and the artifact states the prefix next to each cell.
4. **The CIC-IDS2017 benign denominator is real traffic.** The Thursday-Morning WebAttacks file carries 288,602 all-null padding rows (a doubled header in the original export). They are dropped and counted, so the 2,830,743-flow total and the 2,273,108 benign flows are real rows, not padding.
5. **LOSO threshold-transfer gap, disclosed:** leave-one-day-out ddos folds show AUC 0.998 (2/3 folds) but the fixed train threshold yields R 0.0 on some held-out days (Friday-2017 fold AUC 0.584). The pooled in-sample F1 1.0 must never be quoted as cross-day generalization; the oracle-threshold numbers are in `window_metrics.json`.
6. Mirror row caps (2^20/day) and the Infilteration official misspelling are export artifacts, documented here.
7. CTU-13 scenarios 45-50 were attempted for beacon expansion but the source server delivers ~100 KB/s (hours per file); the beacon model remains LOSO-validated on scenarios 42/43/51/52/53 and was **not retrained**, its metrics are unchanged and still honest.
8. **Alert-level scoring exposes misses the flow gates hide.** On CIC-DDoS2019 flow recall is 0.920 but incident recall is 0.122, because a few large floods carry most of the volume. On CIC-IDS2017 exact alert precision is 0.084 and 523 of 594 alerts are benign-only, while scan and slow-DoS incident recall are zero. The pre-committed gates cover only DDoS and benign FPR; passing them is not evidence that the rule layer covers every class.

## Reproduce

```bash
python -m scripts.benchmarks.bench_transfer --targets "cic-ddos2019=data/raw/ddos2019/01-12/Syn.csv" --out results/transfer/ddos2019
python -m scripts.benchmarks.bench_transfer --targets "cic-ids2018-nf-v2-hoic=data/raw/ids2018/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv" --out results/transfer/hoic
# (and bot / bruteforce / infil analogously; family paths are in corpus_ledger.json)
# every file of every corpus, full row count:
python -m scripts.benchmarks.bench_corpora --jobs 4 --model-dir models
# re-render the report from stored cells, without re-scoring:
python -m scripts.benchmarks.bench_corpora --from-json results/transfer/max/max_results.json --out results/transfer/max
```
