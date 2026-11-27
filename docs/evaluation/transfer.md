# Transfer evaluation, consolidated cross-corpus summary (REAL corpora)

**Dates:** 2026-10-18 zero-shot phase; model pin and full-corpus pass 2026-11-27 · **Harness:** `scripts/benchmarks/bench_transfer.py` · **Pre-committed gates:** rule DDoS F1 ≥ 0.95 on every evaluable corpus; benign FPR ≤ 0.02. Gates were fixed before any run and never tuned after seeing results.

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

**2026-11-26 correction to the archived phase table.** The table above is left
as the 2026-10-18 record. It was produced before two real label
spellings were registered: `DDoS attacks-LOIC-HTTP` (249,873 CSE-CIC-IDS2018
flows) and `UDP-lag` (366,461 CIC-DDoS2019 flows). Both were scored as
unmapped and stayed inside the benign denominators above. The register now
maps them, and the full-corpus pass below is regenerated from the corrected
truth. Do not quote the phase-table FPRs as current: the IDS2018 ML FPR in
particular was 0.1704 partly because LOIC attack flows the model already
detected were counted as benign false positives. They are now true positives,
and the corrected family FPR is 3.288e-05.

## Max scale, every pinned file (2026-11-27)

The zero-shot phase above scored five files chosen from what happened to be on disk. This pass scores the register: `scripts/benchmarks/bench_corpora.py` reads every pinned file of all five corpora, 50 files and 109,643,423 flows in 732.3 seconds, with the rule layer streamed in 250,000-flow chunks and the ML channel on the first 200,000 contiguous flows of each file. The ML scope is a deliberate limit, not a sample: the window model needs a feature frame, and a capture-wide pass is not what a deployment feeds it, so the artifact prints the prefix next to every ML number.

```bash
python -m scripts.benchmarks.bench_corpora --jobs 4 --model-dir <models>
```

| Corpus | Files | Flows scored | Rules, macro F1 | ML, macro F1 |
|---|---|---|---|---|
| CIC-IDS2017 | 8/8 | 2,830,743 | 0.862 | 0.413 |
| CIC-DDoS2019 | 18/18 | 70,427,637 | 0.534 | 0.006 |
| CSE-CIC-IDS2018 | 10/10 | 16,233,002 | not evaluable, no identity | 0.192 |
| UNSW-NB15 | 1/1 | 175,341 | not evaluable, no identity | 0.278 |
| CTU-13 | 13/13 | 19,976,700 | not evaluable, NetFlow | not evaluable, NetFlow |

**Which artifact produced the ML cells.** The run loaded `flowctx_lgbm.joblib`, 2,326,265 bytes, sha256 `01c72bbe06ed...`, whose own metadata records 2,264,599 training rows and the 2026-11-27 rebuild. That is the CIC-IDS2017 model, pinned in `docs/evaluation/models/`. CIC-IDS2017 is therefore in-sample for the ML channel, while CIC-DDoS2019, CSE-CIC-IDS2018 and UNSW-NB15 are genuinely unseen by it. The run records the byte count and SHA256 of every artifact it loads, so a cell can always be traced to the bytes that produced it. The retrained phase records were withdrawn because their bytes were never preserved; no number above depends on them.

**What the full pass adds.**

1. **Flow recall is not incident recall.** On CIC-DDoS2019 the rule layer reaches DDoS flow recall 0.99788 (F1 0.996426), but only 1,175 of 9,927 DDoS truth units `(window, destination)` receive an alert, incident recall 0.1184. The alerts concentrate on the large floods that carry most of the 69.9M flows; most small victim windows are missed. On CIC-IDS2017 DDoS flow recall is 0.979339 and incident recall 41/51; 89 of 96 alerts are exact (precision 0.927083), 5 contain no attack truth, slow-DoS is 33/46, and canonical scan recall is 15/222 (15/27 PortScan; 195 Patator/web units folded in). Two further slow-DoS claims land on Wednesday DDoS Hulk windows: class confusion on attack traffic, not a benign false positive.
2. **Specificity is now measured at both levels.** CIC-IDS2017 benign FPR is 5,523/2,273,108 = 0.00242971, inside the 0.02 gate, but 5 of 96 alerts are benign-only (2 scan, 2 exfil, 1 slow DoS). The 500 kB exfil ratio floor and the host-sweep removal account for the 192-to-102 alert reduction and the 12-alert DDoS2019 reduction; the 250/s byte floor and reply-aware port gate then took 27 CIC2017 DDoS false bursts, leaving 75; the slow-DoS recall work added ten attack-side alerts, taking the pass to 85, and the held-dominant slow profile plus the narrow scan branch added eleven more, taking it to 96. DDoS flow recall is unchanged on both corpora; CIC2017 precision rose to 0.998907 and CIC-DDoS2019 precision is unchanged. CIC-DDoS2019 benign FPR is 51/113,828 = 0.00044804; no alert is benign-only and exact alert precision is 1,175/1,183 = 0.993238. The old 0.797 FPR is withdrawn: 366,461 `UDP-lag` attack flows were inside its benign denominator.
3. **The zero-shot ML gap remains large.** The CIC-IDS2017 model calls 0 of 3,361,567 CIC-DDoS2019 attack flows DDoS, 0.34% of 506,537 IDS2018 DDoS flows, and 0.13% of UNSW-NB15 DoS flows. In-sample CIC-IDS2017 reaches 51.9% DDoS recall at 28 false positives in 1,179,766 benign flows (FPR 2.4e-05). The IDS2018 family FPR is 32/973,140 = 3.288e-05 after the LOIC correction, not the archived 0.1704; that old figure counted detected attack flows as benign false positives.
4. **Coverage is complete and nothing is faked.** CTU-13 has neither flow channel (a NetFlow export carries no TCP flags or directional counters), and IDS2018 and UNSW-NB15 have no identity columns for entity-scoped rules, so those cells say not evaluable. The CTU-13 rows are now readable through `src/ingest/flow_reader.py`, but ingest support does not make the missing channels evaluable: the export's flag set is not a per-packet count and its counters are not directional. The 288,602 all-null padding rows in the CIC-IDS2017 Thursday-Morning file are dropped and counted instead of entering the benign denominator. Truth that cannot be scored is excluded, not merged into benign: 58 literal `Label` rows on IDS2018 are absent from the register, and 96,586 UNSW-NB15 rows carry categories the register marks unscorable. `DDoS attacks-LOIC-HTTP` (249,873) and `UDP-lag` (366,461) are no longer in that excluded set; they are scored as `ddos` and `slowdos`.

**Gate outcome of this pass:** four PASS. CIC-DDoS2019 passes DDoS F1 (0.996426) and benign FPR (0.00044804); CIC-IDS2017 passes DDoS F1 (0.989026) and benign FPR (0.00242971). The gates were fixed before the run and were not moved afterwards. The artifact is `runs/max_scale.md`, with every per-file cell and raw alert count in `runs/max_scale.json`.

## Gate verdicts

Two scopes, because they answer different questions. The zero-shot phase rows were scored before this pass; the full-corpus rows are the ones to quote.

| Gate | Five-file zero-shot phase (archived) | Full-corpus pass (current) |
|---|---|---|
| rule DDoS F1 >= 0.95 | PASS, 1.0 on CIC-DDoS2019 | PASS both: 0.996426 on CIC-DDoS2019, 0.989026 on CIC-IDS2017 |
| benign FPR <= 0.02 | n/a, archived denominators were withdrawn by the label correction | PASS both: 0.00044804 on CIC-DDoS2019 (113,828 benign), 0.00242971 on CIC-IDS2017 (2,273,108 benign) |

The phase rows are kept as history and their FPR denominators are not current;
the correction above explains why. The full pass scores every flow of every
capture, benign traffic included, and CIC-IDS2017 is the harder mixed-capture
test. IDS2018 and UNSW-NB15 rule cells and all CTU-13 cells remain not
evaluable, reported as such rather than as a zero. Alert-level precision and
incident recall are not pre-committed gates; they are reported beside the
gated flow metrics so a pass cannot hide a detector that fires on benign
windows or misses small incidents.

## Honest limitations

1. **The shipped artifact set is the CIC-IDS2017 one, and it is pinned.** The flow-context model behind every ML cell is the 2,326,265-byte artifact in `docs/evaluation/models/`, rebuilt on scikit-learn 1.9.0 on 2026-11-27. Its 2,264,599 training rows are the 80% split of the 2,830,743-flow CIC-IDS2017 register, which is what makes that corpus in-sample and nothing else. The retrained phase was withdrawn with its unpinned bytes, so no published number now depends on a model that cannot be loaded.
2. **IDS2018 ML DDoS recall is 0.34% at 3.288e-05 benign FPR** for the flowctx channel (no identity columns → 0 training windows), measured on 1.78M prefix flows. The old 0.56% at 17% figure is withdrawn with the label correction. The supervised reference was part of the withdrawn retrained phase; its in-sample table is not published here.
3. **ML cells are prefix slices.** The full pass scores the first 200,000 contiguous flows per file because the window model needs a feature frame. A file's prefix is often a single class, so per-file macro F1 is a coverage fact, not a quality estimate; only the family aggregates are read here, and the artifact states the prefix next to each cell.
4. **The CIC-IDS2017 benign denominator is real traffic.** The Thursday-Morning WebAttacks file carries 288,602 all-null padding rows (a doubled header in the original export). They are dropped and counted, so the 2,830,743-flow total and the 2,273,108 benign flows are real rows, not padding.
5. **LOSO threshold-transfer gap, disclosed:** the two leave-one-day-out ddos folds measure AUC 0.9205 (Friday) and 0.9971 (Wednesday), but the fixed training threshold yields recall 0.0 on both held-out days. The oracle operating points are F1 0.9024 and 0.9834. The pooled in-sample result must never be quoted as cross-day generalization; the fold counts are in `window_metrics.json`.
6. Mirror row caps (2^20/day) and the Infilteration official misspelling are export artifacts, documented here.
7. CTU-13 scenarios 45-50 were attempted for beacon expansion but the source server delivers ~100 KB/s (hours per file); the beacon model remains LOSO-validated on scenarios 42/43/51/52/53 and was **not retrained**, its metrics are unchanged and still honest.
8. **Alert-level scoring exposes misses the flow gates hide.** On CIC-DDoS2019 flow recall is 0.99788 but incident recall is 0.1184, because a few large floods carry most of the volume. On CIC-IDS2017 exact alert precision is 0.927083 and 5 of 96 alerts are benign-only; slow-DoS recall is 33/46 and canonical scan recall is 15/222 (15/27 PortScan; 195 Patator/web units folded in). The pre-committed gates cover only DDoS and benign FPR; passing them is not evidence that the rule layer covers every class.

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
