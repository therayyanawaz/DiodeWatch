# Max-scale evaluation, every pinned flow corpus

Every corpus file on disk scored at its full row count, with the rule layer streamed in 250,000-flow chunks and the ML channel on the first 200,000 contiguous flows of each file. Rules never train, so every rule cell is out-of-sample. The ML cells name their own status: in-sample where the corpus trained the shipped artifact, out-of-sample where it never did. Artifacts: `flowctx_lgbm.joblib` fcc1e635a4fe, `tls_novelty.joblib` 78e8d8f2335d, `beacon_lgbm.joblib` 6ba89cc912c1, `dga_lgbm.joblib` 5662ee278023.

## cic-ids2017, 2,830,743 flows in 8 files
- all 8 day-files (5 capture days), 85-column official schema; ML in-sample: these days trained the shipped artifact
- **rules** (window rules): macro F1 0.155432, micro F1 0.244879, scored 2,828,741 flows
    - benign: P 0.956414, R 0.154599, F1 0.266173, n 2,273,108
    - ddos: P 0.216216, R 1.0, F1 0.355556, n 369,393
    - scan: P 0.0, R 0.0, F1 0.0, n 174,945
    - slowdos: P None, R 0.0, F1 0.0, n 11,295
    - benign FPR 1,921,687/2,273,108 = 0.84540066 ([FAIL])
- **ml** (ml.flowctx (flow + window context)): macro F1 0.413036, micro F1 0.409471, scored 1,559,401 flows
    - benign: P 0.905741, R 0.999976, F1 0.950529, n 1,179,766
    - ddos: P 1.0, R 0.51894, F1 0.683292, n 246,703
    - scan: P 0.017809, R 0.018868, F1 0.018323, n 121,637
    - slowdos: P None, R 0.0, F1 0.0, n 11,295
    - benign FPR 28/1,179,766 = 2.373e-05 ([PASS])
    - ML prefix 1,561,399 flows (first 200,000 per file, 0 without a usable clock): a coverage slice, and a single file's prefix is often one class, so read the family line

## cic-ddos2019, 70,427,637 flows in 18 files
- all 18 CSVs of the 01-12 and 03-11 collection days; ML out-of-sample: the shipped artifact predates the Phase 2 retraining and no published training claim covers this corpus
- unmapped labels (reported, never merged): `{'UDP-lag': 366461}`
- **rules** (window rules): macro F1 0.431983, micro F1 0.917507, scored 70,427,637 flows
    - benign: P 1.0, R 0.20309, F1 0.337614, n 480,289
    - ddos: P 0.999955, R 0.920042, F1 0.958336, n 69,945,475
    - slowdos: P None, R 0.0, F1 0.0, n 1,873
    - benign FPR 382,747/480,289 = 0.79690978 ([FAIL])
- **ml** (ml.flowctx (flow + window context)): macro F1 0.039835, micro F1 0.0, scored 3,591,694 flows
    - benign: P 0.063551, R 1.0, F1 0.119506, n 228,254
    - ddos: P None, R 0.0, F1 0.0, n 3,361,567
    - slowdos: P None, R 0.0, F1 0.0, n 1,873
    - benign FPR 0/228,254 = 0.0 ([PASS])
    - ML prefix 3,591,694 flows (first 200,000 per file, 0 without a usable clock): a coverage slice, and a single file's prefix is often one class, so read the family line

## cic-ids2018, 16,233,002 flows in 10 files
- all 10 TrafficForML days; no identity columns, so rules are not evaluable; ML is out-of-sample for the shipped artifact
- unmapped labels (reported, never merged): `{'DDoS attacks-LOIC-HTTP': 249873, 'Label': 58}`
- **rules**: not evaluable, identity columns absent in export, entity-scoped rules not evaluable (reported, never faked)
- **ml** (ml.flowctx (flow + window context)): macro F1 0.179449, micro F1 0.004237, scored 1,782,763 flows
    - benign: P 0.615456, R 0.829565, F1 0.706648, n 1,173,034
    - ddos: P 0.981725, R 0.005606, F1 0.011148, n 306,643
    - scan: P 0.0, R 0.0, F1 0.0, n 200,662
    - slowdos: P None, R 0.0, F1 0.0, n 102,424
    - benign FPR 199,926/1,173,034 = 0.17043496 ([FAIL])
    - ML prefix 1,999,980 flows (first 200,000 per file, 20 without a usable clock): a coverage slice, and a single file's prefix is often one class, so read the family line

## unsw-nb15, 175,341 flows in 1 files
- training-set.csv, 175,341 flows; no identity columns, never used in training, so the ML cell is out-of-sample
- **rules**: not evaluable, identity columns absent in export, entity-scoped rules not evaluable (reported, never faked)
- **ml** (ml.flowctx (flow + window context)): macro F1 0.277948, micro F1 0.001405, scored 78,755 flows
    - benign: P 0.71121, R 1.0, F1 0.831237, n 56,000
    - ddos: P 1.0, R 0.001305, F1 0.002606, n 12,264
    - scan: P None, R 0.0, F1 0.0, n 10,491
    - benign FPR 0/56,000 = 0.0 ([PASS])
    - ML prefix 175,341 flows (first 200,000 per file, 0 without a usable clock): a coverage slice, and a single file's prefix is often one class, so read the family line

## ctu-13, 19,976,700 flows in 13 files
- all 13 scenarios; NetFlow export, neither flow channel applies
- **rules**: not evaluable, NetFlow export has no TCP flags or directional counters, so neither flow channel is defined
- **ml**: not evaluable, directional flow statistics unavailable in this export

## Pre-committed gates (unchanged from bench_transfer)
- [FAIL] rule ddos F1 >= 0.95 (cic-ids2017): 0.355556
- [FAIL] benign FPR <= 0.02 (cic-ids2017): 0.84540066
- [PASS] rule ddos F1 >= 0.95 (cic-ddos2019): 0.958336
- [FAIL] benign FPR <= 0.02 (cic-ddos2019): 0.79690978
