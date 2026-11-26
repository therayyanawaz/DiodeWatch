# Max-scale evaluation, every pinned flow corpus

Every corpus file on disk scored at its full row count, with the rule layer streamed in 250,000-flow chunks and the ML channel on the first 200,000 contiguous flows of each file. Rules never train, so every rule cell is out-of-sample. The ML cells name their own status: in-sample where the corpus trained the shipped artifact, out-of-sample where it never did. Artifacts: `flowctx_lgbm.joblib` fcc1e635a4fe, `tls_novelty.joblib` 78e8d8f2335d, `beacon_lgbm.joblib` 6ba89cc912c1, `dga_lgbm.joblib` 5662ee278023.

## cic-ids2017, 2,830,743 flows in 8 files
- all 8 day-files (5 capture days), 85-column official schema; ML in-sample: these days trained the shipped artifact
- **rules** (window rules): macro F1 0.381306, micro F1 0.516607, scored 2,828,741 flows
    - benign: P 0.98778, R 0.850351, F1 0.913928, n 2,273,108
    - ddos: P 0.440538, R 0.998216, F1 0.611296, n 369,393
    - scan: P 0.0, R 0.0, F1 0.0, n 174,945
    - slowdos: P None, R 0.0, F1 0.0, n 11,295
    - benign FPR 340,169/2,273,108 = 0.14964929 ([FAIL])
    - alerts: 594/594 scored, exact precision 0.084175, any-attack precision 0.119529, 523 benign-only
    - alert recall (window x entity): ddos 47/51, slowdos 0/46, scan 0/222
- **ml** (ml.flowctx (flow + window context)): macro F1 0.413036, micro F1 0.409471, scored 1,559,401 flows
    - benign: P 0.905741, R 0.999976, F1 0.950529, n 1,179,766
    - ddos: P 1.0, R 0.51894, F1 0.683292, n 246,703
    - scan: P 0.017809, R 0.018868, F1 0.018323, n 121,637
    - slowdos: P None, R 0.0, F1 0.0, n 11,295
    - benign FPR 28/1,179,766 = 2.373e-05 ([PASS])
    - ML prefix 1,561,399 flows (first 200,000 per file, 0 without a usable clock): a coverage slice, and a single file's prefix is often one class, so read the family line

## cic-ddos2019, 70,427,637 flows in 18 files
- all 18 CSVs of the 01-12 and 03-11 collection days; ML out-of-sample: the shipped artifact predates the Phase 2 retraining and no published training claim covers this corpus
- **rules** (window rules): macro F1 0.555309, micro F1 0.915895, scored 70,427,637 flows
    - benign: P 0.549888, R 0.993077, F1 0.707834, n 113,828
    - ddos: P 0.99934, R 0.920118, F1 0.958094, n 69,945,475
    - slowdos: P None, R 0.0, F1 0.0, n 368,334
    - benign FPR 788/113,828 = 0.00692273 ([PASS])
    - alerts: 1,424/1,424 scored, exact precision 0.918539, any-attack precision 0.990871, 13 benign-only
    - alert recall (window x entity): ddos 1,216/9,927, slowdos 0/448
- **ml** (ml.flowctx (flow + window context)): macro F1 0.005954, micro F1 0.0, scored 3,591,694 flows
    - benign: P 0.009012, R 1.0, F1 0.017863, n 32,368
    - ddos: P None, R 0.0, F1 0.0, n 3,361,567
    - slowdos: P None, R 0.0, F1 0.0, n 197,759
    - benign FPR 0/32,368 = 0.0 ([PASS])
    - ML prefix 3,591,694 flows (first 200,000 per file, 0 without a usable clock): a coverage slice, and a single file's prefix is often one class, so read the family line

## cic-ids2018, 16,233,002 flows in 10 files
- all 10 TrafficForML days; no identity columns, so rules are not evaluable; ML is out-of-sample for the shipped artifact
- unmapped labels (reported, never merged): `{'Label': 58}`
- **rules**: not evaluable, identity columns absent in export, entity-scoped rules not evaluable (reported, never faked)
- **ml** (ml.flowctx (flow + window context)): macro F1 0.192179, micro F1 0.0034, scored 1,782,763 flows
    - benign: P 0.615456, R 0.999967, F1 0.76195, n 973,140
    - ddos: P 0.981725, R 0.003394, F1 0.006764, n 506,537
    - scan: P 0.0, R 0.0, F1 0.0, n 200,662
    - slowdos: P None, R 0.0, F1 0.0, n 102,424
    - benign FPR 32/973,140 = 3.288e-05 ([PASS])
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
- [FAIL] rule ddos F1 >= 0.95 (cic-ids2017): 0.611296
- [FAIL] benign FPR <= 0.02 (cic-ids2017): 0.14964929
- [PASS] rule ddos F1 >= 0.95 (cic-ddos2019): 0.958094
- [PASS] benign FPR <= 0.02 (cic-ddos2019): 0.00692273
