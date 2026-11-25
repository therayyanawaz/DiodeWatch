# Dataset register

Live provenance for every file: `data/raw/manifest.json` (URL + SHA256 + bytes
+ fetch time, written by the fetch scripts). Corpora never committed
(see .gitignore). Rows below summarize; the manifest is authoritative.

| Corpus | Local path | Source script | Contents |
|---|---|---|---|
| CIC-IDS2017, all 8 day-files (5 capture days; BENIGN + DoS GoldenEye/Hulk/slowhttptest/slowloris + Heartbleed + WebAttack + Infiltration + Bot + PortScan + DDoS), full official schema (85 cols) | `data/raw/cic2017/` (8 files, ~292 MB) + `data/slices/baseline_slice.parquet` (200,000 rows, 50/50, seed 42) + `data/slices/flows.ndjson` (200k canonical records) | `scripts/fetch/download_ml_corpora.py`, `scripts/fetch/download_baseline_slice.py` | 2,830,743 real flow rows in total (the Thursday-Morning WebAttacks file carries 288,602 all-null padding rows; the max-scale benchmark drops them and reports the count rather than scoring them as benign). Raw parquet SHA256 `d23a259820b16e1ad54f9f3b58d5727c5032d383015f90bc7c07cebbdf8a7140` (verified 2026-09-16); slice rebuilt 2026-09-16 SHA256 `1ad22cb47af2b708433af01024abf73612da5e9f22be3bc313c93255e493ff9e` (same seed/rows as the Sep slice `ff806f…`; bytes differ by parquet writer version only) |
| CIC-DDoS2019, 01-12 training day (11/11 CSVs, ~50.06M rows) + 03-11 test day (7/7 CSVs, ~20.36M rows) | `data/raw/ddos2019/` (~21 GB) | `scripts/fetch/download_transfer_corpora.py` + `verify_transfer_corpora.py` | HF `baalajimaestro/CICDDoS2019` mirror; per-file SHA256 in `data/raw/manifest.json`, row/label counts in `data/raw/corpus_ledger.json`. Full identity columns on all 18 files. `01-12/Syn.csv` row-exact: 1,582,681 rows = Sep-2026 zero-shot corpus. 01-12/TFTP dominates (20.1M rows). Mixed-label files: 03-11/LDAP (+NetBIOS), 03-11/MSSQL (+LDAP), 03-11/UDP (+MSSQL), 03-11/UDPLag (+Syn/UDP), 01-12/UDPLag (UDP-lag + WebDDoS) |
| CSE-CIC-IDS2018, all 10 TrafficForML days (10/10, 16,233,002 rows) | `data/raw/ids2018/` (~7 GB) | `scripts/fetch/download_transfer_corpora.py` + `verify_transfer_corpora.py` | HF `bencorn/CICIDS2018` mirror of the official CICFlowMeter exports. Verified quirks: NO identity columns on any day (rules not-evaluable there, as Sep eval reported); 7 day-files capped at exactly 1,048,575 rows (CIC export limitation); Tue-20 (LOIC-HTTP, 7.95M rows) is the only uncapped day, while Thu-01 and Wed-28 stop short of the cap; literal `'Label'` strings appear as label values in Fri-16/Thu-01/Wed-28 (repeated-header remnants, dropped by the bench guard) |
| UNSW-NB15 training-set.csv (175,341 rows; testing-set.csv not hosted on this mirror) + feature doc | `data/raw/unsw/` (32 MB) | `scripts/fetch/download_transfer_corpora.py` + `verify_transfer_corpora.py` | HF `Mouwiya/UNSW-NB15` mirror; canonical columns (`attack_cat`, `label`) verified |
| CTU-13, all 13 scenarios (42-54, ~19.98M NetFlows) | `data/raw/ctu13/` | `scripts/fetch/download_ml_corpora.py` (42/43/51/52/53) + `download_transfer_corpora.py` (44-50, 54) + `verify_transfer_corpora.py` | `mcfp.felk.cvut.cz` official host; per-file SHA256 in manifest, row/bot counts in ledger |
| DGA: argencon.csv.gz (1.0M benign + 1.9M DGA, 51 families) | `data/raw/dga/` (34 MB) | `scripts/fetch/download_ml_corpora.py` | HF `harpomaxx/dga-detection` (CC-BY-2.0) |
| Benign domains: Umbrella top-1m | `data/raw/dns/top-1m.csv.zip` (13 MB) | fetched 2026-09-16, SHA256 `fe3a9c73221ef45d…` (full: manifest) | `s3-us-west-1.amazonaws.com/umbrella-static` (independent holdout, never trained on) |
| TLS: abuse.ch SSLBL JA3 fingerprints | `docs/evaluation/tls/ja3_fingerprints.csv` (8.5 kB, **committed**, the channel needs it on a fresh clone, and `data/` is ignored) | fetched 2026-09-16, SHA256 `6974182489b6e5f5…` (full: manifest) | `sslbl.abuse.ch` watchlist for `src/detectors/ml/tls_ja3.py`; refresh by overwriting this file |

Notes:

- **Identity columns are required by the ingest layer** (`src/ingest`). An earlier mirror
  (`c01dsnap`) stripped `Flow ID / IPs / ports / Protocol / Timestamp`, so the corpus moved
  to the `traffic_labels` mirror above, which keeps the full official CIC schema.
- `data/slices/flows.ndjson` (unifier output, 200,000 canonical records) is derived
  and git-ignored; regenerate with
  `python -m src.ingest.unify --input data/slices/baseline_slice.parquet --out data/slices/flows.ndjson`.
- Known source quirks (passed through faithfully, do not "fix"):
  - 330 BENIGN flows have `Protocol=0` and `Source/Destination Port=0` (CICFlowMeter could
    not resolve their protocol; packet counts are non-zero).
  - 21 BENIGN flows carry `Flow Duration=-1` (CIC sentinel for "not computable").
  - 213 of the 200,000 slice rows carry a negative inter-arrival time (200 are exactly
    `-1`, the same "not computable" sentinel; the rest reach `-13` µs, from packets the
    capture wrote out of order). The unifier passes them through, a negative gap is
    what an out-of-order capture genuinely is, and the pcap reader can produce one.
  - `120000000` µs appears as the ceiling in 9 of the 14 IAT columns. That is not a
    coincidence: it is exactly the 120 s flow timeout, so the largest gap a flow can
    ever contain is the gap that closed it. Our own pcap grouping enforces the same
    bound, which is why the two sources agree on the extreme.

**Provenance completeness:** every corpus file under `data/raw/` has exactly one
entry in `data/raw/manifest.json` (URL + SHA256 + bytes + first-fetch time), 54
files as of the last verify. Re-running a fetcher on a file it already has never
rewrites that entry; a file fetched by an older script revision is backfilled from
the file itself with its on-disk mtime as the fetch time, never with the re-run's
clock. UNSW's `testing-set.csv` has no pinned mirror, so it is absent from the
manifest rather than silently missing.

Planned next (not yet fetched, no pinned mirror verified): 3-5 Malware-Traffic-Analysis.net pcaps for `data/pcaps/` (per-post URLs, manual).

Rules: corpora never committed to git (see .gitignore); every dataset gets a pinned URL + SHA256 before it is used in training or benchmarks; eval slices are written once and never touched by training code.
