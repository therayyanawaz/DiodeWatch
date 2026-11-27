# Model card, `tls_novelty.joblib`

TLS/JA3 channel: an abuse.ch SSLBL watchlist plus an IsolationForest novelty
model over five aggregate connection features. The watchlist is a lookup, not a
statistical guess; the novelty model is the part that can generalize to a
fingerprint the list does not contain.

## What it reads

Five channel features, in this order (the order is the contract, see
[`feature_order.json`](feature_order.json)):

| # | Feature | What it captures |
|---|---|---|
| 1 | `n_conns` | connections the client opened in the window |
| 2 | `n_dst` | distinct destinations the client contacted |
| 3 | `sni_rate` | share of connections that carried SNI |
| 4 | `n_dst_ports` | distinct destination ports |
| 5 | `conns_per_dst` | connections per destination |

Missing values use the ordered median mapping stored in the artifact.

## What it decides

A client is flagged when its JA3 hash is on the pinned watchlist, or when its
novelty score falls outside the stored baseline interval. JA4 and JA4S are
carried into the alert evidence as context; they do not add a feature or a
watchlist hit. On this artifact the novelty interval is empty (`nov_lo` and
`nov_hi` are both `0.0`) and `degenerate_baseline` is `true`, so the novelty
branch is disabled and the watchlist lookup is the only alert source. The
generated baseline gives every
client the same aggregate vector, which is not enough spread to fit a novelty
boundary. A real Zeek `ssl.log` baseline is what makes that branch usable.

| Property | Value |
|---|---|
| Estimator | IsolationForest, 150 trees, contamination 0.02 |
| Watchlist | 97 SSLBL JA3 hashes, pinned offline |
| Novelty interval | `0.0` to `0.0` (no usable spread) |
| Channel state | watchlist active, novelty disabled |

## Provenance and limits

Fit on 5,004 generated benign-shaped clients from the pinned synthetic
workload, with the SSLBL watchlist loaded from
`docs/evaluation/tls/ja3_fingerprints.csv`. The measured plant check is in
`docs/evaluation/runs/tls_metrics.json`.

* **The synthetic plant is not real-data performance.** It proves the
  watchlist path fires and the novelty path was evaluated separately; it does
  not prove detection on a live network.
* **A watchlist is stale by construction.** New families and rotated
  fingerprints are missed until the list is refreshed.
* **The novelty branch needs a real baseline.** With one aggregate vector per
  client the fit set has no spread, so the channel correctly disables itself
  instead of scoring noise.
* **Server-side fingerprinting is context, not a decision.** The pcap metadata
  reader computes JA3S and JA4S from the ServerHello, but the model features and
  the watchlist are client-side JA3 only. Certificate chains and application data
  are still never read.

## Integrity

| | |
|---|---|
| File | `docs/evaluation/models/tls_novelty.joblib` |
| Bytes | 97,163 |
| sha256 | `1ce23b359e446d16d6bfaaedffe2416dd54942d2269c2be78364df67a3598828` |
| Restored to | `models/tls_novelty.joblib` |
| Loader | `src/detectors/ml/tls_ja3.py` |

If the file is absent the loader keeps the static watchlist path and reports
the novelty model unavailable.