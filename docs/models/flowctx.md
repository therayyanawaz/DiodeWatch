# Model card, `flowctx_lgbm.joblib`

One-vs-rest LightGBM ensemble for flow plus 10-second window context. Each
threat class has its own binary booster, decision threshold and imputation
medians. The ensemble scores one flow at a time, but the window aggregates on
that flow describe the traffic around it.

## What it reads

Fifty-nine numeric features, in this order (the order is the contract, see
[`feature_order.json`](feature_order.json)):

| # | Feature | What it captures |
|---|---|---|
| 1 | `duration_s` | connection lifetime in seconds |
| 2 | `fwd_pkts` | packets sent by the source |
| 3 | `bwd_pkts` | packets returned by the destination |
| 4 | `tot_pkts` | both directions combined |
| 5 | `fwd_bytes` | payload bytes sent by the source |
| 6 | `bwd_bytes` | payload bytes returned |
| 7 | `tot_bytes` | both directions combined |
| 8 | `avg_fwd_pkt_size` | mean outbound packet size |
| 9 | `avg_bwd_pkt_size` | mean inbound packet size |
| 10 | `avg_pkt_size` | mean packet size across the flow |
| 11 | `flow_bytes_per_s` | total byte rate |
| 12 | `flow_pkts_per_s` | total packet rate |
| 13 | `fwd_bytes_per_s` | outbound byte rate |
| 14 | `bwd_bytes_per_s` | inbound byte rate |
| 15 | `fwd_pkts_per_s` | outbound packet rate |
| 16 | `bwd_pkts_per_s` | inbound packet rate |
| 17 | `fwd_byte_ratio` | outbound share of bytes |
| 18 | `byte_asymmetry` | directional byte imbalance |
| 19 | `pkt_asymmetry` | directional packet imbalance |
| 20 | `is_tcp` | TCP protocol indicator |
| 21 | `is_udp` | UDP protocol indicator |
| 22 | `is_icmp` | ICMP protocol indicator |
| 23 | `fin_flags` | FIN flag count |
| 24 | `syn_flags` | SYN flag count |
| 25 | `rst_flags` | RST flag count |
| 26 | `psh_flags` | PSH flag count |
| 27 | `ack_flags` | ACK flag count |
| 28 | `urg_flags` | URG flag count |
| 29 | `is_dns` | DNS port indicator |
| 30 | `src_flow_count` | flows the source produced |
| 31 | `src_dst_port_count` | distinct destination ports the source touched |
| 32 | `src_dst_ip_count` | distinct destinations the source touched |
| 33 | `src_dst_port_entropy` | spread of the source's destination ports |
| 34 | `src_dns_share` | DNS share of the source's flows |
| 35 | `dst_flow_count` | flows the destination received |
| 36 | `dst_src_port_count` | distinct source ports the destination saw |
| 37 | `dst_src_ip_count` | distinct sources that reached the destination |
| 38 | `dst_src_port_entropy` | spread of the destination's source ports |
| 39 | `wdst_flows` | flows to the destination in this window |
| 40 | `wdst_n_src` | distinct sources in that window |
| 41 | `wdst_flows_per_sec` | destination flow rate |
| 42 | `wdst_fwd_bytes_per_sec` | bytes sent to the destination per second |
| 43 | `wdst_pkts_ratio` | packet balance toward the destination |
| 44 | `wdst_mean_fwd_pkt` | mean inbound packet size at the destination |
| 45 | `wdst_syn_share` | SYN share of the destination's window |
| 46 | `wdst_half_open` | half-open connection count |
| 47 | `wdst_src_conc` | source concentration at the destination |
| 48 | `wdst_udp_share` | UDP share of the destination's window |
| 49 | `wdst_held_conns` | long-lived connections to the destination |
| 50 | `wdst_mean_dur_s` | mean connection duration at the destination |
| 51 | `wsrc_flows` | flows from the source in this window |
| 52 | `wsrc_n_dports` | distinct destination ports the source used |
| 53 | `wsrc_n_dips` | distinct destinations the source contacted |
| 54 | `wsrc_bytes_per_flow` | mean bytes per source flow |
| 55 | `wsrc_upload_ratio` | outbound share for the source |
| 56 | `wsrc_resp_share` | share of source flows with a response |
| 57 | `wsrc_udp_share` | UDP share of the source's window |
| 58 | `wsrc_internal_dst_share` | internal-destination share |
| 59 | `wsrc_server_share` | server-port share |

Missing values are filled from the per-class median mapping stored in the
artifact. That mapping is ordered because it is also the training-order record.

## What it decides

For each class the booster returns a probability; an alert is emitted when the
probability is at or above that class's stored threshold. The thresholds travel
with the weights so a loader cannot silently re-tune them.

| Class | Stored threshold |
|---|---:|
| ddos | `0.9999027992847203` |
| scan | `0.9999996486421512` |
| bruteforce | `0.999968488630534` |
| webattack | `0.9999999102800384` |
| bot | `0.999999999220716` |

| Property | Value |
|---|---|
| Estimator | LightGBM binary boosters, 300 trees, 63 leaves, learning rate 0.1 |
| Classes | five one-vs-rest boosters plus a benign class label |
| Imputation | per-class median mapping stored in the artifact |

## Provenance and limits

Trained on the eight CIC-IDS2017 day files: 2,264,599 protocol-A training rows
and 566,144 held-out rows, 10-second windows. The run record with the measured
behaviour is `docs/evaluation/runs/window_metrics.json`; this card records the
artifact identity and the decision contract, not a second copy of the metrics.

* **Protocol A shares window context across neighbouring flows.** The
  leave-one-day-out ddos result is the strict cross-day check, and its fixed
  training threshold can return zero recall on a held-out day even when the
  ranking transfers. That is why the alerting point is reported as in-sample
  and the LOSO result is kept beside it, not averaged into the headline.
* **Web attack and bot support is small.** Their thresholds are tuned on
  roughly one to two thousand positives; treat those operating points as
  indicative. The dedicated beacon and TLS channels carry most of the bot
  coverage.
* **Infiltration is not trained.** Twenty-nine flows corpus-wide cannot train
  or evaluate a class honestly.
* **This is the CIC-IDS2017 model.** It is in-sample for CIC-IDS2017 and
  out-of-sample for every other corpus. The full-corpus evaluation names that
  status per family.

## Integrity

| | |
|---|---|
| File | `docs/evaluation/models/flowctx_lgbm.joblib` |
| Bytes | 2,326,265 |
| sha256 | `01c72bbe06ed42ae5650147248333f0073dcff208a82db5a7d2ca935d2670a75` |
| Restored to | `models/flowctx_lgbm.joblib` |
| Loader | `src/detectors/ml/supervised_windows.py` |

If the file is absent the loader reports the channel unavailable and the
pipeline continues on its rule path; nothing silently scores.