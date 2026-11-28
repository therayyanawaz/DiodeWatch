# Stream intake: bounded queue and ingest-to-alert

Measured 2026-11-28 13:14 IST on one Windows development workstation. The
machine is not a deployment target; these are the timings this host produced.

```bash
python scripts/benchmarks/bench_stream.py --rates 5000,10000,50000 --windows 6
```

The run paces canonical 47-field flow records from
`data/slices/flows.ndjson` at the requested rate, retimed into consecutive 10 s
windows. A producer puts records into a bounded `queue.Queue`; a worker consumes
them through the existing `replay_flows` path. The queue capacity is two seconds
of the offered rate: 10,000 records at 5,000 flows/s, 20,000 at 10,000, and
100,000 at 50,000. A full queue blocks the producer (`put` waits), so memory is
bounded and backpressure is observable. This queue drops nothing.

The clock starts when the first canonical flow of a window is offered to the
queue and stops when that window's alert leaves the rule layer. It therefore
covers window fill, queue wait, DataFrame construction and rule evaluation. It
does **not** include packet capture, the exporter's capture-to-flow assembly,
dashboard rendering or the evidence store write. It is a flow-ingest-to-alert
clock, not a NIC-to-alert clock.

## Results

| target (flows/s) | accepted | arrivals (flows/s) | p50 ingest-to-alert | p95 ingest-to-alert | p95 last-flow-to-alert | p95 window work | queue peak | blocked puts / time | verdict |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 5,000 | 300,000 | 5,004 | 11,449 ms | **11,810 ms** | 1,855 ms | 1,805 ms | 9,999 / 10,000 | 0 / 0.0 s | sustained |
| 10,000 | 600,000 | 10,008 | 11,934 ms | **12,678 ms** | 2,720 ms | 2,670 ms | 20,000 / 20,000 | 5 / 2.36 s | sustained, brief saturation |
| 50,000 | 3,000,000 | 23,880 | 32,011 ms | **39,919 ms** | 15,593 ms | 15,589 ms | 100,000 / 100,000 | 5 / 53.59 s | overload |

Each row is six consecutive windows, all alert-bearing (14, 16 and 108 alerts
respectively). Every p95 is the nearest-rank value over six windows, so it is
also the worst of the six; p50 is the typical window. This is a small sample,
not a high-resolution latency distribution.

At 5,000 flows/s the p95 clock is 11.81 s. Roughly 9.95 s of that is the window
filling, as it must for a 10 s tumbling window. The p95 last-flow-to-alert cost
is 1.86 s; the p95 rule-evaluation share is 0.55 s, so frame assembly accounts
for most of that tail.
The queue never blocked, but it reached 9,999 of 10,000 records, so the two-second
buffer is close to its limit even at the target rate.

At 10,000 flows/s the p95 clock is 12.68 s and the p95 window work is 2.67 s
(0.63 s of rule evaluation). The queue filled completely and blocked the producer
five times for 2.36 s total, then drained. Window work is still well below the
10 s fill, so the rate is sustainable.

At the 50,000 flows/s target the pipeline does not sustain the offered rate.
The queue saturates, the producer is blocked for 53.59 s across five puts, and
the achieved ingress falls to 23,880 flows/s. The p95 clock is 39.92 s and the
p95 window work is 15.59 s; the p95 rule-evaluation share is 1.95 s, so DataFrame
construction dominates under a 500,000-row window with a full queue.
The window fill stretches to 29.34 s because the producer cannot keep its
schedule while blocked. This is reported as overload, not as a sustained 50,000
result.

The 175 ms figure elsewhere on this site is `run_rules` p95 on the earlier 40,000
flow batch replay. It excludes frame construction, queue wait and window fill,
so it is not the clock in this table.

The machine-readable copy of this run is
[`stream_backpressure.json`](stream_backpressure.json).
