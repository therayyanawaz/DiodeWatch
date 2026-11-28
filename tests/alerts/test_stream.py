"""Bounded streaming intake: queue backpressure and the alert clock."""
from __future__ import annotations

import threading
import time

from src.alerts.stream import BoundedFlowQueue, PacedStream
from src.alerts.watch import replay_flows
from src.detectors.rules import make_rules

BASE_TS = 1_499_268_000.0


def _syn(i: int, ts: float) -> dict:
    return {
        "flow_id": f"10.1.0.1-10.9.9.9-{50000 + i}-80-6",
        "src_ip": "10.1.0.1", "src_port": 50000 + i,
        "dst_ip": "10.9.9.9", "dst_port": 80, "protocol": 6, "proto": "tcp",
        "timestamp": "2017-07-05T12:20:00", "ts_epoch": ts,
        "duration_us": 1, "fwd_pkts": 1, "bwd_pkts": 0,
        "fwd_bytes": 60, "bwd_bytes": 0,
        "fin_flags": 0, "syn_flags": 1, "rst_flags": 0,
        "psh_flags": 0, "ack_flags": 0, "urg_flags": 0, "label": None,
    }


def test_bounded_queue_blocks_and_records_the_wait():
    q = BoundedFlowQueue(1)
    q.put({"id": 1})
    started = threading.Event()

    def producer() -> None:
        started.set()
        q.put({"id": 2})

    t = threading.Thread(target=producer, daemon=True)
    t.start()
    assert started.wait(1.0)
    deadline = time.perf_counter() + 1.0
    while q.blocked_puts == 0 and time.perf_counter() < deadline:
        time.sleep(0.001)
    assert q.blocked_puts == 1
    assert t.is_alive(), "put must block while the queue is at capacity"
    assert next(iter(q)) == {"id": 1}
    t.join(2.0)
    assert not t.is_alive()
    assert q.accepted == 2 and q.high_water == 1
    assert next(iter(q)) == {"id": 2}
    q.close()
    assert list(q) == []


def test_paced_stream_reports_ingest_to_alert():
    flows = [_syn(i, BASE_TS + i / 300.0) for i in range(320)]
    run = PacedStream(flows, rate=300, window_s=1.0, queue_capacity=32,
                      rules=make_rules()).run()
    summary = run.summary()
    assert summary["accepted"] == 320
    assert summary["flows"] == 320
    assert summary["alerts"] >= 1
    # The first alert cannot exist before its one-second window fills.
    assert 900.0 <= summary["p95_ingest_to_alert_ms"] < 5000.0
    assert summary["p95_fill_ms"] >= 900.0
    assert all(w.ingress_first is not None for w in run.windows)
    assert all(w.window_ms >= w.eval_ms for w in run.windows)


def test_plain_replay_has_no_ingest_clock():
    win = next(replay_flows([_syn(0, BASE_TS)], window_s=1.0))
    assert win.ingest_to_alert_ms is None
    assert win.alert_ms is None
