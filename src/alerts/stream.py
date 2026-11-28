"""Bounded, paced flow intake with an ingest-to-alert clock.

`watch.replay_flows` is a pull loop: it reads a capture as fast as the disk
allows, so its window `eval_ms` answers "how much CPU did evaluation take",
not "how long after a packet did an alert exist". This module adds the
producer/queue/worker boundary a live sensor has:

    producer (paced) --> BoundedFlowQueue --> replay_flows worker

The bounded queue is the memory ceiling. When it is full, `put` blocks, so
the producer is backpressured instead of growing an unbounded backlog; the
queue records every blocking wait and its high-water mark. The clock starts
when the producer stamps a canonical flow record, not at the NIC. The upstream
capture-to-flow-export time is outside this process and is not claimed.
"""
from __future__ import annotations

import queue
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass

from src.alerts.watch import WindowResult, replay_flows

_SENTINEL = object()


class BoundedFlowQueue:
    """A fixed-capacity queue whose full state blocks the producer."""

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("queue capacity must be >= 1")
        self.capacity = int(capacity)
        self._q: queue.Queue = queue.Queue(maxsize=self.capacity)
        self._closed = False
        self._aborted = False
        self.offered = 0
        self.accepted = 0
        self.blocked_puts = 0
        self.blocked_ms = 0.0
        self.high_water = 0

    def put(self, rec: dict) -> None:
        """Enqueue one record, blocking while the queue is at capacity."""
        if self._aborted:
            raise RuntimeError("flow queue was aborted")
        self.offered += 1
        full = self._q.full()
        if full:
            self.blocked_puts += 1
        started = time.perf_counter()
        self._q.put(rec)
        if full:
            self.blocked_ms += (time.perf_counter() - started) * 1000.0
        self.accepted += 1
        self.high_water = max(self.high_water, self._q.qsize())
        if self._aborted:
            raise RuntimeError("flow queue was aborted")

    def __iter__(self):
        while True:
            item = self._q.get()
            if item is _SENTINEL:
                return
            yield item

    def close(self) -> None:
        if self._closed or self._aborted:
            return
        self._closed = True
        self._q.put(_SENTINEL)

    def abort(self) -> None:
        """Stop the worker side without leaving a blocked producer behind."""
        if self._aborted:
            return
        self._aborted = True
        while True:
            try:
                self._q.get_nowait()
            except queue.Empty:
                break
        try:
            self._q.put_nowait(_SENTINEL)
        except queue.Full:
            pass


@dataclass
class StreamStats:
    """Queue and wall-clock counters for one paced run."""
    capacity: int
    offered: int = 0
    accepted: int = 0
    blocked_puts: int = 0
    blocked_ms: float = 0.0
    high_water: int = 0
    windows: int = 0
    flows: int = 0
    alerts: int = 0
    wall_s: float = 0.0
    first_ingress: float | None = None
    last_ingress: float | None = None


@dataclass
class StreamRun:
    """Closed windows plus the queue behaviour that produced them."""
    windows: list[WindowResult]
    stats: StreamStats

    @staticmethod
    def _pct(sorted_vals: list[float], q: float) -> float:
        if not sorted_vals:
            return 0.0
        k = min(len(sorted_vals) - 1, max(0, round(q * (len(sorted_vals) - 1))))
        return sorted_vals[k]

    def summary(self) -> dict[str, float]:
        """Latency percentiles over alert-bearing windows only.

        A window with no alert has no flow-ingest-to-alert event to measure.
        The primary clock is first-ingest -> alert, which includes the tumbling
        window's fill; `p95_alert_ms` is last-ingest -> alert and isolates
        queueing plus evaluation.
        """
        alerts = [w for w in self.windows if w.alerts]
        e2e = sorted(v for w in alerts
                     if (v := w.ingest_to_alert_ms) is not None)
        tail = sorted(v for w in alerts if (v := w.alert_ms) is not None)
        queued = sorted(v for w in alerts if (v := w.queue_ms) is not None)
        filled = sorted(v for w in alerts if (v := w.fill_ms) is not None)
        evals = sorted(w.eval_ms for w in alerts)
        windows_ms = sorted(v for w in alerts if (v := w.window_ms) is not None)
        wall = max(self.stats.wall_s, 1e-9)
        if (self.stats.first_ingress is not None
                and self.stats.last_ingress is not None):
            arrival_span = max(self.stats.last_ingress
                               - self.stats.first_ingress, 1e-9)
        else:
            arrival_span = 1e-9
        return {
            "capacity": float(self.stats.capacity),
            "offered": float(self.stats.offered),
            "accepted": float(self.stats.accepted),
            "arrival_fps": self.stats.accepted / arrival_span,
            "run_fps": self.stats.accepted / wall,
            "arrival_span_s": arrival_span,
            "blocked_puts": float(self.stats.blocked_puts),
            "blocked_ms": self.stats.blocked_ms,
            "high_water": float(self.stats.high_water),
            "windows": float(self.stats.windows),
            "flows": float(self.stats.flows),
            "alerts": float(self.stats.alerts),
            "wall_s": self.stats.wall_s,
            "latency_windows": float(len(alerts)),
            "p50_ingest_to_alert_ms": self._pct(e2e, 0.50),
            "p95_ingest_to_alert_ms": self._pct(e2e, 0.95),
            "max_ingest_to_alert_ms": e2e[-1] if e2e else 0.0,
            "p50_alert_ms": self._pct(tail, 0.50),
            "p95_alert_ms": self._pct(tail, 0.95),
            "p95_queue_ms": self._pct(queued, 0.95),
            "p95_fill_ms": self._pct(filled, 0.95),
            "p95_window_ms": self._pct(windows_ms, 0.95),
            "p95_eval_ms": self._pct(evals, 0.95),
        }


class PacedStream:
    """Feed flows at an offered rate through a bounded queue into the worker.

    `rate=None` feeds as fast as the producer can copy, which is useful for
    tests but is not an offered-rate measurement. `queue_capacity` defaults
    to two seconds of traffic at the offered rate, enough for a sustainable
    window evaluation to finish without stalling the producer.
    """

    def __init__(self, flows: Iterable[dict], *, rate: float | None,
                 window_s: float = 10.0, queue_capacity: int | None = None,
                 rules=None) -> None:
        if rate is not None and rate <= 0:
            raise ValueError("rate must be > 0")
        self.flows = flows
        self.rate = rate
        self.window_s = window_s
        self.queue_capacity = queue_capacity
        self.rules = rules

    def run(self) -> StreamRun:
        capacity = (self.queue_capacity if self.queue_capacity is not None
                    else max(1, int(2 * self.rate)) if self.rate else 1024)
        q = BoundedFlowQueue(capacity)
        started = time.perf_counter()
        errors: list[BaseException] = []
        # Batch the pace at ~20 wakeups/s: per-flow sleep overhead on Windows
        # drifts the offered rate by tens of percent at 5k+ flows/s.
        batch = max(1, int(self.rate / 20)) if self.rate else 1

        def produce() -> None:
            if self.rate is None:
                schedule = 0.0
            else:
                schedule = time.perf_counter()
            n = 0
            try:
                for rec in self.flows:
                    if self.rate is not None and n % batch == 0:
                        due = schedule + n / self.rate
                        delay = due - time.perf_counter()
                        if delay > 0:
                            time.sleep(delay)
                    out = dict(rec)
                    out["_ingress_monotonic"] = time.perf_counter()
                    q.put(out)
                    n += 1
            except BaseException as exc:  # noqa: BLE001 - re-raised on worker
                errors.append(exc)
            finally:
                q.close()

        producer = threading.Thread(target=produce, name="diodewatch-producer",
                                    daemon=True)
        producer.start()
        windows: list[WindowResult] = []
        try:
            for win in replay_flows(iter(q), window_s=self.window_s,
                                    rules=self.rules):
                windows.append(win)  # noqa: PERF402 - abort path needs the loop
        except BaseException:
            q.abort()
            raise
        finally:
            producer.join()
            wall_s = time.perf_counter() - started
        if errors:
            raise errors[0]
        stats = StreamStats(
            capacity=capacity,
            offered=q.offered,
            accepted=q.accepted,
            blocked_puts=q.blocked_puts,
            blocked_ms=q.blocked_ms,
            high_water=q.high_water,
            windows=len(windows),
            flows=sum(w.n_flows for w in windows),
            alerts=sum(len(w.alerts) for w in windows),
            wall_s=wall_s,
            first_ingress=min((w.ingress_first for w in windows
                               if w.ingress_first is not None), default=None),
            last_ingress=max((w.ingress_last for w in windows
                              if w.ingress_last is not None), default=None),
        )
        return StreamRun(windows=windows, stats=stats)
