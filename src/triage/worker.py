"""Background triage worker: alerts -> verdicts off the hot path.

The rule/ML detectors are the real-time layer (10,000 flows/s); Laya triage
is post-detection decision support whose latency is hardware-bound (0.1-0.2 s
per alert on Apple-silicon-class CPUs, seconds on weak boxes). This module
makes that latency invisible to the feed:

  * one daemon thread drains a bounded priority queue (critical first, then
    newest-first) so the alerts an analyst is watching get verdicts first;
  * `drain()` returns finished verdicts for the UI to attach — the replay
    loop never blocks on the model;
  * engine unavailable => the worker reports `degraded` with the actionable
    reason and the feed runs triage-free (never silent junk).

Streamlit-free; the dashboard keeps one worker in st.session_state.
"""
from __future__ import annotations

import threading
from collections import defaultdict
from pathlib import Path
from queue import Empty, Full, PriorityQueue
from typing import Any

from src.alerts.schema import Alert
from src.alerts.triage_store import record_verdicts
from src.triage.engine import LayaTriage

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

MAX_QUEUE = 64


class TriageWorker:
    """Priority background triage over finished alerts (one live session)."""

    def __init__(self, engine: LayaTriage | None = None,
                 model_dir: str = "models/laya-onnx",
                 max_queue: int = MAX_QUEUE) -> None:
        self.engine = engine or LayaTriage(model_dir)
        self._q: PriorityQueue = PriorityQueue(maxsize=max_queue)
        self._lock = threading.Lock()
        self._results: dict[str, dict[str, Any]] = {}
        self._queued: set[str] = set()
        self._seq = 0
        self.submitted = 0
        self.processed = 0
        self.dropped = 0
        self.degraded: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        if self.engine.available():
            self._thread = threading.Thread(
                target=self._run, name="laya-triage", daemon=True)
            self._thread.start()
        else:
            self.degraded = str(self.engine.status().get("reason") or
                                "Laya triage channel unavailable")

    # ------------------------------------------------------------------ api
    def submit(self, alerts: list[Alert]) -> int:
        """Queue alerts for triage (already-done/queued ids are skipped).
        Returns the number newly queued. Full queue => lowest-priority
        insertions are dropped and counted (never blocks the replay)."""
        if self._thread is None:
            return 0
        n = 0
        for a in sorted(alerts, key=self._priority_key):
            aid = a.alert_id
            if not aid or aid in self._queued:
                continue
            with self._lock:
                if aid in self._results:
                    continue
                self._queued.add(aid)
            self._seq += 1
            try:
                self._q.put_nowait((self._priority_key(a), self._seq, a))
                self.submitted += 1
                n += 1
            except Full:
                with self._lock:
                    self._queued.discard(aid)
                self.dropped += 1
        return n

    def drain(self) -> dict[str, dict[str, Any]]:
        """Finished verdicts since the last drain: {alert_id: summary}."""
        with self._lock:
            out, self._results = self._results, {}
        with self._lock:
            for aid in out:
                self._queued.discard(aid)
        return out

    def status(self) -> dict[str, Any]:
        with self._lock:
            queued = len(self._queued)
        return {
            "available": self._thread is not None,
            "degraded_reason": self.degraded,
            "queued": queued,
            "done": self.processed,
            "dropped": self.dropped,
            "avg_ms": (round(self.engine.ms_total / self.processed, 1)
                       if self.processed else None),
        }

    def status_line(self) -> str:
        s = self.status()
        if not s["available"]:
            return (f"🧠 Laya triage: **degraded** — "
                    f"{(s['degraded_reason'] or 'unavailable')[:90]}")
        bits = [f"{s['queued']} queued", f"{s['done']} done"]
        if s["avg_ms"]:
            bits.append(f"{s['avg_ms'] / 1000:.1f} s/alert"
                        if s["avg_ms"] >= 1000
                        else f"{s['avg_ms']:.0f} ms/alert")
        if s["dropped"]:
            bits.append(f"{s['dropped']} dropped (queue full)")
        return f"🧠 Laya triage: **active** — {' · '.join(bits)} (background)"

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    # -------------------------------------------------------------- internals
    @staticmethod
    def _priority_key(a: Alert) -> tuple[int, float]:
        return (_SEV_RANK.get(a.severity or "medium", 2),
                -_alert_epoch(a))

    def _run(self) -> None:  # pragma: no cover - thread body (tested via fake)
        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=0.5)
            except Empty:  # queue timeout -> keep waiting for stop
                continue
            if item is None:
                break
            _, _, alert = item
            try:
                summary = self.engine.triage_quiet(alert)
            except Exception as e:  # noqa: BLE001 - never kill the thread on one bad alert
                summary = None
                self.degraded = f"triage error: {e}"
            if summary is None:
                with self._lock:
                    self._queued.discard(alert.alert_id)
                if self.degraded is None:
                    self.degraded = (self.engine.status_reason()
                                     or "triage unavailable")
                break  # channel down: stop consuming, keep results served
            with self._lock:
                self._results[alert.alert_id] = summary
                self._queued.discard(alert.alert_id)
            self.processed += 1


def _alert_epoch(a: Alert) -> float:
    import pandas as pd
    try:
        t = pd.Timestamp(a.timestamp)
        return t.timestamp() if not pd.isna(t) else 0.0
    except (ValueError, TypeError, OverflowError):
        return 0.0


def attach_verdicts(alerts: list[Alert],
                    verdicts: dict[str, dict[str, Any]]) -> int:
    """Attach drained verdicts onto session alerts (advisory, idempotent).

    Mutates the Alert objects in place — the same objects the Live feed and
    Evidence tab render — so verdicts pop in without any re-ingest.
    """
    if not verdicts:
        return 0
    from src.triage.engine import attach_evidence
    n = 0
    for a in alerts:
        s = verdicts.get(a.alert_id)
        if s is None or getattr(a, "triage", None) is not None:
            continue
        attach_evidence(a, s)
        a.triage = s
        n += 1
    return n


def tick(alerts: list[Alert], tw: TriageWorker, db: str | Path) -> int:
    """One non-blocking triage cycle for a live session.

    Submits the newest alerts that have no verdict yet, attaches whatever the
    worker finished, and persists those verdicts to the side table beside the
    evidence chain. The write is the point: a verdict that only lives in this
    browser session is why one `alert_id` exported two different incident
    reports. `db` is the live session's evidence db — with no chained session to
    write into, `record_verdicts` stores nothing rather than inventing one.
    """
    tw.submit([a for a in alerts[-20:] if a.triage is None])
    verdicts = tw.drain()
    if not verdicts:
        return 0
    attach_verdicts(alerts, verdicts)
    return record_verdicts([a for a in alerts if a.alert_id in verdicts], db)


def per_class_dispositions(alerts: list[Alert]) -> dict[str, dict[str, int]]:
    """Triage outcome distribution per threat class (Metrics display)."""
    out: dict[str, dict[str, int]] = defaultdict(dict)
    for a in alerts:
        v = getattr(a, "triage", None)
        if v and v.get("recommended"):
            d = out[a.threat_class]
            d[v["recommended"]] = d.get(v["recommended"], 0) + 1
    return dict(out)
