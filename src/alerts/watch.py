"""Live replay engine: flows in, alerts + performance counters out.

The dashboard's Live tab needs the same contract a deployment would have:
canonical flow records stream through tumbling windows, closed windows are
evaluated by the detectors, and the wall-clock cost of each evaluation gives
the latency numbers we report. This module is that loop, decoupled from any
UI so it stays unit-testable headless:

    for win in replay_flows(flow_iter, window_s=10):
        win.alerts         # list[Alert] fired by this window
        win.flows_per_sec  win.eval_ms  win.n_flows

* Rule detectors run on every window (fast, interpretable — the demo path).
* `ReplayStats` accumulates the judge metrics with honest definitions:
  - `replay_fps`: capture flows per second of *replayed traffic* (what the
    demo is feeding through);
  - `sustained_fps`: per-window n_flows / eval_seconds — the rate the machine
    could sustain if fed continuously (eval must beat window_s to keep up);
  - `p50/p95 window eval ms` and `p95 per-flow ms` (eval_ms / n_flows).

Pure stdlib + pandas; no streamlit import here (the UI stays thin).
"""
from __future__ import annotations

import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

import pandas as pd

from src.alerts.schema import SEVERITY_ORDER, Alert
from src.alerts.store import iso_to_epoch
from src.detectors.rules import make_rules, run_rules

DEFAULT_WINDOW_S = 10.0


@dataclass
class WindowResult:
    """Everything the Live tab needs about one closed window."""
    win_idx: int
    window_start: float          # epoch seconds of window start
    n_flows: int
    alerts: list[Alert]
    flows_per_sec: float         # replayed traffic rate in this window
    eval_ms: float               # detector evaluation wall time for the window
    capture_end: float | None = None  # max capture ts_epoch in the window

    @property
    def sustained_fps(self) -> float:
        """Flows/sec this window's evaluation could sustain continuously."""
        return self.n_flows / max(self.eval_ms / 1000.0, 1e-9)


@dataclass
class ReplayStats:
    """Cumulative performance counters across a replay session."""
    window_s: float = DEFAULT_WINDOW_S
    windows: int = 0
    flows: int = 0
    alerts: int = 0
    eval_ms: list[float] = field(default_factory=list)
    window_flows: list[int] = field(default_factory=list)
    max_sustained_fps: float = 0.0

    def add(self, w: WindowResult) -> None:
        self.windows += 1
        self.flows += w.n_flows
        self.alerts += len(w.alerts)
        self.eval_ms.append(w.eval_ms)
        self.window_flows.append(w.n_flows)
        self.max_sustained_fps = max(self.max_sustained_fps, w.sustained_fps)

    @staticmethod
    def _pct(sorted_vals: list[float], q: float) -> float:
        if not sorted_vals:
            return 0.0
        k = min(len(sorted_vals) - 1, max(0, round(q * (len(sorted_vals) - 1))))
        return sorted_vals[k]

    def summary(self) -> dict[str, float]:
        lat = sorted(self.eval_ms)
        # per-window evaluation of n flows: per-flow latency = eval/n; the p95
        # over those is the honest "how long did a flow wait" proxy for batch
        # evaluation (empty windows contribute nothing).
        per_flow = sorted(ms / n for ms, n in zip(self.eval_ms, self.window_flows)
                          if n > 0)
        span = max(self.windows * self.window_s, 1e-9)
        return {
            "replay_fps": self.flows / span,
            "alerts_per_sec": self.alerts / span,
            "sustained_fps": self.max_sustained_fps,
            "p50_eval_ms": self._pct(lat, 0.50),
            "p95_eval_ms": self._pct(lat, 0.95),
            "p95_per_flow_ms": self._pct(per_flow, 0.95),
            "windows": float(self.windows),
            "flows": float(self.flows),
            "alerts": float(self.alerts),
        }


def _window_index(ts_epoch: float, window_s: float) -> int:
    # fast path: None/NaN check without pandas (hot per-flow call)
    import math
    if ts_epoch is None:
        return -1
    try:
        f = float(ts_epoch)
    except (TypeError, ValueError):
        return -1
    if math.isnan(f):
        return -1
    return int(f // window_s)


def replay_flows(flows: Iterable[dict], *, window_s: float = DEFAULT_WINDOW_S,
                 rules=None) -> Iterator[WindowResult]:
    """Group a flow stream into tumbling windows; evaluate each as it closes.

    Watermark semantics: a window is evaluated when a flow from a strictly
    later window arrives (flow sources are expected roughly time-ordered —
    sort the stream first if the reader may emit out of order); everything
    remaining flushes at EOF.
    """
    rules = rules if rules is not None else make_rules()
    buckets: dict[int, list[dict]] = {}
    max_seen: int | None = None
    for rec in flows:
        idx = _window_index(rec.get("ts_epoch"), window_s)
        if idx < 0:
            continue
        b = buckets.get(idx)
        if b is None:
            buckets[idx] = [rec]
        else:
            b.append(rec)
        # ordered fast path: only a NEW max window can close older ones —
        # one sorted flush per new window, not per packet (was: sorted() per packet)
        if max_seen is None or idx > max_seen:
            max_seen = idx
            if len(buckets) > 1:
                for old in sorted(k for k in buckets if k < idx):
                    yield _evaluate(old, buckets.pop(old), window_s, rules)
    for old in sorted(buckets):
        yield _evaluate(old, buckets[old], window_s, rules)


def _evaluate(win_idx: int, recs: list[dict], window_s: float,
              rules) -> WindowResult:
    df = pd.DataFrame(recs)
    t0 = time.perf_counter()
    alerts = run_rules(df, rules=rules, window_s=int(window_s))
    eval_ms = (time.perf_counter() - t0) * 1000.0
    # fast max-ts without pd.notna per record (hot for large windows)
    import math
    cmax = None
    for r in recs:
        v = r.get("ts_epoch")
        if v is None:
            continue
        try:
            f = float(v)
        except (TypeError, ValueError):
            continue
        if math.isnan(f):
            continue
        if cmax is None or f > cmax:
            cmax = f
    return WindowResult(
        win_idx=win_idx,
        window_start=win_idx * window_s,
        n_flows=len(recs),
        alerts=alerts,
        flows_per_sec=len(recs) / window_s,
        eval_ms=eval_ms,
        capture_end=cmax,
    )


class SessionStore:
    """In-memory ring of the latest alerts + stats for one UI session.

    The dashboard keeps one of these in `st.session_state`; the Live tab
    renders `alerts[-table_rows:]` and the timeline buckets by second.
    """

    def __init__(self, max_alerts: int = 5_000) -> None:
        self.alerts: list[Alert] = []
        self.stats = ReplayStats()
        self.max_alerts = max_alerts
        self.timeline: dict[int, int] = {}   # epoch second -> alert count
        # -- idempotent-ingest counters (P1-1: suppression made visible) --
        self.raw_alerts = 0      # every alert absorbed, pre-suppression
        self.unique_total = 0    # alert_ids first seen -> joined the feed
        self.suppressed = 0      # re-detections collapsed (same alert_id)
        self._seen_ids: set[str] = set()
        self.entities: set[tuple] = set()   # (threat_class, entity key) pairs
        # Highest severity absorbed this session — the wall's threat headline.
        self.max_severity: str | None = None
        self._max_rank = -1
        # threat_class -> {"count", "severity", "attack"} over the whole
        # session. The wall's tiles and radar read these instead of counting
        # the alerts that reached the screen: the feed ring, the wire cap and
        # the DOM cap would each understate a long capture after a reconnect.
        self.class_stats: dict[str, dict[str, object]] = {}

    def _take(self, alerts: list[Alert]) -> list[Alert]:
        """Count raw vs unique vs suppressed, raise the severity headline and
        the per-class stats, and return alerts new to the feed.

        Suppression mirrors the AlertStore contract: an alert whose stable
        uuid5 alert_id was already absorbed is a re-detection of the same
        entity/event and collapses to the existing record (counted, not
        re-rendered)."""
        fresh: list[Alert] = []
        for a in alerts:
            self.raw_alerts += 1
            sev = (a.severity or "").lower()
            rank = SEVERITY_ORDER.get(sev)
            if rank is not None and rank > self._max_rank:
                self._max_rank, self.max_severity = rank, sev
            aid = getattr(a, "alert_id", None)
            if aid and aid in self._seen_ids:
                self.suppressed += 1
                continue
            if aid:
                self._seen_ids.add(aid)
            self.unique_total += 1
            tc = a.threat_class or "unknown"
            self.entities.add((tc, a.key or a.src_ip or a.dst_ip
                               or a.flow_id or "?"))
            stat = self.class_stats.setdefault(
                tc, {"count": 0, "severity": None, "attack": None})
            stat["count"] = stat["count"] + 1
            if rank is not None and rank > SEVERITY_ORDER.get(
                    str(stat["severity"] or ""), -1):
                stat["severity"], stat["attack"] = sev, a.attack_technique
            fresh.append(a)
        return fresh

    def take_fresh(self, alerts: list[Alert]) -> list[Alert]:
        """Dedup pass only: raw/unique/suppressed counters + severity headline,
        fresh returned.
        (Split out so a persistent sidecar can persist exactly the alerts
        that joined the feed — see src/alerts/live_store.py.)"""
        return self._take(alerts)

    def prime_seen(self, alert_ids: Iterable[str]) -> None:
        """Mark ids as already ingested, without counting them as absorbed.

        A session reopening a db that survived a restart uses this so old
        evidence is not re-broadcast as a fresh detection."""
        self._seen_ids.update(str(i) for i in alert_ids)

    def extend(self, fresh: list[Alert], window_start: float) -> None:
        """Timeline + feed append for window-fresh alerts (absorb tail)."""
        fallback = int(window_start)
        for a in fresh:
            sec = int(iso_to_epoch(a.timestamp)) or fallback
            self.timeline[sec] = self.timeline.get(sec, 0) + 1
        self.alerts.extend(fresh)
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[-self.max_alerts:]

    def extend_alerts(self, fresh: list[Alert]) -> None:
        """Timeline + feed append for sidecar alerts (absorb_alerts tail)."""
        for a in fresh:
            sec = int(iso_to_epoch(a.timestamp))
            if sec:
                self.timeline[sec] = self.timeline.get(sec, 0) + 1
        self.alerts.extend(fresh)
        self.stats.alerts += len(fresh)
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[-self.max_alerts:]

    def absorb(self, w: WindowResult) -> None:
        self.stats.add(w)
        self.extend(self.take_fresh(w.alerts), w.window_start)

    def absorb_alerts(self, alerts: list[Alert]) -> None:
        """Absorb alerts that arrive outside the window loop (ML-channel
        sidecar detectors): they join the feed, timeline and alert totals,
        but never the window/latency counters."""
        if not alerts:
            return
        self.extend_alerts(self.take_fresh(alerts))

    def metrics(self) -> dict[str, float | str | None]:
        m = self.stats.summary()
        for k in ("replay_fps", "alerts_per_sec", "sustained_fps",
                  "p50_eval_ms", "p95_eval_ms", "p95_per_flow_ms"):
            m[k] = round(m[k], 2)
        # The headline has to be the number of records the wall shows. It is
        # NOT stats.alerts: the rule path counts every firing into that counter
        # (it is the load figure behind alerts_per_sec) while the ML sidecar
        # path only counts what joined the feed, so a replay of an already
        # ingested capture headlined "2 alerts" over an empty feed on one
        # channel and "0 alerts" on the other. alerts_per_sec stays raw on
        # purpose: re-detections did cost the pipeline that work.
        m["alerts"] = self.unique_total
        m["alerts_raw"] = self.raw_alerts
        m["alerts_suppressed"] = self.suppressed
        m["entities"] = len(self.entities)
        # The threat level is the session's, not the visible cards': a feed
        # trimmed to max_alerts, capped to FEED_CAP on the wire or filtered in
        # the browser still has to read CRITICAL when a critical fired.
        m["max_severity"] = self.max_severity
        return m
