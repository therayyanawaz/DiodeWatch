"""Persistent chain-writing store for the live web wall (Priority 1).

`LiveEvidenceStore` wraps an `AlertStore` behind the replay session so the
tamper-evident evidence chain grows in real time while the wall streams:

* one SQLite db per session (fresh on launch/reset, the demo starts at
  link 0 and climbs visibly); DB_PATH is fixed so both launchers (SPA :8530
  and Streamlit :8501) can read the same file;
* every absorbed window is inserted through `insert_many` in one batch -
  the per-window batch keeps chain writes off the fsync-per-alert path
  (10k flows/s replays must not stall on transaction commits);
* every failure degrades to the in-memory ring buffer with an explicit
  reason, the wall never crashes and never fakes a chain.

The session's read path (recent feed, timeline, evidence) stays on the
fast in-memory `SessionStore`; the persistent store is a write-through
sidecar for integrity, so UI latency is unchanged when persistence is
disabled.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

from .schema import Alert, validate_alert
from .store import AlertStore, ledger_path, verify_chain
from .watch import SessionStore, WindowResult

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = REPO_ROOT / "data" / "alerts" / "live_session.db"


def db_path() -> Path:
    """Where the live-session evidence db lives (overridable for tests)."""
    return Path(os.environ.get("DIODE_LIVE_DB", DEFAULT_DB_PATH))


class LiveEvidenceStore:
    """Ring-buffer session + persistent chain-writing sidecar."""

    def __init__(self, max_alerts: int = 5_000,
                 path: str | Path | None = None) -> None:
        self.session = SessionStore(max_alerts=max_alerts)
        self.path = Path(path) if path is not None else db_path()
        self.error: str | None = None       # degrade reason (None = healthy)
        self.rejected = 0     # alerts the schema refused, never shown, never lost
        self._store: AlertStore | None = None
        self._open()

    # ------------------------------------------------------------------ setup
    def _open(self) -> None:
        """Open the session db, CONTINUING its evidence chain.

        This used to unlink the previous session's db on every launch, which
        both destroyed that evidence and made a truncated chain
        indistinguishable from a normal reset. When a clean slate is genuinely
        wanted (`DIODE_LIVE_RESET=1`) the old db and its ledger are archived
        together, so history and anchor survive the reset.
        """
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if os.environ.get("DIODE_LIVE_RESET") == "1":
                self._archive()
            self._store = AlertStore(self.path, check_same_thread=False)
            self.session.prime_seen(self._store.known_alert_ids())
        except OSError as e:
            self._store = None
            self.error = f"persistent store unavailable: {e}"
        except sqlite3.DatabaseError as e:
            self._store = None
            self.error = f"existing evidence db unreadable: {e}"

    def _archive(self) -> None:
        """Move a previous session's db and ledger aside, as a pair.

        They must move together: a ledger left behind next to a fresh db would
        read as a truncated chain.
        """
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        for p in (self.path, ledger_path(self.path)):
            for suffix in ("", "-wal", "-shm"):
                f = Path(str(p) + suffix)
                if f.exists():
                    f.rename(f.with_name(f"{f.stem}.{stamp}{f.suffix}"))

    # ------------------------------------------------------------------ write
    def absorb(self, w: WindowResult) -> list[Alert]:
        """One closed window: feed the ring buffer, persist its alerts.

        Returns exactly what the wall may broadcast, deduped and schema-valid,
        the same objects handed to the chain. Previously the loop broadcast the
        raw window list while the store persisted a filtered subset, so an
        analyst could see (and photograph) an alert the chain never recorded.
        """
        fresh = self.session.take_fresh(self._valid(w.alerts))
        self.session.stats.add(w)
        shown = self._persist(fresh)
        self.session.extend(shown, w.window_start)
        return shown

    def absorb_alerts(self, alerts: list[Alert]) -> list[Alert]:
        """ML-channel sidecar alerts (no window counters). Returns what to show."""
        fresh = self.session.take_fresh(self._valid(alerts))
        shown = self._persist(fresh)
        self.session.extend_alerts(shown)
        return shown

    def _valid(self, alerts: list[Alert]) -> list[Alert]:
        """Drop schema-rejects BEFORE the dedup counters, and count them.

        Filtering ahead of `take_fresh` is what keeps the three views of the
        same fact in agreement: the counters, the feed and the chain all see
        one population. Rejected alerts appear nowhere except `rejected`.
        """
        if not alerts:
            return alerts
        valid = [a for a in alerts if not validate_alert(a)]
        self.rejected += len(alerts) - len(valid)
        return valid

    def _persist(self, alerts: list[Alert]) -> list[Alert]:
        """Hand a deduped, schema-valid batch to the chain; return what to show."""
        if not alerts:
            return []
        if self._store is None:
            return alerts          # ring buffer only; `evidence()` says so
        t0 = time.perf_counter()
        try:
            ins, _dup, inv = self._store.insert_many(alerts)
            if inv:                # the two validators must never diverge silently
                self.rejected += inv
            self._inserted += ins
            self._persist_ms = getattr(self, "_persist_ms", 0.0) + \
                (time.perf_counter() - t0) * 1000.0
        except Exception as e:  # noqa: BLE001, degrade, never crash the wall
            self.error = f"persistent store write failed: {e}"
            try:
                self._store.close()
            except Exception as close_err:  # noqa: BLE001, degrade, not crash
                print(f"[live-store] close after failure also failed: "
                      f"{close_err}", file=sys.stderr, flush=True)
            self._store = None
        return alerts

    # ------------------------------------------------------------------ read
    @property
    def degraded(self) -> bool:
        return self._store is None

    @property
    def _inserted(self) -> int:
        return getattr(self, "_inserted_count", 0)

    @_inserted.setter
    def _inserted(self, v: int) -> None:
        self._inserted_count = v

    def evidence(self) -> dict[str, Any]:
        """Cheap per-tick honesty fields for the wall, runs no chain queries.

        `persisted` false means the feed is backed by the ring buffer only, so
        nothing the analyst sees is provably in the chain; `rejected` counts the
        alerts the schema refused, which are shown nowhere but are not lost.
        """
        return {"persisted": not self.degraded, "rejected": self.rejected,
                "error": self.error}

    def chain(self) -> dict[str, Any]:
        """Everything /api/chain and the Metrics tab need, honestly."""
        if self.degraded:
            return {"available": False, "degraded": True,
                    "error": self.error, "links": 0, "head": None,
                    "inserted": self._inserted, "persisted": False,
                    "rejected": self.rejected}
        head = self._store.chain_head()
        return {
            "available": head is not None,
            "degraded": False,
            "error": None,
            "db": str(self.path),
            "links": self._store.chain_length(),
            "head": head,
            "inserted": self._inserted,
            "rejected": self.rejected,
            "persisted": True,
            # False = the chain is only self-consistent: no append-only ledger
            # exists to prove the db was not rewritten or truncated.
            "anchored": self._store.ledger.exists(),
            "ledger_error": self._store.ledger_error,
            "insert_ms": round(
                getattr(self, "_persist_ms", 0.0), 2),
        }

    def probe(self, deep: bool = False) -> dict[str, Any]:
        """Live readback for /api/health: a real query, not a constant.

        Touches the persistent store with an actual SELECT (row count plus the
        chain length), so a db that is locked, truncated or missing tables
        answers `ok: false` with the reason instead of a green light. `deep`
        adds `PRAGMA quick_check`, which reads every page: callers poll this
        shallow and ask for deep on demand.
        """
        if self.degraded:
            return {"ok": False, "detail": self.error or "persistence unavailable"}

        def _touch() -> dict[str, Any]:
            store = self._store
            assert store is not None
            conn = store._conn
            out = {"ok": True, "alerts": int(conn.execute(
                "SELECT COUNT(*) FROM alerts").fetchone()[0]),
                "chain_links": int(store.chain_length())}
            if deep:
                out["quick_check"] = conn.execute(
                    "PRAGMA quick_check").fetchone()[0]
            return out

        try:
            return _touch()
        except Exception as e:  # noqa: BLE001, a probe must answer, not raise
            return {"ok": False, "detail": f"store probe failed: {e}"}

    def verify(self) -> dict[str, Any]:
        """Full recompute (occasional, a CLI job, not a per-poll job).

        Same result shape as `verify_chain` on every exit, including the
        degraded one: a caller that reads `anchored` or `alerts` must never
        find the key missing because persistence failed.
        """
        if self.degraded:
            return {"ok": False, "links": 0, "alerts": 0, "head": None,
                    "anchored": False, "error": self.error}
        return verify_chain(self.path)

    # ------------------------------------------------------------------ pass-through
    def __getattr__(self, name: str) -> Any:
        """Everything else (alerts, metrics, timeline, ...) hits the session."""
        return getattr(self.__dict__["session"], name)

    def close(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None
