"""SQLite side table for Laya triage verdicts, annotation, not evidence.

Why a side table and not a column on `alerts`:

  * the tamper-evident chain (`store.py`) hashes exactly the detection row a
    detector produced. Triage is advisory decision support produced AFTER the
    detection; keeping it out of the chain means (a) pre-triage databases keep
    verifying unchanged, and (b) a re-triage with a newer model can never be
    mistaken for tampering with evidence.
  * the join key is the alert's stable `alert_id` (uuid5 over the detection
    payload), so verdicts survive idempotent re-ingest, and so a verdict
    computed by one surface reaches the report exported by another. The live
    surfaces share this file (`data/alerts/live_session.db`), which is why
    `:8501` persists what its worker decides and `:8530` joins it on export:
    the same `alert_id` must not print two different incident reports.

    python -m src.alerts.triage_store recent --db data/alerts/phase6_alerts.db
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path
from typing import Any

from .schema import Alert
from .store import iso_now

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_triage (
    alert_id      TEXT PRIMARY KEY,
    ts_epoch      REAL NOT NULL,
    disposition   TEXT,
    urgency       REAL,
    corroborates  REAL,
    p_false_positive REAL,
    verdict_json  TEXT NOT NULL,
    model_dir     TEXT,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_triage_disp ON alert_triage(disposition);
CREATE INDEX IF NOT EXISTS idx_triage_ts   ON alert_triage(ts_epoch DESC);
"""


class TriageStore:
    """Read/write side table joined on alert_id (shares the alerts db file)."""

    def __init__(self, db_path: str | Path) -> None:
        self.path = Path(db_path)
        if self.path.parent != Path("."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------ write
    def record(self, alert: Alert, model_dir: str | None = None) -> bool:
        """Store the verdict currently attached to `alert.triage` (if any)."""
        v = getattr(alert, "triage", None)
        if not v:
            return False
        from .store import iso_to_epoch
        self._conn.execute(
            "INSERT OR REPLACE INTO alert_triage "
            "(alert_id, ts_epoch, disposition, urgency, corroborates, "
            " p_false_positive, verdict_json, model_dir, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (alert.alert_id, iso_to_epoch(alert.timestamp),
             v.get("recommended"), v.get("urgency"),
             v.get("corroborates_class"), v.get("p_false_positive"),
             json.dumps(v, ensure_ascii=False, default=str), model_dir,
             iso_now()))
        self._conn.commit()
        return True

    # ------------------------------------------------------------------- read
    def get(self, alert_id: str) -> dict[str, Any] | None:
        r = self._conn.execute(
            "SELECT * FROM alert_triage WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        if r is None:
            return None
        d = dict(r)
        d["verdict"] = json.loads(d.pop("verdict_json"))
        return d

    def join(self, alerts: list[Alert]) -> list[Alert]:
        """Return these alerts with their stored verdicts attached.

        Attaches both halves of what the live worker produces, the `.triage`
        field and the evidence row derived from it, so a report exported by a
        surface that never ran triage prints the same facts as one that did.

        Copies, not mutations: the wall feeds this the same Alert objects it
        broadcasts, and an alert must not change because a judge downloaded a
        report. Alerts that already carry a verdict are left alone.
        """
        from src.triage.engine import attach_evidence
        for i, a in enumerate(alerts):
            row = self.get(a.alert_id) if a.alert_id else None
            if row is None or a.triage is not None:
                continue
            annotated = replace(a, evidence=list(a.evidence),
                                triage=row["verdict"])
            attach_evidence(annotated, row["verdict"])
            alerts[i] = annotated
        return alerts

    def recent(self, limit: int = 50,
               disposition: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM alert_triage WHERE 1=1"
        args: list[Any] = []
        if disposition:
            sql += " AND disposition = ?"
            args.append(disposition)
        sql += " ORDER BY ts_epoch DESC, rowid DESC LIMIT ?"
        args.append(int(limit))
        out = []
        for r in self._conn.execute(sql, args):
            d = dict(r)
            d["verdict"] = json.loads(d.pop("verdict_json"))
            out.append(d)
        return out

    def counts(self) -> dict[str, int]:
        """Disposition distribution (dashboard / rehearsal display)."""
        return {r["disposition"] or "?": int(r["n"]) for r in
                self._conn.execute(
                    "SELECT disposition, COUNT(*) AS n FROM alert_triage "
                    "GROUP BY disposition ORDER BY n DESC")}

    def close(self) -> None:
        self._conn.close()


def _existing_db(db: str | Path) -> Path | None:
    """The db file if a chained session already owns it, else nothing.

    Creating one here would leave a db holding verdicts with no evidence chain
    beside it, and a report reader would infer a session that never ran.
    """
    path = Path(db)
    return path if path.exists() else None


def record_verdicts(alerts: Iterable[Alert], db: str | Path) -> int:
    """Persist the advisory verdicts these alerts carry; returns how many."""
    path = _existing_db(db)
    if path is None:
        return 0
    ts = TriageStore(path)
    try:
        return sum(1 for a in alerts if ts.record(a))
    finally:
        ts.close()


def join_verdicts(alerts: list[Alert], db: str | Path) -> list[Alert]:
    """Attach the verdicts persisted for these alerts, whoever computed them."""
    path = _existing_db(db)
    if path is None:
        return alerts
    ts = TriageStore(path)
    try:
        return ts.join(alerts)
    finally:
        ts.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m src.alerts.triage_store",
        description="Inspect stored Laya triage verdicts.")
    ap.add_argument("cmd", choices=["recent", "counts"])
    ap.add_argument("--db", default="data/alerts/phase6_alerts.db")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--disposition", default=None)
    args = ap.parse_args(argv)
    ts = TriageStore(args.db)
    if args.cmd == "counts":
        print(json.dumps(ts.counts(), indent=2))
    else:
        rows = ts.recent(args.limit, args.disposition)
        for r in rows:
            v = r["verdict"]
            print(f"{r['alert_id'][:8]}… {r['disposition']:<15} "
                  f"urgency={v.get('urgency')} fp={v.get('p_false_positive')} "
                  f"corr={v.get('corroborates_class')}")
        print(f"-- {len(rows)} verdict(s)")
    ts.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
