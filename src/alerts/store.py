"""SQLite evidence store + JSONL sink for alerts.

The store is deliberately small and dependency-free (`sqlite3`, stdlib):

* one row per alert, the alert schema flattened to columns, evidence as a
  JSON document, plus the derived `ts_epoch` (sortable, indexable) and the
  stable `alert_id` primary key (idempotent re-ingestion: inserting the same
  detection twice inserts it once);
* indexes on the query paths an analyst actually uses, recency
  (`ts_epoch`), threat class, severity, and victim (`dst_ip`/`src_ip`);
* `recent()` answers "what happened in the last N alerts" and
  `between()` answers "what happened in this window" (the incident-report
  query), both are single indexed scans;
* WAL journaling so a monitor/UI can read the file while the store is being
  written by another process.

`write_jsonl` / `ingest_jsonl` produce/consume exactly the per-line alert dict
format the detectors already emit (`to_dict()` + one JSON object per line), so
the store and the ML/rule engines share one serialization contract.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Self

from .schema import Alert, EvidenceItem, alert_from_dict, validate_alert

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    ts_epoch        REAL NOT NULL,
    timestamp       TEXT NOT NULL,
    flow_id         TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    proto           TEXT,
    threat_class    TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL,
    detector        TEXT,
    key             TEXT,
    attack_technique TEXT,
    attack_tactic   TEXT,
    window_start    TEXT,
    window_end      TEXT,
    window_seconds  REAL,
    label           TEXT,
    evidence_json   TEXT NOT NULL
);
-- tamper-evident chain: one link per appended alert, in append order.
--   payload_hash = SHA256(canonical alert row bytes)
--   prev_hash    = previous link's chain_hash (GENESIS for the first link)
--   chain_hash   = SHA256(prev_hash || payload_hash)
-- Verifying recomputes the whole chain in rowid order; any edited/deleted
-- row breaks every link after it, and the verifier names the first break.
CREATE TABLE IF NOT EXISTS evidence_chain (
    link_no     INTEGER PRIMARY KEY,
    alert_id    TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    chain_hash  TEXT NOT NULL,
    inserted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chain_alert ON evidence_chain(alert_id);
CREATE INDEX IF NOT EXISTS idx_alerts_ts     ON alerts(ts_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_class  ON alerts(threat_class);
CREATE INDEX IF NOT EXISTS idx_alerts_sev    ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_dst    ON alerts(dst_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_src    ON alerts(src_ip);
-- composite: the analyst filters ("recent critical", "recent ddos") use these
CREATE INDEX IF NOT EXISTS idx_alerts_class_ts ON alerts(threat_class, ts_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_sev_ts   ON alerts(severity, ts_epoch DESC);
"""

_COLS = ("alert_id, ts_epoch, timestamp, flow_id, src_ip, dst_ip, src_port, "
         "dst_port, proto, threat_class, severity, confidence, detector, key, "
         "attack_technique, attack_tactic, window_start, window_end, "
         "window_seconds, label, evidence_json")


def iso_to_epoch(ts: str | float | None) -> float:
    """ISO-8601 timestamp -> Unix epoch (UTC). Naive timestamps are treated
    as UTC (the pipeline writes UTC everywhere). Returns 0.0 when unparsable
    so a bad row never breaks the ingest batch."""
    if ts is None or ts == "":
        return 0.0
    # fast path: numeric epoch already (int/float pass straight through)
    if isinstance(ts, (int, float)):
        import math as _math
        f = float(ts)
        return f if not _math.isnan(f) else 0.0  # NaN -> 0.0
    s = str(ts).strip()
    # cache repeated window timestamps (many alerts share one window_end)
    _hit = _EPOCH_CACHE.get(s)
    if _hit is not None:
        return _hit
    try:
        val = float(s)
        if len(_EPOCH_CACHE) < 4096:
            _EPOCH_CACHE[s] = val
        return val
    except ValueError:
        pass
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        val = dt.timestamp()
        if len(_EPOCH_CACHE) < 4096:
            _EPOCH_CACHE[s] = val
        return val
    except ValueError:
        return 0.0


_EPOCH_CACHE: dict[str, float] = {}


def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


_GENESIS_HASH = "0" * 64


def payload_hash(row: tuple) -> str:
    """SHA256 over the canonical bytes of one alert row (the _COLS order)."""
    canon = json.dumps(list(row), ensure_ascii=False, default=str,
                       separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def ledger_path(db_path: str | Path) -> Path:
    """Append-only twin of the chain, beside the db.

    The db alone is tamper-evident only against a reader who cannot write it:
    with write access, a edited history can be re-hashed link by link. Writing
    each new head to a second file means truncating or rewriting the chain in
    the db has to be done in both places, and `verify_chain` fails when the two
    disagree. It is an anchor, not a seal, see docs/alerts.md.
    """
    p = Path(db_path)
    return p.with_name(p.stem + ".chain-ledger.ndjson")


def read_ledger(db_path: str | Path) -> list[dict[str, Any]]:
    """Ledger lines in write order (empty when the file does not exist)."""
    try:
        with ledger_path(db_path).open(encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []


class AlertStore:
    """SQLite alert evidence store."""

    def __init__(self, db_path: str | Path,
                 check_same_thread: bool = True) -> None:
        self.path = Path(db_path)
        if self.path.parent != Path("."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: the live web wall constructs the store on
        # the event loop but writes from a worker thread (asyncio.to_thread).
        # Safe, every write serializes behind BEGIN IMMEDIATE, and cross-
        # process writers are serialized by SQLite's own file locking.
        self._conn = sqlite3.connect(str(self.path),
                                     check_same_thread=check_same_thread)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA temp_store=MEMORY")
        self._conn.execute("PRAGMA cache_size=-64000")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self.ledger = ledger_path(self.path)
        self.ledger_error: str | None = None
        self._sync_ledger()

    # ------------------------------------------------------------------ write
    def insert(self, alert: Alert) -> int:
        """Insert one alert. Returns 1 inserted, 0 duplicate (OR IGNORE)."""
        return self.insert_many([alert])[0]

    def insert_many(self, alerts: Iterable[Alert],
                    batch: int = 2_000) -> tuple[int, int, int]:
        """Insert a batch. Returns (inserted, duplicates, invalid)."""
        inserted = duplicates = invalid = 0
        rows: list[tuple] = []
        n = 0
        for a in alerts:
            problems = validate_alert(a)
            if problems:
                invalid += 1
                continue
            rows.append(self._row(a))
            n += 1
            if n >= batch:
                ins, dup = self._flush(rows)
                inserted += ins
                duplicates += dup
                rows = []
                n = 0
        if rows:
            ins, dup = self._flush(rows)
            inserted += ins
            duplicates += dup
        return inserted, duplicates, invalid

    def _flush(self, rows: list[tuple]) -> tuple[int, int]:
        """Insert one batch and chain exactly the rows that landed.

        The chain must only link freshly inserted rows, a mixed batch
        (new + duplicate alert_ids) must not produce links for duplicates,
        or the chain would outgrow the alerts table and verify would fail.
        """
        self._conn.execute("BEGIN IMMEDIATE")   # serialize link_no across writers
        try:
            if len(rows) > 1:
                # ids already in the table before this batch (they must NOT
                # be chained); within-batch duplicates collapse to first-seen
                marks = ",".join("?" * len(rows))
                pre = {r[0] for r in self._conn.execute(
                    f"SELECT alert_id FROM alerts WHERE alert_id IN ({marks})",
                    [r[0] for r in rows])}
            else:
                pre = set()
            cur = self._conn.executemany(
                f"INSERT OR IGNORE INTO alerts ({_COLS}) "
                f"VALUES ({','.join('?' * 21)})", rows)
            inserted = cur.rowcount
            if inserted == len(rows):
                # fast path: everything landed (the common demo case)
                links = self._append_chain_links(rows)
            elif inserted:
                landed, seen = [], set()
                for r in rows:
                    if r[0] not in pre and r[0] not in seen:
                        seen.add(r[0])
                        landed.append(r)
                links = self._append_chain_links(landed)
            else:
                links = []
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        self._append_ledger(links)
        return inserted, len(rows) - inserted

    # ------------------------------------------------------------------ chain
    def _append_chain_links(self, rows: list[tuple]) -> list[dict[str, Any]]:
        """Chain freshly inserted alert rows (caller holds the write txn)."""
        head_row = self._conn.execute(
            "SELECT link_no, chain_hash FROM evidence_chain "
            "ORDER BY link_no DESC LIMIT 1").fetchone()
        link_no = head_row["link_no"] if head_row else 0
        prev_hash = head_row["chain_hash"] if head_row else _GENESIS_HASH
        now = iso_now()
        links = []
        for row in rows:
            ph = payload_hash(row)
            ch = hashlib.sha256((prev_hash + ph).encode("utf-8")).hexdigest()
            link_no += 1
            links.append({"link_no": link_no, "alert_id": row[0],
                          "payload_hash": ph, "prev_hash": prev_hash,
                          "chain_hash": ch, "inserted_at": now})
            prev_hash = ch
        self._conn.executemany(
            "INSERT INTO evidence_chain (link_no, alert_id, payload_hash, "
            "prev_hash, chain_hash, inserted_at) VALUES (?,?,?,?,?,?)",
            [(l["link_no"], l["alert_id"], l["payload_hash"], l["prev_hash"],
              l["chain_hash"], l["inserted_at"]) for l in links])
        return links

    def _append_ledger(self, links: list[dict[str, Any]]) -> None:
        """Mirror new chain heads to the append-only ledger file.

        Best-effort by construction: a ledger write failure must never lose or
        block evidence, so it degrades the *anchor* and records why. The ledger
        is opened in append mode only, nothing in this codebase truncates it.
        """
        if not links:
            return
        try:
            self.ledger.parent.mkdir(parents=True, exist_ok=True)
            with self.ledger.open("a", encoding="utf-8") as fh:
                for l in links:
                    fh.write(json.dumps({"link_no": l["link_no"],
                                         "alert_id": l["alert_id"],
                                         "chain_hash": l["chain_hash"]},
                                        ensure_ascii=False, default=str) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self.ledger_error = None
        except OSError as e:
            self.ledger_error = f"ledger append failed: {e}"

    def _read_ledger(self) -> list[dict[str, Any]]:
        return read_ledger(self.path)

    def _sync_ledger(self) -> None:
        """Backfill the ledger for db links it is missing (crash before append).

        Only ever grows the ledger. A ledger LONGER than the db means links were
        removed from the db (the danger case) and is left untouched so
        verify_chain reports it.
        """
        if not self.ledger.exists():
            return
        rows = self._conn.execute(
            "SELECT link_no, alert_id, chain_hash FROM evidence_chain "
            "ORDER BY link_no ASC").fetchall()
        have = len(self._read_ledger())
        if have >= len(rows):
            return
        self._append_ledger([{"link_no": r["link_no"], "alert_id": r["alert_id"],
                              "chain_hash": r["chain_hash"]} for r in rows[have:]])

    def chain_head(self) -> dict[str, Any] | None:
        """The newest chain link: {link_no, alert_id, chain_hash, inserted_at}."""
        r = self._conn.execute(
            "SELECT link_no, alert_id, chain_hash, inserted_at "
            "FROM evidence_chain ORDER BY link_no DESC LIMIT 1").fetchone()
        return dict(r) if r else None

    def chain_length(self) -> int:
        return int(self._conn.execute(
            "SELECT COUNT(*) FROM evidence_chain").fetchone()[0])

    def _row(self, a: Alert) -> tuple:
        return (
            a.alert_id, iso_to_epoch(a.timestamp), a.timestamp, a.flow_id,
            a.src_ip, a.dst_ip, a.src_port, a.dst_port, a.proto,
            a.threat_class, a.severity, float(a.confidence), a.detector, a.key,
            a.attack_technique, a.attack_tactic, a.window_start, a.window_end,
            a.window_seconds, a.label,
            json.dumps([e.to_dict() for e in a.evidence], default=str),
        )

    def ingest_dicts(self, records: Iterable[dict[str, Any]]) -> tuple[int, int, int]:
        """Ingest stored/exported alert dicts (see alert_from_dict)."""
        return self.insert_many(alert_from_dict(d) for d in records)

    # ------------------------------------------------------------------ read
    @staticmethod
    def _from_row(r: sqlite3.Row) -> Alert:
        evidence = json.loads(r["evidence_json"] or "[]")
        return Alert(
            alert_id=r["alert_id"], timestamp=r["timestamp"],
            flow_id=r["flow_id"], src_ip=r["src_ip"], dst_ip=r["dst_ip"],
            src_port=r["src_port"], dst_port=r["dst_port"], proto=r["proto"],
            threat_class=r["threat_class"], severity=r["severity"],
            confidence=r["confidence"],
            evidence=[EvidenceItem(**e) for e in evidence],
            window_start=r["window_start"], window_end=r["window_end"],
            window_seconds=r["window_seconds"], key=r["key"],
            detector=r["detector"], attack_technique=r["attack_technique"],
            attack_tactic=r["attack_tactic"], label=r["label"],
        )

    def recent(self, limit: int = 50, threat_class: str | None = None,
               severity: str | None = None,
               since_epoch: float | None = None) -> list[Alert]:
        """Newest-first alerts, newest of a class/severity or since a time."""
        sql = "SELECT * FROM alerts WHERE 1=1"
        args: list[Any] = []
        if threat_class:
            sql += " AND threat_class = ?"
            args.append(threat_class)
        if severity:
            sql += " AND severity = ?"
            args.append(severity)
        if since_epoch is not None:
            sql += " AND ts_epoch >= ?"
            args.append(since_epoch)
        sql += " ORDER BY ts_epoch DESC, rowid DESC LIMIT ?"
        args.append(int(limit))
        return [self._from_row(r) for r in self._conn.execute(sql, args)]

    def between(self, start_iso: str, end_iso: str) -> list[Alert]:
        """All alerts whose timestamp falls in [start, end] (chronological)."""
        rows = self._conn.execute(
            "SELECT " + _COLS + " FROM alerts WHERE ts_epoch >= ? AND ts_epoch <= ?"
            " ORDER BY ts_epoch ASC, rowid ASC",
            (iso_to_epoch(start_iso), iso_to_epoch(end_iso)))
        return [self._from_row(r) for r in rows]

    def get(self, alert_id: str) -> Alert | None:
        row = self._conn.execute(
            "SELECT " + _COLS + " FROM alerts WHERE alert_id = ?",
            (alert_id,)).fetchone()
        return self._from_row(row) if row else None

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])

    def known_alert_ids(self) -> set[str]:
        """Every alert id already under chain custody in this db.

        A restarted session uses it to refuse to re-broadcast history as a new
        detection: the link already exists, so the wall must not show it again.
        """
        return {r[0] for r in
                self._conn.execute("SELECT alert_id FROM alerts")}

    def count_by(self, column: str) -> dict[str, int]:
        col = column if column in ("threat_class", "severity", "detector") \
            else "threat_class"
        return {r[0]: int(r[1]) for r in
                self._conn.execute(f"SELECT {col}, COUNT(*) FROM alerts "
                                   f"GROUP BY {col} ORDER BY 2 DESC")}

    def stats(self) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n, MIN(ts_epoch) AS first_ts, "
            "MAX(ts_epoch) AS last_ts FROM alerts").fetchone()
        head = self.chain_head()
        return {
            "alerts": int(row["n"]),
            "first_ts": row["first_ts"] or 0.0,
            "last_ts": row["last_ts"] or 0.0,
            "by_threat_class": self.count_by("threat_class"),
            "by_severity": self.count_by("severity"),
            "db_path": str(self.path),
            "chain": {"length": self.chain_length(), "head": head,
                      "anchored": self.ledger.exists()},
        }

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# ------------------------------------------------------------------ verifier
def verify_chain(db_path: str | Path) -> dict[str, Any]:
    """Recompute the whole evidence chain and cross-check it against the ledger.

    Returns {"ok", "links", "alerts", "head", "anchored", "error"}: `error` is
    None on an intact chain, otherwise a description of the first break (edited
    or deleted alert row, edited chain row, re-ordering, an alert row outside
    the chain, or a db shorter/disagreeing with the ledger). `anchored` is
    False when no ledger file exists, the chain is then self-consistent only,
    which is stated rather than hidden.
    Works on a store created by any DiodeWatch version, an empty or missing
    chain table simply verifies with 0 links.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    ledger = read_ledger(db_path)
    anchored = bool(ledger)

    def res(ok: bool, links: int = 0, head: dict | None = None,
            alerts: int = 0, error: str | None = None) -> dict[str, Any]:
        """One result shape for every exit, so no caller reads a missing key."""
        return {"ok": ok, "links": links, "alerts": alerts, "head": head,
                "anchored": anchored, "error": error}

    try:
        try:
            chains = conn.execute(
                "SELECT link_no, alert_id, payload_hash, prev_hash, chain_hash "
                "FROM evidence_chain ORDER BY link_no ASC").fetchall()
        except sqlite3.OperationalError:
            chains = []                      # no chain table: a pre-chain store
        try:
            rows = conn.execute(f"SELECT {_COLS} FROM alerts").fetchall()
        except sqlite3.OperationalError:
            if chains:
                return res(False, links=len(chains),
                           error="alerts table missing but chain links exist")
            # a pre-chain store: the current column set is absent, but the row
            # count still proves evidence was inserted without any custody
            try:
                n = int(conn.execute(
                    "SELECT COUNT(*) FROM alerts").fetchone()[0])
            except sqlite3.OperationalError:
                n = 0
            if n:
                return res(False, alerts=n,
                           error=f"{n} alert rows but no chain links, "
                                 "store predates the evidence chain")
            rows = []
        # The ledger is history written to a second place. It may lag the db
        # (a write that died mid-batch, healed by _sync_ledger on open) but it
        # must never run ahead of it, that is a deleted tail.
        if len(ledger) > len(chains):
            return res(False, links=len(chains),
                       head=dict(chains[-1]) if chains else None,
                       alerts=len(rows),
                       error=f"chain truncated: the ledger holds "
                             f"{len(ledger)} links but the db holds "
                             f"{len(chains)}, the newest "
                             f"{len(ledger) - len(chains)} were deleted")
        if not chains:
            if rows:
                return res(False, alerts=len(rows),
                           error=f"{len(rows)} alert rows but no chain links, "
                                 "store predates the evidence chain")
            return res(True)
        by_id = {r["alert_id"]: tuple(r) for r in rows}
        prev_hash = _GENESIS_HASH
        for link in chains:
            alert_id = link["alert_id"]
            row = by_id.get(alert_id)
            if row is None:
                return res(False, links=link["link_no"], head=dict(chains[-1]),
                           alerts=len(by_id),
                           error=f"link {link['link_no']}: alert "
                                 f"{alert_id} missing from alerts table")
            ph = payload_hash(row)
            if ph != link["payload_hash"]:
                return res(False, links=link["link_no"], head=dict(chains[-1]),
                           alerts=len(by_id),
                           error=f"link {link['link_no']}: alert {alert_id} "
                                 "payload was modified after insertion")
            if link["prev_hash"] != prev_hash:
                return res(False, links=link["link_no"], head=dict(chains[-1]),
                           alerts=len(by_id),
                           error=f"link {link['link_no']}: prev_hash does not "
                                 "match the preceding chain_hash (chain edited "
                                 "or rows inserted out of order)")
            expected = hashlib.sha256(
                (prev_hash + ph).encode("utf-8")).hexdigest()
            if link["chain_hash"] != expected:
                return res(False, links=link["link_no"], head=dict(chains[-1]),
                           alerts=len(by_id),
                           error=f"link {link['link_no']}: chain_hash mismatch "
                                 f"(expected {expected[:16]}…)")
            prev_hash = link["chain_hash"]
        # Every alert row must be linked. The walk above only visits chain
        # links, so without this an INSERT INTO alerts that skips
        # evidence_chain verifies green while recent(), the incident report and
        # the STIX export all serve the unchained row as if it had custody.
        if len(by_id) != len(chains):
            unchained = sorted(set(by_id) - {l["alert_id"] for l in chains})
            return res(False, links=len(chains), head=dict(chains[-1]),
                       alerts=len(by_id),
                       error=f"{len(by_id) - len(chains)} alert row(s) sit "
                             f"outside the chain (evidence without custody): "
                             f"{', '.join(unchained[:3])}"
                             + ("…" if len(unchained) > 3 else ""))
        # Ledger cross-check: the link-by-link walk only proves the db is
        # self-consistent, so deleting the newest links (with their rows) and
        # re-hashing nothing at all would pass. The append-only file is the
        # second place that history has to have been written.
        for led, db_link in zip(ledger, chains):
            if led.get("chain_hash") != db_link["chain_hash"]:
                return res(False, links=db_link["link_no"],
                           head=dict(chains[-1]), alerts=len(by_id),
                           error=f"link {db_link['link_no']}: ledger and "
                                 "db disagree, chain history was "
                                 "rewritten in the db")
        return res(True, links=len(chains), head=dict(chains[-1]),
                   alerts=len(by_id))
    finally:
        conn.close()


# ------------------------------------------------------------------ JSONL I/O
def write_jsonl(alerts: Iterable[Alert], path: str | Path,
                append: bool = False) -> int:
    """One alert dict per line (the shared serialization contract)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    n = 0
    with p.open(mode, encoding="utf-8") as fh:
        for a in alerts:
            fh.write(json.dumps(a.to_dict(), ensure_ascii=False, default=str) + "\n")
            n += 1
    return n


def iter_jsonl(path: str | Path, limit: int | None = None) -> Iterator[dict[str, Any]]:
    """Yield alert dicts from a JSONL file (or a single JSON array file)."""
    p = Path(path)
    if not p.exists():
        return
    with p.open(encoding="utf-8") as fh:
        head = fh.readline()
        fh.seek(0)
        if head.lstrip().startswith("["):
            data = json.load(fh)
            items = data if isinstance(data, list) else [data]
            seen = 0
            for d in items:
                if isinstance(d, dict):
                    yield d
                    seen += 1
                    if limit is not None and seen >= limit:
                        return
            return
        seen = 0
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if isinstance(d, dict):
                yield d
                seen += 1
                if limit is not None and seen >= limit:
                    return


def ingest_jsonl(path: str | Path, store: AlertStore,
                 limit: int | None = None) -> tuple[int, int, int]:
    """Ingest every alert dict in a JSONL file into the store."""
    return store.ingest_dicts(iter_jsonl(path, limit=limit))

