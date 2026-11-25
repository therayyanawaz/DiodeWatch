"""Backup, vacuum and retention for the evidence stores.

Three jobs the evidence path never had:

* `backup_db` takes a consistent online snapshot through SQLite's backup API
  (readers and writers keep running), copies the append-only ledger beside it,
  and then RE-VERIFIES the copy: a backup that does not itself verify is not a
  backup, it is a corrupted second copy of the evidence, and it is reported as
  failed rather than shelved. The ledger is copied BEFORE the db is snapshotted
  because `verify_chain` treats a ledger that runs ahead of the chain as a
  deleted tail; a ledger that lags it is a tolerated crash state.
* `vacuum_db` reclaims the space deleted rows leave behind (WAL churn on a
  long-lived session db grows the file even when the row count does not).
* `prune_families` is the retention half: a "family" is one stamped db plus the
  ledger and journal files that belong to it, matching how `LiveEvidenceStore.
  _archive` and `backup_db` name their pairs. Families are pruned whole, never
  file by file, so a stamped db is never left without its anchor.

Deleting alert rows is deliberately absent: the chain hashes every row in
append order, so row-level retention would break verification permanently and
turn the store into a self-consistent forgery. Space is reclaimed by
archiving/rotating whole dbs (already the reset behaviour) and pruning the
rotations, which keeps every surviving db verifiable.

    python -m src.alerts.maintenance --db data/alerts/live_session.db
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from .store import ledger_path, verify_chain

_LOG = logging.getLogger("diode.maintenance")

_STAMP = "%Y%m%dT%H%M%SZ"
_STAMP_RE = re.compile(r"\.(\d{8}T\d{6}Z)")


def _stamp() -> str:
    return time.strftime(_STAMP, time.gmtime())


def backup_db(db_path: str | Path, dest_dir: str | Path,
              stamp: str | None = None) -> dict[str, Any]:
    """Consistent online snapshot of one evidence db, then verify the copy."""
    src = Path(db_path)
    dest_dir = Path(dest_dir)
    if not src.exists():
        return {"ok": False, "error": f"{src} does not exist"}
    stamp = stamp or _stamp()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{src.stem}.{stamp}.db"
    n = 2
    while dest.exists():
        dest = dest_dir / f"{src.stem}.{stamp}-{n}.db"
        n += 1

    # Ledger first: a copy that lags the db verifies (a tolerated crash state),
    # a db that lags its ledger reads as a truncated chain.
    src_ledger = ledger_path(src)
    dest_ledger = ledger_path(dest)
    ledger_copied = False
    if src_ledger.exists():
        dest_ledger.write_bytes(src_ledger.read_bytes())
        ledger_copied = True

    try:
        source = sqlite3.connect(str(src), timeout=30)
        target = sqlite3.connect(str(dest))
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
    except sqlite3.Error as e:
        dest.unlink(missing_ok=True)
        if ledger_copied:
            dest_ledger.unlink(missing_ok=True)
        return {"ok": False, "error": f"sqlite backup failed: {e}"}

    verdict = verify_chain(dest)
    return {"ok": bool(verdict["ok"]), "db": str(dest),
            "ledger": str(dest_ledger) if ledger_copied else None,
            "bytes": dest.stat().st_size, "stamp": stamp, "verify": verdict,
            "error": verdict.get("error")}


def vacuum_db(db_path: str | Path) -> dict[str, Any]:
    """Reclaim free pages and truncate the WAL, reporting the real difference.

    Fails soft on a locked db: a store under active write keeps its lock, the
    caller records the failure and the next run reclaims. VACUUM never makes
    the file bigger here, so a smaller-or-equal result is asserted by callers
    that care.
    """
    src = Path(db_path)
    if not src.exists():
        return {"ok": False, "error": f"{src} does not exist"}
    conn = sqlite3.connect(str(src), timeout=30)
    try:
        before = conn.execute("PRAGMA page_count").fetchone()[0]
        freelist_before = conn.execute("PRAGMA freelist_count").fetchone()[0]
        bytes_before = src.stat().st_size
        conn.execute("VACUUM")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        after = conn.execute("PRAGMA page_count").fetchone()[0]
        freelist_after = conn.execute("PRAGMA freelist_count").fetchone()[0]
        return {"ok": True, "pages_before": int(before), "pages_after": int(after),
                "freelist_before": int(freelist_before),
                "freelist_after": int(freelist_after),
                "bytes_before": bytes_before, "bytes_after": src.stat().st_size}
    except sqlite3.Error as e:
        return {"ok": False, "error": f"vacuum failed: {e}"}
    finally:
        conn.close()


def prune_families(directory: str | Path, stem: str, keep: int = 8) -> dict[str, Any]:
    """Delete whole backups beyond the newest `keep`, never live files.

    The unit is one backup db: `{stem}.{stamp}` or `{stem}.{stamp}-{n}.db`,
    with its ledger (`{...}.chain-ledger.ndjson`) and journal files riding
    along. Counting dbs rather than stamps is what makes retention honest when
    several backups land in the same second (the `-n` suffixes share one
    stamp): `keep=8` really retains 8 dbs, not 8 stamps holding unbounded
    duplicates. The live db and ledger carry no stamp and can never match.
    """
    directory = Path(directory)
    keep = max(1, int(keep))
    if not directory.exists():
        return {"ok": True, "kept": [], "removed": [], "freed_bytes": 0}

    def order_key(name: str) -> tuple:
        m = _STAMP_RE.search(name)
        s = re.search(r"-(\d+)\.db$", name)
        return (m.group(1) if m else "", int(s.group(1)) if s else 0)

    dbs = sorted(
        (f.name for f in directory.iterdir()
         if f.is_file() and f.name.startswith(f"{stem}.")
         and _STAMP_RE.search(f.name) and f.name.endswith(".db")),
        key=order_key)
    doomed = dbs[:-keep] if len(dbs) > keep else []
    survivors = dbs[-keep:]
    removed: list[str] = []
    freed = 0
    for name in doomed:
        base = name[:-3]                    # strip ".db"
        companions = (name, base + ".chain-ledger.ndjson",
                      name + "-wal", name + "-shm")
        for companion in companions:
            f = directory / companion
            if not f.exists():
                continue
            try:
                freed += f.stat().st_size
                f.unlink()
                removed.append(f.name)
            except OSError as e:
                _LOG.warning("prune could not remove %s: %s", f, e)
    return {"ok": True, "kept": survivors, "removed": removed,
            "freed_bytes": freed}


def prune_archives(db_path: str | Path, keep: int = 8) -> dict[str, Any]:
    """Retention for the archived session pairs `_archive` leaves beside a db."""
    src = Path(db_path)
    return prune_families(src.parent, src.stem, keep)


def run_maintenance(db_path: str | Path | None = None,
                    backup_dir: str | Path | None = None,
                    keep: int = 8, vacuum: bool = True) -> dict[str, Any]:
    """Backup, prune and (optionally) vacuum, in one recordable step.

    `db_path` defaults to the live-session store (`DIODE_LIVE_DB` honoured),
    `backup_dir` to a `backups/` folder beside it. Every step reports into
    `steps`; `ok` is False when any step that ran failed. A missing source db
    is not a failure: there is nothing to back up yet.
    """
    from .live_store import db_path as live_db_path

    src = Path(db_path) if db_path is not None else live_db_path()
    bdir = Path(backup_dir) if backup_dir is not None else src.parent / "backups"
    out: dict[str, Any] = {"db": str(src), "backup_dir": str(bdir),
                           "steps": {}, "ok": True}
    steps = out["steps"]
    if src.exists():
        backup = backup_db(src, bdir)
        steps["backup"] = backup
        out["ok"] &= bool(backup["ok"])
        steps["prune_backups"] = prune_families(bdir, src.stem, keep)
        steps["prune_archives"] = prune_archives(src, keep)
    else:
        steps["backup"] = {"skipped": f"{src} does not exist yet"}
    if vacuum and src.exists():
        vac = vacuum_db(src)
        steps["vacuum"] = vac
        out["ok"] &= bool(vac["ok"])
    level = logging.INFO if out["ok"] else logging.ERROR
    _LOG.log(level, "maintenance run", extra={"db": str(src),
                                              "ok": bool(out["ok"])})
    return out


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(
        description="Backup, prune and vacuum the evidence stores")
    ap.add_argument("--db", default=None,
                    help="evidence db (default: the live-session store)")
    ap.add_argument("--backup-dir", default=None,
                    help="where snapshots go (default: backups/ beside the db)")
    ap.add_argument("--keep", type=int, default=8,
                    help="stamped families to retain (default: 8)")
    ap.add_argument("--no-vacuum", action="store_true",
                    help="skip the VACUUM pass")
    args = ap.parse_args(argv)
    result = run_maintenance(args.db, args.backup_dir, args.keep,
                             vacuum=not args.no_vacuum)
    print(json.dumps(result, indent=1))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
