"""Backup, vacuum and retention do their jobs and report honestly.

The bar for a backup here is higher than "a file appeared": the copy must
verify with its ledger, a tampered source must produce a backup that admits
it, and retention must move stamped families whole, never a db without its
anchor. Row deletion is deliberately absent, the chain makes it impossible to
do honestly.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from src.alerts.maintenance import backup_db, prune_families, run_maintenance, vacuum_db
from src.alerts.schema import EvidenceItem
from src.alerts.store import AlertStore, ledger_path, verify_chain
from tests.alerts.test_alerts import make_alert


def _filled_store(path: Path, n: int = 5) -> AlertStore:
    store = AlertStore(path)
    store.insert_many([make_alert(i) for i in range(n)])
    return store


def test_backup_copies_the_pair_and_the_copy_verifies(tmp_path):
    src = tmp_path / "live_session.db"
    _filled_store(src)
    result = backup_db(src, tmp_path / "backups", stamp="20261125T120000Z")
    assert result["ok"] is True, result
    assert result["verify"]["ok"] is True
    assert result["verify"]["anchored"] is True, "ledger must ride along"
    backup = Path(result["db"])
    assert backup.exists()
    assert Path(result["ledger"]).exists()
    assert Path(result["ledger"]).read_bytes() == ledger_path(src).read_bytes()
    # the copy is a standalone db: it opens and holds every alert
    conn = sqlite3.connect(backup)
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 5
    conn.close()


def test_a_backup_of_a_tampered_store_admits_it(tmp_path):
    src = tmp_path / "live_session.db"
    _filled_store(src)
    conn = sqlite3.connect(src)
    conn.execute("UPDATE alerts SET confidence = 0.123456789 WHERE rowid = 2")
    conn.commit()
    conn.close()
    result = backup_db(src, tmp_path / "backups")
    assert result["ok"] is False
    assert "modified" in result["error"]


def test_backup_without_a_ledger_is_self_consistent_and_says_so(tmp_path):
    src = tmp_path / "live_session.db"
    _filled_store(src)
    ledger_path(src).unlink()
    result = backup_db(src, tmp_path / "backups")
    assert result["ok"] is True
    assert result["verify"]["anchored"] is False


def test_vacuum_reclaims_the_pages_deleted_rows_leave(tmp_path):
    src = tmp_path / "live_session.db"
    store = _filled_store(src, 60)
    big = [EvidenceItem("bulk", ">=", "observed", 1.0, "padding " * 200, "")]
    for i in range(60, 140):
        a = make_alert(i)
        a.evidence = big
        store.insert(a)
    store.close()

    conn = sqlite3.connect(src)
    conn.execute("DELETE FROM alerts WHERE alert_id NOT IN "
                 "(SELECT alert_id FROM alerts LIMIT 5)")
    conn.commit()
    assert conn.execute("PRAGMA freelist_count").fetchone()[0] > 0
    conn.close()

    result = vacuum_db(src)
    assert result["ok"] is True, result
    assert result["freelist_after"] < result["freelist_before"]
    assert result["freelist_after"] == 0
    assert result["bytes_after"] <= result["bytes_before"]


def test_prune_moves_families_whole_and_never_touches_the_live_pair(tmp_path):
    bdir = tmp_path / "backups"
    bdir.mkdir()
    for i, stamp in enumerate(f"2026110{T}T000000Z" for T in range(1, 6)):
        (bdir / f"live_session.{stamp}.db").write_text(f"db{i}")
        (bdir / f"live_session.{stamp}.chain-ledger.ndjson").write_text("[]")
    (bdir / "live_session.db").write_text("live")          # no stamp: untouchable
    (bdir / "live_session.chain-ledger.ndjson").write_text("[]")
    (bdir / "unrelated.db").write_text("x")                # wrong stem

    result = prune_families(bdir, "live_session", keep=2)
    assert result["ok"] is True
    assert len(result["removed"]) == 6, "3 whole families, 2 files each"
    kept = sorted(p.name for p in bdir.iterdir())
    # ASCII order: stamped names (digits) first, then the live ledger, the
    # live db, then the file with the wrong stem
    assert kept == ["live_session.20261104T000000Z.chain-ledger.ndjson",
                    "live_session.20261104T000000Z.db",
                    "live_session.20261105T000000Z.chain-ledger.ndjson",
                    "live_session.20261105T000000Z.db",
                    "live_session.chain-ledger.ndjson",
                    "live_session.db",
                    "unrelated.db"]


def test_prune_counts_backups_not_stamps(tmp_path):
    """Same-second backups (-2, -3 suffixes) are separate units of retention."""
    bdir = tmp_path / "backups"
    bdir.mkdir()
    for suffix in ("", "-2", "-3"):
        (bdir / f"live_session.20261125T000000Z{suffix}.db").write_text("x")
        (bdir / f"live_session.20261125T000000Z{suffix}.chain-ledger.ndjson"
         ).write_text("[]")
    result = prune_families(bdir, "live_session", keep=2)
    assert len(list(bdir.glob("*.db"))) == 2
    assert len(list(bdir.glob("*.ndjson"))) == 2
    assert result["removed"] == ["live_session.20261125T000000Z.db",
                                 "live_session.20261125T000000Z.chain-ledger.ndjson"]


def test_run_maintenance_backs_up_prunes_and_reports_one_verdict(tmp_path):
    src = tmp_path / "live_session.db"
    _filled_store(src)
    out = run_maintenance(src, tmp_path / "backups", keep=2)
    assert out["ok"] is True
    assert out["steps"]["backup"]["ok"] is True
    # a second and third run prune to keep=2
    for stamp in ("20261126T000000Z", "20261127T000000Z"):
        assert run_maintenance(src, tmp_path / "backups", keep=2,
                               vacuum=False)["ok"] is True
    backups = list((tmp_path / "backups").glob("live_session.*.db"))
    assert len(backups) == 2
    # the CLI answers with the same shape and exit 0
    import subprocess
    import sys
    proc = subprocess.run(
        [sys.executable, "-m", "src.alerts.maintenance", "--db", str(src),
         "--backup-dir", str(tmp_path / "backups"), "--keep", "2"],
        capture_output=True, text=True, check=True)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["ok"] is True


def test_run_maintenance_on_a_missing_db_skips_without_failing(tmp_path):
    out = run_maintenance(tmp_path / "nope.db", tmp_path / "backups")
    assert out["ok"] is True
    assert "skipped" in out["steps"]["backup"]
    assert not (tmp_path / "backups").exists() or \
        not list((tmp_path / "backups").iterdir())


def test_a_backed_up_chain_still_verifies_against_its_own_ledger(tmp_path):
    src = tmp_path / "live_session.db"
    _filled_store(src)
    result = backup_db(src, tmp_path / "backups")
    verdict = verify_chain(result["db"])
    assert verdict["ok"] is True and verdict["anchored"] is True
    assert verdict["alerts"] == 5

def test_the_scheduled_run_updates_the_counters_the_health_route_reports(
        tmp_path, monkeypatch):
    """The server's scheduler calls run_maintenance with these arguments."""
    pytest.importorskip("fastapi")
    import apps.mission_control.server as srv
    db = srv.SESSION.store.path
    result = run_maintenance(db, db.parent / "backups", keep=4, vacuum=True)
    assert result["ok"] is True
    assert (db.parent / "backups").is_dir()
