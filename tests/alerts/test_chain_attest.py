"""Tamper-evident evidence chain (C1) + offline attestation bundle (C5).

Covered:
  * hash chain, links append in insertion order, head advances, idempotent
    re-ingest does NOT add duplicate links;
  * verify_chain, PASS on an intact store; names the first broken link when
    a payload is edited after insertion; detects chain-row edits and
    alert-row deletion; graceful on pre-chain stores (0 links);
  * CLI, `verify-chain` exit 0 on PASS, exit 1 on tamper;
  * attestation bundle, deterministic manifest hash for a fixed tree,
    --verify exit 0 on an untouched tree and exit 1 after any file changes,
    ATTESTATION.md renders the identity + chain sections.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

from src.alerts.cli import main as alerts_cli
from src.alerts.store import (
    _COLS,
    AlertStore,
    ledger_path,
    read_ledger,
    verify_chain,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tests.alerts.test_alerts import make_alert


# --------------------------------------------------------------------------- #
# C1, chain writes
# --------------------------------------------------------------------------- #
def test_chain_links_append_and_head_advances(tmp_path):
    db = tmp_path / "a.db"
    with AlertStore(db) as store:
        assert store.chain_head() is None and store.chain_length() == 0
        store.insert_many([make_alert(i, cls="ddos") for i in range(10)])
        head = store.chain_head()
        assert head["link_no"] == 10 and store.chain_length() == 10
        prev = head["chain_hash"]
        store.insert(make_alert(10, cls="scan"))
        head2 = store.chain_head()
        assert head2["link_no"] == 11 and head2["chain_hash"] != prev
        # head format: hex sha256
        assert len(head2["chain_hash"]) == 64


def test_chain_idempotent_reingest_adds_no_links(tmp_path):
    alerts = [make_alert(i, cls="ddos") for i in range(20)]
    with AlertStore(tmp_path / "a.db") as store:
        store.insert_many(alerts)
        assert store.chain_length() == 20
        store.insert_many(alerts)          # all duplicates (stable alert_id)
        assert store.chain_length() == 20  # no duplicate links
        assert verify_chain(tmp_path / "a.db")["ok"] is True


def test_verify_passes_on_intact_store(tmp_path):
    alerts = [make_alert(i, cls=("ddos", "scan", "exfil")[i % 3])
              for i in range(50)]
    with AlertStore(tmp_path / "a.db") as store:
        store.insert_many(alerts)
    r = verify_chain(tmp_path / "a.db")
    assert r["ok"] is True and r["error"] is None
    assert r["links"] == 50 and r["head"]["link_no"] == 50


# --------------------------------------------------------------------------- #
# custody gaps: unchained rows, truncated tails, rewritten history
# --------------------------------------------------------------------------- #
def test_ledger_mirrors_the_chain_and_marks_the_store_anchored(tmp_path):
    db = tmp_path / "a.db"
    with AlertStore(db) as store:
        store.insert_many([make_alert(i, cls="ddos") for i in range(10)])
        store.insert(make_alert(10, cls="scan"))
    led = read_ledger(db)
    assert len(led) == 11
    assert [l["link_no"] for l in led] == list(range(1, 12))
    r = verify_chain(db)
    assert r["ok"] is True and r["anchored"] is True
    assert r["alerts"] == 11


def test_verify_detects_an_alert_row_outside_the_chain(tmp_path):
    """The orphan loophole: a row served by recent()/STIX with no custody."""
    db = tmp_path / "a.db"
    with AlertStore(db) as store:
        store.insert_many([make_alert(i, cls="ddos") for i in range(5)])
        row = store._row(make_alert(99, cls="ddos"))
        store._conn.execute(
            f"INSERT INTO alerts ({_COLS}) VALUES ({','.join('?' * 21)})", row)
        store._conn.commit()
    r = verify_chain(db)
    assert r["ok"] is False
    assert "outside the chain" in r["error"]
    assert "1 alert row" in r["error"]


def test_verify_detects_a_truncated_tail(tmp_path):
    """Deleting the newest links AND their rows leaves the db self-consistent."""
    db = tmp_path / "a.db"
    with AlertStore(db) as store:
        ids = [make_alert(i, cls="ddos").alert_id for i in range(8)]
        store.insert_many([make_alert(i, cls="ddos") for i in range(8)])
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM evidence_chain WHERE link_no > 5")
    conn.execute(f"DELETE FROM alerts WHERE alert_id IN ({','.join('?' * 3)})",
                 ids[5:])
    conn.commit()
    conn.close()
    r = verify_chain(db)
    assert r["ok"] is False and "truncated" in r["error"]
    assert "3" in r["error"]


def test_verify_detects_rewritten_history_even_if_rehashed(tmp_path):
    """Re-hash the db to make it self-consistent, the ledger still disagrees."""
    db = tmp_path / "a.db"
    with AlertStore(db) as store:
        store.insert_many([make_alert(i, cls="ddos") for i in range(6)])
    conn = sqlite3.connect(db)
    conn.execute("UPDATE alerts SET key = '10.9.9.9'")
    conn.commit()
    conn.close()
    r = verify_chain(db)
    assert r["ok"] is False
    assert "modified after insertion" in r["error"] or "disagree" in r["error"]


def test_unanchored_store_says_so_instead_of_claiming_custody(tmp_path):
    db = tmp_path / "a.db"
    with AlertStore(db) as store:
        store.insert_many([make_alert(i, cls="ddos") for i in range(4)])
    ledger_path(db).unlink()
    r = verify_chain(db)
    assert r["ok"] is True and r["anchored"] is False


def test_ledger_backfills_after_a_crash_between_commit_and_append(tmp_path):
    """db ahead of the ledger is a lost append, not tampering, it self-heals."""
    db = tmp_path / "a.db"
    with AlertStore(db) as store:
        store.insert_many([make_alert(i, cls="ddos") for i in range(6)])
    lines = ledger_path(db).read_text(encoding="utf-8").splitlines()
    ledger_path(db).write_text("\n".join(lines[:4]) + "\n", encoding="utf-8")
    with AlertStore(db) as store:                      # reopen heals the tail
        assert store.chain_length() == 6
    assert len(read_ledger(db)) == 6
    assert verify_chain(db)["ok"] is True


def test_verify_names_edited_payload(tmp_path):
    alerts = [make_alert(i, cls="ddos") for i in range(10)]
    with AlertStore(tmp_path / "a.db") as store:
        store.insert_many(alerts)
    # edit one alert row after the fact (evidence tampering)
    conn = sqlite3.connect(tmp_path / "a.db")
    victim = alerts[3].alert_id
    conn.execute("UPDATE alerts SET confidence = 0.01 WHERE alert_id = ?",
                 (victim,))
    conn.commit()
    conn.close()
    r = verify_chain(tmp_path / "a.db")
    assert r["ok"] is False
    assert victim in r["error"] and "modified" in r["error"]
    assert r["links"] == 4   # first broken link number


def test_verify_detects_chain_row_edit(tmp_path):
    with AlertStore(tmp_path / "a.db") as store:
        store.insert_many([make_alert(i) for i in range(10)])
    conn = sqlite3.connect(tmp_path / "a.db")
    conn.execute("UPDATE evidence_chain SET chain_hash = ? WHERE link_no = 5",
                 ("f" * 64,))
    conn.commit()
    conn.close()
    r = verify_chain(tmp_path / "a.db")
    assert r["ok"] is False and r["links"] == 5


def test_verify_detects_deleted_alert_row(tmp_path):
    alerts = [make_alert(i) for i in range(10)]
    with AlertStore(tmp_path / "a.db") as store:
        store.insert_many(alerts)
    conn = sqlite3.connect(tmp_path / "a.db")
    conn.execute("DELETE FROM alerts WHERE alert_id = ?",
                 (alerts[7].alert_id,))
    conn.commit()
    conn.close()
    r = verify_chain(tmp_path / "a.db")
    assert r["ok"] is False and "missing" in r["error"]


def test_verify_graceful_on_pre_chain_and_empty_stores(tmp_path):
    # a store with alert rows but no chain (pre-chain version)
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE alerts (alert_id TEXT PRIMARY KEY)")
    conn.execute("INSERT INTO alerts VALUES ('x')")
    conn.commit()
    conn.close()
    r = verify_chain(db)
    assert r["ok"] is False and "no chain links" in r["error"]

    # an empty store verifies trivially, and every result carries every key,
    # so a caller can never read a missing one as an accidental pass
    with AlertStore(tmp_path / "empty.db"):
        pass
    r2 = verify_chain(tmp_path / "empty.db")
    assert r2 == {"ok": True, "links": 0, "alerts": 0, "head": None,
                  "anchored": False, "error": None}
    assert set(verify_chain(db)) == set(r2)


def test_verify_chain_cli_exit_codes(tmp_path, capsys):
    nd = tmp_path / "in.ndjson"
    from src.alerts.store import write_jsonl
    alerts = [make_alert(i) for i in range(5)]
    write_jsonl(alerts, nd)
    db = tmp_path / "cli.db"
    assert alerts_cli(["store", "--alerts", str(nd), "--db", str(db)]) == 0
    assert alerts_cli(["verify-chain", "--db", str(db)]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True

    # tamper -> exit 1
    conn = sqlite3.connect(db)
    conn.execute("UPDATE alerts SET detector = 'evil' WHERE rowid = 1")
    conn.commit()
    conn.close()
    assert alerts_cli(["verify-chain", "--db", str(db)]) == 1
    out = capsys.readouterr().out
    assert json.loads(out)["ok"] is False


def test_stats_includes_chain(tmp_path):
    with AlertStore(tmp_path / "a.db") as store:
        store.insert_many([make_alert(i) for i in range(3)])
        s = store.stats()
        assert s["chain"]["length"] == 3
        assert s["chain"]["head"]["link_no"] == 3


# --------------------------------------------------------------------------- #
# C5, attestation bundle
# --------------------------------------------------------------------------- #
@pytest.fixture()
def attest_mod():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "attest", Path(__file__).resolve().parents[2] / "scripts" / "checks" / "attest.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_attest_build_verify_roundtrip(attest_mod, tmp_path):
    out = tmp_path / "attest"
    assert attest_mod.main(["--out", str(out)]) == 0
    man = json.loads((out / "attestation.json").read_text(encoding="utf-8"))
    assert man["manifest_hash"] and len(man["manifest_hash"]) == 64
    assert man["counts"]["source"] >= 1      # src/**/*.py found
    assert man["counts"]["requirements"] == 1
    # verification passes on the untouched tree
    assert attest_mod.main(["--verify", str(out)]) == 0


def test_attest_verify_fails_on_tampered_file(attest_mod, tmp_path):
    out = tmp_path / "attest"
    assert attest_mod.main(["--out", str(out)]) == 0
    # modify a hashed file after sealing
    marker = tmp_path / "marker.py"
    marker.write_text("# change\n", encoding="utf-8")
    (attest_mod.REPO_ROOT / "src" / "__attest_tmp.py").write_text(
        "# temporary probe\n", encoding="utf-8")
    try:
        assert attest_mod.main(["--verify", str(out)]) == 1
    finally:
        (attest_mod.REPO_ROOT / "src" / "__attest_tmp.py").unlink()


def test_attest_verify_fails_on_edited_manifest(attest_mod, tmp_path):
    out = tmp_path / "attest"
    assert attest_mod.main(["--out", str(out)]) == 0
    man = json.loads((out / "attestation.json").read_text(encoding="utf-8"))
    man["git"]["commit"] = "0" * 40            # forge the commit
    (out / "attestation.json").write_text(
        json.dumps(man, indent=2), encoding="utf-8")
    assert attest_mod.main(["--verify", str(out)]) == 1


def test_attest_verify_missing_bundle(attest_mod, tmp_path):
    assert attest_mod.main(["--verify", str(tmp_path / "nope")]) == 2


def test_attestation_md_renders(attest_mod, tmp_path):
    out = tmp_path / "attest"
    assert attest_mod.main(["--out", str(out)]) == 0
    md = (out / "ATTESTATION.md").read_text(encoding="utf-8")
    for token in ("Attestation Bundle", "Manifest hash", "Verify",
                  "scripts/checks/attest.py --verify"):
        assert token in md
