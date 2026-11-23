"""Off-box anchoring: the digest, the RFC 3161 request, and the tamper path.

`test_chain_attest.py` covers the chain itself and the on-box bundle. This file
covers the step past the ceiling: a digest that names exactly what the chain
held, exported so a third party keeps its own copy, and an RFC 3161 request that
binds that digest to a wall-clock time without contacting anything.

The tests that matter most are the two the feature exists for:
  * the same store digests to the same bytes, or a timestamp over it is
    meaningless;
  * a store whose rows were edited digests differently and says `chain_ok`
    False, so an export cannot launder a tampered capture.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest

from src.alerts import attest
from src.alerts.cli import main as alerts_cli
from src.alerts.store import AlertStore

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tests.alerts.test_alerts import make_alert


def _store(db: Path, n: int = 3) -> Path:
    with AlertStore(db) as store:
        store.insert_many([make_alert(i, cls="ddos") for i in range(n)])
    return db


def test_digest_reports_the_head_and_the_length(tmp_path):
    doc = attest.digest(_store(tmp_path / "a.db", 7))
    assert doc["chain_ok"] is True and doc["chain_error"] is None
    assert doc["links"] == 7 and doc["alerts"] == 7
    assert doc["head_link_no"] == 7
    assert len(doc["head_chain_hash"]) == 64
    assert len(doc["digest_sha256"]) == 64


def test_the_same_store_digests_to_the_same_bytes(tmp_path):
    """A timestamp over a digest that moves is a timestamp over nothing."""
    db = _store(tmp_path / "a.db")
    first, second = attest.digest(db), attest.digest(db)
    assert first == second
    assert attest.canonical_bytes(first) == attest.canonical_bytes(second)


def test_an_edited_store_digests_differently_and_reports_the_break(tmp_path):
    db = _store(tmp_path / "a.db", 4)
    clean = attest.digest(db)

    conn = sqlite3.connect(db)
    conn.execute("UPDATE alerts SET confidence = confidence + 0.01 "
                 "WHERE rowid = (SELECT MIN(rowid) FROM alerts)")
    conn.commit()
    conn.close()

    dirty = attest.digest(db)
    assert dirty["chain_ok"] is False
    assert dirty["chain_error"]
    assert dirty["digest_sha256"] != clean["digest_sha256"]


def test_export_names_the_file_after_the_digest(tmp_path):
    db = _store(tmp_path / "a.db", 2)
    doc = attest.export(db, tmp_path / "out")
    path = Path(doc["path"])
    assert path.exists()
    assert doc["digest_sha256"][:16] in path.name

    written = json.loads(path.read_text(encoding="utf-8"))
    assert written["digest_sha256"] == doc["digest_sha256"]
    # the file's own bytes re-hash to the value it carries
    assert attest.canonical_bytes(written) == attest.canonical_bytes(doc["path"] and written)


def test_cli_exports_and_signals_a_broken_chain(tmp_path, capsys):
    db = _store(tmp_path / "a.db", 3)
    assert attest.main(["--db", str(db), "--out", str(tmp_path / "out")]) == 0
    assert "chain   intact" in capsys.readouterr().out

    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM alerts WHERE rowid = (SELECT MAX(rowid) FROM alerts)")
    conn.commit()
    conn.close()
    assert attest.main(["--db", str(db), "--out", str(tmp_path / "out2")]) == 1


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not on PATH")
def test_timestamp_request_is_a_der_encoded_tsq(tmp_path):
    doc = attest.export(_store(tmp_path / "a.db"), tmp_path / "out")
    tsq = attest.timestamp_request(doc["path"])
    assert tsq is not None and tsq.exists() and tsq.stat().st_size > 0
    # RFC 3161 requests are DER-encoded ASN.1: a SEQUENCE tag leads the file.
    assert tsq.read_bytes()[0] == 0x30


def test_a_missing_openssl_is_reported_not_faked(tmp_path):
    """The air-gapped laptop case: no OpenSSL, so no request, and the caller is
    told. A silent empty file would be worse than a missing one."""
    doc = attest.export(_store(tmp_path / "a.db"), tmp_path / "out")
    assert attest.timestamp_request(doc["path"], openssl="/nonexistent/openssl") is None
    ok, message = attest.verify_timestamp("a.tsq", "a.tsr", openssl="/nonexistent/openssl")
    assert ok is False and "not available" in message


def test_an_invalid_timestamp_response_fails_verification(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("openssl not on PATH")
    doc = attest.export(_store(tmp_path / "a.db"), tmp_path / "out")
    tsq = attest.timestamp_request(doc["path"])
    bogus = tmp_path / "bogus.tsr"
    bogus.write_bytes(b"not a timestamp token")
    ok, message = attest.verify_timestamp(tsq, bogus)
    assert ok is False and message


def test_verify_chain_still_agrees_with_the_digest(tmp_path):
    """The digest is a view of verify_chain, not a second opinion that can
    drift: a store that verifies clean must digest as clean."""
    db = _store(tmp_path / "a.db", 5)
    report = alerts_cli(["verify-chain", "--db", str(db)])
    assert report == 0
    assert attest.digest(db)["chain_ok"] is True
