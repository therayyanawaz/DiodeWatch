"""Laya System-1 triage channel tests (no model weights needed).

Covered:
  * runtime port parity, Jev state serialization, option rendering,
    temperature buckets, sequence layout, confidence math;
  * degradation contract, LayaUnavailable with an actionable reason when the
    bundle or onnxruntime is missing; engine status stays honest;
  * question mapping, alert envelope -> state + typed questions -> summary;
  * advisory evidence attach, verdict lands as an evidence item without
    touching the detection fields the hash chain covers;
  * triage side table, record/join/counts outside the evidence hash chain,
    with the chain's own verifier still green afterwards.
"""
from __future__ import annotations

import json

import pytest

from src.alerts.schema import Alert, EvidenceItem, alert_from_dict, validate_alert
from src.alerts.store import AlertStore, verify_chain
from src.alerts.triage_store import TriageStore
from src.triage import laya_runtime as lr
from src.triage import questions as Q
from src.triage.engine import LayaTriage, attach_evidence

BASE = "2026-09-04T00:00:00"


def make_alert(i: int = 0, cls: str = "ddos", **kw) -> Alert:
    return Alert(
        timestamp=BASE, threat_class=cls, confidence=0.9,
        evidence=[EvidenceItem("flows_per_sec", ">=", 695.4, 50.0,
                               "695.4 flows/s to one dst", "flows/s")],
        flow_id=f"f{i}", key="10.0.0.9", detector="ddos", **kw)


# --------------------------------------------------------------------------- #
# pure port parity
# --------------------------------------------------------------------------- #
def test_py_json_dumps_matches_python_json_semantics():
    # insertion key order + ", "/": " separators, ensure_ascii=False
    assert lr.py_json_dumps({"b": 1, "a": "é"}) == '{"b": 1, "a": "é"}'
    assert lr.py_json_dumps([1, "x", None, True]) == '[1, "x", null, true]'
    assert lr.py_json_dumps("plain") == '"plain"'
    assert lr.serialize_state({"k": 1}) == '{"k": 1}'
    assert lr.serialize_state("raw") == "raw"


def test_render_options_shapes_match_question_types():
    choice = lr.Question("choice", "pick", {"a": "alpha", "b": None})
    assert lr.render_options(choice) == ["a: alpha", "b"]
    score = lr.Question("score", "rate", ["low", "mid", "high"])
    assert lr.render_options(score) == ["level 0: low", "level 1: mid",
                                        "level 2: high"]
    noul = lr.Question("noul", "holds?", None)
    assert lr.render_options(noul) == [
        "false: no, the statement does not hold",
        "true: yes, the statement holds"]
    # list-form choice criteria normalize to option->None
    assert lr.render_options(lr.Question("choice", "p", ["x", "y"])) == \
        ["x", "y"]


def test_temperature_buckets_and_softmax():
    assert lr.temp_bucket(lr.QTYPES["noul"], 2) == "noul:2"
    assert lr.temp_bucket(lr.QTYPES["choice"], 4) == "choice:3-5"
    assert lr.temp_bucket(lr.QTYPES["choice"], 11) == "choice:11+"
    p = lr.softmax([1.0, 1.0])
    assert p == [0.5, 0.5]
    assert lr.confidence_from_probs([0.5, 0.5]) == 0.0
    assert lr.confidence_from_probs([1.0, 0.0]) == 1.0
    assert lr.confidence_from_probs([1.0]) == 1.0


def test_build_sequence_layout_and_budgets():
    # stand-in tokenizer: whitespace split + fixed special ids
    ids_map = {"cls": 1, "sep": 2, "mask": 3, "pad": 0}

    def encode(t: str) -> list[int]:
        return [100 + (hash(w) % 500) for w in t.split()]

    q = lr.Question("choice", "pick one", {"a": None, "b": None})
    ids, markers = lr.build_sequence(encode, ids_map, {"k": 1}, q,
                                     max_len=512, head_max_len=192)
    assert ids[0] == 1                            # [CLS] opens the sequence
    assert ids[-1] == 2                           # trailing [SEP]
    assert ids[markers[0]] == 3                   # marker slots hold [MASK]
    assert ids[markers[1]] == 3
    assert len(markers) == 2
    assert len(ids) <= 512


def test_build_sequence_state_truncation_to_max_len():
    ids_map = {"cls": 1, "sep": 2, "mask": 3, "pad": 0}

    def encode(t: str) -> list[int]:
        return list(range(10, 10 + len(t.split())))

    q = lr.Question("noul", "holds?", None)
    big_state = {"evidence": [{"condition": f"c{i}", "observed": i}
                              for i in range(400)]}
    ids, markers = lr.build_sequence(encode, ids_map, big_state, q,
                                     max_len=128, head_max_len=64)
    assert len(ids) == 128                        # hard cap respected
    assert len(markers) == 2


# --------------------------------------------------------------------------- #
# degradation contract
# --------------------------------------------------------------------------- #
def test_missing_bundle_degrades_with_actionable_reason(tmp_path):
    with pytest.raises(lr.LayaUnavailable) as ei:
        lr.Laya.load(tmp_path)
    msg = str(ei.value)
    assert "fetch_laya" in msg and "missing" in msg


def test_engine_status_honest_when_unavailable(tmp_path):
    eng = LayaTriage(tmp_path / "nope")
    assert eng.available() is False
    st = eng.status()
    assert st["available"] is False and "reason" in st
    # quiet triage degrades to None and remembers why
    assert eng.triage_quiet(make_alert()) is None
    assert eng.status_reason() is not None


def test_triage_cli_refuses_when_the_bundle_is_absent(tmp_path, capsys):
    """The CLI carried its own copy of the batch loop and printed len(alerts)
    as the triaged count whether or not the bundle answered for them. It now
    shares triage_alerts(), so the refusal and the count come from one place."""
    from src.triage.engine import main as triage_main
    inp = tmp_path / "alerts.ndjson"
    inp.write_text("\n".join(json.dumps(a.to_dict())
                             for a in (make_alert(0), make_alert(1))),
                   encoding="utf-8")
    out = tmp_path / "triaged.ndjson"
    rc = triage_main(["--input", str(inp), "--out", str(out),
                      "--model-dir", str(tmp_path / "no-bundle")])
    assert rc == 1
    assert "unavailable" in capsys.readouterr().err
    assert not out.exists(), "an unavailable channel must not write an output"


def test_system_one_requires_questions(tmp_path):
    eng = LayaTriage(tmp_path / "nope")
    with pytest.raises(lr.LayaUnavailable):
        eng.triage(make_alert())  # unavailable before the ValueError path


# --------------------------------------------------------------------------- #
# question mapping
# --------------------------------------------------------------------------- #
def test_state_of_carries_evidence_not_bookkeeping():
    a = make_alert(0, src_ip="10.0.0.9", dst_ip="93.184.216.34",
                   dst_port=443, proto="tcp")
    s = Q.state_of(a)
    assert s["threat_class"] == "ddos" and s["confidence"] == 0.9
    assert s["evidence"][0]["condition"] == "flows_per_sec"
    assert s["dst"] == "93.184.216.34"
    assert "alert_id" not in s and "window_start" not in s
    # serializes inside the model's token budget (survives 512-token cap)
    assert len(lr.serialize_state(s)) < 4000


def test_triage_questions_are_typed_and_ordered():
    qs = Q.triage_questions(make_alert(0, "scan"))
    assert list(qs) == ["disposition", "urgency", "corroborate"]
    assert qs["disposition"].type == "choice"
    assert list(qs["disposition"].criteria) == list(Q.DISPOSITIONS)
    assert qs["urgency"].type == "score"
    assert len(qs["urgency"].criteria) == 4
    assert qs["corroborate"].type == "noul"
    # noisy classes get the plain false-positive option text
    noisy = Q.triage_questions(make_alert(0, "ddos"))
    assert "detector artifact" in noisy["disposition"].criteria["false_positive"]
    quiet = Q.triage_questions(make_alert(0, "dga"))
    assert "rare" in quiet["disposition"].criteria["false_positive"]


def test_answer_summary_roundtrip():
    answers = {
        "disposition": lr.Answer(
            type="choice", choice="investigate",
            probabilities={"escalate": 0.1, "investigate": 0.6,
                           "monitor": 0.2, "false_positive": 0.1},
            confidence=0.55, act_probability=0.9),
        "urgency": lr.Answer(type="score", score=1.4,
                             legend={"0": "routine", "1": "today",
                                     "2": "now", "3": "drop everything"},
                             probabilities={"0": 0.1, "1": 0.5, "2": 0.3,
                                            "3": 0.1},
                             confidence=0.4, act_probability=0.9),
        "corroborate": lr.Answer(type="noul", noul=0.83, confidence=0.2,
                                 act_probability=0.9),
    }
    s = Q.answer_summary(answers)
    assert s["recommended"] == "investigate"
    assert s["p_false_positive"] == 0.1
    assert s["urgency"] == 1.4 and "urgency_legend" in s
    assert s["corroborates_class"] == 0.83


# --------------------------------------------------------------------------- #
# advisory evidence attach
# --------------------------------------------------------------------------- #
def test_attach_evidence_is_advisory_only():
    a = make_alert(0)
    before = (a.confidence, a.severity, a.alert_id)
    summary = {"recommended": "monitor", "p_false_positive": 0.44,
               "urgency": 0.8, "corroborates_class": 0.61}
    attach_evidence(a, summary)
    item = a.evidence[-1]
    assert item.condition == "triage.disposition"
    assert item.observed == "monitor"
    # detection fields untouched (chain-covered payload intact)
    assert (a.confidence, a.severity, a.alert_id) == before
    assert validate_alert(a) == []


# --------------------------------------------------------------------------- #
# advisory guard + model provenance in the verdict envelope
# --------------------------------------------------------------------------- #
def test_stamp_contract_adds_guard_and_provenance():
    """Every verdict carries auto_close_allowed=False, requires_human_review=True
    and its model provenance, stamped without any weights or session."""
    from src.triage.engine import stamp_contract
    summary = {"recommended": "false_positive", "p_false_positive": 0.35}
    stamp_contract(summary, model_dir="models/laya-onnx")

    # the guard: false_positive is a recommendation, never a close decision
    assert summary["auto_close_allowed"] is False
    assert summary["requires_human_review"] is True
    # provenance
    assert summary["model_name"]
    assert summary["model_revision"] == lr.MODEL_REVISION
    # sha: real bundle present -> real digest; absent -> None. Either way it
    # must look like a digest-or-None, never a crash or empty string.
    assert summary["bundle_sha256"] is None or (
        isinstance(summary["bundle_sha256"], str)
        and len(summary["bundle_sha256"]) == 64)


def test_stamp_contract_hashes_bundle_once():
    """bundle_sha256 is computed lazily once per process and reused."""
    from src.triage import engine as eng_mod

    calls = []

    def fake_sha(model_dir):
        calls.append(str(model_dir))
        return "abc123"

    orig, orig_cached = eng_mod.bundle_sha256, eng_mod._CACHED_SHA
    eng_mod.bundle_sha256 = fake_sha
    eng_mod._CACHED_SHA = None
    try:
        eng_mod.stamp_contract({"recommended": "monitor"})
        eng_mod.stamp_contract({"recommended": "monitor"})
    finally:
        eng_mod.bundle_sha256 = orig
        eng_mod._CACHED_SHA = orig_cached
    assert calls == [str(eng_mod.DEFAULT_BUNDLE_DIR)]  # hashed exactly once


def test_model_revision_pin_matches_fetch_script():
    """The runtime pin and the fetch script must agree (single source of truth)."""
    import scripts.fetch.fetch_laya as fetch
    assert lr.MODEL_REVISION == fetch.HF_REVISION
    assert len(lr.MODEL_REVISION) == 40          # full git sha


# --------------------------------------------------------------------------- #
# triage side table (outside the evidence hash chain)
# --------------------------------------------------------------------------- #
def test_triage_store_record_join_counts(tmp_path):
    db = tmp_path / "alerts.db"
    store = AlertStore(db)
    a = make_alert(0)
    store.insert(a)

    ts = TriageStore(db)
    a.triage = {"recommended": "escalate", "urgency": 2.3,
                "corroborates_class": 0.91, "p_false_positive": 0.02}
    assert ts.record(a, model_dir="models/laya-onnx") is True
    assert ts.record(make_alert(1)) is False          # no verdict attached

    got = ts.get(a.alert_id)
    assert got["disposition"] == "escalate"
    assert got["verdict"]["urgency"] == 2.3
    assert ts.counts() == {"escalate": 1}

    # join re-attaches onto a fresh Alert object (roundtrip through store), as a
    # copy: the wall broadcasts the objects it hands the report route, and an
    # alert must not gain an evidence row because somebody downloaded a PDF.
    fresh = store.recent(limit=10)[0]
    assert fresh.triage is None
    n_evidence = len(fresh.evidence)
    joined = ts.join([fresh])[0]
    assert joined is not fresh
    assert fresh.triage is None and len(fresh.evidence) == n_evidence
    assert joined.triage["recommended"] == "escalate"
    # and the full advisory trail the live worker produces, not half of it
    assert [e.condition for e in joined.evidence][n_evidence] == "triage.disposition"
    assert ts.join([joined])[0] is joined     # already carries a verdict
    ts.close()
    store.close() if hasattr(store, "close") else None


def test_hash_chain_unaffected_by_triage_side_table(tmp_path):
    db = tmp_path / "alerts.db"
    store = AlertStore(db)
    a = make_alert(0)
    store.insert(a)
    n_links = store.chain_length()

    ts = TriageStore(db)
    a.triage = {"recommended": "investigate", "urgency": 1.0,
                "corroborates_class": 0.5, "p_false_positive": 0.2}
    ts.record(a)
    ts.close()

    # chain unchanged by triage writes, and still verifies green
    assert store.chain_length() == n_links
    res = verify_chain(db)
    assert res["ok"] is True
    if hasattr(store, "close"):
        store.close()


# --------------------------------------------------------------------------- #
# alert schema: additive triage field round-trips
# --------------------------------------------------------------------------- #
def test_alert_triage_field_roundtrips_through_dict():
    a = make_alert(0)
    a.triage = {"recommended": "escalate", "urgency": 2.3,
                "corroborates_class": 0.91, "p_false_positive": 0.02}
    d = a.to_dict()
    assert d["triage"]["recommended"] == "escalate"
    b2 = alert_from_dict(d)
    assert b2.triage == a.triage
    assert validate_alert(b2) == []


def test_alert_without_triage_serializes_null():
    d = make_alert(0).to_dict()
    assert d["triage"] is None
    assert validate_alert(alert_from_dict(d)) == []
