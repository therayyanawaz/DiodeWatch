"""Dashboard tests: replay engine (watch.py) + demo pcap + session store.

Headless: everything here runs the exact calls the dashboard makes, without
importing streamlit, except the one caption test that has to render the app.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.alerts.schema import CLASS_NAMES, display_class
from src.alerts.watch import DEFAULT_WINDOW_S, SessionStore, replay_flows
from src.ingest.pcap_reader import stream_flows

REPO = Path(__file__).resolve().parents[2]
DEMO = REPO / "data" / "pcaps" / "demo_threats.pcap"
BASE_TS = 1_700_000_000.0


# --------------------------------------------------------------------------- #
# demo capture (generated on demand; cached in data/pcaps)
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def demo_pcap() -> Path:
    if not DEMO.exists():
        from scripts.generators.make_demo_pcap import main as gen_main

        gen_main([])
    return DEMO


@pytest.fixture(scope="module")
def demo_flows(demo_pcap) -> list[dict]:
    flows = list(stream_flows(demo_pcap))
    flows.sort(key=lambda r: r["ts_epoch"])
    return flows


def _replay(flows: list[dict], window_s: float = DEFAULT_WINDOW_S):
    store = SessionStore()
    for w in replay_flows(flows, window_s=window_s):
        store.absorb(w)
    return store


# --------------------------------------------------------------------------- #
# windowing / replay engine
# --------------------------------------------------------------------------- #
def test_replay_groups_into_windows(demo_flows):
    store = _replay(demo_flows)
    assert store.stats.windows > 0
    assert store.stats.flows == len(demo_flows)
    # every window evaluated is a multiple-sized bucket: flows accounted for
    assert sum(store.stats.window_flows) == len(demo_flows)


def test_replay_watermark_closes_windows_in_order(demo_flows):
    seen = []
    for w in replay_flows(demo_flows, window_s=DEFAULT_WINDOW_S):
        seen.append(w.win_idx)
    assert seen == sorted(seen), "windows must be evaluated chronologically"


def test_replay_skips_records_without_timestamp():
    junk = [{"ts_epoch": None, "flow_id": "x"}]
    assert list(replay_flows(junk)) == []


# --------------------------------------------------------------------------- #
# detection scenarios inside the demo capture
# --------------------------------------------------------------------------- #
def test_demo_pcap_fires_all_four_signatures(demo_flows):
    store = _replay(demo_flows)
    fired = {a.detector: a.key for a in store.alerts}
    assert fired.get("ddos") == "10.9.9.9"
    assert fired.get("slowdos") == "10.7.7.7"
    assert fired.get("scan") == "10.5.0.7"
    assert fired.get("exfil") == "10.20.0.9"


def test_demo_classes_are_named_not_printed_raw(demo_flows):
    """The feed column printed `a.threat_class`, so a judge read "scan" here
    while the wall above it said "Recon Scan" about the same alert. Both now go
    through schema.CLASS_NAMES, and this fails the day a detector starts
    emitting a class the table never named."""
    store = _replay(demo_flows)
    fired = {a.threat_class for a in store.alerts}
    assert fired <= set(CLASS_NAMES), f"unnamed: {sorted(fired - set(CLASS_NAMES))}"
    assert {display_class(c) for c in fired} == {
        "DDoS", "Recon Scan", "Exfiltration", "Slow DoS"}


def test_demo_pcap_threats_overlap_like_real_captures(demo_flows):
    """Mixed battlespace: paired threats land in the SAME window."""
    by_win: dict[int, set[str]] = {}
    for w in replay_flows(demo_flows, window_s=DEFAULT_WINDOW_S):
        if w.alerts:
            by_win.setdefault(w.win_idx, set()).update(a.detector for a in w.alerts)
    mixed = {k: v for k, v in by_win.items() if len(v) >= 2}
    assert mixed, "no window fired multiple threats at once"
    dets = {d for v in mixed.values() for d in v}
    assert {"ddos", "scan", "slowdos", "exfil"} <= dets


def test_demo_pcap_benign_windows_stay_quiet(demo_flows):
    for w in replay_flows(demo_flows, window_s=DEFAULT_WINDOW_S):
        if w.window_start < BASE_TS + 50:  # benign mix occupies 0-40 s
            assert w.alerts == [], f"false alarm in benign window {w.win_idx}"


def test_scenario_alerts_carry_evidence_and_attack(demo_flows):
    store = _replay(demo_flows)
    for a in store.alerts:
        assert a.evidence, f"{a.detector} alert without evidence"
        assert a.attack_technique, f"{a.detector} alert without ATT&CK"
        assert a.severity in ("low", "medium", "high", "critical")
        assert a.alert_id


# --------------------------------------------------------------------------- #
# performance counters
# --------------------------------------------------------------------------- #
def _alert_of(ts: float, cls: str = "ddos", key: str = "10.9.9.9"):
    import pandas as pd

    from src.alerts.schema import Alert
    return Alert(
        timestamp=pd.Timestamp(ts, unit="s", tz="UTC").strftime(
            "%Y-%m-%dT%H:%M:%S"),
        detector="rule.ddos", threat_class=cls, confidence=0.9, key=key,
        src_ip=key, dst_ip="10.0.0.1", window_seconds=10,
    )


def test_session_store_counts_suppression():
    """P1-1: raw vs unique vs suppressed counters, a re-absorbed alert with
    the same stable alert_id collapses instead of duplicating the feed."""
    store = SessionStore()
    a = _alert_of(BASE_TS + 10)
    for _ in range(3):                      # same re-detection absorbed 3x
        store.absorb_alerts([a])
    assert store.raw_alerts == 3
    assert store.unique_total == 1
    assert store.suppressed == 2
    assert len(store.alerts) == 1           # feed holds one record
    m = store.metrics()
    assert m["alerts_raw"] == 3 and m["alerts"] == 1
    assert m["alerts_suppressed"] == 2 and m["entities"] == 1


def test_headline_counts_records_the_wall_shows(demo_flows):
    """The stat line is the feed size on every channel, not the firing count.

    `stats.alerts` is the rule path's raw firings (it is what alerts_per_sec
    measures), while the ML sidecar path adds only what joined the feed. So a
    replay of a capture already under custody headlined 2 alerts over an empty
    wall on the rule path and 0 on the sidecar path, same situation, two
    numbers, one of them a claim about evidence the feed does not contain.
    """
    first = _replay(demo_flows)
    assert first.metrics()["alerts"] == len(first.alerts) > 0

    second = SessionStore()
    second.prime_seen([a.alert_id for a in first.alerts])
    for w in replay_flows(demo_flows, window_s=DEFAULT_WINDOW_S):
        second.absorb(w)
    m = second.metrics()
    assert m["alerts"] == len(second.alerts) == 0
    assert m["alerts_raw"] == len(first.alerts)
    assert m["alerts_suppressed"] == len(first.alerts)


def test_session_store_distinct_alerts_all_kept():
    store = SessionStore()
    store.absorb_alerts([_alert_of(BASE_TS + 10),
                         _alert_of(BASE_TS + 20, cls="scan", key="10.5.0.7"),
                         _alert_of(BASE_TS + 30, cls="exfil", key="10.20.0.9")])
    assert store.unique_total == 3 and store.suppressed == 0
    assert store.metrics()["entities"] == 3


def test_session_metrics_populate(demo_flows):
    store = _replay(demo_flows)
    m = store.metrics()
    assert m["replay_fps"] > 0
    assert m["alerts_per_sec"] > 0
    assert m["windows"] == store.stats.windows
    assert m["flows"] == len(demo_flows)
    assert m["p95_eval_ms"] >= m["p50_eval_ms"] >= 0
    assert m["p95_per_flow_ms"] >= 0
    assert m["sustained_fps"] > 0


def test_timeline_buckets_by_second(demo_flows):
    store = _replay(demo_flows)
    assert store.timeline
    assert sum(store.timeline.values()) == store.stats.alerts


def test_session_store_ring_buffer(demo_flows):
    store = SessionStore(max_alerts=2)
    for w in replay_flows(demo_flows, window_s=DEFAULT_WINDOW_S):
        store.absorb(w)
        if len(store.alerts) >= 4:
            break
    assert len(store.alerts) <= 2


# --------------------------------------------------------------------------- #
# exports glue (same calls the Evidence tab makes)
# --------------------------------------------------------------------------- #
def test_session_alert_exports_to_stix_and_report(tmp_path, demo_flows):
    from src.alerts.export_stix import write_stix
    from src.alerts.report import write_report

    store = _replay(demo_flows)
    alert = store.alerts[0]
    bundle, problems = write_stix([alert], tmp_path / "b.json")
    assert problems == []
    assert bundle["type"] == "bundle"
    rep = write_report([alert], tmp_path / "r.html", title="t")
    html = rep.read_text(encoding="utf-8")
    assert alert.threat_class in html
    assert all(e.condition in html for e in alert.evidence)


def test_session_alert_exports_to_ocsf(tmp_path, demo_flows):
    from src.alerts.export_ocsf import validate_event, write_ocsf

    store = _replay(demo_flows)
    alert = store.alerts[0]
    out = tmp_path / "finding.json"
    events, problems = write_ocsf([alert], out)
    assert problems == []
    assert len(events) == 1
    assert validate_event(events[0]) == []
    assert events[0]["finding_info"]["uid"] == alert.alert_id
    assert json.loads(out.read_text(encoding="utf-8")) == events[0]


# --------------------------------------------------------------------------- #
# alert-feed filter chips (severity + detector)
# --------------------------------------------------------------------------- #
def test_filter_semantics_on_real_session(demo_flows):
    """The chip filter contract, exercised on the real demo session."""
    store = _replay(demo_flows)
    recent = store.alerts[-300:][::-1]
    detectors = {(a.detector or "unknown") for a in store.alerts}

    def active(sel):
        return [s for s in (sel or []) if s != "all"]

    def apply(sev_sel, det_sel):
        sev_f, det_f = active(sev_sel), active(det_sel)
        return [a for a in recent
                if (not sev_f or (a.severity or "medium").lower() in sev_f)
                and (not det_f or (a.detector or "unknown") in det_f)]

    assert len(apply(["all"], ["all"])) == len(store.alerts)
    assert len(apply([], [])) == len(store.alerts)          # empty == all
    assert len(apply(["all", "high"], ["all"])) == len(apply(["high"], ["all"]))
    assert len(apply(["all"], list(detectors))) == len(store.alerts)
    assert apply(["low"], ["ml.beacon"]) == []  # impossible combination
    # at least one chip combo actually narrows the feed
    assert len(apply(["critical"], ["all"])) < len(store.alerts)


# --------------------------------------------------------------------------- #
# channel disclosure in the metrics caption
# --------------------------------------------------------------------------- #
def test_tls_caption_discloses_the_novelty_layer():
    """The headline F1 is the *combined* channel, so the caption has to say
    how much each layer contributed and whether novelty runs at all -
    otherwise a watchlist-only 1.000 reads as an anomaly-model result."""
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    pin = (REPO / "results" / "ml" / "tls_metrics.json")
    if not pin.exists():
        pin = REPO / "docs" / "evaluation" / "runs" / "tls_metrics.json"
    tls = json.loads(pin.read_text(encoding="utf-8"))
    plant = tls["synthetic_plant_eval"]

    at = AppTest.from_file(str(REPO / "apps" / "dashboard" / "app.py"))
    at.run(timeout=180)
    assert len(at.exception) == 0
    line = next(c.value for c in at.caption
                if "ml.tls" in (c.value or ""))
    assert f"watchlist {plant['watchlist_only']['tp']}" in line
    assert f"novelty {plant['novelty_only']['tp']}" in line
    assert ("novelty layer active" if tls["novelty_available"]
            else "novelty layer disabled") in line


# --------------------------------------------------------------------------- #
# the chain claim in the metrics panel
# --------------------------------------------------------------------------- #
def test_chain_panel_names_its_anchor(tmp_path, monkeypatch):
    """Re-hashing proves the rows agree with each other; only the append-only
    ledger beside the db proves nobody rewrote them. This panel printed
    `integrity: PASS` either way, which is a stronger claim than the wall makes
    about the same file.
    """
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    from src.alerts.live_store import LiveEvidenceStore
    from src.alerts.store import ledger_path, verify_chain
    from tests.alerts.test_alerts import make_alert

    db = tmp_path / "chain.db"
    store = LiveEvidenceStore(path=db)
    store.absorb_alerts([make_alert(0, "scan"), make_alert(1, "exfil")])
    store.close()
    ledger_path(db).unlink(missing_ok=True)   # the twin file, not the chain
    monkeypatch.setenv("DIODE_LIVE_DB", str(db))
    anchored = verify_chain(db)["anchored"]   # the fact the panel must reflect
    assert anchored is False

    at = AppTest.from_file(str(REPO / "apps" / "dashboard" / "app.py"))
    at.run(timeout=180)
    assert len(at.exception) == 0
    line = next(c.value for c in at.code if "integrity:" in (c.value or ""))
    assert "PASS" not in line
    assert ("RE-VERIFIED · ANCHORED" if anchored
            else "RE-VERIFIED (no anchor)") in line


# --------------------------------------------------------------------------- #
# the diode tab's own counters
# --------------------------------------------------------------------------- #
def test_diode_card_prints_no_zero_it_did_not_observe(tmp_path, monkeypatch):
    """`_diode_card()` is the tab's second renderer of the same status file
    (`apps/dashboard/diode_panel.py` is the standalone one), and it used to
    print `Outbound connections 0` / `Violations 0` next to an honest
    `Outbound bytes not observed`: on a host with no kernel socket table those
    are an absent observer, not an absent egress, and the paragraph under them
    claimed the OS refuses the packets whatever the verdict said.
    """
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    from src.diode.monitor import now_iso, write_json

    fact = tmp_path / "status.json"
    write_json(fact, {
        "timestamp": now_iso(), "monitor_available": False,
        "mode": "monitor-only", "backend": "none",
        "backend_reason": "no /proc/net on this host", "protected_uid": 1000,
        "enforcement_verified": None, "dropped_packets": None,
        "outbound_connections": 0, "outbound_bytes": None,
        "bytes_accounting": "proc-only", "compliant": False,
        "violations_total": 0, "seq": 1})
    monkeypatch.setenv("DIODE_STATUS_FILE", str(fact))

    at = AppTest.from_file(str(REPO / "apps" / "dashboard" / "app.py"))
    at.run(timeout=180)
    assert len(at.exception) == 0
    cells = {m.label: str(m.value) for m in at.metric}
    for label in ("Outbound bytes", "Outbound connections",
                  "Violations (attempts)"):
        assert cells[label] == "not observed", cells
    notes = " ".join(el.value or "" for el in at.info)
    assert "no zero below is evidence" in notes
