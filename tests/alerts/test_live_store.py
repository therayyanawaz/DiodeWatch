"""Live web-wall evidence persistence (Priority 1 / t3).

Covered:
  * LiveEvidenceStore, the chain climbs in real time as windows absorb:
    link count == alerts joined the feed, head changes every poll-worthy
    window, verify-chain PASSES on the live-written db;
  * chain-level idempotency: re-absorbing the same alerts adds ZERO links
    and leaves the head byte-identical;
  * ring-buffer roll-over survival: the feed trims to max_alerts but the
    chain (and its verifiability) keeps every stored link;
  * degrade-to-ring-buffer: a poisoned store path flips `degraded`, keeps
    the feed alive, and reports the reason, never a faked chain;
  * SessionStore split (take_fresh/extend/extend_alerts) preserves the
    old absorb/absorb_alerts behavior exactly (counters, timeline, trim);
  * the threat headline: `max_severity` is raised at the absorb funnel, so a
    trimmed feed cannot understate it and a schema-reject cannot fake it;
  * the timeline: buckets are UTC epoch seconds, the same instant the
    `window_start` fallback uses, on any host the wall runs on;
  * the per-class stats: session-wide counts the store owns, so neither a
    trimmed feed ring nor a capped wire can understate the tiles;
  * the broadcast contract: absorb()/absorb_alerts() return EXACTLY the
    alerts that reached the chain, schema-rejected ones are counted in
    `rejected` and shown nowhere, and `evidence()` says whether the feed
    is chained at all;
  * session reopen: the chain continues across restarts (its history is
    evidence, not scratch), primed dedup keeps old links off the wall,
    and DIODE_LIVE_RESET=1 archives db + ledger as a pair.
"""
from __future__ import annotations

import numpy as np

from src.alerts.drift import ChannelBaseline, DriftPolicy, FeatureBaseline
from src.alerts.live_store import LiveEvidenceStore
from src.alerts.store import AlertStore, ledger_path, verify_chain
from src.alerts.watch import SessionStore, WindowResult
from tests.alerts.test_alerts import make_alert


def _beacon_drift_policy() -> DriftPolicy:
    ref = np.random.default_rng(11).normal(0, 1, 5_000)
    return DriftPolicy(
        channels={"ml.beacon": ChannelBaseline(
            channel="ml.beacon",
            features={"dt_cv": FeatureBaseline.from_values(ref)},
            threshold=0.5,
        )},
        threshold=0.5, min_samples=100)


def _window(i: int, n: int = 3) -> WindowResult:
    """One closed window carrying n alerts, one minute apart from window i."""
    alerts = [make_alert(i * n + j, cls=("ddos", "scan", "exfil")[j % 3])
              for j in range(n)]
    return WindowResult(win_idx=i, window_start=i * 10.0, n_flows=50,
                        alerts=alerts, flows_per_sec=5.0, eval_ms=12.0,
                        capture_end=i * 10.0 + 10.0)


# --------------------------------------------------------------------------- #
# drift latch gates the channel before calibration
# --------------------------------------------------------------------------- #
def test_drift_alarm_withholds_that_channels_alerts(tmp_path):
    live = LiveEvidenceStore(path=tmp_path / "drift.db", calibration=None,
                             drift=_beacon_drift_policy())
    shifted = [{"dt_cv": 10.0} for _ in range(500)]
    rule = make_alert(2, cls="ddos")
    rule.detector = "ddos"
    shown = live.absorb_alerts(
        [make_alert(1, cls="beacon"), rule],
        [("ml.beacon", shifted)])
    assert [a.detector for a in shown] == ["ddos"]   # rules are never gated
    assert live.drift_abstained == 1
    ev = live.evidence()
    assert ev["drift"]["alarmed"] == ["ml.beacon"]
    assert ev["drift"]["readings"]["ml.beacon"]["alarm"] is True
    assert live.chain()["links"] == 1
    live.close()


def test_drift_latch_does_not_hide_a_healthy_channel(tmp_path):
    live = LiveEvidenceStore(path=tmp_path / "drift.db", calibration=None,
                             drift=_beacon_drift_policy())
    live.absorb_alerts([make_alert(1, cls="beacon")],
                       [("ml.beacon", [{"dt_cv": 10.0} for _ in range(500)])])
    again = live.absorb_alerts([make_alert(2, cls="beacon")],
                               [("ml.beacon", [{"dt_cv": 0.0}
                                               for _ in range(500)])])
    assert again == []                       # a good window does not clear it
    dga = live.absorb_alerts([make_alert(3, cls="dga")])
    assert len(dga) == 1 and dga[0].detector == "ml.dga"
    assert live.drift_abstained == 2
    live.close()


def test_too_few_rows_is_not_a_drift_alarm(tmp_path):
    live = LiveEvidenceStore(path=tmp_path / "drift.db", calibration=None,
                             drift=_beacon_drift_policy())
    shown = live.absorb_alerts([make_alert(1, cls="beacon")],
                               [("ml.beacon", [{"dt_cv": 10.0} for _ in range(2)])])
    assert len(shown) == 1
    assert live.drift_abstained == 0
    reading = live.evidence()["drift"]["readings"]["ml.beacon"]
    assert reading["evaluated"] is False and reading["alarm"] is False
    live.close()


# --------------------------------------------------------------------------- #
# chain tracks inserts in real time
# --------------------------------------------------------------------------- #
def test_chain_climbs_with_each_window(tmp_path):
    db = tmp_path / "live.db"
    live = LiveEvidenceStore(path=db)
    total = 0
    for i in range(5):
        w = _window(i, n=3)
        total += len(live.absorb(w))
        c = live.chain()
        assert c["available"] and c["links"] == total
    c = live.chain()
    assert c["head"]["link_no"] == 15
    # every stored alert is verifiable on the live-written db
    r = verify_chain(db)
    assert r["ok"] is True and r["links"] == 15
    live.close()


def test_chain_head_changes_between_windows(tmp_path):
    live = LiveEvidenceStore(path=tmp_path / "live.db")
    heads = []
    for i in range(3):
        live.absorb(_window(i))
        heads.append(live.chain()["head"]["chain_hash"])
    assert len(set(heads)) == 3          # head advanced every window
    live.close()


def test_verify_passes_on_live_written_db(tmp_path):
    db = tmp_path / "live.db"
    live = LiveEvidenceStore(path=db)
    for i in range(4):
        live.absorb(_window(i))
    live.absorb_alerts([make_alert(900, cls="beacon")])   # sidecar path too
    r = live.verify()
    assert r["ok"] is True and r["links"] == 13
    live.close()


# --------------------------------------------------------------------------- #
# chain-level idempotency
# --------------------------------------------------------------------------- #
def test_reabsorbing_same_alerts_adds_no_links(tmp_path):
    live = LiveEvidenceStore(path=tmp_path / "live.db")
    live.absorb(_window(0, n=5))
    head_before = live.chain()["head"]
    links_before = live.chain()["links"]

    # the same window absorbed again (server restart / client refresh race)
    w = _window(0, n=5)
    live.absorb(w)
    live.absorb_alerts(list(w.alerts))   # and again via the sidecar path

    c = live.chain()
    assert c["links"] == links_before
    assert c["head"] == head_before
    assert live.verify()["ok"] is True
    live.close()


def test_mixed_batch_chains_only_fresh_rows(tmp_path):
    """A batch of new + duplicate alerts must chain only the new ones."""
    db = tmp_path / "mixed.db"
    with AlertStore(db) as store:
        first = [make_alert(i) for i in range(4)]
        store.insert_many(first)
        assert store.chain_length() == 4
        # second batch: 2 duplicates of the first + 2 brand-new alerts
        second = [make_alert(0), make_alert(1), make_alert(10), make_alert(11)]
        ins, dup, _inv = store.insert_many(second)
        assert (ins, dup) == (2, 2)
        assert store.chain_length() == 6   # NOT 8
        r = verify_chain(db)
        assert r["ok"] is True and r["links"] == 6


# --------------------------------------------------------------------------- #
# roll-over survival + fresh sessions
# --------------------------------------------------------------------------- #
def test_chain_survives_ring_buffer_rollover(tmp_path):
    live = LiveEvidenceStore(path=tmp_path / "live.db", max_alerts=10)
    for i in range(8):
        live.absorb(_window(i, n=3))       # 24 alerts -> feed trims to 10
    assert len(live.alerts) == 10           # ring buffer trimmed
    c = live.chain()
    assert c["links"] == 24                 # chain kept everything
    assert live.verify()["ok"] is True
    live.close()


def test_session_reopen_continues_the_chain(tmp_path):
    """A restart must not destroy or reset the evidence it is supposed to keep.

    Wiping the db on launch made every demo start "clean", and made a chain
    deleted by hand indistinguishable from a chain that never existed."""
    db = tmp_path / "live.db"
    live = LiveEvidenceStore(path=db)
    live.absorb(_window(0, n=4))
    assert live.chain()["links"] == 4
    head_before = live.chain()["head"]["chain_hash"]
    live.close()

    live2 = LiveEvidenceStore(path=db)
    c = live2.chain()
    assert c["links"] == 4 and c["head"]["chain_hash"] == head_before
    # links continue where they stopped: link 5 hangs off link 4, not genesis
    live2.absorb(_window(9, n=2))
    c = live2.chain()
    assert c["links"] == 6 and c["head"]["link_no"] == 6
    assert live2.verify()["ok"] is True
    live2.close()


def test_reopened_session_does_not_rebroadcast_chained_history(tmp_path):
    """An alert already under custody must not reappear on the wall as new."""
    db = tmp_path / "live.db"
    live = LiveEvidenceStore(path=db)
    w = _window(0, n=4)
    live.absorb(w)
    live.close()

    live2 = LiveEvidenceStore(path=db)
    assert live2.absorb(w) == []          # same alerts, already linked
    assert live2.chain()["links"] == 4    # and no duplicate links either
    assert len(live2.alerts) == 0         # nothing re-rendered on the feed
    assert live2.suppressed == 4
    live2.close()


def test_reset_archives_db_and_ledger_together(tmp_path, monkeypatch):
    """DIODE_LIVE_RESET=1 is the only way to a zero link, and it keeps history."""
    db = tmp_path / "live.db"
    live = LiveEvidenceStore(path=db)
    live.absorb(_window(0, n=3))
    assert live.chain()["anchored"] is True
    live.close()
    before = ledger_path(db).read_text(encoding="utf-8")

    monkeypatch.setenv("DIODE_LIVE_RESET", "1")
    live2 = LiveEvidenceStore(path=db)
    assert live2.chain()["links"] == 0
    assert live2.chain()["anchored"] is False
    live2.absorb(_window(5, n=2))
    assert live2.chain()["head"]["link_no"] == 2   # a real fresh chain
    live2.close()

    # the previous session is moved aside, not deleted: both halves of the
    # pair survive, so its chain still verifies on its own
    old_db = next(iter(tmp_path.glob("live.*.db")))
    assert verify_chain(old_db)["ok"] is True
    archived_ledger = next(iter(tmp_path.glob("live.chain-ledger.*.ndjson")))
    assert len(archived_ledger.read_text(encoding="utf-8").splitlines()) == 3
    assert ledger_path(db).read_text(encoding="utf-8") != before


# --------------------------------------------------------------------------- #
# broadcast == chain (the wall may only show what the chain recorded)
# --------------------------------------------------------------------------- #
def test_absorb_returns_exactly_what_the_chain_recorded(tmp_path):
    db = tmp_path / "live.db"
    live = LiveEvidenceStore(path=db)
    shown = live.absorb(_window(0, n=5))
    with AlertStore(db) as store:
        chained = {a.alert_id for a in store.recent(limit=50)}
    assert {a.alert_id for a in shown} == chained
    assert live.chain()["links"] == len(shown)
    assert [a.alert_id for a in live.alerts] == [a.alert_id for a in shown]
    live.close()


def test_absorb_hides_what_the_schema_rejected(tmp_path):
    """A malformed alert must not reach a screen the chain never saw."""
    live = LiveEvidenceStore(path=tmp_path / "live.db")
    bad = make_alert(0, cls="ddos")
    bad.threat_class = "not_a_real_class"     # fails validate_alert
    bad.evidence = []
    good = make_alert(1, cls="scan")
    assert bad.severity == "critical" and good.severity == "high"
    shown = live.absorb_alerts([bad, good])
    assert [a.alert_id for a in shown] == [good.alert_id]
    assert live.rejected == 1
    assert live.chain()["rejected"] == 1
    assert live.chain()["links"] == 1
    assert [a.alert_id for a in live.alerts] == [good.alert_id]
    # the invisible critical must not colour the wall's headline either
    assert live.metrics()["max_severity"] == "high"
    assert live.verify()["ok"] is True
    live.close()


def test_evidence_reports_whether_the_feed_is_chained(tmp_path):
    live = LiveEvidenceStore(path=tmp_path / "live.db")
    assert live.evidence() == {
        "persisted": True, "rejected": 0, "abstained": 0,
        "calibration": {"available": False, "error": None},
        "drift": {"available": False, "error": None},
        "drift_abstained": 0, "error": None}
    live.absorb(_window(0, n=3))
    assert live.evidence()["persisted"] is True
    live.close()

    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir", encoding="utf-8")
    degraded = LiveEvidenceStore(path=blocker / "x.db")
    try:
        shown = degraded.absorb(_window(0, n=3))
        assert len(shown) == 3               # the feed still works
        ev = degraded.evidence()
        assert ev["persisted"] is False and ev["error"]
    finally:
        degraded.close()


# --------------------------------------------------------------------------- #
# degrade-to-ring-buffer
# --------------------------------------------------------------------------- #
def test_degrades_to_ring_buffer_on_bad_path(tmp_path, monkeypatch):
    # a path whose parent is a FILE poisons the open (mkdir fails)
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir", encoding="utf-8")
    live = LiveEvidenceStore(path=blocker / "x.db")
    try:
        assert live.degraded is True
        assert live.chain()["degraded"] is True
        assert live.chain()["error"]
        # the feed keeps working
        live.absorb(_window(0, n=3))
        assert len(live.alerts) == 3
        assert live.chain()["links"] == 0   # honest: no chain, not a fake
    finally:
        live.close()


def test_session_split_matches_old_absorb_behavior(tmp_path):
    """take_fresh/extend composition == absorb (counters, timeline, trim)."""
    alerts = [make_alert(i) for i in range(6)]
    w = _window(0)

    # path A: the classic absorb calls
    a = SessionStore(max_alerts=4)
    a.absorb(w)
    a.absorb(w)                     # duplicate absorb: windows/flows bump again
    a.absorb_alerts(list(alerts))

    # path B: the split API a persistent sidecar uses, composed in the order
    # absorb() composes it. Probing take_fresh out-of-band would count the
    # same firings a third time, so dedup is asserted on the feed instead.
    b = SessionStore(max_alerts=4)
    b.stats.add(w)
    b.extend(b.take_fresh(w.alerts), w.window_start)
    n = len(b.alerts)
    b.stats.add(w)
    b.extend(b.take_fresh(w.alerts), w.window_start)
    assert len(b.alerts) == n         # re-detections collapse, counters still bump
    b.extend_alerts(b.take_fresh(alerts))

    assert a.metrics() == b.metrics()
    assert [x.alert_id for x in a.alerts] == [x.alert_id for x in b.alerts]
    assert a.timeline == b.timeline


def test_threat_headline_outlives_the_feed_it_is_rendered_from():
    """`max_severity` is a property of the session, not of the visible feed.

    The wall ranked severities over the cards it could render, so as soon as
    the feed passed max_alerts (or the wire's FEED_CAP on a reload) a critical
    that had been trimmed away let the headline drop back to CALM. Absorb and
    metrics() are the one funnel both paths share, so the level is raised
    there and the trim cannot take it away.
    """
    store = SessionStore(max_alerts=2)
    store.absorb_alerts([make_alert(0, "scan", severity="medium")])
    assert store.metrics()["max_severity"] == "medium"
    store.absorb_alerts([make_alert(1, "ddos", severity="critical")])
    assert store.metrics()["max_severity"] == "critical"

    # two lesser alerts now push the critical out of the feed itself; the
    # headline must not follow it out
    store.absorb_alerts([make_alert(2, "scan", severity="low"),
                         make_alert(3, "scan", severity="medium")])
    assert [a.severity for a in store.alerts] == ["low", "medium"]
    assert store.metrics()["max_severity"] == "critical"


def test_a_redetected_threat_raises_the_headline_without_joining_the_feed():
    """The level tracks what the session absorbed, not only what it rendered.

    `prime_seen` lets a reopening dedup ids it already chained; when one of
    them fires again the wall collapses it to a re-detection, but the link is
    carrying a critical right now and CALM would be a lie about that."""
    store = SessionStore()
    store.prime_seen([make_alert(0, "ddos", severity="critical").alert_id])
    store.absorb_alerts([make_alert(0, "ddos", severity="critical")])
    m = store.metrics()
    assert m["alerts"] == 0 and m["alerts_suppressed"] == 1
    assert m["max_severity"] == "critical"


def test_timeline_buckets_are_utc_seconds_not_host_local():
    """`timeline` is keyed by epoch second, so the histogram has to mean the
    same instant on every host.

    Every timestamp the pipeline writes is naive UTC (`iso_at` emits
    "YYYY-MM-DDTHH:MM:SS" with no zone), and parsing one with
    `datetime.timestamp()` reads it as HOST-LOCAL: on this IST box every
    bucket landed 5h30m early, and hours away from the `window_start` bucket
    an alert with no timestamp of its own falls back to, which is also what
    killed the zero-filled quiet baseline the renderer builds between them.
    The store and the diode monitor already force naive -> UTC; the timeline
    now shares that one parser instead of a third private copy.

    Honest limit: the offset is zero on a UTC runner, so this can only fail
    on a machine like the one it was found on."""
    store = SessionStore()
    store.absorb_alerts([make_alert(1, "scan")])   # naive 2026-09-04T00:01:00
    assert store.timeline == {1_788_480_060: 1}

    # Same instant through the window path: the alert that has to fall back
    # to window_start must share the parsed alert's bucket, not sit 19800 s
    # away from it.
    no_ts = make_alert(2, "scan")
    no_ts.timestamp = ""
    w = WindowResult(win_idx=0, window_start=1_788_480_060.0, n_flows=5,
                     alerts=[make_alert(1, "ddos"), no_ts],
                     flows_per_sec=5.0, eval_ms=1.0)
    win_store = SessionStore()
    win_store.absorb(w)
    assert win_store.timeline == {1_788_480_060: 2}


def test_per_class_stats_are_the_session_not_the_rendered_feed():
    """The tiles and the radar count the session, so a capped wire cannot make
    the wall contradict its own headline.

    Both surfaces used to accumulate from the cards the browser had rendered.
    A reload ships only the newest FEED_CAP alerts and the feed ring trims to
    `max_alerts`, so a long capture re-rendered its class tiles from a slice of
    itself: the hero said 612 while the tiles summed to 400. The store owns the
    per-class numbers now, still only what joined the feed, because a
    re-detection is one alert, not two.
    """
    store = SessionStore(max_alerts=2)
    store.absorb_alerts([make_alert(0, "scan", severity="medium"),
                         make_alert(1, "ddos", severity="critical"),
                         make_alert(2, "scan", severity="low")])
    assert len(store.alerts) == 2                      # the ring trimmed
    assert store.class_stats["scan"]["count"] == 2     # the tile still says 2
    # the class line carries its worst sighting, with the technique that came
    # with it, so a lesser re-detection cannot soften the tile
    assert store.class_stats["scan"]["severity"] == "medium"
    assert store.class_stats["scan"]["attack"] == make_alert(0, "scan").attack_technique
    assert store.class_stats["ddos"]["severity"] == "critical"
    assert (sum(s["count"] for s in store.class_stats.values())
            == store.metrics()["alerts"])

    store.absorb_alerts([make_alert(2, "scan", severity="low")])   # re-detection
    assert store.class_stats["scan"]["count"] == 2


# --------------------------------------------------------------------------- #
# default path (shared DB_PATH contract)
# --------------------------------------------------------------------------- #
def test_db_path_env_override(monkeypatch, tmp_path):
    from src.alerts.live_store import db_path

    monkeypatch.setenv("DIODE_LIVE_DB", str(tmp_path / "custom.db"))
    assert db_path() == tmp_path / "custom.db"
    monkeypatch.delenv("DIODE_LIVE_DB")
    assert db_path().name == "live_session.db"
