"""Dashboard pack-source registry: contract + replay sanity."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from src.alerts.pack import PACK_DIR, available_sources, ensure_pack
from src.detectors.rules import run_rules
from src.ingest.pcap_reader import stream_flows

REPO = Path(__file__).resolve().parents[2]


def test_sources_match_manifest():
    man = json.loads((PACK_DIR / "pack_manifest.json").read_text())
    items = {item["pcap"]: item for item in man["pack"]}
    sources = ensure_pack()
    assert [s.key for s in sources] == ["01_ddos", "02_c2_beacon",
                                        "03_dga_tunnel", "04_exfil_scan",
                                        "05_slowloris", "06_exfil_ratio"]
    for s in sources:
        item = items[f"{s.key}.pcap"]
        assert s.pcap.exists()
        assert tuple(item["expected"].get("rule_expected") or ()) \
            == s.rule_expected
        assert s.story and s.label and s.detector_note


def test_available_sources_only_lists_existing_pcaps(tmp_path, monkeypatch):
    """A missing pcap drops that source instead of breaking the sidebar."""
    import src.alerts.pack as pack_mod

    monkeypatch.setattr(pack_mod, "PACK_DIR", tmp_path)
    assert pack_mod.available_sources() == []
    (tmp_path / "01_ddos.pcap").write_bytes(b"stub")
    avail = pack_mod.available_sources()
    assert [s.key for s in avail] == ["01_ddos"]


def test_every_rule_scenario_replays_and_fires():
    """Pack sources with rule expectations fire them; benign windows stay quiet."""
    for src in available_sources():
        flows = sorted(stream_flows(src.pcap), key=lambda r: r["ts_epoch"])
        alerts = run_rules(pd.DataFrame(flows), window_s=10)
        if src.rule_expected:
            got = {a.threat_class for a in alerts}
            assert set(src.rule_expected) <= got, f"{src.key}: {got}"
            assert all(a.label is None for a in alerts)
        else:
            # ML-channel scenarios: windowed rule replay stays silent
            assert alerts == [], f"{src.key} fired rules: {[a.threat_class for a in alerts]}"


def test_ml_scenarios_fire_in_their_channels():
    """Beacon + DGA detections come from the sidecar channels (the honest path)."""
    from src.detectors.ml import beacon as beacon_mod
    from src.detectors.ml.dga import DgaModel

    models = REPO / "models"
    flows = beacon_mod.load_ctu(PACK_DIR / "02_c2_beacon_netflow.csv")
    pairs = beacon_mod.pair_series(flows)
    bm = beacon_mod.BeaconModel.load(models)
    scores = bm.predict_score(pairs)
    assert any(src == "10.30.0.9" and sc >= bm.threshold
               for src, sc in zip(pairs["src_ip"], scores))

    dm = DgaModel.load(models)
    doms = pd.Series([l.strip() for l in
                      (PACK_DIR / "03_dga_domains.txt").read_text().splitlines()
                      if l.strip()])
    assert bool((dm.score_domains(doms) >= dm.threshold).all())


def test_ml_channel_alerts_and_progressive_release():
    """Sidecar scoring yields alerts; MlChannelReplay releases them in order."""
    from src.alerts.pack import MlChannelReplay, ml_channel_alerts, pd_ts_to_epoch

    # rule scenarios have no ML channel
    assert ml_channel_alerts("01_ddos") == []
    assert ml_channel_alerts("04_exfil_scan") == []
    assert ml_channel_alerts("05_slowloris") == []
    assert ml_channel_alerts("06_exfil_ratio") == []

    # beacon: one model-fired alert, timestamped at the C2 contact
    beacon = ml_channel_alerts("02_c2_beacon")
    assert len(beacon) == 1
    b = beacon[0]
    assert b.threat_class == "beacon" and b.detector == "ml.beacon"
    assert b.confidence >= 0.9
    assert b.timestamp  # release time known

    # dga: all 46 tunnel domains flagged, back-timed from the pcap queries
    dga = ml_channel_alerts("03_dga_tunnel")
    assert len(dga) == 46
    assert all(a.threat_class == "dga" for a in dga)
    assert all(a.timestamp for a in dga)
    ts = [pd_ts_to_epoch(a.timestamp) for a in dga]
    assert ts == sorted(ts)

    # progressive release: nothing before the first ts, monotonic drain
    r = MlChannelReplay.for_scenario("03_dga_tunnel")
    assert r.total == 46
    assert r.due(ts[0] - 1) == []
    first = r.due(ts[0])
    assert len(first) >= 1
    got = [a.alert_id for a in first]
    got += [a.alert_id for a in r.due(ts[-1])]
    assert len(got) == 46 and len(set(got)) == 46
    assert r.due(ts[-1] + 60) == []  # cursor exhausted


def test_ml_alerts_join_the_live_feed_end_to_end():
    """Full replay loop: ML alerts land in the SessionStore alongside rules."""
    from src.alerts.pack import MlChannelReplay
    from src.alerts.watch import SessionStore, replay_flows
    from src.detectors.rules import make_rules
    from src.ingest.pcap_reader import stream_flows

    for src in available_sources():
        if src.rule_expected:
            continue
        flows = sorted(stream_flows(src.pcap), key=lambda r: r["ts_epoch"])
        store = SessionStore()
        ml = MlChannelReplay.for_scenario(src.key)
        for w in replay_flows(flows, window_s=10, rules=make_rules()):
            store.absorb(w)
            due = (ml.due(w.capture_end)
                   if w.capture_end is not None else ml.drain_all())
            store.absorb_alerts(due)
        store.absorb_alerts(ml.drain_all())
        assert store.stats.windows > 0
        expected = {"02_c2_beacon": 1, "03_dga_tunnel": 46}[src.key]
        got = [a for a in store.alerts if a.threat_class in ("beacon", "dga")]
        assert len(got) == expected, f"{src.key}: {len(got)} != {expected}"
        # no rule alerts on ML scenarios -> the stats counter matches the feed
        assert store.stats.alerts == expected
        # every ML alert kept its capture timestamp -> timeline populated
        assert store.timeline
