"""SOC-ready alert schema, SQLite evidence store, and export tests.

Covered:
  * schema extensions — severity ladder, stable alert_id, flow 5-tuple,
    att&ck_techniques list form, legacy-dict reparse (alert_from_dict);
  * SQLite store — thousands of inserts error-free, idempotent re-insert,
    indexed recency/class/severity queries, time-window queries;
  * JSONL sink — write/ingest round-trip on the shared per-line contract;
  * STIX 2.1 export — structurally valid bundle, deterministic ids, IP and
    domain observables, sentinel fallback for unobservable alerts;
  * incident report — self-contained HTML with every evidence field rendered.
"""
from __future__ import annotations

import json

from src.alerts.export_stix import observable_of, stix_bundle, validate_bundle
from src.alerts.report import render_report_page, write_report
from src.alerts.schema import (
    ATTACK_MAP,
    CLASS_NAMES,
    SEVERITY_BY_CLASS,
    SEVERITY_ORDER,
    THREAT_LEVELS,
    Alert,
    EvidenceItem,
    alert_from_dict,
    alert_id_of,
    display_class,
    severity_for,
    threat_level,
    validate_alert,
)
from src.alerts.store import (
    AlertStore,
    ingest_jsonl,
    iso_to_epoch,
    iter_jsonl,
    write_jsonl,
)

BASE = "2026-09-04T00:00:00"


def make_alert(i: int, cls: str = "ddos", *, conf: float | None = None,
               key: str | None = None, **kw) -> Alert:
    """One evidence-rich alert, spread one minute apart."""
    conf = conf if conf is not None else (0.9 if cls in ("ddos", "scan") else 0.8)
    h, m = divmod(i, 60)
    ts = f"2026-09-04T{h:02d}:{m:02d}:00"
    return Alert(
        timestamp=ts,
        threat_class=cls,
        confidence=conf,
        evidence=[EvidenceItem(
            condition=f"{cls}_rate", operator=">=", observed=float(100 + i),
            threshold=50.0, description=f"{cls} signature fired", unit="count"),
            EvidenceItem("shape", "==", "observed", "expected",
                         "conjunctive shape held", "")],
        flow_id=f"f{i}", key=key or f"10.0.0.{i % 250}",
        detector=f"ml.{cls}", label=None, **kw)


# --------------------------------------------------------------------------- #
# schema extensions
# --------------------------------------------------------------------------- #
def test_severity_ladder_is_deterministic():
    assert severity_for("ddos", 0.5) == "high"       # base stays
    assert severity_for("ddos", 0.95) == "critical"  # confident escalates
    assert severity_for("scan", 0.5) == "medium"
    assert severity_for("scan", 0.9) == "high"
    assert severity_for("exfil", 0.5) == "critical"  # critical base never drops
    assert severity_for("martian", 0.99) == "medium"  # unknown classes default


def test_display_names_cover_the_whole_taxonomy():
    """One table owns the words both analyst surfaces render, keyed by exactly
    the classes the severity ladder can rank and the ATT&CK map can export — a
    class that reaches a report cannot arrive on screen without a name."""
    assert set(CLASS_NAMES) == set(SEVERITY_BY_CLASS) == set(ATTACK_MAP)
    assert display_class("scan") == "Recon Scan"
    assert display_class("tls_anomaly") == "TLS Anomaly"


def test_an_unlisted_class_keeps_its_own_words():
    """A friendly name invented for a class nobody named would put words in the
    detector's mouth, and a blank would hide that anything fired at all."""
    assert display_class("martian_probe") == "MARTIAN PROBE"
    assert display_class("") == "UNCLASSIFIED"
    assert display_class(None) == "UNCLASSIFIED"


def test_threat_level_words_cover_the_severity_ladder():
    """`SessionStore.max_severity` owns the worst severity; this owns the word
    both surfaces print for it, so the wall's hero and the dashboard headline
    cannot describe one session as ELEVATED and "high" at the same time."""
    assert set(THREAT_LEVELS) == set(SEVERITY_ORDER)
    assert threat_level(None) == "CALM"        # nothing has fired yet
    assert threat_level("medium") == "GUARDED"
    assert threat_level("critical") == "CRITICAL"
    # a severity outside the ladder is not talked down to CALM
    assert threat_level("apocalyptic") == "APOCALYPTIC"


def test_alert_derives_severity_id_and_techniques():
    a = make_alert(1, "ddos", conf=0.95)
    assert a.severity == "critical"
    assert a.alert_id and validate_alert(a) == []
    d = a.to_dict()
    assert d["att&ck_techniques"] == ["T1498"]
    assert d["severity"] == "critical" and "alert_id" in d


def test_flow_5tuple_roundtrips():
    a = make_alert(0, src_ip="192.168.1.7", dst_ip="93.184.216.34",
                   src_port=44123, dst_port=443, proto="tcp")
    d = a.to_dict()
    assert d["src_ip"] == "192.168.1.7" and d["dst_port"] == 443
    assert d["proto"] == "tcp"
    assert validate_alert(a) == []


def test_alert_id_stable_and_sensitive_to_payload():
    a1, a2 = make_alert(3, key="10.0.0.9"), make_alert(3, key="10.0.0.9")
    assert a1.alert_id == a2.alert_id == alert_id_of(a1)
    b = make_alert(3, key="10.0.0.10")
    assert b.alert_id != a1.alert_id


def test_validate_flags_bad_severity_id_and_ports():
    bad = make_alert(0, conf=0.95, severity="extreme", alert_id="not-a-uuid",
                     src_port=70000)
    problems = validate_alert(bad)
    assert any("severity" in p for p in problems)
    assert any("alert_id" in p for p in problems)
    assert any("src_port" in p for p in problems)


def test_alert_from_dict_accepts_legacy_records():
    legacy = {
        "timestamp": BASE, "flow_id": "x", "threat_class": "ddos",
        "confidence": 0.8, "detector": "ddos", "key": "10.0.0.5",
        "evidence": [{"condition": "volumetric_rate", "operator": ">=",
                      "observed": 200, "threshold": 50, "description": "flood",
                      "unit": "flows/s"}],
        # no src_ip/dst_ip/severity/alert_id/att&ck_techniques (old format)
    }
    a = alert_from_dict(legacy)
    assert a.src_ip is None and a.dst_ip is None
    assert a.severity == "high" and a.alert_id          # derived on rebuild
    assert a.evidence[0].observed == 200
    assert validate_alert(a) == []
    # full new-format dict round-trips losslessly through to_dict
    a2 = make_alert(2, src_ip="10.1.1.1", dst_ip="10.2.2.2", src_port=1111,
                    dst_port=53, proto="udp")
    rebuilt = alert_from_dict(a2.to_dict())
    assert rebuilt.to_dict() == a2.to_dict()


# --------------------------------------------------------------------------- #
# SQLite store
# --------------------------------------------------------------------------- #
def test_store_inserts_thousands_and_is_idempotent(tmp_path):
    alerts = [make_alert(i, cls=("ddos", "scan", "exfil")[i % 3])
              for i in range(5000)]
    db = tmp_path / "alerts.db"
    with AlertStore(db) as store:
        inserted, dup, invalid = store.insert_many(alerts)
        assert (inserted, dup, invalid) == (5000, 0, 0)
        assert store.count() == 5000
        # second pass: same detections, all duplicate (stable alert_id)
        assert store.insert_many(alerts) == (0, 5000, 0)
        assert store.count() == 5000


def test_store_rejects_invalid_alerts_without_failing(tmp_path):
    bad = [make_alert(i) for i in range(3)]
    bad.append(Alert(timestamp="", threat_class="martian", confidence=3.0,
                     evidence=[]))
    with AlertStore(tmp_path / "a.db") as store:
        inserted, _dup, invalid = store.insert_many(bad)
        assert inserted == 3 and invalid == 1
        assert store.count() == 3


def test_store_recent_order_filters_and_window_query(tmp_path):
    alerts = [make_alert(i, cls=("ddos", "ddos", "exfil")[i % 3],
                         conf=0.95 if i % 3 else 0.8)
              for i in range(120)]  # 2 hours, one alert per minute
    db = tmp_path / "a.db"
    with AlertStore(db) as store:
        store.insert_many(alerts)

        recent = store.recent(limit=10)
        stamps = [a.timestamp for a in recent]
        assert stamps == sorted(stamps, reverse=True)
        assert recent[0].timestamp == "2026-09-04T01:59:00"

        ddos = store.recent(limit=1000, threat_class="ddos")
        assert ddos and all(a.threat_class == "ddos" for a in ddos)

        crit = store.recent(limit=1000, severity="critical")
        assert crit and all(a.severity == "critical" for a in crit)
        # exfil conf 0.8 stays critical (base), ddos 0.8 stays high
        assert any(a.threat_class == "exfil" for a in crit)
        assert all(a.confidence >= 0.9 or a.threat_class == "exfil"
                   for a in crit)

        window = store.between("2026-09-04T00:30:00", "2026-09-04T01:30:00")
        assert len(window) == 61
        t = [a.timestamp for a in window]
        assert t == sorted(t)                       # chronological
        assert window[0].timestamp == "2026-09-04T00:30:00"

        by_id = store.get(window[5].alert_id)
        assert by_id and by_id.evidence == window[5].evidence


def test_store_stats_and_epoch_parsing():
    assert iso_to_epoch("1970-01-01T00:00:00") == 0.0
    assert iso_to_epoch("1970-01-01T00:00:00Z") == 0.0
    assert iso_to_epoch("2026-09-04T00:00:00") > 1_700_000_000
    assert iso_to_epoch("not-a-date") == 0.0
    assert iso_to_epoch(None) == 0.0


# --------------------------------------------------------------------------- #
# JSONL round-trip
# --------------------------------------------------------------------------- #
def test_jsonl_roundtrip_into_store(tmp_path):
    alerts = [make_alert(i, cls=("ddos", "scan", "exfil")[i % 3])
              for i in range(300)]
    path = tmp_path / "alerts.ndjson"
    assert write_jsonl(alerts, path) == 300
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l]
    assert len(lines) == 300
    d = json.loads(lines[0])
    assert d["att&ck_techniques"] == [d["attack_technique"]]
    assert d["severity"] in ("critical", "high", "medium", "low")

    db = tmp_path / "a.db"
    with AlertStore(db) as store:
        assert ingest_jsonl(path, store) == (300, 0, 0)
        assert store.count() == 300
        assert store.recent(1)[0].to_dict() == alerts[-1].to_dict()


def test_iter_jsonl_accepts_single_json_array(tmp_path):
    # tolerance for producers that wrote one top-level JSON array
    alerts = [make_alert(i, cls="ddos") for i in range(5)]
    p = tmp_path / "array.json"
    p.write_text(json.dumps([a.to_dict() for a in alerts]), encoding="utf-8")
    got = list(iter_jsonl(p))
    assert len(got) == 5 and got[0]["threat_class"] == "ddos"


# --------------------------------------------------------------------------- #
# STIX 2.1 export
# --------------------------------------------------------------------------- #
def test_stix_bundle_for_ip_and_domain_alerts(tmp_path):
    ddos = make_alert(0, "ddos", conf=0.95, key=None,
                      src_ip="10.1.0.3", dst_ip="203.0.113.9",
                      src_port=40000, dst_port=80, proto="tcp")
    dga = make_alert(1, "dga", key="a1b2c3d4.example.com")
    beacon = Alert(timestamp="2026-09-04T00:02:00", threat_class="beacon",
                   confidence=0.7, detector="ml.beacon",
                   key="192.168.1.9->198.51.100.44:443",
                   evidence=[EvidenceItem("periodicity", ">=", 0.92, 0.8,
                                          "peaks at 60s", "score")])
    alerts = [ddos, dga, beacon]

    b1 = stix_bundle(alerts)
    problems = validate_bundle(b1)
    assert problems == []
    objs = b1["objects"]
    types = {o["type"] for o in objs}
    assert {"identity", "indicator", "observed-data", "attack-pattern",
            "ipv4-addr", "domain-name"} <= types
    inds = [o for o in objs if o["type"] == "indicator"]
    assert len(inds) == 3
    for ind, a in zip(inds, alerts):
        assert a.alert_id in ind["description"] or a.detector in ind["description"]
        assert ind["pattern"] and ind["pattern"].startswith("[")
        # the 2.1 required properties, plus severity kept where a label used to be
        assert ind["pattern_type"] == "stix" and ind["pattern_version"] == "2.1"
        assert a.threat_class in ind["indicator_types"]
        assert a.severity in ind["description"]
        assert ind["created_by_ref"] == next(
            o["id"] for o in objs if o["type"] == "identity")
        assert "labels" not in ind and "kill_chain_phases" not in ind
    # IP observable pattern present for the endpoint alert
    ddos_ind = next(o for o in inds if o["name"].startswith("ddos"))
    assert "203.0.113.9" in ddos_ind["pattern"]
    # 2.1 observations REFERENCE first-class observables; they do not embed a map
    obs = [o for o in objs if o["type"] == "observed-data"]
    assert len(obs) == 3
    assert all(o["object_refs"] and "objects" not in o for o in obs)
    scos = {o["id"]: o for o in objs
            if o["type"] in ("ipv4-addr", "ipv6-addr", "domain-name")}
    assert all(r in scos for o in obs for r in o["object_refs"])
    assert [s["value"] for s in scos.values() if s["type"] == "domain-name"] == \
        ["a1b2c3d4.example.com"]
    # the beacon key became its dst address, not the "src->dst:port" string
    assert "198.51.100.44" in {s["value"] for s in scos.values()}
    assert all("spec_version" not in s and "created" not in s for s in scos.values())
    # deterministic ids: same input -> identical bundle
    assert json.dumps(b1, sort_keys=True) == \
        json.dumps(stix_bundle(alerts), sort_keys=True)

    # file output path works too
    out = tmp_path / "bundle.json"
    from src.alerts.export_stix import write_stix
    _, problems = write_stix(alerts, out)
    assert problems == []
    assert json.loads(out.read_text(encoding="utf-8"))["type"] == "bundle"


def test_write_stix_refuses_to_put_an_invalid_bundle_on_disk(tmp_path, monkeypatch):
    """The exporter is correct, so nothing natural produces problems — the
    guarantee has to be tested by handing `write_stix` a broken bundle. An
    un-ingestible file in the export directory is worse than no file: the
    dashboard and CLI both report success from the return value alone.
    """
    from src.alerts import export_stix
    monkeypatch.setattr(
        export_stix, "stix_bundle",
        lambda alerts: {"type": "bundle", "id": "not-a-stix-id", "objects": []})
    out = tmp_path / "nested" / "bad.json"
    _, problems = export_stix.write_stix([make_alert(0)], out)
    assert problems and not out.exists()


def test_indicator_types_answer_in_the_vocabulary_consumers_filter_on():
    """2.1 closes indicator_types to recommended terms; a bare threat-class name
    is legal (open vocabulary) but invisible to a consumer that filters on
    "malicious-activity". The assertion level already exists in `severity`,
    which the ladder derives from class + confidence, so it maps from there.
    """
    for sev, term in {"critical": "malicious-activity",
                      "high": "malicious-activity",
                      "medium": "suspicious-activity",
                      "low": "anomalous-activity"}.items():
        a = make_alert(0, "scan")
        a.severity = sev
        ind = next(o for o in stix_bundle([a])["objects"]
                   if o["type"] == "indicator")
        assert ind["indicator_types"] == [term, "scan"], sev


def test_validate_bundle_rejects_the_shape_this_exporter_used_to_emit():
    """Every defect the first version shipped, asserted one by one.

    Before this fix the exporter emitted bare-UUID ids, a `spec_version` on the
    Bundle, indicator `labels` + `kill_chain_phases` with no `pattern_type`, and
    observations carrying a 2.0 `objects` map — JSON that no TAXII server, SIEM
    or stix2 parser accepts — and `validate_bundle()` returned no problems for
    all of it. Mutating real output back into that shape has to fail loudly.
    """
    real = stix_bundle([make_alert(0, "ddos", src_ip="10.1.0.3",
                                   dst_ip="203.0.113.9")])
    assert validate_bundle(real) == []
    stale = json.loads(json.dumps(real))
    stale["spec_version"] = "2.1"
    stale["id"] = stale["id"].split("--", 1)[1]
    for o in stale["objects"]:
        o["id"] = o["id"].split("--", 1)[1]
        if o["type"] == "indicator":
            o["labels"] = ["threat-class:ddos", "severity:high"]
            o["kill_chain_phases"] = [{"kill_chain_name": "mitre-attack",
                                       "phase_name": "impact"}]
            del o["pattern_type"], o["indicator_types"]
        if o["type"] == "observed-data":
            o["objects"] = {"0": {"type": "ipv4-addr", "value": "203.0.113.9"}}
            del o["object_refs"]
    problems = "\n".join(validate_bundle(stale))
    for expected in ("is not 'bundle--<uuid>'",
                     "Bundle carries spec_version",
                     "is not '<type>--<uuid>'",
                     "pattern_type != stix",
                     "missing indicator_types",
                     "2.0-only labels",
                     "2.0-only kill_chain_phases",
                     "uses the 2.0 objects map",
                     "missing object_refs",
                     "dangling created_by_ref"):
        assert expected in problems, f"validator misses: {expected}"


def test_observable_of_prefers_endpoints_then_key():
    ip_a = make_alert(0, src_ip="10.0.0.1", dst_ip="93.184.216.34", key="zz")
    assert observable_of(ip_a) == ("ipv4-addr", "93.184.216.34")
    dom = make_alert(1, "dga", key="x.yz.com")
    assert observable_of(dom) == ("domain-name", "x.yz.com")
    beacon_v6 = make_alert(2, "beacon", key="10.0.0.1->[2001:db8::5]:443")
    assert observable_of(beacon_v6) == ("ipv6-addr", "2001:db8::5")
    beacon_v4 = make_alert(3, "beacon", key="10.0.0.1->93.184.216.34:443")
    assert observable_of(beacon_v4) == ("ipv4-addr", "93.184.216.34")
    none_a = Alert(timestamp=BASE, threat_class="scan", confidence=0.6,
                   detector="scan", evidence=[EvidenceItem("c", ">", 1, 0)])
    assert observable_of(none_a) is None
    # ...and such an alert still exports (sentinel pattern, no observable)
    b = stix_bundle([none_a])
    assert validate_bundle(b) == []
    ind = next(o for o in b["objects"] if o["type"] == "indicator")
    assert ind["pattern"] and "0.0.0.0" in ind["pattern"]
    assert not [o for o in b["objects"] if o["type"] == "observed-data"]


# --------------------------------------------------------------------------- #
# incident report
# --------------------------------------------------------------------------- #
def test_incident_report_renders_evidence_fields(tmp_path):
    alerts = [make_alert(i, cls=("ddos", "scan", "exfil")[i % 3])
              for i in range(12)]
    alerts[0].src_ip, alerts[0].dst_ip = "10.1.0.3", "203.0.113.9"
    out = write_report(alerts, tmp_path / "incident.html",
                       title="Shift review")
    text = out.read_text(encoding="utf-8")
    assert out.exists() and text.count("<div class=\"alert\">") == 12
    assert "Shift review" in text
    for cond in ("ddos_rate", "scan_rate", "exfil_rate", "shape"):
        assert cond in text
    for tok in ("T1498", "T1046", "T1048", "critical", "high",
                "observed", "threshold", "10.1.0.3", "203.0.113.9"):
        assert tok in text


def test_single_alert_report_prints_one_time_not_a_degenerate_range(tmp_path):
    """The wall's report route exports exactly one alert per `alert_id`, and the
    header rendered its range as `X — X`, which reads as a corrupt record on the
    page a judge prints.
    """
    one = make_alert(3)
    text = write_report([one], tmp_path / "one.html").read_text(encoding="utf-8")
    assert "window: 2026-09-04T00:03:00" in text
    assert " — 2026-09-04T00:03:00" not in text
    pair = write_report([one, make_alert(4)], tmp_path / "pair.html") \
        .read_text(encoding="utf-8")
    assert "window: 2026-09-04T00:03:00 — 2026-09-04T00:04:00" in pair


def test_report_escapes_wire_controlled_fields(tmp_path):
    """Fields that originate on the wire are attacker-chosen text.

    The incident report is opened by an analyst in a browser, so an IP,
    entity or description lifted off the link must never be emitted raw.
    """
    payload = '<img src=x onerror="alert(1)">'
    a = make_alert(0)
    a.src_ip = payload
    a.key = payload
    a.flow_id = payload
    a.timestamp = payload
    a.evidence = [EvidenceItem(condition=payload, operator="=", observed=1.0,
                               threshold=2.0, description=payload, unit="")]
    text = write_report([a], tmp_path / "x.html").read_text(encoding="utf-8")
    assert "<img src=x" not in text
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in text
    assert "<script" not in text.lower()


def test_triage_verdict_survives_both_report_renderers(tmp_path):
    """The exported file and the in-site page must agree on the advisory.

    Both read the verdict through one table of the engine's own envelope
    keys, so a key the engine does not emit prints nothing rather than a
    placeholder an analyst would misread as a real disposition.
    """
    a = make_alert(0)
    a.triage = {"recommended": "escalate", "urgency": 2.0,
                "p_false_positive": 0.42, "corroborates_class": 0.88,
                "requires_human_review": True}
    summary = ("disposition escalate · urgency 2.0 · "
               "P(false-positive) 0.42")
    exported = write_report([a], tmp_path / "t.html").read_text(encoding="utf-8")
    for text in (exported, render_report_page([a])):
        assert summary in text
        assert "NEVER MUTATES THE DETECTION" in text

    # a verdict with no urgency prints no urgency field at all
    thin = make_alert(1)
    thin.triage = {"recommended": "watch", "p_false_positive": 0.1}
    partial = "disposition watch · P(false-positive) 0.1"
    exported_thin = write_report([thin], tmp_path / "thin.html").read_text(encoding="utf-8")
    assert partial in exported_thin and partial in render_report_page([thin])


def test_five_tuple_omits_endpoints_that_were_never_observed(tmp_path):
    """Fan-in and sweep alerts key on one endpoint; the other is absent.

    Rendering the missing side as empty octets (`: → 10.9.9.9: ()`) made a
    correct detection look like a corrupt record on a judge-facing page.
    """
    fan_in = make_alert(0, dst_ip="10.9.9.9")
    both = make_alert(1, src_ip="10.1.0.3", src_port=51234,
                      dst_ip="203.0.113.9", dst_port=443, proto="TCP")
    alerts = [fan_in, both]
    for text in (write_report(alerts, tmp_path / "f.html")
                 .read_text(encoding="utf-8"), render_report_page(alerts)):
        assert "dst 10.9.9.9" in text
        assert "10.1.0.3:51234 → 203.0.113.9:443 (TCP)" in text
        assert ": →" not in text and ": (" not in text


def test_both_report_renderers_label_alerts_the_way_the_wall_does(tmp_path):
    """CLASS_NAMES owns the words a judge reads, but both renderers passed the
    detector's own identifier straight through: the feed and the wall said
    "Recon Scan" while the PDF printed from the same alert said "scan", and the
    in-site card head said "SCAN". A label the report invents for itself is a
    label nobody maintains.
    """
    classes = ("ddos", "scan", "exfil", "beacon")
    alerts = [make_alert(i, cls=c) for i, c in enumerate(classes)]
    alerts.append(make_alert(9, cls=""))
    for text in (write_report(alerts, tmp_path / "names.html")
                 .read_text(encoding="utf-8"),
                 render_report_page(alerts)):
        for cls in classes:
            assert CLASS_NAMES[cls] in text
            # the raw id may remain in machine fields, never as a label
            assert f"<td>{cls}</td>" not in text
        assert "Alert beacon" not in text and ">BEACON<" not in text
        assert "UNCLASSIFIED" in text          # a blank class is named, not blank
        assert "+00:00 UTC" not in text        # prints `generated … UTC`, once


def test_empty_report_and_cli_smoke(tmp_path):
    out = write_report([], tmp_path / "empty.html")
    assert "No alerts in the selected range" in \
        out.read_text(encoding="utf-8")

    from src.alerts.cli import main
    nd = tmp_path / "in.ndjson"
    write_jsonl([make_alert(i) for i in range(40)], nd)
    db = tmp_path / "cli.db"
    assert main(["store", "--alerts", str(nd), "--db", str(db)]) == 0
    assert main(["stats", "--db", str(db)]) == 0
    assert main(["recent", "--db", str(db), "--limit", "3",
                 "--class", "ddos"]) == 0
    rep = tmp_path / "cli.html"
    assert main(["report", "--db", str(db), "--window-start", BASE,
                 "--window-end", "2026-09-04T01:00:00",
                 "--out", str(rep)]) == 0
    assert rep.exists()
    stix = tmp_path / "cli.json"
    assert main(["stix", "--alerts", str(nd), "--out", str(stix)]) == 0
    assert json.loads(stix.read_text(encoding="utf-8"))["type"] == "bundle"


def test_triage_round_trips_through_the_store_without_touching_the_chain(
        tmp_path):
    """`triage_store counts` was documented as the way to inspect stored
    verdicts, and nothing in the pipeline ever wrote that table; a batch report
    also lost the advisory line the Live tab shows. Both ends are wired now.

    The verdict stays annotation: the chain over the same rows still verifies,
    because re-triaging with a newer model must never re-hash detection history.
    """
    from src.alerts.cli import main
    from src.alerts.store import verify_chain
    from src.alerts.triage_store import (
        TriageStore,
        join_verdicts,
        record_verdicts,
    )

    alerts = [make_alert(0, "scan"), make_alert(1, "exfil")]
    alerts[0].triage = {"recommended": "escalate", "urgency": 2.0,
                        "corroborates_class": 0.9, "p_false_positive": 0.05}
    nd = tmp_path / "triaged.ndjson"
    write_jsonl(alerts, nd)
    db = tmp_path / "triage.db"
    assert main(["store", "--alerts", str(nd), "--db", str(db)]) == 0

    ts = TriageStore(db)
    assert ts.counts() == {"escalate": 1}
    assert ts.get(alerts[0].alert_id)["verdict"]["urgency"] == 2.0
    assert ts.recent(10)[0]["disposition"] == "escalate"
    ts.close()
    assert verify_chain(db)["ok"] is True

    rep = tmp_path / "triage.html"
    assert main(["report", "--db", str(db), "--out", str(rep)]) == 0
    html = rep.read_text(encoding="utf-8")
    assert html.count("TRIAGE") == 1          # the verdict's alert, not both
    assert "escalate" in html

    # neither end invents an evidence db: :8501 persists only into a chained
    # session that already exists, so a report reader is never shown a db whose
    # only contents are verdicts for detections nobody recorded.
    absent = tmp_path / "no_session.db"
    assert record_verdicts(alerts, absent) == 0
    solo = make_alert(5, "ddos")
    assert join_verdicts([solo], absent)[0].triage is None
    assert not absent.exists()
