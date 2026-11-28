"""OCSF 1.10.0 Detection Finding export tests.

The exporter is stdlib-only and deterministic, so these tests pin the mapping
and the refusal boundary: a correct alert becomes a clean event, and a broken
event never reaches disk.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime, timezone

import pytest

from src.alerts.export_ocsf import (
    OCSF_VERSION,
    ocsf_event,
    validate_event,
    validate_events,
    write_ocsf,
)
from src.alerts.schema import Alert, EvidenceItem


def make_ddos() -> Alert:
    return Alert(
        timestamp="2026-09-04T00:02:00",
        threat_class="ddos",
        confidence=0.95,
        evidence=[EvidenceItem("flows_per_sec", ">=", 695.4, 500.0,
                               "695.4 flows/sec to one dst", "flows/s")],
        flow_id="f1", src_ip="10.1.0.3", dst_ip="203.0.113.9",
        src_port=40000, dst_port=80, proto="tcp",
        window_start="2026-09-04T00:01:50",
        window_end="2026-09-04T00:02:00",
        key="203.0.113.9", detector="ddos",
    )


def make_dga() -> Alert:
    return Alert(
        timestamp="2026-09-04T00:03:00",
        threat_class="dga",
        confidence=0.8,
        evidence=[EvidenceItem("entropy", ">=", 4.2, 3.8,
                               "high entropy domain", "bits")],
        key="a1b2c3d4.example.com", detector="ml.dga",
    )


def _epoch(ts: str) -> int:
    return int(datetime.fromisoformat(ts).replace(
        tzinfo=timezone.utc).timestamp() * 1000)


def test_ddos_alert_maps_to_detection_finding_create():
    a = make_ddos()
    event = ocsf_event(a)

    assert validate_event(event) == []
    assert (event["class_uid"], event["category_uid"],
            event["activity_id"], event["type_uid"]) == (2004, 2, 1, 200401)
    assert (event["class_name"], event["category_name"],
            event["activity_name"]) == ("Detection Finding", "Findings", "Create")
    assert (event["severity_id"], event["severity"]) == (5, "Critical")
    assert (event["confidence_id"], event["confidence"],
            event["confidence_score"]) == (3, "High", 95)
    assert event["is_alert"] is True
    assert (event["status_id"], event["status"]) == (1, "New")
    assert event["time"] == _epoch(a.timestamp)
    assert event["finding_info"]["created_time"] == event["time"]
    assert event["finding_info"]["uid"] == a.alert_id
    assert (event["metadata"]["uid"] == event["metadata"]["correlation_uid"]
            == a.alert_id)
    assert event["metadata"]["version"] == OCSF_VERSION == "1.10.0"
    assert event["metadata"]["product"]["name"] == "DiodeWatch"
    assert event["metadata"]["original_time"] == "2026-09-04T00:02:00.000Z"

    attack = event["finding_info"]["attacks"][0]
    assert attack["tactic"] == {"name": "Impact"}
    assert attack["technique"] == {"uid": "T1498",
                                   "name": "Network Denial of Service"}
    assert event["finding_info"]["analytic"]["type_id"] == 1

    ev = event["evidences"][0]
    assert ev["uid"] == a.alert_id and ev["name"] == "ddos"
    assert ev["src_endpoint"] == {"ip": "10.1.0.3", "port": 40000}
    assert ev["dst_endpoint"] == {"ip": "203.0.113.9", "port": 80}
    assert ev["data"]["evidence"][0]["condition"] == "flows_per_sec"
    assert "query" not in ev

    assert event["observables"] == [
        {"name": "evidences[0].src_endpoint.ip", "type": "IP Address",
         "type_id": 2, "value": "10.1.0.3"},
        {"name": "evidences[0].dst_endpoint.ip", "type": "IP Address",
         "type_id": 2, "value": "203.0.113.9"},
    ]
    assert json.loads(json.dumps(event)) == event
    assert ocsf_event(a) == event


def test_dga_alert_uses_dns_query_and_ml_analytic():
    a = make_dga()
    event = ocsf_event(a)

    assert validate_event(event) == []
    assert event["finding_info"]["analytic"]["type_id"] == 4
    assert event["evidences"][0]["query"] == {
        "hostname": "a1b2c3d4.example.com"}
    assert event["observables"] == [{
        "name": "evidences[0].query.hostname", "type": "Hostname",
        "type_id": 1, "value": "a1b2c3d4.example.com"}]
    # A dotted ATT&CK id is split the way OCSF models it.
    attack = event["finding_info"]["attacks"][0]
    assert attack["technique"]["uid"] == "T1568"
    assert attack["sub_technique"] == {
        "uid": "T1568.002", "name": "Domain Generation Algorithms"}
    assert "src_endpoint" not in event["evidences"][0]
    assert "dst_endpoint" not in event["evidences"][0]


def test_non_dns_domain_key_is_not_fabricated_as_a_query():
    a = Alert(timestamp="2026-09-04T00:04:00", threat_class="beacon",
              confidence=0.7, detector="ml.beacon",
              key="a1b2c3d4.example.com",
              evidence=[EvidenceItem("periodicity", ">=", 0.92, 0.8,
                                     "peaks at 60s", "score")])
    event = ocsf_event(a)

    assert validate_event(event) == []
    assert "query" not in event["evidences"][0]
    assert "observables" not in event
    assert event["evidences"][0]["data"]["key"] == "a1b2c3d4.example.com"


def test_dns_key_that_is_an_ip_is_not_emitted_as_a_hostname():
    a = make_dga()
    a.key = "10.9.0.4"
    event = ocsf_event(a)

    assert validate_event(event) == []
    assert "query" not in event["evidences"][0]
    assert "observables" not in event
    assert event["evidences"][0]["data"]["key"] == "10.9.0.4"


def test_alert_without_a_detector_does_not_emit_null():
    a = Alert(timestamp="2026-09-04T00:05:00", threat_class="scan",
              confidence=0.5, detector=None,
              evidence=[EvidenceItem("fanout", ">=", 30, 20, "one source", "hosts")])
    event = ocsf_event(a)

    assert validate_event(event) == []
    assert "detector" not in event["evidences"][0]["data"]
    assert event["finding_info"]["analytic"]["uid"] == "diodewatch.unknown"


def test_write_ocsf_is_deterministic_jsonl_and_refuses_bad_events(tmp_path):
    a, b = make_ddos(), make_dga()
    out = tmp_path / "findings.jsonl"
    events, problems = write_ocsf([a, b], out)
    assert problems == [] and len(events) == 2
    raw = out.read_bytes()
    assert b"\r\n" not in raw and raw.endswith(b"\n")
    lines = raw.decode("utf-8").splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["finding_info"]["uid"] for line in lines] == [
        a.alert_id, b.alert_id]
    assert validate_events([json.loads(line) for line in lines]) == []
    assert write_ocsf([a, b], out)[1] == []
    assert out.read_bytes() == raw

    bad = Alert(timestamp="not-a-timestamp", threat_class="scan",
                confidence=0.5, evidence=[EvidenceItem("x", ">", 1, 0)])
    missing = tmp_path / "bad.jsonl"
    _, problems = write_ocsf([bad], missing)
    assert problems and not missing.exists()

    # A failed export must not truncate or replace an earlier good stream.
    _, problems = write_ocsf([bad], out)
    assert problems and out.read_bytes() == raw
    assert not list(tmp_path.glob(".*.tmp"))

    empty = tmp_path / "empty.jsonl"
    _, problems = write_ocsf([], empty)
    assert problems == ["no OCSF events to export"]
    assert not empty.exists()


@pytest.mark.parametrize("mutate", [
    lambda e: e.update(type_uid=200402),
    lambda e: e["finding_info"].update(uid=""),
    lambda e: e["finding_info"]["analytic"].update(type_id=12),
    lambda e: e["finding_info"].pop("created_time"),
    lambda e: e["finding_info"]["attacks"][0]["technique"].update(uid="1498"),
    lambda e: e["evidences"][0].update(query={"hostname": "10.9.0.4"}),
    lambda e: e["evidences"][0]["src_endpoint"].update(ip="not-an-ip"),
    lambda e: e["evidences"][0]["src_endpoint"].update(port=70000),
    lambda e: e.update(severity_id=4),                 # label says Critical
    lambda e: e["metadata"].update(version="1.9.0"),
    lambda e: e.pop("time"),
    lambda e: e["observables"][0].update(value="203.0.113.99"),
    lambda e: e["observables"][0].update(name="evidences[0].dst_endpoint.ip"),
    lambda e: e["evidences"][0]["data"].update(extra=None),
])
def test_validator_rejects_broken_event(mutate):
    event = copy.deepcopy(ocsf_event(make_ddos()))
    mutate(event)
    assert validate_event(event), event


def test_validator_rejects_duplicate_observable():
    event = copy.deepcopy(ocsf_event(make_ddos()))
    event["observables"].append(copy.deepcopy(event["observables"][0]))
    assert any("duplicates" in p for p in validate_event(event))


def test_cli_exports_ocsf_and_returns_two_on_invalid(tmp_path):
    from src.alerts.cli import main

    src = tmp_path / "alerts.ndjson"
    src.write_text("\n".join(json.dumps(a.to_dict())
                             for a in (make_ddos(), make_dga())) + "\n",
                   encoding="utf-8")
    out = tmp_path / "findings.jsonl"
    assert main(["ocsf", "--alerts", str(src), "--out", str(out)]) == 0
    assert len(out.read_text(encoding="utf-8").splitlines()) == 2

    bad_src = tmp_path / "bad.ndjson"
    bad = make_ddos().to_dict()
    bad["timestamp"] = "not-a-timestamp"
    bad["window_start"] = None
    bad["window_end"] = None
    bad_src.write_text(json.dumps(bad) + "\n", encoding="utf-8")
    bad_out = tmp_path / "bad.jsonl"
    assert main(["ocsf", "--alerts", str(bad_src), "--out", str(bad_out)]) == 2
    assert not bad_out.exists()
