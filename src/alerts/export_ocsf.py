"""OCSF 1.10.0 Detection Finding export for alerts, offline and stdlib only.

The SOC contract beside the STIX bundle is an OCSF event stream. Each alert
becomes one Detection Finding (class UID 2004, category UID 2, activity Create,
type UID 200401), serialized as one compact JSON object per line. OCSF defines
events, not a bundle envelope, so the file is JSONL: a consumer can read it
without unwrapping an array, and every line can be validated on its own.

No OCSF SDK is a dependency. The emitted subset is built here and checked
structurally before writing. The check is deliberately stricter than the OCSF
minimum: it enforces the required Detection Finding attributes, sibling labels,
MITRE identifiers, endpoint and observable value types, and that every
observable points at the event value it claims to summarize. It is not a full
OCSF meta-schema validator and does not pretend to cover classes this exporter
never emits.

The mapping is intentionally conservative:

* the finding is a Create event; this exporter has no lifecycle history, so it
  does not invent Update or Close activities;
* `time` is the detection instant the Finding class calls creation time: the
  alert timestamp, normally the end of its window, never the export clock. The
  underlying span is carried separately in `start_time`, `end_time`,
  `finding_info.first_seen_time` and `finding_info.last_seen_time`;
* `evidences[0].data` carries the complete observed-vs-threshold evidence, the
  detector id, flow id, key and window seconds, so no source detail is lost
  when OCSF has no first-class field for it;
* domains become DNS query evidence only for the DGA and DNS-tunnel classes,
  where a queried hostname is what the detector actually saw. Other classes do
  not get a fabricated `query`;
* source and destination endpoints are emitted only when the alert carries
  them, and observables point into those same fields instead of introducing
  values that are absent from the event;
* `confidence` is the alert's stored detector or calibrated confidence, mapped
  to the OCSF low/medium/high ladder. It is not a probability of intrusion and
  the export does not claim calibration where the alert carries none.

Ids are deterministic: `finding_info.uid` and `metadata.uid` are the alert's
stable uuid5, so re-exporting the same alerts produces byte-identical JSONL.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import tempfile
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .schema import ATTACK_MAP, Alert, display_class

# Pinned upstream release, https://github.com/ocsf/ocsf-schema/tree/v1.10.0.
# The version is emitted in metadata.version and is a fact about this mapping.
OCSF_VERSION = "1.10.0"
DETECTION_FINDING_UID = 2004
FINDINGS_CATEGORY_UID = 2
CREATE_ACTIVITY_UID = 1
DETECTION_FINDING_CREATE_UID = 200401
DETECTION_FINDING_NAME = "Detection Finding"
FINDINGS_CATEGORY_NAME = "Findings"
CREATE_ACTIVITY_NAME = "Create"
DETECTION_FINDING_CREATE_NAME = "Detection Finding: Create"

PRODUCT_NAME = "DiodeWatch"
# Kept in step with pyproject.toml. The value describes the producer, not OCSF.
PRODUCT_VERSION = "1.0.0"
PRODUCT_UID = "diodewatch"

_NS = uuid.NAMESPACE_URL
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
_ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_OBSERVABLE_PATH_RE = re.compile(
    r"^evidences\[(\d+)\]\.(src_endpoint|dst_endpoint|query)\.(ip|hostname)$")


def _is_domain(value: str) -> bool:
    """A DNS name with an alphabetic TLD, never an address or a bare word."""
    if not _DOMAIN_RE.match(value):
        return False
    # DNS has no all-numeric TLD. Without this, a dotted IPv4 literal passes
    # the label grammar and is emitted as a query hostname it never was.
    return any(ch.isalpha() for ch in value.rsplit(".", 1)[-1])

_SEVERITY = {
    "low": (2, "Low"),
    "medium": (3, "Medium"),
    "high": (4, "High"),
    "critical": (5, "Critical"),
}
_SEVERITY_LABELS = {
    0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High",
    5: "Critical", 6: "Fatal", 99: "Other",
}
_CONFIDENCE_LABELS = {0: "Unknown", 1: "Low", 2: "Medium", 3: "High", 99: "Other"}
_STATUS_LABELS = {
    1: "New", 2: "In Progress", 3: "Suppressed", 4: "Resolved",
    5: "Archived", 6: "Deleted",
}
_ANALYTIC_TYPES = set(range(12)) | {99}
_OBSERVABLE_TYPES = {1: "Hostname", 2: "IP Address"}


def _finding_uid(a: Alert) -> str:
    """Stable finding id, the alert id when present.

    Alerts normally carry that id already. The fallback keeps hand-built or
    legacy alerts deterministic too; it never uses the export clock.
    """
    if a.alert_id:
        return str(a.alert_id)
    seed = "|".join(str(v or "") for v in
                    (a.timestamp, a.threat_class, a.detector, a.key, a.flow_id))
    return str(uuid.uuid5(_NS, f"diodewatch/ocsf/finding/{seed}"))


def _epoch_ms(value: Any) -> int | None:
    """ISO-8601 or epoch seconds/milliseconds to OCSF timestamp_t milliseconds."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            f = float(value)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(f) or f < 0:
            return None
        return int(f if f >= 1e11 else f * 1000)
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        return int(dt.timestamp() * 1000)
    except (OverflowError, OSError, ValueError):
        return None


def _finding_time(a: Alert) -> int | None:
    """Creation time for the finding: alert time, then the window end.

    The Finding class redefines `time` as creation time. Falling back to the
    window end is explicit, and an alert with neither is refused by the
    validator instead of being stamped with a fake epoch.
    """
    return _epoch_ms(a.timestamp) or _epoch_ms(a.window_end)


def _window_times(a: Alert) -> tuple[int | None, int | None]:
    return _epoch_ms(a.window_start), _epoch_ms(a.window_end)


def _rfc3339(value: Any) -> str | None:
    """Normalize a source timestamp to UTC RFC3339 with milliseconds."""
    ms = _epoch_ms(value)
    if ms is None:
        return None
    dt = datetime.fromtimestamp(ms / 1000.0, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"


def _confidence(a: Alert) -> tuple[int, str, int]:
    try:
        c = float(a.confidence)
    except (TypeError, ValueError):
        return 0, "Unknown", 0
    if not math.isfinite(c) or c < 0:
        return 0, "Unknown", 0
    score = max(0, min(100, round(c * 100)))
    if c >= 0.9:
        return 3, "High", score
    if c >= 0.7:
        return 2, "Medium", score
    if c > 0:
        return 1, "Low", score
    return 0, "Unknown", score


def _severity(a: Alert) -> tuple[int, str]:
    return _SEVERITY.get((a.severity or "").lower(),
                         (0, _SEVERITY_LABELS[0]))


def _port(value: Any) -> Any:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def _endpoint(ip: Any, port: Any) -> dict[str, Any] | None:
    ep: dict[str, Any] = {}
    if ip:
        ep["ip"] = str(ip)
    port = _port(port)
    if port is not None:
        ep["port"] = port
    return ep or None


def _dns_hostname(a: Alert) -> str | None:
    """The queried domain, only where the detector class means a DNS query."""
    if a.threat_class not in ("dga", "dns_tunnel") or not a.key:
        return None
    key = str(a.key).strip()
    return key if _is_domain(key) else None


def _attack(a: Alert) -> list[dict[str, Any]]:
    """One ATT&CK attack object, with no invented tactic or technique id."""
    tactic = (a.attack_tactic or "").strip()
    technique = (a.attack_technique or "").strip()
    if not tactic and not technique:
        return []
    attack: dict[str, Any] = {}
    if tactic:
        attack["tactic"] = {"name": tactic}
    if technique:
        name = next((t[1] for t in ATTACK_MAP.values() if t[0] == technique), "")
        if "." in technique:
            # OCSF separates a technique from its sub-technique. Keep both ids
            # rather than putting a dotted id in the technique field where a
            # consumer filtering T1499 would not find it.
            base = technique.split(".", 1)[0]
            base_name = next((t[1] for t in ATTACK_MAP.values()
                              if t[0] == base), "")
            tech: dict[str, Any] = {"uid": base}
            if base_name:
                tech["name"] = base_name
            sub: dict[str, Any] = {"uid": technique}
            if name:
                sub["name"] = name
            attack["technique"] = tech
            attack["sub_technique"] = sub
        else:
            tech = {"uid": technique}
            if name:
                tech["name"] = name
            attack["technique"] = tech
    return [attack]


def _analytic(a: Alert) -> dict[str, Any]:
    detector = (a.detector or "diodewatch.unknown").strip()
    # ml.* channels are learned models; the rule and window channels are rules.
    type_id = 4 if detector.startswith("ml") else 1
    return {
        "name": detector,
        "uid": detector,
        "type_id": type_id,
        "version": PRODUCT_VERSION,
    }


def _describe(a: Alert) -> str:
    parts = [(f"{a.threat_class} ({a.severity}) detected by "
              f"{a.detector or '?'} with confidence {a.confidence:.2f}")]
    if a.flow_id:
        parts.append(f"flow {a.flow_id}")
    if a.src_ip and a.dst_ip:
        parts.append(f"endpoints {a.src_ip} -> {a.dst_ip}"
                     + (f":{a.dst_port}" if a.dst_port else ""))
    if a.window_start and a.window_end:
        parts.append(f"window {a.window_start} / {a.window_end}")
    if a.attack_technique:
        parts.append(f"ATT&CK {a.attack_technique}")
    for e in a.evidence[:5]:
        parts.append(f"{e.condition}: observed {e.observed} "
                     f"{e.operator} threshold {e.threshold}"
                     + (f" ({e.description})" if e.description else ""))
    return " | ".join(parts)


def _evidence_data(a: Alert) -> dict[str, Any]:
    data: dict[str, Any] = {
        "alert_id": _finding_uid(a),
        "threat_class": a.threat_class,
        "severity": a.severity,
        "detector": a.detector,
        "confidence": round(float(a.confidence), 4),
    }
    for key, value in (("flow_id", a.flow_id), ("key", a.key),
                       ("window_seconds", a.window_seconds),
                       ("window_start", a.window_start),
                       ("window_end", a.window_end),
                       ("attack_technique", a.attack_technique),
                       ("attack_tactic", a.attack_tactic)):
        if value is not None:
            data[key] = value
    if a.evidence:
        data["evidence"] = [e.to_dict() for e in a.evidence]
    return {k: v for k, v in data.items() if v is not None}


def _observables(a: Alert, dns_hostname: str | None) -> list[dict[str, Any]]:
    """Pointers to values already present in the event, never new values."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()

    def add(name: str, type_id: int, value: Any) -> None:
        val = str(value)
        key = (type_id, val)
        if val and key not in seen:
            seen.add(key)
            out.append({"name": name, "type": _OBSERVABLE_TYPES[type_id],
                        "type_id": type_id, "value": val})

    if a.src_ip:
        add("evidences[0].src_endpoint.ip", 2, a.src_ip)
    if a.dst_ip:
        add("evidences[0].dst_endpoint.ip", 2, a.dst_ip)
    if dns_hostname:
        add("evidences[0].query.hostname", 1, dns_hostname)
    return out


def ocsf_event(a: Alert) -> dict[str, Any]:
    """Build one OCSF 1.10.0 Detection Finding Create event (no I/O)."""
    uid = _finding_uid(a)
    when = _finding_time(a)
    start, end = _window_times(a)
    severity_id, severity = _severity(a)
    confidence_id, confidence, confidence_score = _confidence(a)
    dns_hostname = _dns_hostname(a)

    event: dict[str, Any] = {
        "activity_id": CREATE_ACTIVITY_UID,
        "activity_name": CREATE_ACTIVITY_NAME,
        "category_uid": FINDINGS_CATEGORY_UID,
        "category_name": FINDINGS_CATEGORY_NAME,
        "class_uid": DETECTION_FINDING_UID,
        "class_name": DETECTION_FINDING_NAME,
        "type_uid": DETECTION_FINDING_CREATE_UID,
        "type_name": DETECTION_FINDING_CREATE_NAME,
        "severity_id": severity_id,
        "severity": severity,
        "is_alert": True,
        "status_id": 1,
        "status": _STATUS_LABELS[1],
        "confidence_id": confidence_id,
        "confidence": confidence,
        "confidence_score": confidence_score,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": PRODUCT_NAME,
                "uid": PRODUCT_UID,
                "vendor_name": PRODUCT_NAME,
                "version": PRODUCT_VERSION,
            },
            "uid": uid,
            "correlation_uid": uid,
            "log_name": "diodewatch.alerts",
            "log_provider": PRODUCT_NAME,
        },
        "finding_info": {
            "uid": uid,
            "title": f"{display_class(a.threat_class)} detected by "
                     f"{a.detector or 'unknown detector'}",
            "desc": _describe(a),
            "created_time": when,
            "analytic": _analytic(a),
        },
        "evidences": [{
            "uid": uid,
            "name": a.detector or f"{a.threat_class} evidence",
            "data": _evidence_data(a),
        }],
    }
    if when is not None:
        event["time"] = when
    if a.timestamp:
        original = _rfc3339(a.timestamp)
        if original is not None:
            event["metadata"]["original_time"] = original
    if start is not None:
        event["start_time"] = start
        event["finding_info"]["first_seen_time"] = start
    if end is not None:
        event["end_time"] = end
        event["finding_info"]["last_seen_time"] = end

    attack = _attack(a)
    if attack:
        event["finding_info"]["attacks"] = attack

    evidence = event["evidences"][0]
    src = _endpoint(a.src_ip, a.src_port)
    dst = _endpoint(a.dst_ip, a.dst_port)
    if src:
        evidence["src_endpoint"] = src
    if dst:
        evidence["dst_endpoint"] = dst
    if dns_hostname:
        evidence["query"] = {"hostname": dns_hostname}

    observables = _observables(a, dns_hostname)
    if observables:
        event["observables"] = observables
    return event


def ocsf_events(alerts: Iterable[Alert]) -> list[dict[str, Any]]:
    """Build one event per alert, in input order (no I/O)."""
    return [ocsf_event(a) for a in alerts]


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_epoch_ms(value: Any) -> bool:
    """A positive integer epoch millisecond, never a float, bool or zero."""
    return _is_int(value) and value > 0


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _no_none(value: Any, path: str = "") -> list[str]:
    """OCSF JSON omits absent attributes; null is not an absent attribute."""
    out: list[str] = []
    if value is None:
        out.append(f"{path or '<root>'} is null")
    elif isinstance(value, dict):
        for k, v in value.items():
            out.extend(_no_none(v, f"{path}.{k}" if path else str(k)))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out.extend(_no_none(v, f"{path}[{i}]"))
    return out


def _check_sibling(problems: list[str], obj: dict[str, Any], id_key: str,
                   label_key: str, labels: dict[int, str],
                   where: str) -> None:
    ident = obj.get(id_key)
    if not _is_int(ident) or ident not in labels:
        problems.append(f"{where}.{id_key} is not a known enum value")
        return
    label = obj.get(label_key)
    if label is not None and label != labels[ident]:
        problems.append(f"{where}.{label_key} {label!r} != "
                        f"{labels[ident]!r} for {id_key} {ident}")


def _valid_endpoint(problems: list[str], ep: Any, path: str) -> None:
    if not isinstance(ep, dict):
        problems.append(f"{path} is not an object")
        return
    identity = ("ip", "mac", "uid", "name", "hostname", "instance_uid",
                "interface_uid", "interface_name")
    if not any(ep.get(k) for k in identity):
        problems.append(f"{path} has no endpoint identity")
    if "ip" in ep:
        try:
            ipaddress.ip_address(str(ep["ip"]))
        except ValueError:
            problems.append(f"{path}.ip {ep.get('ip')!r} is not an IP address")
    if "port" in ep and (not _is_int(ep["port"])
                         or not 0 <= ep["port"] <= 65535):
        problems.append(f"{path}.port {ep.get('port')!r} is not a port")


def _resolve_observable(event: dict[str, Any], name: str) -> tuple[Any, str] | None:
    """Return (value, expected label) for the narrow observable paths we emit."""
    m = _OBSERVABLE_PATH_RE.match(name)
    if not m:
        return None
    index, container, field = int(m.group(1)), m.group(2), m.group(3)
    evidences = event.get("evidences")
    if not isinstance(evidences, list) or index >= len(evidences):
        return None
    obj = evidences[index]
    if not isinstance(obj, dict) or not isinstance(obj.get(container), dict):
        return None
    value = obj[container].get(field)
    if field == "ip":
        return value, _OBSERVABLE_TYPES[2]
    return value, _OBSERVABLE_TYPES[1]


def validate_event(event: dict[str, Any]) -> list[str]:
    """Check the OCSF subset this exporter emits, including required fields.

    This is the gate `write_ocsf` runs before touching disk. It catches the
    failures a consumer would hit first: missing base attributes, wrong
    class/type identity, sibling labels that disagree with their ids, malformed
    ATT&CK ids, invalid endpoints, and observables whose name or value does not
    resolve to the event. It is not a complete OCSF schema validator.
    """
    if not isinstance(event, dict):
        return ["event is not a JSON object"]
    problems = _no_none(event)
    required = ("activity_id", "category_uid", "class_uid", "metadata",
                "severity_id", "time", "type_uid", "finding_info")
    for key in required:
        if key not in event:
            problems.append(f"missing required {key}")

    if event.get("class_uid") != DETECTION_FINDING_UID:
        problems.append("class_uid != 2004")
    if event.get("class_name") != DETECTION_FINDING_NAME:
        problems.append("class_name != Detection Finding")
    if event.get("category_uid") != FINDINGS_CATEGORY_UID:
        problems.append("category_uid != 2")
    if event.get("category_name") != FINDINGS_CATEGORY_NAME:
        problems.append("category_name != Findings")
    if event.get("activity_id") != CREATE_ACTIVITY_UID:
        problems.append("activity_id != 1")
    if event.get("activity_name") != CREATE_ACTIVITY_NAME:
        problems.append("activity_name != Create")
    if event.get("type_uid") != DETECTION_FINDING_CREATE_UID:
        problems.append("type_uid != 200401")
    if event.get("type_name") not in (None, DETECTION_FINDING_CREATE_NAME):
        problems.append("type_name does not match type_uid")
    if "time" in event and not _is_epoch_ms(event["time"]):
        problems.append("time is not a positive epoch-millisecond integer")

    _check_sibling(problems, event, "severity_id", "severity",
                   _SEVERITY_LABELS, "event")
    _check_sibling(problems, event, "confidence_id", "confidence",
                   _CONFIDENCE_LABELS, "event")
    _check_sibling(problems, event, "status_id", "status",
                   _STATUS_LABELS, "event")
    if "confidence_score" in event and (
            not _is_int(event["confidence_score"])
            or not 0 <= event["confidence_score"] <= 100):
        problems.append("confidence_score is not an integer 0..100")
    if not isinstance(event.get("is_alert"), bool):
        problems.append("is_alert is not a boolean")

    for key in ("start_time", "end_time"):
        if key in event and not _is_epoch_ms(event[key]):
            problems.append(f"{key} is not a positive epoch-millisecond integer")
    if (_is_epoch_ms(event.get("start_time"))
            and _is_epoch_ms(event.get("end_time"))
            and event["start_time"] > event["end_time"]):
        problems.append("start_time is after end_time")

    metadata = event.get("metadata")
    if not isinstance(metadata, dict):
        problems.append("metadata is not an object")
    else:
        if metadata.get("version") != OCSF_VERSION:
            problems.append(f"metadata.version != {OCSF_VERSION}")
        product = metadata.get("product")
        if not isinstance(product, dict):
            problems.append("metadata.product is not an object")
        else:
            for key in ("name", "vendor_name", "version"):
                if not _nonempty_str(product.get(key)):
                    problems.append(f"metadata.product.{key} is empty")
        if "uid" in metadata and not _nonempty_str(metadata["uid"]):
            problems.append("metadata.uid is empty")
        if ("original_time" in metadata
                and not _is_epoch_ms(_epoch_ms(metadata["original_time"]))):
            problems.append("metadata.original_time is not a positive timestamp")

    finding = event.get("finding_info")
    if not isinstance(finding, dict):
        problems.append("finding_info is not an object")
        finding = {}
    else:
        if not _nonempty_str(finding.get("uid")):
            problems.append("finding_info.uid is missing")
        if not _nonempty_str(finding.get("title")):
            problems.append("finding_info.title is missing")
        created = finding.get("created_time")
        if not _is_epoch_ms(created):
            problems.append("finding_info.created_time is not a positive integer")
        elif _is_epoch_ms(event.get("time")) and created != event["time"]:
            problems.append("finding_info.created_time != event.time")
        analytic = finding.get("analytic")
        if not isinstance(analytic, dict):
            problems.append("finding_info.analytic is not an object")
        else:
            if not (analytic.get("name") or analytic.get("uid")):
                problems.append("finding_info.analytic has no name or uid")
            if analytic.get("type_id") not in _ANALYTIC_TYPES:
                problems.append("finding_info.analytic.type_id is not known")
        for key in ("first_seen_time", "last_seen_time"):
            if key in finding and not _is_epoch_ms(finding[key]):
                problems.append(
                    f"finding_info.{key} is not a positive epoch-millisecond integer")
        if (_is_epoch_ms(finding.get("first_seen_time"))
                and _is_epoch_ms(finding.get("last_seen_time"))
                and finding["first_seen_time"] > finding["last_seen_time"]):
            problems.append("finding_info.first_seen_time is after last_seen_time")
        attacks = finding.get("attacks", [])
        if not isinstance(attacks, list):
            problems.append("finding_info.attacks is not an array")
        else:
            for i, attack in enumerate(attacks):
                if not isinstance(attack, dict):
                    problems.append(f"finding_info.attacks[{i}] is not an object")
                    continue
                tech = attack.get("technique")
                tactic = attack.get("tactic")
                if not tech and not tactic and not attack.get("sub_technique"):
                    problems.append(f"finding_info.attacks[{i}] has no mapping")
                if tech is not None:
                    if not isinstance(tech, dict) or not _nonempty_str(tech.get("uid")):
                        problems.append(f"finding_info.attacks[{i}].technique "
                                        "has no uid")
                    elif not _ATTACK_RE.match(tech["uid"]):
                        problems.append(f"finding_info.attacks[{i}].technique.uid "
                                        "is not a MITRE ATT&CK id")
                sub = attack.get("sub_technique")
                if sub is not None:
                    if not isinstance(sub, dict) or not _nonempty_str(sub.get("uid")):
                        problems.append(f"finding_info.attacks[{i}].sub_technique "
                                        "has no uid")
                    elif not _ATTACK_RE.match(sub["uid"]):
                        problems.append(f"finding_info.attacks[{i}].sub_technique.uid "
                                        "is not a MITRE ATT&CK id")
                if tactic is not None and (
                        not isinstance(tactic, dict)
                        or not (tactic.get("name") or tactic.get("uid"))):
                    problems.append(f"finding_info.attacks[{i}].tactic "
                                    "has no name or uid")

    evidences = event.get("evidences")
    if not isinstance(evidences, list) or not evidences:
        problems.append("evidences is not a non-empty array")
        evidences = []
    for i, evidence in enumerate(evidences):
        path = f"evidences[{i}]"
        if not isinstance(evidence, dict):
            problems.append(f"{path} is not an object")
            continue
        if not (evidence.get("name") or evidence.get("uid")):
            problems.append(f"{path} has no name or uid")
        if not isinstance(evidence.get("data"), dict):
            problems.append(f"{path}.data is not an object")
        if "src_endpoint" in evidence:
            _valid_endpoint(problems, evidence["src_endpoint"], f"{path}.src_endpoint")
        if "dst_endpoint" in evidence:
            _valid_endpoint(problems, evidence["dst_endpoint"], f"{path}.dst_endpoint")
        query = evidence.get("query")
        if query is not None:
            if not isinstance(query, dict) or not _nonempty_str(query.get("hostname")):
                problems.append(f"{path}.query has no hostname")
            elif not _is_domain(query["hostname"]):
                problems.append(f"{path}.query.hostname is not a domain")

    obs = event.get("observables")
    if obs is not None:
        if not isinstance(obs, list) or not obs:
            problems.append("observables is not a non-empty array")
        else:
            seen: set[tuple[int, str]] = set()
            for i, item in enumerate(obs):
                path = f"observables[{i}]"
                if not isinstance(item, dict):
                    problems.append(f"{path} is not an object")
                    continue
                name, type_id = item.get("name"), item.get("type_id")
                if not _nonempty_str(name):
                    problems.append(f"{path}.name is empty")
                    continue
                if type_id not in _OBSERVABLE_TYPES:
                    problems.append(f"{path}.type_id is not 1 or 2")
                    continue
                if item.get("type") != _OBSERVABLE_TYPES[type_id]:
                    problems.append(f"{path}.type does not match type_id")
                value = item.get("value")
                if not _nonempty_str(value):
                    problems.append(f"{path}.value is empty")
                    continue
                resolved = _resolve_observable(event, name)
                if resolved is None:
                    problems.append(f"{path}.name does not resolve to an event value")
                    continue
                actual, label = resolved
                if actual != value:
                    problems.append(f"{path}.value does not match {name}")
                if item.get("type") != label:
                    problems.append(f"{path}.type does not match resolved value")
                if type_id == 1 and not _is_domain(value):
                    problems.append(f"{path}.value is not a hostname")
                if type_id == 2:
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        problems.append(f"{path}.value is not an IP address")
                pair = (type_id, value)
                if pair in seen:
                    problems.append(f"{path} duplicates an earlier observable")
                seen.add(pair)
    return problems


def validate_events(events: list[dict[str, Any]]) -> list[str]:
    """Validate a non-empty event stream; returns every problem found."""
    if not isinstance(events, list):
        return ["events is not a list"]
    if not events:
        return ["no OCSF events to export"]
    problems: list[str] = []
    for i, event in enumerate(events):
        for p in validate_event(event):
            problems.append(f"event[{i}]: {p}")
    return problems


def write_ocsf(alerts: Iterable[Alert],
               path: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Build, validate, and only then write newline-delimited JSON.

    Returns (events, problems). If any event fails validation no new output
    is written and an existing file is left untouched: an un-ingestible export
    in the alert directory is worse than no export at all, because an operator
    can still fix a missing file. A successful write goes to a temporary file
    in the same directory and is then replaced atomically, so a crash cannot
    leave a half-written stream under the requested name.
    """
    events = ocsf_events(alerts)
    problems = validate_events(events)
    if not problems:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        lines = "".join(json.dumps(e, ensure_ascii=False,
                                   separators=(",", ":")) + "\n"
                        for e in events)
        tmp_name = ""
        try:
            with tempfile.NamedTemporaryFile(
                    "w", encoding="utf-8", newline="\n", dir=p.parent,
                    prefix=f".{p.name}.", suffix=".tmp",
                    delete=False) as fh:
                tmp_name = fh.name
                fh.write(lines)
            os.replace(tmp_name, p)
        except BaseException:
            if tmp_name:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
            raise
    return events, problems
