"""STIX 2.1 bundle export for alerts — fully offline, stdlib only.

The SOC-facing contract for the pipeline is a STIX 2.1 bundle an analyst can
hand to a TAXII server / SIEM. The `stix2` library is intentionally NOT a
dependency: the nodal-centre environment is offline and requirements stay
pinned and small, so the bundle is hand-built against the 2.1 spec subset we
emit and validated structurally before writing:

* `identity`      — the analytics enclave (producer), named as
                    `created_by_ref` on everything this module emits
* `attack-pattern`— one per MITRE ATT&CK technique referenced, mapped the 2.1
                    way: an external reference to the public matrix
                    (`source_name` mitre-attack, `external_id` the technique).
                    No network call.
* `indicator`     — one per alert: `pattern` over the alert's observable with
                    `pattern_type` / `pattern_version` (required), `indicator_types`
                    carrying the recommended 2.1 term for the alert's severity plus
                    the threat class, `valid_from`, confidence 0-100,
                    severity + evidence in the description. `pattern` is
                    mandatory, so an alert whose key and endpoints are not
                    observable carries a never-matching sentinel pattern and no
                    observed-data (honest: never a fabricated observable)
* `observed-data` — the alert as one observation: first/last observed,
                    `number_observed = 1`, and `object_refs` naming the
                    first-class cyber observables (ipv4-addr / ipv6-addr /
                    domain-name) the bundle carries beside it

STIX 2.1 removed `labels` and `kill_chain_phases` from indicator and deprecated
the `indicates` relationship, so this emits none of them: the threat class is an
indicator type, the ATT&CK mapping is an external reference, and the indicator's
pattern and the observation's referenced observables already name the same value.

IDs are deterministic (`<type>--uuid5` over stable fields), so re-exporting the
same alert set yields byte-identical bundles — good for diffing and caching.

Honest limitations (documented, not hidden): patterns are single-item equality
patterns (no boolean composition); alerts without an observable key get the
sentinel pattern and no observed-data; `confidence` is the detector's own score
scaled to 0-100, not a calibrated probability of intrusion.
"""
from __future__ import annotations

import ipaddress
import json
import re
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .schema import ATTACK_MAP, Alert

_NS = uuid.NAMESPACE_URL
# 2.1 cyber observables this exporter can name as first-class bundle objects
_SCO_TYPES = ("ipv4-addr", "ipv6-addr", "domain-name")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
_PRODUCER_ID = f"identity--{uuid.uuid5(_NS, 'https://diodewatch/enclave-identity')}"
# The enclave's own founding timestamp: fixed, so bundles stay byte-identical.
_CREATED = "2026-09-01T00:00:00Z"
# 2.1 recommends this closed list for indicator_types; a consumer that filters
# on it should see what this detector asserted, so the severity ladder (derived
# from threat class + confidence, never hand-set) maps onto it. The threat
# class rides along: the property is an open vocabulary.
_INDICATOR_TYPE = {"critical": "malicious-activity",
                   "high": "malicious-activity",
                   "medium": "suspicious-activity",
                   "low": "anomalous-activity"}


def _uid(kind: str, seed: str) -> str:
    """A 2.1 object id: the type names the namespace, then a stable UUID.

    `<type>--<uuid>` is not cosmetic — a validator rejects a bare UUID, and
    every reference in the bundle is matched against these strings.
    """
    return f"{kind}--{uuid.uuid5(_NS, f'diodewatch/{kind}/{seed}')}"


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _key_ip(key: str) -> str | None:
    """dst endpoint from a beacon-style key: "src->dst", "src->[v6]:port"."""
    arrow = key.rfind("->")
    if arrow == -1:
        return None
    dst = key[arrow + 2:].strip()
    if dst.startswith("["):                      # bracketed IPv6, optional :port
        end = dst.find("]")
        if end == -1:
            return None
        ip = dst[1:end]
        return ip if _is_ip(ip) else None
    if dst.count(":") == 1 and dst.rsplit(":", 1)[1].isdigit():
        dst = dst.rsplit(":", 1)[0]              # strip IPv4 :port
    return dst if _is_ip(dst) else None


def observable_of(a: Alert) -> tuple[str, str] | None:
    """Best observable for an alert: (ipv4-addr|ipv6-addr|domain-name, value).

    Preference order: explicit endpoints (dst then src), then the alert's
    `key` (rule/ML alerts carry the entity they fired on; beacon/TLS keys are
    "src->dst[:port]" and their dst is used), then the flow_id. Returns None
    when nothing is a real IP/domain (the exporter then falls back to a
    never-matching sentinel pattern and omits observed-data).
    """
    candidates: list[str] = []
    for v in (a.dst_ip, a.src_ip):
        if v:
            candidates.append(str(v))
    if a.key:
        candidates.append(str(a.key))
    if a.flow_id:
        candidates.append(str(a.flow_id))
    for c in candidates:
        c = c.strip()
        if _is_ip(c):
            return ("ipv6-addr" if ":" in c else "ipv4-addr", c)
        if _DOMAIN_RE.match(c):
            return ("domain-name", c)
    if a.key:
        ip = _key_ip(str(a.key))
        if ip:
            return ("ipv6-addr" if ":" in ip else "ipv4-addr", ip)
    return None


def _ts(a: Alert) -> str:
    """ISO-8601 timestamp the STIX spec accepts (naive UTC gains Z)."""
    t = (a.window_end or a.timestamp or "").strip()
    if not t:
        return "1970-01-01T00:00:00Z"
    if t.endswith("Z") or "+" in t:
        return t
    if len(t) == 19 and t[10] == "T":  # YYYY-MM-DDTHH:MM:SS (naive UTC)
        return t + "Z"
    return t


def _identity() -> dict[str, Any]:
    return {
        "type": "identity",
        "id": _PRODUCER_ID,
        "spec_version": "2.1",
        "created": _CREATED,
        "modified": _CREATED,
        "name": "DiodeWatch analytics enclave",
        "description": ("Passive AI-based threat detection on unidirectional "
                        "IP traffic (one-way data-diode enclave)."),
        "identity_class": "organization",
        "sectors": ["technology"],
    }


def _attack_pattern(technique: str) -> dict[str, Any]:
    name, _, tactic = "", "", ""
    for tid, tname, ttac in ATTACK_MAP.values():  # search by technique id
        if tid == technique:
            name, tactic = tname, ttac
            break
    return {
        "type": "attack-pattern",
        "id": _uid("attack-pattern", technique),
        "spec_version": "2.1",
        "created": _CREATED,
        "modified": _CREATED,
        "created_by_ref": _PRODUCER_ID,
        "name": name or f"MITRE ATT&CK {technique}",
        "description": f"Observed threat behaviour mapped to ATT&CK technique "
                       f"{technique} ({tactic}).",
        "external_references": [{
            "source_name": "mitre-attack",
            "external_id": technique,
        }],
    }


def _indicator(a: Alert, pattern: str) -> dict[str, Any]:
    technique = a.attack_technique or ""
    types = [_INDICATOR_TYPE.get(a.severity or "", "unknown")]
    if a.threat_class and a.threat_class not in types:
        types.append(a.threat_class)
    return {
        "type": "indicator",
        "id": _uid("indicator", a.alert_id or ""),
        "spec_version": "2.1",
        "created": _ts(a),
        "modified": _ts(a),
        "created_by_ref": _PRODUCER_ID,
        "name": f"{a.threat_class} alert — {a.detector or 'detector'}",
        "description": _describe(a),
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": _ts(a),
        "indicator_types": types,
        "confidence": min(100, max(0, round(float(a.confidence) * 100))),
        "external_references": ([{"source_name": "mitre-attack",
                                  "external_id": technique}]
                                if technique else []),
    }


def _observable(obs: tuple[str, str]) -> dict[str, Any]:
    """A 2.1 first-class cyber observable: type, id, value. No spec_version,
    no created/modified — SCOs are not SDOs."""
    return {"type": obs[0], "id": _uid(obs[0], obs[1]), "value": obs[1]}


def _observed_data(a: Alert, sco_id: str) -> dict[str, Any]:
    return {
        "type": "observed-data",
        "id": _uid("observed-data", a.alert_id or ""),
        "spec_version": "2.1",
        "created": _ts(a),
        "modified": _ts(a),
        "created_by_ref": _PRODUCER_ID,
        "first_observed": _ts(a),
        "last_observed": _ts(a),
        "number_observed": 1,
        "object_refs": [sco_id],
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


# Indicator.pattern is mandatory, but a rule window with no address or domain
# anywhere has nothing to name. 0.0.0.0 (the unspecified address) is the honest
# placeholder: no consumer matches it to a host, and the evidence lives in the
# description instead of in an observable that was never seen.
_SENTINEL_PATTERN = "[ipv4-addr:value = '0.0.0.0']"


def stix_bundle(alerts: Iterable[Alert]) -> dict[str, Any]:
    """Build a STIX 2.1 bundle from alerts (deterministic ids, no I/O)."""
    alerts = list(alerts)
    objects: list[dict[str, Any]] = [_identity()]
    observables: dict[str, dict[str, Any]] = {}
    techniques: set[str] = set()
    for a in alerts:
        obs = observable_of(a)
        pattern = (f"[{obs[0]}:value = '{obs[1]}']" if obs
                   else _SENTINEL_PATTERN)
        objects.append(_indicator(a, pattern))
        if obs:
            sco = _observable(obs)
            objects.append(_observed_data(a, sco["id"]))
            # one observable object per distinct value, referenced by every
            # observation that saw it: 2.1 SCOs are objects, not payload
            observables.setdefault(sco["id"], sco)
        if a.attack_technique and a.attack_technique not in techniques:
            techniques.add(a.attack_technique)
            objects.append(_attack_pattern(a.attack_technique))
    objects.extend(observables.values())
    return {
        "type": "bundle",
        "id": _uid("bundle", ",".join(sorted(str(a.alert_id) for a in alerts))),
        "objects": objects,
    }


def _is_uuid(s: str) -> bool:
    try:
        uuid.UUID(s)
        return True
    except (ValueError, AttributeError):
        return False


_SDO_TYPES = ("identity", "indicator", "attack-pattern", "observed-data")
_REF_KEYS = ("created_by_ref", "source_ref", "target_ref", "object_refs")


def validate_bundle(bundle: dict[str, Any]) -> list[str]:
    """Structural self-check against what STIX 2.1 actually enforces.

    Being a Bundle of JSON objects is not the same as being ingestible: a bare
    UUID where `<type>--<uuid>` is required, an indicator with no
    `pattern_type`, or an observation holding a 2.0 `objects` map all parse here
    and fail at the first TAXII server, SIEM import or `stix2` call. These are
    the properties a consumer's validator checks, run before writing.
    """
    problems: list[str] = []
    if bundle.get("type") != "bundle":
        problems.append("top-level type != bundle")
    bid = str(bundle.get("id", ""))
    if not bid.startswith("bundle--") or not _is_uuid(bid[len("bundle--"):]):
        problems.append(f"bundle id {bid!r} is not 'bundle--<uuid>'")
    if "spec_version" in bundle:
        problems.append("Bundle carries spec_version, which 2.1 does not define")
    objs = bundle.get("objects", [])
    if not objs:
        problems.append("empty objects list")

    ids: set[str] = set()
    for o in objs:
        otype = o.get("type") or ""
        oid = o.get("id") or ""
        if not otype or not oid:
            problems.append(f"object missing id/type: {otype or o}")
            continue
        if oid in ids:
            problems.append(f"duplicate object id {oid}")
        ids.add(oid)
        if not oid.startswith(f"{otype}--") or not _is_uuid(oid[len(otype) + 2:]):
            problems.append(f"id {oid} is not '<type>--<uuid>' for {otype}")
        if otype in _SCO_TYPES:
            if not o.get("value"):
                problems.append(f"observable {oid} has no value")
            if "spec_version" in o or "created" in o:
                problems.append(f"observable {oid} carries SDO properties")
            continue
        if otype not in _SDO_TYPES:
            problems.append(f"unsupported object type {otype}")
        if o.get("spec_version") != "2.1" or not o.get("created") \
                or not o.get("modified"):
            problems.append(f"{otype} {oid} lacks spec_version 2.1 / timestamps")
        if otype == "indicator":
            if o.get("pattern_type") != "stix":
                problems.append(f"indicator {oid} pattern_type != stix")
            for req in ("pattern", "pattern_version", "valid_from",
                        "indicator_types"):
                if not o.get(req):
                    problems.append(f"indicator {oid} missing {req}")
            for dropped in ("labels", "kill_chain_phases"):
                if dropped in o:
                    problems.append(f"indicator {oid} uses 2.0-only {dropped}")
        if otype == "observed-data":
            if "objects" in o:
                problems.append(f"observed-data {oid} uses the 2.0 objects map")
            if not isinstance(o.get("object_refs"), list) \
                    or not o.get("object_refs"):
                problems.append(f"observed-data {oid} missing object_refs")
            if not isinstance(o.get("number_observed"), int):
                problems.append(f"observed-data {oid} number_observed not an int")

    for o in objs:
        for key in _REF_KEYS:
            refs = o.get(key)
            if not refs:
                continue
            for r in (refs if isinstance(refs, list) else [refs]):
                if r not in ids:
                    problems.append(f"{o.get('type')} {o.get('id')} "
                                    f"has dangling {key} {r}")
    return problems


def write_stix(alerts: Iterable[Alert], path: str | Path) -> tuple[dict[str, Any], list[str]]:
    """Build, validate, and only then write: returns (bundle, problems).

    A bundle that fails `validate_bundle` never reaches disk. Writing it and
    letting the caller notice would leave an un-ingestible file sitting in the
    export directory — worse than no export at all.
    """
    bundle = stix_bundle(alerts)
    problems = validate_bundle(bundle)
    if not problems:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return bundle, problems
