"""Alert layer: evidence-rich schema, SQLite store, exports.

    schema       — Alert / EvidenceItem envelope, ATT&CK map, severity ladder
    store        — SQLite evidence store + JSONL sink
    export_stix  — offline STIX 2.1 bundle builder
    report       — self-contained HTML incident report
    cli          — `python -m src.alerts.cli` entry points
"""
from .schema import (
    ATTACK_MAP,
    SEVERITY_BY_CLASS,
    Alert,
    EvidenceItem,
    alert_from_dict,
    alert_id_of,
    severity_for,
    validate_alert,
)

__all__ = [
    "ATTACK_MAP",
    "SEVERITY_BY_CLASS",
    "Alert",
    "EvidenceItem",
    "alert_from_dict",
    "alert_id_of",
    "severity_for",
    "validate_alert",
]
