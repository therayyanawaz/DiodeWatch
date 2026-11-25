"""Single owner of label truth: corpus label strings -> threat classes.

Two axes live here, deliberately in one module:

* PRODUCTION taxonomy, ``CLASSES`` (model class-id order), ``CLASS_LABELS``
  (consolidated label substrings) and ``class_of`` (what the detectors emit).
  Substring-based and ORDER-SENSITIVE: ``webattack`` is checked before
  ``bruteforce`` so ``'Web Attack - Brute Force'`` stays webattack.
* EVALUATION axis, ``CANONICAL_CLASSES``, ``LABEL_MAPS`` and
  ``resolve_label_map``: what ``scripts/benchmarks/bench_transfer.py`` scores against.
  Exact per-corpus maps; a label absent from its corpus map is reported as
  unmapped (counted, never merged).

The axes agree by design but are NOT identical: the evaluation axis folds
bruteforce/webattack into ``scan``, keeps slow attacks separate (``slowdos``)
and designates FPR-pressure corpora whose labels map to benign. The permitted
(class_of, canonical) pairs are enumerated in ``RELATIONSHIP``, editing
either surface without updating that table fails ``tests/detectors/test_labels.py``,
which is the structural guard against the two surfaces drifting apart.
"""
from __future__ import annotations

import numpy as np

# --------------------------------------------------------------------------
# production taxonomy (consumed by the detectors; class id == index)
# --------------------------------------------------------------------------
# threat class -> consolidated label substrings (matched after normalizing:
# label strings vary by corpus and mirror, e.g. 'Web Attack <dash> XSS',
# CSE-CIC-IDS2018 title case, CIC-DDoS2019 'Syn').
CLASS_LABELS: dict[str, tuple[str, ...]] = {
    "ddos": ("DDoS", "DDOS", "DoS ", "Heartbleed",
             "Syn"),   # CIC-DDoS2019 attack family label
    "scan": ("PortScan",),
    # checked BEFORE bruteforce so 'Web Attack - Brute Force' stays webattack
    "webattack": ("Web Attack",),
    # IDS2018 'FTP-BruteForce'/'SSH-Bruteforce'/'Brute Force -Web' join the
    # 2017 'Patator' family under 'bruteforce'
    "bruteforce": ("Patator", "BruteForce", "Bruteforce", "Brute Force"),
    "bot": ("Bot",),
    "infiltration": ("Infil",),   # covers official 'Infiltration' + IDS2018 'Infilteration'
}

# class order used in the supervised model (index == class id)
CLASSES: list[str] = ["benign", "ddos", "scan", "bruteforce", "webattack",
                      "bot", "infiltration"]


def class_of(label: str | float | None) -> str | None:
    """Map a CIC label string to a consolidated threat class.

    Returns None for unrecognized non-null labels, the caller decides whether
    to drop them (never silently relabelled as benign).
    """
    if label is None or (isinstance(label, float) and np.isnan(label)):
        return "benign"
    s = str(label).strip()
    if s.lower() == "benign":   # BENIGN (2017/2019) + title case (2018)
        return "benign"
    for cls, keys in CLASS_LABELS.items():
        if any(k in s for k in keys):
            return cls
    return None


# --------------------------------------------------------------------------
# evaluation axis (consumed by scripts/benchmarks/bench_transfer.py)
# --------------------------------------------------------------------------
CANONICAL_CLASSES = ("ddos", "slowdos", "scan", "exfil", "benign")

# Explicit harmonization: target label -> canonical class. A label absent
# here is reported as unmapped (counted, never merged).
LABEL_MAPS: dict[str, dict[str, str]] = {
    "cic-ids2017-wednesday": {
        "BENIGN": "benign", "DoS Hulk": "ddos", "DoS GoldenEye": "ddos",
        "DoS slowloris": "slowdos", "DoS Slowhttptest": "slowdos",
        "Heartbleed": "benign",     # no volumetric/DoS-window mapping -> benign
    },
    # full week (8 day-files): the shape the max-scale pass scores. Web attacks
    # and Patator join scan on the canonical axis, like ICS2018 brute force;
    # Bot/Infiltration have no canonical flow-window key and stay unmapped.
    "cic-ids2017": {
        "BENIGN": "benign",
        "DoS Hulk": "ddos", "DoS GoldenEye": "ddos", "DDoS": "ddos",
        "DoS slowloris": "slowdos", "DoS Slowhttptest": "slowdos",
        "Heartbleed": "benign",
        "PortScan": "scan", "FTP-Patator": "scan", "SSH-Patator": "scan",
        "Web Attack \x96 Brute Force": "scan",
        "Web Attack \x96 XSS": "scan",
        "Web Attack \x96 Sql Injection": "scan",
        "Bot": "unmapped", "Infiltration": "unmapped",
    },
    "cic-ddos2019": {
        "DDoS": "ddos", "BENIGN": "benign", "WebDDoS": "ddos",
        # UDP-lag slow attack families map to slowdos where present:
        "UDPLag": "slowdos", "Syn": "ddos",
        # DrDoS (01-12) and reflection families (03-11), every one volumetric:
        "DrDoS_DNS": "ddos", "DrDoS_LDAP": "ddos", "DrDoS_MSSQL": "ddos",
        "DrDoS_NTP": "ddos", "DrDoS_NetBIOS": "ddos", "DrDoS_SNMP": "ddos",
        "DrDoS_SSDP": "ddos", "DrDoS_UDP": "ddos",
        "LDAP": "ddos", "MSSQL": "ddos", "NetBIOS": "ddos", "Portmap": "ddos",
        "TFTP": "ddos", "UDP": "ddos",
    },
    "cic-ids2018-nf-v2": {
        "Benign": "benign", "DDOS attack-HOIC": "ddos",
        "DDOS attack-LOIC-UDP": "ddos", "DDOS attack-LOIC-HTTP": "ddos",
        "DoS attacks-Hulk": "ddos", "DoS attacks-SlowHTTPTest": "slowdos",
        # both spellings occur: the corpus spells it 'Slowloris' with a hyphen
        "DoS attacks-Slowloris": "slowdos",
        "DoS attacks slowloris": "slowdos", "DoS attacks-GoldenEye": "ddos",
        "FTP-BruteForce": "scan", "SSH-Bruteforce": "scan",
        "Brute Force -Web": "scan", "Brute Force -XSS": "scan",
        "SQL Injection": "scan",
        # binary-only axes (no canonical mapping) -> reported unmapped:
        "Bot": "unmapped", "Infilteration": "unmapped", "Heartbleed": "unmapped",
    },
    # UNSW-NB15 multi-class axis: attack_cat, not the binary label (the binary
    # split cannot tell a DoS from a fuzzer). DoS and Reconnaissance have a
    # canonical key; the remaining families do not, and are kept off the benign
    # denominator by mapping them to 'unmapped' rather than leaving them absent.
    "unsw-nb15": {
        "Normal": "benign",
        "DoS": "ddos", "Reconnaissance": "scan",
        "Exploits": "unmapped", "Fuzzers": "unmapped", "Generic": "unmapped",
        "Analysis": "unmapped", "Backdoor": "unmapped",
        "Shellcode": "unmapped", "Worms": "unmapped",
    },
    "ctu13-heldout": {
        "Botnet": "benign",            # beacon is pair-level, not flow-window;
        "Normal": "benign",            # CTU-13 here = FPR pressure only
    },
}

# Permitted (class_of(label), canonical) pairs across LABEL_MAPS, with the
# reason each pair matches or deliberately differs. tests/detectors/test_labels.py
# walks every map entry against this table: a new/edited mapping whose pair
# is absent fails the suite until the change is documented HERE.
RELATIONSHIP: dict[tuple[str | None, str], str] = {
    ("benign", "benign"): "exact",
    ("ddos", "ddos"): "exact",
    ("ddos", "slowdos"): "production folds slow DoS into ddos; eval keeps slowdos",
    ("ddos", "benign"): "Heartbleed (2017): not volumetric/DoS-window -> benign pressure",
    ("ddos", "unmapped"): "Heartbleed (2018): binary axis only",
    ("bruteforce", "scan"): "IDS2018 brute-force families score as scan on the eval axis",
    ("scan", "scan"): "exact: 2017 PortScan reaches its own canonical class",
    ("webattack", "scan"): "2017 web attacks join scan, like the ICS2018 brute-force families",
    (None, "scan"): "SQL Injection and UNSW Reconnaissance: no production substring key",
    (None, "ddos"): "DrDoS_*/TFTP/LDAP-family and UNSW DoS labels lack a production substring key",
    (None, "slowdos"): "UDPLag: family label without a production substring key",
    (None, "unmapped"): "UNSW exploit/fuzzer/backdoor families have no canonical flow-window key",
    (None, "benign"): "UNSW 'Normal' / CTU 'Normal' corpus conventions",
    ("bot", "unmapped"): "Bot: binary-only axis, no canonical mapping",
    ("infiltration", "unmapped"): "Infilteration: binary-only axis, no canonical mapping",
    ("bot", "benign"): "CTU-13 heldout: FPR-pressure corpus only",
}


def resolve_label_map(name: str,
                      explicit: dict[str, str] | None) -> dict[str, str]:
    """Explicit map wins; else exact corpus match; else longest prefix match
    (so 'cic-ddos2019-selftest' reuses the 'cic-ddos2019' map)."""
    if explicit is not None:
        return explicit
    if name in LABEL_MAPS:
        return LABEL_MAPS[name]
    best = max((k for k in LABEL_MAPS if name.startswith(k)), key=len,
               default=None)
    return LABEL_MAPS.get(best, {}) if best else {}
