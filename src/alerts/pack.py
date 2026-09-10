"""Demo pack registry: one place that knows the six scenario captures.

The dashboard sidebar offers the pack's pcaps as replay sources next to the
combined demo capture. This module is the streamlit-free contract between the
pack generator (scripts/generators/make_demo_pack.py), the manifest it writes, and the
UI: labels, story captions, and which detector is expected to fire.

The ML-channel scenarios (C2 beacon, DNS tunnel) are detected by their own
models, not the windowed rule replay. `ml_channel_alerts` scores the sidecar
input exactly as `python -m src.detectors.ml_engine` would (same loaders,
same models, same thresholds), and `MlChannelReplay` releases those alerts
progressively in capture-time order while the Live tab's rule replay
advances, so beacon/DGA alerts appear in the alert feed as the scenario
unfolds, alongside (or instead of) rule alerts.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from src.alerts.schema import Alert

REPO = Path(__file__).resolve().parents[2]
PACK_DIR = REPO / "data" / "pcaps" / "pack"


@dataclass(frozen=True)
class PackSource:
    """One replayable pack scenario."""

    key: str                      # manifest stem, e.g. "01_ddos"
    pcap: Path
    label: str                    # sidebar label
    story: str                    # one-line caption under the selector
    rule_expected: tuple[str, ...]
    detector_note: str            # how the scenario is detected


def _manifest() -> dict | None:
    p = PACK_DIR / "pack_manifest.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def ensure_pack() -> list[PackSource]:
    """Return the pack sources, generating the pack once if missing."""
    if _manifest() is None:
        subprocess.run(
            [sys.executable, str(REPO / "scripts" / "generators" / "make_demo_pack.py")],
            cwd=REPO, check=False, capture_output=True, text=True)
    man = _manifest() or {}
    items = {item["pcap"]: item for item in man.get("pack", [])}

    def exp(stem: str) -> dict:
        return (items.get(f"{stem}.pcap") or {}).get("expected") or {}

    return [
        PackSource(
            key="01_ddos",
            pcap=PACK_DIR / "01_ddos.pcap",
            label="01 · DDoS flood",
            story="benign mix → 900-host SYN flood → calm",
            rule_expected=tuple(exp("01_ddos").get("rule_expected") or ()),
            detector_note="Rule layer fires in the Live replay.",
        ),
        PackSource(
            key="02_c2_beacon",
            pcap=PACK_DIR / "02_c2_beacon.pcap",
            label="02 · C2 beaconing (ML)",
            story="benign mix → two infected hosts calling one controller",
            rule_expected=tuple(exp("02_c2_beacon").get("rule_expected") or ()),
            detector_note=(
                "Detected by the beacon channel (pair periodicity on the "
                "NetFlow sidecar derived from this pcap), its alerts surface "
                "in the Live feed as the scenario replays; the windowed rule "
                "replay stays silent by design."),
        ),
        PackSource(
            key="03_dga_tunnel",
            pcap=PACK_DIR / "03_dga_tunnel.pcap",
            label="03 · DNS tunnel / DGA (ML)",
            story="benign DNS → 46 base32 tunnel + random-SLD queries",
            rule_expected=tuple(exp("03_dga_tunnel").get("rule_expected") or ()),
            detector_note=(
                "Detected by the DGA channel (lexical model on the queried "
                "names), alerts surface in the Live feed timed to each DNS "
                "query as it replays; the rule replay stays silent by design."),
        ),
        PackSource(
            key="04_exfil_scan",
            pcap=PACK_DIR / "04_exfil_scan.pcap",
            label="04 · Exfil + port scan",
            story="benign mix → 60-port sweep → 19 MB bulk upload",
            rule_expected=tuple(exp("04_exfil_scan").get("rule_expected") or ()),
            detector_note="Rule layer fires in the Live replay.",
        ),
        PackSource(
            key="05_slowloris",
            pcap=PACK_DIR / "05_slowloris.pcap",
            label="05 · Slow-rate DoS",
            story="benign mix → 40 held dribbles, no volumetric footprint",
            rule_expected=tuple(exp("05_slowloris").get("rule_expected") or ()),
            detector_note="Rule layer fires in the Live replay.",
        ),
        PackSource(
            key="06_exfil_ratio",
            pcap=PACK_DIR / "06_exfil_ratio.pcap",
            label="06 · Ratio exfiltration",
            story="benign mix → 28:1 asymmetric upload under the bulk bar",
            rule_expected=tuple(exp("06_exfil_ratio").get("rule_expected") or ()),
            detector_note="Rule layer fires in the Live replay.",
        ),
    ]


def available_sources() -> list[PackSource]:
    """Only the sources whose pcap actually exists on disk."""
    return [s for s in ensure_pack() if s.pcap.exists()]


# --------------------------------------------------------------------------- #
# ML-channel replay: sidecar-scoring alerts released in capture-time order
# --------------------------------------------------------------------------- #
def ml_channel_alerts(key: str) -> list[Alert]:
    """Score a scenario's sidecar through its ML channel, exactly as the
    ml_engine CLI would. Alerts come back sorted by capture time (when known).

    * 02_c2_beacon: the NetFlow sidecar (derived from the pcap through the
      real ingest) through the pair-periodicity BeaconModel.
    * 03_dga_tunnel: the domains sidecar through the lexical DgaModel. Alerts
      are back-timed from the pcap's own DNS packets so they surface while
      the queries replay.

    Every other scenario has no ML channel and returns []. Model artifacts
    missing => [] as well: the UI already says the channel needs models.
    """
    import pandas as pd

    if key == "02_c2_beacon":
        from src.detectors.ml import beacon as beacon_mod

        csv_path = PACK_DIR / "02_c2_beacon_netflow.csv"
        if not csv_path.exists():
            return []
        flows = beacon_mod.load_ctu(csv_path)
        pairs = beacon_mod.pair_series(flows)
        model = beacon_mod.BeaconModel.load(REPO / "models")
        scores = model.predict_score(pairs)
        # ts_first per pair -> release time (works for both model and rule modes)
        got = beacon_mod.emit_alerts(
            pairs, scores, threshold=model.threshold if model.booster is not None
            else 0.5)
        got.sort(key=lambda a: a.timestamp or "")
        return got

    if key == "03_dga_tunnel":
        from src.detectors.ml.dga import DgaModel

        txt = PACK_DIR / "03_dga_domains.txt"
        if not txt.exists():
            return []
        domains = pd.Series(
            [ln.strip() for ln in txt.read_text(encoding="utf-8").splitlines()
             if ln.strip()], dtype="string")
        try:
            model = DgaModel.load(REPO / "models")
        except FileNotFoundError:
            model = DgaModel.fallback()
            if not bool((model.score_domains(domains) >= 0.5).any()):
                return []
            model.threshold = 0.5
        scores = model.score_domains(domains)
        got = model.emit_alerts(domains, scores, threshold=model.threshold)
        # Back-time each alert from the pcap's own DNS packets: the DGA alerts
        # carry no timestamp, so give them the query time of their domain -
        # the alert then appears while that query replays.
        qts = _dns_query_times()
        for a in got:
            name = str((a.key or "").strip(".").lower())
            ts = qts.get(name)
            if ts is not None:
                a.timestamp = ts
        got.sort(key=lambda a: a.timestamp or "")
        return got

    return []


def _dns_query_times() -> dict[str, str]:
    """{domain: iso-ts} for the DNS queries in 03_dga_tunnel.pcap (pkt layer)."""
    from scapy.all import DNS, PcapReader

    pcap = PACK_DIR / "03_dga_tunnel.pcap"
    out: dict[str, str] = {}
    if not pcap.exists():
        return out
    try:
        from scapy.all import PcapReader
        with PcapReader(str(pcap)) as reader:
            for pkt in reader:
                dns = pkt.getlayer(DNS)
                if dns is None or dns.qd is None or int(dns.qdcount or 0) < 1:
                    continue
                qname = getattr(dns.qd, "qname", b"") or b""
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                name = str(qname).rstrip(".\x00").lower()
                if not name:
                    continue
                ts = float(pkt.time)
                out.setdefault(name, pd_ts_iso(ts))
    except (OSError, ValueError):
        return {}
    return out


def pd_ts_iso(ts_epoch: float) -> str:
    """Epoch seconds -> ISO-8601 UTC (the alert schema's timestamp format)."""
    import pandas as pd

    return (pd.Timestamp(ts_epoch, unit="s", tz="UTC").isoformat())


@dataclass
class MlChannelReplay:
    """Progressive release of ML-channel alerts during a Live replay.

    The sidecar is scored once up front (`ml_channel_alerts`); `due()` then
    yields every alert whose capture timestamp is at or before the replay's
    current clock, so the alert feed fills exactly when the traffic that
    caused it replays. Stateless and streamlit-free: the UI keeps one of
    these in st.session_state next to the window generator.
    """

    alerts: list[Alert] = field(default_factory=list)
    cursor: int = 0

    @classmethod
    def for_scenario(cls, key: str) -> MlChannelReplay:
        return cls(alerts=ml_channel_alerts(key))

    @property
    def total(self) -> int:
        return len(self.alerts)

    def due(self, clock_epoch: float) -> list[Alert]:
        """Alerts with timestamp <= clock not yet released (in order)."""
        out: list[Alert] = []
        while self.cursor < len(self.alerts):
            ts = self.alerts[self.cursor].timestamp
            if not ts:
                break
            try:
                t = pd_ts_to_epoch(ts)
            except (ValueError, TypeError, OverflowError):
                break
            if t > clock_epoch:
                break
            out.append(self.alerts[self.cursor])
            self.cursor += 1
        return out

    def drain_all(self) -> list[Alert]:
        """Release everything remaining (end of replay / timestampless alerts)."""
        out = self.alerts[self.cursor:]
        self.cursor = len(self.alerts)
        return out


def pd_ts_to_epoch(ts_iso: str) -> float:
    """ISO-8601 (any tz) -> epoch seconds."""
    import pandas as pd

    t = pd.Timestamp(ts_iso)
    if t.tzinfo is None:
        t = t.tz_localize("UTC")
    return t.timestamp()
