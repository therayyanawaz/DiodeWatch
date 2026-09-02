"""Egress enforcer: kernel-level outbound denial for the analytics identity.

The diode guarantee is a firewall property, not a code convention. This module
installs a host firewall profile that drops EVERY outbound packet of the
protected user (the uid the analytics pipeline runs as) except traffic on the
loopback interface, so the analytics stack can talk to local services
(Streamlit UI, local API, local resolver on 127.0.0.53) but is physically
unable to reach the monitored network or the internet.

Backends, in preference order:

1. **nftables** (primary; the Implementation Plan's choice), one `inet`
   table ``diode`` with an OUTPUT chain: ``meta skuid <uid> oif "lo" accept``
   then ``meta skuid <uid> counter drop``. The rule carries a counter so the
   kernel itself reports how many packets were dropped (live proof, read by
   the monitor).
2. **iptables** fallback for hosts without nftables, the same two rules via
   the ``owner`` match module, inserted at the top of OUTPUT with a
   ``diode-guard-<uid>`` comment marker.

Degradation contract (the nodal-centre rule): if root is unavailable, no
nftables/iptables binary exists, or rule installation fails, the enforcer
reports ``backend="none"`` with a human reason and the caller MUST fall back
to monitor-only mode, enforcement is never silently assumed.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field

NFT_TABLE = "inet diode"
NFT_CHAIN = "egress"
IPT_MARKER = "diode-guard"


@dataclass
class EnforceResult:
    """Outcome of an apply()/verify() call. `ok=False` ⇒ monitor-only mode."""
    ok: bool
    backend: str                # "nftables" | "iptables" | "none"
    reason: str = ""
    dropped_packets: int | None = None   # nftables counter when readable
    rules: list[str] = field(default_factory=list)


def protected_uid() -> int:
    """The uid the pipeline runs as: SUDO_UID (sudo caller) or the euid.

    When the enforcer is invoked through `sudo`, os.getuid() is 0 but the
    analytics processes run under the *invoking* user, protecting root would
    drop the wrong traffic. SUDO_UID disambiguates.
    """
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid is not None and sudo_uid.isdigit():
        return int(sudo_uid)
    getuid = getattr(os, "getuid", None)
    return getuid() if getuid is not None else -1


def render_nft_ruleset(uid: int) -> str:
    """Pure ruleset text for `nft -f -`. All outbound of `uid` except lo: drop."""
    return f"""table inet diode {{
    chain egress {{
        type filter hook output priority 0; policy accept;
        meta skuid {uid} oif "lo" accept
        meta skuid {uid} counter drop
    }}
}}
"""


def render_iptables_rules(uid: int) -> list[str]:
    """The two iptables rules (insert order matters: lo-accept lands first)."""
    marker = f"{IPT_MARKER}-{uid}"
    return [
        (f"iptables -I OUTPUT 1 -m owner --uid-owner {uid} "
         f"-m comment --comment {marker} -j DROP"),
        (f"iptables -I OUTPUT 1 -m owner --uid-owner {uid} -o lo "
         f"-m comment --comment {marker} -j ACCEPT"),
    ]


def _run(cmd: list[str], timeout: float = 10.0,
         input: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          check=False, input=input)


def detect_backend() -> tuple[str, str]:
    """Return (backend, reason). backend is 'nftables' | 'iptables' | 'none'."""
    if os.name != "posix" or not hasattr(os, "geteuid"):
        return "none", "egress enforcement requires Linux (this host is not POSIX/Linux)"
    if os.geteuid() != 0:
        return "none", "root required to install firewall rules (sudo unavailable or not used)"
    if shutil.which("nft"):
        return "nftables", ""
    if shutil.which("iptables"):
        return "iptables", ""
    return "none", "no nftables or iptables binary found on this host"


class Enforcer:
    """Install/verify/remove the egress-deny profile for one uid."""

    def __init__(self, backend: str | None = None) -> None:
        self.backend, self.reason = detect_backend() if backend is None else (backend, "")

    # ---- apply -------------------------------------------------------------
    def apply(self, uid: int) -> EnforceResult:
        if self.backend == "nftables":
            return self._apply_nft(uid)
        if self.backend == "iptables":
            return self._apply_iptables(uid)
        return EnforceResult(ok=False, backend="none", reason=self.reason)

    def _apply_nft(self, uid: int) -> EnforceResult:
        # fresh table: delete leftovers from a previous run, ignore errors
        _run(["nft", "delete", "table", NFT_TABLE])
        p = _run(["nft", "-f", "-"], input=render_nft_ruleset(uid))
        if p.returncode != 0:
            return EnforceResult(False, "nftables",
                                 f"nft apply failed: {p.stderr.strip() or p.stdout.strip()}")
        v = self.verify(uid)
        if not v.ok:
            return EnforceResult(False, "nftables",
                                 f"rules installed but verification failed: {v.reason}")
        return EnforceResult(True, "nftables", dropped_packets=v.dropped_packets,
                             rules=[l.strip() for l in render_nft_ruleset(uid).splitlines()
                                    if l.strip().startswith("meta skuid")])

    def _apply_iptables(self, uid: int) -> EnforceResult:
        for rule in render_iptables_rules(uid):   # drop first, then lo-accept
            p = _run(rule.split())
            if p.returncode != 0:
                return EnforceResult(False, "iptables",
                                     f"iptables failed: {p.stderr.strip() or p.stdout.strip()}")
        v = self.verify(uid)
        if not v.ok:
            return EnforceResult(False, "iptables",
                                 f"rules installed but verification failed: {v.reason}")
        return EnforceResult(True, "iptables", rules=render_iptables_rules(uid))

    # ---- verify ------------------------------------------------------------
    def verify(self, uid: int) -> EnforceResult:
        if self.backend == "nftables":
            return self._verify_nft(uid)
        if self.backend == "iptables":
            return self._verify_iptables(uid)
        return EnforceResult(False, "none", reason=self.reason)

    def _verify_nft(self, uid: int) -> EnforceResult:
        p = _run(["nft", "list", "chain", NFT_TABLE, NFT_CHAIN])
        if p.returncode != 0:
            return EnforceResult(False, "nftables",
                                 "diode table/chain missing from ruleset "
                                 f"(nft rc={p.returncode})")
        text = p.stdout
        if f'skuid {uid} oif "lo"' not in text or f"skuid {uid}" not in text:
            return EnforceResult(False, "nftables", "egress rules for uid missing")
        if "drop" not in text:
            return EnforceResult(False, "nftables", "drop rule missing")
        # counter: "meta skuid 0 counter packets 3 bytes 132 drop"
        dropped = None
        for tok in text.split():
            if tok == "packets":
                try:
                    dropped = int(text.split("packets")[1].split()[0])
                except (IndexError, ValueError):
                    pass
        return EnforceResult(True, "nftables", dropped_packets=dropped)

    def _verify_iptables(self, uid: int) -> EnforceResult:
        marker = f"{IPT_MARKER}-{uid}"
        for spec in (f"-m owner --uid-owner {uid} -m comment --comment {marker}",
                     f"-m owner --uid-owner {uid} -o lo -m comment --comment {marker}"):
            p = _run(["iptables", "-C", "OUTPUT", *spec.split()])
            if p.returncode != 0:
                return EnforceResult(False, "iptables", f"rule missing: {spec}")
        return EnforceResult(True, "iptables")

    # ---- remove ------------------------------------------------------------
    def remove(self, uid: int) -> None:
        """Best-effort removal of the diode profile (idempotent, never raises)."""
        if self.backend == "nftables":
            _run(["nft", "delete", "table", NFT_TABLE])
        elif self.backend == "iptables":
            # rule = iptables -I OUTPUT 1 -m owner ...  →  iptables -D OUTPUT -m owner ...
            for rule in render_iptables_rules(uid):
                _run(["iptables", "-D", "OUTPUT", *rule.split()[4:]])
