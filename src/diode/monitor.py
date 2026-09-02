"""Egress monitor: live proof of zero outbound traffic.

A small background component that periodically snapshots the protected uid's
sockets from the kernel's socket tables and writes a status JSON the UI polls:

* connection inventory from ``/proc/net/{tcp,tcp6,udp,udp6}`` (stdlib reads,
  no privileges, uid column per socket, works with zero install);
* per-socket byte counters from ``ss -tinaep`` (TCP_INFO over netlink) when
  available — ``bytes_sent`` summed over external peers is the Diode Proof
  number;
* violation events: any non-local, non-loopback socket of the protected uid
  that newly appears between ticks is an *attempted outbound connection* and
  is recorded (status JSON + append-only ndjson audit log). In enforced mode
  the kernel drops its packets, so ``outbound_bytes`` stays 0 — the monitor
  proves the guarantee and catches the attempts.

Degradation: on non-Linux hosts (no /proc/net) the monitor cannot observe
sockets; it still writes a status JSON with ``monitor_available: false`` and
an honest reason, so the UI never shows a fabricated zero.

The status JSON is written by the host whose innocence it attests, so it is an
*allegation*. ``assess()`` below is the single place that decides what a UI may
claim from it — every surface (FastAPI, both dashboards, both JS clients)
renders that verdict instead of re-deriving one from raw file fields.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# /proc/net state codes → names. Outbound-relevant states are the client-side
# ones; LISTEN / SYN-RECV / CLOSE are inbound or dead ends. UDP rows always
# carry code 07 (CLOSE) regardless of activity, so they are labelled "UDP".
STATE_NAMES = {"01": "ESTABLISHED", "02": "SYN-SENT", "03": "SYN-RECV",
               "04": "FIN-WAIT-1", "05": "FIN-WAIT-2", "06": "TIME-WAIT",
               "07": "CLOSE", "08": "CLOSE-WAIT", "09": "LAST-ACK",
               "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW-SYN-RECV"}
OUTBOUND_STATES = {"ESTABLISHED", "SYN-SENT", "FIN-WAIT-1", "FIN-WAIT-2",
                   "TIME-WAIT", "CLOSE-WAIT", "LAST-ACK", "CLOSING", "UDP"}
SS_STATE_FIX = {"ESTAB": "ESTABLISHED"}

PROC_FILES = {"tcp": "tcp", "tcp6": "tcp6", "udp": "udp", "udp6": "udp6"}

_IPV6_WORDS = re.compile(r"([0-9A-Fa-f]{8})")


@dataclass
class SocketEntry:
    """One socket row from /proc/net/* or ss."""
    proto: str
    local_addr: str
    local_port: int
    peer_addr: str
    peer_port: int
    state: str            # human name ("ESTABLISHED", "SYN-SENT", ...)
    uid: int
    bytes_sent: int | None = None
    bytes_received: int | None = None

    @property
    def key(self) -> tuple:
        return (self.proto, self.local_addr, self.local_port,
                self.peer_addr, self.peer_port)

    @property
    def peer(self) -> str:
        return f"{self.peer_addr}:{self.peer_port}"


# --------------------------------------------------------------------------- #
# /proc/net parsing
# --------------------------------------------------------------------------- #

def decode_ip(hex_addr: str) -> str:
    """Decode a /proc/net address field. IPv4 = 8 hex digits, IPv6 = 32."""
    if len(hex_addr) == 8:  # IPv4, little-endian dword
        raw = bytes.fromhex(hex_addr)
        return socket.inet_ntop(socket.AF_INET, raw[::-1])
    if len(hex_addr) == 32:  # IPv6, four little-endian dwords
        words = _IPV6_WORDS.findall(hex_addr)
        raw = b"".join(bytes.fromhex(w)[::-1] for w in words)
        return socket.inet_ntop(socket.AF_INET6, raw)
    return ""


def parse_proc_line(line: str, proto: str) -> SocketEntry | None:
    """Parse one /proc/net/{tcp,tcp6,udp,udp6} data line; None for headers/junk.

    Column layout: sl local_address rem_address st tx_queue:rx_queue
    tr:tm->when retrnsmt uid timeout inode ...
    """
    parts = line.split()
    if len(parts) < 10 or ":" not in parts[1]:
        return None
    local = parts[1].rsplit(":", 1)
    remote = parts[2].rsplit(":", 1)
    try:
        local_ip, local_port = decode_ip(local[0]), int(local[1], 16)
        peer_ip, peer_port = decode_ip(remote[0]), int(remote[1], 16)
        uid = int(parts[7])
    except (ValueError, IndexError):
        return None
    state = "UDP" if proto.startswith("udp") else STATE_NAMES.get(parts[3], parts[3])
    return SocketEntry(proto=proto, local_addr=local_ip, local_port=local_port,
                       peer_addr=peer_ip, peer_port=peer_port, state=state or parts[3],
                       uid=uid)


def read_proc_sockets(proc_dir: str | Path = "/proc/net") -> list[SocketEntry]:
    """All sockets from /proc/net; missing files (e.g. non-Linux) → empty list."""
    entries: list[SocketEntry] = []
    for proto, fname in PROC_FILES.items():
        try:
            with open(Path(proc_dir) / fname, encoding="utf-8") as fh:
                for line in fh:
                    e = parse_proc_line(line, proto)
                    if e is not None:
                        entries.append(e)
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return entries


# --------------------------------------------------------------------------- #
# ss byte counters (TCP_INFO via netlink)
# --------------------------------------------------------------------------- #

def run_ss(ss_bin: str = "ss", timeout: float = 6.0) -> str:
    """`ss -tinaep` output (tcp, all states, numeric, extended, processes)."""
    p = subprocess.run([ss_bin, "-tinaep"], capture_output=True, text=True,
                       timeout=timeout, check=False)
    return p.stdout


def parse_ss(text: str) -> list[SocketEntry]:
    """Parse `ss -tinaep` output into SocketEntries with byte counters.

    Format: header line `State Recv-Q Send-Q Local Address:Port Peer Address:Port
    Process`, then per socket a header row plus TAB-indented info rows carrying
    `bytes_sent:`, `bytes_received:` and `uid:` tokens.
    """
    out: list[SocketEntry] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        parts = lines[i].split()
        if len(parts) < 5 or parts[0] in ("State", "Id") or ":" not in parts[3]:
            i += 1
            continue
        state, local, peer = parts[0], parts[3], parts[4]
        state = SS_STATE_FIX.get(state, state)
        # collect continuation (info) lines of this socket
        j = i + 1
        info = []
        while j < len(lines) and lines[j].startswith("\t"):
            info.append(lines[j])
            j += 1
        i = j
        blk = " ".join([lines[i - 1], *info])
        m_uid = re.search(r"uid:(\d+)", blk)
        if m_uid is None:
            continue
        lp = _split_addr_port(local)
        pp = _split_addr_port(peer)
        if lp is None or pp is None:
            continue
        m_sent = re.search(r"bytes_sent:(\d+)", blk)
        m_recv = re.search(r"bytes_received:(\d+)", blk)
        # ss prints both families in one table while /proc splits them by file,
        # and poll() joins on the family-carrying key — so label the row the
        # same way /proc would. run_ss asks for TCP only: no udp here.
        out.append(SocketEntry(
            proto="tcp6" if ":" in lp[0] else "tcp", local_addr=lp[0], local_port=lp[1],
            peer_addr=pp[0], peer_port=pp[1], state=state,
            uid=int(m_uid.group(1)),
            bytes_sent=int(m_sent.group(1)) if m_sent else 0,
            bytes_received=int(m_recv.group(1)) if m_recv else 0))
    return out


def _split_addr_port(s: str) -> tuple[str, int] | None:
    """'1.2.3.4:80' or '[::1]:80' or '0.0.0.0:*' → (ip, port); None if bad."""
    try:
        if s.startswith("["):
            ip, _, rest = s[1:].partition("]")
            port = int(rest.lstrip(":"))
        else:
            ip, _, ps = s.rpartition(":")
            if ps == "*":
                return None
            port = int(ps)
        return ip, port
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# classification
# --------------------------------------------------------------------------- #

def _norm_addr(addr: str) -> Any:
    try:
        a = ipaddress.ip_address(addr)
        if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
            return a.ipv4_mapped
        return a
    except ValueError:
        return None


def host_local_addresses() -> set[Any]:
    """This host's own addresses (loopback + interface + hostname resolves)."""
    local: set[Any] = set()
    try:
        local.add(ipaddress.ip_address("127.0.0.1"))
        local.add(ipaddress.ip_address("::1"))
    except ValueError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            a = _norm_addr(info[4][0])
            if a is not None:
                local.add(a)
    except OSError:
        pass
    if os.name == "posix":
        try:  # /proc/net/if_inet6: plain-hex addr (byte order, unlike tcp6)
            with open("/proc/net/if_inet6", encoding="utf-8") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 1 and len(parts[0]) == 32:
                        try:
                            local.add(ipaddress.IPv6Address(int(parts[0], 16)))
                        except ValueError:
                            continue
        except (FileNotFoundError, OSError):
            pass
        try:  # interface IPv4 addresses via SIOCGIFADDR
            import fcntl
            import struct
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for _, name in socket.if_nameindex():  # (index, name) tuples
                try:
                    packed = fcntl.ioctl(s.fileno(), 0x8915,  # SIOCGIFADDR
                                         struct.pack("256s", name.encode()[:15]))
                    ip = socket.inet_ntoa(packed[20:24])
                    norm = _norm_addr(ip)
                    if norm is not None:
                        local.add(norm)
                except OSError:
                    continue
        except (ImportError, OSError):
            pass
    return local


def is_external(entry: SocketEntry, local_addrs: set[Any]) -> bool:
    """True when the socket is in an outbound state and its peer is neither
    loopback, one of this host's addresses, nor a no-peer placeholder."""
    if entry.state not in OUTBOUND_STATES:
        return False
    if entry.peer_port == 0 or entry.peer_addr in ("0.0.0.0", "::"):
        return False
    peer = _norm_addr(entry.peer_addr)
    if peer is None:
        return False
    # compare by string so callers may pass either ipaddress objects or strings
    return not peer.is_loopback and str(peer) not in {str(a) for a in local_addrs}


# --------------------------------------------------------------------------- #
# status model
# --------------------------------------------------------------------------- #

@dataclass
class DiodeStatus:
    """One monitor tick — the exact shape written to the status JSON."""
    timestamp: str
    monitor_available: bool
    mode: str                       # "enforced" | "monitor-only"
    backend: str                    # "nftables" | "iptables" | "none"
    backend_reason: str = ""
    protected_uid: int | None = None
    protected_user: str | None = None
    enforcement_verified: bool | None = None
    dropped_packets: int | None = None
    outbound_connections: int = 0
    # None means "not measured". Never default this to 0: an unobserved host
    # would otherwise render as a proven zero (see assess()).
    outbound_bytes: int | None = None
    bytes_accounting: str = "tcp-info"   # "tcp-info" | "proc-only"
    compliant: bool = False       # set only when the socket table was readable
    violations_total: int = 0
    violations: list[dict[str, Any]] = field(default_factory=list)
    local_addresses: list[str] = field(default_factory=list)
    last_error: str | None = None
    seq: int = 0                  # monotonic heartbeat counter (anti-rollback)
    writer_pid: int = field(default_factory=lambda: os.getpid())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "timestamp": self.timestamp,
            "monitor_available": self.monitor_available,
            "mode": self.mode,
            "backend": self.backend,
            "backend_reason": self.backend_reason,
            "protected_uid": self.protected_uid,
            "protected_user": self.protected_user,
            "enforcement_verified": self.enforcement_verified,
            "dropped_packets": self.dropped_packets,
            "outbound_connections": self.outbound_connections,
            "outbound_bytes": self.outbound_bytes,
            "bytes_accounting": self.bytes_accounting,
            "compliant": self.compliant,
            "violations_total": self.violations_total,
            "violations": self.violations,
            "local_addresses": self.local_addresses,
            "last_error": self.last_error,
            "seq": self.seq,
            "writer_pid": self.writer_pid,
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def poll(uid: int, *, proc_dir: str | Path = "/proc/net",
         local_addrs: set[Any] | None = None,
         ss_text: str | None = None,
         ss_bin: str | None = "ss",
         mode: str = "monitor-only", backend: str = "none",
         backend_reason: str = "", now: str | None = None) -> DiodeStatus:
    """One snapshot of the protected uid's outbound sockets.

    `ss_text` may be injected (tests); when it is None and `ss_bin` is None,
    byte accounting degrades to "proc-only".
    """
    ts = now or now_iso()
    local = local_addrs if local_addrs is not None else host_local_addresses()
    proc_entries = [e for e in read_proc_sockets(proc_dir) if e.uid == uid]
    outbound = [e for e in proc_entries if is_external(e, local)]

    # byte counters (ss success is tracked separately: empty output is fine)
    ss_ok = False
    ss_entries: list[SocketEntry] = []
    if ss_text is not None:
        ss_entries, ss_ok = parse_ss(ss_text), True
    elif ss_bin is not None and shutil.which(ss_bin):
        try:
            ss_entries, ss_ok = parse_ss(run_ss(ss_bin)), True
        except (subprocess.TimeoutExpired, OSError):
            pass
    bytes_accounting = "tcp-info" if ss_ok else "proc-only"

    by_key = {e.key: e for e in ss_entries if e.uid == uid}
    outbound_bytes = None
    if ss_ok:
        for e in outbound:
            info = by_key.get(e.key)
            if info is not None:
                e.bytes_sent = info.bytes_sent
                e.bytes_received = info.bytes_received
        # UDP asks for bytes through a different socket op and TCP_INFO has no
        # counter for it; a TCP socket can also be missing from ss when it dies
        # between the two reads. Either way that socket's egress is unknown, and
        # adding it as a zero would turn an unmeasured host into a proven clean
        # tick — so the total is withheld and the label says how many are unknown.
        uncounted = sum(1 for e in outbound
                        if not e.proto.startswith("tcp") or by_key.get(e.key) is None)
        if uncounted:
            bytes_accounting = f"tcp-info-{uncounted}-uncounted"
        else:
            outbound_bytes = sum(e.bytes_sent or 0 for e in outbound)

    violations = [{
        "timestamp": ts,
        "proto": e.proto,
        "peer": e.peer,
        "state": e.state,
        "bytes_sent": e.bytes_sent if e.bytes_sent else 0,
    } for e in outbound]

    user = None
    try:
        import pwd
        user = pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        pass

    # An unreadable socket table yields an empty `outbound` list, which must
    # not read as compliance: nothing was observed.
    available = bool(proc_entries) or Path(proc_dir).exists()

    return DiodeStatus(
        timestamp=ts,
        monitor_available=available,
        mode=mode, backend=backend, backend_reason=backend_reason,
        protected_uid=uid, protected_user=user,
        outbound_connections=len(outbound),
        outbound_bytes=outbound_bytes,
        bytes_accounting=bytes_accounting,
        compliant=available and not outbound,
        violations=violations,
        local_addresses=sorted(str(a) for a in local),
    )


def write_json(path: Path, obj: dict[str, Any]) -> None:
    """Atomic write (tmp file + rename) so the UI never reads a half-written tick."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, default=str)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def diff_outbound(prev: set[tuple], cur: set[tuple]) -> list[tuple]:
    """Newly appeared outbound socket keys (attempted connections)."""
    if prev is None:
        return sorted(cur)
    return sorted(cur - prev)


# --------------------------------------------------------------------------- #
# background loop
# --------------------------------------------------------------------------- #

class Monitor:
    """Periodic poller: writes status JSON + violation audit events.

    First tick establishes the baseline; sockets already outbound at startup
    are still recorded as violations (they exist ⇒ something connected).
    """

    def __init__(self, uid: int, *, interval: float = 2.0,
                 status_file: str | Path = "data/diode_status.json",
                 events_file: str | Path | None = "data/diode_events.ndjson",
                 enforcer=None, proc_dir: str | Path = "/proc/net",
                 local_addrs: set[Any] | None = None,
                 ss_bin: str | None = "ss") -> None:
        self.uid = uid
        self.interval = interval
        self.status_file = Path(status_file)
        self.events_file = Path(events_file) if events_file else None
        self.enforcer = enforcer
        self.proc_dir = proc_dir
        self.local_addrs = local_addrs
        self.ss_bin = ss_bin

    # -- one tick ------------------------------------------------------------
    def tick(self) -> DiodeStatus:
        mode = "monitor-only"
        backend = "none"
        backend_reason = ""
        verified: bool | None = None
        dropped = None
        if self.enforcer is not None:
            mode = "enforced"
            backend = self.enforcer.backend
            backend_reason = self.enforcer.reason
            v = self.enforcer.verify(self.uid)
            verified = v.ok
            dropped = v.dropped_packets
            if not v.ok:
                backend_reason = v.reason or backend_reason

        st = poll(self.uid, proc_dir=self.proc_dir, local_addrs=self.local_addrs,
                  ss_bin=self.ss_bin, mode=mode, backend=backend,
                  backend_reason=backend_reason)
        st.enforcement_verified = verified
        st.dropped_packets = dropped
        return st

    # -- loop ----------------------------------------------------------------
    def run(self, *, once: bool = False, max_violations_in_status: int = 20,
            max_ticks: int | None = None) -> int:
        prev: set[tuple] | None = None
        violations_total = 0
        recent: list[dict[str, Any]] = []
        ticks = 0
        seq = next_seq(self.status_file)
        try:
            while True:
                st = self.tick()
                local = (self.local_addrs if self.local_addrs is not None
                         else host_local_addresses())
                entries = [e for e in read_proc_sockets(self.proc_dir)
                           if e.uid == self.uid and is_external(e, local)]
                cur = {e.key: e for e in entries}
                # diff_outbound reports the whole set when there is no previous
                # tick: a socket already outbound when the monitor started is
                # evidence, not a baseline to forgive.
                for key in diff_outbound(prev, set(cur)):
                    e = cur[key]
                    ev = {"timestamp": now_iso(), "uid": self.uid,
                          "proto": e.proto, "local": f"{e.local_addr}:{e.local_port}",
                          "peer": e.peer, "state": e.state,
                          "note": "outbound connection attempted "
                                  "(kernel drops it in enforced mode)"}
                    violations_total += 1
                    recent.append(ev)
                    recent = recent[-max_violations_in_status:]
                    if self.events_file is not None:
                        self._append_event(ev)
                prev = set(cur)
                st.violations_total = violations_total
                st.violations = recent
                st.seq = seq
                seq += 1
                write_json(self.status_file, st.to_dict())
                ticks += 1
                if once or (max_ticks is not None and ticks >= max_ticks):
                    return 0
                time.sleep(self.interval)
        except KeyboardInterrupt:
            return 0

    def _append_event(self, ev: dict[str, Any]) -> None:
        self.events_file.parent.mkdir(parents=True, exist_ok=True)
        with self.events_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev) + "\n")


def read_status(path: str | Path = "data/diode_status.json") -> dict[str, Any] | None:
    """Latest status JSON as a dict (None when the monitor never ran)."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


# --------------------------------------------------------------------------- #
# proof assessment — the trust boundary
# --------------------------------------------------------------------------- #

# A tick older than this describes a dead monitor, not a clean host. Read once,
# here: an operator-tightened window must not mean "stale" on the wall and
# "fresh" on the dashboard below it.
PROOF_MAX_AGE_S = float(os.environ.get("DIODE_PROOF_MAX_AGE_S", "90"))

_SCOPE_NOTE = ("scoped to the protected uid and to kernel TCP/UDP socket "
               "tables: other uids, and raw/AF_PACKET sends, are outside what "
               "both the enforcer and this monitor can see")


def _epoch_of(value: Any) -> float | None:
    """ISO-8601 status timestamp → unix seconds (None when unparsable)."""
    try:
        dt = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def assess(status: dict[str, Any] | None, *, now_epoch: float | None = None,
           max_age_s: float = PROOF_MAX_AGE_S,
           last_seq: int | None = None) -> dict[str, Any]:
    """Decide what a UI may claim from a self-reported status JSON.

    `proof` is "pass" only when a live monitor actually measured zero outbound
    bytes; "fail" when it measured some; "unknown" in every other case — which
    is what keeps an absent observer from rendering as a green zero. `verdict`
    is the single label every surface must show.

    `last_seq` lets a long-lived reader detect a rewound heartbeat: a status
    file whose counter went backwards was replaced, not written by the monitor
    that produced the one seen before.
    """
    now = time.time() if now_epoch is None else now_epoch
    if not isinstance(status, dict):
        return {"verdict": "NO-STATUS", "proof": "unknown", "observed": False,
                "stale": True, "age_s": None, "seq": None,
                "reasons": ["no status JSON — the egress monitor has never run"]}

    reasons: list[str] = []
    ts = _epoch_of(status.get("timestamp"))
    age_s = None if ts is None else round(now - ts, 1)
    stale = False
    if age_s is None:
        stale = True
        reasons.append("status has no parsable timestamp")
    elif age_s < -max_age_s:
        stale = True
        reasons.append(f"status is timestamped {-age_s:.0f}s in the future — "
                       "clock advanced or file hand-edited")
    elif age_s > max_age_s:
        stale = True
        reasons.append(f"last heartbeat {age_s:.0f}s old (> {max_age_s:.0f}s) — "
                       "the monitor process is not writing")

    seq = status.get("seq")
    seq = seq if isinstance(seq, int) and not isinstance(seq, bool) else None
    if stale and seq is None:
        reasons.append("no heartbeat counter in status (pre-v2 monitor)")
    if last_seq is not None and seq is not None and seq < last_seq:
        stale = True
        reasons.append(f"heartbeat rewound from seq {last_seq} to {seq} — the "
                       "status file was replaced rather than written by the "
                       "monitor this reader was watching")

    available = status.get("monitor_available") is True
    raw_bytes = status.get("outbound_bytes")
    measured = isinstance(raw_bytes, int) and not isinstance(raw_bytes, bool)
    observed = available and measured
    if not available:
        reasons.append("this host exposes no kernel socket table "
                       f"({status.get('backend_reason') or status.get('last_error') or 'no /proc/net'})")
    elif not measured:
        acct = str(status.get("bytes_accounting") or "")
        # ss may have run and simply had no counter for some sockets; saying
        # "no ss/TCP_INFO" then would blame a tool that worked and hide which
        # sockets went unmeasured.
        if "uncounted" in acct:
            why = (f"{acct.rsplit('-', 2)[1] if '-' in acct else '?'} outbound "
                   "socket(s) had no TCP_INFO counter")
        elif not acct or acct == "proc-only":
            why = "no ss/TCP_INFO on this host"
        else:
            why = f"byte accounting reported {acct}"
        reasons.append(f"byte total withheld ({why}) — an unmeasured zero is "
                       "not a proven zero")

    mode = status.get("mode")
    verified = status.get("enforcement_verified") is True
    if stale:
        verdict, proof = "STALE", "unknown"
    elif not observed:
        verdict, proof = "NO-OBSERVATION", "unknown"
    elif raw_bytes > 0:
        verdict, proof = "EGRESS-OBSERVED", "fail"
        reasons.append(f"{raw_bytes} bytes left the protected identity")
    elif mode == "enforced" and verified:
        verdict, proof = "ENFORCED-VERIFIED", "pass"
    elif mode == "enforced":
        verdict, proof = "ENFORCED-UNVERIFIED", "pass"
        reasons.append("kernel rules could not be re-verified this tick — "
                       "the byte count is real, the blocking is unproven")
    else:
        verdict, proof = "MONITOR-ONLY-CLEAN", "pass"
        reasons.append("observed clean, but nothing on this host is blocking "
                       "egress — this is a measurement, not a guarantee")
    reasons.append(_SCOPE_NOTE)
    return {"verdict": verdict, "proof": proof, "observed": observed,
            "stale": stale, "age_s": age_s, "seq": seq, "reasons": reasons}


def default_status_path() -> Path:
    """Where the monitor writes, and therefore where every reader looks.

    `DIODE_STATUS_FILE` is honoured here rather than per surface, so a
    relocated status file cannot be live on one UI and missing on the next.
    """
    return Path(os.environ.get(
        "DIODE_STATUS_FILE",
        str(Path(__file__).resolve().parents[2] / "data" / "diode_status.json")))


class ProofReader:
    """One reader's worth of diode proof: the file, the verdict, and the
    heartbeat memory that catches a rewound counter on the next read.

    Every surface reads through this so "stale" and "rewound" mean one thing
    across the product. The status file is written by the very host it attests,
    so what a reader hands a UI is the verdict, never the raw fields.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else None
        self.last_seq: int | None = None

    @property
    def path(self) -> Path:
        # resolved on every read, so the file can be moved after import
        return self._path or default_status_path()

    def read(self) -> dict[str, Any]:
        status = read_status(self.path)
        if not isinstance(status, dict):
            return {"available": False, "path": str(self.path),
                    "proof": assess(None)}
        verdict = assess(status, last_seq=self.last_seq)
        seq = verdict.get("seq")
        if isinstance(seq, int) and (self.last_seq is None or seq >= self.last_seq):
            self.last_seq = seq
        status["available"] = True
        status["proof"] = verdict
        status["path"] = str(self.path)
        return status


def next_seq(status_file: str | Path) -> int:
    """Heartbeat value for the next tick: one past the file's last counter."""
    prev = read_status(status_file)
    if isinstance(prev, dict):
        s = prev.get("seq")
        if isinstance(s, int) and not isinstance(s, bool) and s > 0:
            return s + 1
    return 1
