"""Diode Guard tests: egress enforcer + egress monitor.

The enforcer and monitor are pure-stdlib and testable without privileges:
proc/ss parsing uses injected fixtures, ruleset rendering is a pure function,
and backend detection is monkeypatched. The root-level acceptance (real
firewall rules, blocked external connect, zero bytes) lives in
`scripts/check_diode.py`, which is skipped here.
"""
from __future__ import annotations

import json
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.diode.enforcer import (
    Enforcer,
    EnforceResult,
    detect_backend,
    protected_uid,
    render_iptables_rules,
    render_nft_ruleset,
)
from src.diode.monitor import (
    Monitor,
    ProofReader,
    assess,
    decode_ip,
    diff_outbound,
    is_external,
    next_seq,
    now_iso,
    parse_proc_line,
    parse_ss,
    poll,
    read_status,
    write_json,
)

LOCAL = {"127.0.0.1", "::1", "10.0.0.5", "fe80::1"}

# --- /proc/net/tcp fixtures (real column layout) ---------------------------
TCP_EXT_ESTAB = ("  0: 0100007F:1F90 5D8C0A8C:01BB 01 00000000:00000000 "
                 "00:00000000 00000000  1000        0 12345 1 "
                 "0000000000000000 100 0 0 10 0")          # 127.0.0.1:8080 -> 140.10.140.93:443
TCP_EXT_SYNSENT = ("  1: 0100007F:C350 08080808:01BB 02 00000000:00000000 "
                   "00:00000000 00000000  1000        0 12346 1 "
                   "0000000000000000 100 0 0 10 0")        # 127.0.0.1:50000 -> 8.8.8.8:443
TCP_LISTEN = ("  2: 00000000:01BD 00000000:0000 0A 00000000:00000000 "
              "00:00000000 00000000  1000        0 12347 1 "
              "0000000000000000 100 0 0 10 0")             # 0.0.0.0:445 LISTEN
TCP_LOOPBACK = ("  3: 0100007F:1F90 0100007F:01BB 01 00000000:00000000 "
                "00:00000000 00000000  1000        0 12348 1 "
                "0000000000000000 100 0 0 10 0")           # loopback ESTAB
TCP_OTHER_UID = TCP_EXT_ESTAB.replace("  1000", "  1001", 1)
TCP6_EXT = ("  0: 00000000000000000000000001000000:115C "
            "B80D0120000000000000000001000000:01BB 01 00000000:00000000 "
            "00:00000000 00000000  1000        0 12349 1 "
            "0000000000000000 100 0 0 10 0")               # [::1]:4444 -> [2001:db8::1]:443
TCP6_LOOPBACK = ("  1: 00000000000000000000000001000000:1F90 "
                 "00000000000000000000000001000000:01BB 01 00000000:00000000 "
                 "00:00000000 00000000  1000        0 12350 1 "
                 "0000000000000000 100 0 0 10 0")          # [::1]:8080 -> [::1]:443
TCP6_V4MAPPED = ("  2: 0000000000000000FFFF00000100007F:1F90 "
                 "0000000000000000FFFF00000100007F:01BB 01 00000000:00000000 "
                 "00:00000000 00000000  1000        0 12351 1 "
                 "0000000000000000 100 0 0 10 0")          # ::ffff:127.0.0.1 both ends
UDP_EXT = ("  0: 0100007F:0035 5D8C0A8C:0035 07 00000000:00000000 "
           "00:00000000 00000000  1000        0 31455 2 "
           "0000000000000000 0")                            # 127.0.0.1:53 -> 140.12.140.93:53
UDP_IDLE = ("  1: 0100007F:0035 00000000:0000 07 00000000:00000000 "
            "00:00000000 00000000  1000        0 31456 2 "
            "0000000000000000 0")                           # bound, no peer


# --------------------------------------------------------------------------- #
# address decoding
# --------------------------------------------------------------------------- #

def test_decode_ip_v4_little_endian():
    assert decode_ip("0100007F") == "127.0.0.1"
    assert decode_ip("5D8C0A8C") == "140.10.140.93"
    assert decode_ip("08080808") == "8.8.8.8"


def test_decode_ip_v6_word_swapped():
    assert decode_ip("00000000000000000000000001000000") == "::1"
    assert decode_ip("B80D0120000000000000000001000000") == "2001:db8::1"
    assert decode_ip("0000000000000000FFFF00000100007F") == "::ffff:127.0.0.1"


def test_parse_proc_line_fields():
    e = parse_proc_line(TCP_EXT_ESTAB, "tcp")
    assert e is not None
    assert (e.proto, e.local_addr, e.local_port, e.peer_addr, e.peer_port,
            e.state, e.uid) == ("tcp", "127.0.0.1", 8080,
                                "140.10.140.93", 443, "ESTABLISHED", 1000)


def test_parse_proc_line_states_and_udp():
    assert parse_proc_line(TCP_EXT_SYNSENT, "tcp").state == "SYN-SENT"
    assert parse_proc_line(TCP_LISTEN, "tcp").state == "LISTEN"
    u = parse_proc_line(UDP_EXT, "udp")
    assert u.state == "UDP" and u.peer_port == 53
    assert parse_proc_line("garbage", "tcp") is None
    assert parse_proc_line("sl local_address ...", "tcp") is None


# --------------------------------------------------------------------------- #
# classification
# --------------------------------------------------------------------------- #

def test_is_external_classification():
    cases = [
        (parse_proc_line(TCP_EXT_ESTAB, "tcp"), True),
        (parse_proc_line(TCP_EXT_SYNSENT, "tcp"), True),
        (parse_proc_line(TCP_LOOPBACK, "tcp"), False),
        (parse_proc_line(TCP_LISTEN, "tcp"), False),
        (parse_proc_line(TCP6_EXT, "tcp6"), True),
        (parse_proc_line(TCP6_LOOPBACK, "tcp6"), False),
        (parse_proc_line(TCP6_V4MAPPED, "tcp6"), False),
        (parse_proc_line(UDP_EXT, "udp"), True),
        (parse_proc_line(UDP_IDLE, "udp"), False),
    ]
    for e, expected in cases:
        assert is_external(e, LOCAL) is expected, (e, expected)


def test_host_own_address_is_not_external():
    e = parse_proc_line(TCP_EXT_ESTAB.replace("5D8C0A8C", "0500000A"), "tcp")
    # 10.0.0.5 is in LOCAL -> localhost-to-self connection is not outbound
    assert e.peer_addr == "10.0.0.5"
    assert is_external(e, LOCAL) is False


# --------------------------------------------------------------------------- #
# ss byte counters
# --------------------------------------------------------------------------- #

SS_FIXTURE = """State Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
ESTAB 0      0          127.0.0.1:8080      140.10.140.93:443 ino:9018 sk:4 cgroup:/init.scope <->
\t ts sack cubic wscale:10,10 rto:204 rtt:0.039/0.018 ato:40 mss:52736 pmtu:65535 rcvmss:1100 advmss:65483 cwnd:10 bytes_sent:5000 bytes_acked:5000 bytes_received:1100 segs_out:2 segs_in:4 data_segs_out:1 data_segs_in:1 send 108176410256bps lastsnd:508 lastrcv:508 lastack:508 pacing_rate 213614177208bps delivery_rate 14547862064bps delivered:2 app_limited rcv_space:65483 rcv_ssthresh:68537 minrtt:0.029 snd_wnd:105472 rcv_wnd:68608 uid:1000
SYN-SENT 0    1          127.0.0.1:50000    8.8.8.8:443 ino:11411 sk:5 cgroup:/init.scope <->
\t ts sack cubic wscale:10,10 rto:204 rtt:0.09/0.05 ato:40 mss:34304 pmtu:65535 rcvmss:5000 advmss:65483 cwnd:10 segs_out:1 segs_in:0 send 30492444444bps lastsnd:508 lastrcv:508 lastack:508 pacing_rate 60480881536bps delivery_rate 10555076920bps delivered:2 app_limited rcv_space:65495 rcv_ssthresh:104585 minrtt:0.026 snd_wnd:68608 rcv_wnd:105472 uid:1000
ESTAB 0      0          [::1]:4444          [2001:db8::1]:443 ino:9019 sk:6 cgroup:/init.scope <->
\t ts sack cubic wscale:10,10 rto:204 rtt:0.05/0.02 ato:40 mss:1440 pmtu:1500 bytes_sent:3000 bytes_acked:3000 bytes_received:700 segs_out:2 segs_in:4 data_segs_out:1 data_segs_in:1 uid:1000
LISTEN 0      4096       127.0.0.54:53       0.0.0.0:*     users:(("systemd-resolve",pid=85,fd=19)) uid:989 ino:146 sk:2 cgroup:/system.slice/systemd-resolved.service <->
"""


def test_parse_ss_entries_with_bytes():
    entries = parse_ss(SS_FIXTURE)
    by_peer = {e.peer: e for e in entries}
    assert by_peer["140.10.140.93:443"].bytes_sent == 5000
    assert by_peer["140.10.140.93:443"].bytes_received == 1100
    assert by_peer["140.10.140.93:443"].state == "ESTABLISHED"  # ESTAB normalized
    assert by_peer["8.8.8.8:443"].bytes_sent == 0               # no bytes_sent token
    assert by_peer["8.8.8.8:443"].uid == 1000
    assert all(e.uid == 1000 for e in entries)
    assert len(entries) == 3   # the LISTEN row's peer 0.0.0.0:* is a no-peer placeholder
    # bracketed addresses are the v6 family, and the brackets are not part of it
    assert by_peer["2001:db8::1:443"].proto == "tcp6"
    assert by_peer["2001:db8::1:443"].local_addr == "::1"
    assert by_peer["2001:db8::1:443"].bytes_sent == 3000
    assert by_peer["140.10.140.93:443"].proto == "tcp"



# --------------------------------------------------------------------------- #
# poll() end-to-end with fake /proc + fake ss
# --------------------------------------------------------------------------- #

def _write_proc_dir(tmp_path: Path) -> Path:
    d = tmp_path / "procnet"
    d.mkdir()
    (d / "tcp").write_text(f"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                           f"{TCP_EXT_ESTAB}\n{TCP_EXT_SYNSENT}\n{TCP_LISTEN}\n{TCP_LOOPBACK}\n{TCP_OTHER_UID}\n",
                           encoding="utf-8")
    (d / "tcp6").write_text(f"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                            f"{TCP6_EXT}\n{TCP6_LOOPBACK}\n{TCP6_V4MAPPED}\n", encoding="utf-8")
    (d / "udp").write_text(f"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                           f"{UDP_EXT}\n{UDP_IDLE}\n", encoding="utf-8")
    (d / "udp6").write_text("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
                            encoding="utf-8")
    return d


def _clean_proc_dir(d: Path) -> None:
    """Rewrite all /proc fixtures to loopback/listen only (zero outbound)."""
    hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    (d / "tcp").write_text(hdr + f"{TCP_LOOPBACK}\n{TCP_LISTEN}\n", encoding="utf-8")
    (d / "tcp6").write_text(hdr + f"{TCP6_LOOPBACK}\n", encoding="utf-8")
    (d / "udp").write_text(hdr + f"{UDP_IDLE}\n", encoding="utf-8")
    (d / "udp6").write_text(hdr, encoding="utf-8")


def test_poll_counts_outbound_and_merges_ss_bytes(tmp_path):
    d = _write_proc_dir(tmp_path)
    st = poll(1000, proc_dir=d, local_addrs=LOCAL, ss_text=SS_FIXTURE)
    # external: tcp ESTAB + tcp SYN-SENT + tcp6 ext + udp ext = 4
    assert st.outbound_connections == 4
    assert st.compliant is False
    peers = {v["peer"] for v in st.violations}
    assert peers == {"140.10.140.93:443", "8.8.8.8:443", "2001:db8::1:443",
                     "140.10.140.93:53"}
    # every socket's own counters, including the IPv6 one ss prints bracketed
    assert {v["peer"]: v["bytes_sent"] for v in st.violations} == {
        "140.10.140.93:443": 5000, "8.8.8.8:443": 0, "2001:db8::1:443": 3000,
        "140.10.140.93:53": 0}
    # ... but no tick total: the UDP row has no TCP_INFO counter, and an
    # unknown socket added as zero would read as a measured clean host.
    assert st.outbound_bytes is None
    assert st.bytes_accounting == "tcp-info-1-uncounted"


def test_poll_totals_tcp_egress_across_both_families(tmp_path):
    d = _write_proc_dir(tmp_path)
    hdr = ("  sl  local_address rem_address   st tx_queue rx_queue "
           "tr tm->when retrnsmt   uid  timeout inode\n")
    (d / "udp").write_text(hdr + f"{UDP_IDLE}\n", encoding="utf-8")  # bound, no peer
    st = poll(1000, proc_dir=d, local_addrs=LOCAL, ss_text=SS_FIXTURE)
    assert st.outbound_connections == 3
    assert st.outbound_bytes == 8000     # 5000 v4 + 0 syn-sent + 3000 v6
    assert st.bytes_accounting == "tcp-info"


def test_poll_withholds_total_for_sockets_ss_did_not_report(tmp_path):
    """ss and /proc read the same kernel a moment apart; when they disagree the
    tick is unmeasured, not zero. `assess()` turns None into NO-OBSERVATION, so
    an unaccounted socket can never render as ENFORCED-VERIFIED."""
    d = _write_proc_dir(tmp_path)
    st = poll(1000, proc_dir=d, local_addrs=LOCAL,
              ss_text="State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n")
    assert st.outbound_connections == 4
    assert st.outbound_bytes is None
    assert st.bytes_accounting == "tcp-info-4-uncounted"


def test_poll_zero_outbound_is_compliant(tmp_path):
    d = _write_proc_dir(tmp_path)
    _clean_proc_dir(d)
    st = poll(1000, proc_dir=d, local_addrs=LOCAL, ss_text="State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n")
    assert st.outbound_connections == 0
    assert st.outbound_bytes == 0
    assert st.compliant is True
    assert st.violations == []


def test_poll_degrades_to_proc_only_without_ss(tmp_path):
    d = _write_proc_dir(tmp_path)
    st = poll(1000, proc_dir=d, local_addrs=LOCAL, ss_bin=None)
    assert st.bytes_accounting == "proc-only"
    assert st.outbound_bytes is None
    assert st.outbound_connections == 4


def test_poll_monitor_available_flag_on_non_linux(tmp_path):
    d = tmp_path / "no_such_proc"
    st = poll(1000, proc_dir=d, local_addrs=LOCAL, ss_bin=None)
    assert st.outbound_connections == 0
    assert st.monitor_available is False


def test_poll_status_json_roundtrip(tmp_path):
    d = _write_proc_dir(tmp_path)
    st = poll(1000, proc_dir=d, local_addrs=LOCAL, ss_text=SS_FIXTURE,
              mode="enforced", backend="nftables")
    dct = st.to_dict()
    json.dumps(dct)  # must serialize
    for key in ("timestamp", "mode", "backend", "protected_uid", "compliant",
                "outbound_bytes", "outbound_connections", "violations_total",
                "violations", "bytes_accounting"):
        assert key in dct


# --------------------------------------------------------------------------- #
# status file I/O
# --------------------------------------------------------------------------- #

def test_write_json_atomic_and_read_status(tmp_path):
    p = tmp_path / "status.json"
    write_json(p, {"a": 1})
    assert read_status(p) == {"a": 1}
    assert read_status(tmp_path / "missing.json") is None


# --------------------------------------------------------------------------- #
# assess(): the status file is an allegation, the verdict is the gate
# --------------------------------------------------------------------------- #

def _live(**over) -> dict:
    """A status JSON exactly as a healthy enforced monitor would write it."""
    base = {"timestamp": now_iso(), "monitor_available": True,
            "mode": "enforced", "backend": "nftables", "backend_reason": "",
            "protected_uid": 1000, "enforcement_verified": True,
            "dropped_packets": 7, "outbound_connections": 0,
            "outbound_bytes": 0, "bytes_accounting": "tcp-info",
            "compliant": True, "violations_total": 0, "seq": 5}
    base.update(over)
    return base


def test_assess_passes_only_a_measured_clean_tick():
    v = assess(_live())
    assert v["proof"] == "pass" and v["verdict"] == "ENFORCED-VERIFIED"
    assert v["observed"] is True and v["stale"] is False


def test_assess_denies_observation_without_byte_accounting():
    """The classic fake zero: bytes unmeasured must never read as proven."""
    v = assess(_live(outbound_bytes=None, bytes_accounting="proc-only"))
    assert v["proof"] == "unknown" and v["verdict"] == "NO-OBSERVATION"
    assert any("unmeasured zero" in r for r in v["reasons"])


def test_assess_names_the_sockets_that_had_no_counter():
    """ss worked here; it just had nothing to report for part of the set.

    The reason line used to say "no ss/TCP_INFO" for every unmeasured tick, so
    on a host where ss ran and a UDP socket sat in the set it blamed a tool
    that had functioned and hid which sockets were never counted.
    """
    v = assess(_live(outbound_bytes=None, bytes_accounting="tcp-info-2-uncounted"))
    assert v["proof"] == "unknown"
    why = " ".join(v["reasons"])
    assert "2 outbound socket(s) had no TCP_INFO counter" in why, why
    assert "no ss/TCP_INFO on this host" not in why, why


def test_assess_denies_a_missing_monitor():
    assert assess(None)["proof"] == "unknown"
    v = assess(_live(), now_epoch=time.time() + 3600)
    assert v["proof"] == "unknown" and v["verdict"] == "STALE"


def test_assess_flags_a_hand_written_status():
    """A forger can set the timestamp to now — the heartbeat still betrays it."""
    v = assess(_live(seq=3), last_seq=9)
    assert v["proof"] == "unknown" and v["stale"] is True
    assert any("rewound" in r for r in v["reasons"])


def test_proof_reader_is_the_only_way_a_surface_opens_the_status_file(tmp_path,
                                                                     monkeypatch):
    """The wall, the dashboard tab and the standalone panel each used to open
    the file their own way: one passed a tightened staleness window and
    remembered the heartbeat, two did not, so the same monitor could read
    STALE on the wall and ENFORCED-VERIFIED on the tab underneath it.

    The reader owns all three inputs now, and resolves `DIODE_STATUS_FILE` per
    read rather than at import, because a surface that started before the
    operator pointed it somewhere else must still follow.
    """
    fact = tmp_path / "diode_status.json"
    monkeypatch.setenv("DIODE_STATUS_FILE", str(fact))
    reader = ProofReader()

    missing = reader.read()
    assert missing["available"] is False and missing["path"] == str(fact)
    assert missing["proof"]["verdict"] == "NO-STATUS"

    write_json(fact, _live(seq=4))
    ok = reader.read()
    assert ok["available"] is True
    assert ok["proof"]["verdict"] == "ENFORCED-VERIFIED"
    assert reader.last_seq == 4

    write_json(fact, _live(seq=2))          # replaced, not written by the monitor
    rewound = reader.read()
    assert rewound["proof"]["verdict"] == "STALE"
    assert any("rewound" in r for r in rewound["proof"]["reasons"])
    assert reader.last_seq == 4             # the forgery does not move the memory


def test_assess_flags_a_clock_set_forward():
    future = datetime.now(timezone.utc).replace(
        year=datetime.now(timezone.utc).year + 1).isoformat(timespec="seconds")
    v = assess(_live(timestamp=future))
    assert v["proof"] == "unknown" and v["verdict"] == "STALE"


def test_assess_reports_observed_egress_as_failure():
    v = assess(_live(outbound_bytes=42, compliant=False))
    assert v["proof"] == "fail" and v["verdict"] == "EGRESS-OBSERVED"


def test_assess_separates_enforced_unverified_from_monitor_only_clean():
    assert assess(_live(enforcement_verified=False))["verdict"] == \
        "ENFORCED-UNVERIFIED"
    assert assess(_live(mode="enforced", backend="none",
                        enforcement_verified=None))["verdict"] == \
        "ENFORCED-UNVERIFIED"
    v = assess(_live(mode="monitor-only", enforcement_verified=None))
    assert v["proof"] == "pass" and v["verdict"] == "MONITOR-ONLY-CLEAN"


def test_assess_scopes_the_claim_to_uid_and_kernel_sockets():
    """The uid/raw-socket blind spot must be stated, not left in the docs."""
    v = assess(_live())
    assert any("af_packet" in r.lower() or "other uids" in r.lower()
               for r in v["reasons"])


def test_poll_compliant_is_false_without_an_observer(tmp_path):
    """Non-Linux: zero sockets observed because nothing could be read."""
    st = poll(1000, proc_dir=tmp_path / "no_such_proc", local_addrs=LOCAL,
              ss_bin=None)
    assert st.monitor_available is False
    assert st.compliant is False
    assert assess(st.to_dict())["proof"] == "unknown"


def test_next_seq_continues_the_heartbeat(tmp_path):
    p = tmp_path / "st.json"
    assert next_seq(p) == 1                  # no file yet
    write_json(p, _live(seq=7))
    assert next_seq(p) == 8
    write_json(p, {"no": "seq"})
    assert next_seq(p) == 1                  # unreadable counter restarts at 1


def test_monitor_run_writes_monotonic_heartbeat(tmp_path):
    d = _write_proc_dir(tmp_path)
    _clean_proc_dir(d)
    p = tmp_path / "st.json"
    mon = Monitor(1000, status_file=p, events_file=None, proc_dir=d,
                  local_addrs=LOCAL, ss_bin=None)
    mon.run(max_ticks=2)
    assert read_status(p)["seq"] == 2
    mon.run(max_ticks=1)                      # restart continues, never rewinds
    assert read_status(p)["seq"] == 3


# --------------------------------------------------------------------------- #
# violation diff
# --------------------------------------------------------------------------- #

def test_diff_outbound():
    k1 = ("tcp", "127.0.0.1", 50000, "8.8.8.8", 443)
    k2 = ("tcp", "127.0.0.1", 50001, "1.1.1.1", 443)
    assert diff_outbound(None, {k1}) == [k1]
    assert diff_outbound({k1}, {k1}) == []
    assert diff_outbound({k1}, {k1, k2}) == [k2]


# --------------------------------------------------------------------------- #
# Monitor loop
# --------------------------------------------------------------------------- #

class FakeEnforcer:
    backend = "nftables"
    reason = ""

    def verify(self, uid):
        return EnforceResult(True, "nftables", dropped_packets=7)


def test_monitor_tick_enforced_mode(tmp_path):
    d = _write_proc_dir(tmp_path)
    mon = Monitor(1000, status_file=tmp_path / "st.json", enforcer=FakeEnforcer(),
                  proc_dir=d, local_addrs=LOCAL, ss_bin=None)
    st = mon.tick()
    assert st.mode == "enforced"
    assert st.enforcement_verified is True
    assert st.dropped_packets == 7
    assert st.outbound_connections == 4


def test_monitor_run_once_writes_status_and_events(tmp_path):
    d = _write_proc_dir(tmp_path)
    _clean_proc_dir(d)
    stf = tmp_path / "st.json"
    evf = tmp_path / "events.ndjson"
    mon = Monitor(1000, status_file=stf, events_file=evf, proc_dir=d,
                  local_addrs=LOCAL, ss_bin=None)
    assert mon.run(once=True) == 0
    st = read_status(stf)
    assert st["compliant"] is True
    assert st["violations_total"] == 0
    assert st["protected_uid"] == 1000


def test_monitor_records_sockets_already_outbound_at_startup(tmp_path):
    """`run(once=True)` is the single-shot path the acceptance script uses.

    A socket already external when the monitor started is the finding itself, so
    it is recorded on the first tick rather than forgiven as a baseline: without
    it, one live external SYN-SENT reported `violations_total=0` while the same
    status said `compliant: false`.
    """
    d = _write_proc_dir(tmp_path)
    stf = tmp_path / "st.json"
    evf = tmp_path / "events.ndjson"
    mon = Monitor(1000, status_file=stf, events_file=evf, proc_dir=d,
                  local_addrs=LOCAL, ss_bin=None)
    assert mon.run(once=True) == 0
    st = read_status(stf)
    assert st["outbound_connections"] == 4
    assert st["violations_total"] == 4
    assert {v["peer"] for v in st["violations"]} == {
        "140.10.140.93:443", "8.8.8.8:443", "2001:db8::1:443", "140.10.140.93:53"}
    assert len(evf.read_text(encoding="utf-8").splitlines()) == 4


def test_monitor_detects_new_outbound_socket_as_violation(tmp_path):
    d = _write_proc_dir(tmp_path)
    _clean_proc_dir(d)          # zero external sockets to start: every finding
                                # below is one the monitor saw appear
    stf = tmp_path / "st.json"
    evf = tmp_path / "events.ndjson"
    mon = Monitor(1000, status_file=stf, events_file=evf, interval=0.2,
                  proc_dir=d, local_addrs=LOCAL, ss_bin=None)

    t = threading.Thread(target=lambda: mon.run(max_ticks=3))
    t.start()
    time.sleep(0.35)  # let tick 1 (baseline) finish
    (d / "tcp").write_text(f"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                           f"{TCP_LOOPBACK}\n{TCP_EXT_SYNSENT}\n", encoding="utf-8")
    t.join(timeout=10)
    assert not t.is_alive()

    st = read_status(stf)
    assert st["violations_total"] == 1
    assert st["violations"][0]["peer"] == "8.8.8.8:443"
    assert st["violations"][0]["state"] == "SYN-SENT"
    events = [json.loads(l) for l in evf.read_text(encoding="utf-8").splitlines()]
    assert len(events) == 1 and events[0]["peer"] == "8.8.8.8:443"


def test_monitor_second_violation_appends(tmp_path):
    d = _write_proc_dir(tmp_path)
    _clean_proc_dir(d)          # as above: clean baseline, so the count is
                                # exactly the sockets that appeared mid-run
    stf = tmp_path / "st.json"
    evf = tmp_path / "events.ndjson"
    mon = Monitor(1000, status_file=stf, events_file=evf, interval=0.2,
                  proc_dir=d, local_addrs=LOCAL, ss_bin=None)
    t = threading.Thread(target=lambda: mon.run(max_ticks=4))
    t.start()
    time.sleep(0.35)   # tick1 baseline, tick2 clean
    (d / "tcp").write_text(f"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                           f"{TCP_LOOPBACK}\n{TCP_EXT_SYNSENT}\n", encoding="utf-8")
    time.sleep(0.2)    # tick3 sees SYN-SENT → violation 1
    (d / "tcp").write_text(f"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                           f"{TCP_LOOPBACK}\n{TCP_EXT_SYNSENT}\n{TCP_EXT_ESTAB}\n",
                           encoding="utf-8")
    time.sleep(0.2)    # tick4 sees ESTAB → violation 2
    t.join(timeout=10)
    assert not t.is_alive()
    st = read_status(stf)
    assert st["violations_total"] == 2
    assert len(st["violations"]) == 2


# --------------------------------------------------------------------------- #
# enforcer (no privileges needed: rendering + detection are pure)
# --------------------------------------------------------------------------- #

def test_render_nft_ruleset():
    rs = render_nft_ruleset(1000)
    assert 'skuid 1000 oif "lo" accept' in rs
    assert "skuid 1000 counter drop" in rs
    assert "hook output" in rs


def test_render_iptables_rules():
    rules = render_iptables_rules(1000)
    assert len(rules) == 2
    assert rules[0].startswith("iptables -I OUTPUT 1 -m owner --uid-owner 1000")
    assert "diode-guard-1000" in rules[0]
    assert "-o lo" in rules[1]
    # order: DROP inserted first, lo-ACCEPT second -> lo-ACCEPT lands first
    assert "DROP" in rules[0] and "ACCEPT" in rules[1]


def test_detect_backend_on_windows_or_without_tools(monkeypatch):
    backend, reason = detect_backend()
    if not hasattr(__import__("os"), "geteuid"):
        assert backend == "none" and "Linux" in reason
    else:  # POSIX without root
        import os
        monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
        backend, reason = detect_backend()
        assert backend == "none" and "root" in reason


def test_detect_backend_nftables_preferred(monkeypatch):
    import os
    import shutil
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(shutil, "which",
                        lambda name: "/usr/sbin/nft" if name == "nft" else None)
    assert detect_backend()[0] == "nftables"
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert detect_backend()[0] == "none"


def test_enforcer_apply_degrades_without_root(monkeypatch):
    import os
    import shutil
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/sbin/nft")
    en = Enforcer()
    res = en.apply(1000)
    assert res.ok is False and res.backend == "none"
    assert "root" in res.reason


def test_enforcer_verify_nft_parses_counter(monkeypatch):
    import os
    import shutil
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    en = Enforcer()
    ruleset = """table inet diode {
\tchain egress {
\t\ttype filter hook output priority 0; policy accept;
\t\tmeta skuid 1000 oif "lo" accept
\t\tmeta skuid 1000 counter packets 3 bytes 132 drop
\t}
}
"""
    monkeypatch.setattr("src.diode.enforcer._run",
                        lambda *a, **k: subprocess.CompletedProcess(a[0], 0,
                                                                    stdout=ruleset))
    v = en.verify(1000)
    assert v.ok is True
    assert v.dropped_packets == 3


def test_enforcer_verify_nft_fails_when_rules_missing(monkeypatch):
    import os
    import shutil
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    en = Enforcer()
    monkeypatch.setattr("src.diode.enforcer._run",
                        lambda *a, **k: subprocess.CompletedProcess(a[0], 1,
                                                                    stdout=""))
    v = en.verify(1000)
    assert v.ok is False and "missing" in v.reason


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_cli_status_writes_json(tmp_path):
    from src.diode.cli import main as cli_main
    out = tmp_path / "st.json"
    assert cli_main(["status", "--uid", "1000", "--status-file", str(out)]) == 0
    dct = json.loads(out.read_text(encoding="utf-8"))
    assert dct["protected_uid"] == 1000
    assert "outbound_connections" in dct
    assert dct["timestamp"]


def test_cli_monitor_once(tmp_path):
    out = tmp_path / "st.json"
    ev = tmp_path / "ev.ndjson"
    # run a single tick via max_ticks through the Monitor directly is covered
    # elsewhere; here just ensure monitor command starts and writes status
    mon = Monitor(1000, status_file=out, events_file=ev, ss_bin=None)
    assert mon.run(once=True) == 0
    assert read_status(out) is not None


def test_protected_uid_prefers_sudo(monkeypatch):
    import os
    monkeypatch.setenv("SUDO_UID", "4242")
    monkeypatch.setattr(os, "getuid", lambda: 0, raising=False)
    assert protected_uid() == 4242
    monkeypatch.delenv("SUDO_UID")
    assert protected_uid() == 0


def test_now_iso_utc():
    ts = now_iso()
    assert ts.endswith("+00:00") or "+00:00" in ts


# --------------------------------------------------------------------------- #
# UI panel (Streamlit AppTest — renders without exceptions)
# --------------------------------------------------------------------------- #

# The headline each verdict must print, in the widget that carries its severity.
# Kept next to the test rather than read off the panel so a wording change in
# apps/dashboard/diode_panel.py has to be a deliberate edit here too.
_PANEL_HEADLINES = {
    "ENFORCED-VERIFIED": ("success", "**ENFORCED**"),
    "ENFORCED-UNVERIFIED": ("warning", "**ENFORCED (UNVERIFIED)**"),
    "MONITOR-ONLY-CLEAN": ("warning", "**MONITOR-ONLY (OBSERVED CLEAN)**"),
    "EGRESS-OBSERVED": ("error", "**NON-COMPLIANT**"),
}

# Overrides, applied when each case runs: a heartbeat is only fresh for
# PROOF_MAX_AGE_S, so a status stamped at import time drifts out of the window
# mid-suite and the case silently stops testing what its id says it does. The
# "stale" id is the one exception: three hours old is stale whenever it runs.
_PANEL_STATUSES = [
    pytest.param({}, id="verified"),
    pytest.param({"enforcement_verified": False}, id="unverified"),
    pytest.param({"mode": "monitor-only", "enforcement_verified": None},
                 id="monitor-only"),
    pytest.param({"outbound_bytes": 42, "compliant": False}, id="egress"),
    pytest.param({"timestamp": (datetime.now(timezone.utc)
                                - timedelta(hours=3)).isoformat(timespec="seconds")},
                 id="stale"),
    pytest.param({"outbound_bytes": None, "bytes_accounting": "proc-only"},
                 id="unmeasured-zero"),
]


@pytest.mark.parametrize("over", _PANEL_STATUSES)
def test_diode_panel_banner_matches_assess_verdict(tmp_path, monkeypatch, over):
    """The panel prints assess()'s verdict, never a nicer claim than it was given.

    This test used to assert only that *some* banner appeared. The panel emits a
    banner on every branch, so it passed even if a stale or unobserved proof
    rendered as a green ENFORCED - the exact failure the panel exists to prevent.
    """
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    panel = Path(__file__).resolve().parents[2] / "apps" / "dashboard" / "diode_panel.py"
    fact = tmp_path / "status.json"
    write_json(fact, _live(**over))
    monkeypatch.setenv("DIODE_STATUS_FILE", str(fact))

    at = AppTest.from_file(str(panel))
    at.run(timeout=60)
    assert not at.exception
    assert any("Diode Proof" in (t.value or "") for t in at.title)

    verdict = assess(read_status(fact))["verdict"]
    widget, headline = _PANEL_HEADLINES.get(verdict, ("error", f"**NO PROOF ({verdict})**"))
    shown = " ".join(el.value or "" for el in getattr(at, widget))
    assert headline in shown, f"{verdict} did not print {headline!r} in {widget}: {shown}"
    if verdict != "ENFORCED-VERIFIED":
        green = " ".join(el.value or "" for el in at.success)
        assert "**ENFORCED**" not in green, f"{verdict} rendered as a green guarantee"


def test_diode_panel_stops_counting_what_the_host_could_not_observe(tmp_path,
                                                                   monkeypatch):
    """A monitor with no kernel socket table reports zeros for *nothing seen*.

    The panel used to print `Outbound connections 0` / `Violations 0` there and
    close with "the enclave has stayed silent", so a Windows dev box claimed the
    absence of egress from the absence of an observer.
    """
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    panel = Path(__file__).resolve().parents[2] / "apps" / "dashboard" / "diode_panel.py"
    fact = tmp_path / "status.json"
    write_json(fact, _live(monitor_available=False))
    monkeypatch.setenv("DIODE_STATUS_FILE", str(fact))

    at = AppTest.from_file(str(panel))
    at.run(timeout=60)
    assert not at.exception
    cells = {m.label: str(m.value) for m in at.metric}
    assert cells["Outbound bytes"] == "not observed"
    assert cells["Outbound connections"] == "not observed"
    assert cells["Violations (attempts)"] == "not observed"
    captions = " ".join(el.value or "" for el in at.caption)
    assert "could not have been recorded either way" in captions


# What the paragraph under the counters is allowed to claim for each verdict
# that measured its zeros. Both surfaces read this sentence to judges, and only
# one of the two states has a kernel refusing anything.
#
# These are the overrides, not the status itself: a heartbeat is only fresh for
# PROOF_MAX_AGE_S, so stamping it at import time made this pass alone and fail
# in a full run, once the suite had been collecting for longer than the window.
_PANEL_NOTES = [
    pytest.param({}, id="verified"),
    pytest.param({"mode": "monitor-only", "enforcement_verified": None},
                 id="monitor-only"),
]


@pytest.mark.parametrize("over", _PANEL_NOTES)
def test_diode_panel_only_promises_a_refusal_it_measured(tmp_path, monkeypatch,
                                                         over):
    """A measured zero under MONITOR-ONLY is a reading; the kernel refused nothing.

    The dashboard used to print "the kernel refused every attempt" under every
    verdict, so the laptop demo — which is monitor-only at best — recited the
    enforcement claim of a machine it does not have.
    """
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    panel = Path(__file__).resolve().parents[2] / "apps" / "dashboard" / "diode_panel.py"
    fact = tmp_path / "status.json"
    write_json(fact, _live(**over))
    monkeypatch.setenv("DIODE_STATUS_FILE", str(fact))

    at = AppTest.from_file(str(panel))
    at.run(timeout=60)
    assert not at.exception
    assert assess(read_status(fact))["proof"] == "pass"
    notes = " ".join(el.value or "" for el in at.info)
    enforced = assess(read_status(fact))["verdict"] == "ENFORCED-VERIFIED"
    assert ("refused every attempt" in notes) == enforced, notes
    if not enforced:
        assert "reading, not an enforced guarantee" in notes, notes
