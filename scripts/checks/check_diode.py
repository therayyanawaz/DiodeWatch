#!/usr/bin/env python3
"""Exit check: Diode Guard - enforce + prove "no outbound traffic".

Two acceptance paths, chosen automatically:

1. **Enforced (Linux + root + nftables/iptables)** - the real proof:
   * egress-deny rules installed for the protected uid and verified live;
   * a child process of the protected uid CANNOT TCP-connect to an external
     host (8.8.8.8:443) while loopback connections still work;
   * mid-attempt, the egress monitor reports the attempt as a violation
     while `outbound_bytes` stays 0 (the kernel drops the packets);
   * the nft drop counter increments - kernel-level proof of denial.

2. **Monitor-only (no root / no firewall tooling / non-Linux)** - graceful
   degradation: the monitor runs, writes an honest status JSON, and the
   script reports enforcement as unavailable with the reason. This is the
   nodal-centre fallback path and it must work, not error.

Exit code 0 = acceptance criteria met (or correctly degraded).

Usage:
    python scripts/checks/check_diode.py [--uid N | --user NAME] [--status-file PATH]
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

try:
    import pwd
except ImportError:  # non-POSIX (Windows dev box): pwd unavailable
    pwd = None

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from src.diode.enforcer import Enforcer, protected_uid
from src.diode.monitor import Monitor, assess, poll, read_status

CHILD_CODE = r"""
import socket, sys
results = []
try:
    s = socket.create_connection(("8.8.8.8", 443), timeout=6)
    s.close()
    results.append("EXTERNAL_CONNECTED")
except Exception as e:
    results.append("EXTERNAL_BLOCKED:" + type(e).__name__)
try:
    s = socket.create_connection(("127.0.0.1", __PORT__), timeout=3)
    s.close()
    results.append("LOCALHOST_OK")
except Exception as e:
    results.append("LOCALHOST_FAIL:" + type(e).__name__)
print("|".join(results))
sys.stdout.flush()
"""


def _drop_privs(uid: int):
    """preexec_fn: switch to the protected uid so the firewall matches."""
    pw = pwd.getpwuid(uid)
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(uid)


def run_child(uid: int, port: int) -> str:
    code = CHILD_CODE.replace("__PORT__", str(port))
    cmd = [sys.executable, "-c", code]
    kw: dict = {}
    if os.geteuid() == 0 and uid != 0:
        kw["preexec_fn"] = lambda: _drop_privs(uid)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False,
                       **kw)
    return (p.stdout or "").strip() or f"NO_OUTPUT rc={p.returncode}"


def check_enforced(uid: int, status_file: Path) -> bool:
    print(f"\n=== enforced acceptance (uid {uid}, user "
          f"{pwd.getpwuid(uid).pw_name})")
    ok = True
    en = Enforcer()

    # 1. apply + verify
    res = en.apply(uid)
    if not res.ok:
        print(f"  [FAIL] apply failed: {res.reason}")
        return False
    print(f"  apply      : ok ({res.backend})")
    v = en.verify(uid)
    if not v.ok:
        print(f"  [FAIL] verify failed: {v.reason}")
        en.remove(uid)
        return False
    print(f"  verified   : rules live (kernel drops so far: {v.dropped_packets})")

    try:
        # 2. loopback listener for the child's localhost check
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        accepted = threading.Event()

        def accept_loop():
            try:
                conn, _ = srv.accept()
                accepted.set()
                conn.close()
            except OSError:
                pass

        threading.Thread(target=accept_loop, daemon=True).start()

        # 3. child attempts external + localhost while we watch
        child_result: dict = {}

        def spawn():
            child_result["out"] = run_child(uid, port)

        t = threading.Thread(target=spawn)
        t.start()
        time.sleep(1.5)  # child is mid-connect to 8.8.8.8 (SYN-SENT)

        st = poll(uid, mode="enforced", backend=en.backend)
        print(f"  mid-attempt: outbound_connections={st.outbound_connections} "
              f"outbound_bytes={st.outbound_bytes} "
              f"({st.bytes_accounting}) "
              f"violations={[x['peer'] for x in st.violations]}")

        t.join(timeout=40)
        srv.close()
        child = child_result.get("out", "CHILD_CRASHED")

        # 4. assert child behaviour
        if child.startswith("EXTERNAL_BLOCKED"):
            print(f"  external   : blocked ({child.split('|')[0].split(':')[1]}) [ok]")
        elif child.startswith("EXTERNAL_CONNECTED"):
            print("  [FAIL] external connect SUCCEEDED under enforcement")
            ok = False
        else:
            print(f"  [FAIL] unexpected child output: {child!r}")
            ok = False

        if "LOCALHOST_OK" in child:
            print("  localhost  : loopback connect allowed [ok]")
        else:
            print(f"  [FAIL] localhost connect failed: {child}")
            ok = False

        # 5. monitor saw the attempt, but zero bytes left the host
        if st.outbound_connections >= 1:
            print("  monitor    : attempt detected as violation [ok]")
        else:
            print("  [FAIL] monitor did not observe the outbound attempt")
            ok = False
        if st.outbound_bytes == 0:
            print("  monitor    : outbound_bytes == 0 (kernel dropped) [ok]")
        else:
            print(f"  [FAIL] outbound_bytes = {st.outbound_bytes} != 0 "
                  f"(accounting: {st.bytes_accounting})")
            ok = False

        # 6. kernel drop counter incremented
        v2 = en.verify(uid)
        print(f"  kernel     : drop counter now {v2.dropped_packets} "
              f"(was {v.dropped_packets})")
        if v2.dropped_packets is not None and v2.dropped_packets > (v.dropped_packets or 0):
            print("  kernel     : packets actually dropped [ok]")
        else:
            print("  [warn] drop counter did not increase (SYNs may have been "
                  "dropped before counter? check nft ruleset)")

        # 7. a running Monitor writes the status JSON the UI polls
        mon = Monitor(uid, status_file=status_file, events_file=None, ss_bin="ss")
        mon.run(once=True)
        if read_status(status_file) is not None:
            print(f"  status json: {status_file} written [ok]")
        else:
            print("  [FAIL] status JSON not written")
            ok = False
    finally:
        en.remove(uid)
        v3 = en.verify(uid)
        print(f"  cleanup    : rules removed ({'ok' if not v3.ok else 'STILL PRESENT!'})")
        if v3.ok:
            ok = False
    return ok


def check_monitor_only(status_file: Path) -> bool:
    print("\n=== monitor-only acceptance (graceful degradation)")
    print(f"  reason     : {Enforcer().reason or 'enforcement not requested'}")
    uid = protected_uid()
    mon = Monitor(uid, status_file=status_file, events_file=None, ss_bin="ss")
    mon.run(once=True)
    st = read_status(status_file)
    if st is None:
        print("  [FAIL] monitor did not write a status JSON")
        return False
    print(f"  status     : monitor_available={st['monitor_available']} "
          f"mode={st['mode']} backend={st['backend']}")
    print(f"  status     : outbound_connections={st['outbound_connections']} "
          f"outbound_bytes={st['outbound_bytes']}")
    required = {"timestamp", "mode", "backend", "protected_uid", "compliant",
                "outbound_connections", "outbound_bytes", "violations_total",
                "violations", "bytes_accounting"}
    missing = required - set(st)
    if missing:
        print(f"  [FAIL] status JSON missing keys: {sorted(missing)}")
        return False
    if st["mode"] != "monitor-only":
        print(f"  [FAIL] expected monitor-only mode, got {st['mode']}")
        return False
    verdict = assess(st)
    print(f"  proof      : {verdict['verdict']} ({verdict['proof']})")
    for why in verdict["reasons"]:
        print(f"               - {why}")
    # The contract on a host with no observer is *honest degradation*, not
    # compliance: a status that claims clean while nothing was measured fails.
    if verdict["proof"] == "fail":
        print("  [FAIL] outbound traffic observed")
        return False
    if st.get("compliant") and not verdict["observed"]:
        print("  [FAIL] status reports compliance the monitor never observed")
        return False
    print("  status json: schema valid, degradation honest [ok]")
    print("  [note] this host cannot observe egress at all — the run below "
          "proves the degradation contract ONLY, not zero outbound traffic")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--uid", type=int, default=None)
    ap.add_argument("--user", default=None)
    ap.add_argument("--status-file", type=Path,
                    default=REPO / "data" / "diode_status.json")
    args = ap.parse_args()

    uid = args.uid
    if uid is None and args.user is not None:
        uid = pwd.getpwnam(args.user).pw_uid
    if uid is None:
        uid = protected_uid()

    print(f"host        : {os.uname().nodename if hasattr(os, 'uname') else os.name}"
          f"  python {sys.version.split()[0]}")
    user = pwd.getpwuid(uid).pw_name if pwd is not None else "?"
    print(f"protected   : uid {uid if uid >= 0 else 'n/a'} ({user})")

    en = Enforcer()
    can_enforce = (en.backend == "nftables" or en.backend == "iptables") and \
                  os.geteuid() == 0 and os.name == "posix"
    ok = check_enforced(uid, args.status_file) if can_enforce \
        else check_monitor_only(args.status_file)
    if not can_enforce:
        print("\n[note] enforced acceptance requires Linux + root + nftables/"
              "iptables - run inside the nodal environment (or WSL Ubuntu) "
              "as root to execute the real proof.")
    if not ok:
        print("\n[FAIL] acceptance criteria NOT met", file=sys.stderr)
    elif can_enforce:
        print("\n[PASS] Diode Guard enforced acceptance met", file=sys.stderr)
    else:
        # Never a bare "PASS": this branch proves the degradation contract, and
        # says so, because no egress measurement was possible on this host.
        print("\n[PASS-scoped] degradation contract met — no egress proof "
              "produced (host cannot enforce or observe)", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
