"""Diode Guard CLI: enforce + prove "no outbound traffic".

Subcommands:

    apply    — install the egress-deny firewall profile for the analytics uid
               (root + nftables/iptables required; else reports monitor-only)
    remove   — remove the profile (idempotent)
    verify   — check the profile is live, report kernel drop counters
    status   — one monitor snapshot → data/diode_status.json
    monitor  — background loop: poll every N seconds, write status JSON + an
               ndjson audit log of violation events

Graceful degradation (nodal-centre rule): without root or firewall tooling,
`apply` and `monitor --enforce` fall back to monitor-only mode and say so —
enforcement is never silently assumed, and the UI banner explains why.

Examples:
    python -m src.diode.cli monitor --enforce            # nodal centre
    python -m src.diode.cli apply --user analytics
    python -m src.diode.cli status                       # one-shot snapshot
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.diode.enforcer import Enforcer, protected_uid
from src.diode.monitor import (
    Monitor,
    assess,
    default_status_path,
    next_seq,
    poll,
    write_json,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
# where every reader (the wall, the dashboard tab, the standalone panel) looks
DEFAULT_STATUS = default_status_path()
DEFAULT_EVENTS = REPO_ROOT / "data" / "diode_events.ndjson"


def _resolve_uid(args) -> int:
    if args.uid is not None:
        return args.uid
    if args.user is not None:
        import pwd
        return pwd.getpwnam(args.user).pw_uid
    return protected_uid()


def _human_name(uid: int) -> str:
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        return str(uid)


def cmd_apply(args) -> int:
    uid = _resolve_uid(args)
    en = Enforcer()
    res = en.apply(uid)
    print(f"backend       : {res.backend}")
    print(f"ok            : {res.ok}")
    if res.reason:
        print(f"reason        : {res.reason}")
    if res.rules:
        print("rules:")
        for r in res.rules:
            print(f"  {r}")
    if res.dropped_packets is not None:
        print(f"kernel drops  : {res.dropped_packets} packets (nft counter)")
    if not res.ok:
        print(f"\n[monitor-only] enforcement disabled on this host — "
              f"{res.reason}")
        return 2
    print(f"\nenforced: uid {uid} ({_human_name(uid)}) cannot reach anything "
          f"outside loopback")
    return 0


def cmd_remove(args) -> int:
    uid = _resolve_uid(args)
    en = Enforcer()
    en.remove(uid)
    v = en.verify(uid)
    print("rules removed" if not v.ok else "[warn] rules still present")
    return 0 if not v.ok else 1


def cmd_verify(args) -> int:
    uid = _resolve_uid(args)
    en = Enforcer()
    v = en.verify(uid)
    print(f"backend       : {en.backend}")
    print(f"verified      : {v.ok}")
    if v.dropped_packets is not None:
        print(f"kernel drops  : {v.dropped_packets} packets (nft counter)")
    if v.reason:
        print(f"reason        : {v.reason}")
    return 0 if v.ok else 1


def cmd_status(args) -> int:
    uid = _resolve_uid(args)
    st = poll(uid, mode="monitor-only")
    st.seq = next_seq(args.status_file)
    out = st.to_dict()
    write_json(Path(args.status_file), out)
    print(json.dumps(out, indent=2, default=str))
    verdict = assess(out)
    print(f"\nstatus written: {args.status_file}")
    print(f"proof           : {verdict['verdict']} ({verdict['proof']})")
    for why in verdict["reasons"]:
        print(f"                  - {why}")
    return 0


def cmd_monitor(args) -> int:
    uid = _resolve_uid(args)
    enforcer = None
    if args.enforce:
        enforcer = Enforcer()
        res = enforcer.apply(uid)
        if res.ok:
            print(f"[enforced] egress-deny active for uid {uid} "
                  f"({_human_name(uid)}) via {res.backend}")
        else:
            enforcer = None
            print(f"[monitor-only] enforcement unavailable: {res.reason}")
            print("  UI will show 'strict enforcement disabled (environment "
                  "constraints)'")
    else:
        print("[monitor-only] running without --enforce (observation only)")
    mon = Monitor(uid, interval=args.interval,
                  status_file=args.status_file, events_file=args.events_file,
                  enforcer=enforcer)
    print(f"status file   : {args.status_file}")
    print(f"events file   : {args.events_file or '(none)'}")
    print(f"poll interval : {args.interval}s  (Ctrl-C to stop)\n")
    return mon.run()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name, fn, help_txt in (("apply", cmd_apply, "install egress-deny rules"),
                               ("remove", cmd_remove, "remove egress-deny rules"),
                               ("verify", cmd_verify, "verify rules are live"),
                               ("status", cmd_status, "one-shot monitor snapshot"),
                               ("monitor", cmd_monitor, "background monitor loop")):
        p = sub.add_parser(name, help=help_txt)
        p.set_defaults(fn=fn)
        p.add_argument("--uid", type=int, default=None,
                       help="protected uid (default: sudo caller / current uid)")
        p.add_argument("--user", default=None, help="protected user name")

    sub.choices["status"].add_argument(
        "--status-file", default=str(DEFAULT_STATUS))
    sub.choices["monitor"].add_argument(
        "--status-file", default=str(DEFAULT_STATUS))
    sub.choices["monitor"].add_argument(
        "--events-file", default=str(DEFAULT_EVENTS))
    sub.choices["monitor"].add_argument("--interval", type=float, default=2.0)
    sub.choices["monitor"].add_argument("--enforce", action="store_true",
                                        help="install egress-deny first "
                                             "(falls back to monitor-only)")
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
