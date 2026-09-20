# Diode Guard, Enforce and Prove "No Outbound Traffic"

The unidirectional constraint is a **firewall property**, not a code
convention: the analytics identity physically cannot send anything outside
loopback, and a live panel shows the kernel's own counters as proof.

```
 protected uid (analytics pipeline, UI, monitor)
        │  all sockets
        v
┌─────────────────────────────┐      /proc/net/{tcp,tcp6,udp,udp6}   ┌──────────────┐
│  nftables `inet diode`      │◄───── uid filter + state + peer ─────┤ egress       │
│  chain egress (OUTPUT):     │      ss -tinaep (TCP_INFO bytes)     │ monitor      │
│    skuid <uid> oif "lo" acc │ ───────────────────────────────────► │ (2 s poll)   │
│    skuid <uid> counter drop │      status JSON + violation ndjson  └──────┬───────┘
└─────────────────────────────┘                                           │ poll
                                                                          v
                            apps/dashboard/diode_view.py, the Streamlit renderer, written once
                            (diode_panel.py page and the dashboard's Diode Proof tab both call it)
```

## What enforces

`src/diode/enforcer.py` installs one `inet` table `diode` with an OUTPUT
chain (nftables primary, `iptables -m owner` fallback):

```
meta skuid <uid> oif "lo" accept      # loopback: UI/API/local resolver OK
meta skuid <uid> counter drop         # everything else: refused by the kernel
```

* Scope is the **uid** the analytics pipeline runs as (`--uid`, `--user`, or
  `SUDO_UID` → the sudo caller, never root-by-accident). Run the pipeline
  under that identity and it is *structurally unable* to reach the monitored
  network, the internet, or any LAN peer, UDP, TCP, ICMP, IPv4 and IPv6.
* The drop rule carries a **kernel counter** (`nft list chain inet diode
  egress` → `counter packets N bytes M drop`); `verify` reads it and the
  panel shows it, denial is counted, not claimed.
* Rules persist across monitor restarts (that is the point); `remove` is
  explicit and idempotent. Apply is also idempotent (fresh table each time).

## What proves

`src/diode/monitor.py` polls every 2 s (stdlib reads, no privileges):

| Signal | Source | Meaning |
|---|---|---|
| `outbound_connections` | `/proc/net/{tcp,tcp6,udp,udp6}` | live count of the protected uid's sockets with a non-local, non-loopback peer, in client-side states (ESTABLISHED, SYN-SENT, …, UDP) |
| `outbound_bytes` | `ss -tinaep` (TCP_INFO `bytes_sent`) | bytes the protected uid actually transmitted outside loopback, **0 in enforced mode** |
| `violations` / `violations_total` | socket-set diff between ticks | every *attempted* outbound connection, timestamped, appended to `data/diode_events.ndjson` |
| `dropped_packets` | nftables counter | kernel-level denial count |
| `enforcement_verified` | `nft list` / `iptables -C` each tick | rules still live, not silently lost |

Status JSON (`data/diode_status.json`, atomic write) is the UI's contract:
`schema_version`, `timestamp`, `mode`, `backend`, `backend_reason`,
`protected_uid/user`, `enforcement_verified`, `dropped_packets`,
`outbound_connections`, `outbound_bytes`, `bytes_accounting`
(`tcp-info` | `proc-only` when `ss` is absent), `compliant`, `violations`.

Every surface opens that file through one `ProofReader`, it resolves
`DIODE_STATUS_FILE` and the `DIODE_PROOF_MAX_AGE_S` staleness window, remembers
the `seq` heartbeat across reads, and hands the UI `assess()`'s verdict rather
than the raw fields, because the file is written by the very host it attests.
The monitor's own CLI default resolves the same variable, so a relocated status
file is written where the UIs look for it.

## Commands

```bash
python -m src.diode.cli apply --user analytics     # enforce (needs root + nft/iptables)
python -m src.diode.cli verify                     # rules live? kernel drop counter?
python -m src.diode.cli status                     # one snapshot -> data/diode_status.json
python -m src.diode.cli monitor --enforce          # nodal centre: enforce + poll forever
python -m src.diode.cli monitor                    # no root: monitor-only (observation)
python -m src.diode.cli remove                     # take the profile down (idempotent)

streamlit run apps/dashboard/diode_panel.py                    # Diode Proof panel (polls status JSON)
```

Acceptance (both paths, `scripts/checks/check_diode.py`, exit 0 = pass):

```bash
python scripts/checks/check_diode.py      # auto-selects enforced vs monitor-only
```

## Graceful degradation (nodal-centre rule)

If root, nftables/iptables, or Linux are unavailable, the enforcer reports
`backend="none"` + a reason and **everything falls back to monitor-only**:
the monitor keeps running and writing honest status; the panel shows an
amber **MONITOR-ONLY** banner explaining that strict enforcement is disabled
due to environment constraints. Enforcement is never silently assumed and a
fabricated zero is never shown (`monitor_available: false` + reason when
/proc/net is unavailable, `bytes_accounting: proc-only` when `ss` is
missing).

## Byte accounting

`ss` is asked for TCP only (`ss -tinaep`), for both families. `poll()` merges
each outbound socket's counters by `(proto, local, peer)`, where the family
comes from the address `ss` printed, bracketed is `tcp6`, the label `/proc`
gives the same socket, so an IPv6 egress lands in the total instead of
reading zero.

The tick total is only published when **every** outbound socket has a counter.
A UDP socket has none (`TCP_INFO` is a TCP thing) and a TCP socket can be
missing from `ss` when it closes between the two reads, so `outbound_bytes` is
then `null` and `bytes_accounting` names the count (`tcp-info-2-uncounted`).
`assess()` renders a null total as `NO-OBSERVATION`: an unmeasured egress is
never a proven zero. The per-socket `bytes_sent` in `violations` still carries
whatever `ss` reported for that socket.

`run()` also records every outbound socket present on its **first** tick, so
`violations_total` counts a connection that was already open when the monitor
started rather than forgiving it as a baseline, the same reading `compliant`
already gave. A surface prints `not observed` for the connection and violation
counters whenever `monitor_available` is false, so an absent observer never
renders as an absent egress.

## Honest limitations

* `outbound_bytes` is TCP `bytes_sent` (netlink TCP_INFO). UDP sockets are
  counted as connections but have no byte counter in `ss`; in enforced mode
  the kernel drops their packets all the same (`dropped_packets` covers both).
* An inbound-accepted connection to the protected uid is indistinguishable
  from an outbound-originated one in `/proc`; both are flagged as outbound.
  The diode design has the enclave never *reply*, so any non-loopback peer
  of the protected identity is a violation by policy.
* Enforcing by uid protects the analytics *processes*; it does not firewall
  other users on the same host (scope is deliberate, never lock out the
  operator).

## Verified results (WSL Ubuntu, 2026-09-05)

`scripts/checks/check_diode.py` as root: apply ok → external TCP connect to
8.8.8.8:443 **blocked** (TimeoutError, SYNs dropped), loopback connect
**allowed**, monitor mid-attempt reported `outbound_connections=1` and
`outbound_bytes=0`, kernel drop counter 0 → 6, rules removed cleanly.
Windows dev box: monitor-only path exercised, honest status, exit 0.
