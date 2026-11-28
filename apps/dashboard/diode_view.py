"""The one Streamlit renderer of the diode proof status.

Both Streamlit surfaces show this panel: the dashboard's Diode Proof tab
(`apps/dashboard/app.py`) and the standalone page
(`DIODE_DASHBOARD_ALLOW_ANONYMOUS=1 streamlit run
apps/dashboard/diode_panel.py`; both pass `apps.dashboard.auth` first). Each
used to carry its own
copy of the banner, the four counters and the closing paragraph, which is how
a honesty gate fixed in one file stayed broken in the other, printing
`Outbound connections 0` beside an honest `Outbound bytes not observed`.
One renderer, one set of gates, both AppTests lock it.

`status` is a `ProofReader.read()` result. The file is written by the host it
attests, so `assess()` owns the verdict and nothing here may upgrade it: the
banner prints the verdict it was given, a count only renders as a number when
the kernel exposed a socket table, and a byte total only renders when the
monitor measured one.
"""
from __future__ import annotations

import streamlit as st


def render_diode_proof(status: dict) -> None:
    """Draw everything below the caller's own heading for one status read."""
    if not status["available"]:
        st.error("No monitor status yet, the egress monitor is not running.")
        st.code("python -m src.diode.cli monitor --enforce\n"
                "# without root:  python -m src.diode.cli monitor")
        st.caption(f"Waiting for {status['path']} ...")
        return

    backend = status.get("backend", "none")
    proof = status["proof"]
    verdict = proof["verdict"]
    reasons = [f"`{r}`" for r in proof["reasons"]]

    # ---- verdict banner ----------------------------------------------------
    if verdict == "ENFORCED-VERIFIED":
        st.success(f"**ENFORCED**, kernel egress-deny active ({backend}), "
                   "rules re-verified this tick, zero outbound bytes measured")
    elif verdict == "ENFORCED-UNVERIFIED":
        st.warning("**ENFORCED (UNVERIFIED)**, the byte count was measured but "
                   "the kernel rules could not be re-verified. Treat as "
                   "monitor-only until the ruleset is checked.")
    elif verdict == "MONITOR-ONLY-CLEAN":
        reason = status.get("backend_reason") or "not requested"
        st.warning(
            "**MONITOR-ONLY (OBSERVED CLEAN)**, zero outbound bytes *measured*, "
            "but nothing on this host blocks egress: this is a reading, not a "
            f"guarantee. Enforcement is off because *{reason}*.\n\n"
            "Run `python -m src.diode.cli monitor --enforce` as root on the "
            "nodal machine for enforced proof.")
    elif verdict == "EGRESS-OBSERVED":
        st.error(f"**NON-COMPLIANT**, {proof['reasons'][0]}")
    else:
        st.error(f"**NO PROOF ({verdict})**, nothing is being demonstrated "
                 f"right now:\n\n" + "\n".join(f"- {r}" for r in reasons))

    # ---- headline metrics --------------------------------------------------
    seen = status.get("monitor_available") is True
    ob = status.get("outbound_bytes")
    dropped = status.get("dropped_packets")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Outbound bytes",
              "0" if (proof["proof"] == "pass" and ob == 0) else (
                  ob if proof["proof"] != "unknown" else "not observed"),
              help="Bytes the protected identity actually transmitted outside "
                   "loopback (TCP_INFO via ss). 'not observed' means the "
                   "monitor could not measure, never a silent zero.")
    c2.metric("Outbound connections",
              status.get("outbound_connections", 0) if seen else "not observed",
              help="Live count of the protected identity's sockets with "
                   "non-local peers.")
    c3.metric("Violations (attempts)",
              status.get("violations_total", 0) if seen else "not observed",
              help="Attempted outbound connections detected since the monitor "
                   "started, including ones already open when it started, "
                   "each was dropped by the kernel in enforced mode.")
    c4.metric("Kernel-dropped packets",
              dropped if dropped is not None else "n/a",
              help="nftables drop-rule counter: packets the kernel refused "
                   "to send for the protected uid.")

    # ---- what the numbers prove -------------------------------------------
    note = ("A data diode physically forbids any return path into the "
            "monitored network, NTRO's problem statement makes *proving* "
            "that part of the deliverable. This panel shows the kernel's "
            "own counters.")
    if proof["proof"] == "pass":
        note += (" Every counter below reads zero, and " +
                 ("the kernel refused every attempt this tick."
                  if verdict == "ENFORCED-VERIFIED" else
                  "nothing on this host refused anything: it is a reading, "
                  "not an enforced guarantee."))
    elif proof["proof"] == "fail":
        note += (" Egress was measured, the traffic and the attempts that "
                 "made it are below.")
    else:
        note += (" Nothing on this host is being measured right now, so no "
                 "zero below is evidence of one-way operation.")
    st.info(note)

    # ---- violations --------------------------------------------------------
    st.subheader("Violations seen")
    violations = status.get("violations") or []
    if violations:
        st.dataframe(violations, use_container_width=True, height=200)
    elif seen:
        st.caption("None since monitor start.")
    else:
        st.caption("This host exposed no socket table, so an attempt could "
                   "not have been recorded either way.")

    # ---- details -----------------------------------------------------------
    with st.expander("Monitor & enforcement details"):
        rows = [
            ("Verdict", f"{verdict} (proof: {proof['proof']})"),
            ("Why", "; ".join(proof["reasons"])),
            ("Mode", status.get("mode")),
            ("Compliant", status.get("compliant")),
            ("Last update", status.get("timestamp")),
            ("Heartbeat age", "unknown" if proof["age_s"] is None
             else f"{proof['age_s']}s"),
            ("Heartbeat counter", status.get("seq")),
            ("Monitor available", status.get("monitor_available")),
            ("Protected identity",
             (f"{status.get('protected_user')} "
              f"(uid {status.get('protected_uid')})")),
            ("Enforcement backend", status.get("backend")),
            ("Enforcement verified", status.get("enforcement_verified")),
            ("Byte accounting", status.get("bytes_accounting")),
            ("Local addresses", ", ".join(status.get("local_addresses") or [])),
            ("Status file", status["path"]),
        ]
        for label, value in rows:
            st.write(f"**{label}:** {value}")
