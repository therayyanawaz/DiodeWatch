"""Diode Proof panel — the live, always-on proof of zero egress.

Polls the egress monitor's status JSON through the shared `ProofReader`
(the file `DIODE_STATUS_FILE` points at, judged against the
`DIODE_PROOF_MAX_AGE_S` staleness window) every 2 s and hands it to
`diode_view.render_diode_proof()`, the renderer the dashboard's Diode Proof tab
uses too: the verdict banner, the proof numbers (outbound bytes, connections,
violation attempts, kernel drops) and the violation log are drawn from one
place, so neither surface can print a claim the other has to retract.

Run the monitor first:

    python -m src.diode.cli monitor --enforce      # nodal centre (root)
    python -m src.diode.cli monitor                # no root: monitor-only

then start the panel:

    streamlit run apps/dashboard/diode_panel.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from apps.dashboard.diode_view import render_diode_proof
from src.diode.monitor import ProofReader

st.set_page_config(page_title="Diode Proof - zero egress", page_icon="🔒",
                   layout="wide")


def render() -> None:
    st.title("🔒 Diode Proof")
    st.caption("Enforced, not claimed: every outbound packet of the analytics "
               "identity is dropped by the kernel except loopback. This panel "
               "shows the live proof.")

    # one reader for every surface (the wall uses the same class), so the
    # staleness window and the heartbeat memory cannot diverge per UI
    reader = st.session_state.setdefault("diode_reader", ProofReader())
    render_diode_proof(reader.read())


if hasattr(st, "fragment"):  # Streamlit >= 1.37: auto-refresh
    render = st.fragment(run_every=2.0)(render)

render()
if not hasattr(st, "fragment"):
    st.caption("Auto-refresh needs Streamlit >= 1.37 - press R or click "
               "refresh to repoll.")
    if st.button("Refresh now"):
        st.rerun()
    time.sleep(0.1)
