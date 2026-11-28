"""DiodeWatch analyst dashboard: Live · Evidence · Metrics · Diode Proof.

    DIODE_DASHBOARD_ALLOW_ANONYMOUS=1 streamlit run apps/dashboard/app.py
    export DIODE_DASHBOARD_PASSWORD='a shared password of 12+ chars'
    streamlit run apps/dashboard/app.py

Four tabs, one storyline, INPUT → INTELLIGENCE → PROOF:

* **Live**: pick a capture (the synthetic demo pcap is generated on first
  run), replay it window-by-window with auto-refresh, and watch alerts appear
  with flows/sec, alerts/sec and p95 latency. Click a row to inspect it in
  Evidence.
* **Evidence**: the full alert envelope of the selected alert: 5-tuple,
  ATT&CK tags, and every evidence item (observed vs threshold), plus
  STIX 2.1 / incident-report export buttons.
* **Metrics**: per-class precision/recall/F1 from the held-out evaluation
  (results/ml/*.json), false-positive rate on benign slices, and the live
  throughput/latency counters.
* **Diode Proof**: the diode monitor's live status: enforcement banner,
  zero-outbound proof numbers, violations, and why this matters for NTRO.

Runs fully offline; no external calls at runtime.

The app is locked by default: `apps.dashboard.auth` runs before any store,
capture or status file is read. Anonymous access is an explicit loopback-only
demo mode; a network deployment sets a password and terminates TLS in front.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from apps.dashboard.auth import require_auth
from apps.dashboard.diode_view import render_diode_proof
from src.alerts.export_ocsf import write_ocsf
from src.alerts.export_stix import write_stix
from src.alerts.live_store import db_path
from src.alerts.pack import MlChannelReplay, PackSource, available_sources
from src.alerts.report import write_report
from src.alerts.schema import display_class, threat_level
from src.alerts.watch import SessionStore, replay_flows
from src.detectors.ml.pins import load_ml_metrics
from src.detectors.rules import make_rules
from src.diode.monitor import ProofReader
from src.ingest.pcap_reader import stream_flows
from src.triage.worker import TriageWorker, tick

st.set_page_config(page_title="DiodeWatch, Flow Threat Detection",
                   page_icon="🛡️", layout="wide")

# Locked by default: no store, status file or capture is read until this gate
# returns. The wall is a separate surface with its own boundary.
require_auth(st, surface="Analyst dashboard")


# --------------------------------------------------------------------------- #
# session state
# --------------------------------------------------------------------------- #
def _reset_session() -> None:
    tw = st.session_state.get("triage_worker")
    if tw is not None:
        tw.close()
    st.session_state.store = SessionStore()
    st.session_state.replay_started = False
    st.session_state.replay_finished = False
    st.session_state.selected_id = None
    st.session_state.window_gen = None
    st.session_state.ml_replay = None
    st.session_state.triage_worker = None
    st.session_state.pop("feed_sev", None)
    st.session_state.pop("feed_det", None)


if "store" not in st.session_state:
    _reset_session()


# --------------------------------------------------------------------------- #
# replay engine glue
# --------------------------------------------------------------------------- #
def _ensure_demo_pcap() -> Path:
    from scripts.generators.make_demo_pcap import DEFAULT_OUT
    from scripts.generators.make_demo_pcap import main as gen_main

    if not DEFAULT_OUT.exists():
        gen_main([])
    return DEFAULT_OUT


def _start_replay(pcap: Path, window_s: int) -> None:
    flows = list(stream_flows(pcap))
    flows.sort(key=lambda r: r["ts_epoch"])
    st.session_state.window_gen = replay_flows(flows, window_s=float(window_s),
                                               rules=make_rules())
    st.session_state.replay_started = True
    st.session_state.replay_finished = False
    # Pack ML scenarios: the sidecar channel is scored once up front (same
    # loaders/models as `python -m src.detectors.ml_engine`); its alerts are
    # then released progressively while the rule replay advances.
    ml_key = pack_src.key if pack_src is not None else None
    st.session_state.ml_replay = (MlChannelReplay.for_scenario(ml_key)
                                  if ml_key else None)
    # Laya triage: background worker, live verdicts off the hot path.
    st.session_state.triage_worker = TriageWorker()


def _absorb_ml_due(capture_end: float | None) -> None:
    """Release ML-channel alerts whose capture time the replay has reached."""
    ml = st.session_state.get("ml_replay")
    if ml is None:
        return
    if capture_end is None:
        due = ml.drain_all()
        samples = ml.drain_samples()
    else:
        due = ml.due(capture_end)
        samples = ml.due_samples(capture_end)
    if due or samples:
        st.session_state.store.absorb_alerts(due, samples)


def _advance(pcap: Path | None, window_s: int, n_windows: int) -> None:
    """Evaluate the next n_windows of the replay into the session store."""
    if pcap is None:
        return
    if not st.session_state.replay_started:
        _start_replay(pcap, window_s)
    gen = st.session_state.window_gen
    if gen is None:
        return
    for _ in range(n_windows):
        try:
            w = next(gen)
        except StopIteration:
            st.session_state.replay_finished = True
            break
        st.session_state.store.absorb(w)
        _absorb_ml_due(w.capture_end)
    if st.session_state.replay_finished:
        _absorb_ml_due(None)
    _triage_tick(st.session_state.store.alerts)


def _triage_tick(session_alerts: list) -> None:
    """One non-blocking cycle of the background triage worker: submit what has
    no verdict yet, attach what finished, persist those verdicts beside the
    chain so the wall's export of the same alert_id agrees with this feed."""
    tw: TriageWorker | None = st.session_state.get("triage_worker")
    if tw is not None:
        tick(session_alerts, tw, db_path())
# --------------------------------------------------------------------------- #
# sidebar
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.title("🛡️ DiodeWatch")
    st.caption("AI threat detection on unidirectional IP traffic · "
               "offline by design")

    st.subheader("Replay source")
    src_mode = st.radio("Input", ["Demo pcap (synthetic threats)",
                                  "Demo pack (scenario)", "My pcap"],
                        label_visibility="collapsed")
    pcap_path: Path | None = None
    pack_src: PackSource | None = None
    if src_mode == "Demo pcap (synthetic threats)":
        try:
            pcap_path = _ensure_demo_pcap()
            st.success(f"Demo capture ready ({pcap_path.stat().st_size / 1e6:.1f} MB)")
            st.caption("Timeline: benign mix → DDoS flood → slow-DoS → "
                       "port sweep → bulk exfil.")
        except Exception as e:  # noqa: BLE001
            st.error(f"Demo pcap generation failed: {e}")
    elif src_mode == "Demo pack (scenario)":
        try:
            sources = available_sources()
        except Exception as e:  # noqa: BLE001
            sources = []
            st.error(f"Demo pack unavailable: {e}")
        if sources:
            def _src_label(s: PackSource) -> str:
                return s.label

            pack_src = st.selectbox(
                "Scenario", sources, format_func=_src_label,
                label_visibility="collapsed")
            pcap_path = pack_src.pcap
            st.success(f"{pack_src.pcap.name} "
                       f"({pack_src.pcap.stat().st_size / 1e6:.1f} MB)")
            st.caption(pack_src.story)
            st.caption(f"✅ {pack_src.detector_note}")
        else:
            st.info("Pack not generated yet, run "
                    "`python scripts/generators/make_demo_pack.py` (or reload this page "
                    "and it will generate once, automatically).")
    else:
        pcaps = sorted((REPO_ROOT / "data" / "pcaps").glob("*.pcap*"))
        if pcaps:
            pcap_path = st.selectbox("Capture", pcaps,
                                     format_func=lambda p: p.name)
        else:
            st.info("No .pcap files in data/pcaps/, drop one there or use "
                    "the demo capture.")

    # a source switch must start a fresh session (the replay generator is
    # bound to the capture it was started with)
    src_key = ("demo" if src_mode == "Demo pcap (synthetic threats)"
               else f"pack:{pack_src.key}" if pack_src is not None
               else f"file:{pcap_path}" if pcap_path is not None
               else "none")
    if st.session_state.get("src_key") != src_key:
        st.session_state.src_key = src_key
        if st.session_state.get("replay_started"):
            _reset_session()

    window_s = st.slider("Window size (s)", 5, 60, 10)
    speed = st.slider("Windows per tick", 1, 10, 1)
    auto = st.toggle("Auto-refresh", value=True)
    interval = st.select_slider("Refresh interval (s)", [1, 2, 3, 5], value=2)

    st.divider()
    st.caption(f"Session: {len(st.session_state.store.alerts):,} alerts · "
               f"{st.session_state.store.stats.flows:,} flows evaluated")
    if st.button("↺ Reset session", use_container_width=True):
        _reset_session()
        st.rerun()


# --------------------------------------------------------------------------- #
# LIVE tab
# --------------------------------------------------------------------------- #
tab_live, tab_ev, tab_metrics, tab_diode = st.tabs(
    ["🔴 Live", "🔎 Evidence", "📈 Metrics", "🔒 Diode Proof"])


def _render_live() -> None:
    store: SessionStore = st.session_state.store
    m = store.metrics()
    # the session's posture, from the table the wall's hero reads: an empty
    # session says CALM, a critical one says CRITICAL, on both surfaces
    level = threat_level(m.get("max_severity"))
    show = (st.error if level == "CRITICAL"
            else st.warning if level != "CALM" else st.caption)
    show(f"Session threat level, **{level}** · {m['alerts']:,} alerts")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Flows / sec (replay)", f"{m['replay_fps']:,.1f}",
              help="Capture-time flow rate being fed through the pipeline.")
    m2.metric("Alerts / sec", f"{m['alerts_per_sec']:,.2f}")
    m3.metric("p95 window eval", f"{m['p95_eval_ms']:,.0f} ms",
              help="Wall time to evaluate one window of flows (p95).")
    m4.metric("Sustained capacity", f"{m['sustained_fps']:,.0f} flows/s",
              help="Max flow rate the evaluation loop could sustain "
                   "continuously (per-window flows / eval time).")
    if m.get("alerts_raw"):
        st.caption(
            f"Idempotent ingest, {m['alerts_raw']:,} raw detections → "
            f"{m['alerts']:,} unique records "
            f"({m['alerts_suppressed']:,} re-detections collapsed; "
            f"{m['entities']} distinct entities)."
        )
    tw: TriageWorker | None = st.session_state.get("triage_worker")
    if tw is not None:
        st.caption(tw.status_line())

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Alert feed")
        if store.alerts:
            recent = store.alerts[-300:][::-1]
            # filter chips: severity + detector. Options come from the whole
            # session store (alerts only accumulate, so a chip never vanishes
            # between reruns) and are cleared on session reset.
            f_sev, f_det = st.columns(2)
            with f_sev:
                sev_sel = st.pills(
                    "Severity", ["all", "critical", "high", "medium", "low"],
                    selection_mode="multi", default=["all"], key="feed_sev",
                    label_visibility="collapsed")
            with f_det:
                det_opts = ["all"] + sorted(
                    {(a.detector or "unknown") for a in store.alerts})
                det_sel = st.pills(
                    "Detector", det_opts, selection_mode="multi",
                    default=["all"], key="feed_det",
                    label_visibility="collapsed")

            def _active(sel: list[str] | None) -> list[str]:
                # 'all' wins only when selected alone (or nothing is): tapping
                # a specific chip while 'all' is still on must filter
                sel = [s for s in (sel or []) if s != "all"]
                return sel

            sev_f = _active(sev_sel)
            det_f = _active(det_sel)
            shown = [a for a in recent
                     if (not sev_f or (a.severity or "medium").lower() in sev_f)
                     and (not det_f or (a.detector or "unknown") in det_f)]
            if sev_f or det_f:
                st.caption(f"Showing {len(shown)} of {len(recent)} alerts "
                           "(filters active).")
            if shown:
                rows = [{
                    "time": a.timestamp, "threat": display_class(a.threat_class),
                    "severity": (a.severity or "medium").upper(),
                    "conf": round(float(a.confidence), 2),
                    "key": a.key or "", "detector": a.detector or "",
                    "ATT&CK": a.attack_technique or "",
                } for a in shown]
                event = st.dataframe(
                    pd.DataFrame(rows), use_container_width=True, height=360,
                    on_select="rerun", selection_mode="single-row", key="feed")
                sel_rows = event.selection.rows
                if sel_rows:
                    aid = shown[sel_rows[0]].alert_id
                    if aid != st.session_state.selected_id:
                        st.session_state.selected_id = aid
                        st.session_state._evidence_refresh = True
                st.caption("Click a row, then open the **Evidence** tab.")
            else:
                st.info("No alerts match the current filters, tap **all "
                        "** on a chip row to clear.")
        else:
            st.info("No alerts yet, start the replay below.")
    with right:
        st.subheader("Timeline (alerts / window)")
        if store.timeline:
            tl = (pd.DataFrame({"t": list(store.timeline.keys()),
                                "alerts": list(store.timeline.values())})
                  .sort_values("t"))
            # Zero-fill every second across the range so bursts read as
            # spikes against a quiet baseline (sparse 1-alert seconds
            # otherwise render as a flat line).
            t0, t1 = int(tl["t"].min()), int(tl["t"].max())
            if t1 > t0 and t1 - t0 <= 7200:
                full = pd.DataFrame({"t": range(t0, t1 + 1)})
                tl = full.merge(tl, on="t", how="left").fillna({"alerts": 0})
            tl["time"] = pd.to_datetime(tl["t"], unit="s")
            st.bar_chart(tl.set_index("time")["alerts"], height=250)
        else:
            st.caption("The timeline fills as alerts fire.")

    if st.session_state.replay_finished:
        ml_replay = st.session_state.get("ml_replay")
        n_ml = ml_replay.total if ml_replay is not None else 0
        if pack_src is not None and not pack_src.rule_expected and n_ml == 0:
            st.info(
                f"Replay complete, {store.stats.flows:,} flows in "
                f"{store.stats.windows} windows with **zero alerts**: this "
                "scenario is detected by an ML channel that needs its model "
                "artifact under models/. " + pack_src.detector_note)
        elif pack_src is not None and not pack_src.rule_expected:
            st.success(
                f"Replay complete, {store.stats.flows:,} flows in "
                f"{store.stats.windows} windows, **{n_ml} ML-channel "
                "alerts** released in capture-time order as the scenario "
                "replayed (zero rule alerts, as designed, this threat is "
                "not a window-shape rule). Inspect one in **Evidence**.")
        else:
            st.success(f"Replay complete, {store.stats.flows:,} flows in "
                       f"{store.stats.windows} windows, "
                       f"{len(store.alerts)} alerts. "
                       f"Inspect any alert in **Evidence**; "
                       f"benchmarks are in **Metrics**.")


# one window per full-script run (any widget interaction); the Live fragment
# advances `speed` more per auto-refresh tick on top of this
if pcap_path is not None and not st.session_state.replay_finished:
    _advance(pcap_path, window_s, 1)

with tab_live:
    if auto and not st.session_state.replay_finished:
        @st.fragment(run_every=interval)
        def _live_tick() -> None:
            _advance(pcap_path, window_s, speed)
            _render_live()
            # a finished replay or a fresh row selection must reach the
            # OTHER tabs, which only render on a full-script run
            if st.session_state.pop("_evidence_refresh", False) \
                    or st.session_state.replay_finished:
                try:
                    st.rerun(scope="app")
                except TypeError:  # streamlit < 1.37
                    st.rerun()

        _live_tick()
    else:
        _render_live()
        if not st.session_state.replay_finished and st.button(
                "▶ Evaluate next window", type="primary"):
            _advance(pcap_path, window_s, 1)
            st.rerun()
    if st.session_state.replay_finished and st.button("↻ Replay from start"):
        _reset_session()
        st.rerun()

# --------------------------------------------------------------------------- #
# EVIDENCE tab
# --------------------------------------------------------------------------- #
with tab_ev:
    alerts = st.session_state.store.alerts
    if not alerts:
        st.info("Run a replay in the **Live** tab, click an alert row, and "
                "its full evidence appears here.")
    else:
        sel_id = st.session_state.get("selected_id")
        sel = next((a for a in alerts if a.alert_id == sel_id), alerts[-1])
        if sel_id != sel.alert_id:
            st.caption("Showing the newest alert (click a Live row to pin "
                       "another).")

        st.subheader(f"{display_class(sel.threat_class)}, {sel.detector or '?'}")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Confidence", f"{float(sel.confidence) * 100:.0f}%")
        c2.metric("Severity", (sel.severity or "medium").upper())
        c3.metric("ATT&CK", sel.attack_technique or " -")
        c4.metric("Window", f"{sel.window_seconds or 10:.0f}s")

        triage = getattr(sel, "triage", None)
        if triage:
            st.caption(
                f"🧠 **Laya triage (advisory):** {triage.get('recommended', ' -')}"
                f" · urgency {float(triage.get('urgency') or 0):.2f}/3"
                f" · P(false-positive) "
                f"{float(triage.get('p_false_positive') or 0):.2f}"
                f" · corroborates class "
                f"{float(triage.get('corroborates_class') or 0):.2f}")

        _agg = (sel.flow_id or "").endswith("/*")
        _entity = sel.src_ip or sel.dst_ip or sel.key or "?"
        _tuple = (f"{_entity}, window aggregate (one entity, many flows; "
                  f"no single port)" if _agg else
                  f"{sel.src_ip or '?'}:{sel.src_port or '?'} → "
                  f"{sel.dst_ip or '?'}:{sel.dst_port or '?'} "
                  f"({sel.proto or '?'})")
        st.markdown(
            f"**Entity:** `{sel.key or ' -'}`&nbsp;&nbsp;·&nbsp;&nbsp;"
            f"**Flow:** `{sel.flow_id or ' -'}`  \n"
            f"**{'Entity (window aggregate)' if _agg else '5-tuple'}:** "
            f"`{_tuple}`&nbsp;&nbsp;·&nbsp;&nbsp;"
            f"**Tactic:** {sel.attack_tactic or ' -'}&nbsp;&nbsp;·&nbsp;&nbsp;"
            f"**Time:** {sel.timestamp}")

        st.markdown("**Evidence, observed vs threshold**")
        ev_rows = [{
            "condition": e.condition,
            "observed": e.observed,
            "op": e.operator,
            "threshold": e.threshold,
            "unit": e.unit,
            "description": e.description,
        } for e in sel.evidence]
        st.dataframe(pd.DataFrame(ev_rows), use_container_width=True,
                     height=min(80 + 28 * max(len(ev_rows) - 1, 0), 340))

        d1, d2, d3, _ = st.columns([1, 1, 1, 1])
        with d1:
            if st.button("🛰 Build STIX 2.1 bundle"):
                out = REPO_ROOT / "data" / "alerts" / "ui_stix_bundle.json"
                _, problems = write_stix([sel], out)
                if problems:
                    st.error(f"STIX validation: {problems}")
                else:
                    st.session_state.stix_bytes = out.read_bytes()
        with d2:
            if st.button("🧭 Build OCSF 1.10 finding"):
                out = REPO_ROOT / "data" / "alerts" / "ui_ocsf_finding.json"
                _, problems = write_ocsf([sel], out)
                if problems:
                    st.error(f"OCSF validation: {problems}")
                else:
                    st.session_state.ocsf_bytes = out.read_bytes()
                    st.session_state.ocsf_alert_id = sel.alert_id
        with d3:
            if st.button("📄 Build incident report"):
                out = REPO_ROOT / "data" / "alerts" / "ui_incident.html"
                write_report([sel], out,
                             title=f"Incident, {display_class(sel.threat_class)} "
                                   f"({sel.timestamp})")
                st.session_state.report_bytes = out.read_bytes()

        if st.session_state.get("stix_bytes"):
            st.download_button("⬇ Download stix_bundle.json",
                               data=st.session_state.stix_bytes,
                               file_name=f"stix_{sel.threat_class}.json",
                               mime="application/json")
        if (st.session_state.get("ocsf_bytes")
                and st.session_state.get("ocsf_alert_id") == sel.alert_id):
            st.download_button("⬇ Download ocsf_detection_finding.json",
                               data=st.session_state.ocsf_bytes,
                               file_name=f"ocsf_detection_{sel.threat_class}.json",
                               mime="application/json")
        if st.session_state.get("report_bytes"):
            st.download_button("⬇ Download incident_report.html",
                               data=st.session_state.report_bytes,
                               file_name="incident_report.html",
                               mime="text/html")

        with st.expander("Raw alert JSON"):
            st.json(sel.to_dict())


# --------------------------------------------------------------------------- #
# METRICS tab
# --------------------------------------------------------------------------- #
with tab_metrics:
    st.subheader("Detection quality, held-out evaluation (results/ml)")
    ml = load_ml_metrics(REPO_ROOT)
    rows = []
    win = ml.get("window", {})
    disabled = []
    for cls, pc in (win.get("per_class") or {}).items():
        # threshold=None: the tuning slice never reached the precision gate,
        # so the class is rank-only. Scoring it as 0.000 would read as a
        # measured failure rather than a disabled channel.
        if pc.get("threshold") is None:
            disabled.append(cls)
            continue
        rows.append({"detector": "ml.flowctx", "class": cls,
                     "precision": pc.get("precision", 0.0),
                     "recall": pc.get("recall", 0.0),
                     "F1": pc.get("f1", 0.0),
                     "support": pc.get("support", 0)})
    sup = ml.get("supervised", {})
    for cls, pc in (sup.get("per_class") or {}).items():
        rows.append({"detector": "ml.supervised (reference)", "class": cls,
                     "precision": pc.get("precision", 0.0),
                     "recall": pc.get("recall", 0.0),
                     "F1": pc.get("f1", 0.0),
                     "support": pc.get("support", 0)})
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, height=270)
        st.caption("Protocol A: stratified per-day holdout. The reference "
                   "flow-level model plateaus at macro-F1 ≈ 0.30 (documented "
                   "in docs/ml.md); the flow+window ensemble is the "
                   "production detector.")
        if disabled:
            st.caption("ml.flowctx disabled by the precision gate (rank-only, "
                       "never alerts): " + ", ".join(disabled) + ".")
    else:
        st.info("results/ml/*.json not found, run scripts/checks/check_ml.py "
                "train-windows to populate the tables.")

    # The per-class table cannot express beacon/DGA/TLS protocols (ROC-AUC on
    # candidate pairs, family holdout, synthetic plant). Name their real
    # numbers instead of omitting three of five channels.
    other = []
    if ml.get("beacon"):
        b = ml["beacon"]
        other.append(
            f"**ml.beacon** ROC-AUC {float(b.get('roc_auc_macro') or 0):.3f} "
            f"macro (LOSO) · P {float(b.get('precision') or 0):.3f} / "
            f"R {float(b.get('recall') or 0):.3f}")
    if ml.get("dga"):
        d = ml["dga"]
        other.append(
            f"**ml.dga** F1 {float(d.get('f1') or 0):.3f} · "
            f"P {float(d.get('precision') or 0):.3f} / "
            f"R {float(d.get('recall') or 0):.3f}")
    if ml.get("tls"):
        t = ml["tls"]
        plant = t.get("synthetic_plant_eval") or {}
        wl = plant.get("watchlist_only") or {}
        nov = plant.get("novelty_only") or {}
        line = (f"**ml.tls** synthetic plant F1 "
                f"{float(plant.get('f1') or 0):.3f}")
        if wl or nov:
            line += (f" · detections: watchlist {int(wl.get('tp') or 0)},"
                     f" novelty {int(nov.get('tp') or 0)}")
        line += (f" · {int(t.get('watchlist_size') or 0)} JA3 watchlist · "
                 f"novelty layer "
                 + ("active" if t.get("novelty_available")
                    else "disabled (fit baseline has no spread)"))
        other.append(line)
    if other:
        st.caption("Other channels, each gated on its own protocol: "
                   + " · ".join(other))

    st.subheader("False-positive rate on benign slices")
    fpd = win.get("benign_false_positives_per_day", {})
    if fpd:
        fp = pd.DataFrame({"corpus day": list(fpd.keys()),
                           "benign rows flagged": list(fpd.values())})
        st.dataframe(fp, use_container_width=True, height=200)
        total_fp = sum(fpd.values())
        st.metric("Total benign false positives (held-out days)",
                  total_fp,
                  delta="0 required" if total_fp == 0 else None,
                  delta_color="normal" if total_fp == 0 else "inverse")
    else:
        st.caption("No per-day benign FP data in window metrics.")

    st.subheader("Throughput & latency")
    m = st.session_state.store.metrics()
    if st.session_state.store.stats.windows:
        b1, b2, b3, b4 = st.columns(4)
        b1.metric("Sustained capacity", f"{m['sustained_fps']:,.0f} flows/s")
        b2.metric("Replay rate", f"{m['replay_fps']:,.1f} flows/s")
        b3.metric("p95 window eval", f"{m['p95_eval_ms']:,.0f} ms")
        b4.metric("p95 per-flow", f"{m['p95_per_flow_ms'] * 1000:,.0f} µs")
        st.caption("Live rule-engine loop counters for this session. "
                   "Benchmark rating (docs/benchmarks.md): 10,000 flows/s "
                   "sustained at the rule engine, 32,301 flows/s batch ML "
                   "scoring, twice the 5,000 flows/s requirement.")
    else:
        st.caption("Run a replay to collect this session's throughput "
                   "counters.")

    # Tamper-evident evidence chain (C1), the live db both launchers share.
    st.subheader("Evidence integrity, hash-chained alerts")
    try:
        from src.alerts.store import verify_chain as _verify

        _db = db_path()
        if _db.exists():
            _res = _verify(_db)
            if _res["ok"] and _res["links"]:
                head = _res["head"] or {}
                # The wall's words for the same computation. "PASS" alone was a
                # stronger claim than this panel is owed: re-hashing proves the
                # rows agree with each other, only the ledger beside the db
                # proves nobody rewrote them and re-hashed the history.
                verdict = ("RE-VERIFIED · ANCHORED" if _res["anchored"]
                           else "RE-VERIFIED (no anchor)")
                st.code(f"db:         {_db}\n"
                        f"links:      {_res['links']:,}\n"
                        f"chain head: {head.get('chain_hash', ' -')}\n"
                        f"integrity:  {verdict}",
                        language=None)
                if not _res["anchored"]:
                    st.caption(f"No append-only ledger beside {_db}: every link "
                               "recomputed, so the chain is self-consistent, a "
                               "rewritten history re-hashed would look the same.")
            elif _res["ok"]:
                st.caption("Live evidence db exists but no alerts have been "
                           "stored yet, launch a replay from the web wall "
                           "(:8530) and the chain climbs here in real time.")
            else:
                st.error(f"Evidence chain BREAK DETECTED: {_res['error']}")
        else:
            st.caption("No live evidence db yet, launch a replay from the "
                       "web wall (:8530) or run `python -m src.alerts.cli "
                       "store` to build one.")
    except Exception as e:  # noqa: BLE001, never break Metrics on db issues
        st.caption(f"Evidence chain unavailable: {e}")

# --------------------------------------------------------------------------- #
# DIODE PROOF tab (fragment: re-polls the monitor JSON every 2 s)
# --------------------------------------------------------------------------- #
with tab_diode:
    @st.fragment(run_every=2)
    def _diode_card() -> None:
        # the same reader and the same renderer as the standalone Diode Proof
        # page: one status file, one staleness window, one set of honesty
        # gates, so the two Streamlit surfaces cannot diverge again.
        reader = st.session_state.setdefault("diode_reader", ProofReader())
        st.subheader("🔒 One-way guarantee, enforced, not claimed")
        render_diode_proof(reader.read())

    _diode_card()
