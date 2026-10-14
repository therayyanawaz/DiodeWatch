#!/usr/bin/env python3
"""Exit check: dashboard data plane, end to end, headless.

The Streamlit UI is a thin layer over this pipeline; the acceptance criteria
are therefore verified against the same calls the UI makes:

  1. demo pcap generates (or regenerates) deterministically;
  2. replay of the demo capture fires all four rule signatures -
     ddos, slowdos, scan, exfil, with ZERO alerts on benign windows;
  3. performance counters populate (flows/sec, alerts/sec, p95 latency);
  4. alert→evidence→export chain works: STIX bundle validates, incident
     report renders, both from a session alert;
  5. the diode status path the Diode Proof tab polls returns honest data;
  6. apps/dashboard/app.py imports clean and declares the four tabs.

    python scripts/checks/check_dashboard.py
"""
from __future__ import annotations

import ast
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from src.alerts.export_stix import write_stix
from src.alerts.report import write_report
from src.alerts.schema import display_class
from src.alerts.watch import SessionStore, replay_flows
from src.ingest.pcap_reader import stream_flows

DEMO = REPO / "data" / "pcaps" / "demo_threats.pcap"
OUT = REPO / "data" / "alerts"
BASE_TS = 1_700_000_000.0
SCENARIOS = {  # detector -> expected (key, scenario window start)
    "ddos": ("10.9.9.9", BASE_TS + 50),
    "slowdos": ("10.7.7.7", BASE_TS + 80),
    "scan": ("10.5.0.7", BASE_TS + 50),
    "exfil": ("10.20.0.9", BASE_TS + 80),
}


def main() -> int:
    ok = True

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f", {detail}" if detail else ""))
        ok = ok and cond

    # ---- 1. demo capture ---------------------------------------------------
    print("=== demo pcap")
    if not DEMO.exists():
        from scripts.generators.make_demo_pcap import main as gen_main

        gen_main([])
    check("demo pcap exists", DEMO.exists(), str(DEMO.name))

    # ---- 2+3. replay through the engine the UI drives ----------------------
    print("=== replay (SessionStore + replay_flows, as the Live tab drives)")
    flows = list(stream_flows(DEMO))
    flows.sort(key=lambda r: r["ts_epoch"])
    store = SessionStore()
    t0 = time.perf_counter()
    for w in replay_flows(flows, window_s=10):
        store.absorb(w)
    wall = time.perf_counter() - t0

    fired: dict[str, tuple[str, float]] = {}
    benign_windows = 0
    benign_fp = None
    for w in replay_flows(flows, window_s=10):
        for a in w.alerts:
            fired.setdefault(a.detector, (a.key, w.window_start))
        if w.window_start < BASE_TS + 50 and w.n_flows:
            benign_windows += 1
            if w.alerts:
                benign_fp = (w.window_start, [a.detector for a in w.alerts])
    for det, (key, _win) in SCENARIOS.items():
        got = fired.get(det)
        check(f"{det} fired on {key}",
              got is not None and got[0] == key,
              f"window {(_win - BASE_TS):.0f}s" if got else "missing")
    check("zero false alarms on benign windows", benign_fp is None,
          f"{benign_windows} benign windows")

    m = store.metrics()
    print(f"  metrics: {m}")
    check("throughput counters populated",
          m["replay_fps"] > 0 and m["windows"] > 0)
    check("latency counters populated", m["p95_eval_ms"] > 0)
    check("replay completes quickly", wall < 120, f"{wall:.1f}s")

    # ---- 4. evidence -> exports --------------------------------------------
    print("=== evidence & exports")
    alert = store.alerts[0]
    check("session alert carries evidence", bool(alert.evidence),
          f"{len(alert.evidence)} items")
    check("alert carries ATT&CK tag", bool(alert.attack_technique),
          alert.attack_technique or "")
    OUT.mkdir(parents=True, exist_ok=True)
    bundle, problems = write_stix([alert], OUT / "accept_bundle.json")
    check("STIX 2.1 bundle validates", not problems,
          f"{len(bundle['objects'])} objects")
    rep = write_report([alert], OUT / "accept_incident.html",
                       title="Dashboard acceptance")
    html = rep.read_text(encoding="utf-8")
    check("incident report renders evidence",
          all(e.condition in html for e in alert.evidence)
          # the words the reader is shown, not the detector's identifier
          and display_class(alert.threat_class) in html)

    # ---- 5. diode status path (exactly what the tab polls) ------------------
    print("=== diode proof path")
    from src.diode.monitor import ProofReader

    # read through the same reader the surfaces use: a checker that opened a
    # hardcoded path would pass while every UI reported NO-STATUS
    reader = ProofReader()
    status = reader.read()
    if not status["available"]:
        from src.diode.enforcer import protected_uid
        from src.diode.monitor import Monitor

        mon = Monitor(protected_uid(), status_file=reader.path,
                      events_file=None, ss_bin="ss")
        mon.run(once=True)
        status = reader.read()
    check("diode status JSON available", status["available"])
    if status["available"]:
        check("diode status honest",
              status.get("mode") in ("enforced", "monitor-only")
              and "monitor_available" in status,
              f"mode={status.get('mode')} backend={status.get('backend')}")

    # ---- 6. dashboard declares the four tabs -------------------------------
    print("=== dashboard module")
    src = (REPO / "apps" / "dashboard" / "app.py").read_text(encoding="utf-8")
    try:
        ast.parse(src)
        check("apps/dashboard/app.py parses", True)
    except SyntaxError as e:
        check("apps/dashboard/app.py parses", False, str(e))
    lines = src.splitlines()
    tabs_line = next((ln + lines[i + 1] for i, ln in enumerate(lines)
                      if "st.tabs(" in ln and i + 1 < len(lines)), "")
    for tab in ("Live", "Evidence", "Metrics", "Diode Proof"):
        check(f"tab declared: {tab}", tab in tabs_line)

    # ---- 7. demo pack sources in the sidebar --------------------------------
    print("=== demo pack sources (sidebar)")
    from src.alerts.pack import MlChannelReplay, available_sources

    try:
        sources = available_sources()
    except Exception as e:  # noqa: BLE001
        sources = []
        check("pack sources load", False, str(e))
    check("six pack sources available", len(sources) == 6,
          f"{[s.key for s in sources]}")
    for s in sources:
        flows = list(stream_flows(s.pcap))
        flows.sort(key=lambda r: r["ts_epoch"])
        s_alerts = []
        for w in replay_flows(flows, window_s=10):
            s_alerts.extend(a.threat_class for a in w.alerts)
        if s.rule_expected:
            check(f"{s.key}: rule replay fires {list(s.rule_expected)}",
                  set(s.rule_expected) <= set(s_alerts),
                  f"got {sorted(set(s_alerts))}")
        else:
            check(f"{s.key}: rule replay silent (ML channel scenario)",
                  not s_alerts, f"got {sorted(set(s_alerts))}")
            ml = MlChannelReplay.for_scenario(s.key)
            n_ml = ml.total
            check(f"{s.key}: ML channel fires ({n_ml} alerts)", n_ml > 0,
                  f"got {n_ml}")
            # progressive release: nothing due before its first capture time,
            # everything out by the end
            if n_ml and ml.alerts[0].timestamp:
                from src.alerts.pack import pd_ts_to_epoch
                t0 = pd_ts_to_epoch(ml.alerts[0].timestamp)
                check(f"{s.key}: ML alerts release in capture-time order",
                      not ml.due(t0 - 1) and len(ml.due(t0) + ml.drain_all())
                      == n_ml, "cursor did not advance in order")
    check("dashboard wires pack sources",
          '"Demo pack (scenario)"' in src and "available_sources" in src
          and "MlChannelReplay" in src)

    # ---- 8. alert-feed filter chips (severity + detector) -------------------
    print("=== alert-feed filter chips")
    check("feed renders severity + detector pills",
          "st.pills" in src and 'key="feed_sev"' in src
          and 'key="feed_det"' in src)
    check("severity bands offered",
          '"critical"' in src and '"high"' in src and '"medium"' in src)
    check("specific chip overrides 'all'", 's != "all"' in src)
    check("detector options derived from session alerts",
          '(a.detector or "unknown")' in src)

    print("\n[PASS] Dashboard acceptance criteria met" if ok
          else "\n[FAIL] acceptance criteria NOT met", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
