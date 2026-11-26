# Live demonstration script (3-5 minutes)

Everything runs **offline** on this laptop: no cloud, no APIs, no internet.
Pre-flight (once, before judges arrive): `python scripts/checks/rehearse_demo.py`
twice (two green `demo is GO` runs) then open the dashboard:

    .venv/Scripts/python.exe -m streamlit run apps/dashboard/app.py
    # http://localhost:8501, keep the 🔴 Live tab selected, demo pcap source

(`run_demo.bat` does the same and generates the pack + restores the pinned
models first; `--port 8510` moves it. The mission-control wall on `:8530`,
`python apps/mission_control/server.py`, is the alternative surface, same
pipeline, same numbers, one shared replay session, see `docs/dashboard.md`.)

---

## 0. The scenario (30 s, talk over the idle dashboard)

> "This is an AI watchtower for a **unidirectional** network, the kind of
> one-way link NTRO protects with **data diodes**. Traffic can only flow OUT
> of the secure enclave, and nothing can flow back in. That keeps the
> classified network safe, but it also blinds us: no active scanning, no
> agent callbacks, no DNS answers, the sensor sees packets and nothing else.
> Everything you're about to see runs on that one-sided view, entirely on
> this machine."

## 1. Live, replay a capture (60-90 s)

In the sidebar the demo pcap is already selected ("Demo pcap (synthetic
threats)": realistic background, then two mixed battlespace windows -
DDoS flood reconned under cover, slow-DoS running while data walks out
the door, like a real incident). Auto-refresh is on; let it run.

> "The capture streams in 10-second windows through the same pipeline a
> deployment would run. Watch the alert feed."

Points to hit as alerts appear:

- the **metrics strip**: flows/sec, alerts/sec, p95 window eval, and
  **sustained capacity** (say the number, the benchmark rates the rule
  engine at **10,000 flows/s sustained**, twice the 5,000 target);
- the **timeline chart** filling as each attack window closes;
- "no machine learning yet, these are interpretable rules, so an analyst
  can read exactly why each alert fired."

## 2. Evidence, open one alert (60 s)

Click the exfil row in the feed (or the newest alert), switch to 🔎 Evidence.

> "Every alert is SOC-ready by schema: threat class, confidence, severity -
> and here's the part that matters, **evidence**: each fired condition with
> the observed value against its threshold. This one uploaded 19.2 megabytes
> where the policy allows 5. The ATT&CK tag, T1048, exfiltration over
> web service, plugs straight into a SOC workflow."

Press **Export STIX** (bundle downloads; 2.1, validates clean) and mention
the HTML incident report (`python -m src.alerts.cli report ...`, docs/alerts.md).

## 3. Metrics, held-out numbers (45 s)

Switch to 📈 Metrics.

> "Accuracy claims are from the full-corpus pass, not a curated slice. The
> pre-committed rule gates split: CIC-DDoS2019 F1 0.958 with benign FPR
> 0.0069 passes; CIC-IDS2017 F1 0.611 with FPR 0.1496 fails. At alert level
> the same layer is exact on 0.919 of DDoS2019 alerts but catches only 0.122
> of DDoS incidents; on CIC2017 exact precision is 0.084 and 523 of 594
> alerts are benign-only. The C2 beacon model scores ROC-AUC 0.92 on botnets
> it has never seen; the DGA model sits at 0.90 precision with a 0.11
> false-positive rate on a million benign domains. The failures are on the
> page beside the passes."

## 4. Diode Proof, the zero that must stay zero (45 s)

Switch to 🔒 Diode Proof.

> "This panel is the proof the problem statement asks for: the kernel's own
> counters. On the deployment box it runs **enforced**, the ruleset refuses
> egress for the analytics identity, the byte counter is *measured* and reads
> zero, and any attempt appears in the violation log below. On this laptop the
> same panel reads **MONITOR-ONLY** with `not observed` counters, because
> Windows gives the monitor no `/proc/net` to read. It prints that instead of a
> zero it did not measure, and that refusal is half the guarantee: a readout
> that looks clean while blind would prove nothing. The watchtower can see
> everything and touch nothing."

## 5. Close (30 s), the second story: C2 + DNS (optional, if time)

> "One more scenario, live in the same dashboard. Under **Demo pack
> (scenario)** pick *02 · C2 beaconing*: the beacon model fires on the
> infected host at 0.98 confidence and the alert lands in the feed exactly
> when that C2 contact replays. Then *03 · DNS tunnel / DGA*: watch 46
> alerts stream in timed to each tunneled DNS query, click one and its
> lexical evidence is right there; the pack's benign names were not flagged.
> Two more
> rule stories round out the coverage: *05 · Slow-rate DoS* (40 held
> dribbles, no volumetric footprint) and *06 · Ratio exfiltration* (28:1
> asymmetric upload under the bulk bar). The same
> channels run headless too: `python scripts/checks/rehearse_demo.py` replays the
> whole pack (detections, store, exports, diode) in one scripted pass."

---

## Failure drills (if a judge asks)

| question | answer |
|---|---|
| "What if the ML model is wrong?" | Rules and ML are independent layers; every alert carries its evidence so an analyst can overrule it; thresholds are config, not code. |
| "Does it need the internet?" | Never, ingest, models, exports, and the diode monitor all run offline; corpora are pre-cached. |
| "Where do the numbers come from?" | `docs/benchmarks.md` + `results/benchmarks/*.json`, regenerated by `scripts/benchmarks/bench_throughput.py` and `scripts/benchmarks/bench_accuracy.py`. |
| "What does 'enforced' mean here?" | `python -m src.diode.cli monitor --enforce` under WSL root installs egress-deny rules; the kernel drop counter is the proof (docs/diode.md). |
