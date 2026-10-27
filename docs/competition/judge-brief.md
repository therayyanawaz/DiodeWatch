# DiodeWatch — Passive Threat Intelligence for Diode-Protected Links

**Smart India Hackathon 2026** | Problem Statement: *AI-Based Detection of Cyber Threats in Unidirectional IP Traffic* | Sponsor: **NTRO**

---

## The problem, in one sentence

A classified network crosses a hardware **data diode** — monitoring data can leave, but **nothing can ever return**. We built AI-based threat detection that watches that one-way IP stream passively, detects hostile activity in real time, and raises evidence-rich analyst alerts — while being physically and logically incapable of sending anything back to the monitored side.

## Why detection, not prevention

The diode makes return traffic **physically impossible**, and the problem statement explicitly excludes inline blocking, active probing and live source queries. The only honest control we can offer is detection with auditable proof that we never violated the one-way boundary — so we audit that boundary live rather than merely asserting it.

## Architecture — five one-way layers behind the diode

```
PROTECTED NETWORK → DATA DIODE → [ INGEST → FEATURES → DETECTORS → ALERTS ] ENCLAVE → dashboards
```

- **Ingest (read-only)** — pcap replay or mirrored port → canonical bidirectional flows; no handshakes, no probes, no decryption
- **Features** — frozen 73-feature active registry, vectorised (flow rates, entropy, byte asymmetry, port-cardinality context, per-packet timing and size statistics; `dns_*` / `tls_ja3*` / `active_idle_*` families are declared-future, never emitted as live)
- **Detectors** — instant auditable **rules** (DDoS, slow-DoS, scan, exfiltration) + gated **LightGBM ML** (C2 beaconing on CTU-13 leave-one-scenario-out, DGA/tunnel, TLS/JA3, flow+window context). Any channel that fails its quality gate is excluded — **never junk-scored**
- **Alerts** — ATT&CK-tagged envelope, observed-vs-threshold evidence + top-feature attribution (top-N model features with observed values), STIX 2.1 bundle + one-click HTML incident report
- **Proof** — kernel-level egress denial where privileges allow; live **Diode Proof panel** with outbound bytes, violations and kernel drop counters — mode-aware (enforced / monitor-only), **never a faked zero**

## Five numbers that matter (measured, not promised)

1. **10,000 flows/sec sustained** on 4 cores / 8 GB — 2× the problem-statement target
2. **Per-class F1 ≥ 0.95 where data allows** — DDoS and scan window F1 = 1.0; all 8 out-of-sample ML quality gates pass; **rule DDoS F1 = 1.0, 0 of 392 benign-labelled windows alerted on the never-trained CIC-DDoS2019 corpus** (true zero-shot, 1.58M flows, a different capture and year than the training data — same lab family; that day is almost all attack traffic, so its benign denominator is small. The rule layer on 440k benign windows is point 3)
3. **FPR ≤ 2 alerts/hour committed** — the ML channel raised **1 FP in 440,031 benign flows** (CIC-IDS2017 Wednesday, full-day flow-context precision 0.999996), and **0 on every individual day** after per-day calibration; across 2.03M benign flows in the new 2018/2019 corpora the ML channel raised **5 false positives** (2.5e-06). The rule layer is measured separately: on that same Wednesday corpus it emits 128 alerts, 91 on benign-labelled windows — stated openly in [`rules.md`](../rules.md)
4. **DDoS detected within its first 10-second window**; batch-amortized p95 per-flow cost 0.03–0.07 ms at rated load
5. **0 outbound bytes** to the monitored segment across a 30-minute replay + idle run under active enforcement

## How we differ from what you may already know

| Against a generic Suricata / Zeek / Grafana stack | Against the known public DiodeWatch baseline |
|---|---|
| Generic stacks audit threats, not themselves — none verifies its own unidirectionality, publishes per-class F1 on held-out real data, or exports ATT&CK-tagged, evidence-rich STIX envelopes. | The public baseline replays synthetic JSONL events at ~60 events/s with simulated egress control. Ours ingests real PCAP/flow corpora, sustains ~10,000 flows/s, and proves egress denial at the kernel layer with honest degradation. |

## One honest limitation

Primary validation rests on CIC-IDS2017 plus a completed cross-corpus evaluation on **five real corpora from other labs and years** (CIC-DDoS2019 Syn, 4 CSE-CIC-IDS2018 attack days — 5M flows total, `results/transfer/summary.md`): the rule layer generalizes at F1 1.0 / FPR 0.0 zero-shot on CIC-DDoS2019, while the ML flow-context channel reports recall 0.0 on the new corpora with **PSI drift (1.0–14.4) published as the explanation** — it fails closed instead of guessing under distribution shift. The IDS2018 export lacks identity columns, so entity-scoped rules are honestly reported not-evaluable there, and CTU-13 held-out scenarios / UNSW-NB15 remain future work (server throttled). Encrypted malware is detected from **metadata only** — JA3/JA3S fingerprints, packet sizes, timing — with no payload decryption, as the problem statement requires. On a machine without administrator/root rights, kernel egress denial cannot be installed; the system degrades explicitly to monitor-only mode with an amber banner. **Stated — never hidden.**

## Live demo (4 minutes)

| Time | What the panel sees |
|---|---|
| 0:00–0:30 | The diode constraint — enforcement-mode badge, live outbound counter at zero, why one-way networks exist |
| 0:30–2:00 | Live replay of six scenarios (volumetric DDoS → C2 beacon → DNS tunnel/DGA → bulk exfil + scan → slow-rate DoS → ratio exfil); alerts fire in real time |
| 2:00–3:00 | Evidence drill-down — which feature crossed which threshold, ATT&CK tag, one-click STIX export / incident report |
| 3:00–4:00 | Metrics tab (throughput, F1, FPR, latency) + Diode Proof panel closes the loop: 0 outbound bytes |

---

*Provenance: every number traces to `docs/benchmarks.md`, `results/ml/*.json`, `results/benchmarks/*.json`, or `docs/diode.md`. Full detail: `README.md` · `docs/demo_script.md`.*
