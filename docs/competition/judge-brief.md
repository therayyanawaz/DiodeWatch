# DiodeWatch, Passive Threat Intelligence for Diode-Protected Links

**Smart India Hackathon 2026** | Problem Statement: *AI-Based Detection of Cyber Threats in Unidirectional IP Traffic* | Sponsor: **NTRO**

---

## The problem, in one sentence

A classified network crosses a hardware **data diode**: monitoring data can leave, but **nothing can ever return**. DiodeWatch watches that one-way IP stream passively, detects hostile activity in real time, and raises evidence-rich analyst alerts, while remaining physically and logically incapable of sending anything back to the monitored side.

## Why detection, not prevention

The diode makes return traffic **physically impossible**, and the problem statement explicitly excludes inline blocking, active probing and live source queries. The only honest control we can offer is detection with auditable proof that we never violated the one-way boundary, so we audit that boundary live rather than merely asserting it.

## Architecture, five one-way layers behind the diode

```
PROTECTED NETWORK → DATA DIODE → [ INGEST → FEATURES → DETECTORS → ALERTS ] ENCLAVE → dashboards
```

- **Ingest (read-only)**: pcap replay or mirrored port → canonical bidirectional flows; no handshakes, no probes, no decryption
- **Features**: frozen 73-feature active registry, vectorised (flow rates, entropy, byte asymmetry, port-cardinality context, per-packet timing and size statistics). DNS and TLS/JA3 fields are populated only by the optional Zeek sidecar, not decoded from raw pcaps; active/idle families are declared-future.
- **Detectors**: instant auditable **rules** (DDoS, slow-DoS, scan, exfiltration) + gated **LightGBM ML** (C2 beaconing on CTU-13 leave-one-scenario-out, DGA/tunnel, TLS/JA3, flow+window context). Any channel that fails its quality gate is excluded, **never junk-scored**
- **Alerts**: ATT&CK-tagged envelope, observed-vs-threshold evidence + top-feature attribution (top-N model features with observed values), STIX 2.1 bundle + one-click HTML incident report
- **Proof**: kernel-level egress denial where privileges allow; live **Diode Proof panel** with outbound bytes, violations and kernel drop counters, mode-aware (enforced / monitor-only), **never a faked zero**

## Five measured results

1. **10,000 flows/sec sustained** on 4 cores / 8 GB, 2× the problem-statement target.
2. **Rule DDoS gates: two pass, two fail.** Pre-committed, fixed before the run: CIC-DDoS2019 F1 0.958 and benign FPR 0.0069 pass; CIC-IDS2017 F1 0.611 and FPR 0.1496 fail. The full pass scores 50 files and 109,643,423 flows. There is no universal F1 1.0 claim.
3. **Alert-level scoring is published with the flow metrics.** On CIC-DDoS2019, 1,424 alerts give exact precision 0.919 and any-attack precision 0.991, but DDoS incident recall is 0.122 (1,216/9,927) although flow recall is 0.920. On CIC-IDS2017, exact precision is 0.084 and 523 of 594 alerts are benign-only; scan and slow-DoS incident recall are zero. Volume recall hides both effects, so both are shown.
4. **DDoS detected within its first 10-second window**; batch-amortized per-flow cost 0.03-0.07 ms at rated load.
5. **0 outbound bytes on the enforced Linux path** across a 30-minute replay + idle run. Windows has no kernel enforcement path, so its wall must say monitor-only, never a fabricated zero.

## How we differ from what you may already know

| Against a generic Suricata / Zeek / Grafana stack | Against the known public DiodeWatch baseline |
|---|---|
| Generic stacks audit threats, not themselves; none verifies its own unidirectionality, publishes per-class F1 on real corpora with in-sample cells labelled, or exports ATT&CK-tagged, evidence-rich STIX envelopes. | The public baseline replays synthetic JSONL events at ~60 events/s with simulated egress control. Ours ingests real PCAP/flow corpora, sustains ~10,000 flows/s, and proves egress denial at the kernel layer on Linux, with monitor-only degradation where that path does not exist. |

## Limits we state before questions

Primary validation is **five public corpora, 50 files and 109,643,423 flows**.
Rules are evaluable only on the two CIC corpora that carry identity columns,
CIC-IDS2017 and CIC-DDoS2019; IDS2018 and UNSW-NB15 have none, and CTU-13 is
NetFlow with neither flow channel, so those cells are reported not evaluable rather than as zeros. The
ML artifact is the shipped CIC-IDS2017 model: it is in-sample there and calls
0 of 3.36M CIC-DDoS2019 attack flows DDoS, 0.34% of IDS2018 DDoS flows and
0.13% of UNSW DoS flows. It fails closed under drift (PSI 1.0-14.4), which is
honest but is not cross-corpus detection. After the LOIC label correction the
IDS2018 flow-context FPR is 3.3e-05, not the archived 17%. Slow-DoS and scan
rule recall are zero in the full pass. Encrypted malware is classified from
metadata only, with no payload decryption. On Windows the kernel egress path
does not exist, so the system shows monitor-only rather than a zero. **The
failures and the small-incident misses stay in the published record.**

## Live demo (4 minutes)

| Time | What the panel sees |
|---|---|
| 0:00-0:30 | The diode constraint, enforcement-mode badge, live outbound counter, and why one-way networks exist; zero is shown only when enforcement is active |
| 0:30-2:00 | Live replay of six scenarios (volumetric DDoS → C2 beacon → DNS tunnel/DGA → bulk exfil + scan → slow-rate DoS → ratio exfil); alerts fire in real time |
| 2:00-3:00 | Evidence drill-down, which feature crossed which threshold, ATT&CK tag, one-click STIX export / incident report |
| 3:00-4:00 | Metrics tab (throughput, F1, FPR, alert precision, incident recall, latency) + Diode Proof panel; enforced hosts show zero egress, monitor-only hosts say so |

---

*Provenance: every number traces to `docs/benchmarks.md`, `docs/evaluation/runs/*.json`, or `docs/diode.md`. `results/` is runtime output and is not a citation target. Full detail: `README.md` · `docs/demo_script.md`.*
