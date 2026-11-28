# Analyst UIs, Mission-Control Wall · Streamlit Dashboard

Two judge-facing surfaces over the same detection pipeline, both fully offline:
the mission-control wall (`apps/mission_control/`, `:8530`) and
a four-tab Streamlit dashboard (`apps/dashboard/`, `:8501`) that replays a
capture, watches alerts fire in real time, drills into any alert's evidence,
shows the honest evaluation numbers, and proves zero egress. The wall is
documented first, then the Streamlit tabs.

```bash
python -m apps.mission_control.server --port 8530     # or: run_web.bat
streamlit run apps/dashboard/app.py            # http://localhost:8501
```

## The mission-control wall, `apps/mission_control/` (:8530)

FastAPI serves `apps/mission_control/static` and pushes the replay over a
WebSocket; no page makes a font or CDN request. `/` is the home page and the
analyst wall in one, `/status` its service board, both built from `frontend/`
(Vite + React + TypeScript) and shipped as that build's committed bundle, so the
offline launch asks nothing of the host: no Node, no registry, no CDN. The
stylesheet and the formatter module the bundle is built against are hand-written
and sit beside it.

| Route | Answers |
|---|---|
| `/`, `/status` | the wall and the service board, the build's two pages, each a `FileResponse` off `apps/mission_control/static/`, so neither needs a mount invented for it |
| `/ws/live` | snapshot on connect: state, params, source, progress, metrics, timeline, `class_stats`, `class_names`, `threat_levels`, evidence, and the last `FEED_CAP` alerts |
| `/api/session` | GET = the same snapshot; POST starts a replay (`source`, `window_s`, `tick_ms`); `/api/session/pause`, `/resume`, `/reset` |
| `/api/sources` | the demo capture, every pack scenario whose pcap exists, plus loose files in `data/pcaps/` |
| `/api/evidence/{id}` | one alert's envelope and observed-vs-threshold evidence, plus the advisory Laya verdict and the evidence row derived from it. The payload also carries `triage_line`, the sentence `src.alerts.report.triage_line` prints in the incident report, and the drawer renders it verbatim instead of wording a verdict itself |
| `/api/export/stix/{id}`, `/api/export/ocsf/{id}`, `/api/export/report/{id}`, `/report/{id}` | STIX 2.1 download, one OCSF 1.10.0 Detection Finding download, HTML report download, report rendered in-site. `/api/evidence`, the report download and the report page first join the advisory verdict recorded for that `alert_id` beside the chain (`src.alerts.triage_store.join_verdicts`) and render a copy, so one `alert_id` gets one answer wherever a judge asks; STIX and OCSF serialize the alert itself, and no download can change what the wall broadcasts |
| `/api/ml_metrics` | the pinned `results/ml/*.json` figures, published numbers, not live inference |
| `/api/diode` | the status file **plus the server's verdict**: heartbeat freshness, counter monotonicity, whether byte accounting actually ran |
| `/api/chain` | `LiveEvidenceStore.chain()`: the live session's link count and head hash, and whether an append-only ledger beside the db anchors it |
| `/api/chain/verify` | re-hashes every alert payload and re-walks the chain against the ledger; asked for by the board's RE-VERIFY button, never polled, because it reads the whole session |
| `/api/demo_script` | `docs/demo_script.md`, rendered by the wall's own help button |
| `/api/health` | liveness only |

Each number on screen has one owner, which is what keeps a reload honest:

| Panel | Owner |
|---|---|
| hero alert count, flows/sec, p95, sustained capacity | `SessionStore.metrics()`, the whole session |
| class tiles, radar, class filter chips | `SessionStore.class_stats`, counted when an alert is absorbed |
| threat-level headline | `SessionStore.max_severity` for the severity, `schema.THREAT_LEVELS` for the word, shipped in the snapshot, and the Streamlit Live tab prints the same pair |
| timeline histogram | `SessionStore.timeline`, bucketed in UTC |
| class words on every surface | `schema.CLASS_NAMES`, the wall ships it in the snapshot and owns no copy in JS, the Streamlit feed imports the same table, and `display_class` names the class in the incident report the judge prints, so one alert cannot read "Recon Scan" on a screen and "SCAN" on the page |
| feed list | the last `FEED_CAP = 400` alerts on the wire, 80 cards in the DOM, out of a store ring capped at 5,000 |

Three caps sit between the session and the feed, so the feed is labelled "last
N of M" and never allowed to redefine the counters above it.

### The wall's client, `frontend/`

`frontend/src` is Vite + React + TypeScript, and its build output is committed
into `apps/mission_control/static/`, the directory the server already mounts at
`/`; `/` and `/status` serve those two pages and their chunks resolve as
`/assets/…`. Committing the output is what keeps the offline launch honest, and
it is also the one way a shipped artifact could drift away from the source that
made it, so CI rebuilds `frontend/` on Node 22 and fails unless that directory
is byte-identical to what that build writes (`.github/workflows/ci.yml`). The
bundle's chunks are content-hashed, so only the two page shells and the
hand-written assets are revalidated per request.

```bash
cd frontend
npm ci              # needs network once; the repo ships no node_modules
npm run build       # tsc --noEmit, prunes static/assets, writes static/
npm run dev         # :5199/, proxying /api, /status and /ws/live to :8530
```

What renders: the hero session controls (source, window, cadence, launch /
pause / resume / reset), the threat-level headline, the three throughput
tiles, the class tiles with their radar canvas, the detectors grid, the
benchmark capacity card, the alert timeline canvas, the Detection Quality
table, the alert feed with its severity and class filters, the custody pill,
the Diode Proof panel, the evidence drawer with its STIX, OCSF and report
exports,
the custom source picker, the seventeen help tooltips and the status board.
The board is the build's second page rather than a hash route inside the SPA,
so the existing `StaticFiles` mount and the `FileResponse` routes are the only
things serving either.

The wall takes its words from the server, `class_names` and `threat_levels`
ride the snapshot, so the client owns no spelling, and renders
`/api/diode`'s verdict instead of deriving one from a status file the monitored
host wrote itself. It owns no clock either: `frontend/src/format.ts` re-exports
`fmt`, `fmtTime` and `fmtLocal` from `static/js/dom.js`, so the naive-UTC rule
that `check_timefmt.mjs` proves on a +5:30 CI host is one implementation, not a
verified file beside an unverified one. The feed is painted newest-first on both
of its paths, because a prepending live push and a reversed rebuild disagree,
and the counters and canvases animate on one rule, the deadband-and-rate
interpolation in `useEased.ts`, with the inline `<symbol>` sprite carried
identically by both page entries, so one diff settles both.
`tests/ui/test_mission_control.py` pins the diode read-set, the route
references, the shared formatter, that feed order, all seventeen help
tooltips' wording, every panel class contract, the ten status rows and every
`#i-*` glyph the tree reaches for. `/` and `/status` are both in the asset walk,
which then follows the `href`/`src` the served HTML actually carries, so a missing
or stale build output fails CI rather than a browser tab.

`/status` reports ten services in two groups, Platform: Web/API server, Live
link, Replay session, Rule engine; Detection & evidence: ML channels, Diode
monitor, Evidence chain, Idempotent ingest, Capture sources, Detection quality
data. Every row is derived from a live API call, and the diode row renders
`/api/diode`'s verdict instead of re-deriving one from a file the monitored
host could have written by hand. The Evidence chain row goes one step further:
`/api/chain` can only describe what the session appended, so a row edited
underneath it still reads INTACT, and the row's RE-VERIFY button asks
`/api/chain/verify` to recompute every hash and report BREAK DETECTED with the
link it stopped at.

Optional, in another terminal, the wall, the Diode Proof tab and the
standalone panel all read the egress proof through one `ProofReader`
(`src/diode/monitor.py`), so the status file, the verdict's staleness window
(`DIODE_PROOF_MAX_AGE_S`, default 90 s) and the heartbeat counter are shared
and a monitor cannot be STALE on one surface while it reads ENFORCED on
another. The file is `data/diode_status.json` by default, `DIODE_STATUS_FILE`
to point somewhere else, the monitor's own CLI resolves the same variable, so
a relocated file is written and read in the same place:

```bash
python -m src.diode.cli monitor          # monitor-only (no root needed)
python -m src.diode.cli monitor --enforce   # enforced (root, Linux/nftables)
```

### Who may drive the wall (`apps/mission_control/security.py`)

The wall binds `127.0.0.1` by default, and loopback is not a boundary: any page
the browser loads can reach it, and the POST routes start, pause and reset a
replay that writes to the evidence store. Four protections apply, and they are
independent:

* **Headers on every response**, including the 400, 401, 413 and 429:
  `frame-ancestors 'none'`, `script-src 'self'`, `object-src 'none'`,
  `form-action 'none'`, `nosniff`, `no-referrer`, a same-origin opener policy
  and a permissions policy. The page cannot be framed, cannot load a
  third-party script and cannot post a form anywhere.
* **A token, when one is configured.** `DIODE_WALL_TOKEN` (or `--token`) makes
  every `/api` route answer 401 without it, and refuses the `/ws/live` handshake,
  which is a separate channel: HTTP middleware never sees a WebSocket, and the
  socket carries the same alert stream as the REST routes.
* **A host allowlist and a request-body cap** in `limits.py`.
  `DIODE_ALLOWED_HOSTS` defaults to `127.0.0.1,localhost,[::1]`; a foreign Host
  is 400 before a route runs, which closes the DNS-rebinding path to loopback.
  With a token configured, a request without it is 401 first; a token-bearing
  request with a foreign Host still reaches the 400.
  A body over `DIODE_MAX_BODY_BYTES` (1 MiB) is 413, counted from the ASGI
  stream rather than trusted Content-Length.
* **API rate limits.** 600 `/api` requests and 12 unsafe requests per 60 s
  window, then 429 with `Retry-After`. The buckets are global to the process,
  not per client: with one analyst and nginx in front, every request arrives
  from 127.0.0.1 anyway. The point is to stop a scripted start/reset loop, not
  to meter a team.

```bash
DIODE_WALL_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(24))")   python -m apps.mission_control.server --port 8530
curl -H "X-Diode-Token: $DIODE_WALL_TOKEN" http://127.0.0.1:8530/api/session
```

The request guards are configurable without a rebuild:

| Variable | Default | Effect |
|---|---|---|
| `DIODE_ALLOWED_HOSTS` | `127.0.0.1,localhost,[::1]` | comma-separated Host names; bare `*` is refused at startup |
| `DIODE_MAX_BODY_BYTES` | `1048576` | largest HTTP request body, counted from the stream |
| `DIODE_API_RATE_LIMIT` | `600` | `/api` requests per window |
| `DIODE_WRITE_RATE_LIMIT` | `12` | unsafe (POST/PUT/PATCH/DELETE) requests per window |
| `DIODE_RATE_WINDOW_S` | `60` | window length in seconds |

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: rebind.example' \
  http://127.0.0.1:8530/api/session        # 400
```

Binding to anything other than loopback refuses to start without a token, because
an unauthenticated wall on a shared network lets anyone who can reach the port
drive and read the capture; `--allow-unauthenticated` exists for the case where
that is genuinely intended. The browser client does not send a token, on purpose:
a token pasted into a page is a token in a page. A token-protected wall is driven
through the API (the launchers, the CLI, `curl -H`), and the read-only pages stay
readable so there is somewhere to put the token at all. For a network-facing
deployment, `deployment.md` ships TLS termination, the single-worker systemd
unit and a Host drop-in; it does not add authentication, so the trusted-network
restriction still applies. nginx forwards the browser's Host, so add the public
name to `DIODE_ALLOWED_HOSTS` or the wall answers 400.

## The Streamlit dashboard, four tabs

### Tab 1, 🔴 Live

* **Source**: three radio modes. *Demo pcap (synthetic threats)* replays
  `data/pcaps/demo_threats.pcap` (auto-generated on first run by
  `scripts/generators/make_demo_pcap.py`); *Demo pack (scenario)* offers all
  **six** scenarios registered in `src/alerts/pack.py` and generated by
  `scripts/generators/make_demo_pack.py`, `01 · DDoS flood`, `02 · C2
  beaconing (ML)`, `03 · DNS tunnel / DGA (ML)`, `04 · Exfil + port scan`,
  `05 · Slow-rate DoS`, `06 · Ratio exfiltration`, each showing its story
  caption and the detector expected to fire; *My pcap* lists every capture in
  `data/pcaps/`. Switching sources resets the session. The two ML-channel
  scenarios run their sidecar channels live:
  the beacon (pair periodicity on the pcap-derived NetFlow) and DGA (lexical
  model on the queried names) alerts are scored once by the same loaders and
  models as `python -m src.detectors.ml_engine`, then released into the alert
  feed in capture-time order as the scenario replays, the windowed rule
  replay stays silent for them by design.
* **Replay**: flows are aggregated from the capture (CICFlowMeter idle
  semantics) and streamed through tumbling windows (default 10 s, 5-60 s); each
  window is evaluated by the rule detectors as it closes
  (`src/alerts/watch.py`). `Windows per tick` (1-10) sets how far auto-refresh
  advances per tick, on a 1/2/3/5 s interval.
* **Key metrics**: a session threat-level line (CALM/GUARDED/ELEVATED/CRITICAL
  from `store.metrics()["max_severity"]` through the same `THREAT_LEVELS` table
  the wall's hero reads, with the session's alert count beside it), then
  flows/sec (replay rate), alerts/sec, p95 window
  evaluation latency, and max sustained capacity (per-window flows ÷ eval
  time, the rate the loop could keep up with if fed continuously); under them,
  the idempotent-ingest line (raw detections → unique records, re-detections
  collapsed, distinct entities) and the triage worker's status line.
* **Alert feed**: newest first, the last 300 alerts of the session. The `threat`
  column shows the shared display name from `CLASS_NAMES` (`Recon Scan`,
  `C2 Beacon`), the same words the wall renders, not the detector's raw class
  id. The `time`
  column prints each alert's own stored timestamp verbatim, in the spelling its
  producer used, naive UTC from the rule layer, `+00:00` from the ML sidecar -
  so it shows the evidence clock, not a normalised one; the wall above is the
  surface that renders every alert as one UTC clock. **Severity** and
  **Detector** pill rows (both multi-select) narrow the table, with options
  drawn from the whole session so a chip never vanishes mid-replay;
  combinations intersect, an impossible combination shows an explicit empty
  state, and a caption reports "Showing N of M". Click a row to pin it for the
  Evidence tab.
* **Timeline**: alerts per window as a bar chart (zero-filled between
  the first and last alert so a burst reads as a spike against a quiet
  baseline); reaching EOF swaps the replay for a completion banner that states
  the flows, windows and alerts actually recorded.

### Tab 2, 🔎 Evidence

The selected alert's full envelope: threat class, confidence, derived
severity, ATT&CK technique + tactic, the flow 5-tuple, and an
**observed-vs-threshold** table of every evidence item (the same objects an
analyst would audit). Export buttons build, validate, and download:

* a **STIX 2.1 bundle** for the alert (`src.alerts.export_stix`,
  structurally validated before download);
* an **OCSF 1.10.0 Detection Finding** (`src.alerts.export_ocsf`), one compact
  JSON object with the finding id, creation time, ATT&CK mapping, full evidence
  and observable pointers, structurally validated before download;
* an **HTML incident report** (`src.alerts.report`, self-contained,
  print-to-PDF ready). The verdict this surface's worker attached travels with
  it: each drained verdict is written to the side table beside the chain, so a
  report exported later, from here, from `:8530`, or from the batch CLI -
  prints the same advisory line for the same `alert_id`.

### Tab 3, 📈 Metrics (static, from the evaluation runs)

* Per-class **precision / recall / F1** read from `results/ml/*.json`
  (out-of-sample evaluation: `ml.flowctx` production ensemble; the
  `ml.supervised` flow-level model is a design reference, not a shipped
  artifact).
* **False-positive rate on benign slices**: per-day benign rows flagged on
  the held-out corpus days (0 everywhere after the benign-budget
  fix).
* **Throughput & latency** counters of the current session's live loop,
  next to a pointer to the ≥5,000 flows/sec batch commitment.
* **Evidence integrity**: `verify_chain` re-hashes the live session's whole
  chain and reports `RE-VERIFIED · ANCHORED` or `RE-VERIFIED (no anchor)` -
  the wall's words for the same computation, since a re-hashed chain without
  the append-only ledger beside its db only proves the rows agree with each
  other.

### Tab 4, 🔒 Diode Proof

Prominent enforcement banner: **ENFORCED** (green; kernel rules verified
live) vs **MONITOR-ONLY** (amber; explicit reason, enforcement is never
silently assumed). Then the proof numbers from the diode monitor's status
JSON (polled every 2 s via a Streamlit fragment, through the same
`ProofReader` and verdict the wall serves at `/api/diode`; the tab body is the shared `apps/dashboard/diode_view.render_diode_proof()`, the same function the standalone `diode_panel.py` page runs, so one status file cannot be described two ways):

| Metric | Meaning |
|---|---|
| Outbound bytes | what the protected identity actually transmitted outside loopback (TCP_INFO), **0** when the guarantee holds, `not observed` when the accounting did not run or a socket has no counter |
| Outbound connections | live non-loopback sockets of the protected uid, `not observed` when this host exposed no kernel socket table |
| Violations | every attempted outbound connection since monitor start, including any already open when the monitor began |
| Kernel-dropped packets | nftables counter, denial counted, not claimed |

Plus one or two sentences of *why*: a data diode physically forbids return
traffic into the monitored network, and NTRO's problem statement makes
proving it part of the deliverable, the panel shows the kernel's own
counters so "zero egress" is measured, not asserted.

## Architecture notes

* `apps/dashboard/app.py` is thin: replay/state lives in `src/alerts/watch.py`
  (`replay_flows`, `WindowResult`, `ReplayStats`, `SessionStore`), headless
  and unit-tested (`tests/ui/test_dashboard.py`); exports reuse
  `src.alerts.export_stix` / `src.alerts.export_ocsf` / `src.alerts.report`;
  the diode card polls
  `src.diode.monitor.read_status`. Auto-refresh uses `st.fragment` and only
  advances the replay, scrolling/selection elsewhere is untouched.
* `apps/mission_control/server.py` reuses the same `SessionStore` and replay
  generator (the wall is a transport, not a second pipeline) and its API,
  snapshot shape and per-class aggregates are covered by
  `tests/ui/test_mission_control.py`, including a replay of the pinned models
  end to end over the routes the browser actually calls.
* Everything runs **offline**: no external calls at runtime; the demo pcap
  is generated locally by scapy.

## Demo pcap scenario schedule (`scripts/generators/make_demo_pcap.py`)

| Replay clock | Scenario | Expected alert |
|---|---|---|
| 0-40 s | benign web mix | none (verified quiet) |
| 50-62 s | volumetric DDoS flood, ~75 flows/s, 100 srcs → 10.9.9.9 | `ddos` on 10.9.9.9 |
| 50-62 s | port sweep under cover of the flood, 60 unanswered probes from 10.5.0.7 | `scan` on 10.5.0.7 (same window as the DDoS) |
| 80-93 s | slow-rate DoS: 40 conversations held past the window, 2:1 dribble → 10.7.7.7 | `slowdos` on 10.7.7.7 (detector `slowdos`) |
| 80-93 s | bulk exfil, ~19 MB outward from 10.20.0.9 | `exfil` on 10.20.0.9 (same window as the slow DoS) |

Regenerate: `python scripts/generators/make_demo_pcap.py [--out PATH]`.

## Acceptance (`scripts/checks/check_dashboard.py`, exit 0 = pass)

Headless verification of everything the UI does: demo capture present →
replay fires **all four signatures on the right windows with zero benign
false alarms** → counters populate → session alert exports (STIX and OCSF
validate, report renders) → diode status path honest → `apps/dashboard/app.py` parses and
declares the four tabs. The interactive checks (start offline, replay,
click-through, Diode Proof at zero) are the same calls with a UI on top.

The wall's own JavaScript is gated too: `node --check` on every file it ships,
plus `node scripts/checks/check_timefmt.mjs` on the feed's capture-clock
formatter (one instant, written two ways by two producers, must render one
time). CI runs both clock checks under `TZ=Asia/Kolkata`, because a UTC runner
physically cannot see a host-local shift.
