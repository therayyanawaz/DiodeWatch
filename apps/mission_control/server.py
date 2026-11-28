"""DiodeWatch mission-control web server: FastAPI backend + offline analyst wall.

    python apps/mission_control/server.py [--port 8530]
    (or) .venv\\Scripts\\python.exe -m uvicorn apps.mission_control.server:app --port 8530

Serves `apps/mission_control/static/`: `/` is the home page and the analyst
wall in one, `/status` its service board, both rendered by the React client in
`frontend/` and committed as its built bundle, so the host needs no Node, no
registry and no CDN and nothing on either page is fetched. The stylesheet and
the formatter module the bundle is built against are hand-written and sit
beside it. It streams the REAL rule-engine replay through a WebSocket, using
the same building blocks as the Streamlit dashboard (`src.alerts.watch`,
`src.alerts.pack`):

* one shared replay session (a "mission-control wall"): POST /api/session
  starts it on a chosen source; every connected browser receives each closed
  window's alerts + running performance counters live;
* REST: sources list, alert evidence envelopes, STIX 2.1 / incident-report
  export, held-out ML quality metrics, diode egress status.

The replay advances one tumbling window per tick (default 1 s) in a worker
thread so pandas work never blocks the event loop.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import logging_setup, security

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

_STARTED_AT = time.time()
_APP_VERSION: str | None = None
_LOG = logging.getLogger("diode.wall")


def _app_version() -> str:
    """The released version, read once from pyproject.toml."""
    global _APP_VERSION
    if _APP_VERSION is None:
        try:
            text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
            m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
            _APP_VERSION = m.group(1) if m else "unknown"
        except OSError:
            _APP_VERSION = "unknown"
    return _APP_VERSION

from src.alerts.export_stix import write_stix
from src.alerts.live_store import LiveEvidenceStore
from src.alerts.pack import MlChannelReplay, ensure_pack
from src.alerts.report import render_report_page, triage_line, write_report
from src.alerts.schema import CLASS_NAMES, THREAT_LEVELS, Alert, display_class
from src.alerts.triage_store import join_verdicts
from src.alerts.watch import DEFAULT_WINDOW_S, replay_flows
from src.detectors.ml.pins import load_ml_metrics
from src.detectors.rules import make_rules
from src.diode.monitor import ProofReader
from src.ingest.pcap_reader import stream_flows

WEB_DIR = Path(__file__).resolve().parent
# The built client ships inside this tree: `frontend/` emits both pages and
# their chunks here with `base: "/"`, so a page served at `/` or `/status`
# references `/assets/…` and the mount at the bottom of this file already walks
# what it needs. Nothing about the bundle needs its own route or mount.
STATIC_DIR = WEB_DIR / "static"

# ML channels (C2 beacon / DGA) need trained artifacts under models/
ML_CHANNELS_AVAILABLE = any((REPO_ROOT / "models").glob("*.joblib"))

# Newest alerts only on the wire: a snapshot is rebroadcast on every window
# tick, so the feed carries what the browser can re-render, not the session.
FEED_CAP = 400


async def _warm_pack_once() -> None:
    """Generate the demo pack once in the background (first run only)."""
    try:
        await asyncio.to_thread(ensure_pack)
    except Exception as e:  # noqa: BLE001, best-effort warm-up
        print(f"[web] demo pack warm-up skipped: {e}", flush=True)


# --------------------------------------------------------------------------- #
# scheduled maintenance lands with src/alerts/maintenance.py (next commit);
# --------------------------------------------------------------------------- #
# Interval 0 (DIODE_MAINTENANCE_INTERVAL_S=0) disables the loop entirely; the
# CLI still does a one-shot run. Runs only land between replays: a VACUUM or a
# backup taken mid-window is safe (SQLite serialises it) but can hold the
# store's lock long enough to stall a live tick, so the scheduler waits for
# idle/finished/error and retries on the next tick of the interval.
MAINT_INTERVAL_S = max(0, int(os.environ.get("DIODE_MAINTENANCE_INTERVAL_S")
                              or 21_600))
MAINT_KEEP = max(1, int(os.environ.get("DIODE_BACKUP_KEEP") or 8))
MAINT_LAST: dict = {"ran_at": None, "ok": None, "result": None}
MAINT_COUNTS = {"ok": 0, "fail": 0}


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    task = asyncio.create_task(_warm_pack_once())
    yield
    task.cancel()


app = FastAPI(title="DiodeWatch Mission Control", docs_url=None, redoc_url=None,
              lifespan=_lifespan)


# Hardened before the first route is registered: a response that skips the
# header pass would be the one an attacker frames.
security.install(app)


# Both spellings of each page, because the static mount answers `/index.html`
# as readily as the route that serves the same bytes at `/`.
_UI_SHELLS = ("/", "/status", "/index.html", "/status.html")


@app.middleware("http")
async def _revalidate_ui_assets(request, call_next):
    """Make browsers revalidate the UI shell instead of serving a stale copy.

    StaticFiles emits ETag/Last-Modified but no Cache-Control, so a fresh disk
    cache would mask an edited stylesheet, a rebuilt bundle or a replaced wall
    index. `no-cache` forces the conditional request on every load (cheap 304s).
    The bundle's chunks deliberately miss this: Vite names them after their own
    bytes, so a rebuilt client is a different URL and cannot be served stale."""
    response = await call_next(request)
    path = request.url.path
    if path.startswith(("/css/", "/js/")) or path in _UI_SHELLS:
        response.headers["Cache-Control"] = "no-cache"
    return response


# --------------------------------------------------------------------------- #
# replay session (one shared "wall"; every viewer sees the same feed)
# --------------------------------------------------------------------------- #
class ReplaySession:
    """Singleton live-replay session driving the WebSocket broadcast."""

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.state = "idle"     # idle | loading | running | paused | finished | error
        self.error: str | None = None
        self.params = {"source": "demo", "window_s": DEFAULT_WINDOW_S,
                       "tick_ms": 1000}
        self.store = LiveEvidenceStore()
        self.window_gen = None
        self.ml_replay: MlChannelReplay | None = None
        self.source_label = " -"
        self.source_story = ""
        self.span: tuple[float, float] | None = None   # capture first/last ts
        self.last_capture_end = None
        self._task: asyncio.Task | None = None
        self._pause_evt = asyncio.Event()
        self._pause_evt.set()
        self._epoch = 0            # bumped per session; stale loops bail out

    # -- session lifecycle -------------------------------------------------- #
    async def start(self, params: dict) -> None:
        # Hold the lock for the whole lifecycle: two overlapping starts must
        # never both reach "running" (two tasks iterating one generator →
        # "generator already executing"). Starts are serialized on the wall.
        async with self.lock:
            await self._stop_task()
            self._apply_params(params)
            self.store.close()
            self.store = LiveEvidenceStore()
            self.window_gen = None
            self.ml_replay = None
            self.span = None
            self.last_capture_end = None
            self.error = None
            self.state = "loading"
            epoch = self._epoch = self._epoch + 1
            await self._broadcast({"type": "state", "state": "loading",
                                   "message": "Loading capture…"})
            ok = await asyncio.to_thread(self._start_replay_sync)
            if not ok or self._epoch != epoch:
                return
            self.state = "running"
            _LOG.info("replay started", extra={
                "source": self.params["source"],
                "window_s": self.params["window_s"],
                "epoch": epoch})
            await self._broadcast(self._window_msg(state="running"))
            self._task = asyncio.create_task(self._loop(self.window_gen, epoch))

    def _apply_params(self, params: dict) -> None:
        self.params["source"] = str(params.get("source") or "demo")
        try:
            self.params["window_s"] = int(params.get("window_s")
                                          or DEFAULT_WINDOW_S)
        except (TypeError, ValueError):
            self.params["window_s"] = DEFAULT_WINDOW_S
        try:
            self.params["tick_ms"] = max(250, min(10_000,
                                                  int(params.get("tick_ms")
                                                      or 1000)))
        except (TypeError, ValueError):
            self.params["tick_ms"] = 1000

    def _start_replay_sync(self) -> bool:
        """Resolve the capture + build the window generator (blocking OK)."""
        src = self.params["source"]
        try:
            key = None
            if src == "demo":
                from scripts.generators.make_demo_pcap import DEFAULT_OUT
                from scripts.generators.make_demo_pcap import main as gen_main
                if not DEFAULT_OUT.exists():
                    gen_main([])
                pcap, label = DEFAULT_OUT, "Demo capture, mixed threats"
                story = ("benign mix → DDoS flood → slow-DoS → port sweep → "
                         "bulk exfil")
            elif src.startswith("pack:"):
                key = src.split(":", 1)[1]
                match = next((s for s in ensure_pack() if s.key == key), None)
                if match is None or not match.pcap.exists():
                    raise FileNotFoundError(f"pack scenario {key!r} not found")
                pcap, label, story = match.pcap, match.label, match.story
            elif src.startswith("file:"):
                pcap = Path(src.split(":", 1)[1])
                if not pcap.exists():
                    raise FileNotFoundError(f"{pcap.name} does not exist")
                label, story = pcap.name, "User-supplied capture"
            else:
                raise ValueError(f"unknown source {src!r}")

            flows = list(stream_flows(pcap))
            flows.sort(key=lambda r: r["ts_epoch"])
            ts = [f["ts_epoch"] for f in flows if f.get("ts_epoch") is not None]
            self.span = (min(ts), max(ts)) if ts else None
            self.window_gen = replay_flows(
                flows, window_s=float(self.params["window_s"]),
                rules=make_rules())
            self.ml_replay = (MlChannelReplay.for_scenario(key)
                              if key else None)
            self.source_label = label
            self.source_story = story
            return True
        except Exception as e:  # noqa: BLE001, surfaced to the client
            self.state = "error"
            self.error = str(e)
            _LOG.error("replay failed to start", extra={"source": src,
                                                        "error": str(e)})
            return False

    def _absorb_ml_due(self, capture_end: float | None,
                       ml_replay: MlChannelReplay | None,
                       store: LiveEvidenceStore) -> list[Alert]:
        """Release ML-channel sidecar alerts due at this replay clock.

        Takes explicit references so a stale loop thread can never touch a
        newer session's store/channel objects.
        """
        if ml_replay is None:
            return []
        if capture_end is None:
            due = ml_replay.drain_all()
            samples = ml_replay.drain_samples()
        else:
            due = ml_replay.due(capture_end)
            samples = ml_replay.due_samples(capture_end)
        # Return what the store accepted, not what the channel emitted: an alert
        # the chain refused must not reach the wall either.
        return store.absorb_alerts(due, samples) if (due or samples) else []

    async def _loop(self, gen, epoch: int) -> None:
        """Advance one window per tick (pandas work in a thread), broadcast.

        `gen`, the store and the ML replay are captured as locals; if a newer
        session supersedes this one, the epoch check makes this loop exit
        instead of iterating a generator it no longer owns.
        """
        store, ml_replay = self.store, self.ml_replay
        try:
            # "paused" keeps the consumer alive: `_pause_evt` is the gate that
            # stops the replay, and a loop that exited on the state label would
            # leave resume() restoring a label with no worker behind it.
            while self.state in ("running", "paused") and self._epoch == epoch:
                await self._pause_evt.wait()
                if self._epoch != epoch:
                    return
                drained: list[Alert] = []

                def _advance(drained: list[Alert] = drained, gen=gen,
                             store=store, ml=ml_replay) -> bool:
                    if gen is None:
                        return True
                    try:
                        w = next(gen)
                    except StopIteration:
                        drained.extend(self._absorb_ml_due(None, ml, store))
                        return True
                    drained.extend(store.absorb(w))
                    drained.extend(self._absorb_ml_due(w.capture_end, ml, store))
                    self.last_capture_end = w.capture_end
                    return False

                done = await asyncio.to_thread(_advance)
                if self._epoch != epoch:
                    return
                if done:
                    self.state = "finished"
                    msg = self._window_msg(state="finished")
                    msg["new_alerts"] = [a.to_dict() for a in drained]
                    await self._broadcast(msg)
                    break
                msg = self._window_msg()
                msg["new_alerts"] = [a.to_dict() for a in drained]
                await self._broadcast(msg)
                await asyncio.sleep(self.params["tick_ms"] / 1000.0)
        except Exception as e:  # noqa: BLE001
            self.state = "error"
            self.error = str(e)
            _LOG.error("replay loop failed", extra={"epoch": epoch,
                                                    "error": str(e)})
            await self._broadcast({"type": "error", "message": str(e)})

    async def pause(self) -> None:
        if self.state == "running":
            self._pause_evt.clear()
            self.state = "paused"
            await self._broadcast({"type": "state", "state": "paused"})

    async def resume(self) -> None:
        if self.state == "paused":
            self._pause_evt.set()
            self.state = "running"
            await self._broadcast({"type": "state", "state": "running"})

    async def reset(self) -> None:
        async with self.lock:
            await self._stop_task()
            self.state = "idle"
            self.store.close()
            self.store = LiveEvidenceStore()
            self.window_gen = None
            self.ml_replay = None
            self.span = None
            self.last_capture_end = None
            self.error = None
        _LOG.info("replay reset")
        await self._broadcast({"type": "state", "state": "idle"})

    async def _stop_task(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        self._pause_evt.set()

    # -- payloads ----------------------------------------------------------- #
    async def _broadcast(self, msg: dict) -> None:
        await _broadcast(msg)

    def _progress(self) -> float | None:
        """Fraction of this capture's own time span that the replay has reached.

        Dividing absolute capture epochs read 100% from the first window of any
        capture that does not start at the epoch, which is every capture.
        """
        if self.span and self.last_capture_end is not None:
            first, last = self.span
            span = last - first
            if span <= 0:
                return 1.0
            return round(min(1.0, max(0.0, (self.last_capture_end - first)
                                      / span)), 4)
        return None

    def _window_msg(self, *, state: str | None = None) -> dict:
        return {
            "type": "windows",
            "state": state or self.state,
            "metrics": self.store.metrics(),
            "progress": self._progress(),
            "new_alerts": [],
            "timeline": self.store.timeline,
            "class_stats": self.store.class_stats,
            "evidence": self.store.evidence(),
        }

    async def snapshot(self) -> dict:
        return {
            "state": self.state,
            "error": self.error,
            "params": dict(self.params),
            "source": {"label": self.source_label, "story": self.source_story},
            "progress": self._progress(),
            "metrics": self.store.metrics(),
            # shortcut: transport caps the feed at the last FEED_CAP while
            # `metrics` reports the whole session, so the UI labels the list
            # "last N of M" rather than contradicting the hero count.
            # Upgrade: paginate the feed instead of truncating it.
            "alerts": [a.to_dict() for a in self.store.alerts[-FEED_CAP:]],
            "timeline": self.store.timeline,
            "class_stats": self.store.class_stats,
            # display names ride the snapshot so the wall cannot call an alert
            # something the Streamlit feed does not (schema.CLASS_NAMES owns them)
            "class_names": CLASS_NAMES,
            "threat_levels": THREAT_LEVELS,
            "evidence": self.store.evidence(),
            "ml_available": ML_CHANNELS_AVAILABLE,
            "ml_total": self.ml_replay.total if self.ml_replay else 0,
        }


SESSION = ReplaySession()


# --------------------------------------------------------------------------- #
# websocket clients
# --------------------------------------------------------------------------- #
CLIENTS: set[WebSocket] = set()


async def _broadcast(msg: dict) -> None:
    dead = []
    data = json.dumps(msg, default=str)
    for ws in list(CLIENTS):
        try:
            await ws.send_text(data)
        except Exception:  # noqa: BLE001
            dead.append(ws)
    for ws in dead:
        CLIENTS.discard(ws)


# --------------------------------------------------------------------------- #
# REST API
# --------------------------------------------------------------------------- #
def _sources_list() -> list[dict]:
    out = [{"key": "demo", "label": "Demo capture, mixed threats",
            "story": "benign mix → DDoS flood → slow-DoS → port sweep → bulk exfil",
            "kind": "demo"}]
    try:
        for s in ensure_pack():
            if s.pcap.exists():
                out.append({"key": f"pack:{s.key}", "label": s.label,
                            "story": s.story, "kind": "pack",
                            "note": s.detector_note})
    except Exception as e:  # noqa: BLE001, sources degrade to demo-only
        print(f"[web] pack sources unavailable: {e}", flush=True)
    for p in sorted((REPO_ROOT / "data" / "pcaps").glob("*.pcap*")):
        if p.name != "demo_threats.pcap":
            out.append({"key": f"file:{p}", "label": p.name, "story": "",
                        "kind": "file"})
    return out


@app.get("/api/sources")
async def api_sources() -> list[dict]:
    # pack generation on first run blocks, keep it off the event loop
    return await asyncio.to_thread(_sources_list)


@app.get("/api/session")
async def api_session_get() -> dict:
    return await SESSION.snapshot()


@app.post("/api/session")
async def api_session_start(params: dict) -> dict:
    await SESSION.start(params)
    return {"state": SESSION.state, "error": SESSION.error}


@app.post("/api/session/pause")
async def api_session_pause() -> dict:
    await SESSION.pause()
    return {"state": SESSION.state}


@app.post("/api/session/resume")
async def api_session_resume() -> dict:
    await SESSION.resume()
    return {"state": SESSION.state}


@app.post("/api/session/reset")
async def api_session_reset() -> dict:
    await SESSION.reset()
    return {"state": SESSION.state}


def _live_alert(alert_id: str) -> Alert:
    """Look an alert up in the live session, or refuse with the same 404.

    Four handlers each re-implemented this lookup and each raised an identical
    refusal; a fifth would have had three ways to forget the refusal.
    """
    alert = next((a for a in SESSION.store.alerts if a.alert_id == alert_id),
                 None)
    if alert is None:
        raise HTTPException(404, "alert not in the live session")
    return alert


def _alert_for_reader(alert_id: str) -> Alert:
    """The session alert plus the advisory verdict recorded for that id.

    Laya triage runs on the Streamlit surface and in the batch CLI, and both
    write the verdict to the side table beside the chain. Without the join the
    same `alert_id` answered two different ways: the report route had no verdict
    to print, so the ADVISORY line was simply missing, and the JSON evidence
    endpoint said `triage: null` while the page beside it named a disposition.
    Every route that answers "tell me about this alert" goes through here, on a
    copy, so nothing a judge reads can change the alert the wall broadcasts.
    """
    return join_verdicts([_live_alert(alert_id)], SESSION.store.path)[0]


@app.get("/api/evidence/{alert_id}")
async def api_evidence(alert_id: str) -> dict:
    """One alert for the drawer, with `triage_line` spelled by the report
    renderer that owns the sentence. The client prints it verbatim rather than
    keeping its own wording of what a verdict means."""
    alert = _alert_for_reader(alert_id)
    payload = alert.to_dict()
    payload["triage_line"] = triage_line(alert.triage) if alert.triage else None
    return payload


@app.get("/api/export/stix/{alert_id}")
async def api_export_stix(alert_id: str) -> FileResponse:
    alert = _live_alert(alert_id)
    out = REPO_ROOT / "data" / "alerts" / f"stix_{alert.threat_class}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    _, problems = write_stix([alert], out)
    if problems:
        raise HTTPException(500, f"STIX validation: {problems}")
    return FileResponse(out, media_type="application/json", filename=out.name)


@app.get("/api/export/report/{alert_id}")
async def api_export_report(alert_id: str) -> FileResponse:
    alert = _alert_for_reader(alert_id)
    out = REPO_ROOT / "data" / "alerts" / "incident_report.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    write_report([alert], out, title=f"Incident, "
                                     f"{display_class(alert.threat_class)} "
                                     f"({alert.timestamp})")
    return FileResponse(out, media_type="text/html",
                        filename="incident_report.html")


@app.get("/report/{alert_id}")
async def report_page(alert_id: str) -> HTMLResponse:
    alert = _alert_for_reader(alert_id)
    return HTMLResponse(render_report_page(
        [alert], title=f"Incident, {display_class(alert.threat_class)} "
                       f"({alert.timestamp})"))


@app.get("/")
async def wall_page() -> FileResponse:
    """The home page and the analyst wall, one page, at the root.

    The client is built in `frontend/` and shipped as its committed bundle, so
    the page is a file and every number on it arrives over the routes below."""
    return FileResponse(STATIC_DIR / "index.html", media_type="text/html")


@app.get("/status")
async def status_page() -> FileResponse:
    """The all-services status board, the build's second page, so no route is
    invented for it. It reads the same live APIs (/api/health, /api/diode,
    /api/chain, /api/ml_metrics, /api/sources) and the /ws/live snapshot, so it
    always reflects real state."""
    return FileResponse(STATIC_DIR / "status.html", media_type="text/html")


@app.get("/api/ml_metrics")
async def api_ml_metrics() -> dict:
    return load_ml_metrics(REPO_ROOT)


_DIODE = ProofReader()


@app.get("/api/diode")
async def api_diode() -> dict:
    """Egress status plus the server's verdict, the only proof a client may show.

    `data/diode_status.json` is written by the very host whose innocence it
    attests, so its fields are allegations. `proof` is computed here from
    heartbeat freshness, counter monotonicity and whether byte accounting
    actually ran; clients render it instead of re-deriving a verdict from
    whatever the file happened to say. The reader is the one every surface
    shares, so a monitor cannot be STALE on the wall and FRESH on a tab.
    """
    return _DIODE.read()


@app.get("/api/chain")
async def api_chain() -> dict:
    """Tamper-evident evidence chain of the LIVE session, in real time."""
    return SESSION.store.chain()


@app.get("/api/chain/verify")
async def api_chain_verify() -> dict:
    """Re-hash every alert row and re-walk the chain, the proof `/api/chain`
    cannot give.

    `chain()` describes what the session appended (link count, head, ledger
    present), so a row edited underneath an intact-looking chain still reads
    INTACT. This route recomputes every hash and cross-checks the append-only
    ledger, which is the only thing that catches the edit. It walks the whole
    session, so it runs on demand off the status board rather than on the
    board's 5 s poll, and on a thread so a long chain cannot stall the wall.
    """
    store = SESSION.store
    verdict = await asyncio.to_thread(store.verify)
    return {"db": str(store.path), "degraded": bool(store.degraded),
            **verdict}


# --------------------------------------------------------------------------- #
# websocket
# --------------------------------------------------------------------------- #
@app.websocket("/ws/live")
async def ws_live(ws: WebSocket) -> None:
    # Middleware never runs for a handshake, so the token is checked here. Close
    # before accept: a refused client must not observe a live socket.
    if security.ws_token_denied(ws):
        await ws.close(code=1008)
        return
    await ws.accept()
    CLIENTS.add(ws)
    _LOG.info("websocket connected", extra={"clients": len(CLIENTS)})
    try:
        await ws.send_json({"type": "snapshot",
                            "data": await SESSION.snapshot()})
        while True:
            await ws.receive_text()   # keepalive from client (ignored)
    except WebSocketDisconnect:
        pass
    finally:
        CLIENTS.discard(ws)
        _LOG.info("websocket closed", extra={"clients": len(CLIENTS)})


@app.get("/api/health")
async def api_health(deep: bool = False) -> JSONResponse:
    """A health answer with evidence behind it, not a constant.

    `ok` is computed: the store is touched with a real query (row count and
    chain length), the data directory is probed for writability, and a failed
    check says so in `checks`. The status board only reads `ok`; the rest is
    for an operator who wants to know WHY a wall is red. `?deep=true` adds
    `PRAGMA quick_check` (every page read), which is a real cost, so the 5 s
    board poll stays shallow and deep checks are asked for on demand.
    """
    checks: dict = {"store": await asyncio.to_thread(SESSION.store.probe, deep)}

    def _writable() -> dict:
        try:
            probe_dir = SESSION.store.path.parent
            probe_dir.mkdir(parents=True, exist_ok=True)
            marker = probe_dir / ".health-write-probe"
            marker.write_text("probe", encoding="utf-8")
            marker.unlink()
            return {"ok": True, "dir": str(probe_dir)}
        except OSError as e:
            return {"ok": False, "detail": f"data dir not writable: {e}"}

    checks["data_dir"] = await asyncio.to_thread(_writable)
    ok = all(c["ok"] for c in checks.values())
    return JSONResponse({
        "ok": ok,
        "version": _app_version(),
        "uptime_s": round(time.time() - _STARTED_AT, 1),
        "state": SESSION.state,
        "ws_clients": len(CLIENTS),
        "checks": checks,
        "maintenance": {"last_ran_at": MAINT_LAST["ran_at"],
                        "last_ok": MAINT_LAST["ok"],
                        "runs_ok": MAINT_COUNTS["ok"],
                        "runs_failed": MAINT_COUNTS["fail"],
                        "interval_s": MAINT_INTERVAL_S},
    })


_METRIC_STATES = ("idle", "loading", "running", "paused", "finished", "error")


def _metrics_line(name: str, value: float, *, help_: str | None = None,
                  type_: str | None = None, labels: str | None = None) -> str:
    line = "" if help_ is None else f"# HELP {name} {help_}\n"
    if type_ is not None:
        line += f"# TYPE {name} {type_}\n"
    label_part = f"{{{labels}}}" if labels else ""
    shown = int(value) if float(value).is_integer() else value
    return f"{line}{name}{label_part} {shown}\n"


def _metrics_text() -> str:
    """Prometheus text format, process-local counters, no dependencies.

    Everything reads through try/except: a metrics endpoint must render with
    the numbers it has rather than 500 because one store went away.
    """
    out: list[str] = []

    def add(name: str, value, **kw) -> None:
        try:
            out.append(_metrics_line(name, float(value), **kw))
        except Exception as e:  # noqa: BLE001, metrics must not 500
            _LOG.warning("metric %s failed", name, extra={"error": str(e)})

    add("diodewatch_uptime_seconds", time.time() - _STARTED_AT,
        help_="Seconds the mission-control process has been serving.",
        type_="gauge")
    state = SESSION.state
    for s in _METRIC_STATES:
        add("diodewatch_session_state", 1.0 if state == s else 0.0,
            help_="1 for the current replay session state.",
            type_="gauge", labels=f'state="{s}"')
    store = SESSION.store
    add("diodewatch_session_alerts", len(store.alerts),
        help_="Alerts in the live session ring buffer.", type_="gauge")
    add("diodewatch_alerts_inserted_total", store._inserted,
        help_="Alerts handed to the persistent evidence chain this process.",
        type_="counter")
    add("diodewatch_alerts_rejected_total", store.rejected,
        help_="Alerts the schema refused, shown nowhere and never lost.",
        type_="counter")
    try:
        links = 0 if store.degraded else store._store.chain_length()
    except Exception:  # noqa: BLE001
        links = 0
    add("diodewatch_chain_links", links,
        help_="Evidence chain links in the live store.", type_="gauge")
    add("diodewatch_ws_clients", len(CLIENTS),
        help_="Browsers attached to the live socket.", type_="gauge")
    add("diodewatch_replay_sessions_total", SESSION._epoch,
        help_="Replay sessions started since process start.", type_="counter")
    for cls, n in sorted((store.class_stats or {}).items()):
        add("diodewatch_alerts_by_class", n, type_="gauge",
            help_="Session alerts by threat class.",
            labels=f'threat_class="{cls}"')
    add("diodewatch_maintenance_runs_total", MAINT_COUNTS["ok"],
        help_="Scheduled maintenance runs that succeeded.", type_="counter")
    add("diodewatch_maintenance_failures_total", MAINT_COUNTS["fail"],
        help_="Scheduled maintenance runs that failed.", type_="counter")
    return "".join(out)


@app.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    """Process-local counters in the Prometheus text format.

    Deliberately outside /api, like the read-only pages: a scraper should not
    need the token, and the numbers it gets are counts, not evidence.
    """
    return Response(_metrics_text(), media_type="text/plain; charset=utf-8")


@app.get("/api/demo_script")
async def api_demo_script() -> FileResponse:
    """The narrated demo script (docs/demo_script.md) for the help button."""
    p = REPO_ROOT / "docs" / "demo_script.md"
    if not p.exists():
        raise HTTPException(404, "demo script not found")
    return FileResponse(p, media_type="text/markdown",
                        filename="demo_script.md")


# --------------------------------------------------------------------------- #
# static SPA (mounted last so API routes win)
# --------------------------------------------------------------------------- #
_FAVICON_SVG = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
                "<text y='.9em' font-size='90'>\U0001F6E1\uFE0F</text></svg>")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    return Response(content=_FAVICON_SVG, media_type="image/svg+xml")


app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True),
          name="static")


# Last, so the access log is the outermost middleware and records the status
# every inner layer (headers, cache policy, 401s) settled on.
logging_setup.access_middleware(app)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="DiodeWatch mission-control server")
    ap.add_argument("--port", type=int, default=8530)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--token", default=None,
                    help=f"bearer token for /api (default: ${security.TOKEN_ENV})")
    ap.add_argument("--allow-unauthenticated", action="store_true",
                    help="permit a non-loopback bind with no token")
    args = ap.parse_args(argv)
    if args.token:
        os.environ[security.TOKEN_ENV] = args.token
    token = security.startup_guard(args.host, args.allow_unauthenticated)
    loginfo = logging_setup.ensure_setup()
    _LOG.info("server starting", extra={
        "host": args.host, "port": args.port, "token_required": bool(token),
        "app_log": loginfo.get("app_log"),
        "access_log": loginfo.get("access_log"),
        "maintenance_interval_s": MAINT_INTERVAL_S,
        "version": _app_version()})
    if token:
        print(f"wall: /api requires {security.TOKEN_HEADER} ({len(token)} chars)")
    elif args.host not in security.LOOPBACK:
        print("wall: WARNING unauthenticated on a reachable interface")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
