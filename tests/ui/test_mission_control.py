"""Mission control smoke tests.

server.py serves every number a judge sees, but nothing imported it: an import
error or a broken route shipped with CI green. These tests drive the read-only
API over HTTP, including the trust boundary at /api/diode — the status file is
an allegation written by the host it attests, so the verdict must be the
server's, never the file's.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

REPO = Path(__file__).resolve().parents[2]


def _status(**over) -> dict:
    """A status JSON as a healthy enforced monitor would write it."""
    base = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
            "monitor_available": True, "mode": "enforced", "backend": "nftables",
            "backend_reason": "", "protected_uid": 1000,
            "enforcement_verified": True, "dropped_packets": 7,
            "outbound_connections": 0, "outbound_bytes": 0,
            "bytes_accounting": "tcp-info", "compliant": True,
            "violations_total": 0, "seq": 5}
    base.update(over)
    return base


def _client(tmp_path, monkeypatch, status_file: Path | None):
    from fastapi.testclient import TestClient

    import apps.mission_control.server as srv
    if status_file is None:
        monkeypatch.delenv("DIODE_STATUS_FILE", raising=False)
    else:
        monkeypatch.setenv("DIODE_STATUS_FILE", str(status_file))
    return TestClient(srv.app)


def _text(*parts) -> str:
    return REPO.joinpath(*parts).read_text(encoding="utf-8")


def _wall_files() -> list[Path]:
    """Everything the shipped wall is built from: its two page entries and its tree."""
    return ([REPO / "frontend" / "index.html", REPO / "frontend" / "status.html"]
            + sorted((REPO / "frontend" / "src").rglob("*.ts*")))


def _wall_corpus() -> str:
    """The wall's sources as the DOM reads them.

    JSX folds a wrapped line into a single space, so a sentence written over
    four lines in a component is one string on screen. Both sides are
    whitespace-collapsed before comparing, or the pin would fail on the
    formatting rather than the words.
    """
    return " ".join(" ".join(p.read_text(encoding="utf-8").split())
                    for p in _wall_files())


def test_read_routes_answer(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, None)
    assert client.get("/api/health").json() == {"ok": True}

    chain = client.get("/api/chain").json()
    # the UI renders these three; a missing key means a silent blank panel
    assert {"available", "links", "anchored"} <= set(chain)

    ml = client.get("/api/ml_metrics").json()
    # the wall renders the TLS novelty line; a missing key is a blank panel
    assert "tls" in ml and "novelty_available" in ml["tls"]


def test_the_words_the_wall_prints_come_from_the_server(tmp_path, monkeypatch):
    """The wall carried its own label literal and its own CALM/GUARDED ladder,
    which is how one alert was "Recon Scan" on this surface and "scan" in the
    Streamlit feed, and one session "ELEVATED" here and "high" there. The client
    now owns no copy of either table, so a snapshot that stops shipping them
    repaints the wall with raw ids and nothing else notices — except this test."""
    from src.alerts.schema import CLASS_NAMES, SEVERITY_BY_CLASS, THREAT_LEVELS

    client = _client(tmp_path, monkeypatch, None)
    snap = client.get("/api/session").json()
    assert snap["class_names"] == CLASS_NAMES
    assert snap["threat_levels"] == THREAT_LEVELS
    # every class the store can rank is spelled out for the reader rather than
    # passed through as the detector's identifier
    assert all(CLASS_NAMES[c] != c for c in SEVERITY_BY_CLASS)
    assert set(THREAT_LEVELS.values()) == {"CALM", "GUARDED", "ELEVATED", "CRITICAL"}


def test_progress_measures_the_capture_span_not_the_epoch():
    """`progress` drives the wall's Replay progress bar. It divided the replay
    clock by the capture's last absolute epoch, so a capture that does not start
    at 0 (which is every capture) sat at 100% from its first window. Nothing
    else names this field, so the bar could not fall over loudly."""
    import apps.mission_control.server as srv

    s = srv.ReplaySession.__new__(srv.ReplaySession)   # no store, no db
    s.span = (1_700_000_000.0, 1_700_000_093.3)
    s.last_capture_end = 1_700_000_009.31
    assert s._progress() == pytest.approx(0.0998, abs=1e-4)
    s.last_capture_end = 1_700_000_093.3
    assert s._progress() == 1.0
    s.last_capture_end = 1_699_999_990.0        # a clock outside the span
    assert s._progress() == 0.0
    s.span = None
    assert s._progress() is None


def test_chain_reverify_proves_what_the_chain_row_only_claims(tmp_path, monkeypatch):
    """/api/chain describes what the session appended: link count, head hash,
    ledger present. An alert row edited underneath it still reads INTACT, so
    the wall needs a route that re-hashes every payload. It is asked for by hand
    because it walks the whole session — the board polls every 5 s and must not
    run it."""
    import sqlite3

    from fastapi.testclient import TestClient

    import apps.mission_control.server as srv
    from src.alerts.live_store import LiveEvidenceStore
    from tests.alerts.test_alerts import make_alert

    monkeypatch.delenv("DIODE_STATUS_FILE", raising=False)
    db = tmp_path / "chain.db"
    store = LiveEvidenceStore(path=db)
    store.absorb_alerts([make_alert(0, "scan"), make_alert(1, "exfil")])
    monkeypatch.setattr(srv.SESSION, "store", store)
    client = TestClient(srv.app)

    ok = client.get("/api/chain/verify").json()
    assert (ok["ok"], ok["links"], ok["anchored"], ok["degraded"]) == (
        True, 2, True, False)
    assert ok["db"] == str(db)

    con = sqlite3.connect(db)
    con.execute("UPDATE alerts SET confidence = 0.01")
    con.commit()
    con.close()

    broken = client.get("/api/chain/verify").json()
    assert broken["ok"] is False and "modified" in broken["error"]
    # the structural route cannot see the edit — that is the gap RE-VERIFY closes
    assert client.get("/api/chain").json()["links"] == 2
    store.close()


def test_diode_verdict_is_the_servers_not_the_files(tmp_path, monkeypatch):
    """A live heartbeat reads as verified; the same fields three hours old do
    not. The file cannot vote on its own verdict either way."""
    fresh = tmp_path / "fresh.json"
    fresh.write_text(json.dumps(_status()), encoding="utf-8")
    client = _client(tmp_path, monkeypatch, fresh)

    ok = client.get("/api/diode").json()["proof"]
    assert (ok["verdict"], ok["proof"]) == ("ENFORCED-VERIFIED", "pass")

    stale = tmp_path / "stale.json"
    old = time.gmtime(time.time() - 10_800)
    stale.write_text(json.dumps(
        _status(timestamp=time.strftime("%Y-%m-%dT%H:%M:%S+00:00", old))),
        encoding="utf-8")
    client = _client(tmp_path, monkeypatch, stale)

    bad = client.get("/api/diode").json()["proof"]
    assert (bad["verdict"], bad["proof"]) == ("STALE", "unknown")
    assert bad["stale"] is True


def test_diode_without_a_status_file_never_shows_a_green_zero(
        tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, tmp_path / "absent.json")
    body = client.get("/api/diode").json()
    assert body["available"] is False
    assert body["proof"]["verdict"] == "NO-STATUS"
    assert body["proof"]["proof"] == "unknown"


# The wall's egress reader, located by the function that owns it. It must read
# the server's verdict rather than the status file's own claims.
_DIODE_READER = ("frontend/src/components/DiodeProof.tsx",
                 "function view(", "export default function DiodeProof")


def test_the_wall_reads_only_diode_fields_the_server_sends(tmp_path, monkeypatch):
    """The wall reads seven status fields by name, in a language no Python test ran.

    A server that stops sending one does not raise: the cell keeps its dash and
    the panel that exists to prove zero egress quietly stops proving anything.
    So derive the read-set from the shipped source and require the live answer
    to cover it, top level and inside the server's verdict.
    """
    import re

    rel, start, end = _DIODE_READER
    body = ((REPO / rel).read_text(encoding="utf-8")
            .split(start, 1)[1].split(end, 1)[0])
    top = set(re.findall(r"\bd\.([a-z_]+)", body))
    nested = set(re.findall(r"\bp\.([a-z_]+)", body))
    # pinned so a regex that matched nothing cannot pass by covering nothing
    assert len(top) >= 6 and len(nested) >= 3, (top, nested)

    fact = tmp_path / "status.json"
    fact.write_text(json.dumps(_status()), encoding="utf-8")
    answer = _client(tmp_path, monkeypatch, fact).get("/api/diode").json()
    assert top <= set(answer), sorted(top - set(answer))
    assert nested <= set(answer["proof"]), sorted(nested - set(answer["proof"]))


def test_unknown_alert_id_is_refused_on_every_alert_route(tmp_path, monkeypatch):
    """Four routes look an alert up by id. Each used to carry its own copy of
    the refusal, so a fifth could quietly forget it and serve a stack trace or
    an empty report instead of saying the alert is not in this session."""
    client = _client(tmp_path, monkeypatch, None)
    for path in ("/api/evidence/nope", "/api/export/stix/nope",
                 "/api/export/report/nope", "/report/nope"):
        assert client.get(path).status_code == 404, path


def test_pinned_models_replay_end_to_end(tmp_path, monkeypatch):
    """The launcher restores docs/evaluation/models into models/ and CI does the
    same before pytest — but nothing proved those pinned bytes load with the
    scikit-learn actually installed and fire on their own scenario. Checked by
    hand in a clean clone first: the beacon scenario replays to one alert.
    """
    import apps.mission_control.server as srv
    root = Path(srv.__file__).resolve().parents[2]
    if not list((root / "models").glob("*.joblib")):
        pytest.skip("models/ is git-ignored — nothing pinned to restore")
    from fastapi.testclient import TestClient
    monkeypatch.delenv("DIODE_STATUS_FILE", raising=False)
    # Own chain, not data/alerts/live_session.db: a store primes its dedup ids
    # from the db it opens, so re-replaying a scenario already in that chain
    # suppresses its own alert — correct for the wall, fatal for a test.
    monkeypatch.setenv("DIODE_LIVE_DB", str(tmp_path / "replay.db"))

    with TestClient(srv.app) as client:      # lifespan builds the demo pack
        assert client.post("/api/session", json={
            "source": "pack:02_c2_beacon", "tick_ms": 50}).status_code == 200
        deadline = time.time() + 120
        snap = client.get("/api/session").json()
        while snap["state"] not in ("finished", "error") and time.time() < deadline:
            time.sleep(0.5)
            snap = client.get("/api/session").json()

        assert snap["state"] == "finished", snap["error"]
        beacon = [a for a in snap["alerts"] if a["threat_class"] == "beacon"]
        assert beacon, "the pinned beacon model produced no alert on its scenario"
        # the stat line the wall renders is the feed the wall sent, not how many
        # times a detector fired
        assert snap["metrics"]["alerts"] == len(snap["alerts"])
        # and the per-class numbers the tiles/radar draw agree with it on the
        # wire, or a reload would repaint the wall with a smaller session
        assert (sum(v["count"] for v in snap["class_stats"].values())
                == snap["metrics"]["alerts"])
        assert client.get(f"/api/evidence/{beacon[0]['alert_id']}").status_code == 200


def test_every_asset_the_ui_references_is_served(tmp_path, monkeypatch):
    """The wall is the judge's first screen, and one typoed `href` ships it
    blank: the HTML answers 200 while the stylesheet and module behind it 404,
    which no Python assertion can see. So follow the references the shipped
    pages actually make and require each one to resolve over HTTP.

    `/` is the home page and `/status` the service board; the bundle lives in
    the same tree the static mount already walks, so a chunk referenced as
    `/assets/…` resolves or the walk says so. Only `href`/`src` are followed:
    the bundle's own string literals are not references, and `dom.js` is
    imported at build time rather than fetched at run time, so no page link can
    prove it.
    """
    import posixpath
    import re
    client = _client(tmp_path, monkeypatch, None)
    ref = re.compile(r'(?:href|src)="([^"]+)"')
    served: set[str] = set()
    queue = ["/", "/status"]
    while queue:
        url = queue.pop()
        if url in served:
            continue
        r = client.get(url)
        assert r.status_code == 200, f"{url} is not served"
        served.add(url)
        for raw in ref.findall(r.text):
            path = raw.split("?")[0].split("#")[0]
            if not path.endswith((".css", ".js", ".html")):
                continue          # anchors, /api routes, data: URIs
            queue.append(path if path.startswith("/")
                         else posixpath.normpath(
                             posixpath.join(posixpath.dirname(url), path)))
    # pinned so a broken regex cannot pass by fetching nothing but the pages:
    # the stylesheet and the hashed chunks are only reachable through an href
    # the walk had to read out of the served HTML
    assert "/css/app.css" in served, sorted(served)
    assert any(u.startswith("/assets/") for u in served), sorted(served)


def test_the_wall_shell_always_revalidates(tmp_path, monkeypatch):
    """`no-cache` is the only thing between a judge and a stale wall.

    StaticFiles sends ETag without Cache-Control, so a warm disk cache keeps
    handing out the previous index after a rebuilt bundle, which is exactly the
    failure the header exists to prevent. The mount answers `/index.html` as
    readily as the route serving the same bytes at `/`, so every spelling of
    both pages has to revalidate. The chunks deliberately do not: Vite names
    them after their own bytes, so a new build is a new URL and a conditional
    request per chunk buys nothing.
    """
    import re

    client = _client(tmp_path, monkeypatch, None)
    for url in ("/", "/status", "/index.html", "/status.html", "/css/app.css"):
        assert client.get(url).headers.get("Cache-Control") == "no-cache", url

    html = client.get("/").text
    chunk = re.search(r'src="(/assets/[^"]+\.js)"', html).group(1)
    assert client.get(chunk).headers.get("Cache-Control") is None, chunk


def test_the_wall_names_no_route_this_server_does_not_answer(
        tmp_path, monkeypatch):
    """Every absolute path the wall reaches for must be answered here.

    Streamlit (:8501) owns its own routes; a panel that copies one of them
    renders a blank widget inside an otherwise working page, which neither
    `npm run build` nor an HTTP walk of the HTML can see. So read the paths out
    of the client's source and require each to be a declared route, a prefix of
    one, or a file this server serves.
    """
    import re

    import apps.mission_control.server as srv

    sources = [p.read_text(encoding="utf-8") for p in _wall_files()]
    refs = {m.group(0) for text in sources
            for m in re.finditer(
                # the lookbehind keeps a repo path that merely ends in a route
                # name out of the set: only a path the client reaches for
                # starts at a quote, a bracket or whitespace
                r'(?<![A-Za-z0-9_.\-/])/(?:api|css|report|status|ws)[a-z0-9/_-]*'
                r"(?:\.[a-z]{2,4})?", text)}
    # pinned so a regex that matched nothing cannot pass by resolving nothing
    assert len(refs) >= 10, sorted(refs)

    routes = {r.path for r in srv.app.routes}
    client = _client(tmp_path, monkeypatch, None)
    unresolved = []
    for ref in sorted(refs):
        path = ref.rstrip("/") or "/"
        if path in routes or any(t.startswith(f"{path}/") for t in routes):
            continue
        if client.get(path).status_code == 200:
            continue
        unresolved.append(ref)
    assert not unresolved, sorted(unresolved)


def test_the_wall_rebuild_lands_the_order_the_live_path_drew():
    """One feed, two painters, and they used to disagree.

    The store hands out alerts oldest-first, so a snapshot rebuild that walked
    it straight into a prepending painter landed the OLDEST card on top and then
    let the 80-card DOM cap trim from the bottom, discarding the newest alerts:
    a reload of a streaming wall drew a different session than the one on
    screen. No Python test executes JS, so the shape of the two paint paths is
    pinned on the shipped source instead — newest-first into state,
    newest-first out of the cap.
    """
    wall = (REPO / "frontend" / "src" / "useWall.ts").read_text(encoding="utf-8")
    # newest-first is one rule, applied to the store's array and to each push
    assert "const newestFirst = (list: Alert[]) => [...list].reverse();" in wall
    assert "alerts: newestFirst(d.alerts || [])" in wall, \
        "the snapshot path stopped matching the live path's newest-first feed"
    assert "return fresh.length ? [...fresh, ...prev] : prev;" in wall, \
        "a live push stopped prepending: the feed is no longer newest-first"

    feed = (REPO / "frontend" / "src" / "components" / "AlertFeed.tsx"
            ).read_text(encoding="utf-8")
    assert "alerts.slice(0, DOM_CAP)" in feed, \
        "the cap must trim the oldest off the tail, not the newest off the head"


def test_the_wall_ships_one_clock_formatter():
    """`scripts/checks/check_timefmt.mjs` runs against `dom.js` on a non-UTC CI
    host, and its whole argument is that the wall renders one clock, not two.
    A client that carried its own copy of the same helpers would leave the check
    proving one file honest while a second, unverified one was on screen — and
    the naive-UTC rule that took a bug to write is exactly the rule a later edit
    breaks in one copy only. So `dom.js` owns the formatters, the client imports
    it across the boundary, and no component file may re-declare one.
    """
    import re

    dom = (REPO / "apps" / "mission_control" / "static" / "js" / "dom.js"
           ).read_text(encoding="utf-8")
    for name in ("fmt", "fmtTime", "fmtLocal"):
        assert f"export const {name} =" in dom, f"dom.js no longer owns {name}"

    shim = (REPO / "frontend" / "src" / "format.ts").read_text(encoding="utf-8")
    assert 'from "../../apps/mission_control/static/js/dom.js"' in shim

    own = re.compile(r"(?:export\s+)?(?:const|function)\s+(?:fmt|fmtTime|fmtLocal)\b")
    for path in sorted((REPO / "frontend" / "src").rglob("*.ts*")):
        assert not own.search(path.read_text(encoding="utf-8")), path


# Every help button the wall ships, in the words it must print. Each one says
# what a number is NOT, so a panel edited into a bare claim loses its caveat.
_HELP_TIPS = [
    'Session roll-up from alert severities: CALM with no alerts, then GUARDED, ELEVATED or CRITICAL as the worst severity climbs. Counts alerts, not traffic.',
    'The three live channels evaluated on every closed window: the Rule Engine (deterministic 10-second-window rules), ML Channels (C2-beacon and DGA sidecars) and the Diode Monitor (egress proof).',
    'Top 4 alert classes in this session by count; the radar maps their shape against each other.',
    'Replayed capture throughput: flows evaluated per second on this machine.',
    'Alert rate for the current replay session.',
    'Highest flows per second this machine sustained (flows divided by window eval time); p95 window-eval latency below.',
    'Deployment rating: 10,000 flows/s sustained — twice the 5,000 requirement — measured on the live rule engine, not estimated.',
    'Alerts per capture-second across the replay, zero-filled so bursts read as spikes against quiet seconds.',
    'Every closed window lands here the instant its detector fires — click a row to open its evidence.',
    'Live egress counters behind the one-way claim: bytes and connections stay zero when they are measured, and kernel drops count enforced denials. Monitor-only hosts and unmeasured ticks say so explicitly.',
    'Held-out scores per detector from the committed evaluation runs — out-of-sample only. Protocols differ by channel (per-class holdout, leave-one-scenario-out, family holdout, synthetic plant) and are stated inline.',
    'Observed-vs-threshold proof for the selected alert, with ATT&CK tags and one-click STIX and report export.',
    'Services reporting healthy right now across the platform and detection groups below.',
    'Services up but limited — for example a monitor-only diode or missing ML artifacts. The board rows say why.',
    'Services not running or reporting nothing — the board rows name the cause.',
    'The serving layer: API process, live socket, replay wall and rule engine.',
    'Downstream of detection: ML sidecars, egress proof, the tamper-evident chain and its inputs.',
]


def test_the_wall_prints_every_caveat_its_help_buttons_carry():
    """Seventeen help buttons carry the wall's honesty, and dropping one drops
    the caveat with it.

    Each tooltip says what a number is NOT: that the diode counters can be
    "not observed" rather than zero, that a capacity figure is a deployment
    rating, that the quality table is out-of-sample only. Those sentences are
    the difference between a judge reading a panel correctly and reading it into
    something it never claimed, so the wall must print every one of them in the
    same words. Compared as the DOM reads it: JSX folds a wrapped line into a
    single space, so both sides are whitespace-collapsed.
    """
    # pinned: the set is the wall's caveat inventory, not an accident of a regex
    assert len(_HELP_TIPS) == 17, len(_HELP_TIPS)

    corpus = _wall_corpus()
    missing = [" ".join(w.split()) for w in _HELP_TIPS
               if " ".join(w.split()) not in corpus]
    assert not missing, missing


def test_the_wall_renders_every_panel_its_stylesheet_lays_out():
    """The wall's panels are a claim about markup, so pin them as markup.

    A component that exists in the tree but never reaches the DOM is invisible
    either way. Each class name below is a contract `static/css/app.css` lays
    out and a screen reader inherits, matched as one whole token because a card
    carries its own class beside it. Also pinned: the wall's two canvases and
    the ten rows a judge reads on the service board.
    """
    import re

    files = _wall_files()
    corpus = "\n".join(p.read_text(encoding="utf-8") for p in files)
    for contract in ("grid3", "tilegrid", "radar-legend", "chartcard", "cap-line",
                     "qualitypanel", "chan-list", "statusgrid", "pillselect",
                     "customsel--mini", "replay-progress", "feed-tools",
                     "diode-grid", "hero-card", "statrow"):
        assert re.search(rf'(?<![\w-]){re.escape(contract)}(?![\w-])', corpus), contract

    canvases = sum(p.read_text(encoding="utf-8").count("<canvas")
                   for p in files if p.suffix == ".tsx")
    assert canvases == 2, "the radar and the timeline are the wall's two canvases"

    board = _text("frontend", "src", "components", "StatusBoard.tsx")
    for row in ("Web / API server", "Live link (WebSocket)", "Replay session",
                "Rule engine", "ML channels", "Diode monitor (egress)",
                "Evidence chain", "Idempotent ingest", "Capture sources",
                "Detection quality data"):
        assert f'"{row}"' in board, row


def test_the_wall_sprite_holds_every_glyph_its_pages_reference():
    """One `<use href="#i-x">` with no matching `<symbol>` renders an empty box.

    The icon set is inline, offline and un-fetched, and both page entries carry
    the identical block — which is only worth anything while it stays a copy
    rather than a re-typed near-match. The set is pinned non-empty so an
    emptied sprite cannot pass by matching nothing.
    """
    import re

    block = re.compile(r'<svg xmlns="http://www\.w3\.org/2000/svg" '
                       r'style="display:none" aria-hidden="true">.*?</svg>', re.DOTALL)
    sprites = [block.search(_text("frontend", page)).group(0)
               for page in ("index.html", "status.html")]
    assert sprites[0] == sprites[1], "the two pages shipped different icon sets"

    shipped = set(re.findall(r'<symbol id="(i-[a-z0-9-]+)"', sprites[0]))
    assert len(shipped) >= 20, sorted(shipped)
    used = {m.group(1)
            for path in sorted((REPO / "frontend" / "src").rglob("*.ts*"))
            for m in re.finditer(r'"#?(i-[a-z0-9-]+)"',
                                 path.read_text(encoding="utf-8"))}
    assert used <= shipped, sorted(used - shipped)


def test_a_verdict_recorded_by_another_surface_reaches_every_answer(
        tmp_path, monkeypatch):
    """Laya triage runs on :8501 and in the batch CLI; the wall runs neither. It
    writes the verdict to the side table beside the chain, so until every
    alert-reading route joined it, one `alert_id` answered two different ways —
    the advisory line on one surface, a blank on the report and `triage: null`
    in the JSON the drawer fetches. The join must also not touch the alert the
    wall broadcasts, and must not re-hash the evidence."""
    from fastapi.testclient import TestClient

    import apps.mission_control.server as srv
    from src.alerts.live_store import LiveEvidenceStore
    from src.alerts.store import verify_chain
    from src.alerts.triage_store import record_verdicts
    from tests.alerts.test_alerts import make_alert

    monkeypatch.delenv("DIODE_STATUS_FILE", raising=False)
    db = tmp_path / "triage_parity.db"
    store = LiveEvidenceStore(path=db)
    alert = make_alert(0, "scan")
    store.absorb_alerts([alert])
    monkeypatch.setattr(srv.SESSION, "store", store)
    client = TestClient(srv.app)

    url = f"/report/{alert.alert_id}"
    evidence_url = f"/api/evidence/{alert.alert_id}"
    n_evidence = len(alert.evidence)
    assert "TRIAGE — ADVISORY" not in client.get(url).text
    before = client.get(evidence_url).json()
    assert (before["triage"], before["triage_line"]) == (None, None)

    twin = make_alert(0, "scan")        # same payload, so the same stable id
    twin.triage = {"recommended": "escalate", "urgency": 2.4,
                   "corroborates_class": 0.9, "p_false_positive": 0.03}
    assert record_verdicts([twin], db) == 1

    page = client.get(url).text
    assert "TRIAGE — ADVISORY" in page
    assert "disposition escalate" in page
    # the derived advisory row too, which is half of what the worker attaches
    assert "triage.disposition" in page
    answer = client.get(evidence_url).json()
    assert answer["triage"]["recommended"] == "escalate"
    # the drawer prints this sentence verbatim: one owner for the wording, the
    # same one the incident report uses
    assert (answer["triage_line"]
            == "disposition escalate · urgency 2.4 · P(false-positive) 0.03")
    assert [e["condition"] for e in answer["evidence"]][-1] == "triage.disposition"
    # downloading a report cannot change the alert the wall broadcasts
    assert (alert.triage, len(alert.evidence)) == (None, n_evidence)
    assert verify_chain(db)["ok"] is True
    store.close()


def test_both_report_routes_title_with_the_display_name(tmp_path, monkeypatch):
    """Titles are built by the caller, not the renderer, so the report tests
    cannot see this: both routes wrote "Incident — scan" from the raw id while
    every other row on the same wall read "Recon Scan".
    """
    from fastapi.testclient import TestClient

    import apps.mission_control.server as srv
    from src.alerts.live_store import LiveEvidenceStore
    from src.alerts.schema import CLASS_NAMES
    from tests.alerts.test_alerts import make_alert

    monkeypatch.delenv("DIODE_STATUS_FILE", raising=False)
    store = LiveEvidenceStore(path=tmp_path / "title.db")
    alert = make_alert(0, "scan")
    store.absorb_alerts([alert])
    monkeypatch.setattr(srv.SESSION, "store", store)
    client = TestClient(srv.app)

    for url in (f"/report/{alert.alert_id}",
                f"/api/export/report/{alert.alert_id}"):
        text = client.get(url).text
        assert f"Incident — {CLASS_NAMES['scan']} " in text
        assert "Incident — scan" not in text
    store.close()


def test_resuming_a_paused_replay_moves_the_replay_not_just_the_label(
        tmp_path, monkeypatch):
    """`pause()` clears the gate and flips the state, but the worker loop's own
    `while self.state == "running"` exits when it next looks — so a pause that
    lands while a window is being evaluated or while the loop is sleeping leaves
    nothing to consume the generator. `resume()` restored the label and the gate
    with no worker behind them: the wall kept saying "streaming" over counters
    frozen mid-capture."""
    monkeypatch.setenv("DIODE_LIVE_DB", str(tmp_path / "pause_resume.db"))
    client = _client(tmp_path, monkeypatch, None)

    def windows() -> float:
        return client.get("/api/session").json()["metrics"]["windows"]

    def wait_for(cond) -> bool:
        # 40 s, not 20: this waits on a live worker thread, and a loaded
        # host (a full suite in parallel, a cold antivirus scan) stretched
        # the old budget past the point where a correct worker could still
        # answer. The wait is a timeout, not the assertion.
        for _ in range(160):
            if cond():
                return True
            time.sleep(0.25)
        return False

    with client:                       # lifespan warms the demo capture
        client.post("/api/session", json={"source": "demo", "window_s": 10,
                                          "tick_ms": 250})
        assert wait_for(lambda: windows() >= 2), "replay never advanced"

        client.post("/api/session/pause")
        frozen = windows()
        time.sleep(1.0)
        assert windows() == frozen, "pause did not hold the replay"

        client.post("/api/session/resume")
        assert wait_for(lambda: windows() > frozen), \
            "resume restored the state label, not the worker"
        client.post("/api/session/reset")
