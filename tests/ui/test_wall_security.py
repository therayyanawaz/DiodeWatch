"""The wall's trust boundary has to be enforced, not described.

Two claims from `apps/mission_control/security.py` are checked here:

  * every response carries the hardening headers, including 401s, because a
    response that skips them is the one that gets framed;
  * a configured token really stops an unauthenticated `/api` call, and the
    startup guard refuses a reachable bind without one.

The 401 case matters more than it looks: the wall's POST routes start, pause and
reset a replay that writes to the evidence store, so an unauthenticated caller on
a shared host is not a read-only nuisance.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

CSP_MARKERS = ("frame-ancestors 'none'", "script-src 'self'", "object-src 'none'")


def _client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import apps.mission_control.server as srv
    monkeypatch.setenv("DIODE_LIVE_DB", str(tmp_path / "wall_token.db"))
    return TestClient(srv.app)


def test_every_response_carries_the_hardening_headers(tmp_path, monkeypatch):
    monkeypatch.delenv("DIODE_WALL_TOKEN", raising=False)
    client = _client(tmp_path, monkeypatch)
    for path in ("/", "/status", "/api/diode", "/api/session"):
        resp = client.get(path)
        assert resp.status_code == 200, path
        csp = resp.headers.get("content-security-policy", "")
        for marker in CSP_MARKERS:
            assert marker in csp, (path, marker, csp)
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("referrer-policy") == "no-referrer"


def test_a_configured_token_stops_an_unauthenticated_post(tmp_path, monkeypatch):
    """The mutating route is the one that matters: without the token the wall
    would let any local page start or reset a capture."""
    monkeypatch.setenv("DIODE_WALL_TOKEN", "s3cret-token")
    client = _client(tmp_path, monkeypatch)

    denied = client.post("/api/session/reset")
    assert denied.status_code == 401
    assert "x-diode-token" in denied.json()["detail"]

    # a 401 is still a response the browser may frame, so it carries the headers
    assert "frame-ancestors 'none'" in denied.headers["content-security-policy"]

    # reads are equally protected: the evidence store is not public either
    assert client.get("/api/session").status_code == 401
    allowed = client.get("/api/session", headers={"X-Diode-Token": "s3cret-token"})
    assert allowed.status_code == 200


def test_the_bearer_spelling_works_too(tmp_path, monkeypatch):
    monkeypatch.setenv("DIODE_WALL_TOKEN", "s3cret-token")
    client = _client(tmp_path, monkeypatch)
    ok = client.get("/api/session", headers={"Authorization": "Bearer s3cret-token"})
    assert ok.status_code == 200
    wrong = client.get("/api/session", headers={"Authorization": "Bearer nope"})
    assert wrong.status_code == 401


def test_the_live_socket_is_refused_without_the_token(tmp_path, monkeypatch):
    """The socket carries the whole alert stream, and HTTP middleware never sees a
    WebSocket handshake: before this check, a token-protected wall still streamed
    every alert to any local page."""
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    import apps.mission_control.server as srv
    monkeypatch.setenv("DIODE_WALL_TOKEN", "s3cret-token")
    monkeypatch.setenv("DIODE_LIVE_DB", str(tmp_path / "ws.db"))
    client = TestClient(srv.app)

    with (pytest.raises(WebSocketDisconnect) as exc,
          client.websocket_connect("/ws/live")):
        pass
    assert exc.value.code == 1008


def test_the_live_socket_accepts_the_token_in_the_query_string(tmp_path, monkeypatch):
    """A browser cannot set a header on a handshake, so the query string is the
    only way a page can present it."""
    from fastapi.testclient import TestClient

    import apps.mission_control.server as srv
    monkeypatch.setenv("DIODE_WALL_TOKEN", "s3cret-token")
    monkeypatch.setenv("DIODE_LIVE_DB", str(tmp_path / "ws2.db"))
    client = TestClient(srv.app)

    with client.websocket_connect("/ws/live?token=s3cret-token") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "snapshot"


def test_the_policy_does_not_allow_arbitrary_websocket_origins():
    """`connect-src 'self'` already covers ws to this origin; listing the bare
    `ws:` scheme would let the page open a socket to any host."""
    from apps.mission_control import security
    connect = next(p for p in security.CSP.split(";") if "connect-src" in p)
    assert connect.strip() == "connect-src 'self'"


def test_static_shell_stays_readable_without_a_token(tmp_path, monkeypatch):
    """A token protects the API, not the page: the shell has to load for the
    browser to have somewhere to put a token at all."""
    monkeypatch.setenv("DIODE_WALL_TOKEN", "s3cret-token")
    client = _client(tmp_path, monkeypatch)
    assert client.get("/").status_code == 200


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::"])
def test_a_reachable_bind_without_a_token_refuses_to_start(monkeypatch, host):
    from apps.mission_control import security
    monkeypatch.delenv(security.TOKEN_ENV, raising=False)
    with pytest.raises(SystemExit) as exc:
        security.startup_guard(host)
    assert "refusing to bind" in str(exc.value)


def test_loopback_needs_no_token_and_a_reachable_bind_accepts_one(monkeypatch):
    from apps.mission_control import security
    monkeypatch.delenv(security.TOKEN_ENV, raising=False)
    assert security.startup_guard("127.0.0.1") == ""
    monkeypatch.setenv(security.TOKEN_ENV, "tok")
    assert security.startup_guard("0.0.0.0") == "tok"
