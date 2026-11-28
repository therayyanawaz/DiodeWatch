"""The wall's request guards: trusted host, body cap and rate limits.

These are separate from the token in `test_wall_security.py`. A token holder can
still script start/reset in a loop, and loopback is not a host boundary. The
tests use a small app with the same middleware so a low limit can be proved
without 600 requests, then the shipped app is checked for the default wiring.
"""
from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI, Request

from apps.mission_control import limits as lim
from apps.mission_control import security

CSP = "frame-ancestors 'none'"


def _guarded_app(**over):
    cfg = lim.LimitsConfig(
        allowed_hosts=("127.0.0.1", "localhost"),
        api_limit=over.get("api_limit", 4),
        write_limit=over.get("write_limit", 2),
        window_s=over.get("window_s", 60),
        max_body_bytes=over.get("max_body_bytes", 32),
    )
    app = FastAPI()

    @app.get("/api/read")
    async def read() -> dict:
        return {"ok": True}

    @app.post("/api/write")
    async def write() -> dict:
        return {"ok": True}

    @app.post("/api/echo")
    async def echo(request: Request) -> dict:
        body = await request.body()
        return {"length": len(body)}

    lim.install(app, config=cfg)
    security.install(app)          # outermost, so rejections keep the headers
    return app


def _client(app=None):
    from fastapi.testclient import TestClient
    return TestClient(app or _guarded_app(),
                      base_url="http://127.0.0.1:8530")


def test_a_foreign_host_is_refused_before_a_route(monkeypatch):
    monkeypatch.delenv(security.TOKEN_ENV, raising=False)
    client = _client()
    assert client.get("/api/read").status_code == 200
    assert client.get("/api/read", headers={"Host": "localhost"}).status_code == 200

    denied = client.get("/api/read", headers={"Host": "rebind.example"})
    assert denied.status_code == 400
    assert "invalid host" in denied.text.lower()
    assert CSP in denied.headers["content-security-policy"]

    # Host is the outer check: an oversized body under a foreign name is 400,
    # not 413, and no bytes are buffered for it.
    denied = client.post("/api/echo", content=b"x" * 64,
                         headers={"Host": "rebind.example"})
    assert denied.status_code == 400


def test_token_is_checked_before_the_host_allowlist(monkeypatch):
    monkeypatch.setenv(security.TOKEN_ENV, "s3cret")
    client = _client()
    # A missing token is 401 even when the Host is also wrong; the token layer
    # is outermost. A token-bearing request then reaches the host check (400).
    denied = client.get("/api/read", headers={"Host": "rebind.example"})
    assert denied.status_code == 401
    denied = client.get("/api/read",
                        headers={"Host": "rebind.example",
                                 "X-Diode-Token": "s3cret"})
    assert denied.status_code == 400


def test_api_reads_are_rate_limited_with_retry_after(monkeypatch):
    monkeypatch.delenv(security.TOKEN_ENV, raising=False)
    client = _client()
    for _ in range(4):
        assert client.get("/api/read").status_code == 200
    denied = client.get("/api/read")
    assert denied.status_code == 429
    assert denied.headers["retry-after"] == "60"
    assert denied.headers["connection"] == "close"
    assert "rate limit" in denied.json()["detail"]
    assert CSP in denied.headers["content-security-policy"]


def test_unsafe_methods_have_their_own_smaller_budget(monkeypatch):
    monkeypatch.delenv(security.TOKEN_ENV, raising=False)
    client = _client()
    assert client.post("/api/write").status_code == 200
    assert client.post("/api/write").status_code == 200
    denied = client.post("/api/write")
    assert denied.status_code == 429
    assert denied.headers["retry-after"] == "60"


def test_the_body_cap_counts_the_stream_not_just_the_header(monkeypatch):
    monkeypatch.delenv(security.TOKEN_ENV, raising=False)
    client = _client()
    ok = client.post("/api/echo", content=b"x" * 32,
                     headers={"Content-Type": "application/octet-stream"})
    assert ok.status_code == 200, ok.text
    assert ok.json()["length"] == 32

    denied = client.post("/api/echo", content=b"x" * 33,
                         headers={"Content-Type": "application/octet-stream"})
    assert denied.status_code == 413
    assert denied.headers["connection"] == "close"
    assert "exceeds 32" in denied.json()["detail"]
    assert CSP in denied.headers["content-security-policy"]


def test_the_body_cap_counts_asgi_messages_not_the_declared_length(monkeypatch):
    """The middleware counts the bytes it receives, so a scope whose
    Content-Length says 1 cannot wave 33 bytes through. Real HTTP framing
    rejects that mismatch before ASGI; this pins the middleware's own contract.
    """
    monkeypatch.delenv(security.TOKEN_ENV, raising=False)
    app = _guarded_app()

    async def call() -> tuple[int, bytes]:
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": "POST", "scheme": "http", "path": "/api/echo",
            "raw_path": b"/api/echo", "query_string": b"", "root_path": "",
            "headers": [(b"host", b"127.0.0.1"),
                        (b"content-length", b"1"),
                        (b"content-type", b"application/octet-stream")],
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 8530),
        }
        incoming = [
            {"type": "http.request", "body": b"x" * 16, "more_body": True},
            {"type": "http.request", "body": b"x" * 17, "more_body": False},
        ]
        sent: list[dict] = []

        async def receive() -> dict:
            return incoming.pop(0) if incoming else {"type": "http.disconnect"}

        async def send(message: dict) -> None:
            sent.append(message)

        await app(scope, receive, send)
        start = next(m for m in sent if m["type"] == "http.response.start")
        body = b"".join(m.get("body", b"") for m in sent
                        if m["type"] == "http.response.body")
        return start["status"], body

    status, body = asyncio.run(call())
    assert status == 413
    assert "exceeds 32" in json.loads(body)["detail"]


def test_invalid_content_length_is_a_400(monkeypatch):
    monkeypatch.delenv(security.TOKEN_ENV, raising=False)
    client = _client()
    denied = client.post("/api/echo", content=b"{}",
                         headers={"Content-Length": "nope"})
    assert denied.status_code == 400
    assert "Content-Length" in denied.json()["detail"]


def test_limits_config_defaults_and_parsing(monkeypatch):
    for name in (lim.HOSTS_ENV, lim.API_LIMIT_ENV, lim.WRITE_LIMIT_ENV,
                 lim.WINDOW_ENV, lim.BODY_ENV):
        monkeypatch.delenv(name, raising=False)
    cfg = lim.LimitsConfig.from_env()
    assert cfg.allowed_hosts == lim.DEFAULT_ALLOWED_HOSTS
    assert cfg.api_limit == lim.DEFAULT_API_LIMIT
    assert cfg.write_limit == lim.DEFAULT_WRITE_LIMIT
    assert cfg.window_s == lim.DEFAULT_WINDOW_S
    assert cfg.max_body_bytes == lim.DEFAULT_MAX_BODY_BYTES

    monkeypatch.setenv(lim.HOSTS_ENV, " Wall.Example , 127.0.0.1 ")
    monkeypatch.setenv(lim.API_LIMIT_ENV, "7")
    cfg = lim.LimitsConfig.from_env()
    assert cfg.allowed_hosts == ("wall.example", "127.0.0.1")
    assert cfg.api_limit == 7


@pytest.mark.parametrize(("name", "value"), [
    (lim.API_LIMIT_ENV, "0"),
    (lim.API_LIMIT_ENV, "many"),
    (lim.BODY_ENV, "-1"),
    (lim.HOSTS_ENV, ""),
    (lim.HOSTS_ENV, "*"),
])
def test_bad_limit_config_refuses_to_start(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(SystemExit):
        lim.LimitsConfig.from_env()


def test_the_sliding_window_expires_old_hits():
    now = [0.0]
    window = lim.SlidingWindow(2, 10, clock=lambda: now[0])
    assert window.take() is None
    assert window.take() is None
    retry = window.take()
    assert retry is not None and 9.9 <= retry <= 10.0
    now[0] = 10.1
    assert window.take() is None


def test_the_shipped_app_publishes_the_limits_and_rejects_a_foreign_host(
        tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import apps.mission_control.server as srv
    monkeypatch.delenv(security.TOKEN_ENV, raising=False)
    monkeypatch.setenv("DIODE_LIVE_DB", str(tmp_path / "limits.db"))
    client = TestClient(srv.app, base_url="http://127.0.0.1:8530")

    health = client.get("/api/health").json()
    assert health["limits"]["max_body_bytes"] == 1_048_576
    assert health["limits"]["write_rate_limit"] == 12
    assert "localhost" in health["limits"]["allowed_hosts"]

    denied = client.get("/api/health", headers={"Host": "evil.example"})
    assert denied.status_code == 400
    assert CSP in denied.headers["content-security-policy"]
