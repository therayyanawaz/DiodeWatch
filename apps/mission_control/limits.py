"""Host allowlist, request-body cap and rate limits for the wall.

Three controls sit between the socket and the replay routes, independent of the
token in `security.py`:

  * **Trusted hosts.** A browser page can resolve its own name to 127.0.0.1 and
    reach a loopback wall with a foreign Host header. `DIODE_ALLOWED_HOSTS`
    defaults to `127.0.0.1,localhost,[::1]`; anything else is refused with 400
    before a route runs (the token layer, when configured, answers 401 first if
    the token is missing). Behind nginx the browser's Host is what arrives, so
    a deployment adds its DNS name to this list.
  * **A body cap.** `DIODE_MAX_BODY_BYTES` defaults to 1 MiB and is enforced by
    counting the ASGI request stream, not by trusting Content-Length. A lying
    header cannot carry a larger body through. The nginx template has the same
    1 MiB transport cap.
  * **Sliding-window rate limits.** `DIODE_API_RATE_LIMIT` requests per
    `DIODE_RATE_WINDOW_S` apply to every /api route; unsafe methods also spend
    `DIODE_WRITE_RATE_LIMIT` slots. The defaults are 600 API requests and 12
    writes per 60 s. The buckets are global to the process, not per client:
    the wall is one analyst and one session, and behind nginx every request
    arrives from 127.0.0.1 anyway. A token holder who scripts start/reset gets
    429s with a Retry-After instead of driving the replay forever.

Rejections are JSON and carry the same hardening headers as every other
response because `security.install` wraps this middleware. The counters that
matter are in the access log: the logger records the path and the status, never
the query string.
"""
from __future__ import annotations

import math
import os
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import FastAPI
from starlette.datastructures import Headers
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

HOSTS_ENV = "DIODE_ALLOWED_HOSTS"
API_LIMIT_ENV = "DIODE_API_RATE_LIMIT"
WRITE_LIMIT_ENV = "DIODE_WRITE_RATE_LIMIT"
WINDOW_ENV = "DIODE_RATE_WINDOW_S"
BODY_ENV = "DIODE_MAX_BODY_BYTES"

DEFAULT_ALLOWED_HOSTS = ("127.0.0.1", "localhost", "[::1]")
DEFAULT_API_LIMIT = 600
DEFAULT_WRITE_LIMIT = 12
DEFAULT_WINDOW_S = 60
DEFAULT_MAX_BODY_BYTES = 1_048_576

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class LimitsConfig:
    allowed_hosts: tuple[str, ...]
    api_limit: int
    write_limit: int
    window_s: int
    max_body_bytes: int

    def as_dict(self) -> dict:
        return {
            "allowed_hosts": list(self.allowed_hosts),
            "api_rate_limit": self.api_limit,
            "write_rate_limit": self.write_limit,
            "rate_window_s": self.window_s,
            "max_body_bytes": self.max_body_bytes,
        }

    @classmethod
    def from_env(cls) -> LimitsConfig:
        return cls(
            allowed_hosts=_allowed_hosts(),
            api_limit=_positive_int(API_LIMIT_ENV, DEFAULT_API_LIMIT),
            write_limit=_positive_int(WRITE_LIMIT_ENV, DEFAULT_WRITE_LIMIT),
            window_s=_positive_int(WINDOW_ENV, DEFAULT_WINDOW_S),
            max_body_bytes=_positive_int(BODY_ENV, DEFAULT_MAX_BODY_BYTES),
        )


def _allowed_hosts() -> tuple[str, ...]:
    raw = os.environ.get(HOSTS_ENV)
    if raw is None:
        return DEFAULT_ALLOWED_HOSTS
    hosts = tuple(part.strip().lower() for part in raw.split(",") if part.strip())
    if not hosts:
        raise SystemExit(f"{HOSTS_ENV} is set but names no host")
    if "*" in hosts:
        raise SystemExit(
            f"{HOSTS_ENV}=* would disable the host allowlist; name the hosts")
    return hosts


def _positive_int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a positive integer, got {raw!r}") from exc
    if value < 1:
        raise SystemExit(f"{name} must be at least 1, got {value}")
    return value


class SlidingWindow:
    """Count admitted events in the last window; return a retry delay or None."""

    def __init__(self, limit: int, window_s: int,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.limit = limit
        self.window_s = window_s
        self._clock = clock
        self._hits: deque[float] = deque()

    def take(self) -> float | None:
        now = self._clock()
        cutoff = now - self.window_s
        while self._hits and self._hits[0] <= cutoff:
            self._hits.popleft()
        if len(self._hits) >= self.limit:
            return max(0.0, self._hits[0] + self.window_s - now)
        self._hits.append(now)
        return None


class _BodyTooLarge(Exception):
    pass


class WallLimitsMiddleware:
    """Rate-limit /api, then buffer and cap the HTTP body before the app."""

    def __init__(self, app: ASGIApp, config: LimitsConfig,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.app = app
        self.config = config
        self._api = SlidingWindow(config.api_limit, config.window_s, clock)
        self._writes = SlidingWindow(config.write_limit, config.window_s, clock)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path == "/api" or path.startswith("/api/"):
            retry = self._api.take()
            if retry is not None:
                await self._reject(scope, receive, send, 429,
                                   "API rate limit exceeded", retry)
                return
            if scope.get("method", "GET").upper() not in SAFE_METHODS:
                retry = self._writes.take()
                if retry is not None:
                    await self._reject(scope, receive, send, 429,
                                       "write rate limit exceeded", retry)
                    return

        headers = Headers(scope=scope)
        declared = headers.getlist("content-length")
        if len(declared) > 1:
            await self._reject(scope, receive, send, 400,
                               "duplicate Content-Length")
            return
        if declared:
            try:
                length = int(declared[0].strip(), 10)
            except ValueError:
                await self._reject(scope, receive, send, 400,
                                   "invalid Content-Length")
                return
            if length < 0:
                await self._reject(scope, receive, send, 400,
                                   "negative Content-Length")
                return
            if length > self.config.max_body_bytes:
                await self._reject(
                    scope, receive, send, 413,
                    f"request body exceeds {self.config.max_body_bytes} bytes")
                return

        try:
            body = await self._read_body(receive)
        except _BodyTooLarge:
            await self._reject(
                scope, receive, send, 413,
                f"request body exceeds {self.config.max_body_bytes} bytes")
            return
        if body is None:
            return       # the peer disconnected before a complete body arrived
        await self.app(scope, _replay(body, receive), send)

    async def _read_body(self, receive: Receive) -> bytes | None:
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return None
            if message["type"] != "http.request":
                return None
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.config.max_body_bytes:
                raise _BodyTooLarge
            chunks.append(chunk)
            if not message.get("more_body", False):
                return b"".join(chunks)

    async def _reject(self, scope: Scope, receive: Receive, send: Send,
                      status: int, detail: str,
                      retry_after: float | None = None) -> None:
        headers = {}
        if retry_after is not None:
            headers["Retry-After"] = str(max(1, math.ceil(retry_after)))
        # These rejections can leave an unread request body on the wire; close
        # rather than let the next request inherit it.
        if status in (400, 413, 429):
            headers["Connection"] = "close"
        response = JSONResponse({"detail": detail}, status_code=status,
                                headers=headers)
        await response(scope, receive, send)


def _replay(body: bytes, receive: Receive) -> Receive:
    """Yield the buffered body once, then defer to the real receive.

    Returning a synthetic disconnect after the body breaks FileResponse: it
    streams the file in one task while the other reads receive to notice a
    client that went away, and an immediate disconnect cancels the file before
    it is sent. Forwarding the real receive lets the response layer end that
    wait when it sends, which is exactly what an unbuffered request does.
    """
    sent = False

    async def replay() -> dict:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay


def install(app: FastAPI,
            config: LimitsConfig | None = None) -> LimitsConfig:
    """Install the host allowlist and the request guard; return the config.

    TrustedHost is the outer of the two, so a foreign Host costs no body read.
    `security.install` is called after this and is therefore outermost, which
    is what puts the hardening headers on a 400, 413 or 429 as well.
    """
    cfg = config or LimitsConfig.from_env()
    # Added first, so the host check is the outer of the two and a foreign
    # Host is refused before a byte of its body is read.
    app.add_middleware(WallLimitsMiddleware, config=cfg)
    app.add_middleware(TrustedHostMiddleware,
                       allowed_hosts=list(cfg.allowed_hosts),
                       www_redirect=False)
    return cfg
