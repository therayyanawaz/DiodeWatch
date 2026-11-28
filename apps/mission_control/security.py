"""The wall's trust boundary: response hardening and an optional bearer token.

The server binds loopback by default, which is the right default for a demo on
one machine but not a security boundary on its own: any page the browser loads
can reach 127.0.0.1, so a stray tab can start a replay, stop one, or read the
evidence store the wall is displaying. Three protections, deliberately separate:

  * **Headers on every response.** A strict CSP means the wall can only execute
    its own bundle, and `frame-ancestors 'none'` means no page can wrap it.
    These cost nothing and apply whether or not a token is configured.

  * **A host allowlist, a 1 MiB body cap and API rate limits** in the adjacent
    `limits.py`: a foreign Host is a 400, an oversized body is a 413, and a
    scripted replay loop spends its 12 write slots per minute and then gets 429.

  * **A bearer token for the API and the live socket, when one is configured.**
    `DIODE_WALL_TOKEN` (or `--token`) turns every `/api` route into a 401 without
    it, and refuses the `/ws/live` handshake, which carries the same alerts over
    a channel HTTP middleware never inspects. Binding to a
    non-loopback interface requires a token: `startup_guard` refuses to start
    otherwise, because an unauthenticated wall on a shared network lets anyone
    who can reach the port drive and read the capture.

The browser client does not send the token, on purpose: a token pasted into a
page is a token in a page. A token-protected wall is driven through the API (the
launchers, the CLI, `curl -H`), and `docs/dashboard.md` says so.
"""
from __future__ import annotations

import hmac
import os

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

TOKEN_ENV = "DIODE_WALL_TOKEN"
TOKEN_HEADER = "x-diode-token"
LOOPBACK = {"127.0.0.1", "::1", "localhost", "0:0:0:0:0:0:0:1"}

# script-src 'self': the wall runs only the bundle Vite emitted. style-src needs
# 'unsafe-inline' because React writes style attributes; no <style> block or
# third-party stylesheet is loadable. connect-src is 'self' alone: under CSP3 that
# already permits ws/wss to this origin, while the bare `ws:` scheme source would
# have allowed the page to open a socket to any host that spoke WebSocket.
CSP = (
    "default-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'; object-src 'none'; "
    "script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'"
)

HEADERS: tuple[tuple[str, str], ...] = (
    ("Content-Security-Policy", CSP),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
)


def configured_token() -> str:
    return (os.environ.get(TOKEN_ENV) or "").strip()


def _supplied(request) -> str:
    header = request.headers.get(TOKEN_HEADER)
    if header:
        return header.strip()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def guard_headers(request, token: str):
    """Return a 401 response when the request may not proceed, else None."""
    if not token or not request.url.path.startswith("/api"):
        return None
    supplied = _supplied(request)
    if hmac.compare_digest(supplied, token):
        return None
    return JSONResponse(
        {"detail": f"this wall requires a {TOKEN_HEADER} token"},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer", **dict(HEADERS)},
    )


async def _dispatch(request, call_next):
    denied = guard_headers(request, configured_token())
    if denied is not None:
        return denied
    response = await call_next(request)
    for key, value in HEADERS:
        response.headers.setdefault(key, value)
    return response


def ws_token_denied(ws, token: str | None = None) -> bool:
    """True when a WebSocket handshake must be refused.

    A `BaseHTTPMiddleware` dispatch function is not called for a WebSocket: the
    token that protects every `/api` route left `/ws/live` open, and that socket
    is the whole alert stream. A browser cannot set a header on a handshake, so
    the token is accepted from `?token=` as well; it is the same secret over the
    same loopback, and the alternative is an unauthenticated evidence feed.
    """
    token = configured_token() if token is None else token
    if not token:
        return False
    supplied = (ws.query_params.get("token")
                or ws.headers.get(TOKEN_HEADER)
                or "").strip()
    return not hmac.compare_digest(supplied, token)


def install(app: FastAPI) -> None:
    app.add_middleware(BaseHTTPMiddleware, dispatch=_dispatch)


def startup_guard(host: str, allow_unauthenticated: bool = False) -> str:
    """Enforce the rule that a reachable wall is an authenticated wall.

    Returns the token in force (possibly ""), so `main()` can print where it
    came from. Raises SystemExit when the configuration would expose an open
    control surface.
    """
    token = configured_token()
    if host not in LOOPBACK and not token and not allow_unauthenticated:
        raise SystemExit(
            f"refusing to bind {host}: set {TOKEN_ENV} (or pass --token) so the "
            f"wall is not an unauthenticated control surface, or pass "
            f"--allow-unauthenticated if that is genuinely intended"
        )
    return token
