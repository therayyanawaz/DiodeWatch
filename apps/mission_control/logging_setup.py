"""Structured logging for the mission-control server.

Two rotating JSON-lines files under one directory (default `data/logs/`,
moved with `DIODE_LOG_DIR`):

* `mission_control.log`: application events (session lifecycle, websocket
  handshakes, maintenance runs, replay errors). Every line is one JSON object,
  so an operator can `grep` a field instead of parsing prose.
* `access.log`: one line per HTTP request, written by middleware so 401s,
  static hits and API calls all land in the same place.

The query string is never logged. The wall token rides `?token=`, so a full
URL in an access log would put the token in a file with a 5 MB retention
window; the path alone is what an access log is for.

Rotation is size-based (default 5 MB x 5 files, `DIODE_LOG_MAX_BYTES` /
`DIODE_LOG_BACKUPS`) and fails soft: a log directory the process cannot write
must never stop the wall from serving, it degrades to stderr only.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

ENV_DIR = "DIODE_LOG_DIR"
ENV_MAX_BYTES = "DIODE_LOG_MAX_BYTES"
ENV_BACKUPS = "DIODE_LOG_BACKUPS"

APP_LOG = "mission_control.log"
ACCESS_LOG = "access.log"
DEFAULT_MAX_BYTES = 5_000_000
DEFAULT_BACKUPS = 5

# Standard LogRecord attributes; everything else on a record came in through
# `extra=` and belongs in the JSON line.
_RESERVED = frozenset((
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "module", "msecs",
    "message", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "stack_print", "thread", "threadName",
    "taskName",
))


class JsonFormatter(logging.Formatter):
    """One JSON object per line, extras flattened onto the top level."""

    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
                  + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                out[key] = value
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str, ensure_ascii=False)


def log_dir() -> Path:
    return Path(os.environ.get(ENV_DIR) or (REPO_ROOT / "data" / "logs"))


def _rotating_handler(directory: Path, filename: str, max_bytes: int,
                      backups: int) -> RotatingFileHandler:
    directory.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(directory / filename,
                                  maxBytes=max(200, int(max_bytes)),
                                  backupCount=max(1, int(backups)),
                                  encoding="utf-8")
    handler.setFormatter(JsonFormatter())
    return handler


_configured = False


def ensure_setup(force: bool = False) -> dict[str, Any]:
    """Configure the `diode.*` logger tree once; returns where files land.

    Safe to call per-request: after the first pass it is a dictionary lookup.
    `force=True` reconfigures against the current environment (tests use it to
    point the log dir at a temporary directory).
    """
    global _configured
    info: dict[str, Any] = {"log_dir": str(log_dir())}
    if _configured and not force:
        return info

    root = logging.getLogger("diode")
    for existing in list(root.handlers):
        existing.close()
        root.removeHandler(existing)
    access = logging.getLogger("diode.access")
    for existing in list(access.handlers):
        existing.close()
        access.removeHandler(existing)

    try:
        max_bytes = int(os.environ.get(ENV_MAX_BYTES) or DEFAULT_MAX_BYTES)
        backups = int(os.environ.get(ENV_BACKUPS) or DEFAULT_BACKUPS)
        app_handler = _rotating_handler(log_dir(), APP_LOG, max_bytes, backups)
        access_handler = _rotating_handler(log_dir(), ACCESS_LOG,
                                           max_bytes, backups)
    except OSError as e:
        # No file destination: keep serving, mirror warnings to stderr and say
        # so on the first line an operator sees.
        info["error"] = f"log files unavailable, stderr only: {e}"
        info["configured"] = False
        _configured = True
        return info

    root.setLevel(logging.INFO)
    root.addHandler(app_handler)
    mirror = logging.StreamHandler()
    mirror.setLevel(logging.WARNING)
    mirror.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root.addHandler(mirror)

    access.setLevel(logging.INFO)
    access.addHandler(access_handler)
    root.propagate = False
    access.propagate = False
    _configured = True
    info.update({"app_log": str(log_dir() / APP_LOG),
                 "access_log": str(log_dir() / ACCESS_LOG),
                 "max_bytes": max_bytes, "backups": backups,
                 "configured": True})
    return info


def access_middleware(app: Any) -> None:
    """Register the outermost request logger.

    Added last, so it runs first and records the status every inner layer
    (security headers, cache policy) agreed on, including 401s.
    """
    log = logging.getLogger("diode.access")

    @app.middleware("http")
    async def _access(request, call_next):
        started = time.perf_counter()
        ensure_setup()
        response = await call_next(request)
        # Path only, never the query string: the wall token rides ?token=.
        log.info("request", extra={
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "ms": round((time.perf_counter() - started) * 1000.0, 1),
            "client": request.client.host if request.client else "",
        })
        return response


def stderr_fallback(message: str) -> None:
    print(message, file=sys.stderr, flush=True)
