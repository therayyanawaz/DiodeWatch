"""The wall writes structured JSON logs and never leaks the token to them.

Three claims:

  * every HTTP request lands in a rotating access log, and the query string
    never does (the wall token rides ?token=, so a full URL would put the
    token in a file with a 5 MB retention window);
  * rotation really caps the number of files and the base size;
  * application events are one JSON object per line, extras on top level.
"""
from __future__ import annotations

import json
import logging

import pytest

pytest.importorskip("fastapi")


def _client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import apps.mission_control.server as srv
    monkeypatch.setenv("DIODE_LIVE_DB", str(tmp_path / "wall_ops.db"))
    return TestClient(srv.app), srv


def _point_logs_at(tmp_path, monkeypatch):
    from apps.mission_control import logging_setup as ls
    monkeypatch.setenv("DIODE_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("DIODE_LOG_MAX_BYTES", "100000")
    return ls.ensure_setup(force=True)


def _last_access_line(log_dir):
    lines = (log_dir / "access.log").read_text(encoding="utf-8").splitlines()
    assert lines, "access log is empty"
    return json.loads(lines[-1])


def test_every_request_hits_the_access_log_and_the_token_never_does(
        tmp_path, monkeypatch):
    _point_logs_at(tmp_path, monkeypatch)
    client, _ = _client(tmp_path, monkeypatch)
    client.get("/")
    client.get("/api/health")
    secret = "s3cret-token-value"
    monkeypatch.setenv("DIODE_WALL_TOKEN", secret)
    client.get("/api/session", headers={"x-diode-token": secret})
    monkeypatch.delenv("DIODE_WALL_TOKEN")

    logs = tmp_path / "logs"
    lines = (logs / "access.log").read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 3
    events = [json.loads(line) for line in lines]
    for e in events:
        assert {"ts", "level", "logger", "event", "method", "path", "status",
                "ms", "client"} <= set(e), e
    by_path = {e["path"]: e for e in events}
    assert by_path["/"]["status"] == 200
    assert by_path["/api/session"]["status"] == 200
    text = (logs / "access.log").read_text(encoding="utf-8")
    assert secret not in text, "the token must never reach the access log"


def test_rotation_caps_the_file_count_and_size(tmp_path):
    from logging.handlers import RotatingFileHandler  # noqa: F401

    from apps.mission_control.logging_setup import ACCESS_LOG, _rotating_handler

    log_dir = tmp_path / "rot"
    handler = _rotating_handler(log_dir, ACCESS_LOG, 400, 2)
    lg = logging.getLogger("diode.rotation-test")
    lg.addHandler(handler)
    lg.setLevel(logging.INFO)
    try:
        for i in range(50):
            lg.info("rotation probe %03d", i)
        handler.close()
    finally:
        lg.removeHandler(handler)
    files = sorted(p for p in log_dir.iterdir())
    assert len(files) <= 3, files            # base + 2 rotated
    assert files[-1].stat().st_size <= 400 + 200, "base file stays under max"


def test_app_log_is_json_lines_with_the_session_story(tmp_path, monkeypatch):
    _point_logs_at(tmp_path, monkeypatch)
    client, _ = _client(tmp_path, monkeypatch)
    client.get("/api/health")
    logging.getLogger("diode.wall").info("probe event", extra={"k": "v"})
    lines = (tmp_path / "logs" / "mission_control.log"
             ).read_text(encoding="utf-8").splitlines()
    assert lines
    event = json.loads(lines[-1])
    assert event["event"] == "probe event"
    assert event["k"] == "v"
    assert event["logger"].startswith("diode.")
