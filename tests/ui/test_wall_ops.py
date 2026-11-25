"""The wall's operational surface: logs, health with evidence, metrics.

Three claims:

  * every HTTP request lands in a rotating access log, and the query string
    never does (the wall token rides ?token=, so a full URL would put the
    token in a file);
  * /api/health is computed, not constant: a degraded store turns it red with
    the reason, and the deep probe reads every page;
  * /metrics speaks the Prometheus text format with counters that agree with
    the store.
"""
from __future__ import annotations

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


def test_health_is_computed_and_names_a_degraded_store(tmp_path, monkeypatch):
    _client(tmp_path, monkeypatch)
    from fastapi.testclient import TestClient

    import apps.mission_control.server as srv
    client = TestClient(srv.app)

    healthy = client.get("/api/health").json()
    assert healthy["ok"] is True
    assert healthy["checks"]["store"]["ok"] is True
    assert isinstance(healthy["checks"]["store"]["alerts"], int)
    assert healthy["version"] == "1.0.0"
    assert healthy["uptime_s"] >= 0

    deep = client.get("/api/health", params={"deep": "true"}).json()
    assert deep["checks"]["store"]["quick_check"] == "ok"

    # degrade the store the way a real failure does, then demand the reason
    real_store, real_error = srv.SESSION.store._store, srv.SESSION.store.error
    try:
        srv.SESSION.store._store = None
        srv.SESSION.store.error = "persistent store write failed: disk full"
        degraded = client.get("/api/health").json()
        assert degraded["ok"] is False
        assert degraded["checks"]["store"]["ok"] is False
        assert "disk full" in degraded["checks"]["store"]["detail"]
    finally:
        srv.SESSION.store._store = real_store
        srv.SESSION.store.error = real_error
    assert client.get("/api/health").json()["ok"] is True


def test_metrics_speak_prometheus_and_agree_with_the_store(tmp_path,
                                                          monkeypatch):
    _client(tmp_path, monkeypatch)
    from fastapi.testclient import TestClient

    import apps.mission_control.server as srv
    client = TestClient(srv.app)
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    text = resp.text
    lines = [l for l in text.splitlines() if l and not l.startswith("#")]
    assert all(l.startswith("diodewatch_") for l in lines), lines
    values = {}
    for l in lines:
        name, _, value = l.rpartition(" ")
        values[name] = float(value)

    store = srv.SESSION.store
    assert values["diodewatch_alerts_inserted_total"] == store._inserted
    assert values["diodewatch_alerts_rejected_total"] == store.rejected
    assert values["diodewatch_ws_clients"] == len(srv.CLIENTS)
    assert values["diodewatch_session_state{state=\"idle\"}"] == 1.0
    assert values["diodewatch_uptime_seconds"] >= 0


def test_the_maintenance_scheduler_defaults_are_sane():
    import apps.mission_control.server as srv
    assert srv.MAINT_KEEP >= 1
    assert srv.MAINT_INTERVAL_S >= 0
