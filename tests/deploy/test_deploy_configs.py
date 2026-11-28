"""The wall deployment is a file contract, tested without nginx or systemd."""
from __future__ import annotations

from pathlib import Path

import pytest

from apps.mission_control import server
from scripts.checks import check_deployment as deployment

ROOT = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_shipped_deployment_is_clean() -> None:
    assert deployment.check(ROOT) == []


def test_unit_rejects_a_second_worker() -> None:
    unit = _read("deploy/systemd/diodewatch-wall.service")
    assert "--workers 1" in unit
    problems = deployment.check_unit(unit.replace("--workers 1", "--workers 2"))
    assert any("--workers" in problem for problem in problems)


def test_unit_rejects_a_public_bind() -> None:
    unit = _read("deploy/systemd/diodewatch-wall.service")
    problems = deployment.check_unit(unit.replace("--host 127.0.0.1",
                                                  "--host 0.0.0.0"))
    assert any("0.0.0.0" in problem or "loopback" in problem
               for problem in problems)


def test_unit_requires_the_export_write_path() -> None:
    unit = _read("deploy/systemd/diodewatch-wall.service")
    line = ("ReadWritePaths=/var/lib/diodewatch "
            "/opt/diodewatch/data/alerts\n")
    assert line in unit
    problems = deployment.check_unit(unit.replace(line, ""))
    assert any("ReadWritePaths" in problem for problem in problems)


def test_unit_pins_the_wall_limits() -> None:
    unit = _read("deploy/systemd/diodewatch-wall.service")
    for line in (
        "Environment=DIODE_ALLOWED_HOSTS=127.0.0.1,localhost,[::1]",
        "Environment=DIODE_API_RATE_LIMIT=600",
        "Environment=DIODE_WRITE_RATE_LIMIT=12",
        "Environment=DIODE_RATE_WINDOW_S=60",
        "Environment=DIODE_MAX_BODY_BYTES=1048576",
    ):
        assert line in unit
    problems = deployment.check_unit(unit.replace(
        "Environment=DIODE_WRITE_RATE_LIMIT=12",
        "Environment=DIODE_WRITE_RATE_LIMIT=0"))
    assert any("DIODE_WRITE_RATE_LIMIT" in problem for problem in problems)


def test_unit_requires_a_host_allowlist() -> None:
    unit = _read("deploy/systemd/diodewatch-wall.service")
    line = "Environment=DIODE_ALLOWED_HOSTS=127.0.0.1,localhost,[::1]" + "\n"
    problems = deployment.check_unit(unit.replace(line, ""))
    assert any("DIODE_ALLOWED_HOSTS" in problem for problem in problems)


def test_nginx_rejects_an_obsolete_tls_floor() -> None:
    conf = _read("deploy/nginx/diodewatch.conf")
    problems = deployment.check_nginx(
        conf.replace("TLSv1.2 TLSv1.3", "TLSv1 TLSv1.1"))
    assert any("obsolete" in problem or "ssl_protocols" in problem
               for problem in problems)


def test_nginx_rejects_a_non_loopback_upstream() -> None:
    conf = _read("deploy/nginx/diodewatch.conf")
    problems = deployment.check_nginx(
        conf.replace("http://127.0.0.1:8530", "http://192.0.2.10:8530"))
    assert any("upstream" in problem for problem in problems)


def test_nginx_requires_the_websocket_upgrade_headers() -> None:
    conf = _read("deploy/nginx/diodewatch.conf")
    problems = deployment.check_nginx(
        conf.replace("        proxy_set_header Upgrade $http_upgrade;\n", ""))
    assert any("Upgrade" in problem for problem in problems)


def test_nginx_hides_the_banner_on_both_listeners() -> None:
    conf = _read("deploy/nginx/diodewatch.conf")
    assert conf.count("server_tokens off;") == 2
    problems = deployment.check_nginx(conf.replace("    server_tokens off;\n", "", 1))
    assert any("banner" in problem for problem in problems)


def test_nginx_redirect_listener_uses_the_sanitized_log() -> None:
    conf = _read("deploy/nginx/diodewatch.conf")
    line = "    access_log /var/log/nginx/diodewatch.access.log diodewatch;\n"
    assert conf.count(line) == 2
    problems = deployment.check_nginx(conf.replace(line, "", 1))
    assert any("access log" in problem for problem in problems)


def test_nginx_access_log_cannot_record_the_query_string() -> None:
    conf = _read("deploy/nginx/diodewatch.conf")
    assert "log_format diodewatch" in conf
    problems = deployment.check_nginx(
        conf.replace("$request_method $uri", "$request_method $request_uri", 1))
    assert any("query string" in problem for problem in problems)


def test_launchers_use_the_module_form() -> None:
    assert "exec \"$PY\" -m apps.mission_control.server" in _read("run_web.sh")
    assert "-m apps.mission_control.server" in _read("run_web.bat")
    assert "python -m apps.mission_control.server" in _read("docs/dashboard.md")


def test_cli_passes_one_worker_to_uvicorn(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict = {}

    def fake_run(*args: object, **kwargs: object) -> None:
        calls["args"] = args
        calls["kwargs"] = kwargs

    monkeypatch.setattr(server.uvicorn, "run", fake_run)
    monkeypatch.setattr(server.logging_setup, "ensure_setup", dict)
    server.main(["--port", "0"])

    assert calls["kwargs"]["workers"] == 1
    assert calls["kwargs"]["host"] == "127.0.0.1"
    assert calls["kwargs"]["port"] == 0


def test_cli_refuses_more_than_one_worker() -> None:
    with pytest.raises(SystemExit) as stopped:
        server.main(["--workers", "2"])
    assert stopped.value.code == 2


def test_checker_cli_is_clean(capsys: pytest.CaptureFixture[str]) -> None:
    assert deployment.main([]) == 0
    assert "DEPLOYMENT CLEAN" in capsys.readouterr().out
