"""The Streamlit password gate: config, denial, entry and sign-out."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from apps.dashboard import auth

REPO = Path(__file__).resolve().parents[2]
APP = REPO / "apps" / "dashboard" / "app.py"
PANEL = REPO / "apps" / "dashboard" / "diode_panel.py"
PASSWORD = "correct-horse-battery"


@pytest.fixture(autouse=True)
def _clean_auth_environment(monkeypatch):
    """A developer shell must not decide whether these tests are locked."""
    for key in (auth.PASSWORD_ENV, auth.PASSWORD_FILE_ENV, auth.ANONYMOUS_ENV):
        monkeypatch.delenv(key, raising=False)


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def test_no_configuration_is_locked_not_anonymous():
    cfg = auth.load_config({})
    assert cfg.password is None
    assert cfg.allow_anonymous is False
    assert cfg.error is None
    assert auth.anonymous_permitted(cfg, "127.0.0.1") is False


def test_short_environment_password_is_a_configuration_error():
    cfg = auth.load_config({auth.PASSWORD_ENV: "too-short"})
    assert cfg.password is None
    assert "shorter than 12" in (cfg.error or "")


def test_environment_password_is_used_verbatim():
    cfg = auth.load_config({auth.PASSWORD_ENV: PASSWORD})
    assert cfg.password == PASSWORD
    assert cfg.source == "environment"
    assert cfg.error is None


def test_password_file_ignores_only_trailing_newlines(tmp_path):
    path = tmp_path / "dashboard.pass"
    path.write_text(PASSWORD + "  \r\n", encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)
    cfg = auth.load_config({auth.PASSWORD_FILE_ENV: str(path)})
    assert cfg.password == PASSWORD + "  "
    assert cfg.source == "file"
    assert cfg.error is None


def test_password_file_must_not_be_group_or_other_readable(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX mode bits only")
    path = tmp_path / "dashboard.pass"
    path.write_text(PASSWORD, encoding="utf-8")
    path.chmod(0o644)
    cfg = auth.load_config({auth.PASSWORD_FILE_ENV: str(path)})
    assert cfg.password is None
    assert "chmod 600" in (cfg.error or "")


def test_two_password_sources_are_refused(tmp_path):
    path = tmp_path / "dashboard.pass"
    path.write_text(PASSWORD, encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)
    cfg = auth.load_config({auth.PASSWORD_ENV: PASSWORD,
                            auth.PASSWORD_FILE_ENV: str(path)})
    assert cfg.password is None
    assert "set only one" in (cfg.error or "")


def test_empty_password_file_is_refused(tmp_path):
    path = tmp_path / "dashboard.pass"
    path.write_text("\n", encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)
    cfg = auth.load_config({auth.PASSWORD_FILE_ENV: str(path)})
    assert cfg.password is None
    assert "blank" in (cfg.error or "")


def test_nul_byte_password_is_refused():
    cfg = auth.load_config({auth.PASSWORD_ENV: "long-enough\x00value"})
    assert cfg.password is None
    assert "NUL byte" in (cfg.error or "")


def test_blank_password_file_path_is_refused():
    cfg = auth.load_config({auth.PASSWORD_FILE_ENV: "   "})
    assert cfg.password is None
    assert "is empty" in (cfg.error or "")


def test_missing_password_file_is_a_configuration_error(tmp_path):
    cfg = auth.load_config(
        {auth.PASSWORD_FILE_ENV: str(tmp_path / "absent.pass")})
    assert cfg.password is None
    assert "cannot read" in (cfg.error or "")


def test_non_utf8_password_file_is_refused(tmp_path):
    path = tmp_path / "dashboard.pass"
    path.write_bytes(b"\xff\xfe" + PASSWORD.encode("utf-8"))
    if os.name == "posix":
        path.chmod(0o600)
    cfg = auth.load_config({auth.PASSWORD_FILE_ENV: str(path)})
    assert cfg.password is None
    assert "not UTF-8" in (cfg.error or "")


def test_anonymous_flag_only_accepts_one_or_zero():
    cfg = auth.load_config({auth.ANONYMOUS_ENV: "true"})
    assert cfg.allow_anonymous is False
    assert "must be 1 or 0" in (cfg.error or "")
    assert auth.load_config({auth.ANONYMOUS_ENV: "0"}).allow_anonymous is False
    assert auth.load_config({auth.ANONYMOUS_ENV: "1"}).allow_anonymous is True


@pytest.mark.parametrize("address", [
    "127.0.0.1", "127.1.2.3", "localhost", "::1", "[::1]"])
def test_loopback_binds_are_recognised(address):
    assert auth.is_loopback_bind(address) is True


@pytest.mark.parametrize("address", [
    None, "", "0.0.0.0", "::", "192.0.2.1", "dashboard.example", "127.0.0.1:8501"])
def test_non_loopback_binds_are_not_recognised(address):
    assert auth.is_loopback_bind(address) is False


def test_anonymous_is_permitted_only_on_a_loopback_with_no_password():
    anonymous = auth.AuthConfig(None, True, "none")
    assert auth.anonymous_permitted(anonymous, "127.0.0.1") is True
    assert auth.anonymous_permitted(anonymous, "0.0.0.0") is False
    assert auth.anonymous_permitted(anonymous, None) is False
    protected = auth.AuthConfig(PASSWORD, True, "environment")
    assert auth.anonymous_permitted(protected, "127.0.0.1") is False
    broken = auth.AuthConfig(None, True, "none", "bad config")
    assert auth.anonymous_permitted(broken, "127.0.0.1") is False


def test_password_comparison_is_exact_and_unicode_safe():
    assert auth.password_matches("pässword-1234", "pässword-1234") is True
    assert auth.password_matches("pässword-1234", "password-1234") is False
    assert auth.password_matches(PASSWORD, PASSWORD + "x") is False
    assert auth.password_stamp(PASSWORD) != auth.password_stamp(PASSWORD + "x")


# --------------------------------------------------------------------------- #
# rendered gate
# --------------------------------------------------------------------------- #
def _run(path: Path, timeout: int = 180):
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(path))
    at.run(timeout=timeout)
    return at


def _set_db(monkeypatch, tmp_path):
    monkeypatch.setenv("DIODE_LIVE_DB", str(tmp_path / "live.db"))
    monkeypatch.setenv("DIODE_STATUS_FILE", str(tmp_path / "status.json"))


def test_dashboard_without_a_secret_renders_only_the_lock(monkeypatch, tmp_path):
    _set_db(monkeypatch, tmp_path)
    at = _run(APP)
    assert not at.exception
    assert len(at.tabs) == 0
    assert any("Dashboard locked" in (t.value or "") for t in at.title)
    assert any("No dashboard password" in (e.value or "") for e in at.error)
    assert not at.metric
    assert not (tmp_path / "live.db").exists()
    assert not (tmp_path / "status.json").exists()


def test_wrong_password_does_not_render_the_dashboard(monkeypatch, tmp_path):
    _set_db(monkeypatch, tmp_path)
    monkeypatch.setenv(auth.PASSWORD_ENV, PASSWORD)
    at = _run(APP)
    assert len(at.text_input) == 1
    assert len(at.tabs) == 0

    at.text_input[0].input("not-the-password")
    at.button[0].click()
    at.run(timeout=180)
    assert not at.exception
    assert any("Invalid password" in (e.value or "") for e in at.error)
    assert len(at.tabs) == 0


def test_password_enters_the_dashboard_and_sign_out_locks_it(monkeypatch, tmp_path):
    _set_db(monkeypatch, tmp_path)
    monkeypatch.setenv(auth.PASSWORD_ENV, PASSWORD)
    at = _run(APP)
    at.text_input[0].input(PASSWORD)
    at.button[0].click()
    at.run(timeout=180)
    assert not at.exception
    assert len(at.tabs) == 4
    assert any("Signed in" in (c.value or "") for c in at.sidebar.caption)

    at.sidebar.button[0].click()
    at.run(timeout=180)
    assert not at.exception
    assert len(at.tabs) == 0
    assert any("DiodeWatch dashboard" in (t.value or "") for t in at.title)


def test_five_failures_pause_sign_in(monkeypatch, tmp_path):
    _set_db(monkeypatch, tmp_path)
    monkeypatch.setenv(auth.PASSWORD_ENV, PASSWORD)
    at = _run(APP)
    for _ in range(auth.MAX_FAILED_ATTEMPTS):
        at.text_input[0].input("not-the-password")
        at.button[0].click()
        at.run(timeout=60)
    assert not at.exception
    assert any("Too many failed attempts" in (e.value or "") for e in at.error)
    assert len(at.text_input) == 0
    assert len(at.tabs) == 0


def test_changing_the_password_invalidates_an_open_session(monkeypatch, tmp_path):
    _set_db(monkeypatch, tmp_path)
    monkeypatch.setenv(auth.PASSWORD_ENV, PASSWORD)
    at = _run(APP)
    at.text_input[0].input(PASSWORD)
    at.button[0].click()
    at.run(timeout=180)
    assert len(at.tabs) == 4

    monkeypatch.setenv(auth.PASSWORD_ENV, "a-different-password")
    at.run(timeout=180)
    assert not at.exception
    assert len(at.tabs) == 0
    assert len(at.text_input) == 1


def test_misconfiguration_locks_instead_of_falling_back_to_anonymous(
        monkeypatch, tmp_path):
    _set_db(monkeypatch, tmp_path)
    monkeypatch.setenv(auth.PASSWORD_ENV, "too-short")
    monkeypatch.setenv(auth.ANONYMOUS_ENV, "1")
    at = _run(APP)
    assert not at.exception
    assert len(at.tabs) == 0
    assert any("misconfigured" in (e.value or "") for e in at.error)


def test_anonymous_mode_is_visible_and_local_only(monkeypatch, tmp_path):
    _set_db(monkeypatch, tmp_path)
    monkeypatch.setenv(auth.ANONYMOUS_ENV, "1")
    at = _run(APP)
    assert not at.exception
    assert len(at.tabs) == 4
    assert any("Authentication is off" in (w.value or "") for w in at.warning)


def test_anonymous_mode_is_refused_on_a_public_bind(monkeypatch, tmp_path):
    _set_db(monkeypatch, tmp_path)
    monkeypatch.setenv(auth.ANONYMOUS_ENV, "1")
    import streamlit

    real = streamlit.get_option

    def public_bind(key, *args, **kwargs):
        if key == "server.address":
            return "0.0.0.0"
        return real(key, *args, **kwargs)

    monkeypatch.setattr(streamlit, "get_option", public_bind)
    at = _run(APP)
    assert not at.exception
    assert len(at.tabs) == 0
    assert any("not bound to loopback" in (e.value or "") for e in at.error)


def test_diode_panel_is_locked_without_a_secret(monkeypatch, tmp_path):
    _set_db(monkeypatch, tmp_path)
    at = _run(PANEL)
    assert not at.exception
    assert any("Dashboard locked" in (t.value or "") for t in at.title)
    assert not any("Diode Proof" in (t.value or "") for t in at.title)
