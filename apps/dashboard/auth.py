"""Password gate for the Streamlit analyst surfaces.

The dashboard is a second surface beside the wall, and Streamlit binds every
interface by default. This module makes the default a locked page: a shared
password must be configured, or the operator must explicitly allow anonymous
access for a loopback-only local demo. It is authentication, not identity:
there are no accounts, roles or per-user audit trails.

Configure exactly one of:

* ``DIODE_DASHBOARD_PASSWORD``, at least 12 characters; or
* ``DIODE_DASHBOARD_PASSWORD_FILE``, a UTF-8 file whose trailing newline is
  ignored. On POSIX the file may not be readable by group or other.

Anonymous access is opt-in with ``DIODE_DASHBOARD_ALLOW_ANONYMOUS=1`` and is
refused unless Streamlit is bound to a loopback address. The repository
``.streamlit/config.toml`` sets that binding; a network deployment passes
``--server.address`` explicitly and must set a password.

The password is held in process memory only. A successful sign-in lives in
the Streamlit session state, so a browser refresh asks for it again and a
changed password invalidates older sessions on their next rerun.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PASSWORD_ENV = "DIODE_DASHBOARD_PASSWORD"
PASSWORD_FILE_ENV = "DIODE_DASHBOARD_PASSWORD_FILE"
ANONYMOUS_ENV = "DIODE_DASHBOARD_ALLOW_ANONYMOUS"
MIN_PASSWORD_CHARS = 12
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 30.0

AUTH_KEY = "_diode_dashboard_authenticated"
AUTH_STAMP_KEY = "_diode_dashboard_auth_stamp"
FAILURES_KEY = "_diode_dashboard_failures"
LOCKED_UNTIL_KEY = "_diode_dashboard_locked_until"
PASSWORD_INPUT_KEY = "_diode_dashboard_password_input"


@dataclass(frozen=True)
class AuthConfig:
    """What the environment asked for, and whether it was coherent."""

    password: str | None
    allow_anonymous: bool
    source: str
    error: str | None = None


def _password_problem(password: str) -> str | None:
    if not password.strip():
        return "the dashboard password is blank"
    if "\x00" in password:
        return "the dashboard password contains a NUL byte"
    if len(password) < MIN_PASSWORD_CHARS:
        return (f"the dashboard password is shorter than "
                f"{MIN_PASSWORD_CHARS} characters")
    return None


def _read_password_file(path: Path) -> tuple[str | None, str | None]:
    """Return (password, error). Never include the file contents in an error."""
    try:
        if os.name == "posix":
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                return None, ("the password file is readable by group or "
                              "other; chmod 600 it")
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"cannot read the password file: {exc}"
    except UnicodeDecodeError:
        return None, "the password file is not UTF-8"
    password = text.rstrip("\r\n")
    problem = _password_problem(password)
    if problem:
        return None, problem
    return password, None


def load_config(environ: Mapping[str, str] | None = None) -> AuthConfig:
    """Read the environment once per rerun and fail closed on ambiguity."""
    env = os.environ if environ is None else environ
    raw_password = env.get(PASSWORD_ENV)
    raw_file = env.get(PASSWORD_FILE_ENV)
    raw_anonymous = env.get(ANONYMOUS_ENV)

    allow_anonymous = False
    errors: list[str] = []
    if raw_anonymous not in (None, "", "0", "1"):
        errors.append(f"{ANONYMOUS_ENV} must be 1 or 0")
    else:
        allow_anonymous = raw_anonymous == "1"

    if raw_password is not None and raw_file is not None:
        errors.append(f"set only one of {PASSWORD_ENV} and {PASSWORD_FILE_ENV}")
        return AuthConfig(None, allow_anonymous, "none", "; ".join(errors))

    if raw_password is not None:
        problem = _password_problem(raw_password)
        if problem:
            errors.append(problem)
        return AuthConfig(None if errors else raw_password, allow_anonymous,
                          "environment", "; ".join(errors) or None)

    if raw_file is not None:
        if not raw_file.strip():
            errors.append(f"{PASSWORD_FILE_ENV} is empty")
            return AuthConfig(None, allow_anonymous, "none", "; ".join(errors))
        password, problem = _read_password_file(Path(raw_file).expanduser())
        if problem:
            errors.append(problem)
        return AuthConfig(None if errors else password, allow_anonymous,
                          "file", "; ".join(errors) or None)

    return AuthConfig(None, allow_anonymous, "none", "; ".join(errors) or None)


def password_matches(expected: str, candidate: str) -> bool:
    """Constant-time comparison; str compare_digest is ASCII-only, so encode."""
    return hmac.compare_digest(expected.encode("utf-8"),
                               candidate.encode("utf-8"))


def password_stamp(password: str) -> str:
    """Session invalidation stamp, not a stored credential."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def is_loopback_bind(address: str | None) -> bool:
    """True only for an explicit loopback listener, never for an unset bind."""
    if not address:
        return False
    raw = address.strip().lower()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    if raw == "localhost":
        return True
    try:
        return ipaddress.ip_address(raw).is_loopback
    except ValueError:
        return False


def anonymous_permitted(config: AuthConfig, address: str | None) -> bool:
    """Anonymous access is an explicit local-demo mode, not a fallback."""
    return (config.error is None and config.password is None
            and config.allow_anonymous and is_loopback_bind(address))


def _server_address(st: Any) -> str | None:
    getter = getattr(st, "get_option", None)
    if getter is None:
        return None
    value = getter("server.address")
    return value if isinstance(value, str) else None


def _clear_auth(st: Any) -> None:
    for key in (AUTH_KEY, AUTH_STAMP_KEY, FAILURES_KEY, LOCKED_UNTIL_KEY,
                PASSWORD_INPUT_KEY):
        st.session_state.pop(key, None)


def _setup_help(st: Any) -> None:
    st.markdown("Set **one** of these before starting Streamlit:")
    st.code("export DIODE_DASHBOARD_PASSWORD='a shared password of 12+ chars'",
            language="bash")
    st.code("export DIODE_DASHBOARD_PASSWORD_FILE=/run/diodewatch/dashboard.pass",
            language="bash")
    st.caption("On POSIX the password file must be mode 0600. The value is "
               "read from the environment or file on each rerun; it is never "
               "written to the repository.")
    st.markdown("For a loopback-only local demo, anonymous access is an "
                "explicit opt-in:")
    st.code("export DIODE_DASHBOARD_ALLOW_ANONYMOUS=1", language="bash")
    st.caption("Anonymous mode is refused when Streamlit is not bound to a "
               "loopback address. The repository .streamlit/config.toml sets "
               "127.0.0.1; a network deployment must set a password.")


def _locked(st: Any, message: str, detail: str | None = None) -> None:
    st.title("🔒 Dashboard locked")
    st.error(message)
    if detail:
        st.caption(detail)
    _setup_help(st)
    st.stop()


def _sidebar(st: Any, surface: str) -> None:
    st.sidebar.caption(f"Signed in · {surface}")
    if st.sidebar.button("Sign out", key="_diode_dashboard_signout"):
        _clear_auth(st)
        st.rerun()


def _login(st: Any, config: AuthConfig, surface: str) -> None:
    st.title("🔒 DiodeWatch dashboard")
    st.caption(f"{surface} requires the shared dashboard password.")
    st.caption("This is a single shared secret, not a user account. A browser "
               "refresh asks for it again.")

    now = time.monotonic()
    locked_until = float(st.session_state.get(LOCKED_UNTIL_KEY, 0.0) or 0.0)
    if now < locked_until:
        wait = max(1, int(locked_until - now + 0.999))
        st.error(f"Too many failed attempts. Try again in {wait} seconds.")
        st.stop()

    with st.form("diode_dashboard_login", clear_on_submit=True):
        candidate = st.text_input("Dashboard password", type="password",
                                  key=PASSWORD_INPUT_KEY)
        submitted = st.form_submit_button("Sign in")

    if submitted:
        if password_matches(config.password or "", candidate):
            st.session_state[AUTH_KEY] = True
            st.session_state[AUTH_STAMP_KEY] = password_stamp(config.password or "")
            st.session_state[FAILURES_KEY] = 0
            st.session_state.pop(LOCKED_UNTIL_KEY, None)
            st.rerun()
        failures = int(st.session_state.get(FAILURES_KEY, 0)) + 1
        st.session_state[FAILURES_KEY] = failures
        if failures >= MAX_FAILED_ATTEMPTS:
            st.session_state[LOCKED_UNTIL_KEY] = time.monotonic() + LOCKOUT_SECONDS
            st.session_state[FAILURES_KEY] = 0
            st.rerun()
        st.error("Invalid password.")
    st.stop()


def require_auth(st: Any, surface: str = "Analyst dashboard",
                 config: AuthConfig | None = None,
                 address: str | None = None) -> str:
    """Render the gate and stop the script unless access is allowed.

    Returns ``"password"`` or ``"anonymous"``. Every caller must invoke this
    before it reads a store, a status file or a capture.
    """
    cfg = load_config() if config is None else config
    bind = _server_address(st) if address is None else address

    if cfg.error:
        _locked(st, f"Dashboard authentication is misconfigured: {cfg.error}",
                "The dashboard stays locked until the configuration is fixed.")

    if cfg.password is None:
        if cfg.allow_anonymous:
            if anonymous_permitted(cfg, bind):
                st.sidebar.warning(
                    "Authentication is off for this local demo. Do not expose "
                    "this listener.")
                return "anonymous"
            _locked(st,
                    "Anonymous mode is refused because Streamlit is not "
                    f"bound to loopback (server.address={bind or 'unset'}).",
                    "Bind 127.0.0.1 for a local demo, or set a dashboard "
                    "password before serving this surface on a network.")
        _locked(st, "No dashboard password is configured.",
                "The dashboard is locked by default; it no longer renders "
                "data without a configured secret or an explicit local-demo "
                "opt-in.")

    stamp = password_stamp(cfg.password)
    if (st.session_state.get(AUTH_KEY) is True
            and st.session_state.get(AUTH_STAMP_KEY) == stamp):
        _sidebar(st, surface)
        return "password"
    if st.session_state.get(AUTH_KEY) is True:
        _clear_auth(st)

    _login(st, cfg, surface)
    return "password"
