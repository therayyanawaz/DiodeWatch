"""Structural guard for the shipped wall deployment.

The two daemons cannot run in CI or on the Windows development host, so this
check owns what can be proved from the tree: the unit binds loopback, asks for
exactly one worker and pins the host, body and rate limits; the nginx site
terminates TLS on one loopback upstream while preserving the WebSocket
upgrade. It is a configuration guard, not a live handshake; docs/deployment.md
names the live commands.

Run:
    python scripts/checks/check_deployment.py
"""
from __future__ import annotations

import argparse
import re
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UNIT = Path("deploy/systemd/diodewatch-wall.service")
NGINX = Path("deploy/nginx/diodewatch.conf")
DOC = Path("docs/deployment.md")


def _unit_values(text: str) -> list[tuple[str, str, str]]:
    """(section, key, value) for every assignment, comments skipped."""
    out: list[tuple[str, str, str]] = []
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        out.append((section, key.strip(), value.strip()))
    return out


def _strip_nginx_comments(text: str) -> str:
    """Remove # comments without touching quoted log-format text."""
    lines = []
    for raw in text.splitlines():
        quote = None
        cut = len(raw)
        for i, ch in enumerate(raw):
            if ch in ("'", '"'):
                if quote is None:
                    quote = ch
                elif quote == ch:
                    quote = None
            elif ch == "#" and quote is None:
                cut = i
                break
        lines.append(raw[:cut])
    return "\n".join(lines)


def _values(values: list[tuple[str, str, str]], key: str) -> list[str]:
    return [value for _, k, value in values if k == key]


def check_unit(text: str) -> list[str]:
    """Return every violated invariant in the systemd unit."""
    problems: list[str] = []
    values = _unit_values(text)
    service = [(k, v) for section, k, v in values if section == "Service"]
    install = [(k, v) for section, k, v in values if section == "Install"]

    def one(key: str, expected: str) -> None:
        found = [value for k, value in service if k == key]
        if found != [expected]:
            problems.append(f"{key} must be {expected!r}, found {found!r}")

    one("User", "diodewatch")
    one("Group", "diodewatch")
    one("WorkingDirectory", "/opt/diodewatch")
    one("Restart", "on-failure")
    one("StateDirectory", "diodewatch")
    one("NoNewPrivileges", "true")
    one("PrivateTmp", "true")
    one("ProtectSystem", "strict")
    one("ProtectHome", "true")
    one("RestrictAddressFamilies", "AF_INET AF_INET6 AF_UNIX")

    if [value for k, value in service if k == "CapabilityBoundingSet"] != [""]:
        problems.append("CapabilityBoundingSet must be empty")
    if [value for k, value in service if k == "AmbientCapabilities"] != [""]:
        problems.append("AmbientCapabilities must be empty")

    execs = [value for k, value in service if k == "ExecStart"]
    if len(execs) != 1:
        problems.append(f"expected one ExecStart, found {len(execs)}")
    else:
        try:
            argv = shlex.split(execs[0])
        except ValueError as e:
            problems.append(f"ExecStart is not parseable: {e}")
            argv = []
        if not argv:
            problems.append("ExecStart is empty")
        else:
            if argv[0] != "/opt/diodewatch/.venv/bin/python":
                problems.append(
                    f"ExecStart runs {argv[0]!r}, not the service venv")
            if "-m" not in argv or "apps.mission_control.server" not in argv:
                problems.append(
                    "ExecStart must run the wall as a module from the repo root")
            if "--host" not in argv or argv[argv.index("--host") + 1:] == []:
                problems.append("ExecStart has no --host")
            elif argv[argv.index("--host") + 1] != "127.0.0.1":
                problems.append(
                    f"ExecStart binds {argv[argv.index('--host') + 1]!r}, "
                    "not loopback")
            if "--port" not in argv or argv[argv.index("--port") + 1:] == []:
                problems.append("ExecStart has no --port")
            elif argv[argv.index("--port") + 1] != "8530":
                problems.append("ExecStart does not bind 8530")
            workers = [argv[i + 1] for i, arg in enumerate(argv[:-1])
                       if arg == "--workers"]
            if workers != ["1"]:
                problems.append(f"--workers must be exactly 1, found {workers!r}")
            if argv.count("--workers") != 1:
                problems.append("--workers is absent or repeated")
            if "--reload" in argv:
                problems.append("--reload is not a service setting")

    rewrites = _values(values, "ReadWritePaths")
    if not rewrites:
        problems.append("ReadWritePaths is missing")
    else:
        paths = set(" ".join(rewrites).split())
        for required in ("/var/lib/diodewatch", "/opt/diodewatch/data/alerts"):
            if required not in paths:
                problems.append(f"ReadWritePaths misses {required}")

    db = _values(values, "Environment")
    if "DIODE_LIVE_DB=/var/lib/diodewatch/live_session.db" not in db:
        problems.append("DIODE_LIVE_DB is not pinned under /var/lib/diodewatch")
    if "DIODE_LOG_DIR=/var/lib/diodewatch/logs" not in db:
        problems.append("DIODE_LOG_DIR is not pinned under /var/lib/diodewatch")
    for expected in (
        "DIODE_ALLOWED_HOSTS=127.0.0.1,localhost,[::1]",
        "DIODE_API_RATE_LIMIT=600",
        "DIODE_WRITE_RATE_LIMIT=12",
        "DIODE_RATE_WINDOW_S=60",
        "DIODE_MAX_BODY_BYTES=1048576",
    ):
        if expected not in db:
            problems.append(f"unit does not pin {expected}")
    if [value for k, value in install if k == "WantedBy"] != ["multi-user.target"]:
        problems.append("unit is not wanted by multi-user.target")
    docs = _values(values, "Documentation")
    if not any(value.endswith("/docs/deployment.md") for value in docs):
        problems.append("Documentation does not point at docs/deployment.md")

    for forbidden in ("0.0.0.0", "--allow-unauthenticated", "--reload"):
        if forbidden in text:
            problems.append(f"unit mentions forbidden {forbidden!r}")
    return problems


def check_nginx(text: str) -> list[str]:
    """Return every violated invariant in the nginx site."""
    problems: list[str] = []
    active = _strip_nginx_comments(text)

    if active.count("listen 443 ssl;") != 1:
        problems.append("expected exactly one IPv4 443/TLS listener")
    if active.count("listen [::]:443 ssl;") != 1:
        problems.append("expected exactly one IPv6 443/TLS listener")
    if not re.search(r"return\s+301\s+https://\$host\$request_uri;", active):
        problems.append("port 80 does not redirect to https on the same host")

    for key, expected in (
        ("ssl_certificate", "/etc/diodewatch/tls/fullchain.pem"),
        ("ssl_certificate_key", "/etc/diodewatch/tls/privkey.pem"),
    ):
        found = re.findall(rf"^\s*{key}\s+(\S+);", active, re.MULTILINE)
        if found != [expected]:
            problems.append(f"{key} must be {expected!r}, found {found!r}")

    protocols = re.findall(r"^\s*ssl_protocols\s+([^;]+);", active, re.MULTILINE)
    if protocols != ["TLSv1.2 TLSv1.3"]:
        problems.append(
            f"ssl_protocols must be TLSv1.2 TLSv1.3, found {protocols!r}")
    if re.search(r"\b(SSLv[23]|TLSv1(?:\s|;|$)|TLSv1\.1)\b", active):
        problems.append("an obsolete TLS protocol is enabled")
    if "ssl_session_tickets off;" not in active:
        problems.append("TLS session tickets are not disabled")

    upstreams = re.findall(r"^\s*proxy_pass\s+([^;]+);", active, re.MULTILINE)
    if upstreams != ["http://127.0.0.1:8530"]:
        problems.append(f"expected one loopback upstream, found {upstreams!r}")
    if "$" in "".join(upstreams):
        problems.append("proxy_pass is computed from request data")
    if "proxy_http_version 1.1;" not in active:
        problems.append("WebSocket proxying needs HTTP/1.1")
    if "proxy_set_header Upgrade $http_upgrade;" not in active:
        problems.append("Upgrade header is not forwarded")
    if "proxy_set_header Connection $connection_upgrade;" not in active:
        problems.append("Connection header is not mapped")
    if not re.search(
            r"map\s+\$http_upgrade\s+\$connection_upgrade\s*\{", active):
        problems.append("the upgrade map is missing")
    if "proxy_read_timeout 3600s;" not in active:
        problems.append("proxy_read_timeout would cut an idle live socket")
    if active.count("server_tokens off;") != 2:
        problems.append("nginx version banner is not suppressed on both listeners")
    if "proxy_hide_header Server;" not in active:
        problems.append("upstream Server header is not hidden")
    if "client_max_body_size 1m;" not in active:
        problems.append("transport request-size cap is missing")
    if not re.search(
            r'add_header\s+Strict-Transport-Security\s+"max-age=31536000"\s+'
            r"always;", active):
        problems.append("HSTS is missing")

    logs = re.findall(r"^\s*log_format\s+diodewatch\s+(.+?);", active,
                      re.MULTILINE | re.DOTALL)
    if len(logs) != 1:
        problems.append(f"expected one diodewatch log_format, found {len(logs)}")
    else:
        fmt = logs[0]
        if "$uri" not in fmt:
            problems.append("access-log format does not record $uri")
        if "$request_uri" in fmt or "$args" in fmt:
            problems.append("access-log format can record the query string")
    if len(re.findall(
            r"access_log\s+/var/log/nginx/diodewatch\.access\.log\s+diodewatch;",
            active)) != 2:
        problems.append(
            "both listeners must use the query-free access log")

    return problems


def check_doc(text: str) -> list[str]:
    problems: list[str] = []
    lowered = text.lower()
    for phrase in ("--workers 1", "does **not** add", "one worker",
                   "nginx -t", "protect", "no scheduled",
                   "DIODE_ALLOWED_HOSTS", "429", "413", "1 MiB"):
        if phrase.lower() not in lowered:
            problems.append(f"deployment doc is missing {phrase!r}")
    return problems


def check(root: Path = ROOT) -> list[str]:
    problems: list[str] = []
    for rel, checker in ((UNIT, check_unit), (NGINX, check_nginx),
                         (DOC, check_doc)):
        path = root / rel
        if not path.is_file():
            problems.append(f"{rel.as_posix()} is missing")
            continue
        problems.extend(f"{rel.as_posix()}: {p}" for p in checker(
            path.read_text(encoding="utf-8")))
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    problems = check()
    if problems:
        for problem in problems:
            print(f"[FAIL] {problem}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"[ok] unit: {UNIT.as_posix()}")
        print(f"[ok] nginx: {NGINX.as_posix()}")
        print(f"[ok] doc: {DOC.as_posix()}")
        print("DEPLOYMENT CLEAN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
