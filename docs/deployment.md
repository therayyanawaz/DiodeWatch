# Deploying the wall

The wall is one process and one SQLite session. The shipped deployment puts
that process on loopback behind an nginx listener that terminates TLS, so a
browser reaches one HTTPS origin and the application never owns a public
socket or a certificate.

```text
browser -- 443/TCP TLS --> nginx -- 127.0.0.1:8530 HTTP --> wall (1 worker)
                                                              |
                                                              +-- /var/lib/diodewatch/live_session.db
                                                              +-- /var/lib/diodewatch/logs/
                                                              +-- /opt/diodewatch/data/alerts/ (exports)
```

This page covers the transport and process boundary. It does **not** add
authentication. The wall's optional bearer token is for API clients and the
shipped browser does not send it, so a token-protected wall is not a
browser-facing deployment. Keep the HTTPS listener on a management network
and restrict its source addresses until browser authentication is shipped. The
proxy config says the same thing at the top, so an operator who copies only
the file still sees it.

## Files

| File | Installed as | Purpose |
|---|---|---|
| [`deploy/systemd/diodewatch-wall.service`](../deploy/systemd/diodewatch-wall.service) | `/etc/systemd/system/diodewatch-wall.service` | Runs the wall as `diodewatch`, binds loopback, pins `--workers 1`, keeps state under `/var/lib/diodewatch`, and applies a systemd sandbox |
| [`deploy/nginx/diodewatch.conf`](../deploy/nginx/diodewatch.conf) | `/etc/nginx/conf.d/diodewatch.conf` | Redirects port 80 to HTTPS, terminates TLS 1.2/1.3, proxies one upstream, forwards the WebSocket upgrade, and writes a query-free access log |
| `scripts/checks/check_deployment.py` | run from the checkout | Re-checks the invariants below without starting either daemon |
| `tests/deploy/test_deploy_configs.py` | run by pytest | Unit tests for the same invariants and for the worker argument |

## Prerequisites

* Linux with systemd and nginx, Python 3.11, and a certificate for the
  name users will type. The service unit was written for a Debian/Ubuntu
  layout; the paths are explicit rather than distro-discovered.
* An offline wheelhouse or an index reachable at install time for
  `requirements.txt`. Runtime itself makes no outbound calls.
* A DNS name or `/etc/hosts` entry for the certificate. `server_name _;`
  accepts any Host header; replace it with the exact name after the first
  successful test.

## Install

Run from a checkout. The copy is deliberate: `/opt/diodewatch` is the
service's working tree, not the operator's.

```bash
getent passwd diodewatch >/dev/null || \
  sudo useradd --system --home-dir /opt/diodewatch \
    --shell /usr/sbin/nologin diodewatch
sudo install -d -o diodewatch -g diodewatch /opt/diodewatch
sudo rsync -a --exclude .git --exclude .venv --exclude __pycache__ \
  --exclude .pytest_cache --exclude frontend/node_modules \
  ./ /opt/diodewatch/
sudo python3.11 -m venv /opt/diodewatch/.venv
sudo /opt/diodewatch/.venv/bin/pip install -r /opt/diodewatch/requirements.txt
sudo install -d -o diodewatch -g diodewatch \
  /opt/diodewatch/data/alerts /opt/diodewatch/data/logs
```

The export routes write under `data/alerts/`; the unit makes that directory
writable while the rest of `/opt/diodewatch` stays read-only. The live
session and its logs live under `/var/lib/diodewatch`, so a code reinstall
does not move the evidence chain.

Install the two configuration files:

```bash
sudo install -m 0644 deploy/systemd/diodewatch-wall.service \
  /etc/systemd/system/diodewatch-wall.service
sudo install -m 0644 deploy/nginx/diodewatch.conf \
  /etc/nginx/conf.d/diodewatch.conf
sudo install -d /etc/diodewatch/tls
```

### Certificate

Use the organisation's certificate and put the leaf plus intermediates in
`fullchain.pem` and the matching private key in `privkey.pem`. The key is
read by the nginx master process, so `root:root` and mode `0600` are enough:

```bash
sudo install -m 0644 /path/to/fullchain.pem \
  /etc/diodewatch/tls/fullchain.pem
sudo install -m 0600 /path/to/privkey.pem \
  /etc/diodewatch/tls/privkey.pem
sudo chown root:root /etc/diodewatch/tls/fullchain.pem \
  /etc/diodewatch/tls/privkey.pem
```

For a lab-only self-signed certificate, generate one with a subjectAltName
that matches the URL. A browser warning is expected; do not use this
certificate for a shared deployment.

```bash
sudo openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes \
  -keyout /etc/diodewatch/tls/privkey.pem \
  -out /etc/diodewatch/tls/fullchain.pem \
  -subj "/CN=diodewatch.example" \
  -addext "subjectAltName=DNS:diodewatch.example"
sudo chmod 0600 /etc/diodewatch/tls/privkey.pem
```

Then set `server_name` in the nginx server block to that name and restart
nginx. The shipped `_` is a catch-all, not a name.

### Start

```bash
sudo systemctl daemon-reload
sudo nginx -t
sudo systemctl enable --now diodewatch-wall.service
sudo systemctl reload nginx
```

`nginx -t` is the syntax and certificate check. If it fails, nginx keeps its
previous configuration and the wall is unaffected.

The unit runs `python -m apps.mission_control.server` from `/opt/diodewatch`.
That is the only launch form that satisfies the server's package-relative
imports; invoking the file path directly fails before it binds. The shipped
launchers use the same form.

## Verify

```bash
systemctl status diodewatch-wall.service
journalctl -u diodewatch-wall.service -n 50 --no-pager
ss -ltnp 'sport = :8530'
pgrep -af 'apps.mission_control.server'
```

The listener must be `127.0.0.1:8530`, never `0.0.0.0:8530` or a public
address.
Exactly one server process should match. A second matching PID means a
second worker or a second unit, and the two would each own a private
`SessionStore`, so two browsers could see different sessions on the same
URL.

Test the public path from another host:

```bash
curl -fsS --cacert /path/to/fullchain.pem \
  https://diodewatch.example/api/health
curl -sSI --cacert /path/to/fullchain.pem \
  https://diodewatch.example/ | grep -i strict-transport-security
openssl s_client -connect diodewatch.example:443 \
  -servername diodewatch.example -CAfile /path/to/fullchain.pem \
  </dev/null 2>/dev/null | grep 'Protocol\|Cipher'
```

The health route is served by the wall through the proxy, so a 200 proves
the upstream, the certificate and the Host header together. The header
check proves HSTS is present on the HTTPS response. `s_client` should
negotiate TLS 1.2 or 1.3. A request over port 80 should return a 301 with
the HTTPS URL.

Open the wall in a browser and confirm the live feed advances. That is the
WebSocket check: nginx forwards `Upgrade` and `Connection`, and
`proxy_read_timeout` is 3600 s so an idle socket is not cut every minute.

## Why one worker

`SessionStore`, its replay task and the WebSocket subscriber set are
process-local. `--workers 2` would give each worker its own session and
its own socket set: the load balancer would send one browser's API calls
to a different session than its socket, and a reset would affect half the
view. The server therefore rejects any `--workers` value other than 1 with
argparse, and the unit passes `--workers 1` explicitly. This is a
correctness constraint, not a tuning default.

The single process still handles concurrent requests: FastAPI runs handlers
asynchronously and replay work is bounded by the store's own locks. The
commitment is one event loop and one session, not one request at a time.

## Operations

* **Logs**: `/var/lib/diodewatch/logs/mission_control.log` and
  `access.log`, JSON lines, rotated at 5 MB with five backups by default.
  `journalctl` carries startup failures and the stderr mirror.
* **nginx log**: `/var/log/nginx/diodewatch.access.log` uses a custom
  format that records `$uri`, not the query string. The wall token can ride
  `?token=` on the WebSocket, and a default combined log would put it on
  disk.
* **Restart**: `sudo systemctl restart diodewatch-wall.service`. The SQLite
  db and ledger are on disk, so the chain resumes when the process restarts.
* **Upgrade**: copy the new tree, run `pip install -r requirements.txt`, then
  restart. Do not delete `/var/lib/diodewatch`; that is the evidence, not
  cache.
* **Backups**: no scheduled maintenance loop ships in this build. Run this
  from `/opt/diodewatch`, in a timer or cron, as the service user:

  ```bash
  sudo -u diodewatch env DIODE_LIVE_DB=/var/lib/diodewatch/live_session.db \
    /opt/diodewatch/.venv/bin/python -m src.alerts.maintenance
  ```

  It snapshots into `/var/lib/diodewatch/backups/`, verifies the copy and keeps
  eight families. For a host-level copy, archive `/var/lib/diodewatch` as a
  directory, db and ledger together.
* **Reset**: stop the service. For a clean session, add a temporary drop-in
  and start once:

  ```bash
  sudo install -d /etc/systemd/system/diodewatch-wall.service.d
  printf '[Service]\nEnvironment=DIODE_LIVE_RESET=1\n' | \
    sudo tee /etc/systemd/system/diodewatch-wall.service.d/reset.conf
  sudo systemctl daemon-reload
  sudo systemctl start diodewatch-wall.service
  ```

  Remove `reset.conf` and run `daemon-reload` again, otherwise every start
  archives the previous session. The store archives the db and ledger as a
  pair rather than silently truncating; do not remove the state directory
  unless that archive is no longer wanted.

## Limits

* TLS terminates at nginx. The application still speaks plain HTTP on
  loopback, and `docs/status.md` is the authority on which hardening items
  are shipped.
* The proxy does not authenticate. HTTP Basic was not added here because
  the browser WebSocket handshake does not reliably carry cached Basic
  credentials, and a live feed that fails after login is worse than an
  explicit network boundary.
* No rate limit, request-size policy for the application, `TrustedHost`,
  RBAC or multi-tenancy. This is one analyst, one host, one wall.
* No high availability. One systemd unit, one SQLite writer, one process.
  A restart is a short interruption, not a failover.
* The systemd sandbox is a baseline, not a proof. `ProtectSystem=strict`,
  `NoNewPrivileges`, an empty capability set and a private tmp are enabled;
  system-call filtering is deliberately absent because the ML runtime loads
  native libraries and was not exercised under a filter.

## Acceptance

`python scripts/checks/check_deployment.py` re-reads the two files and fails
if the loopback bind, `--workers 1`, TLS certificate paths, protocol floor,
single upstream, WebSocket upgrade or query-free log format drift. It does
not start nginx or systemd, so it is a configuration guard rather than a
live proof. `nginx -t` is the live syntax check, and the curl checks above
are the live transport proof.

On 2026-11-28 the guard passed. nginx 1.28.3 accepted a staged copy of the
site with `nginx -t` (fixed `/etc/diodewatch` paths rewritten to a temporary
directory) and completed a TLS 1.3 handshake; the port-80 response was a 301
with the version banner suppressed. A port-80 request carrying `?token=...`
logged only `$uri`; the canary token did not appear in the access log. The wall
entry point was started with `--workers 1` and answered
`/api/health`. `systemd-analyze verify` accepted the unit against staged
paths. No systemd unit was started, and proxy-to-app, certificate rotation
and reboot behavior remain host checks.
