# Security policy

## Supported versions

| Version | Supported |
|---|---|
| main branch | active development |

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Use GitHub's **private vulnerability reporting** (Security tab →
Report a vulnerability) on this repository, or contact the repository
owner directly. Include a reproduction path and affected component
(`src/ingest`, `src/detectors`, `src/alerts`, `apps/mission_control/server.py`, …).

## Scope and expectations

- Acknowledgement within **7 days**; a fix or mitigation plan within
  **30 days** for confirmed issues.
- Please include: affected component, reproduction steps, observed vs
  expected behaviour, and (if applicable) a minimal dataset or PCAP
  that triggers the issue.

## Deployment hardening notes

DiodeWatch ships as an evaluation-ready analytics enclave component.
When deploying:

- Bind the wall to loopback (`--host 127.0.0.1`, the default) and terminate
  TLS at the shipped nginx template (`docs/deployment.md`). The wall itself
  has **no built-in TLS or browser authentication**. The template adds TLS and
  a single-worker unit, not authentication: keep its listener on a trusted
  management network until that gap is closed. Its optional bearer token
  protects API and WebSocket clients, but the shipped browser does not send
  it. The wall also enforces a Host allowlist, a 1 MiB body cap and
  process-global API rate limits; these are transport controls, not identity,
  and a token holder can still spend the shared bucket.
- The Streamlit dashboard and diode panel are a separate surface. The
  repository `.streamlit/config.toml` binds them to `127.0.0.1` and
  `apps/dashboard/auth.py` locks them by default. Set
  `DIODE_DASHBOARD_PASSWORD` (12+ characters) or
  `DIODE_DASHBOARD_PASSWORD_FILE` (mode 0600 on POSIX);
  `DIODE_DASHBOARD_ALLOW_ANONYMOUS=1` is a loopback-only local-demo opt-out and
  is refused on a network bind. This is one shared password, not user
  identity or RBAC, and it travels in the Streamlit WebSocket: terminate TLS
  in a reverse proxy before any remote access. See `docs/dashboard.md`.
- Run the dashboard as an unprivileged user; grant nftables/iptables
  rights only to the enforcement profile that needs them (`docs/diode.md`).
- On classified/air-gapped hosts, disable Streamlit usage telemetry
  (README → Air-gapped deployment).
