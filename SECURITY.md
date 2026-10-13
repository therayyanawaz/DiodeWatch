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

- Bind the web mission-control UI to loopback (`--host 127.0.0.1`, the
  default) or place it behind an authenticating reverse proxy — the UI
  itself currently has **no built-in authentication or TLS**, and this is
  documented rather than hidden.
- Run the dashboard as an unprivileged user; grant nftables/iptables
  rights only to the enforcement profile that needs them (`docs/diode.md`).
- On classified/air-gapped hosts, disable Streamlit usage telemetry
  (README → Air-gapped deployment).
