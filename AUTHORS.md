# Authors

DiodeWatch is built by a six-person team for **Smart India Hackathon 2026**
(problem statement: *AI-Based Detection of Cyber Threats in Unidirectional IP
Traffic*, sponsored by NTRO). Ownership of each area is enforced by
[`.github/CODEOWNERS`](.github/CODEOWNERS).

| Person | Area | Owns |
|---|---|---|
| **Dikshita Konwar** | Framework, detection core | `src/ingest/`, `src/features/`, `src/detectors/` (rule and window channels), `src/diode/`, `scripts/checks/` |
| **Md Rayyan Nawaz** | Framework, evidence and documentation | `src/alerts/`, `src/triage/`, STIX 2.1 export, incident reports, `docs/`, `README.md` |
| **Prateek Dagar** | AI / machine learning | `src/detectors/ml/`, model artifacts and pins, `scripts/experiments/`, `scripts/fetch/`, `scripts/benchmarks/`, `docs/evaluation/` |
| **Aayush** | Frontend | `apps/dashboard/`, `frontend/` (the React wall), `docs/dashboard.md` |
| **Deependra** | Backend | `apps/mission_control/` (server, routes, shipped bundles), the launchers that serve the wall |
| **kuldeep sharma** | DevOps | `setup/`, `.github/`, `waf/`, packaging, release hygiene |

## Contributing

The project is proprietary (see [`LICENSE`](LICENSE)); contributions are
accepted through pull requests under the terms described in
[`CONTRIBUTING.md`](CONTRIBUTING.md). Every change is reviewed by the owner of
the area it touches.

## Citing this work

See [`CITATION.cff`](CITATION.cff), or use the "Cite this repository" button on
the GitHub sidebar.
