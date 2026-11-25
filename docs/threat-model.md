# Threat model

DiodeWatch sits on the analysis side of a one-way link. This page states what it
is defending, what it is not, and which parts of each boundary are actually
implemented in this tree. It is written in STRIDE because that is the vocabulary a
reviewer arrives with, and it is written honestly because a threat model that
claims nothing is out of scope reads as a marketing page, and one that claims
everything reads as a lie.

## The deployment being modelled

```
 monitored network                                         analysis enclave
┌────────────────────┐   capture    ┌──────────────────┐   ┌────────────────────┐
│ sensors / taps     │ ───────────► │ diode (HW/optic) │ ─►│ ingest, detect,    │
│ (untrusted input)  │              │ one direction    │   │ store, serve       │
└────────────────────┘              └──────────────────┘   └─────────┬──────────┘
                                                                     │ read only
                                                        ┌────────────▼──────────┐
                                                        │ analyst wall (browser)│
                                                        └───────────────────────┘
```

Three trust zones. The first is untrusted by construction: everything arriving
from the monitored network is attacker-influenced, including the packet contents
and therefore every feature, name and field a detector reads. The second is the
enclave where the pipeline runs. The third is a browser an analyst is using.

## Boundary 1, monitored traffic into the pipeline

The adversary here is whoever is generating the traffic. They cannot reach the
enclave directly; the diode makes sure of that. They reach it *through* the data.

| Threat | How it lands | What this tree does | Residual risk |
|---|---|---|---|
| **Tampering** with what the pipeline sees | Crafted packets, malformed headers, truncated captures, deliberately odd encodings | Parsers are written to skip a malformed record rather than abort a run (`src/ingest/`); per-slice counts of skipped records travel with the run | A capture that is malformed in a way the parser tolerates silently changes the denominator. The run record carries the count so the change is visible |
| **Spoofing** the identity of a flow | Forged source addresses, spoofed hostnames in DNS answers | Nothing. Attribution is not a claim DiodeWatch makes: alerts name flows, never people | Every alert is a candidate about traffic, not an allegation about a person. Stated in `docs/alerts.md` |
| **Repudiation** of what was seen | "That capture never contained that" | The evidence chain commits to every alert row, and the ledger mirrors each new head off the database file (`src/alerts/store.py`) | Both live on one host; see boundary 3 |
| **Information disclosure** through the detector | Model outputs leaking capture content into logs or alerts | Alert evidence carries the matched condition, the observed value and the threshold, not the payload | A payload copied into an evidence string would travel further than the capture; reviewers should keep that rule |
| **Denial of service** by volume | A flood sized to exhaust memory or fill the disk | Windowed processing, bounded batches, one replay session per wall | A capture larger than the host can hold is an operational limit, not a defended boundary. `docs/pipeline.md` states the sizing it was tested at |
| **Elevation of privilege** through parsing | A parser bug turning capture bytes into code execution | Dependencies pinned and scanned; SBOM emitted per build | Parsing untrusted bytes is the largest real attack surface in this tree, and it is mitigated, not eliminated |

## Boundary 2, the analyst wall

The adversary here is a page in the analyst's browser, or a person on the same
network as the wall. This is the boundary most likely to be attacked in practice,
because the wall is the only listening socket.

| Threat | How it lands | What this tree does | Residual risk |
|---|---|---|---|
| **Spoofing** an authorised caller | Any local page can POST to `127.0.0.1` | A configured `DIODE_WALL_TOKEN` makes every `/api` route require a token; the startup guard refuses a non-loopback bind without one (`apps/mission_control/security.py`) | The browser client does not send a token, so a token-protected wall is driven through the API, not the UI. Stated in `docs/dashboard.md` |
| **Tampering** with the display | A framed page or an injected script driving the UI | `frame-ancestors 'none'`, `script-src 'self'`, `object-src 'none'`, `form-action 'none'`, plus `nosniff` and a same-origin opener policy on every response including errors | `style-src` allows inline style attributes because React writes them; that is a style injection surface, not a script one |
| **Information disclosure** over the live socket | `/ws/live` streams the same alerts as `/api`, and a WebSocket handshake is not an HTTP request, so response middleware never sees it | The handshake checks the same token (header or `?token=`, because a browser cannot set a header on a WebSocket) and closes with 1008 before accepting | A token-protected wall therefore has no live UI: the socket is refused, and the pages say the push channel is down rather than showing a stale feed |
| **Information disclosure** to another origin | Referrer leakage, cross-origin reads | `Referrer-Policy: no-referrer`, no CORS headers granted, no third-party origin in the CSP, and `connect-src 'self'` so the page cannot open a socket to any host that speaks WebSocket | The wall is single-tenant: every viewer sees the same feed. There is no per-analyst authorisation |
| **Denial of service** by one viewer | Starting and resetting replays in a loop | One shared session, server-side state, a token for control when configured | A token holder can still reset the wall for everyone. That is a deliberate simplification for a demo, not an oversight |
| **Elevation of privilege** | A UI bug reaching an admin route | There are no privileged routes: every route either reads or controls the replay | Not applicable beyond the above |

## Boundary 3, evidence leaving the enclave

The adversary here is whoever holds the database next, including an operator with
root on the analysis host.

| Threat | How it lands | What this tree does | Residual risk |
|---|---|---|---|
| **Tampering** with stored alerts after the fact | Editing rows, deleting rows, re-ordering | Hash chain over every alert row; `verify_chain` names the first break; the ledger mirrors each head to an append-only file (`src/alerts/store.py`) | Chain and ledger live on the same host: root can rebuild both consistently. The chain proves in-place edits, not a wholesale rewrite |
| **Repudiation** of the chain's head at a point in time | "That head never existed then" | `src/alerts/attest.py` exports a canonical digest and, with OpenSSL, an RFC 3161 request bound to a wall clock | Nothing contacts a TSA automatically, by design; a digest nobody timestamped proves only self-consistency |
| **Information disclosure** in an incident pack | A pack shared with a third party carrying more than intended | `src/alerts/pack.py` builds a bundle with a manifest hash; contents are alerts and evidence, not captures | A pack is meant to leave the enclave. Treat one as a disclosure by definition and review it first |
| **Spoofing** the pack's origin | A modified bundle presented as original | Deterministic manifest hash, `--verify` re-derives it | Signature, not identity: the hash proves the bytes are the ones packaged, not who packaged them |

## Boundary 4, what gets executed

The adversary here is a compromised dependency, a compromised model artifact, or a
compromised build step.

| Threat | How it lands | What this tree does | Residual risk |
|---|---|---|---|
| **Tampering** with a dependency | A yanked or replaced release | Pinned requirement set, grouped Dependabot updates, `pip` hash checking available for a locked host build | Requirement floors are ranges, so a fresh install is not byte-identical across hosts |
| **Tampering** with a model artifact | A replaced `.joblib` | Cards record the digest of the shipped bytes and a test fails when they disagree (`docs/models/`) | `models/` is git-ignored: a locally trained artifact has no digest in the tree |
| **Tampering** with the shipped UI | An edited bundle in the tree that no source produces | CI rebuilds the wall and requires the committed bytes to match (`git diff --exit-code` in `.github/workflows/ci.yml`) | The hand-written `static/js` and `static/css` are not build output; they are reviewed as source |
| **Information disclosure** through an inventory | Not knowing what is installed | CycloneDX SBOM emitted on every build (`scripts/checks/make_sbom.py`) | The SBOM lists versions, not vulnerabilities; it is the input to a scanner, not the scanner |
| **Repudiation** of provenance | "It was built from something else" | CI is the only path that produces a green tree, and it runs the full suite plus the guards | Commits are authored by accounts, which is attribution, not proof |

## Explicitly out of scope

Named so nobody assumes coverage that does not exist:

* **Compromise of the analysis host by root.** Full control of the enclave means
  full control of the chain, the ledger and the models. Off-box timestamping is
  the only detection, and only for heads that were timestamped before the
  compromise.
* **The diode hardware itself.** A one-way link is assumed to be one-way. Nothing
  in this tree verifies the hardware.
* **Sensor placement and capture completeness.** Whether the tap saw the traffic
  is a network-engineering question; a detector cannot recover what was never
  captured.
* **Insider action inside the enclave before ingest.** A record never captured
  never reaches the chain.
* **Privacy and lawful basis.** The tooling avoids storing payloads, but the
  authority to analyse a network is the operator's, not this repository's.
* **Nation-state adversaries with supply-chain reach.** Pinning and scanning raise
  the cost; they do not defeat a compromise of the toolchain upstream.

## How to re-check this model

The claims above are executable, which is what keeps them true:

| Claim | Check |
|---|---|
| Every response carries the hardening headers | `tests/ui/test_wall_security.py` |
| A token really stops `/api` without it | `tests/ui/test_wall_security.py` |
| A token really stops the live socket too | `tests/ui/test_wall_security.py` |
| A one-way bind refuses to start unauthenticated | `tests/ui/test_wall_security.py` |
| Tampering with a stored alert is detected | `tests/alerts/test_chain_attest.py` |
| A digest moves when the store moves | `tests/alerts/test_attest_offbox.py` |
| Shipped model digests match their cards | `tests/test_model_cards.py` |
| The committed bundle matches its source | `.github/workflows/ci.yml` |
| The documents' numbers are the measured ones | `scripts/checks/check_claims.py` |
