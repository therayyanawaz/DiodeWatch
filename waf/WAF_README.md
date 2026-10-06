# WAF grading harness (DiodeWatch)

A self-contained ModSecurity v3 ruleset plus a stdlib-only replay harness that
measures it. No Core Rule Set dependency: the grader loads `modsecurity.conf`
by itself.

## Files

| File | Role |
| --- | --- |
| `modsecurity.conf` | Standalone ruleset, 16 rules, IDs `100100`-`100270`. |
| `cases.jsonl` | The 20-case grading corpus (12 attack / 8 benign). Canonical. |
| `smoke.jsonl` | The same corpus as committed by `--generate-corpus`. Kept byte-identical to `cases.jsonl` by test. |
| `waf_replay.py` | Replay harness: replays a corpus against nginx and reports accuracy / FP / FN. |
| `selftest.json` | Committed `--self-test` output (12/12 metric assertions). Contains measured latencies, so it is a sample rather than a byte-comparable golden file. |
| `container/` | nginx configs for the containerised engine, see "Running the containerised stack". |
| `replay-armed.json` / `replay-baseline.json` | Measured live-engine results: ruleset armed vs `SecRuleEngine Off`. |

## Wiring into nginx

```nginx
load_module modules/ngx_http_modsecurity_module.so;   # nginx.conf main context

http {
    modsecurity on;
    modsecurity_rules_file waf/modsecurity.conf;
    server { listen 8080; ... }
}
```

The ruleset is standalone, it declares every directive it needs and uses no
`SecInclude` / `SecRemoteRules`. Adjust `SecDataDir` / `SecTmpDir` /
`SecDebugLog` if the grading host does not have `/workspace`; the container
stack below creates those paths at startup instead of editing the ruleset.

Blocking statuses are `403` (attack), `405` (TRACE) and `414` (over-long URI)
(the statuses the rules' `deny` actions declare) plus `400` (malformed URI)
and `413` (oversized body), which nginx returns at the edge before
ModSecurity's rule can answer `403`. Counting those as "allowed" would report
stopped attacks as misses.

## Running the containerised stack

A permissive app tier that never returns 403/405/414, with the WAF in front,
lets any "blocked" verdict be attributed to the WAF rather than the app.

```bash
docker network create wafnet
docker run -d --name waf-backend --network wafnet \
    python:3.12-alpine python -m http.server 8000 --bind 0.0.0.0

docker run -d --name waf-armed --network wafnet -p 8080:80 \
    --health-cmd "curl -sf http://localhost/ >/dev/null || exit 1" \
    -v "$(pwd)/waf/modsecurity.conf:/etc/modsecurity.d/setup.conf:ro" \
    -v "$(pwd)/waf/container/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$(pwd)/waf/container/site.conf:/etc/nginx/conf.d/default.conf:ro" \
    --entrypoint sh owasp/modsecurity:nginx-alpine \
    -c 'mkdir -p /workspace/modsec-data /workspace/modsec-tmp; \
        touch /workspace/modsec-debug.log; chown -R nginx:nginx /workspace; \
        exec nginx -g "daemon off;"'

python waf/waf_replay.py --replay --corpus waf/cases.jsonl \
       --nginx-url http://127.0.0.1:8080 --summary waf/replay-armed.json
```

Only `waf/modsecurity.conf` is loaded, no Core Rule Set and none of the
image's shipped config, so a block is attributable to the standalone ruleset.
The image's entrypoint scripts are bypassed (`--entrypoint sh`) because they
would otherwise render their own config over the mounted files; the inline
`-c` creates the `/workspace` paths the ruleset names. The explicit
`--health-cmd` replaces the image's own check, which probes HTTPS on
`$SSL_PORT` and reports `unhealthy` for a plain-HTTP proxy.

For attribution, run the same stack with the rules disarmed, the delta is
what the ruleset contributes:

```bash
sed 's/^SecRuleEngine On$/SecRuleEngine Off/' waf/modsecurity.conf > /tmp/waf-baseline.conf
docker run -d --name waf-baseline --network wafnet -p 8081:80 \
    -v /tmp/waf-baseline.conf:/etc/modsecurity.d/setup.conf:ro \
    ... # same mounts/entrypoint as waf-armed, on port 8081
```

## Running the harness

```bash
python waf/waf_replay.py --self-test                      # assert the metric math
python waf/waf_replay.py --dry-run --corpus waf/cases.jsonl   # plan, zero traffic
python waf/waf_replay.py --replay  --corpus waf/cases.jsonl \
       --nginx-url http://127.0.0.1:8080 --summary results/waf.json --verbose
python waf/waf_replay.py --schema                         # corpus record schema
python waf/waf_replay.py --generate-corpus waf/cases.jsonl    # rewrite builtin corpus
```

Exit codes: `0` ok · `1` usage/corpus error · `2` degraded (server
unreachable, or any transport error) · `3` self-test assertion failure.

Corpus input may be JSONL, a JSON array, a `{"cases": [...]}` wrapper, or CSV
(header aliases: `case`/`class`/`path`/`verdict`). A lone JSON object is read
as a single record.

## Rules

| ID | Phase | Status | Severity | Target(s) | Detects |
| --- | --- | --- | --- | --- | --- |
| 100100 | 1 | 403 | CRITICAL | `REQUEST_URI` | SQL injection in URI (SQL-shaped keyword combos) |
| 100110 | 1 | 403 | CRITICAL | `REQUEST_URI`,`REQUEST_FILENAME` | Path traversal / LFI (`..`, `/etc`, `c:\`) |
| 100120 | 1 | 403 | CRITICAL | `REQUEST_FILENAME` | VCS/config dotfiles (`.env`, `.git`) |
| 100121 | 1 | 403 | CRITICAL | `REQUEST_FILENAME` | App config/state files (`wp-config.php`, `server-status`) |
| 100122 | 1 | 403 | WARNING | `REQUEST_FILENAME` | Backup/temp extensions (`.bak`, `.sql`, `~`) |
| 100130 | 1 | 405 | WARNING | `REQUEST_METHOD` | HTTP TRACE |
| 100140 | 1 | 414 | WARNING | `REQUEST_URI` | URI longer than 2048 chars |
| 100150 | 1 | 403 | CRITICAL | `REQUEST_URI`,`REQUEST_FILENAME` | Null-byte injection |
| 100200 | 2 | 403 | CRITICAL | `ARGS`,`ARGS_NAMES`,`REQUEST_BODY` | SQL injection in args/body (incl. `'--` truncation) |
| 100210 | 2 | 403 | CRITICAL | `ARGS`,`ARGS_NAMES`,`REQUEST_BODY`,`REQUEST_URI` | XSS tags, `javascript:`, event handlers, DOM sinks |
| 100220 | 2 | 403 | CRITICAL | `ARGS`,`ARGS_NAMES`,`REQUEST_BODY` | OS command injection / chained shell commands |
| 100230 | 2 | 403 | CRITICAL | `ARGS`,`ARGS_NAMES` | Path traversal inside parameters |
| 100240 | 2 | 403 | CRITICAL | `ARGS` | SSRF probes (loopback, link-local, `file://`) |
| 100250 | 2 | 403 | WARNING | `ARGS` | Sensitive file names in parameters |
| 100260 | 1 | 403 | WARNING | `REQUEST_HEADERS:User-Agent` | Known scanners (`sqlmap`, `nikto`, …) |
| 100270 | 1 | 403 | CRITICAL | `REQUEST_HEADERS:Cookie` | Script/command payload in Cookie |

Design rule: match on SQL-shaped grammar rather than a lone apostrophe, so
legitimate input such as `d'artagnan` or `O'Brien` is never blocked.

## Expected verdicts

The corpus is the expectation table for a live run. "Firing rules" is what the
Python shadow validator (§ below) predicts.

| Case | Category | Expect | Firing rule(s) |
| --- | --- | --- | --- |
| `atk-sqli-union` | sqli | blocked | 100100, 100200 |
| `atk-sqli-or` | sqli | blocked | 100200 |
| `atk-sqli-stack` | sqli | blocked | 100200, 100220 |
| `atk-traversal-uri` | traversal | blocked | 100110 |
| `atk-dotfile` | sensitive-file | blocked | 100120 |
| `atk-gitconfig` | sensitive-file | blocked | 100120 |
| `atk-backup` | sensitive-file | blocked | 100122 |
| `atk-trace` | protocol | blocked | 100130 |
| `atk-long-uri` | protocol | blocked | 100140 |
| `atk-nullbyte` | injection | blocked | 100150 |
| `atk-xss-tag` | xss | blocked | 100210 |
| `atk-cmd-chain` | cmdi | blocked | 100220, 100230, 100240 |
| `ben-home` … `ben-form-body` (8 cases) | benign | allowed | none |

A live run should report `12/12` attacks blocked and `0/8` benign false
positives, i.e. accuracy `1.0`.

## Measured against a live engine

Run against nginx 1.22 + ModSecurity v3 (connector 1.0.3) in
`owasp/modsecurity:nginx-alpine`, replaying `cases.jsonl` (ModSecurity
`SecRuleEngine On`, and again with it `Off` for attribution):

| Metric | Armed | Rules off |
| --- | --- | --- |
| Attacks blocked | **12/12** | 2/12 |
| Benign false positives | **0/8** | 0/8 |
| Accuracy | **1.0** | 0.5 |

Attribution (armed minus baseline): **10** of the 12 stops are the ruleset's
own 403/414 responses. The other **2** are nginx rejecting on its own,
identically in both runs, `atk-traversal-uri` with `400` (nginx refuses a
URI that normalises above the root, so rule 100110's `403` is never reached)
and `atk-trace` with `405` (nginx does not proxy TRACE, so rule 100130 is not
what stops it). Measured p50/p95 latency was 16/47 ms.

Two things this exposed that the shadow validator cannot see:

- Rule 100130 and the traversal branch of 100110 are effectively dead in this
  stack, nginx answers first. They still hold for other front ends.
- The ruleset sets no `SecAuditEngine`/`SecAuditLog`, so there is no audit
  trail naming which rule fired; attribution had to come from the armed vs
  rules-off comparison. Enable audit logging if per-rule evidence is needed.

## What the test suite verifies

`tests/test_waf_ruleset.py` machine-checks the ruleset structurally (every
`SecRule` parses, IDs unique and monotonic, `phase:`/`deny`/`status:` on every
rule, every regex compiles, no unescaped interior double quotes, required
directives present, engine `On`) and then runs a Python **shadow validator**:
the corpus is pushed through the same regexes and each case's expected verdict
must match.

The shadow validator models the **match layer only**, it maps ModSecurity
variables onto corpus fields (`REQUEST_URI`→uri, `REQUEST_METHOD`→method,
`ARGS`/`REQUEST_BODY`→query+body, `REQUEST_HEADERS:X`→headers) and does not
reproduce every engine transformation or multipart/argument parsing nuance. A
mismatch means the ruleset or corpus drifted. Even so, all 20 cases are
modelled (nothing is skipped) so corpus drift such as a placeholder long URI
fails the suite rather than silently costing a false negative in a live run.

`tests/test_waf_harness.py` exercises the documented CLI end-to-end as a
subprocess: `--help`, `--schema`, `--generate-corpus`, `--dry-run`,
`--self-test`, the degraded exit-2 path, malformed/empty corpora, every
supported corpus format, and the invariant that `cases.jsonl` / `smoke.jsonl`
stay byte-identical to `--generate-corpus` output (LF-only).
