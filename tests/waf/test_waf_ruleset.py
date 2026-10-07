"""Structural audit + shadow validation for the standalone WAF ruleset.

Machine-checks what the sandbox report promised for ``waf/modsecurity.conf``:

1. Every SecRule parses: target, @rx operator, action string.
2. Rule IDs are unique and strictly monotonic.
3. Every rule declares ``phase:``, ``deny``, and ``status:``.
4. Every @rx regex compiles under Python's ``re`` (the PCRE-compatible
   subset actually used: ``\\x00`` and inline ``(?i)`` both work).
5. No unescaped interior double-quotes inside rule strings.
6. Required engine directives are present and SecRuleEngine is On.

The shadow validator (§5.3 of the report) runs the corpus through the same
regexes in Python and asserts every case's expected verdict. It cannot
replace a live ModSecurity engine (transformations and target extraction
differ), so it validates the *match layer only*: verdicts must agree with
expectations when the rules are applied to the corpus fields the rules
target. A mismatch here means the ruleset or corpus drifted and the
live-replay expectation table in waf/WAF_README.md is stale.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

WAF_DIR = Path(__file__).resolve().parents[2] / "waf"
RULES_PATH = WAF_DIR / "modsecurity.conf"
CORPUS_PATH = WAF_DIR / "cases.jsonl"

RULE_RE = re.compile(
    r'^SecRule\s+(?P<targets>\S+)\s+"(?P<op>(?:[^"\\]|\\.)*)"\s+'
    r'"(?P<actions>(?:[^"\\]|\\.)*)"\s*$'
)

# ---------------------------------------------------------------------------
# Ruleset parsing
# ---------------------------------------------------------------------------


def load_rules_text() -> str:
    assert RULES_PATH.exists(), f"{RULES_PATH} missing"
    return RULES_PATH.read_text(encoding="utf-8")


def parse_rules(text: str) -> list[dict]:
    """Parse SecRule directives, respecting line continuations."""
    # Join continuation lines (trailing backslash) into single logical lines.
    joined = re.sub(r"\\\n\s*", " ", text)
    rules = []
    for lineno, line in enumerate(joined.splitlines(), 1):
        line = line.strip()
        if not line.startswith("SecRule "):
            continue
        m = RULE_RE.match(line)
        if not m:
            pytest.fail(f"line {lineno}: unparseable SecRule: {line[:100]}...")
        actions = m.group("actions")
        # Unescaped interior double-quote check (report §5.1). ModSecurity
        # action strings quote parameter values with '...' so a bare " inside
        # is always a syntax error.
        assert '"' not in actions, (
            f"line {lineno}: unescaped interior double-quote in actions"
        )
        op = m.group("op")
        # ModSecurity: a bare operator string is an implicit @rx.
        if op.startswith("@rx "):
            pattern = op[len("@rx "):]
        else:
            pattern = op
        rules.append({
            "lineno": lineno,
            "targets": m.group("targets"),
            "pattern": pattern,
            "actions": actions,
        })
    return rules


def rule_id(actions: str) -> int:
    m = re.search(r"id:(\d+)", actions)
    assert m, f"rule without id: {actions[:80]}"
    return int(m.group(1))


# ---------------------------------------------------------------------------
# Structural audit (report §5.1)
# ---------------------------------------------------------------------------


def test_ruleset_has_16_rules():
    rules = parse_rules(load_rules_text())
    assert len(rules) == 16


def test_rule_ids_unique_and_monotonic():
    ids = [rule_id(r["actions"]) for r in parse_rules(load_rules_text())]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    assert ids == sorted(ids), "rule ids not strictly monotonic"
    assert ids[0] == 100100 and ids[-1] == 100270


def test_every_rule_declares_phase_deny_status():
    for r in parse_rules(load_rules_text()):
        a = r["actions"]
        assert re.search(r"\bphase:[12]\b", a), f"id {rule_id(a)}: no phase"
        assert re.search(r"\bdeny\b", a), f"id {rule_id(a)}: no deny"
        assert re.search(r"\bstatus:\d+\b", a), f"id {rule_id(a)}: no status"


@pytest.mark.parametrize("rule", parse_rules(load_rules_text()) if
                          (WAF_DIR / "modsecurity.conf").exists() else [],
                         ids=lambda r: f"id{rule_id(r['actions'])}")
def test_every_regex_compiles(rule):
    re.compile(rule["pattern"])


def test_engine_directives_present():
    text = load_rules_text()
    for directive in ("SecRuleEngine On", "SecRequestBodyAccess On",
                      "SecResponseBodyAccess Off", "SecRequestBodyLimit",
                      "SecRequestBodyLimitAction Reject", "SecArgumentsLimit",
                      "SecDataDir", "SecTmpDir"):
        assert directive in text, f"missing directive: {directive}"
    # Directive scan ignores comments (the header mentions the words).
    live = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert "SecInclude" not in live, "ruleset must be standalone (no SecInclude)"
    assert "SecRemoteRules" not in live, "ruleset must be standalone (no SecRemoteRules)"


# ---------------------------------------------------------------------------
# Python shadow validation (report §5.3 analogue)
# ---------------------------------------------------------------------------


def load_corpus() -> list[dict]:
    assert CORPUS_PATH.exists(), f"{CORPUS_PATH} missing"
    records = []
    for n, line in enumerate(CORPUS_PATH.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if line:
            records.append(json.loads(line))
    assert len(records) == 20
    return records


def corpus_counts(records):
    attack = sum(1 for r in records if r["expect"] == "blocked")
    benign = sum(1 for r in records if r["expect"] == "allowed")
    return attack, benign


def test_corpus_shape():
    records = load_corpus()
    attack, benign = corpus_counts(records)
    assert attack == 12 and benign == 8
    for r in records:
        assert r.get("category") and r.get("uri") and r.get("expect") in ("blocked", "allowed")


def test_corpus_has_no_placeholder_uris():
    """A '<...>' URI is documentation left in the corpus, not a request.

    atk-long-uri shipped as "/?pad=<2048+chars>" and could never be blocked.
    """
    for r in load_corpus():
        assert "<" not in r["uri"], (
            f"{r['id']}: uri looks like a placeholder, not a real request"
        )


def test_long_uri_case_actually_exceeds_the_limit():
    """Rule 100140 denies REQUEST_URI of 2049+ chars; the case must be that long."""
    rec = next(r for r in load_corpus() if r["id"] == "atk-long-uri")
    assert len(rec["uri"]) > 2048, f"atk-long-uri is only {len(rec['uri'])} chars"


# Rule -> (targets-in-corpus-terms, compiled regex) map for shadow validation.
# We map ModSecurity variables onto the corpus record fields the harness sends:
#   REQUEST_URI/REQUEST_FILENAME -> uri (decoded)
#   REQUEST_METHOD      -> method
#   ARGS/ARGS_NAMES/REQUEST_BODY -> uri query params + body (decoded, lowercased
#   per each rule's declared t:lowercase / t:urlDecodeUni chain)
#   REQUEST_HEADERS:X -> headers[x]


def _decode(rec: dict) -> dict:
    from urllib.parse import parse_qsl, unquote
    uri = unquote(rec.get("uri", ""))
    body = unquote(rec.get("body", "") or "")
    headers = {k.lower(): v for k, v in (rec.get("headers") or {}).items()}
    query = dict(parse_qsl(rec.get("uri", "").split("?", 1)[-1]))
    return {"uri": uri, "body": body, "headers": headers, "query": query,
            "method": rec.get("method", "GET")}


def _rule_fires(rule: dict, rec: dict) -> bool:
    """Approximate ModSecurity target extraction for the corpus fields."""
    dec = _decode(rec)
    lower = "t:lowercase" in rule["actions"]
    targets = rule["targets"].split("|")
    subjects: list[str] = []
    for t in targets:
        if t in ("REQUEST_URI", "REQUEST_FILENAME"):
            subjects.append(dec["uri"])
        elif t == "REQUEST_METHOD":
            subjects.append(dec["method"])
        elif t in ("ARGS", "ARGS_NAMES", "REQUEST_BODY"):
            subjects.extend(dec["query"].keys())
            subjects.extend(dec["query"].values())
            subjects.append(dec["body"])
        elif t.startswith("REQUEST_HEADERS:"):
            subjects.append(dec["headers"].get(t.split(":", 1)[1].lower(), ""))
    rx = re.compile(rule["pattern"], re.IGNORECASE if lower else 0)
    # Method guards: rules like TRACE only fire on the right method via the
    # pattern itself, so nothing extra needed here.
    return any(rx.search(s) for s in subjects if s)


# Every case in the corpus is modelled here. Earlier revisions excluded
# atk-long-uri ("engine-side length check") and atk-trace ("method match"),
# but rule 100140 is a plain regex on REQUEST_URI and 100130 a plain regex on
# REQUEST_METHOD once the method is mapped. Those exclusions hid a corpus bug:
# atk-long-uri shipped as the placeholder "/?pad=<2048+chars>", 18 characters,
# which no rule can block. Nothing is excluded now, so that class of drift
# fails the suite instead of silently costing a false negative in a live run.


@pytest.mark.parametrize("rec", load_corpus() if CORPUS_PATH.exists() else [],
                         ids=lambda r: r["id"])
def test_shadow_verdict_matches_expectation(rec):
    rules = parse_rules(load_rules_text())
    blocked = any(_rule_fires(r, rec) for r in rules)
    expect_blocked = rec["expect"] == "blocked"
    assert blocked == expect_blocked, (
        f"{rec['id']}: shadow verdict {'blocked' if blocked else 'allowed'} "
        f"but expected {rec['expect']}"
    )
