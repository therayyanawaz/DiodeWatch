#!/usr/bin/env python3
"""WAF replay harness for the nginx+ModSecurity grading setup.

Modes
-----
--replay         send corpus traffic to --nginx-url and record outcomes
--dry-run        validate corpus and print the plan; sends zero traffic
--self-test      spin an ephemeral permissive stub server, replay through
                 the real request path, and assert the metric math
--schema         print the corpus record schema as JSON
--generate-corpus PATH   write the built-in 20-case smoke corpus

Exit codes: 0 ok, 1 usage/corpus error, 2 degraded (server unreachable or
all requests errored; summary still written), 3 self-test assertion failure.

Stdlib only: argparse, csv, json, urllib.request, http.server,
concurrent.futures. Blocked = status in {400, 403, 405, 413, 414}.
Transport errors count AGAINST the record's expectation (an unsent benign
request is an error, not a false positive), hence exit 2 on a dead server.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

# Statuses that mean "the edge refused the request, it never reached the
# app". 403/405/414 are what the ruleset's deny actions declare; 400 and 413
# are edge rejections from nginx itself — a malformed/over-long URI (400) and
# an oversized request body (413) are refused before ModSecurity's rule can
# answer 403. Measured against a live nginx+ModSecurity stack, the traversal
# case came back 400 in BOTH the armed and rules-off runs, i.e. nginx rejects
# it regardless; counting 400 as "allowed" would have reported that stopped
# attack as a miss. A stricter "who blocked it" comparison needs an armed vs
# rules-off pair of runs, not a wider status set.
BLOCK_STATUSES = {400, 403, 405, 413, 414}

SCHEMA = {
    "id": "str (optional; generated from line number when absent)",
    "category": "str (required)",
    "method": "str (default GET)",
    "uri": "str (path[/query]) — or 'url' for an absolute URL",
    "url": "str (absolute; alternative to uri)",
    "headers": "obj (optional)",
    "body": "str (optional; sent as-is)",
    "expect": "'blocked' | 'allowed' | 'any'",
}

BUILTIN_CORPUS = [
    {"id": "atk-sqli-union", "category": "sqli", "method": "GET",
     "uri": "/search?q=1%20UNION%20SELECT%20username%2C%20password%20FROM%20users",
     "expect": "blocked"},
    {"id": "atk-sqli-or", "category": "sqli", "method": "POST", "uri": "/login",
     "headers": {"Content-Type": "application/x-www-form-urlencoded"},
     "body": "user=admin'--&pass=x", "expect": "blocked"},
    {"id": "atk-sqli-stack", "category": "sqli", "method": "POST", "uri": "/api/v1/item",
     "headers": {"Content-Type": "application/json"},
     "body": "{\"name\": \"x'; DROP TABLE users; --\"}", "expect": "blocked"},
    {"id": "atk-traversal-uri", "category": "traversal", "method": "GET",
     "uri": "/static/..%2f..%2f..%2fetc/passwd", "expect": "blocked"},
    {"id": "atk-dotfile", "category": "sensitive-file", "method": "GET",
     "uri": "/.env", "expect": "blocked"},
    {"id": "atk-gitconfig", "category": "sensitive-file", "method": "GET",
     "uri": "/.git/config", "expect": "blocked"},
    {"id": "atk-backup", "category": "sensitive-file", "method": "GET",
     "uri": "/db.sql.bak", "expect": "blocked"},
    {"id": "atk-trace", "category": "protocol", "method": "TRACE", "uri": "/",
     "expect": "blocked"},
    {"id": "atk-long-uri", "category": "protocol", "method": "GET",
     "uri": "/?pad=" + "A" * 2100, "expect": "blocked"},
    {"id": "atk-nullbyte", "category": "injection", "method": "GET",
     "uri": "/download?file=report.pdf%00.php", "expect": "blocked"},
    {"id": "atk-xss-tag", "category": "xss", "method": "POST", "uri": "/comment",
     "headers": {"Content-Type": "application/json"},
     "body": "{\"text\": \"<script>alert(document.cookie)</script>\"}",
     "expect": "blocked"},
    {"id": "atk-cmd-chain", "category": "cmdi", "method": "POST", "uri": "/ping",
     "headers": {"Content-Type": "application/x-www-form-urlencoded"},
     "body": "host=127.0.0.1;cat+/etc/passwd", "expect": "blocked"},
    {"id": "ben-home", "category": "benign", "method": "GET", "uri": "/",
     "expect": "allowed"},
    {"id": "ben-api-filter", "category": "benign", "method": "GET",
     "uri": "/api/v1/items?category=tools&limit=20", "expect": "allowed"},
    {"id": "ben-login-json", "category": "benign", "method": "POST", "uri": "/login",
     "headers": {"Content-Type": "application/json"},
     "body": "{\"user\": \"o'brien\", \"pass\": \"correct horse\"}",
     "expect": "allowed"},
    {"id": "ben-slug", "category": "benign", "method": "GET",
     "uri": "/blog/2026/09/how-to-write-clean-sql", "expect": "allowed"},
    {"id": "ben-static", "category": "benign", "method": "GET",
     "uri": "/assets/app.min.js?v=9", "expect": "allowed"},
    {"id": "ben-prose-onclick", "category": "benign", "method": "GET",
     "uri": "/docs/events", "expect": "allowed"},
    {"id": "ben-apostrophe", "category": "benign", "method": "GET",
     "uri": "/search?q=d%27artagnan", "expect": "allowed"},
    {"id": "ben-form-body", "category": "benign", "method": "POST", "uri": "/contact",
     "headers": {"Content-Type": "application/x-www-form-urlencoded"},
     "body": "name=O%27Brien&msg=Please+call+back", "expect": "allowed"},
]


# ---------------------------------------------------------------- corpus --

class CorpusError(ValueError):
    pass


def _require(rec: dict, idx: int) -> dict:
    if not isinstance(rec, dict):
        raise CorpusError(f"record {idx}: expected an object, got {type(rec).__name__}")
    if not rec.get("category"):
        raise CorpusError(f"record {idx} ({rec.get('id', '?')}): 'category' is required")
    expect = rec.get("expect", "any")
    if expect not in ("blocked", "allowed", "any"):
        raise CorpusError(f"record {idx} ({rec.get('id', '?')}): expect must be "
                          f"blocked/allowed/any, got {expect!r}")
    if not rec.get("uri") and not rec.get("url"):
        raise CorpusError(f"record {idx} ({rec.get('id', '?')}): needs 'uri' or 'url'")
    return rec


def load_corpus_jsonl(path: str) -> list[dict]:
    records = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CorpusError(f"line {n}: invalid JSON: {exc}") from exc
            _require(rec, n)
            rec.setdefault("id", f"row-{n}")
            records.append(rec)
    if not records:
        raise CorpusError(f"{path}: no usable records")
    return records


def load_corpus_csv(path: str) -> list[dict]:
    # Flexible header aliases so hand-made CSVs load without fuss.
    aliases = {"id": "id", "case": "id", "category": "category", "class": "category",
               "method": "method", "verb": "method", "uri": "uri", "url": "url",
               "path": "uri", "headers": "headers", "body": "body",
               "expect": "expect", "expected": "expect", "verdict": "expect"}
    records = []
    with open(path, encoding="utf-8", newline="") as fh:
        for n, row in enumerate(csv.DictReader(fh), 1):
            rec: dict = {}
            for k, v in row.items():
                key = aliases.get((k or "").strip().lower())
                if key and v not in (None, ""):
                    rec[key] = v
            _require(rec, n)
            rec.setdefault("id", f"row-{n}")
            records.append(rec)
    if not records:
        raise CorpusError(f"{path}: no usable records")
    return records


WRAPPER_KEYS = ("cases", "records", "data", "items")


def _records_from_list(data: list, source: str) -> list[dict]:
    records = []
    for n, rec in enumerate(data, 1):
        _require(rec, n)
        rec.setdefault("id", f"row-{n}")
        records.append(rec)
    if not records:
        raise CorpusError(f"{source}: no usable records")
    return records


def _load_json_document(path: str, text: str) -> list[dict] | None:
    """Return records when ``text`` is a single JSON document, else ``None``.

    ``None`` means "not one JSON document", which for a '{'-leading file
    means it is JSONL (one object per line).
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(data, list):
        return _records_from_list(data, path)
    if isinstance(data, dict):
        for key in WRAPPER_KEYS:
            if isinstance(data.get(key), list):
                return _records_from_list(data[key], path)
        # A lone object is a single record, so it gets field validation —
        # a wrapper typo surfaces as a schema error, not a confusing one.
        _require(data, 1)
        data.setdefault("id", "row-1")
        return [data]
    raise CorpusError(f"{path}: corpus JSON must be an array, object, or JSONL")


def load_corpus(path: str) -> list[dict]:
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise CorpusError(f"cannot read {path}: {exc}") from exc

    # JSONL and single JSON documents both lead with '[' or '{', so the shape
    # decides before CSV is considered. Routing on comma density would swallow
    # JSONL, whose objects are full of commas (4 commas vs 1 brace per line).
    stripped = text.lstrip()
    if stripped.startswith(("[", "{")):
        records = _load_json_document(path, text)
        return records if records is not None else load_corpus_jsonl(path)

    first = next((line for line in text.splitlines() if line.strip()), "")
    if "," in first:
        return load_corpus_csv(path)
    return load_corpus_jsonl(path)


def generate_builtin(path: str) -> int:
    # newline="\n" disables platform newline translation, so a corpus written
    # on Windows is byte-identical to one written at the Linux grading site.
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(json.dumps(rec, ensure_ascii=False) + "\n"
                      for rec in BUILTIN_CORPUS)
    return len(BUILTIN_CORPUS)


# ---------------------------------------------------------------- replay --

def send_one(base_url: str, rec: dict, timeout: float) -> dict:
    url = rec.get("url")
    if not url:
        base = base_url.rstrip("/")
        uri = rec.get("uri", "/")
        url = base + (uri if uri.startswith("/") else "/" + uri)
    method = rec.get("method", "GET")
    headers = dict(rec.get("headers") or {})
    body = rec.get("body")
    data = body.encode("utf-8") if isinstance(body, str) else None
    if data is not None and method.upper() in ("POST", "PUT", "PATCH"):
        headers.setdefault("Content-Length", str(len(data)))
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, latency = resp.status, time.monotonic() - t0
    except urllib.error.HTTPError as exc:
        status, latency = exc.code, time.monotonic() - t0  # a 403 IS an outcome
    # Broad on purpose: a transport failure is recorded against the record's
    # expectation rather than aborting the run, so it is not narrowed to a
    # specific exception tuple.
    except Exception as exc:  # noqa: BLE001
        return {"rec": rec, "ok": False, "status": None, "latency": 0.0,
                "error": f"{type(exc).__name__}: {exc}"}
    return {"rec": rec, "ok": True, "status": status, "latency": latency,
            "error": None}


def run_replay(base_url: str, records: list[dict], workers: int,
               timeout: float) -> list[dict]:
    results = [None] * len(records)  # index-preserved: deterministic order
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(send_one, base_url, rec, timeout): i
                for i, rec in enumerate(records)}
        for fut in concurrent.futures.as_completed(futs):
            results[futs[fut]] = fut.result()
    return results


def compute_metrics(results: list[dict]) -> dict:
    def blocked(r: dict) -> bool:
        return r["ok"] and r["status"] in BLOCK_STATUSES

    errored = [r for r in results if not r["ok"]]
    attack = [r for r in results if r["rec"].get("expect") == "blocked"]
    benign = [r for r in results if r["rec"].get("expect") == "allowed"]
    anycast = [r for r in results if r["rec"].get("expect") == "any"]
    attack_blocked = sum(1 for r in attack if blocked(r))
    benign_allowed = sum(1 for r in benign if r["ok"] and not blocked(r))
    benign_blocked_fp = sum(1 for r in benign if blocked(r))
    attack_expected, benign_expected = len(attack), len(benign)
    denom = attack_expected + benign_expected
    accuracy = ((attack_blocked + benign_allowed) / denom) if denom else 1.0
    fp_rate = (benign_blocked_fp / benign_expected) if benign_expected else 0.0
    fn_rate = ((attack_expected - attack_blocked) / attack_expected) if attack_expected else 0.0
    latencies = sorted(r["latency"] for r in results if r["ok"])
    lat = lambda p: (latencies[min(len(latencies) - 1, int(p * len(latencies)))]
                     if latencies else 0.0)
    by_cat: dict[str, dict] = {}
    for r in results:
        c = r["rec"].get("category", "?")
        slot = by_cat.setdefault(c, {"total": 0, "blocked": 0, "errors": 0})
        slot["total"] += 1
        slot["blocked"] += 1 if blocked(r) else 0
        slot["errors"] += 0 if r["ok"] else 1
    return {
        "mode": "replay",
        "total": len(results),
        "sent": sum(1 for r in results if r["ok"]),
        "errors": len(errored),
        "attack_expected": attack_expected,
        "attack_blocked": attack_blocked,
        "attack_missed": attack_expected - attack_blocked,
        "benign_expected": benign_expected,
        "benign_allowed": benign_allowed,
        "benign_blocked_fp": benign_blocked_fp,
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(fp_rate, 4),
        "false_negative_rate": round(fn_rate, 4),
        "latency_ms": {"p50": round(lat(0.50) * 1000, 1),
                       "p95": round(lat(0.95) * 1000, 1),
                       "max": round(max(latencies) * 1000, 1) if latencies else 0.0},
        "by_category": dict(sorted(by_cat.items())),
        "errored_records": [{"id": r["rec"].get("id"), "error": r["error"]}
                            for r in errored],
        "anycast_excluded": len(anycast),
    }


def print_table(records: list[dict], results: list[dict]) -> None:
    print(f"{'id':<18} {'category':<15} {'expect':<8} {'status':<7} verdict")
    for r in results:
        rec = r["rec"]
        if not r["ok"]:
            verdict = "ERROR"
        elif r["status"] in BLOCK_STATUSES:
            verdict = "blocked"
        else:
            verdict = "allowed"
        print(f"{rec.get('id', '?'):<18} {rec.get('category', '?'):<15} "
              f"{rec.get('expect', 'any'):<8} {r['status'] if r['ok'] else '-'!s:>7} "
              f"{verdict}")


# -------------------------------------------------------------- stub server

class _Permissive(BaseHTTPRequestHandler):
    """Never blocks: everything answers 200. Self-test baseline."""

    def _reply(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        payload = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_TRACE = _reply

    def log_message(self, *a):  # silence request logging
        pass


# -------------------------------------------------------------------- CLI --

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--corpus", help="path to JSONL/CSV corpus")
    src.add_argument("--generate-corpus", metavar="PATH",
                     help="write the built-in 20-case corpus and exit")
    src.add_argument("--schema", action="store_true",
                     help="print corpus record schema as JSON and exit")
    src.add_argument("--self-test", action="store_true",
                     help="replay against an ephemeral permissive stub and assert metric math")
    p.add_argument("--nginx-url", default="http://127.0.0.1:8080")
    p.add_argument("--mode", choices=["replay", "dry-run"], default="replay",
                   help="with --corpus: send traffic (replay) or validate only (dry-run)")
    p.add_argument("--dry-run", action="store_true",
                   help="shorthand for --mode dry-run (zero traffic)")
    p.add_argument("--replay", action="store_true",
                   help="send traffic (default mode; accepted for CLI symmetry)")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--summary", help="write JSON summary to this path")
    p.add_argument("--verbose", action="store_true", help="print per-case table")
    args = p.parse_args(argv)

    if args.schema:
        print(json.dumps(SCHEMA, indent=2))
        return 0

    if args.generate_corpus:
        n = generate_builtin(args.generate_corpus)
        print(f"wrote {n} records -> {args.generate_corpus}")
        return 0

    if args.self_test:
        server = HTTPServer(("127.0.0.1", 0), _Permissive)
        port = server.server_address[1]
        import threading
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            records = [dict(r) for r in BUILTIN_CORPUS]
            results = run_replay(f"http://127.0.0.1:{port}", records,
                                 workers=args.workers, timeout=args.timeout)
        finally:
            server.shutdown()
        metrics = compute_metrics(results)
        metrics["mode"] = "self-test"
        metrics["corpus"] = "builtin-demo"
        expected = {
            "total": 20, "sent": 20, "errors": 0,
            "attack_expected": 12, "attack_blocked": 0, "attack_missed": 12,
            "benign_expected": 8, "benign_allowed": 8, "benign_blocked_fp": 0,
            "accuracy": 0.4, "false_positive_rate": 0.0,
            "false_negative_rate": 1.0,
        }
        checks = [{"metric": k, "expected": v, "got": metrics.get(k),
                   "pass": metrics.get(k) == v}
                  for k, v in expected.items()]
        if args.summary:
            _write_summary(args.summary, {"mode": "self-test", "corpus": "builtin-demo",
                                          "checks": checks, "metrics": metrics})
        ok = all(c["pass"] for c in checks)
        print(f"SELF-TEST {'PASSED' if ok else 'FAILED'} "
              f"({sum(c['pass'] for c in checks)}/{len(checks)} metric assertions)")
        for c in checks:
            if not c["pass"]:
                print(f"  FAIL {c['metric']}: expected {c['expected']}, got {c['got']}")
        return 0 if ok else 3

    # --corpus path
    try:
        records = load_corpus(args.corpus)
    except CorpusError as exc:
        print(f"corpus error: {exc}", file=sys.stderr)
        return 1

    if args.dry_run or args.mode == "dry-run":
        n_attack = sum(1 for r in records if r["expect"] == "blocked")
        n_benign = sum(1 for r in records if r["expect"] == "allowed")
        n_any = sum(1 for r in records if r["expect"] == "any")
        print(f"dry-run: {len(records)} records planned "
              f"({n_attack} attack / {n_benign} benign / {n_any} any) - zero traffic sent")
        if args.summary:
            _write_summary(args.summary, {"mode": "dry-run", "corpus": args.corpus,
                                          "planned": len(records),
                                          "attack": n_attack, "benign": n_benign,
                                          "any": n_any})
        return 0

    results = run_replay(args.nginx_url, records, workers=args.workers,
                         timeout=args.timeout)
    metrics = compute_metrics(results)
    metrics["mode"] = "replay"
    metrics["corpus"] = args.corpus
    if args.verbose:
        print_table(records, results)
    else:
        print(f"sent {metrics['sent']}/{metrics['total']} | errors {metrics['errors']} | "
              f"attacks blocked {metrics['attack_blocked']}/{metrics['attack_expected']} | "
              f"benign FP {metrics['benign_blocked_fp']}/{metrics['benign_expected']} | "
              f"accuracy {metrics['accuracy']:.1%}")
    if args.summary:
        _write_summary(args.summary, metrics)
    if metrics["errors"] == metrics["total"]:
        print("warning: every request errored — is the server up at "
              f"{args.nginx_url}?", file=sys.stderr)
        return 2
    if metrics["errors"]:
        print(f"warning: {metrics['errors']} transport error(s) counted against "
              "their expectations", file=sys.stderr)
        return 2
    return 0


def _write_summary(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
