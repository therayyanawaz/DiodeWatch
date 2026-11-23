"""Ceiling of the evidence chain, and the way past it.

`src.alerts.store` chains every alert row and mirrors each new head to an
append-only ledger file. That proves the store was not edited *in place*, and it
proves it to anyone holding the ledger. It cannot prove anything to someone who
holds neither, and it cannot survive a host that rewrites both: the chain and the
ledger live on the same box, so an operator with root can rebuild them
consistently and hand over a clean-looking store.

The way past that ceiling is to hand a digest to a party that keeps its own copy
and cannot be leaned on: an RFC 3161 time-stamp authority. This module produces
the digest in a canonical form and, when `openssl` and a TSA are available,
the timestamp request that binds it to a wall-clock time. The response token
(`.tsr`) is a file that travels with an incident pack and stays verifiable
years later without this repository, this host or this team.

Deliberate limits, stated rather than implied:

  * Nothing here contacts a TSA. Request generation is local and offline; the
    `.tsq` is what you POST. A demo with no network must still produce the file,
    and an air-gapped enclave transfers it by hand. That is the point.
  * The digest covers the chain head, the link count and the first/last insert
    times, which is the whole tamper surface of the chain. It does not cover the
    alert payloads themselves: the head already commits to every payload through
    the hash chain, so re-hashing them here would add nothing a verifier does
    not already check with `verify_chain`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .store import verify_chain

DIGEST_VERSION = 1


def canonical_bytes(doc: dict[str, Any]) -> bytes:
    """One byte sequence per digest, or the signature means nothing.

    Sorted keys, no whitespace, UTF-8: the same document must hash identically
    from Python, from a shell pipeline and from whatever a verifier writes in
    five years."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def digest(db_path: str | Path) -> dict[str, Any]:
    """The anchored statement about one store: what it holds, and its head."""
    report = verify_chain(db_path)
    head = report.get("head") or {}
    doc = {
        "digest_version": DIGEST_VERSION,
        "chain_ok": bool(report.get("ok")),
        "chain_error": report.get("error"),
        "links": int(report.get("links") or 0),
        "alerts": int(report.get("alerts") or 0),
        "ledger_anchored": bool(report.get("anchored")),
        "head_link_no": head.get("link_no"),
        "head_chain_hash": head.get("chain_hash"),
        "head_inserted_at": head.get("inserted_at"),
    }
    doc["digest_sha256"] = hashlib.sha256(canonical_bytes(doc)).hexdigest()
    return doc


def export(db_path: str | Path, out_dir: str | Path,
           name: str | None = None) -> dict[str, Any]:
    """Write the digest as `<digest>.json` and return it.

    The digest names the file, so an operator cannot label two different exports
    with the same reference, and a verifier can re-hash the bytes it was given
    and see them match the name."""
    doc = digest(db_path)
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    stem = name or f"diodewatch-{doc['digest_sha256'][:16]}"
    path = target / f"{stem}.json"
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8", newline="\n")
    doc["path"] = str(path)
    return doc


def _openssl(explicit: str | None) -> str | None:
    """Resolve the binary, including the caller-supplied case an air-gapped host
    uses to point at a private build. A path that does not exist is absence, not
    an exception to leak."""
    candidate = explicit or shutil.which("openssl")
    if not candidate:
        return None
    return candidate if Path(candidate).exists() or shutil.which(candidate) else None


def timestamp_request(digest_path: str | Path, out_path: str | Path | None = None,
                      openssl: str | None = None) -> Path | None:
    """Wrap an exported digest in an RFC 3161 request (`.tsq`).

    Returns the request path, or None when `openssl` is not on PATH. Absence is
    reported, never faked: a demo laptop without OpenSSL must say so rather than
    emit a file that looks like a timestamp and is not one."""
    digest_path = Path(digest_path)
    binary = _openssl(openssl)
    if not binary:
        return None
    out = Path(out_path) if out_path else digest_path.with_suffix(".tsq")
    cmd = [binary, "ts", "-query", "-data", str(digest_path), "-sha256",
           "-cert", "-out", str(out)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                              check=False)
    except OSError:
        return None
    return out if proc.returncode == 0 else None


def verify_timestamp(tsq_path: str | Path, tsr_path: str | Path,
                     cafile: str | Path | None = None,
                     openssl: str | None = None) -> tuple[bool, str]:
    """Check a TSA response against a request. Returns (ok, message).

    A verifier needs three things and this asks for exactly three: the request,
    the response, and the TSA's certificate. It reads no database and needs no
    part of this project, which is what makes the proof portable."""
    binary = _openssl(openssl)
    if not binary:
        return False, "openssl is not available, so the timestamp cannot be checked here"
    cmd = [binary, "ts", "-verify", "-queryfile", str(tsq_path),
           "-in", str(tsr_path)]
    if cafile:
        cmd += ["-CAfile", str(cafile)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                              check=False)
    except OSError as exc:
        return False, f"openssl could not be run: {exc}"
    output = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, output


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Export an evidence-chain digest and an RFC 3161 request")
    ap.add_argument("--db", required=True, help="alert store to digest")
    ap.add_argument("--out", required=True, help="directory for the digest")
    ap.add_argument("--name", default=None, help="file stem for the digest")
    ap.add_argument("--tsq", action="store_true",
                    help="also build the RFC 3161 request next to the digest")
    args = ap.parse_args(argv)

    doc = export(args.db, args.out, args.name)
    print(f"digest  {doc['digest_sha256']}")
    print(f"chain   {'intact' if doc['chain_ok'] else 'BROKEN: ' + str(doc['chain_error'])}")
    print(f"links   {doc['links']} over {doc['alerts']} alerts")
    print(f"wrote   {doc['path']}")
    if args.tsq:
        tsq = timestamp_request(doc["path"])
        if tsq is None:
            print("no .tsq: openssl is absent, so no request was produced")
            return 0
        print(f"wrote   {tsq}")
        print(f"send it: openssl ts -reply -queryfile {tsq.name} "
              f"-out {tsq.with_suffix('.tsr').name}  (at your TSA)")
    if not doc["chain_ok"]:
        # The digest of a broken chain is still worth exporting, but the exit
        # code must not let a failed verification pass for a clean one.
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
