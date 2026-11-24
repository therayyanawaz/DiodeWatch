"""Emit a CycloneDX 1.5 SBOM for the environment DiodeWatch actually runs on.

A judge asking "what is in this thing, and is any of it known-bad?" should get a
machine-readable answer rather than a prose list in a README that drifts. The
SBOM is generated from the installed distributions, so it describes the same
interpreter that ran the tests, not an aspiration in `requirements.txt`.

    python scripts/checks/make_sbom.py --out sbom.cdx.json

Design choices worth knowing:
  * `purl` (`pkg:pypi/name@version`) is what vulnerability scanners key on, so
    every component carries one; a CPS name/version pair alone matches nothing.
  * Components are sorted and the serial number derives from the content, so two
    runs over one environment produce byte-identical files and a diff means a
    dependency really moved.
  * No network, ever. An air-gapped enclave has to be able to produce this.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

SPEC_VERSION = "1.5"
NORMALISE = re.compile(r"[-_.]+")


def _purl_name(name: str) -> str:
    """PyPI normalises `Foo.Bar_baz` to `foo-bar-baz`; a scanner keys on the
    normalised form, so emit that rather than whatever the wheel called itself."""
    return NORMALISE.sub("-", name).lower()


def _components(skip: set[str]) -> list[dict[str, Any]]:
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for dist in metadata.distributions():
        name = dist.metadata["Name"] if dist.metadata else None
        version = dist.version
        if not name or not version:
            continue
        purl_name = _purl_name(name)
        if purl_name in skip:
            continue
        key = (purl_name, version)
        seen[key] = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{purl_name}@{version}",
            "name": purl_name,
            "version": version,
            "purl": f"pkg:pypi/{purl_name}@{version}",
        }
    return [seen[k] for k in sorted(seen)]


def build(skip: set[str] | None = None, timestamp: str | None = None) -> dict[str, Any]:
    components = _components(skip or set())
    body = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": timestamp or "1970-01-01T00:00:00Z",
            "tools": [{"vendor": "DiodeWatch", "name": "make_sbom.py"}],
            "component": {
                "type": "application",
                "name": "diodewatch",
                "version": _project_version(),
            },
            "properties": [
                {"name": "diodewatch:python", "value": platform.python_version()},
                {"name": "diodewatch:platform", "value": platform.platform()},
            ],
        },
        "components": components,
    }
    # Serial from content: stable across runs, different when the set changes.
    digest = hashlib.sha256(
        json.dumps(components, sort_keys=True).encode("utf-8")).hexdigest()
    body["serialNumber"] = (f"urn:uuid:{digest[:8]}-{digest[8:12]}-{digest[12:16]}-"
                            f"{digest[16:20]}-{digest[20:32]}")
    return body


def _project_version() -> str:
    try:
        return metadata.version("diodewatch")
    except metadata.PackageNotFoundError:
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Emit a CycloneDX SBOM")
    ap.add_argument("--out", default="sbom.cdx.json", help="output path")
    ap.add_argument("--timestamp", default=None,
                    help="ISO-8601 stamp (default: SOURCE_DATE_EPOCH or fixed)")
    ap.add_argument("--skip", default="pip,setuptools,wheel",
                    help="comma-separated distributions to omit")
    args = ap.parse_args(argv)

    timestamp = args.timestamp
    if not timestamp and os.environ.get("SOURCE_DATE_EPOCH"):
        epoch = int(os.environ["SOURCE_DATE_EPOCH"])
        import datetime as _dt
        timestamp = _dt.datetime.fromtimestamp(epoch, _dt.UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ")

    doc = build({s.strip().lower() for s in args.skip.split(",") if s.strip()},
                timestamp)
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8", newline="\n")
    print(f"wrote {target} ({len(doc['components'])} components, "
          f"CycloneDX {doc['specVersion']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
