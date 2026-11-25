"""Run a stock IDS over one capture and report what it cost to do it.

The honest comparison to Suricata or Zeek is about the *shape* of the work, and
that is what this measures:

  * how many alerts the tool raised on a capture the analyst has labels for,
  * how many CPU-seconds and wall-clock seconds it spent,
  * and, when `--ours` is given, the same two figures for DiodeWatch on the same
    capture, so the operator sees both on their own hardware.

It deliberately does **not** compute precision, recall or an F1 against our
labels. Two tools alert on different things (a rule set fires on a signature, a
window ensemble fires on a window) and lining those up requires a mapping
nobody has validated. A number produced from a guessed mapping is worse than no
number, so this produces the volumes and the cost and leaves the judgement to
the person who knows the capture.

    python scripts/benchmarks/bench_reference.py --pcap data/raw/x.pcap --tool auto
    python scripts/benchmarks/bench_reference.py --pcap data/raw/x.pcap --ours

Exit codes: 0 measured, 2 the requested tool is not installed (nothing was
measured, and the message says how to install it), 1 the tool ran and failed.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

try:  # POSIX only; the reference tools are Linux-targeted anyway
    import resource
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]

REPO = Path(__file__).resolve().parents[2]
TOOLS = {
    "suricata": {
        "binary": "suricata",
        "install": "apt-get install suricata  (or build from suricata.io; "
                   "the default Emerging Threats rule set is enough)",
        "alerts": ("eve.json", "event_type", "alert"),
    },
    "zeek": {
        "binary": "zeek",
        "install": "apt-get install zeek  (or the OpenSUSE/Zeek packages; "
                   "`zeek -r` needs no configuration for conn/notice logs)",
        "alerts": ("notice.log", None, None),
    },
}


def available() -> dict[str, str]:
    """Which of the tools this host actually has, and where."""
    return {name: shutil.which(spec["binary"]) or ""
            for name, spec in TOOLS.items() if shutil.which(spec["binary"])}


def _cpu_seconds() -> float | None:
    """CPU time of finished children, or None where the platform cannot say.

    None is reported as null in the JSON rather than as 0.0: a zero would read
    as "this tool used no CPU", which is the one thing it certainly did not do."""
    if resource is None:
        return None
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def _count_suricata_alerts(out_dir: Path) -> int:
    eve = out_dir / "eve.json"
    if not eve.exists():
        return 0
    count = 0
    for line in eve.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("event_type") == "alert":
            count += 1
    return count


def _count_zeek_notices(out_dir: Path) -> int:
    notice = out_dir / "notice.log"
    if not notice.exists():
        return 0
    return sum(1 for line in notice.read_text(encoding="utf-8", errors="replace")
               .splitlines() if line and not line.startswith("#"))


def run_tool(tool: str, pcap: Path) -> dict[str, Any]:
    """Measure one tool on one capture. The work directory is temporary: a
    benchmark must not leave logs behind in the tree."""
    spec = TOOLS[tool]
    binary = shutil.which(spec["binary"])
    if not binary:
        raise FileNotFoundError(spec["install"])

    with tempfile.TemporaryDirectory(prefix=f"bench-{tool}-") as tmp:
        out_dir = Path(tmp)
        if tool == "suricata":
            cmd = [binary, "-r", str(pcap), "-l", str(out_dir), "--runmode=single"]
        else:
            cmd = [binary, "-r", str(pcap), "Log::default_logdir=" + str(out_dir)]
        cpu_before = _cpu_seconds()
        started = time.perf_counter()
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              cwd=str(out_dir), timeout=7200, check=False)
        wall = time.perf_counter() - started
        cpu_after = _cpu_seconds()
        cpu = (None if cpu_before is None or cpu_after is None
               else cpu_after - cpu_before)
        # A tool that exited non-zero may have written a partial log. Counting it
        # as "0 alerts" would read as a clean, cheap pass; None reads as unknown.
        alerts = (None if proc.returncode != 0 else
                  (_count_suricata_alerts if tool == "suricata"
                   else _count_zeek_notices)(out_dir))
        version = subprocess.run(
            [binary, "-V" if tool == "suricata" else "--version"],
            capture_output=True, text=True, check=False,
        ).stdout.strip().splitlines()
        return {
            "tool": tool,
            "version": version[0] if version else "unknown",
            "pcap": str(pcap),
            "pcap_bytes": pcap.stat().st_size,
            "alerts": alerts,
            "cpu_seconds": None if cpu is None else round(cpu, 3),
            "wall_seconds": round(wall, 3),
            "alerts_per_cpu_second": (round(alerts / cpu, 3)
                                      if alerts is not None and cpu and cpu > 0
                                      else None),
            "cpu_note": (None if cpu is not None
                         else "CPU time is not reported on this platform"),
            "exit_code": proc.returncode,
            "stderr_tail": (proc.stderr or "").strip().splitlines()[-3:],
        }


def run_ours(pcap: Path) -> dict[str, Any]:
    """The same two figures for this project, through its own CLI path so the
    comparison is not measuring a hand-built shortcut."""
    import pandas as pd

    from src.detectors.rules import run_rules
    from src.ingest.pcap_reader import stream_flows

    cpu_before = _cpu_seconds()
    started = time.perf_counter()
    frame = pd.DataFrame(list(stream_flows(pcap)))
    alerts = run_rules(frame)
    wall = time.perf_counter() - started
    cpu_after = _cpu_seconds()
    cpu = (None if cpu_before is None or cpu_after is None
           else cpu_after - cpu_before)
    return {
        "tool": "diodewatch",
        "pcap": str(pcap),
        "pcap_bytes": pcap.stat().st_size,
        "flows": len(frame),
        "alerts": len(alerts),
        "cpu_seconds": None if cpu is None else round(cpu, 3),
        "wall_seconds": round(wall, 3),
        "alerts_per_cpu_second": (round(len(alerts) / cpu, 3)
                                  if cpu and cpu > 0 else None),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Measure Suricata or Zeek on one capture, beside our own pass")
    ap.add_argument("--pcap", required=True, help="capture to run over")
    ap.add_argument("--tool", default="auto", choices=("auto", *TOOLS),
                    help="which reference tool (auto: the first one installed)")
    ap.add_argument("--ours", action="store_true",
                    help="also measure this project on the same capture")
    ap.add_argument("--out", default=None, help="write the JSON here")
    args = ap.parse_args(argv)

    pcap = Path(args.pcap)
    if not pcap.exists():
        print(f"no such capture: {pcap}", file=sys.stderr)
        return 1

    found = available()
    if args.tool == "auto":
        if not found:
            print("no reference IDS on this host, so nothing was measured.",
                  file=sys.stderr)
            for name, spec in TOOLS.items():
                print(f"  {name}: {spec['install']}", file=sys.stderr)
            return 2
        tool = next(iter(found))
    else:
        tool = args.tool
        if tool not in found:
            print(f"{tool} is not installed, so nothing was measured.",
                  file=sys.stderr)
            print(f"  {TOOLS[tool]['install']}", file=sys.stderr)
            return 2

    results: list[dict[str, Any]] = []
    try:
        results.append(run_tool(tool, pcap))
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.ours:
        results.append(run_ours(pcap))

    doc = {"capture": str(pcap), "host": os.uname().sysname
           if hasattr(os, "uname") else sys.platform, "results": results}
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(text)

    for row in results:
        cpu = ("     n/a" if row["cpu_seconds"] is None
               else f"{row['cpu_seconds']:8.2f}s")
        alerts = "n/a (run failed)" if row["alerts"] is None else f"{row['alerts']:6d}"
        print(f"{row['tool']:12s} alerts={alerts} "
              f"cpu={cpu} wall={row['wall_seconds']:8.2f}s")
    print("\nVolumes and cost only: precision and recall need a label mapping "
          "between the tools' classes and ours, and a guessed mapping would be "
          "a fabricated number. See docs/benchmarks.md.")
    return 0 if all(r.get("exit_code", 0) == 0 for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
