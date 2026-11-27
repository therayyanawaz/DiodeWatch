"""Stream flow-export records (Argus, nfdump, goflow2) as canonical records.

These are the source formats a NetFlow/IPFIX/sFlow deployment hands over when
there is no capture to re-read:

  * Argus CSV (`ra -c ,`), including the CTU-13 `.binetflow` export;
  * nfdump CSV (`nfdump -o csv`), with or without its header row;
  * goflow2 JSON, one object per line (a top-level JSON array is accepted for
    small files).

Every reader emits exactly `schema.FLOW_FIELDS`, like `table_reader` and
`pcap_reader`. A flow export is not a packet capture, so three limits are
kept explicit instead of guessed:

  * flags: NetFlow/IPFIX/Argus expose connection state or a final TCP flag set,
    not per-packet counts, so the six flag fields stay null;
  * direction: nfdump and goflow2 publish one counter pair for the whole flow,
    so the total goes to the forward side and backward stays zero; Argus rows
    with SrcPkts/DstPkts (or SrcBytes/DstBytes) are split where published;
  * timing: export records carry start/duration, not per-packet timestamps, so
    the 26 IAT/length statistics stay null.

A malformed row is skipped and counted, never allowed to abort a run.
"""
from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterator
from itertools import chain
from pathlib import Path

from .schema import (
    FLOW_FIELDS,
    empty,
    iso_from_epoch,
    normalize_column,
    proto_name,
    synth_flow_id,
    to_float,
    to_int,
    to_ip,
    to_label,
    to_protocol,
    to_timestamp,
)

FLOW_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson", ".binetflow"}

# --------------------------------------------------------------------------- #
# Format detection: a .csv can be a CIC table, an Argus export or nfdump.
# --------------------------------------------------------------------------- #

_DATE = re.compile(r"^\d{4}[-/]\d{1,2}[-/]\d{1,2}[ T]\d{1,2}:\d{2}:\d{2}")


def _looks_like_start(cell: str) -> bool:
    return bool(_DATE.match(cell.strip()))


def sniff_csv_format(path: Path) -> str:
    """Return table, argus or nfdump for a CSV whose header decides."""
    try:
        with open(path, encoding="utf-8-sig", newline="") as fh:
            for row in csv.reader(fh):
                if row and any(cell.strip() for cell in row):
                    break
            else:
                return "table"
    except (OSError, UnicodeDecodeError, csv.Error):
        return "table"

    cells = [normalize_column(c) for c in row]
    known = set(cells)
    if "srcaddr" in known and ("starttime" in known or "totpkts" in known):
        return "argus"
    if "ts" in known and ("te" in known or "td" in known):
        return "nfdump"
    # Headerless nfdump starts with a timestamp. A CIC table starts with a
    # flow id or an address, never a date, so this is a safe last resort.
    if row and _looks_like_start(row[0]):
        return "nfdump"
    return "table"


_GOFLOW2_KEYS = (b'"src_addr"', b'"dst_addr"', b'"time_received_ns"',
                  b'"time_flow_start_ns"')


def _sniff_goflow2(path: Path) -> str | None:
    """Only call a JSON file goflow2 when its head actually looks like it.

    A broad input directory also contains manifests and ledgers; loading those
    as flows would report zero records without explaining why.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(65_536)
    except OSError:
        return None
    return "goflow2" if any(key in head for key in _GOFLOW2_KEYS) else None


def detect_format(path: Path) -> str | None:
    """Best-effort source kind from the suffix and, for text, the head."""
    suffix = path.suffix.lower()
    if suffix in {".pcap", ".pcapng"}:
        return "pcap"
    if suffix in {".parquet", ".pq"}:
        return "table"
    if suffix in {".json", ".jsonl", ".ndjson"}:
        return _sniff_goflow2(path)
    if suffix == ".binetflow":
        return "argus"
    if suffix == ".csv":
        return sniff_csv_format(path)
    return None

# --------------------------------------------------------------------------- #
# Shared record construction
# --------------------------------------------------------------------------- #


def _bump(stats: dict | None, key: str, n: int = 1) -> None:
    if stats is not None:
        stats[key] = stats.get(key, 0) + n


def _duration_us(seconds) -> int | None:
    f = to_float(seconds)
    return None if f is None else round(f * 1_000_000)


def _split_counts(total, fwd, bwd) -> tuple[int | None, int | None]:
    """Prefer a published directional split; otherwise put the total forward."""
    f, b = to_int(fwd), to_int(bwd)
    t = to_int(total)
    if f is not None and b is not None:
        if t is not None and f + b == 0 and t > 0:
            return t, 0
        return f, b
    if t is not None:
        if f is not None:
            return f, max(t - f, 0)
        if b is not None:
            return max(t - b, 0), b
        return t, 0
    if f is not None:
        return f, 0
    if b is not None:
        return 0, b
    return None, None


def _split_bytes(total, fwd, bwd) -> tuple[int | None, int | None]:
    """Split bytes when both sides or a total plus one side is published."""
    f, b = to_int(fwd), to_int(bwd)
    t = to_int(total)
    if f is not None and b is not None:
        return f, b
    if t is not None:
        if f is not None:
            return f, max(t - f, 0)
        if b is not None:
            return max(t - b, 0), b
        return t, 0
    if f is not None:
        return f, 0
    if b is not None:
        return 0, b
    return None, None


def _record(*, src_ip, src_port, dst_ip, dst_port, protocol, timestamp,
            ts_epoch, duration_us, total_pkts=None, fwd_pkts=None,
            bwd_pkts=None, total_bytes=None, fwd_bytes=None, bwd_bytes=None,
            label=None) -> dict:
    """Build one canonical record, with absence left as null."""
    p = to_protocol(protocol)
    f_pkts, b_pkts = _split_counts(total_pkts, fwd_pkts, bwd_pkts)
    f_bytes, b_bytes = _split_bytes(total_bytes, fwd_bytes, bwd_bytes)
    rec = {name: None for name in FLOW_FIELDS}
    rec.update({
        "flow_id": synth_flow_id(src_ip, src_port, dst_ip, dst_port, p),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": p,
        "proto": proto_name(p),
        "timestamp": timestamp,
        "ts_epoch": ts_epoch,
        "duration_us": duration_us,
        "fwd_pkts": f_pkts,
        "bwd_pkts": b_pkts,
        "fwd_bytes": f_bytes,
        "bwd_bytes": b_bytes,
        "label": label,
    })
    return rec

# --------------------------------------------------------------------------- #
# Argus CSV (ra -c ,)
# --------------------------------------------------------------------------- #

_ARGUS = {
    "starttime": "timestamp", "start": "timestamp",
    "dur": "duration_s",
    "proto": "protocol",
    "srcaddr": "src_ip", "srcip": "src_ip",
    "dstaddr": "dst_ip", "dstip": "dst_ip",
    "sport": "src_port", "srcport": "src_port",
    "dport": "dst_port", "dstport": "dst_port",
    "totpkts": "total_pkts", "totbytes": "total_bytes",
    "srcpkts": "fwd_pkts", "dstpkts": "bwd_pkts",
    "srcbytes": "fwd_bytes", "dstbytes": "bwd_bytes",
    "label": "label",
}


def _map_argus(header: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for i, name in enumerate(header):
        field = _ARGUS.get(normalize_column(name))
        if field is not None and field not in out:
            out[field] = i
    return out


def _get(row: list[str], colmap: dict[str, int], key: str):
    i = colmap.get(key)
    return None if i is None or i >= len(row) else row[i]


def stream_argus(path: Path, *, limit: int | None = None,
                 stats: dict | None = None) -> Iterator[dict]:
    """Yield canonical records from an Argus CSV export."""
    if limit is not None and limit <= 0:
        return
    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        header = None
        for row in reader:
            if row and any(cell.strip() for cell in row):
                header = row
                break
        if header is None:
            return
        colmap = _map_argus(header)
        if "src_ip" not in colmap and "dst_ip" not in colmap:
            raise ValueError(
                f"{path}: not an Argus CSV (expected SrcAddr/DstAddr; "
                f"header was {header[:8]!r})"
            )

        emitted = 0
        for row in reader:
            if not row or not any(cell.strip() for cell in row):
                continue
            _bump(stats, "rows")
            src_ip = to_ip(_get(row, colmap, "src_ip"))
            dst_ip = to_ip(_get(row, colmap, "dst_ip"))
            if src_ip is None and dst_ip is None:
                _bump(stats, "skipped")
                continue
            iso, epoch = to_timestamp(_get(row, colmap, "timestamp"))
            rec = _record(
                src_ip=src_ip,
                src_port=to_int(_get(row, colmap, "src_port")),
                dst_ip=dst_ip,
                dst_port=to_int(_get(row, colmap, "dst_port")),
                protocol=_get(row, colmap, "protocol"),
                timestamp=iso,
                ts_epoch=epoch,
                duration_us=_duration_us(_get(row, colmap, "duration_s")),
                total_pkts=_get(row, colmap, "total_pkts"),
                fwd_pkts=_get(row, colmap, "fwd_pkts"),
                bwd_pkts=_get(row, colmap, "bwd_pkts"),
                total_bytes=_get(row, colmap, "total_bytes"),
                fwd_bytes=_get(row, colmap, "fwd_bytes"),
                bwd_bytes=_get(row, colmap, "bwd_bytes"),
                label=to_label(_get(row, colmap, "label")),
            )
            yield rec
            emitted += 1
            if limit is not None and emitted >= limit:
                return

# --------------------------------------------------------------------------- #
# nfdump CSV
# --------------------------------------------------------------------------- #

_NFDUMP = {
    "ts": "timestamp", "te": "end", "td": "duration_s", "pr": "protocol",
    "sa": "src_ip", "da": "dst_ip", "sp": "src_port", "dp": "dst_port",
    "packets": "total_pkts", "bytes": "total_bytes",
    "ipkt": "fwd_pkts", "opkt": "bwd_pkts",
    "ibyt": "fwd_bytes", "obyt": "bwd_bytes",
    "label": "label",
}

# nfdump -o csv without a header: the first 13 fields of the standard layout.
_NFDUMP_POSITIONAL = (
    "ts", "te", "td", "pr", "sa", "da", "sp", "dp", "op",
    "packets", "bytes", "pkt_size", "flg",
)


def _map_nfdump(header: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for i, name in enumerate(header):
        field = _NFDUMP.get(normalize_column(name))
        if field is not None and field not in out:
            out[field] = i
    return out


def _nfdump_has_header(row: list[str]) -> bool:
    cells = {normalize_column(c) for c in row}
    return ("ts" in cells or "te" in cells) and ("sa" in cells or "da" in cells)


def stream_nfdump(path: Path, *, limit: int | None = None,
                  stats: dict | None = None) -> Iterator[dict]:
    """Yield canonical records from nfdump CSV, headerless or with a header."""
    if limit is not None and limit <= 0:
        return
    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        first = None
        for row in reader:
            if row and any(cell.strip() for cell in row):
                first = row
                break
        if first is None:
            return
        if _nfdump_has_header(first):
            header = [normalize_column(c) for c in first]
            rows = reader
        else:
            header = list(_NFDUMP_POSITIONAL[:len(first)])
            rows = chain([first], reader)
        colmap = _map_nfdump(header)
        if "src_ip" not in colmap and "dst_ip" not in colmap:
            raise ValueError(f"{path}: not an nfdump CSV (no sa/da columns)")

        emitted = 0
        for row in rows:
            if not row or not any(cell.strip() for cell in row):
                continue
            _bump(stats, "rows")
            src_ip = to_ip(_get(row, colmap, "src_ip"))
            dst_ip = to_ip(_get(row, colmap, "dst_ip"))
            if src_ip is None and dst_ip is None:
                _bump(stats, "skipped")
                continue
            iso, epoch = to_timestamp(_get(row, colmap, "timestamp"))
            dur = _duration_us(_get(row, colmap, "duration_s"))
            if iso is None:
                end_iso, end_epoch = to_timestamp(_get(row, colmap, "end"))
                if end_epoch is not None:
                    if dur is not None:
                        epoch = end_epoch - dur / 1_000_000.0
                        iso = iso_from_epoch(epoch)
                    else:
                        iso, epoch = end_iso, end_epoch
            rec = _record(
                src_ip=src_ip,
                src_port=to_int(_get(row, colmap, "src_port")),
                dst_ip=dst_ip,
                dst_port=to_int(_get(row, colmap, "dst_port")),
                protocol=_get(row, colmap, "protocol"),
                timestamp=iso,
                ts_epoch=epoch,
                duration_us=dur,
                total_pkts=_get(row, colmap, "total_pkts"),
                fwd_pkts=_get(row, colmap, "fwd_pkts"),
                bwd_pkts=_get(row, colmap, "bwd_pkts"),
                total_bytes=_get(row, colmap, "total_bytes"),
                fwd_bytes=_get(row, colmap, "fwd_bytes"),
                bwd_bytes=_get(row, colmap, "bwd_bytes"),
                label=to_label(_get(row, colmap, "label")),
            )
            yield rec
            emitted += 1
            if limit is not None and emitted >= limit:
                return

# --------------------------------------------------------------------------- #
# goflow2 JSON
# --------------------------------------------------------------------------- #


def _json_objects(path: Path, stats: dict | None):
    """Yield parsed objects from NDJSON, or a top-level array for small files."""
    with open(path, encoding="utf-8-sig") as fh:
        first = fh.read(1)
        while first and first.isspace():
            first = fh.read(1)
        fh.seek(0)
        if first == "[":
            try:
                data = json.load(fh)
            except json.JSONDecodeError:
                _bump(stats, "skipped")
                return
            if not isinstance(data, list):
                _bump(stats, "skipped")
                return
            for obj in data:
                _bump(stats, "rows")
                if isinstance(obj, dict):
                    yield obj
                else:
                    _bump(stats, "skipped")
            return
        for line in fh:
            line = line.strip()
            if not line:
                continue
            _bump(stats, "rows")
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                _bump(stats, "skipped")
                continue
            if isinstance(obj, dict):
                yield obj
            else:
                _bump(stats, "skipped")


def _ns_seconds(value) -> float | None:
    f = to_float(value)
    if f is None or f == 0:
        return None
    return f / 1_000_000_000.0


def _first(obj: dict, *names: str):
    for name in names:
        if name in obj and not empty(obj[name]):
            return obj[name]
    return None


def stream_goflow2(path: Path, *, limit: int | None = None,
                   stats: dict | None = None) -> Iterator[dict]:
    """Yield canonical records from goflow2 JSON (NDJSON or a JSON array)."""
    if limit is not None and limit <= 0:
        return
    emitted = 0
    for obj in _json_objects(path, stats):
        src_ip = to_ip(_first(obj, "src_addr", "src_ip"))
        dst_ip = to_ip(_first(obj, "dst_addr", "dst_ip"))
        if src_ip is None and dst_ip is None:
            _bump(stats, "skipped")
            continue
        start = _ns_seconds(_first(obj, "time_flow_start_ns"))
        end = _ns_seconds(_first(obj, "time_flow_end_ns"))
        received = _ns_seconds(_first(obj, "time_received_ns"))
        epoch = start if start is not None else received
        iso = iso_from_epoch(epoch)
        dur = (round((end - start) * 1_000_000.0)
               if start is not None and end is not None and end >= start else None)
        rec = _record(
            src_ip=src_ip,
            src_port=to_int(_first(obj, "src_port", "sp")),
            dst_ip=dst_ip,
            dst_port=to_int(_first(obj, "dst_port", "dp")),
            protocol=_first(obj, "proto", "protocol"),
            timestamp=iso,
            ts_epoch=epoch,
            duration_us=dur,
            total_pkts=_first(obj, "packets"),
            total_bytes=_first(obj, "bytes"),
            label=to_label(_first(obj, "label", "Label")),
        )
        yield rec
        emitted += 1
        if limit is not None and emitted >= limit:
            return
