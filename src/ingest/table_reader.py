"""Stream CICFlowMeter-style flow tables (CSV or parquet) as canonical records.

One source row is one flow, so this is a row-wise standardization pass:

    raw table  ->  canonical record dict (see src.ingest.schema.FLOW_FIELDS)

Reads in bounded batches (never the whole corpus in memory) so it holds up at
IDS scale, and resolves header dialects through schema.COLUMN_ALIASES so any
CIC mirror (official names, dropped spaces, decimal IPs) standardizes the same.
"""
from __future__ import annotations

from pathlib import Path

import pyarrow.parquet as pq

from .schema import (
    COLUMN_ALIASES,
    CORE_FIELDS,
    STAT_FIELDS,
    empty,
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

TABLE_SUFFIXES = {".csv", ".parquet", ".pq"}


def _map_columns(columns: list[str]) -> dict[str, str]:
    """Canonical field -> actual column name, via alias resolution."""
    mapped: dict[str, str] = {}
    for col in columns:
        canon = COLUMN_ALIASES.get(normalize_column(col))
        if canon is not None and canon not in mapped:
            mapped[canon] = col
    return mapped


def iter_batches(path: Path, batch_size: int = 100_000):
    """Yield pandas DataFrames in bounded batches from .csv or .parquet/.pq."""
    suffix = path.suffix.lower()
    if suffix == ".csv":
        import pandas as pd

        yield from pd.read_csv(
            path,
            chunksize=batch_size,
            low_memory=False,
            dtype=str,          # standardize types ourselves; keeps bad cells visible
        )
        return
    if suffix in {".parquet", ".pq"}:
        pf = pq.ParquetFile(path)
        for batch in pf.iter_batches(batch_size=batch_size):
            yield batch.to_pandas()
        return
    raise ValueError(f"unsupported table suffix {path.suffix!r} (want {sorted(TABLE_SUFFIXES)})")


def stream_records(path: Path, *, limit: int | None = None,
                   batch_size: int = 100_000, missing_ok: bool = False):
    """Yield canonical per-flow records from a CICFlowMeter-style table.

    Yields dicts with exactly schema.FLOW_FIELDS keys. `missing_ok` silences the
    warning about absent identity columns (some public mirrors strip them).
    """

    needed = (set(CORE_FIELDS) | set(STAT_FIELDS)) - {"proto", "ts_epoch"}
    warned = False
    emitted = 0

    for df in iter_batches(path, batch_size=batch_size):
        colmap = _map_columns(list(df.columns))
        if not warned:
            have = set(colmap) & needed
            want = {"src_ip", "src_port", "dst_ip", "dst_port"}
            if not want <= have:
                import sys
                print(
                    f"[warn] {path.name}: identity columns missing "
                    f"({sorted(want - have)}); flow ids/IPs will be partial",
                    file=sys.stderr,
                )
            warned = True

        # Materialize each needed column once per batch (avoids per-cell lookups).
        series = {c: df[colmap[c]].tolist() if c in colmap else None for c in needed}
        n = len(df)
        for i in range(n):
            cell = {c: (None if series[c] is None else series[c][i]) for c in needed}
            src_ip = to_ip(cell["src_ip"])
            dst_ip = to_ip(cell["dst_ip"])
            src_port = to_int(cell["src_port"])
            dst_port = to_int(cell["dst_port"])
            protocol = to_protocol(cell["protocol"])
            iso, epoch = to_timestamp(cell["timestamp"])
            fwd_id = cell["flow_id"]
            flow_id = (str(fwd_id).strip() if not empty(fwd_id) else None)
            if not flow_id:
                flow_id = synth_flow_id(src_ip, src_port, dst_ip, dst_port, protocol)

            record = {
                "flow_id": flow_id,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "proto": proto_name(protocol),
                "timestamp": iso,
                "ts_epoch": epoch,
                "duration_us": to_int(cell["duration_us"]),
                "fwd_pkts": to_int(cell["fwd_pkts"]),
                "bwd_pkts": to_int(cell["bwd_pkts"]),
                "fwd_bytes": to_int(cell["fwd_bytes"]),
                "bwd_bytes": to_int(cell["bwd_bytes"]),
                "fin_flags": to_int(cell["fin_flags"]),
                "syn_flags": to_int(cell["syn_flags"]),
                "rst_flags": to_int(cell["rst_flags"]),
                "psh_flags": to_int(cell["psh_flags"]),
                "ack_flags": to_int(cell["ack_flags"]),
                "urg_flags": to_int(cell["urg_flags"]),
                "label": to_label(cell["label"]),
            }
            # CIC publishes these verbatim; pass them through untouched,
            # including the source's own sentinels (-1, negative IAT Min).
            for name in STAT_FIELDS:
                record[name] = to_float(cell[name])
            yield record
            emitted += 1
            if limit is not None and emitted >= limit:
                return
