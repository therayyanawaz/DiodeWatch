"""Vectorized feature builder: canonical flow records -> frozen feature frame.

Input: a pandas DataFrame of canonical records (the unify schema,
src.ingest.schema.FLOW_FIELDS). Output: a DataFrame with exactly the active
columns declared in specs.FEATURES, in registry order.

Conventions:
  * rates over zero/absent duration and mean sizes over zero packets are NaN
    (never Inf), float64 columns, LightGBM/pandas handle NaN natively;
  * TCP flag counts are 0 for non-TCP flows (matches CIC tables);
  * context features are computed over the whole input batch (one window);
    per-window semantics arrive with the live streaming stage.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.ingest.schema import PROTO_NAMES

from .specs import ACTIVE_NAMES, FEATURES, META_NAMES

REQUIRED = {
    "flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
}
FLAG_COLS = ("fin_flags", "syn_flags", "rst_flags",
             "psh_flags", "ack_flags", "urg_flags")

# Timing/size columns measured at ingest and carried through unchanged: the
# table source aliases CIC's own columns, the pcap source computes the same
# statistics from packets. Registry-driven, so adding one to specs is enough.
_PASSTHROUGH = tuple(f["name"] for f in FEATURES if f["family"] in ("iat", "pktlen"))


def _safe_divide(num: pd.Series, den: pd.Series) -> pd.Series:
    """Vectorized division that yields NaN (never Inf) on zero/None divisors."""
    # fast path: both already float/int, pure numpy, no to_numeric passes
    if pd.api.types.is_numeric_dtype(num.dtype) and pd.api.types.is_numeric_dtype(den.dtype):
        n = num.to_numpy(dtype="float64", na_value=np.nan)
        d = den.to_numpy(dtype="float64", na_value=np.nan)
        with np.errstate(divide="ignore", invalid="ignore"):
            out = np.where(d != 0, n / d, np.nan)
        return pd.Series(out, index=num.index, dtype="float64")
    d = pd.to_numeric(den, errors="coerce").fillna(0.0)
    out = pd.Series(np.nan, index=num.index, dtype="float64")
    mask = d != 0
    out[mask] = pd.to_numeric(num, errors="coerce")[mask] / d[mask]
    return out


def _group_value_entropy(df: pd.DataFrame, group_col: str,
                         value_col: str) -> pd.Series:
    """Per-group Shannon entropy of `value_col`, aligned back to the frame."""
    vc = df.groupby(group_col, sort=False)[value_col].value_counts()
    if vc.empty:
        return pd.Series(0.0, index=df.index)
    p = vc / vc.groupby(level=0, sort=False).transform("sum")
    h = -(p * np.log2(p)).groupby(level=0, sort=False).sum()
    return df[group_col].map(h).fillna(0.0)


def build_features(flows: pd.DataFrame) -> pd.DataFrame:
    """Compute the frozen feature frame from canonical flow records."""
    missing = REQUIRED - set(flows.columns)
    if missing:
        raise ValueError(
            f"input lacks canonical fields {sorted(missing)}; "
            f"expected unify-schema records (src.ingest.schema.FLOW_FIELDS)"
        )
    df = flows.copy()

    # ---- typed core (null -> 0 for counts; NaN-friendly for floats) ---------
    def intcol(name: str) -> pd.Series:
        s = df[name]
        if pd.api.types.is_integer_dtype(s.dtype):
            return s if not s.isna().any() else s.fillna(0).astype("int64")
        if pd.api.types.is_numeric_dtype(s.dtype):
            return s.fillna(0).astype("int64")
        return (pd.to_numeric(s, errors="coerce")
                .fillna(0).astype("int64"))

    fwd_pkts, bwd_pkts = intcol("fwd_pkts"), intcol("bwd_pkts")
    fwd_bytes, bwd_bytes = intcol("fwd_bytes"), intcol("bwd_bytes")
    tot_pkts = fwd_pkts + bwd_pkts
    tot_bytes = fwd_bytes + bwd_bytes

    _dur_col = df["duration_us"]
    if pd.api.types.is_numeric_dtype(_dur_col.dtype):
        dur_us = _dur_col.astype("float64")
    else:
        dur_us = pd.to_numeric(_dur_col, errors="coerce")
    duration_s = dur_us / 1e6

    cols: dict[str, object] = {}
    # meta passes through unchanged; synthesize what canonical sources guarantee
    # (proto name) or leave null when a column is absent entirely.
    for name in META_NAMES:
        if name in df.columns:
            cols[name] = df[name].astype("object")
        elif name == "proto":
            p = pd.to_numeric(df["protocol"], errors="coerce").fillna(0)
            cols[name] = p.map(PROTO_NAMES).astype("object")
        else:
            cols[name] = None  # broadcast scalar (was: misaligned RangeIndex Series)

    # ---- basic --------------------------------------------------------------
    cols["duration_s"] = duration_s
    cols["fwd_pkts"] = fwd_pkts
    cols["bwd_pkts"] = bwd_pkts
    cols["tot_pkts"] = tot_pkts
    cols["fwd_bytes"] = fwd_bytes
    cols["bwd_bytes"] = bwd_bytes
    cols["tot_bytes"] = tot_bytes
    cols["avg_fwd_pkt_size"] = _safe_divide(fwd_bytes, fwd_pkts)
    cols["avg_bwd_pkt_size"] = _safe_divide(bwd_bytes, bwd_pkts)
    cols["avg_pkt_size"] = _safe_divide(tot_bytes, tot_pkts)

    # ---- rates (NaN when duration is zero/absent) ---------------------------
    for col, num in (("flow_bytes_per_s", tot_bytes), ("flow_pkts_per_s", tot_pkts),
                     ("fwd_bytes_per_s", fwd_bytes), ("bwd_bytes_per_s", bwd_bytes),
                     ("fwd_pkts_per_s", fwd_pkts), ("bwd_pkts_per_s", bwd_pkts)):
        cols[col] = _safe_divide(num, duration_s)

    # ---- ratios / asymmetry ---------------------------------------------------
    cols["fwd_byte_ratio"] = _safe_divide(fwd_bytes, tot_bytes).fillna(0.0)
    cols["byte_asymmetry"] = _safe_divide(fwd_bytes - bwd_bytes, tot_bytes).fillna(0.0)
    cols["pkt_asymmetry"] = _safe_divide(fwd_pkts - bwd_pkts, tot_pkts).fillna(0.0)

    # ---- protocol families ---------------------------------------------------
    _proto_col = df["protocol"]
    if pd.api.types.is_numeric_dtype(_proto_col.dtype):
        proto = _proto_col.fillna(0)
    else:
        proto = pd.to_numeric(_proto_col, errors="coerce").fillna(0)
    cols["is_tcp"] = proto.eq(6)
    cols["is_udp"] = proto.eq(17)
    cols["is_icmp"] = proto.eq(1)

    # ---- TCP flag counts (0 when not TCP / column absent) --------------------
    for name in FLAG_COLS:
        cols[name] = intcol(name) if name in df.columns else 0

    # ---- DNS shape -----------------------------------------------------------
    _sport_col = df["src_port"]
    _dport_col = df["dst_port"]
    sport = _sport_col if pd.api.types.is_numeric_dtype(_sport_col.dtype) \
        else pd.to_numeric(_sport_col, errors="coerce")
    dport = _dport_col if pd.api.types.is_numeric_dtype(_dport_col.dtype) \
        else pd.to_numeric(_dport_col, errors="coerce")
    cols["is_dns"] = sport.eq(53) | dport.eq(53)

    # ---- per-packet timing / size (measured upstream, passed through) ---------
    # A source that does not publish them (or a frame built before they existed)
    # yields NaN, never 0, absence must stay distinguishable from a real zero.
    for name in _PASSTHROUGH:
        cols[name] = (pd.to_numeric(df[name], errors="coerce")
                      if name in df.columns else np.nan)

    # ---- context: group statistics over the batch window ----------------------
    src = df["src_ip"].astype(str)
    dst = df["dst_ip"].astype(str)
    ports = dport  # reuse coerced dst_port above (was: second to_numeric)

    src_vc = src.value_counts()
    cols["src_flow_count"] = src.map(src_vc)
    cols["src_dst_port_count"] = df.groupby("src_ip", sort=False)[
        "dst_port"].transform("nunique")
    cols["src_dst_ip_count"] = df.groupby("src_ip", sort=False)[
        "dst_ip"].transform("nunique")
    cols["src_dst_port_entropy"] = _group_value_entropy(df, "src_ip", "dst_port")
    dns_flag = ports.eq(53)
    src_dns = dns_flag.groupby(src.values).transform("sum")
    # reuse src_vc (was: second value_counts pass over same column)
    cols["src_dns_share"] = _safe_divide(src_dns,
                                        src.map(src_vc)).fillna(0.0)

    dst_vc = dst.value_counts()
    cols["dst_flow_count"] = dst.map(dst_vc)
    cols["dst_src_port_count"] = df.groupby("dst_ip", sort=False)[
        "src_port"].transform("nunique")
    cols["dst_src_ip_count"] = df.groupby("dst_ip", sort=False)[
        "src_ip"].transform("nunique")
    cols["dst_src_port_entropy"] = _group_value_entropy(df, "dst_ip", "src_port")

    # single DataFrame construction (was: ~73 per-column insertions)
    out = pd.DataFrame(cols, index=df.index)

    # ---- enforce exact registry order/typing -----------------------------------
    ordered = ACTIVE_NAMES
    out = out[ordered]
    for spec in FEATURES:
        if spec["status"] != "active":
            continue
        col = spec["name"]
        if col not in out.columns:
            continue
        dt = spec["dtype"]
        if dt == "bool":
            if out[col].dtype != "bool":
                out[col] = out[col].fillna(False).astype("bool")
        elif dt == "int" and not pd.api.types.is_integer_dtype(out[col].dtype):
            out[col] = (pd.to_numeric(out[col], errors="coerce")
                        .fillna(0).astype("int64"))
        elif dt == "float" and out[col].dtype != "float64":
            out[col] = pd.to_numeric(out[col], errors="coerce").astype("float64")
    return out
