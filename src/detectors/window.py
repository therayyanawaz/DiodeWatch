"""Time-window aggregation for rule-based detectors.

Rules never look at raw flows one-by-one: threats are *rate and cardinality*
phenomena, so the engine buckets canonical flow records into tumbling windows
(`window_s`, default 10 s) and aggregates per

  * destination  — one row per (window, dst_ip): DDoS signals live here;
  * source       — one row per (window, src_ip): scan / exfil signals live here.

The engine is a thin, vectorized pandas shim over `features.engine`-style
canonical records (same required columns). Null-safe: timestamps that cannot
be coerced are dropped (and counted); counts are NaN-safe; sentinel durations
(-1 µs, CIC quirk) are excluded from duration statistics.

Threshold defaults are calibrated on the pinned CIC-IDS2017 Wednesday
working-hours corpus: `scripts/checks/check_thresholds.py` re-measures every
figure in this package against that corpus and exits non-zero on drift,
`scripts/checks/check_rules.py` is the labelled-slice acceptance check, and
`docs/rules.md` holds the rationale for each constant.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

# One canonical record must expose at least these fields (unify schema).
REQUIRED = {
    "flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "timestamp", "ts_epoch", "duration_us",
    "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
}

FLAG_COLS = ("fin_flags", "syn_flags", "rst_flags",
             "psh_flags", "ack_flags", "urg_flags")


@dataclass(frozen=True)
class WindowFrames:
    """Everything the rule modules consume, for one batch of flows."""
    dst: pd.DataFrame      # one row per (window, dst_ip)
    src: pd.DataFrame      # one row per (window, src_ip)
    window_s: int
    n_flows: int
    n_dropped_ts: int      # flows dropped because ts_epoch was unusable


def _num(df: pd.DataFrame, col: str) -> pd.Series:
    """Numeric coercion + NaN fill for count/byte columns (fast path for numeric dtypes)."""
    if col not in df.columns:
        return pd.Series(0.0, index=df.index)
    s = df[col]
    # fast path: already numeric — skip expensive to_numeric inference
    if pd.api.types.is_numeric_dtype(s.dtype):
        if s.isna().any():
            return s.fillna(0)
        return s
    return pd.to_numeric(s, errors="coerce").fillna(0)


def _is_private_fast(ip_str: str) -> float:
    """RFC1918/loopback/link-local check without ipaddress module (~20x faster).

    Covers 99%+ of prototype traffic (IPv4 dotted-quad). Falls back to
    ipaddress only for non-IPv4 shapes.
    """
    try:
        if ip_str.startswith(("10.", "192.168.")):
            return 1.0
        if ip_str.startswith(("127.", "169.254.")):
            return 1.0
        if ip_str.startswith("172."):
            # 172.16.0.0/12 → second octet 16..31
            dot = ip_str.find(".", 4)
            second = int(ip_str[4:dot] if dot > 4 else 0)
            if 16 <= second <= 31:
                return 1.0
            return 0.0
        if ip_str == "::1" or ip_str.startswith(("fc", "fd", "fe80")):
            return 1.0
        if "." in ip_str and ":" not in ip_str:
            return 0.0  # public IPv4 — no need for ipaddress
        import ipaddress as _ip
        return float(_ip.ip_address(ip_str).is_private)
    except (ValueError, AttributeError):
        return 0.0


_PRIVATE_CACHE: dict[str, float] = {}


def build_windows(flows: pd.DataFrame, window_s: int = 10) -> WindowFrames:
    """Bucket canonical flow records into per-dst and per-src window frames."""
    missing = REQUIRED - set(flows.columns)
    if missing:
        raise ValueError(
            f"input lacks canonical fields {sorted(missing)}; "
            f"expected unify-schema records (src.ingest.schema.FLOW_FIELDS)"
        )
    if window_s <= 0:
        raise ValueError("window_s must be a positive number of seconds")

    # ---- time axis (fast path: skip to_numeric when already numeric) ------
    _ts_col = flows["ts_epoch"]
    if pd.api.types.is_numeric_dtype(_ts_col.dtype):
        ts = _ts_col.fillna(float("nan")).astype("float64")
    else:
        ts = pd.to_numeric(_ts_col, errors="coerce")
    keep = ts.notna()
    n_dropped = int((~keep).sum())
    # no full-frame copy: filter once, reuse caller's frame read-only
    df = flows.loc[keep] if n_dropped else flows
    ts = ts.loc[keep] if n_dropped else ts
    win = (ts // window_s).astype("int64")

    # ---- numeric core ---------------------------------------------------------
    fwd_pkts = _num(df, "fwd_pkts")
    bwd_pkts = _num(df, "bwd_pkts")
    fwd_bytes = _num(df, "fwd_bytes")
    bwd_bytes = _num(df, "bwd_bytes")
    proto_num = _num(df, "protocol")
    # CIC sentinel: Flow Duration == -1 means "unknown"; exclude from stats.
    _dur_col = df["duration_us"]
    if pd.api.types.is_numeric_dtype(_dur_col.dtype):
        dur = _dur_col.astype("float64") / 1e6
    else:
        dur = pd.to_numeric(_dur_col, errors="coerce") / 1e6
    dur = dur.where(dur >= 0)

    frame = pd.DataFrame({
        "__win": win,
        "flow_id": df["flow_id"].astype(str),
        "src_ip": df["src_ip"].astype(str),
        "dst_ip": df["dst_ip"].astype(str),
        "dst_port": _num(df, "dst_port"),
        "src_port": _num(df, "src_port"),
        "protocol": proto_num,
        "fwd_pkts": fwd_pkts,
        "bwd_pkts": bwd_pkts,
        "fwd_bytes": fwd_bytes,
        "bwd_bytes": bwd_bytes,
        "tot_pkts": fwd_pkts + bwd_pkts,
        "tot_bytes": fwd_bytes + bwd_bytes,
        "dur_s": dur,
        "has_bwd": (bwd_pkts > 0).astype("int64"),
        "is_tcp": (proto_num == 6).astype("int64"),
        "is_udp": (proto_num == 17).astype("int64"),
        # kept as raw columns: label rollup happens vectorized below (a
        # per-group Python lambda here forces the WHOLE groupby off the fast
        # C aggregation path — measured 4x slowdown on 50k-row windows)
        "label": df["label"] if "label" in df.columns else None,
    })
    for col in FLAG_COLS:
        frame[col] = _num(df, col)

    # ---- direction-of-connection helpers -------------------------------------
    # RFC1918/loopback/link-local = internal; anything else = external.
    # Fast prefix check + module-level cache (was: ipaddress per unique IP).
    dst_ips = frame["dst_ip"].astype(str)
    uniq = dst_ips.unique()
    # reuse cached results across windows (prototype streams repeat IPs)
    missing = [ip for ip in uniq if ip not in _PRIVATE_CACHE]
    for ip in missing:
        _PRIVATE_CACHE[ip] = _is_private_fast(ip)
    frame["__dst_internal"] = dst_ips.map(_PRIVATE_CACHE)
    # a flow whose SOURCE port is a well-known service port is a server reply
    # (response traffic), not a connection initiated by this host
    frame["__src_service"] = ((frame["src_port"] > 0) &
                               (frame["src_port"] < 1024)).astype(float)

    # ---- per-destination frame (DDoS signals) --------------------------------
    # held_conns / no_resp as boolean-sum aggregations stay on the fast C path
    # (a Python lambda per group would serialize the whole agg); n_dports
    # keeps nunique semantics via a NaN-masked column (nunique skips NaN).
    frame["__held"] = (dur > window_s).astype("float64")
    frame["__dp_gt0"] = frame["dst_port"].where(frame["dst_port"] > 0)
    frame["__no_bwd"] = (frame["has_bwd"] == 0).astype("float64")
    dst = frame.groupby(["__win", "dst_ip"], sort=False).agg(
        flows=("flow_id", "size"),
        n_src=("src_ip", "nunique"),
        src_ports=("src_port", "nunique"),
        fwd_pkts=("fwd_pkts", "sum"),
        bwd_pkts=("bwd_pkts", "sum"),
        fwd_bytes=("fwd_bytes", "sum"),
        bwd_bytes=("bwd_bytes", "sum"),
        mean_dur_s=("dur_s", "mean"),
        max_dur_s=("dur_s", "max"),
        held_conns=("__held", "sum"),
        udp_share=("is_udp", "mean"),
        syn_pkts=("syn_flags", "sum"),
        ack_pkts=("ack_flags", "sum"),
        rst_pkts=("rst_flags", "sum"),
    )
    dst["flows_per_sec"] = dst["flows"] / window_s
    dst["fwd_bytes_per_sec"] = dst["fwd_bytes"] / window_s
    dst["pkts_ratio"] = dst["fwd_pkts"] / dst["bwd_pkts"].replace(0, np.nan)
    dst["mean_fwd_pkt"] = dst["fwd_bytes"] / dst["fwd_pkts"].replace(0, np.nan)
    dst["syn_share"] = dst["syn_pkts"] / dst["fwd_pkts"].replace(0, np.nan)
    dst["half_open"] = (dst["syn_pkts"] - dst["ack_pkts"]).clip(lower=0)
    dst["src_conc"] = np.where(dst["flows"] > 0, dst["n_src"] / dst["flows"], np.nan)

    # ---- per-source frame (scan / exfil signals) ------------------------------
    src = frame.groupby(["__win", "src_ip"], sort=False).agg(
        flows=("flow_id", "size"),
        n_dips=("dst_ip", "nunique"),
        n_dports=("__dp_gt0", "nunique"),
        fwd_bytes=("fwd_bytes", "sum"),
        bwd_bytes=("bwd_bytes", "sum"),
        fwd_pkts=("fwd_pkts", "sum"),
        bwd_pkts=("bwd_pkts", "sum"),
        no_resp=("__no_bwd", "sum"),
        udp_flows=("is_udp", "sum"),
        tcp_flows=("is_tcp", "sum"),
        internal_dst_flows=("__dst_internal", "sum"),
        service_src_flows=("__src_service", "sum"),
    )
    # dtype parity with the previous per-group lambda (float64) so downstream
    # consumers (rules, ML feature frames, stored parquets) see no change
    src["n_dports"] = src["n_dports"].astype("float64")
    src["tot_bytes"] = src["fwd_bytes"] + src["bwd_bytes"]
    src["bytes_per_flow"] = src["tot_bytes"] / src["flows"].replace(0, np.nan)
    src["upload_ratio"] = src["fwd_bytes"] / src["bwd_bytes"].replace(0, np.nan)
    src["resp_share"] = 1.0 - src["no_resp"] / src["flows"].replace(0, np.nan)
    src["udp_share"] = src["udp_flows"] / src["flows"].replace(0, np.nan)
    src["internal_dst_share"] = (src["internal_dst_flows"] /
                                 src["flows"].replace(0, np.nan))
    src["server_share"] = (src["service_src_flows"] /
                           src["flows"].replace(0, np.nan))

    # ---- label rollup (vectorized) -------------------------------------------
    # Semantics identical to the former per-group _first_label: attack labels
    # win over BENIGN (mixed windows are attack windows), ties keep the first
    # occurrence in flow order, and windows with NO label at all stay None
    # (pcap-sourced flows are unlabelled, never 'BENIGN').
    if "label" in frame.columns and frame["label"].notna().any():
        lab = frame["label"].astype(str).where(frame["label"].notna(), "")
        frame["__is_attack"] = lab.ne("") & lab.ne("BENIGN")
        frame["__has_lab"] = lab.ne("").astype("float64")
        frame["__lab"] = lab
        frame["__row"] = np.arange(len(frame))
        attacks = frame[frame["__is_attack"]].sort_values(
            "__row", kind="mergesort")
        dst["label"] = attacks.groupby(["__win", "dst_ip"], sort=False)["__lab"] \
            .first().reindex(dst.index)
        src["label"] = attacks.groupby(["__win", "src_ip"], sort=False)["__lab"] \
            .first().reindex(src.index)
        # groups with labels but no attack -> BENIGN; groups with none -> NaN
        for out_df, key_col in ((dst, "dst_ip"), (src, "src_ip")):
            has_any = frame.groupby(["__win", key_col], sort=False)["__has_lab"] \
                .sum().reindex(out_df.index)
            out_df["label"] = out_df["label"].fillna(
                pd.Series("BENIGN", index=has_any.index)
                .where(has_any > 0))
        # label-less groups (mixed labelled/unlabelled batches) end NaN here;
        # normalize to None so consumers see exactly 'no ground truth'
        dst["label"] = dst["label"].astype(object).where(dst["label"].notna(), None)
        src["label"] = src["label"].astype(object).where(src["label"].notna(), None)
    else:
        # unlabeled input (pcap replay): keep the column present (detectors
        # read row["label"]) with the same all-None values the per-group
        # _first_label agg produced before the vectorized rollup
        dst["label"] = None
        src["label"] = None

    return WindowFrames(dst=dst, src=src, window_s=window_s,
                        n_flows=len(df), n_dropped_ts=n_dropped)


def iso_at(win_index: int, window_s: int, offset_s: float = 0.0) -> str:
    """Window start (+ optional offset) as ISO-8601 UTC (stdlib, no pandas)."""
    from datetime import datetime, timezone
    t = datetime.fromtimestamp(float(win_index * window_s + offset_s),
                               tz=timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S")
