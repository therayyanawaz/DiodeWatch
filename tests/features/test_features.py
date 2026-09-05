"""Feature-engine tests: feature registry, vectorized builder, and pipeline CLI."""
from __future__ import annotations

import json
import math

import numpy as np
import pandas as pd
import pytest

from src.features.engine import build_features
from src.features.pipeline import main as pipeline_main
from src.features.specs import ACTIVE_NAMES, FEATURES, FUTURE_NAMES

RECORD_KEYS = ["flow_id", "src_ip", "src_port", "dst_ip", "dst_port",
               "protocol", "proto", "timestamp", "duration_us",
               "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
               "fin_flags", "syn_flags", "rst_flags",
               "psh_flags", "ack_flags", "urg_flags", "label"]


def rec(**kw) -> dict:
    base = {k: None for k in RECORD_KEYS}
    base.update(kw)
    if base["proto"] is None and base["protocol"] is not None:
        base["proto"] = {6: "tcp", 17: "udp", 1: "icmp"}.get(base["protocol"])
    return base


def sample_flows() -> list[dict]:
    """Six flows with hand-computable feature expectations.

    Four share src 10.0.0.1 with dst ports {80, 443, 53, 53}:
      dst-port entropy = 1.5 bits, unique dst ports = 3, dst IPs = 3,
      DNS share = 0.5, src_flow_count = 4.
    """
    return [
        # 1: web-ish TCP, 1 s duration, symmetric-ish but byte-heavy reply
        rec(flow_id="f1", src_ip="10.0.0.1", src_port=50000,
            dst_ip="10.0.0.2", dst_port=80, protocol=6,
            timestamp="2017-07-05T09:00:00", duration_us=1_000_000,
            fwd_pkts=10, bwd_pkts=6, fwd_bytes=1000, bwd_bytes=2000,
            syn_flags=2, ack_flags=8, label="BENIGN"),
        # 2: same src to another server
        rec(flow_id="f2", src_ip="10.0.0.1", src_port=50001,
            dst_ip="10.0.0.3", dst_port=443, protocol=6,
            timestamp="2017-07-05T09:00:01", duration_us=500_000,
            fwd_pkts=3, bwd_pkts=1, fwd_bytes=300, bwd_bytes=100,
            syn_flags=1, ack_flags=2, label="DoS Hulk"),
        # 3 + 4: two DNS-shaped UDP flows from the same source
        rec(flow_id="f3", src_ip="10.0.0.1", src_port=5353,
            dst_ip="10.0.0.4", dst_port=53, protocol=17,
            timestamp="2017-07-05T09:00:02", duration_us=200_000,
            fwd_pkts=2, bwd_pkts=2, fwd_bytes=100, bwd_bytes=200,
            label="BENIGN"),
        rec(flow_id="f4", src_ip="10.0.0.1", src_port=60000,
            dst_ip="10.0.0.4", dst_port=53, protocol=17,
            timestamp="2017-07-05T09:00:03", duration_us=200_000,
            fwd_pkts=1, bwd_pkts=1, fwd_bytes=50, bwd_bytes=100,
            label="BENIGN"),
        # 5: ICMP echo (no ports)
        rec(flow_id="f5", src_ip="10.0.0.9", src_port=None,
            dst_ip="10.0.0.5", dst_port=None, protocol=1,
            timestamp="2017-07-05T09:00:04", duration_us=10_000,
            fwd_pkts=1, bwd_pkts=1, fwd_bytes=64, bwd_bytes=64,
            label="BENIGN"),
        # 6: zero-duration TCP (rates must be NaN, not Inf)
        rec(flow_id="f6", src_ip="10.0.0.6", src_port=40000,
            dst_ip="10.0.0.2", dst_port=8080, protocol=6,
            timestamp="2017-07-05T09:00:05", duration_us=0,
            fwd_pkts=1, bwd_pkts=0, fwd_bytes=50, bwd_bytes=0,
            syn_flags=1, label="BENIGN"),
    ]


def flows_df() -> pd.DataFrame:
    return pd.DataFrame(sample_flows())


@pytest.fixture()
def ndjson(tmp_path):
    p = tmp_path / "flows.ndjson"
    p.write_text("\n".join(json.dumps(r) for r in sample_flows()), encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

def test_registry_is_consistent():
    assert len(ACTIVE_NAMES) == len(set(ACTIVE_NAMES))
    assert all(f["name"] in ACTIVE_NAMES for f in FEATURES
               if f["status"] == "active")
    # meta first, no future entries in active output
    assert ACTIVE_NAMES[0] == "flow_id"
    assert "tls_ja3" not in ACTIVE_NAMES
    assert "dns_nxdomain_rate" in FUTURE_NAMES
    # iat/pktlen were declared-future until ingest could measure them; the
    # burst-split family still is (see specs.active_idle_* for why).
    assert "iat_us_mean" in ACTIVE_NAMES
    assert "iat_*" not in FUTURE_NAMES
    assert "active_idle_*" in FUTURE_NAMES


# --------------------------------------------------------------------------- #
# engine
# --------------------------------------------------------------------------- #

def test_engine_emits_exact_schema_and_meta():
    feat = build_features(flows_df())
    assert list(feat.columns) == ACTIVE_NAMES
    assert len(feat) == 6
    assert list(feat["flow_id"]) == ["f1", "f2", "f3", "f4", "f5", "f6"]
    assert list(feat["label"].iloc[:2]) == ["BENIGN", "DoS Hulk"]
    assert feat["proto"].iloc[:2].tolist() == ["tcp", "tcp"]


def test_engine_synthesizes_proto_when_column_absent():
    feat = build_features(flows_df().drop(columns=["proto"]))
    assert feat["proto"].iloc[:2].tolist() == ["tcp", "tcp"]
    assert feat["proto"].iloc[4] == "icmp"


def test_engine_passes_timing_and_size_stats_through():
    """Ingest measures them, the engine carries them unchanged.

    Absent means NaN, never 0: a source that publishes no per-packet timing must
    not read as a flow of perfectly evenly-spaced packets.
    """
    flows = flows_df()
    for col in ("iat_us_mean", "iat_us_std", "fwd_len_min", "bwd_len_std"):
        assert col in ACTIVE_NAMES
        assert build_features(flows)[col].isna().all(), col

    enriched = flows.copy()
    enriched["iat_us_mean"] = 1234.5
    enriched["fwd_len_min"] = 54.0
    enriched["bwd_len_std"] = [0.0, 0.0, float("nan"), 1.0, 1.0, 1.0]
    got = build_features(enriched)
    assert got["iat_us_mean"].tolist() == [1234.5] * len(got)
    assert got["fwd_len_min"].tolist() == [54.0] * len(got)
    # a real zero stays zero, a real NaN stays NaN
    assert got["bwd_len_std"].iloc[0] == 0.0
    assert math.isnan(got["bwd_len_std"].iloc[2])


def test_basic_features_match_hand_computation():
    feat = build_features(flows_df())
    r1 = feat.iloc[0]
    assert r1["duration_s"] == pytest.approx(1.0)
    assert (r1["fwd_pkts"], r1["bwd_pkts"], r1["tot_pkts"]) == (10, 6, 16)
    assert (r1["fwd_bytes"], r1["bwd_bytes"], r1["tot_bytes"]) == (1000, 2000, 3000)
    assert r1["flow_bytes_per_s"] == pytest.approx(3000.0)
    assert r1["fwd_bytes_per_s"] == pytest.approx(1000.0)
    assert r1["bwd_bytes_per_s"] == pytest.approx(2000.0)
    assert r1["fwd_pkts_per_s"] == pytest.approx(10.0)
    assert r1["avg_fwd_pkt_size"] == pytest.approx(100.0)
    assert r1["avg_bwd_pkt_size"] == pytest.approx(2000.0 / 6)
    assert r1["fwd_byte_ratio"] == pytest.approx(1 / 3)
    assert r1["byte_asymmetry"] == pytest.approx(-1 / 3)
    assert r1["pkt_asymmetry"] == pytest.approx(4 / 16)
    assert bool(r1["is_tcp"]) and not bool(r1["is_udp"])
    assert r1["syn_flags"] == 2 and r1["ack_flags"] == 8


def test_zero_duration_rates_are_nan_never_inf():
    feat = build_features(flows_df())
    r6 = feat.iloc[5]
    for col in ("flow_bytes_per_s", "flow_pkts_per_s", "fwd_bytes_per_s",
                "bwd_pkts_per_s"):
        assert math.isnan(r6[col])
    assert np.isfinite(feat["flow_bytes_per_s"].replace([np.inf, -np.inf], np.nan)
                       .fillna(0)).all()


def test_context_features_and_entropy():
    feat = build_features(flows_df())
    src1 = feat[feat["src_ip"] == "10.0.0.1"]
    assert (src1["src_flow_count"] == 4).all()
    assert (src1["src_dst_port_count"] == 3).all()   # {80, 443, 53}
    assert (src1["src_dst_ip_count"] == 3).all()     # {.2, .3, .4}
    np.testing.assert_allclose(src1["src_dst_port_entropy"].to_numpy(dtype=float),
                                1.5, rtol=1e-9)
    # two of four flows are DNS-shaped (dst port 53)
    np.testing.assert_allclose(src1["src_dns_share"].to_numpy(dtype=float), 0.5)
    # ICMP single-flow groups collapse to entropy 0
    assert feat.iloc[4]["src_dst_port_entropy"] == pytest.approx(0.0)
    # destination-side context on 10.0.0.4 (two flows, one source, two src ports)
    dst4 = feat[feat["dst_ip"] == "10.0.0.4"]
    assert (dst4["dst_flow_count"] == 2).all()
    assert (dst4["dst_src_ip_count"] == 1).all()
    assert (dst4["dst_src_port_count"] == 2).all()
    np.testing.assert_allclose(dst4["dst_src_port_entropy"].to_numpy(dtype=float),
                               1.0, rtol=1e-9)


def test_dns_and_protocol_flags():
    feat = build_features(flows_df())
    assert bool(feat.iloc[2]["is_dns"])
    assert bool(feat.iloc[3]["is_dns"])
    assert not bool(feat.iloc[0]["is_dns"])
    icmp = feat.iloc[4]
    assert bool(icmp["is_icmp"])
    assert icmp["is_dns"] == False
    assert icmp["fin_flags"] == 0      # non-TCP flag counts are 0


def test_engine_rejects_non_canonical_input():
    bad = flows_df().drop(columns=["duration_us"])
    with pytest.raises(ValueError, match="duration_us"):
        build_features(bad)


# --------------------------------------------------------------------------- #
# pipeline CLI
# --------------------------------------------------------------------------- #

def test_pipeline_writes_parquet_with_consistent_columns(ndjson, tmp_path):
    out = tmp_path / "features.parquet"
    assert pipeline_main(["--input", str(ndjson), "--out", str(out)]) == 0
    df = pd.read_parquet(out)
    assert len(df) == 6
    assert list(df.columns) == ACTIVE_NAMES
    assert list(df["flow_id"]) == ["f1", "f2", "f3", "f4", "f5", "f6"]


def test_pipeline_limit(ndjson, tmp_path):
    out = tmp_path / "limited.parquet"
    assert pipeline_main(["--input", str(ndjson), "--out", str(out),
                          "--limit", "3"]) == 0
    assert len(pd.read_parquet(out)) == 3


def test_pipeline_describe(ndjson, capsys):
    assert pipeline_main(["--describe"]) == 0
    text = capsys.readouterr().out
    assert "[basic]" in text and "[future]" in text
    assert "active features" in text
