"""Ingest layer: raw traffic in, canonical flow records out.

Two front-ends, one schema (see .schema):

    table_reader   CICFlowMeter-style .csv / .parquet  (one row = one flow)
    pcap_reader    .pcap / .pcapng captures (packets aggregated to flows)

Drive both from the CLI:

    python -m src.ingest.unify --input <file-or-dir> --format csv|pcap --out flows.ndjson
"""

__version__ = "1.0.0"
