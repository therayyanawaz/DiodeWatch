"""Ingest layer: raw traffic in, canonical flow records out.

Five front-ends, one schema (see .schema):

    table_reader   CICFlowMeter-style .csv / .parquet  (one row = one flow)
    pcap_reader    .pcap / .pcapng captures (packets aggregated to flows)
    flow_reader    Argus CSV, nfdump CSV, goflow2 JSON (one row = one flow)

Drive them from the CLI:

    python -m src.ingest.unify --input <file-or-dir> \
        --format auto|table|pcap|argus|nfdump|goflow2 --out flows.ndjson
"""

__version__ = "1.0.0"
