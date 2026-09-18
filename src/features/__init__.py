"""Feature layer: canonical flow records in, frozen feature vectors out.

    specs      frozen registry of every feature (active + declared-future)
    engine     vectorized builder: basics, rates, ratios, protocol/TCP-flag
               features, DNS shape, per-source/per-destination context stats
    pipeline   CLI: python -m src.features.pipeline --input flows.ndjson
               --out features.parquet
"""

__version__ = "0.4.0"
