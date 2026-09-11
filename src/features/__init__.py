"""
ShieldNet Features Module.
Provides canonical schema definitions, preprocessors, time-series sequencer,
and cross-dataset schema adapters (CIC-IDS, UNSW-NB15, CTU-13, CICIoT2023, LANL Auth).
"""

from src.features.schema import (
    get_config_a_feature_names,
    get_numeric_feature_names,
    get_schema_dataframe,
    FLOW_LEVEL,
    PACKET_LEVEL,
    META_LEVEL
)
from src.features.schema_adapter import (
    CrossDatasetSchemaAdapter,
    get_schema_adapter
)

__all__ = [
    "get_config_a_feature_names",
    "get_numeric_feature_names",
    "get_schema_dataframe",
    "FLOW_LEVEL",
    "PACKET_LEVEL",
    "META_LEVEL",
    "CrossDatasetSchemaAdapter",
    "get_schema_adapter",
]
